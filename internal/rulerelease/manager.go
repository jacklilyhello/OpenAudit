package rulerelease

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/openaudit/openaudit/internal/engine"
	"github.com/openaudit/openaudit/internal/matcher"
	"github.com/openaudit/openaudit/internal/model"
	"github.com/openaudit/openaudit/internal/rules"
	"github.com/openaudit/openaudit/internal/safepath"
	"github.com/openaudit/openaudit/internal/storage"
	"gopkg.in/yaml.v3"
)

const (
	StateDraft     = "draft"
	StateStaged    = "staged"
	StatePublished = "published"

	releaseDir = ".openaudit-release"
)

type Manager struct {
	root  string
	store storage.Store
}

type Conflict struct {
	Type            string   `json:"type"`
	Severity        string   `json:"severity"`
	AffectedRuleIDs []string `json:"affected_rule_ids"`
	Message         string   `json:"message"`
	SuggestedAction string   `json:"suggested_action,omitempty"`
}

type ValidationResult struct {
	OK        bool       `json:"ok"`
	Status    string     `json:"status"`
	Conflicts []Conflict `json:"conflicts"`
	Errors    []string   `json:"errors,omitempty"`
}

type ReleaseResult struct {
	Release storage.RuleRelease       `json:"release"`
	Items   []storage.RuleReleaseItem `json:"items"`
	Result  ValidationResult          `json:"validation"`
}

type SimulateRequest struct {
	Text        string   `json:"text"`
	Scope       string   `json:"scope"`
	RuleIDs     []string `json:"rule_ids"`
	Version     string   `json:"version"`
	Normalize   *bool    `json:"normalize"`
	MaxHits     int      `json:"max_hits"`
	DraftRuleID string   `json:"draft_rule_id"`
}

type SimulateResult struct {
	Scope          string        `json:"scope"`
	Version        string        `json:"version,omitempty"`
	MatchedRuleIDs []string      `json:"matched_rule_ids"`
	Decision       string        `json:"decision"`
	Result         engine.Result `json:"result"`
}

type BulkRequest struct {
	IDs         []string `json:"ids"`
	Category    string   `json:"category"`
	Severity    string   `json:"severity"`
	ImportBatch string   `json:"import_batch_id"`
	State       string   `json:"state"`
	Actor       string   `json:"actor"`
}

type BulkChange struct {
	RuleID string `json:"rule_id"`
	State  string `json:"state"`
	Path   string `json:"path"`
	Before string `json:"before,omitempty"`
	After  string `json:"after,omitempty"`
}

type BatchRollbackResult struct {
	BatchID string       `json:"batch_id"`
	Files   []BulkChange `json:"files"`
}

type fileRule struct {
	Rule rules.Rule
	Rel  string
	Path safepath.Path
	Data []byte
	Hash string
}

type fileBackup struct {
	root   safepath.Root
	path   safepath.Path
	data   []byte
	exists bool
}

func NewManager(root string, store storage.Store) *Manager {
	return &Manager{root: root, store: store}
}

func (m *Manager) rootSafe() (safepath.Root, error) {
	return safepath.NewRoot(m.root, safepath.RequireExistingDir())
}

func validateRuleID(id string) error {
	if id == "" || strings.ContainsRune(id, 0) || filepath.IsAbs(id) || strings.Contains(id, "/") || strings.Contains(id, "\\") || strings.Contains(id, "..") {
		return os.ErrPermission
	}
	return nil
}

func validateState(s string) error {
	switch s {
	case StateDraft, StateStaged, StatePublished:
		return nil
	default:
		return fmt.Errorf("invalid lifecycle state %q", s)
	}
}

func (m *Manager) statePath(state, id string) (safepath.Root, safepath.Path, error) {
	if err := validateState(state); err != nil {
		return safepath.Root{}, safepath.Path{}, err
	}
	if err := validateRuleID(id); err != nil {
		return safepath.Root{}, safepath.Path{}, err
	}
	root, err := safepath.NewRoot(filepath.Join(m.root, releaseDir, state), safepath.CreateRoot())
	if err != nil {
		return safepath.Root{}, safepath.Path{}, err
	}
	p, err := root.Join(id + ".yml")
	return root, p, err
}

func (m *Manager) customPath(id string) (safepath.Root, safepath.Path, error) {
	if err := validateRuleID(id); err != nil {
		return safepath.Root{}, safepath.Path{}, err
	}
	root, err := safepath.NewRoot(filepath.Join(m.root, "custom"), safepath.CreateRoot())
	if err != nil {
		return safepath.Root{}, safepath.Path{}, err
	}
	p, err := root.Join(id + ".yml")
	return root, p, err
}

func normalizeRuleForState(r rules.Rule, state string) (rules.Rule, []byte, error) {
	if err := validateState(state); err != nil {
		return rules.Rule{}, nil, err
	}
	r.State = state
	if err := rules.NormalizeAndValidate(&r); err != nil {
		return rules.Rule{}, nil, err
	}
	b, err := yaml.Marshal(r)
	if err != nil {
		return rules.Rule{}, nil, err
	}
	return r, b, nil
}

func (m *Manager) UpsertDraft(ctx context.Context, r rules.Rule, actor string) (rules.Rule, error) {
	r, b, err := normalizeRuleForState(r, StateDraft)
	if err != nil {
		return rules.Rule{}, err
	}
	root, p, err := m.statePath(StateDraft, r.ID)
	if err != nil {
		return rules.Rule{}, err
	}
	if err := root.WriteFileAtomic(p, b); err != nil {
		return rules.Rule{}, err
	}
	m.persistLifecycle(ctx, r.ID, StateDraft, actor, "api")
	return r, nil
}

func (m *Manager) DeleteState(ctx context.Context, state, id, actor string) error {
	root, p, err := m.statePath(state, id)
	if err != nil {
		return err
	}
	if err := root.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	m.persistLifecycle(ctx, id, state, actor, "delete")
	return nil
}

func (m *Manager) StageDraft(ctx context.Context, id, actor string) (rules.Rule, error) {
	draftRoot, draftPath, err := m.statePath(StateDraft, id)
	if err != nil {
		return rules.Rule{}, err
	}
	b, err := draftRoot.ReadFile(draftPath)
	if err != nil {
		return rules.Rule{}, err
	}
	var r rules.Rule
	if err := yaml.Unmarshal(b, &r); err != nil {
		return rules.Rule{}, err
	}
	r.State = StateStaged
	r, nb, err := normalizeRuleForState(r, StateStaged)
	if err != nil {
		return rules.Rule{}, err
	}
	stageRoot, stagePath, err := m.statePath(StateStaged, id)
	if err != nil {
		return rules.Rule{}, err
	}
	if err := stageRoot.WriteFileAtomic(stagePath, nb); err != nil {
		return rules.Rule{}, err
	}
	m.persistLifecycle(ctx, id, StateStaged, actor, "stage")
	return r, nil
}

func (m *Manager) ListState(state string) ([]rules.Rule, error) {
	if state == StatePublished {
		files, err := m.activeRules()
		if err != nil {
			return nil, err
		}
		out := make([]rules.Rule, 0, len(files))
		for _, f := range files {
			out = append(out, f.Rule)
		}
		sortRules(out)
		return out, nil
	}
	root, err := safepath.NewRoot(filepath.Join(m.root, releaseDir, state), safepath.CreateRoot())
	if err != nil {
		return nil, err
	}
	var out []rules.Rule
	err = root.Walk(func(p safepath.Path, d fs.DirEntry) error {
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(p.String(), ".yml") && !strings.HasSuffix(p.String(), ".yaml") {
			return nil
		}
		b, err := root.ReadFile(p)
		if err != nil {
			return err
		}
		var r rules.Rule
		if err := yaml.Unmarshal(b, &r); err != nil {
			return err
		}
		r.State = state
		if err := rules.NormalizeAndValidate(&r); err != nil {
			return err
		}
		out = append(out, r)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sortRules(out)
	return out, nil
}

func sortRules(rs []rules.Rule) {
	sort.Slice(rs, func(i, j int) bool { return rs[i].ID < rs[j].ID })
}

func (m *Manager) activeRules() (map[string]fileRule, error) {
	root, err := m.rootSafe()
	if err != nil {
		return nil, err
	}
	out := map[string]fileRule{}
	err = root.Walk(func(p safepath.Path, d fs.DirEntry) error {
		if d.IsDir() && strings.HasPrefix(d.Name(), ".") {
			return fs.SkipDir
		}
		if d.IsDir() || (!strings.HasSuffix(p.String(), ".yml") && !strings.HasSuffix(p.String(), ".yaml")) {
			return nil
		}
		b, err := root.ReadFile(p)
		if err != nil {
			return err
		}
		var r rules.Rule
		if err := yaml.Unmarshal(b, &r); err != nil {
			return err
		}
		r.State = StatePublished
		if err := rules.NormalizeAndValidate(&r); err != nil {
			return err
		}
		rel, err := root.Rel(p)
		if err != nil {
			return err
		}
		r.Path = rel
		out[r.ID] = fileRule{Rule: r, Rel: rel, Path: p, Data: b, Hash: hashBytes(b)}
		return nil
	})
	return out, err
}

func hashBytes(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func (m *Manager) stagedRules() (map[string]fileRule, error) {
	return m.stateFiles(StateStaged)
}

func (m *Manager) stateFiles(state string) (map[string]fileRule, error) {
	root, err := safepath.NewRoot(filepath.Join(m.root, releaseDir, state), safepath.CreateRoot())
	if err != nil {
		return nil, err
	}
	out := map[string]fileRule{}
	err = root.Walk(func(p safepath.Path, d fs.DirEntry) error {
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(p.String(), ".yml") && !strings.HasSuffix(p.String(), ".yaml") {
			return nil
		}
		b, err := root.ReadFile(p)
		if err != nil {
			return err
		}
		var r rules.Rule
		if err := yaml.Unmarshal(b, &r); err != nil {
			return err
		}
		r.State = state
		if err := rules.NormalizeAndValidate(&r); err != nil {
			return err
		}
		rel, err := root.Rel(p)
		if err != nil {
			return err
		}
		r.Path = filepath.Join("custom", r.ID+".yml")
		out[r.ID] = fileRule{Rule: r, Rel: rel, Path: p, Data: b, Hash: hashBytes(b)}
		return nil
	})
	return out, err
}

func BuildSet(rs []rules.Rule) (rules.Set, error) {
	var set rules.Set
	for _, r := range rs {
		if r.State == "" {
			r.State = StatePublished
		}
		if err := rules.NormalizeAndValidate(&r); err != nil {
			return rules.Set{}, err
		}
		set.Rules = append(set.Rules, r)
		if !r.IsEnabled() {
			continue
		}
		switch r.Type {
		case "keyword":
			set.KeywordRules = append(set.KeywordRules, r)
		case "regex":
			set.RegexRules = append(set.RegexRules, r)
		case "domain":
			set.DomainRules = append(set.DomainRules, r)
		case "pinyin":
			set.PinyinRules = append(set.PinyinRules, r)
		case "homophone":
			set.HomophoneRules = append(set.HomophoneRules, r)
		}
	}
	return set, nil
}

func (m *Manager) mergedFutureRules() ([]rules.Rule, map[string]fileRule, map[string]fileRule, error) {
	active, err := m.activeRules()
	if err != nil {
		return nil, nil, nil, err
	}
	staged, err := m.stagedRules()
	if err != nil {
		return nil, nil, nil, err
	}
	merged := make(map[string]rules.Rule, len(active)+len(staged))
	for id, f := range active {
		merged[id] = f.Rule
	}
	for id, f := range staged {
		r := f.Rule
		r.State = StatePublished
		r.Path = filepath.Join("custom", id+".yml")
		merged[id] = r
	}
	out := make([]rules.Rule, 0, len(merged))
	for _, r := range merged {
		out = append(out, r)
	}
	sortRules(out)
	return out, active, staged, nil
}

func DetectConflicts(rs []rules.Rule) []Conflict {
	var out []Conflict
	ids := map[string]int{}
	keywordKey := map[string]string{}
	regexKey := map[string]string{}
	domainKey := map[string]string{}
	for i := range rs {
		r := rs[i]
		ids[r.ID]++
		if r.Type == "regex" {
			for _, p := range r.Patterns {
				if _, err := regexp.Compile(p); err != nil {
					out = append(out, Conflict{Type: "invalid_regex", Severity: "critical", AffectedRuleIDs: []string{r.ID}, Message: fmt.Sprintf("regex rule %s has invalid pattern", r.ID), SuggestedAction: "fix or remove the invalid regex before publishing"})
				}
			}
		}
		for _, kw := range r.Keywords {
			key := "keyword\x00" + strings.ToLower(strings.TrimSpace(r.Category)) + "\x00" + strings.ToLower(strings.TrimSpace(kw))
			if prev, ok := keywordKey[key]; ok && prev != r.ID {
				out = append(out, Conflict{Type: "duplicate_keyword", Severity: "warning", AffectedRuleIDs: []string{prev, r.ID}, Message: "duplicate normalized keyword in the same category", SuggestedAction: "merge duplicate keyword rules or adjust category"})
			} else {
				keywordKey[key] = r.ID
			}
		}
		for _, p := range r.Patterns {
			key := strings.TrimSpace(p)
			if prev, ok := regexKey[key]; ok && prev != r.ID {
				out = append(out, Conflict{Type: "duplicate_regex", Severity: "warning", AffectedRuleIDs: []string{prev, r.ID}, Message: "identical regex pattern appears in more than one rule", SuggestedAction: "merge duplicate regex rules"})
			} else {
				regexKey[key] = r.ID
			}
		}
		for _, d := range r.Domains {
			key := matcher.NormalizeDomain(d)
			if prev, ok := domainKey[key]; ok && prev != r.ID {
				out = append(out, Conflict{Type: "duplicate_domain", Severity: "warning", AffectedRuleIDs: []string{prev, r.ID}, Message: "duplicate normalized domain pattern", SuggestedAction: "merge duplicate domain rules"})
			} else if key != "" {
				domainKey[key] = r.ID
			}
		}
	}
	for id, n := range ids {
		if n > 1 {
			out = append(out, Conflict{Type: "duplicate_rule_id", Severity: "critical", AffectedRuleIDs: []string{id}, Message: "duplicate rule id found", SuggestedAction: "rule ids must be unique before publishing"})
		}
	}
	return out
}

func (m *Manager) DetectStateConflicts() ([]Conflict, error) {
	var out []Conflict
	byID := map[string]map[string]string{}
	for _, state := range []string{StateDraft, StateStaged, StatePublished} {
		rs, err := m.ListState(state)
		if err != nil {
			return nil, err
		}
		for _, r := range rs {
			b, _ := yaml.Marshal(r)
			if byID[r.ID] == nil {
				byID[r.ID] = map[string]string{}
			}
			byID[r.ID][state] = hashBytes(b)
		}
	}
	for id, states := range byID {
		if len(states) < 2 {
			continue
		}
		hash := ""
		diff := false
		for _, h := range states {
			if hash == "" {
				hash = h
				continue
			}
			if h != hash {
				diff = true
			}
		}
		if diff {
			out = append(out, Conflict{Type: "state_version_conflict", Severity: "warning", AffectedRuleIDs: []string{id}, Message: "same rule id differs across draft/staged/published states", SuggestedAction: "stage or publish the intended version explicitly"})
		}
	}
	return out, nil
}

func (m *Manager) Prepublish(ctx context.Context, actor, sample string) (ValidationResult, *SimulateResult, error) {
	rs, _, staged, err := m.mergedFutureRules()
	if err != nil {
		return ValidationResult{}, nil, err
	}
	if len(staged) == 0 {
		return ValidationResult{OK: false, Status: "failed", Errors: []string{"no staged rules available for publish"}}, nil, nil
	}
	set, err := BuildSet(rs)
	if err != nil {
		return ValidationResult{OK: false, Status: "failed", Errors: []string{err.Error()}}, nil, nil
	}
	if _, err := engine.NewFromSet(set); err != nil {
		return ValidationResult{OK: false, Status: "failed", Errors: []string{err.Error()}}, nil, nil
	}
	conflicts := DetectConflicts(rs)
	stateConflicts, err := m.DetectStateConflicts()
	if err != nil {
		return ValidationResult{}, nil, err
	}
	conflicts = append(conflicts, stateConflicts...)
	ok := true
	for _, c := range conflicts {
		if c.Severity == "critical" {
			ok = false
		}
	}
	res := ValidationResult{OK: ok, Status: "passed", Conflicts: conflicts}
	if !ok {
		res.Status = "failed"
	}
	var sim *SimulateResult
	if sample != "" {
		x, err := m.Simulate(SimulateRequest{Text: sample, Scope: StateStaged, MaxHits: 50})
		if err != nil {
			return ValidationResult{}, nil, err
		}
		sim = &x
	}
	m.persistValidation(ctx, actor, StateStaged, res, sim)
	return res, sim, nil
}

func (m *Manager) Publish(ctx context.Context, actor, sample string, reload func() error) (ReleaseResult, error) {
	validation, _, err := m.Prepublish(ctx, actor, sample)
	if err != nil {
		return ReleaseResult{}, err
	}
	if !validation.OK {
		return ReleaseResult{Result: validation}, nil
	}
	futureRules, active, staged, err := m.mergedFutureRules()
	if err != nil {
		return ReleaseResult{}, err
	}
	version, err := m.nextVersion()
	if err != nil {
		return ReleaseResult{}, err
	}
	items := releaseItems(version, active, staged)
	snapshotPath, err := m.writeSnapshot(version, futureRules)
	if err != nil {
		return ReleaseResult{}, err
	}
	var backups []fileBackup
	for id, f := range staged {
		root, p, err := m.customPath(id)
		if err != nil {
			return ReleaseResult{}, err
		}
		old, exists, err := readMaybe(root, p)
		if err != nil {
			return ReleaseResult{}, err
		}
		backups = append(backups, fileBackup{root: root, path: p, data: old, exists: exists})
		r := f.Rule
		r.State = StatePublished
		_, b, err := normalizeRuleForState(r, StatePublished)
		if err != nil {
			return ReleaseResult{}, err
		}
		if err := root.WriteFileAtomic(p, b); err != nil {
			restoreBackups(backups)
			return ReleaseResult{}, err
		}
	}
	if reload != nil {
		if err := reload(); err != nil {
			restoreBackups(backups)
			_ = reload()
			return ReleaseResult{}, err
		}
	}
	for id := range staged {
		m.persistLifecycle(ctx, id, StatePublished, actor, "publish")
		_ = m.DeleteState(ctx, StateStaged, id, actor)
	}
	valJSON, _ := json.Marshal(validation)
	metaJSON, _ := json.Marshal(map[string]any{"source_operation": "publish", "staged_rule_count": len(staged)})
	rel := storage.RuleRelease{Version: version, CreatedAt: time.Now().UTC(), Actor: actor, Status: "published", RuleCount: len(futureRules), AddedCount: countOps(items, "add"), UpdatedCount: countOps(items, "update"), RemovedCount: countOps(items, "remove"), SnapshotPath: snapshotPath, ValidationJSON: string(valJSON), MetadataJSON: string(metaJSON)}
	if m.store != nil {
		if err := m.store.InsertRuleRelease(ctx, rel, items); err != nil {
			return ReleaseResult{}, err
		}
	}
	if err := m.writeReleaseMetadata(rel, items); err != nil {
		return ReleaseResult{}, err
	}
	return ReleaseResult{Release: rel, Items: items, Result: validation}, nil
}

func readMaybe(root safepath.Root, p safepath.Path) ([]byte, bool, error) {
	b, err := root.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	return b, err == nil, err
}

func restoreBackups(backups []fileBackup) {
	for _, b := range backups {
		if !b.exists {
			_ = b.root.Remove(b.path)
			continue
		}
		_ = b.root.WriteFileAtomic(b.path, b.data)
	}
}

func releaseItems(version string, active, staged map[string]fileRule) []storage.RuleReleaseItem {
	var items []storage.RuleReleaseItem
	for id, s := range staged {
		op := "add"
		before := ""
		if a, ok := active[id]; ok {
			before = a.Hash
			op = "update"
		}
		items = append(items, storage.RuleReleaseItem{Version: version, RuleID: id, Operation: op, BeforeHash: before, AfterHash: s.Hash, FilePath: filepath.Join("custom", id+".yml")})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].RuleID < items[j].RuleID })
	return items
}

func countOps(items []storage.RuleReleaseItem, op string) int {
	n := 0
	for _, item := range items {
		if item.Operation == op {
			n++
		}
	}
	return n
}

func (m *Manager) nextVersion() (string, error) {
	root, err := safepath.NewRoot(filepath.Join(m.root, releaseDir, "snapshots"), safepath.CreateRoot())
	if err != nil {
		return "", err
	}
	entries, err := root.ReadDir(root.Path())
	if err != nil {
		return "", err
	}
	max := 0
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "v") {
			continue
		}
		n, err := strconv.Atoi(strings.TrimPrefix(e.Name(), "v"))
		if err == nil && n > max {
			max = n
		}
	}
	return fmt.Sprintf("v%d", max+1), nil
}

func (m *Manager) writeSnapshot(version string, rs []rules.Rule) (string, error) {
	root, err := safepath.NewRoot(filepath.Join(m.root, releaseDir, "snapshots", version), safepath.CreateRoot())
	if err != nil {
		return "", err
	}
	for _, r := range rs {
		rel := publishedRel(r)
		p, err := root.Join(rel)
		if err != nil {
			return "", err
		}
		r.State = StatePublished
		_, b, err := normalizeRuleForState(r, StatePublished)
		if err != nil {
			return "", err
		}
		if err := root.WriteFileAtomic(p, b); err != nil {
			return "", err
		}
	}
	return filepath.Join(releaseDir, "snapshots", version), nil
}

func publishedRel(r rules.Rule) string {
	if strings.TrimSpace(r.Path) != "" {
		return filepath.Clean(r.Path)
	}
	return filepath.Join("custom", r.ID+".yml")
}

func (m *Manager) writeReleaseMetadata(rel storage.RuleRelease, items []storage.RuleReleaseItem) error {
	root, err := safepath.NewRoot(filepath.Join(m.root, releaseDir, "metadata"), safepath.CreateRoot())
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(map[string]any{"release": rel, "items": items}, "", "  ")
	if err != nil {
		return err
	}
	p, err := root.Join(rel.Version + ".json")
	if err != nil {
		return err
	}
	return root.WriteFileAtomic(p, b)
}

func (m *Manager) ListReleases(ctx context.Context, limit, offset int) (storage.ReleasePage, error) {
	if m.store != nil {
		return m.store.QueryRuleReleases(ctx, storage.ReleaseFilter{Limit: limit, Offset: offset})
	}
	return storage.ReleasePage{Items: nil, Page: storage.Page{Limit: limit, Offset: offset}}, nil
}

func (m *Manager) GetRelease(ctx context.Context, version string) (storage.RuleRelease, []storage.RuleReleaseItem, bool, error) {
	if err := validateVersion(version); err != nil {
		return storage.RuleRelease{}, nil, false, err
	}
	if m.store != nil {
		return m.store.GetRuleRelease(ctx, version)
	}
	root, err := safepath.NewRoot(filepath.Join(m.root, releaseDir, "metadata"), safepath.CreateRoot())
	if err != nil {
		return storage.RuleRelease{}, nil, false, err
	}
	p, err := root.Join(version + ".json")
	if err != nil {
		return storage.RuleRelease{}, nil, false, err
	}
	b, err := root.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return storage.RuleRelease{}, nil, false, nil
	}
	if err != nil {
		return storage.RuleRelease{}, nil, false, err
	}
	var x struct {
		Release storage.RuleRelease       `json:"release"`
		Items   []storage.RuleReleaseItem `json:"items"`
	}
	if err := json.Unmarshal(b, &x); err != nil {
		return storage.RuleRelease{}, nil, false, err
	}
	return x.Release, x.Items, true, nil
}

func validateVersion(version string) error {
	if version == "" || strings.ContainsRune(version, 0) || strings.Contains(version, "/") || strings.Contains(version, "\\") || strings.Contains(version, "..") {
		return os.ErrPermission
	}
	if !regexp.MustCompile(`^v[0-9]+$`).MatchString(version) {
		return os.ErrPermission
	}
	return nil
}

func (m *Manager) RollbackRelease(ctx context.Context, version, actor string, reload func() error) (ReleaseResult, error) {
	if err := validateVersion(version); err != nil {
		return ReleaseResult{}, err
	}
	target, err := m.snapshotFiles(version)
	if err != nil {
		return ReleaseResult{}, err
	}
	var rs []rules.Rule
	for _, f := range target {
		rs = append(rs, f.Rule)
	}
	set, err := BuildSet(rs)
	if err != nil {
		return ReleaseResult{}, err
	}
	if _, err := engine.NewFromSet(set); err != nil {
		return ReleaseResult{}, err
	}
	active, err := m.activeRules()
	if err != nil {
		return ReleaseResult{}, err
	}
	root, err := m.rootSafe()
	if err != nil {
		return ReleaseResult{}, err
	}
	for _, f := range active {
		if _, ok := target[f.Rel]; !ok {
			if err := root.Remove(f.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return ReleaseResult{}, err
			}
		}
	}
	for rel, f := range target {
		p, err := root.Join(rel)
		if err != nil {
			return ReleaseResult{}, err
		}
		if err := root.WriteFileAtomic(p, f.Data); err != nil {
			return ReleaseResult{}, err
		}
	}
	if reload != nil {
		if err := reload(); err != nil {
			for _, f := range active {
				_ = root.WriteFileAtomic(f.Path, f.Data)
			}
			_ = reload()
			return ReleaseResult{}, err
		}
	}
	newVersion, err := m.nextVersion()
	if err != nil {
		return ReleaseResult{}, err
	}
	snapshotPath, err := m.writeSnapshot(newVersion, rs)
	if err != nil {
		return ReleaseResult{}, err
	}
	targetByID := map[string]fileRule{}
	for _, f := range target {
		targetByID[f.Rule.ID] = f
	}
	items := diffReleaseItems(newVersion, active, targetByID)
	val := ValidationResult{OK: true, Status: "passed"}
	valJSON, _ := json.Marshal(val)
	metaJSON, _ := json.Marshal(map[string]any{"source_operation": "rollback", "rollback_source_version": version})
	rel := storage.RuleRelease{Version: newVersion, CreatedAt: time.Now().UTC(), Actor: actor, Status: "rollback", RuleCount: len(target), AddedCount: countOps(items, "add"), UpdatedCount: countOps(items, "update"), RemovedCount: countOps(items, "remove"), SnapshotPath: snapshotPath, ValidationJSON: string(valJSON), MetadataJSON: string(metaJSON)}
	if m.store != nil {
		if err := m.store.InsertRuleRelease(ctx, rel, items); err != nil {
			return ReleaseResult{}, err
		}
	}
	if err := m.writeReleaseMetadata(rel, items); err != nil {
		return ReleaseResult{}, err
	}
	return ReleaseResult{Release: rel, Items: items, Result: val}, nil
}

func diffReleaseItems(version string, before map[string]fileRule, after map[string]fileRule) []storage.RuleReleaseItem {
	seen := map[string]bool{}
	var items []storage.RuleReleaseItem
	for id, a := range after {
		op := "add"
		beforeHash := ""
		if b, ok := before[id]; ok {
			op = "update"
			beforeHash = b.Hash
			if b.Hash == a.Hash {
				op = "unchanged"
			}
		}
		items = append(items, storage.RuleReleaseItem{Version: version, RuleID: id, Operation: op, BeforeHash: beforeHash, AfterHash: a.Hash, FilePath: a.Rel})
		seen[id] = true
	}
	for id, b := range before {
		if !seen[id] {
			items = append(items, storage.RuleReleaseItem{Version: version, RuleID: id, Operation: "remove", BeforeHash: b.Hash, FilePath: b.Rel})
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].RuleID < items[j].RuleID })
	return items
}

func (m *Manager) snapshotFiles(version string) (map[string]fileRule, error) {
	root, err := safepath.NewRoot(filepath.Join(m.root, releaseDir, "snapshots", version), safepath.RequireExistingDir())
	if err != nil {
		return nil, err
	}
	out := map[string]fileRule{}
	err = root.Walk(func(p safepath.Path, d fs.DirEntry) error {
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(p.String(), ".yml") && !strings.HasSuffix(p.String(), ".yaml") {
			return nil
		}
		b, err := root.ReadFile(p)
		if err != nil {
			return err
		}
		var r rules.Rule
		if err := yaml.Unmarshal(b, &r); err != nil {
			return err
		}
		r.State = StatePublished
		if err := rules.NormalizeAndValidate(&r); err != nil {
			return err
		}
		rel, err := root.Rel(p)
		if err != nil {
			return err
		}
		out[rel] = fileRule{Rule: r, Rel: rel, Path: p, Data: b, Hash: hashBytes(b)}
		return nil
	})
	return out, err
}

func (m *Manager) Simulate(req SimulateRequest) (SimulateResult, error) {
	if len([]rune(req.Text)) > 10000 {
		return SimulateResult{}, errors.New("sample text exceeds 10000 rune simulation limit")
	}
	scope := req.Scope
	if scope == "" {
		scope = StatePublished
	}
	var rs []rules.Rule
	switch scope {
	case StatePublished:
		rs, _ = m.ListState(StatePublished)
	case StateStaged:
		base, _, _, err := m.mergedFutureRules()
		if err != nil {
			return SimulateResult{}, err
		}
		rs = base
	case StateDraft:
		drafts, err := m.ListState(StateDraft)
		if err != nil {
			return SimulateResult{}, err
		}
		rs = filterRules(drafts, req.RuleIDs, req.DraftRuleID)
	case "version":
		files, err := m.snapshotFiles(req.Version)
		if err != nil {
			return SimulateResult{}, err
		}
		for _, f := range files {
			rs = append(rs, f.Rule)
		}
	default:
		return SimulateResult{}, fmt.Errorf("invalid simulation scope %q", scope)
	}
	set, err := BuildSet(rs)
	if err != nil {
		return SimulateResult{}, err
	}
	e, err := engine.NewFromSet(set)
	if err != nil {
		return SimulateResult{}, err
	}
	maxHits := req.MaxHits
	if maxHits <= 0 || maxHits > 100 {
		maxHits = 100
	}
	res := e.AuditWithOptions(req.Text, auditOptions(req.Normalize, maxHits))
	ids := map[string]bool{}
	for _, h := range res.Hits {
		ids[h.RuleID] = true
	}
	var matched []string
	for id := range ids {
		matched = append(matched, id)
	}
	sort.Strings(matched)
	return SimulateResult{Scope: scope, Version: req.Version, MatchedRuleIDs: matched, Decision: res.Action, Result: res}, nil
}

func auditOptions(normalize *bool, maxHits int) model.AuditOptions {
	return model.AuditOptions{Normalize: normalize, MaxHits: maxHits}
}

func filterRules(rs []rules.Rule, ids []string, one string) []rules.Rule {
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	if one != "" {
		want[one] = true
	}
	if len(want) == 0 {
		return rs
	}
	var out []rules.Rule
	for _, r := range rs {
		if want[r.ID] {
			out = append(out, r)
		}
	}
	return out
}

func (m *Manager) BulkSetEnabled(ctx context.Context, req BulkRequest, enabled bool, reload func() error) ([]BulkChange, error) {
	state := req.State
	if state == "" {
		state = StatePublished
	}
	if err := validateState(state); err != nil {
		return nil, err
	}
	files, err := m.filesForState(state)
	if err != nil {
		return nil, err
	}
	selected, err := selectFiles(files, req)
	if err != nil {
		return nil, err
	}
	if len(selected) == 0 {
		return nil, errors.New("no rules matched bulk operation")
	}
	var changes []BulkChange
	var backups []fileBackup
	for _, f := range selected {
		r := f.Rule
		b := enabled
		r.Enabled = &b
		r.State = state
		_, nb, err := normalizeRuleForState(r, state)
		if err != nil {
			return nil, err
		}
		root, p, err := m.writePathForState(state, r.ID)
		if err != nil {
			return nil, err
		}
		old, exists, err := readMaybe(root, p)
		if err != nil {
			return nil, err
		}
		backups = append(backups, fileBackup{root: root, path: p, data: old, exists: exists})
		if err := root.WriteFileAtomic(p, nb); err != nil {
			restoreBackups(backups)
			return nil, err
		}
		changes = append(changes, BulkChange{RuleID: r.ID, State: state, Path: p.String(), Before: string(f.Data), After: string(nb)})
		m.persistLifecycle(ctx, r.ID, state, req.Actor, "bulk")
	}
	if state == StatePublished && reload != nil {
		if err := reload(); err != nil {
			restoreBackups(backups)
			_ = reload()
			return nil, err
		}
	}
	return changes, nil
}

func (m *Manager) filesForState(state string) (map[string]fileRule, error) {
	if state == StatePublished {
		return m.activeRules()
	}
	return m.stateFiles(state)
}

func (m *Manager) writePathForState(state, id string) (safepath.Root, safepath.Path, error) {
	if state == StatePublished {
		return m.customPath(id)
	}
	return m.statePath(state, id)
}

func selectFiles(files map[string]fileRule, req BulkRequest) ([]fileRule, error) {
	explicit := map[string]bool{}
	for _, id := range req.IDs {
		if err := validateRuleID(id); err != nil {
			return nil, err
		}
		explicit[id] = true
		if _, ok := files[id]; !ok {
			return nil, fmt.Errorf("rule %s not found in %s state", id, req.State)
		}
	}
	var out []fileRule
	for id, f := range files {
		if len(explicit) > 0 && !explicit[id] {
			continue
		}
		if req.Category != "" && f.Rule.Category != req.Category {
			continue
		}
		if req.Severity != "" && f.Rule.RiskLevel != req.Severity {
			continue
		}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Rule.ID < out[j].Rule.ID })
	return out, nil
}

func (m *Manager) RollbackImportBatch(batchID string, generatedFiles []string, reload func() error) (BatchRollbackResult, error) {
	if batchID == "" || len(generatedFiles) == 0 {
		return BatchRollbackResult{}, errors.New("rollback unavailable: import batch lacks generated file metadata")
	}
	root, err := m.rootSafe()
	if err != nil {
		return BatchRollbackResult{}, err
	}
	var backups []fileBackup
	var changes []BulkChange
	for _, file := range generatedFiles {
		p, err := root.Resolve(file)
		if err != nil {
			restoreBackups(backups)
			return BatchRollbackResult{}, err
		}
		if !strings.HasSuffix(p.String(), ".yml") && !strings.HasSuffix(p.String(), ".yaml") {
			restoreBackups(backups)
			return BatchRollbackResult{}, errors.New("rollback refused non-YAML generated file")
		}
		b, exists, err := readMaybe(root, p)
		if err != nil {
			restoreBackups(backups)
			return BatchRollbackResult{}, err
		}
		if !exists {
			continue
		}
		backups = append(backups, fileBackup{root: root, path: p, data: b, exists: exists})
		if err := root.Remove(p); err != nil {
			restoreBackups(backups)
			return BatchRollbackResult{}, err
		}
		changes = append(changes, BulkChange{RuleID: filepath.Base(file), State: StatePublished, Path: p.String(), Before: string(b)})
	}
	if reload != nil {
		if err := reload(); err != nil {
			restoreBackups(backups)
			_ = reload()
			return BatchRollbackResult{}, err
		}
	}
	return BatchRollbackResult{BatchID: batchID, Files: changes}, nil
}

func (m *Manager) persistLifecycle(ctx context.Context, ruleID, state, actor, source string) {
	if m.store == nil {
		return
	}
	_ = m.store.UpsertRuleLifecycle(ctx, storage.RuleLifecycle{RuleID: ruleID, State: state, UpdatedAt: time.Now().UTC(), Actor: actor, Source: source})
}

func (m *Manager) persistValidation(ctx context.Context, actor, target string, result ValidationResult, sim *SimulateResult) {
	if m.store == nil {
		return
	}
	conflicts, _ := json.Marshal(result.Conflicts)
	var simJSON []byte
	if sim != nil {
		simJSON, _ = json.Marshal(sim)
	}
	status := "passed"
	if !result.OK {
		status = "failed"
	}
	_ = m.store.InsertRuleValidationRun(ctx, storage.RuleValidationRun{RunID: fmt.Sprintf("validation_%d", time.Now().UTC().UnixNano()), CreatedAt: time.Now().UTC(), Actor: actor, TargetState: target, Status: status, ConflictsJSON: string(conflicts), SimulationJSON: string(simJSON)})
}
