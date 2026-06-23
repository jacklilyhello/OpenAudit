package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/openaudit/openaudit/internal/bundled"
)

const (
	repoURL                = "https://github.com/daijunhaoMinecraft/NeteaseSensitiveWordsProject"
	pinnedCommit           = "97d3236b999c5f95c7adac1debf7fffb81d8bda2"
	deterministicTimestamp = "2026-06-19T22:03:48Z"
	generator              = "openaudit-sync-netease-rules"
	generatorVersion       = "phase-c"
	manifestSchema         = 1
)

var allow = map[string]string{
	"g79":     "SensitiveWords/G79SensitiveWords.json",
	"x19":     "SensitiveWords/X19SensitiveWords.json",
	"license": "LICENSE",
}

type Manifest struct {
	SchemaVersion                int            `json:"schema_version"`
	Provider                     string         `json:"provider"`
	UpstreamRepository           string         `json:"upstream_repository"`
	PinnedCommit                 string         `json:"pinned_commit"`
	RetrievalTimestamp           string         `json:"retrieval_timestamp"`
	DeterministicSourceTimestamp string         `json:"deterministic_source_timestamp"`
	LicenseIdentifier            string         `json:"license_identifier"`
	GeneratorName                string         `json:"generator_name"`
	GeneratorVersion             string         `json:"generator_version"`
	Sources                      []SourceEntry  `json:"sources"`
	Datasets                     []DatasetEntry `json:"datasets"`
}
type SourceEntry struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	ByteSize  int64  `json:"byte_size"`
	RuleCount int    `json:"source_rule_count,omitempty"`
}
type DatasetEntry struct {
	Dataset                     string         `json:"dataset"`
	SourcePath                  string         `json:"source_path"`
	SourceSHA256                string         `json:"source_sha256"`
	SourceByteSize              int64          `json:"source_byte_size"`
	SourceRuleCount             int            `json:"source_rule_count"`
	GeneratedPackPath           string         `json:"generated_pack_path"`
	GeneratedPackSHA256         string         `json:"generated_pack_sha256"`
	GeneratedPackByteSize       int64          `json:"generated_pack_byte_size"`
	GeneratedReportPath         string         `json:"generated_report_path"`
	GeneratedReportSHA256       string         `json:"generated_report_sha256"`
	GeneratedReportByteSize     int64          `json:"generated_report_byte_size"`
	ImportStatistics            ImportStats    `json:"import_statistics"`
	RE2CompatibilityStatistics  RE2Stats       `json:"re2_compatibility_statistics"`
	IncompatibleReasonBreakdown map[string]int `json:"incompatible_reason_breakdown"`
}
type ImportStats struct {
	TotalSourceRules      int                 `json:"total_source_rules"`
	ParsedRules           int                 `json:"parsed_rules"`
	ImportedRecords       int                 `json:"imported_records"`
	EmptyRecords          int                 `json:"empty_records"`
	MalformedRecords      int                 `json:"malformed_records"`
	UnknownRecords        int                 `json:"unknown_records"`
	DuplicateIdentities   int                 `json:"duplicate_identities"`
	DuplicateRegexContent int                 `json:"duplicate_regex_content"`
	CountsByGroup         []bundled.NameCount `json:"counts_by_group"`
}
type RE2Stats struct {
	CompatibleRules   int `json:"compatible_rules"`
	IncompatibleRules int `json:"incompatible_rules"`
}

func main() {
	log.SetFlags(0)
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
func run() error {
	mode := flag.String("mode", "verify", "verify, regenerate, or download")
	commit := flag.String("commit", pinnedCommit, "full pinned commit SHA")
	retrieved := flag.String("retrieved-at", "", "UTC RFC3339 retrieval timestamp for manifest regeneration")
	expG79 := flag.String("expect-g79-sha256", "", "expected G79 snapshot SHA-256 for download")
	expX19 := flag.String("expect-x19-sha256", "", "expected X19 snapshot SHA-256 for download")
	expLic := flag.String("expect-license-sha256", "", "expected LICENSE SHA-256 for download")
	flag.Parse()
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(*commit) {
		return fmt.Errorf("commit must be a full lowercase 40-character SHA, not a floating ref")
	}
	if *commit != pinnedCommit {
		return fmt.Errorf("this reviewed Phase C lock only permits pinned commit %s", pinnedCommit)
	}
	switch *mode {
	case "verify":
		return verify(false, "")
	case "regenerate":
		return verify(true, *retrieved)
	case "download":
		return download(*commit, *expG79, *expX19, *expLic)
	default:
		return fmt.Errorf("unknown mode %q", *mode)
	}
}

func download(commit, g79, x19, lic string) error {
	if g79 == "" || x19 == "" || lic == "" {
		return errors.New("download requires expected SHA-256 values for G79, X19, and LICENSE")
	}
	expects := map[string]string{"g79": g79, "x19": x19, "license": lic}
	staged := map[string][]byte{}
	for key, path := range allow {
		b, err := fetch(commit, path)
		if err != nil {
			return err
		}
		if sha(b) != expects[key] {
			return fmt.Errorf("downloaded %s SHA-256 mismatch", key)
		}
		if key != "license" {
			if _, _, _, _, err := bundled.BuildPack(b, opts(key, "", "")); err != nil {
				return fmt.Errorf("validate %s JSON: %w", key, err)
			}
		} else if !bytes.Contains(b, []byte("GNU GENERAL PUBLIC LICENSE")) {
			return errors.New("LICENSE validation failed")
		}
		staged[key] = b
	}
	return replaceSnapshots(staged)
}
func fetch(commit, path string) ([]byte, error) {
	u := "https://raw.githubusercontent.com/daijunhaoMinecraft/NeteaseSensitiveWordsProject/" + commit + "/" + path
	parsed, _ := url.Parse(u)
	if parsed.Scheme != "https" {
		return nil, errors.New("HTTPS required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
	c := http.Client{Timeout: 20 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 2 {
			return errors.New("too many redirects")
		}
		if req.URL.Scheme != "https" || req.URL.Host != "raw.githubusercontent.com" {
			return errors.New("redirect denied")
		}
		req.Header.Del("Authorization")
		return nil
	}}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d", path, resp.StatusCode)
	}
	if resp.ContentLength > bundled.DefaultLimits().InputJSONBytes {
		return nil, fmt.Errorf("%s response too large", path)
	}
	lim := bundled.DefaultLimits().InputJSONBytes
	if path == "LICENSE" {
		lim = 1 << 20
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, lim+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > lim {
		return nil, fmt.Errorf("%s response exceeded limit", path)
	}
	return b, nil
}
func replaceSnapshots(m map[string][]byte) error {
	targets := map[string]string{"g79": "third_party/netease-sensitive-words/upstream/G79SensitiveWords.json", "x19": "third_party/netease-sensitive-words/upstream/X19SensitiveWords.json", "license": "third_party/netease-sensitive-words/LICENSE"}
	tmp, err := os.MkdirTemp("", "openaudit-netease-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	for k, b := range m {
		if err := os.WriteFile(filepath.Join(tmp, k), b, 0600); err != nil {
			return err
		}
	}
	backups := []string{}
	for k, t := range targets {
		if err := os.MkdirAll(filepath.Dir(t), 0750); err != nil {
			return err
		}
		bak := t + ".bak." + time.Now().UTC().Format("20060102150405")
		if _, err := os.Stat(t); err == nil {
			if err := os.Rename(t, bak); err != nil {
				return err
			}
			backups = append(backups, bak)
		}
		if err := os.Rename(filepath.Join(tmp, k), t); err != nil {
			return fmt.Errorf("replace failed; retained backups: %v: %w", backups, err)
		}
	}
	for _, b := range backups {
		_ = os.Remove(b)
	}
	return nil
}

func verify(write bool, retrieved string) error {
	if retrieved == "" {
		if old, err := readManifest(); err == nil {
			retrieved = old.RetrievalTimestamp
		} else {
			retrieved = time.Now().UTC().Format(time.RFC3339)
		}
	}
	m, outputs, err := buildManifest(retrieved)
	if err != nil {
		return err
	}
	if write {
		for p, b := range outputs {
			if err := os.MkdirAll(filepath.Dir(p), 0750); err != nil {
				return err
			}
			if err := os.WriteFile(p, b, 0600); err != nil {
				return err
			}
		}
		mb, _ := json.MarshalIndent(m, "", "  ")
		mb = append(mb, '\n')
		if err := os.WriteFile("third_party/netease-sensitive-words/SOURCE.json", mb, 0600); err != nil {
			return err
		}
		return nil
	}
	if err := validateManifest(m); err != nil {
		return err
	}
	for p, b := range outputs {
		old, err := readGeneratedArtifact(p)
		if err != nil {
			return err
		}
		if !bytes.Equal(old, b) {
			return fmt.Errorf("%s is stale or non-reproducible", p)
		}
	}
	committed, err := readManifest()
	if err != nil {
		return err
	}
	cb, _ := json.Marshal(committed)
	mb, _ := json.Marshal(m)
	if !bytes.Equal(cb, mb) {
		return errors.New("SOURCE.json is stale or invalid")
	}
	fmt.Printf("verified NetEase pinned artifacts: g79=%s x19=%s\n", m.Datasets[0].GeneratedPackSHA256, m.Datasets[1].GeneratedPackSHA256)
	return nil
}
func readGeneratedArtifact(path string) ([]byte, error) {
	switch path {
	case "data/bundled/netease-g79.json.gz":
		return os.ReadFile("data/bundled/netease-g79.json.gz")
	case "data/bundled/netease-g79.report.json":
		return os.ReadFile("data/bundled/netease-g79.report.json")
	case "data/bundled/netease-x19.json.gz":
		return os.ReadFile("data/bundled/netease-x19.json.gz")
	case "data/bundled/netease-x19.report.json":
		return os.ReadFile("data/bundled/netease-x19.report.json")
	default:
		return nil, fmt.Errorf("unsafe generated artifact path %q", path)
	}
}

func readSnapshot(dataset string) ([]byte, error) {
	switch dataset {
	case "g79":
		return os.ReadFile("third_party/netease-sensitive-words/upstream/G79SensitiveWords.json")
	case "x19":
		return os.ReadFile("third_party/netease-sensitive-words/upstream/X19SensitiveWords.json")
	default:
		return nil, fmt.Errorf("unknown dataset %q", dataset)
	}
}

func buildManifest(retrieved string) (Manifest, map[string][]byte, error) {
	ts, err := time.Parse(time.RFC3339, deterministicTimestamp)
	if err != nil {
		return Manifest{}, nil, err
	}
	if _, err := time.Parse(time.RFC3339, retrieved); err != nil {
		return Manifest{}, nil, err
	}
	outs := map[string][]byte{}
	m := Manifest{SchemaVersion: manifestSchema, Provider: bundled.ProviderNetEase, UpstreamRepository: repoURL, PinnedCommit: pinnedCommit, RetrievalTimestamp: retrieved, DeterministicSourceTimestamp: deterministicTimestamp, LicenseIdentifier: "GPL-3.0-only", GeneratorName: generator, GeneratorVersion: generatorVersion}
	for _, ds := range []string{"g79", "x19"} {
		b, err := readSnapshot(ds)
		if err != nil {
			return m, nil, err
		}
		packPath := fmt.Sprintf("data/bundled/netease-%s.json.gz", ds)
		reportPath := fmt.Sprintf("data/bundled/netease-%s.report.json", ds)
		pack, rep, _, gz, err := bundled.BuildPack(b, opts(ds, packPath, reportPath, ts))
		if err != nil {
			return m, nil, err
		}
		rb, err := bundled.MarshalReport(rep)
		if err != nil {
			return m, nil, err
		}
		outs[packPath] = gz
		outs[reportPath] = rb
		entry := DatasetEntry{Dataset: ds, SourcePath: allow[ds], SourceSHA256: sha(b), SourceByteSize: int64(len(b)), SourceRuleCount: rep.TotalSourceRules, GeneratedPackPath: packPath, GeneratedPackSHA256: sha(gz), GeneratedPackByteSize: int64(len(gz)), GeneratedReportPath: reportPath, GeneratedReportSHA256: sha(rb), GeneratedReportByteSize: int64(len(rb)), ImportStatistics: ImportStats{rep.TotalSourceRules, rep.ParsedRules, rep.ImportedRecords, rep.EmptyRecords, rep.MalformedRecords, rep.UnknownRecords, rep.DuplicateIdentities, rep.DuplicateRegexContent, rep.CountsByGroup}, RE2CompatibilityStatistics: RE2Stats{rep.RE2CompatibleRules, rep.RE2IncompatibleRules}, IncompatibleReasonBreakdown: breakdown(rep)}
		if pack.Counts.TotalSourceRules != entry.SourceRuleCount {
			return m, nil, errors.New("inconsistent pack/report provenance")
		}
		m.Datasets = append(m.Datasets, entry)
		m.Sources = append(m.Sources, SourceEntry{Path: allow[ds], SHA256: sha(b), ByteSize: int64(len(b)), RuleCount: rep.TotalSourceRules})
	}
	lb, err := os.ReadFile("third_party/netease-sensitive-words/LICENSE")
	if err != nil {
		return m, nil, err
	}
	m.Sources = append(m.Sources, SourceEntry{Path: "LICENSE", SHA256: sha(lb), ByteSize: int64(len(lb))})
	sort.Slice(m.Sources, func(i, j int) bool { return m.Sources[i].Path < m.Sources[j].Path })
	return m, outs, nil
}
func opts(ds, pack, report string, ts ...time.Time) bundled.Options {
	t := time.Time{}
	if len(ts) > 0 {
		t = ts[0]
	}
	path := allow[ds]
	return bundled.Options{Dataset: ds, SourceRepository: repoURL, SourceCommit: pinnedCommit, SourceFilePath: path, OutputPath: pack, ReportPath: report, Timestamp: t, LicenseIdentifier: "GPL-3.0-only"}
}
func breakdown(r bundled.Report) map[string]int {
	m := map[string]int{}
	for _, f := range r.CompatibilityFailures {
		h := f.FeatureHint
		if h == "" {
			h = "unknown"
		}
		m[h]++
	}
	if len(m) == 0 {
		return nil
	}
	return m
}
func readManifest() (Manifest, error) {
	b, err := os.ReadFile("third_party/netease-sensitive-words/SOURCE.json")
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}
func validateManifest(m Manifest) error {
	if m.SchemaVersion != manifestSchema {
		return errors.New("unknown critical SOURCE.json schema version")
	}
	if m.Provider != bundled.ProviderNetEase || m.PinnedCommit != pinnedCommit || m.LicenseIdentifier != "GPL-3.0-only" {
		return errors.New("manifest provenance mismatch")
	}
	seen := map[string]bool{}
	for _, d := range m.Datasets {
		if seen[d.Dataset] {
			return errors.New("duplicate dataset entry")
		}
		seen[d.Dataset] = true
		for _, h := range []string{d.SourceSHA256, d.GeneratedPackSHA256, d.GeneratedReportSHA256} {
			if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(h) {
				return fmt.Errorf("malformed hash for %s", d.Dataset)
			}
		}
		if strings.Contains(d.GeneratedPackPath, "..") || strings.Contains(d.GeneratedReportPath, "..") {
			return errors.New("unsafe generated path")
		}
		sb, err := os.ReadFile("third_party/netease-sensitive-words/upstream/" + filepath.Base(d.SourcePath))
		if err != nil {
			return err
		}
		if sha(sb) != d.SourceSHA256 {
			return fmt.Errorf("source hash mismatch for %s", d.Dataset)
		}
		pb, err := os.ReadFile(d.GeneratedPackPath)
		if err != nil {
			return err
		}
		if sha(pb) != d.GeneratedPackSHA256 {
			return fmt.Errorf("pack hash mismatch for %s", d.Dataset)
		}
		rb, err := os.ReadFile(d.GeneratedReportPath)
		if err != nil {
			return err
		}
		if sha(rb) != d.GeneratedReportSHA256 {
			return fmt.Errorf("report hash mismatch for %s", d.Dataset)
		}
	}
	return nil
}
func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
