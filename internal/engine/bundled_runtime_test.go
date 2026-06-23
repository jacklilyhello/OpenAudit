package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openaudit/openaudit/internal/bundled"
	"github.com/openaudit/openaudit/internal/config"
	"github.com/openaudit/openaudit/internal/model"
	"github.com/openaudit/openaudit/internal/rules"
)

const testSHA = "0123456789abcdef0123456789abcdef01234567"

func packBytes(t *testing.T, dataset, body string) []byte {
	t.Helper()
	_, _, _, gz, err := bundled.BuildPack([]byte(body), bundled.Options{Dataset: dataset, SourceRepository: "https://example.test/repo", SourceCommit: testSHA, SourceFilePath: "SensitiveWords/" + dataset + ".json", Timestamp: time.Unix(1, 0).UTC(), LicenseIdentifier: "GPL-3.0-only"})
	if err != nil {
		t.Fatal(err)
	}
	return gz
}

func makePack(t *testing.T, dir, dataset, body string) {
	t.Helper()
	gz := packBytes(t, dataset, body)
	name := bundled.NetEaseG79Filename
	if dataset == "x19" {
		name = bundled.NetEaseX19Filename
	}
	if err := os.WriteFile(filepath.Join(dir, name), gz, 0600); err != nil {
		t.Fatal(err)
	}
}

func bundledCfg(dir string) config.BundledRulesConfig {
	return config.BundledRulesConfig{Enabled: true, DataDir: dir, NetEase: config.NetEaseBundledConfig{Enabled: true, Mode: "re2", Datasets: config.NetEaseDatasetsConfig{G79: true}, Groups: config.NetEaseGroupsConfig{Shield: true, Intercept: true}}}
}

func TestBundledDefaultDisabledNoFilesystemReads(t *testing.T) {
	local := t.TempDir()
	write(t, filepath.Join(local, "k.yml"), "id: k\ntype: keyword\ncategory: c\nkeywords: [local]\n")
	cfg := config.Defaults().BundledRules
	cfg.DataDir = filepath.Join(t.TempDir(), "missing")
	e, err := NewWithOptions(local, Options{BundledRules: &cfg})
	if err != nil {
		t.Fatal(err)
	}
	if !e.Audit("local", true).Matched {
		t.Fatal("local rule not active")
	}
	if e.Stats().BundledRules == nil {
		t.Fatal("disabled bundled provider status should be exposed when options are supplied")
	}
}

func TestBundledG79X19GroupsAndMatch(t *testing.T) {
	local := t.TempDir()
	write(t, filepath.Join(local, "k.yml"), "id: k\ntype: keyword\ncategory: c\nkeywords: [local]\n")
	dir := t.TempDir()
	makePack(t, dir, "g79", `{"regex":{"shield":{"1":"g79match"},"replace":{"2":"replacehit"},"nickname":{"3":"nickhit"},"remind":{"4":"remindhit"}},"settings":{}}`)
	makePack(t, dir, "x19", `{"regex":{"intercept":{"1":"x19match"}},"settings":{}}`)
	cfg := bundledCfg(dir)
	cfg.NetEase.Datasets.X19 = true
	cfg.NetEase.Groups.Replace = true
	cfg.NetEase.Groups.Nickname = true
	cfg.NetEase.Groups.Remind = true
	e, err := NewWithOptions(local, Options{BundledRules: &cfg})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"g79match", "x19match", "replacehit", "nickhit", "remindhit"} {
		if !e.Audit(s, true).Matched {
			t.Fatalf("%s did not match", s)
		}
	}
	st := e.Stats()
	if st.Regex != 5 || st.BundledRules == nil {
		t.Fatalf("bad stats %#v", st)
	}
}

func TestBundledPackRuleEnabledDoesNotOverrideConfig(t *testing.T) {
	local := t.TempDir()
	dir := t.TempDir()
	makePack(t, dir, "g79", `{"regex":{"replace":{"1":"replacehit"}},"settings":{}}`)
	cfg := bundledCfg(dir)
	e, err := NewWithOptions(local, Options{BundledRules: &cfg})
	if err != nil {
		t.Fatal(err)
	}
	if e.Audit("replacehit", true).Matched {
		t.Fatal("replace should be config disabled")
	}
	cfg.NetEase.Groups.Replace = true
	e, err = NewWithOptions(local, Options{BundledRules: &cfg})
	if err != nil {
		t.Fatal(err)
	}
	if !e.Audit("replacehit", true).Matched {
		t.Fatal("replace should be config enabled despite PackRule.Enabled false")
	}
}

func TestBundledIncompatibleSkippedAndPCRE2Mode(t *testing.T) {
	local := t.TempDir()
	dir := t.TempDir()
	makePack(t, dir, "g79", `{"regex":{"shield":{"1":"okhit","2":"a(?=b)","3":"(?<=a)b","4":"(a)\\\\1"}},"settings":{}}`)
	cfg := bundledCfg(dir)
	e, err := NewWithOptions(local, Options{BundledRules: &cfg})
	if err != nil {
		t.Fatal(err)
	}
	if !e.Audit("okhit", true).Matched || e.Audit("ab", true).Matched {
		t.Fatal("bad incompatible handling")
	}
	cfg.NetEase.Mode = "pcre2"
	if _, err := NewWithOptions(local, Options{BundledRules: &cfg}); err == nil || !strings.Contains(err.Error(), "PCRE2 runtime support is not included") {
		t.Fatalf("expected pcre2 unsupported, got %v", err)
	}
	cfg.NetEase.Enabled = false
	if _, err := NewWithOptions(local, Options{BundledRules: &cfg}); err != nil {
		t.Fatalf("disabled pcre2 should not fail: %v", err)
	}
}

func TestBundledFailuresPreserveOldState(t *testing.T) {
	local := t.TempDir()
	dir := t.TempDir()
	makePack(t, dir, "g79", `{"regex":{"shield":{"1":"oldhit"}},"settings":{}}`)
	cfg := bundledCfg(dir)
	e, err := NewWithOptions(local, Options{BundledRules: &cfg})
	if err != nil {
		t.Fatal(err)
	}
	if !e.Audit("oldhit", true).Matched {
		t.Fatal("old not matched")
	}
	if err := os.Remove(filepath.Join(dir, bundled.NetEaseG79Filename)); err != nil {
		t.Fatal(err)
	}
	if err := e.Reload(); err == nil {
		t.Fatal("missing pack should fail")
	}
	if !e.Audit("oldhit", true).Matched {
		t.Fatal("failed reload replaced matchers")
	}
}

func TestBundledWrongDatasetSymlinkAndCollision(t *testing.T) {
	local := t.TempDir()
	dir := t.TempDir()
	makePack(t, dir, "x19", `{"regex":{"shield":{"1":"x"}},"settings":{}}`)
	if err := os.Rename(filepath.Join(dir, bundled.NetEaseX19Filename), filepath.Join(dir, bundled.NetEaseG79Filename)); err != nil {
		t.Fatal(err)
	}
	cfg := bundledCfg(dir)
	if _, err := NewWithOptions(local, Options{BundledRules: &cfg}); err == nil {
		t.Fatal("wrong dataset accepted")
	}
	os.Remove(filepath.Join(dir, bundled.NetEaseG79Filename))
	outside := filepath.Join(t.TempDir(), "p.gz")
	makePack(t, filepath.Dir(outside), "g79", `{"regex":{"shield":{"1":"x"}},"settings":{}}`)
	os.Rename(filepath.Join(filepath.Dir(outside), bundled.NetEaseG79Filename), outside)
	if err := os.Symlink(outside, filepath.Join(dir, bundled.NetEaseG79Filename)); err != nil {
		t.Fatal(err)
	}
	if _, err := NewWithOptions(local, Options{BundledRules: &cfg}); err == nil {
		t.Fatal("symlink accepted")
	}
	os.Remove(filepath.Join(dir, bundled.NetEaseG79Filename))
	makePack(t, dir, "g79", `{"regex":{"shield":{"1":"x"}},"settings":{}}`)
	write(t, filepath.Join(local, "dup.yml"), "id: netease_g79_shield_d374964aa1a38e83\ntype: keyword\ncategory: c\nkeywords: [dup]\n")
	if _, err := NewWithOptions(local, Options{BundledRules: &cfg}); err == nil {
		t.Fatal("collision accepted")
	}
}

func TestBundledRuntimeGzipFailuresAndOversize(t *testing.T) {
	local := t.TempDir()
	dir := t.TempDir()
	good := packBytes(t, "g79", `{"regex":{"shield":{"1":"ok"}},"settings":{}}`)
	name := filepath.Join(dir, bundled.NetEaseG79Filename)
	corrupt := append([]byte{}, good...)
	corrupt[len(corrupt)-8] ^= 0xff
	if err := os.WriteFile(name, corrupt, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := bundledCfg(dir)
	if _, err := NewWithOptions(local, Options{BundledRules: &cfg}); err == nil {
		t.Fatal("corrupt gzip accepted")
	}
	if err := os.WriteFile(name, good[:len(good)/2], 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewWithOptions(local, Options{BundledRules: &cfg}); err == nil {
		t.Fatal("truncated gzip accepted")
	}
	big := make([]byte, bundled.DefaultLimits().CompressedPackBytes+1)
	if err := os.WriteFile(name, big, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewWithOptions(local, Options{BundledRules: &cfg}); err == nil {
		t.Fatal("oversized pack accepted")
	}
}

func TestBundledSuccessfulReloadAndSnapshotConfig(t *testing.T) {
	local := t.TempDir()
	dir := t.TempDir()
	makePack(t, dir, "g79", `{"regex":{"shield":{"1":"oldhit"}},"settings":{}}`)
	cfg := bundledCfg(dir)
	e, err := NewWithOptions(local, Options{BundledRules: &cfg})
	if err != nil {
		t.Fatal(err)
	}
	cfg.Enabled = false
	cfg.NetEase.Datasets.G79 = false
	makePack(t, dir, "g79", `{"regex":{"shield":{"1":"newhit"}},"settings":{}}`)
	if err := e.Reload(); err != nil {
		t.Fatal(err)
	}
	if e.Audit("oldhit", true).Matched || !e.Audit("newhit", true).Matched {
		t.Fatal("reload did not use engine snapshot and new pack")
	}
	if e.Stats().BundledRules == nil {
		t.Fatal("snapshot lost bundled stats")
	}
}

func TestBundledFailedReloadPreservesStatsFieldForField(t *testing.T) {
	local := t.TempDir()
	dir := t.TempDir()
	makePack(t, dir, "g79", `{"regex":{"shield":{"1":"oldhit"},"replace":{"2":"replacehit"}},"settings":{}}`)
	cfg := bundledCfg(dir)
	cfg.NetEase.Groups.Replace = true
	e, err := NewWithOptions(local, Options{BundledRules: &cfg})
	if err != nil {
		t.Fatal(err)
	}
	oldRules := e.Rules()
	oldStats := e.Stats()
	if !e.Audit("oldhit replacehit", true).Matched {
		t.Fatal("expected old match")
	}
	if err := os.WriteFile(filepath.Join(dir, bundled.NetEaseG79Filename), []byte("bad gzip"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := e.Reload(); err == nil {
		t.Fatal("bad reload succeeded")
	}
	if !reflect.DeepEqual(oldRules, e.Rules()) {
		t.Fatal("rules changed after failed reload")
	}
	if !reflect.DeepEqual(oldStats, e.Stats()) {
		t.Fatalf("stats changed after failed reload\nold=%#v\nnew=%#v", oldStats, e.Stats())
	}
	if !e.Audit("oldhit replacehit", true).Matched {
		t.Fatal("old matches not preserved")
	}
}

func TestBundledConcurrentAuditStatsDuringReload(t *testing.T) {
	local := t.TempDir()
	dir := t.TempDir()
	makePack(t, dir, "g79", `{"regex":{"shield":{"1":"hit0"}},"settings":{}}`)
	cfg := bundledCfg(dir)
	e, err := NewWithOptions(local, Options{BundledRules: &cfg})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = e.Audit("hit0 hit1", true)
					_ = e.Stats()
				}
			}
		}()
	}
	for i := 0; i < 20; i++ {
		if i%2 == 0 {
			makePack(t, dir, "g79", `{"regex":{"shield":{"1":"hit1"}},"settings":{}}`)
			_ = e.Reload()
		} else {
			_ = os.WriteFile(filepath.Join(dir, bundled.NetEaseG79Filename), []byte("invalid"), 0600)
			_ = e.Reload()
		}
	}
	close(stop)
	wg.Wait()
}

func TestBundledStatsJSONCompatibilityAndInvariants(t *testing.T) {
	local := t.TempDir()
	e, err := New(local)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(e.Stats())
	if err != nil {
		t.Fatal(err)
	}
	if string(b) == "" || json.Valid(b) == false {
		t.Fatal("invalid stats json")
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["bundled_rules"]; ok {
		t.Fatal("engine.New stats unexpectedly include bundled_rules")
	}

	dir := t.TempDir()
	makePack(t, dir, "g79", `{"regex":{"shield":{"1":"ok","2":"a(?=b)"},"replace":{"3":"replacehit"}},"settings":{}}`)
	cfg := bundledCfg(dir)
	e, err = NewWithOptions(local, Options{BundledRules: &cfg})
	if err != nil {
		t.Fatal(err)
	}
	st := e.Stats()
	b, err = json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["bundled_rules"]; !ok {
		t.Fatal("explicit bundled options should include bundled_rules stats")
	}
	br := st.BundledRules.(bundled.RuntimeStats)
	ps := br.Providers[bundled.ProviderNetEase]
	if ps.TotalPackRulesExamined != 3 || ps.RE2CompatibleRules != 2 || ps.RE2IncompatibleRules != 1 || ps.ConfigurationDisabledRules != 1 || ps.ActivatedRules != 1 {
		t.Fatalf("bad invariant stats: %#v", ps)
	}
	if ps.RE2CompatibleRules+ps.RE2IncompatibleRules != ps.TotalPackRulesExamined {
		t.Fatal("compatibility totals drifted")
	}
}

func TestBundledTypedProvenanceBehaviorAndHitMetadata(t *testing.T) {
	local := t.TempDir()
	dir := t.TempDir()
	makePack(t, dir, "g79", `{"regex":{"replace":{"42":"replacehit"},"remind":{"43":"remindhit"}},"settings":{}}`)
	makePack(t, dir, "x19", `{"regex":{"nickname":{"7":"nickhit"}},"settings":{}}`)
	cfg := bundledCfg(dir)
	cfg.NetEase.Datasets.X19 = true
	cfg.NetEase.Groups.Replace = true
	cfg.NetEase.Groups.Remind = true
	cfg.NetEase.Groups.Nickname = true
	e, err := NewWithOptions(local, Options{BundledRules: &cfg})
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, r := range e.Rules() {
		if r.Provenance == nil || r.Behavior == nil || len(r.Patterns) != 1 {
			continue
		}
		key := r.Provenance.Dataset + "/" + r.Provenance.Group + "/" + r.Provenance.UpstreamID + "/" + r.Patterns[0] + "/" + r.Behavior.UpstreamBehavior
		found[key] = true
		if r.Provenance.Provider != bundled.ProviderNetEase {
			t.Fatalf("provider not preserved: %#v", r.Provenance)
		}
		if r.Provenance.Group == "replace" && r.Behavior.ReplacementTextAvailable {
			t.Fatal("replacement text availability invented")
		}
	}
	for _, want := range []string{"g79/replace/42/replacehit/replace", "g79/remind/43/remindhit/remind", "x19/nickname/7/nickhit/nickname"} {
		if !found[want] {
			t.Fatalf("missing typed metadata %s in %#v", want, found)
		}
	}
	hits := e.Audit("replacehit", true).Hits
	if len(hits) == 0 || hits[0].Provenance == nil || hits[0].Behavior == nil || hits[0].Provenance.UpstreamID != "42" || hits[0].Behavior.UpstreamBehavior != "replace" {
		t.Fatalf("hit metadata not preserved: %#v", hits)
	}
}

func TestBundledRulesSnapshotMutationIsolation(t *testing.T) {
	local := t.TempDir()
	write(t, filepath.Join(local, "mapping.yml"), `id: mapping
type: pinyin
category: c
mapping:
  原文: [yuanwen]
`)
	dir := t.TempDir()
	makePack(t, dir, "g79", `{"regex":{"replace":{"42":"replacehit"}},"settings":{}}`)
	cfg := bundledCfg(dir)
	cfg.NetEase.Groups.Replace = true
	e, err := NewWithOptions(local, Options{BundledRules: &cfg})
	if err != nil {
		t.Fatal(err)
	}
	rules1 := e.Rules()
	var bundledRule, mappingRule *rules.Rule
	for i := range rules1 {
		if rules1[i].Provenance != nil {
			bundledRule = &rules1[i]
		}
		if rules1[i].ID == "mapping" {
			mappingRule = &rules1[i]
		}
	}
	if bundledRule == nil || bundledRule.Behavior == nil || mappingRule == nil || len(mappingRule.Mapping["原文"]) == 0 {
		t.Fatalf("missing snapshot rules: %#v", rules1)
	}
	bundledRule.Provenance.Provider = "mutated"
	bundledRule.Behavior.UpstreamBehavior = "mutated"
	bundledRule.Behavior.ReplacementTextAvailable = true
	bundledRule.Tags[0] = "mutated"
	bundledRule.Patterns[0] = "mutated"
	enabled := false
	bundledRule.Enabled = &enabled
	mappingRule.Mapping["原文"][0] = "mutated"
	rules2 := e.Rules()
	for _, r := range rules2 {
		if r.Provenance != nil && (r.Provenance.Provider != bundled.ProviderNetEase || r.Behavior.UpstreamBehavior != "replace" || r.Behavior.ReplacementTextAvailable || r.Tags[0] == "mutated" || r.Patterns[0] != "replacehit" || !r.IsEnabled()) {
			t.Fatalf("bundled rule snapshot mutation leaked: %#v", r)
		}
		if r.ID == "mapping" && r.Mapping["原文"][0] != "yuanwen" {
			t.Fatalf("mapping snapshot mutation leaked: %#v", r.Mapping)
		}
	}
}

func TestBundledAuditHitMutationIsolationAndExplanationTrimming(t *testing.T) {
	local := t.TempDir()
	dir := t.TempDir()
	makePack(t, dir, "g79", `{"regex":{"replace":{"42":"replacehit"}},"settings":{}}`)
	cfg := bundledCfg(dir)
	cfg.NetEase.Groups.Replace = true
	e, err := NewWithOptions(local, Options{BundledRules: &cfg})
	if err != nil {
		t.Fatal(err)
	}
	defaultRes := e.Audit("replacehit", true)
	if len(defaultRes.Hits) == 0 || defaultRes.Hits[0].Provenance == nil || defaultRes.Hits[0].Behavior == nil {
		t.Fatalf("default audit missing metadata: %#v", defaultRes.Hits)
	}
	defaultRes.Hits[0].Provenance.Provider = "mutated"
	defaultRes.Hits[0].Behavior.UpstreamBehavior = "mutated"
	again := e.Audit("replacehit", true)
	if again.Hits[0].Provenance.Provider != bundled.ProviderNetEase || again.Hits[0].Behavior.UpstreamBehavior != "replace" {
		t.Fatalf("hit mutation leaked: %#v", again.Hits[0])
	}
	include := true
	withExp := e.AuditWithOptions("replacehit", model.AuditOptions{Normalize: &include, IncludeExplanations: &include})
	if withExp.Hits[0].Provenance == nil || withExp.Hits[0].Behavior == nil {
		t.Fatalf("include explanations should include metadata: %#v", withExp.Hits[0])
	}
	without := false
	trimmed := e.AuditWithOptions("replacehit", model.AuditOptions{Normalize: &include, IncludeExplanations: &without})
	if len(trimmed.Hits) == 0 || trimmed.Hits[0].Provenance != nil || trimmed.Hits[0].Behavior != nil || trimmed.Hits[0].RuleID == "" || trimmed.Hits[0].Action == "" {
		t.Fatalf("metadata not trimmed or core fields missing: %#v", trimmed.Hits)
	}
	b, err := json.Marshal(trimmed)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "provenance") || strings.Contains(string(b), "behavior") {
		t.Fatalf("trimmed JSON exposed metadata: %s", b)
	}
	write(t, filepath.Join(local, "local.yml"), "id: local\ntype: keyword\ncategory: c\nkeywords: [local]\n")
	le, err := New(local)
	if err != nil {
		t.Fatal(err)
	}
	localRes := le.Audit("local", true)
	if len(localRes.Hits) == 0 || localRes.Hits[0].Provenance != nil || localRes.Hits[0].Behavior != nil {
		t.Fatalf("local rule metadata changed: %#v", localRes.Hits)
	}
}

func TestBundledStatsMutationIsolation(t *testing.T) {
	local := t.TempDir()
	dir := t.TempDir()
	makePack(t, dir, "g79", `{"regex":{"shield":{"1":"ok","2":"a(?=b)"}},"settings":{}}`)
	cfg := bundledCfg(dir)
	e, err := NewWithOptions(local, Options{BundledRules: &cfg})
	if err != nil {
		t.Fatal(err)
	}
	st1 := e.Stats()
	br1 := st1.BundledRules.(bundled.RuntimeStats)
	br1.Providers[bundled.ProviderNetEase] = bundled.ProviderRuntimeStats{}
	st2 := e.Stats()
	br2 := st2.BundledRules.(bundled.RuntimeStats)
	if br2.Providers[bundled.ProviderNetEase].TotalPackRulesExamined == 0 {
		t.Fatalf("provider map mutation leaked: %#v", br2)
	}
	ps := br2.Providers[bundled.ProviderNetEase]
	ps.Groups["shield"] = 99
	ps.Datasets["g79"] = bundled.DatasetStats{}
	ps.IncompatibleCompatibilityHint["lookahead"] = 99
	br2.Providers[bundled.ProviderNetEase] = ps
	st3 := e.Stats()
	br3 := st3.BundledRules.(bundled.RuntimeStats)
	ps3 := br3.Providers[bundled.ProviderNetEase]
	if ps3.Groups["shield"] == 99 || !ps3.Datasets["g79"].Loaded || ps3.IncompatibleCompatibilityHint["lookahead"] == 99 {
		t.Fatalf("nested stats mutation leaked: %#v", ps3)
	}
}

func TestBundledConcurrentAuditRulesStatsDuringReload(t *testing.T) {
	local := t.TempDir()
	dir := t.TempDir()
	makePack(t, dir, "g79", `{"regex":{"shield":{"1":"hit0"}},"settings":{}}`)
	cfg := bundledCfg(dir)
	e, err := NewWithOptions(local, Options{BundledRules: &cfg})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = e.Audit("hit0 hit1", true)
					_ = e.Rules()
					_ = e.Stats()
				}
			}
		}()
	}
	for i := 0; i < 20; i++ {
		if i%2 == 0 {
			makePack(t, dir, "g79", `{"regex":{"shield":{"1":"hit1"}},"settings":{}}`)
		} else {
			_ = os.WriteFile(filepath.Join(dir, bundled.NetEaseG79Filename), []byte("invalid"), 0600)
		}
		_ = e.Reload()
	}
	close(stop)
	wg.Wait()
}

func copyCommittedPack(t *testing.T, dir, name string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "data", "bundled", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), b, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestCommittedNetEasePhaseCPacks(t *testing.T) {
	local := t.TempDir()
	dir := t.TempDir()
	copyCommittedPack(t, dir, bundled.NetEaseG79Filename)
	copyCommittedPack(t, dir, bundled.NetEaseX19Filename)
	cfg := config.Defaults().BundledRules
	cfg.DataDir = dir
	if e, err := NewWithOptions(local, Options{BundledRules: &cfg}); err != nil || e.Audit("暴政", true).Matched {
		t.Fatalf("default disabled should not match; err=%v", err)
	}
	cfg.Enabled = true
	cfg.NetEase.Enabled = true
	cfg.NetEase.Datasets.G79 = true
	e, err := NewWithOptions(local, Options{BundledRules: &cfg})
	if err != nil {
		t.Fatal(err)
	}
	if !e.Audit("暴政", true).Matched {
		t.Fatal("expected stable G79 upstream rule to match")
	}
	st := e.Stats().BundledRules.(bundled.RuntimeStats).Providers[bundled.ProviderNetEase]
	if !st.Datasets["g79"].Loaded || st.Datasets["x19"].Loaded || st.Datasets["g79"].LicenseIdentifier != "GPL-3.0-only" {
		t.Fatalf("bad G79 provenance stats: %#v", st.Datasets)
	}
	if st.RE2IncompatibleRules == 0 {
		t.Fatal("expected incompatible rules to remain reported")
	}
	if e.Audit("昵称测试", true).Matched {
		t.Fatal("disabled nickname group should not activate")
	}
	cfg.NetEase.Datasets.G79 = false
	cfg.NetEase.Datasets.X19 = true
	e, err = NewWithOptions(local, Options{BundledRules: &cfg})
	if err != nil {
		t.Fatal(err)
	}
	if !e.Audit("暴政", true).Matched {
		t.Fatal("expected stable X19 upstream rule to match")
	}
	st = e.Stats().BundledRules.(bundled.RuntimeStats).Providers[bundled.ProviderNetEase]
	if st.Datasets["g79"].Loaded || !st.Datasets["x19"].Loaded || st.Datasets["x19"].LicenseIdentifier != "GPL-3.0-only" {
		t.Fatalf("bad X19 provenance stats: %#v", st.Datasets)
	}
	cfg.NetEase.Datasets.G79 = true
	e, err = NewWithOptions(local, Options{BundledRules: &cfg})
	if err != nil {
		t.Fatal(err)
	}
	st = e.Stats().BundledRules.(bundled.RuntimeStats).Providers[bundled.ProviderNetEase]
	if !st.Datasets["g79"].Loaded || !st.Datasets["x19"].Loaded || st.ActivatedRules == 0 {
		t.Fatalf("expected both datasets loaded: %#v", st)
	}
	oldStats := e.Stats()
	if err := os.WriteFile(filepath.Join(dir, bundled.NetEaseG79Filename), []byte("bad gzip"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := e.Reload(); err == nil {
		t.Fatal("expected failed reload")
	}
	if !reflect.DeepEqual(oldStats, e.Stats()) || !e.Audit("暴政", true).Matched {
		t.Fatal("failed reload did not preserve old committed pack state")
	}
}
