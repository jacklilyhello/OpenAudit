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
