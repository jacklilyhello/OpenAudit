package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openaudit/openaudit/internal/bundled"
	"github.com/openaudit/openaudit/internal/config"
)

const testSHA = "0123456789abcdef0123456789abcdef01234567"

func makePack(t *testing.T, dir, dataset, body string) {
	t.Helper()
	_, _, _, gz, err := bundled.BuildPack([]byte(body), bundled.Options{Dataset: dataset, SourceRepository: "https://example.test/repo", SourceCommit: testSHA, SourceFilePath: "SensitiveWords/" + dataset + ".json", Timestamp: time.Unix(1, 0).UTC(), LicenseIdentifier: "GPL-3.0-only"})
	if err != nil {
		t.Fatal(err)
	}
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
