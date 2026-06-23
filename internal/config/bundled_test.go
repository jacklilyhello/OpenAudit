package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBundledDefaultsDisabled(t *testing.T) {
	c := Defaults()
	if c.BundledRules.Enabled || c.BundledRules.NetEase.Enabled || c.BundledRules.NetEase.Datasets.G79 || c.BundledRules.NetEase.Datasets.X19 {
		t.Fatal("defaults enabled")
	}
	if c.BundledRules.NetEase.Mode != "re2" || c.BundledRules.NetEase.RegexEngine != "re2" || !c.BundledRules.NetEase.Groups.Shield || !c.BundledRules.NetEase.Groups.Intercept || c.BundledRules.NetEase.Groups.Replace {
		t.Fatal("bad defaults")
	}
}
func TestBundledYAMLAndEnv(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "c.yml")
	os.WriteFile(cfg, []byte("bundled_rules:\n  enabled: true\n  data_dir: /tmp/bundled\n  netease:\n    enabled: true\n    regex_engine: pcre2\n    datasets:\n      g79: true\n    groups:\n      replace: true\n"), 0600)
	c, err := Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !c.BundledRules.Enabled || c.BundledRules.NetEase.RegexEngine != "pcre2" || !c.BundledRules.NetEase.Datasets.G79 || !c.BundledRules.NetEase.Groups.Replace {
		t.Fatal("yaml not loaded")
	}
	t.Setenv("OPENAUDIT_BUNDLED_RULES_NETEASE_REGEX_ENGINE", "re2")
	t.Setenv("OPENAUDIT_BUNDLED_RULES_NETEASE_DATASETS_X19", "true")
	c, err = Load(cfg)
	if err != nil || !c.BundledRules.NetEase.Datasets.X19 || c.BundledRules.NetEase.RegexEngine != "re2" {
		t.Fatalf("env: %v", err)
	}
	t.Setenv("OPENAUDIT_BUNDLED_RULES_NETEASE_DATASETS_X19", "   ")
	c, err = Load(cfg)
	if err != nil {
		t.Fatalf("blank env should be ignored: %v", err)
	}
}
func TestBundledInvalidBoolean(t *testing.T) {
	t.Setenv("OPENAUDIT_BUNDLED_RULES_ENABLED", "notbool")
	if _, err := Load(""); err == nil {
		t.Fatal("bad bool accepted")
	}
}
func TestBundledInvalidMode(t *testing.T) {
	t.Setenv("OPENAUDIT_BUNDLED_RULES_NETEASE_MODE", "full")
	if _, err := Load(""); err == nil {
		t.Fatal("bad mode accepted")
	}
}
func TestBundledNULPath(t *testing.T) {
	c := Defaults()
	c.BundledRules.DataDir = "bad\x00path"
	if err := Validate(c); err == nil {
		t.Fatal("NUL path accepted")
	}
}
func TestBundledParentTraversalPath(t *testing.T) {
	t.Setenv("OPENAUDIT_BUNDLED_RULES_DATA_DIR", "../x")
	if _, err := Load(""); err == nil {
		t.Fatal("traversal path accepted")
	}
}
func TestBundledValidPaths(t *testing.T) {
	t.Setenv("OPENAUDIT_BUNDLED_RULES_DATA_DIR", "/tmp/openaudit-bundled")
	if _, err := Load(""); err != nil {
		t.Fatalf("absolute path rejected: %v", err)
	}
	t.Setenv("OPENAUDIT_BUNDLED_RULES_DATA_DIR", "./data..cache/bundled")
	if _, err := Load(""); err != nil {
		t.Fatalf("harmless dots rejected: %v", err)
	}
}
