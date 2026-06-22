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
	if c.BundledRules.NetEase.Mode != "re2" || !c.BundledRules.NetEase.Groups.Shield || !c.BundledRules.NetEase.Groups.Intercept || c.BundledRules.NetEase.Groups.Replace {
		t.Fatal("bad defaults")
	}
}
func TestBundledYAMLAndEnv(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "c.yml")
	os.WriteFile(cfg, []byte("bundled_rules:\n  enabled: true\n  data_dir: /tmp/bundled\n  netease:\n    enabled: true\n    mode: pcre2\n    datasets:\n      g79: true\n    groups:\n      replace: true\n"), 0600)
	c, err := Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !c.BundledRules.Enabled || c.BundledRules.NetEase.Mode != "pcre2" || !c.BundledRules.NetEase.Datasets.G79 || !c.BundledRules.NetEase.Groups.Replace {
		t.Fatal("yaml not loaded")
	}
	t.Setenv("OPENAUDIT_BUNDLED_RULES_NETEASE_DATASETS_X19", "true")
	c, err = Load(cfg)
	if err != nil || !c.BundledRules.NetEase.Datasets.X19 {
		t.Fatalf("env: %v", err)
	}
}
func TestBundledInvalidEnvModePath(t *testing.T) {
	t.Setenv("OPENAUDIT_BUNDLED_RULES_ENABLED", "notbool")
	if _, err := Load(""); err == nil {
		t.Fatal("bad bool accepted")
	}
	t.Setenv("OPENAUDIT_BUNDLED_RULES_ENABLED", "")
	t.Setenv("OPENAUDIT_BUNDLED_RULES_NETEASE_MODE", "full")
	if _, err := Load(""); err == nil {
		t.Fatal("bad mode accepted")
	}
	t.Setenv("OPENAUDIT_BUNDLED_RULES_NETEASE_MODE", "re2")
	t.Setenv("OPENAUDIT_BUNDLED_RULES_DATA_DIR", "../x")
	if _, err := Load(""); err == nil {
		t.Fatal("bad path accepted")
	}
}
