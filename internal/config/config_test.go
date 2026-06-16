package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultsAndFile(t *testing.T) {
	c, err := Load("")
	if err != nil || c.Server.Addr != ":8080" {
		t.Fatalf("defaults %#v %v", c, err)
	}
	p := filepath.Join(t.TempDir(), "c.yml")
	os.WriteFile(p, []byte("server:\n  addr: ':9090'\nlimits:\n  max_hits: 7\n"), 0644)
	c, err = Load(p)
	if err != nil || c.Server.Addr != ":9090" || c.Limits.MaxHits != 7 {
		t.Fatalf("override %#v %v", c, err)
	}
}
func TestEnv(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yml")
	os.WriteFile(p, []byte("rules:\n  data_dir: ./x\n"), 0644)
	t.Setenv("OPENAUDIT_CONFIG", p)
	c, _ := Load("")
	if c.Rules.DataDir != "./x" {
		t.Fatal(c.Rules.DataDir)
	}
}
