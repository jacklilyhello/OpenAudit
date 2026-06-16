package engine

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
}
func TestAuditAndMapping(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "k.yml"), "id: k\ntype: keyword\ncategory: c\nrisk_level: high\naction: block\nkeywords: [bad]\n")
	write(t, filepath.Join(dir, "p.yml"), "id: p\ntype: pinyin\ncategory: c\naction: review\nmapping:\n  法轮功: [flg]\n")
	e, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	res := e.Audit("bad flg", true)
	if !res.Matched || len(res.Hits) != 2 {
		t.Fatalf("bad audit %#v", res)
	}
}
func TestReloadFailureKeepsOldRules(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "r.yml")
	write(t, path, "id: k\ntype: keyword\ncategory: c\nkeywords: [good]\n")
	e, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	write(t, path, "id: r\ntype: regex\ncategory: c\npatterns: ['[']\n")
	if err := e.Reload(); err == nil {
		t.Fatal("expected reload failure")
	}
	if !e.Audit("good", true).Matched {
		t.Fatal("old rules were not kept")
	}
}
