package rulehistory

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/openaudit/openaudit/internal/safepath"
)

func TestTextDiff(t *testing.T) {
	d := TextDiff("enabled: true\nkeywords: old\n", "enabled: false\nkeywords: old\nkeywords: new\n")
	if d.Summary.AddedLines != 2 || d.Summary.RemovedLines != 1 {
		t.Fatalf("bad summary: %+v", d)
	}
	d2 := TextDiff("a\nb\n", "b\na\n")
	if len(d2.Added) != 0 || len(d2.Removed) != 0 {
		t.Fatalf("diff should be deterministic set-style: %+v", d2)
	}
}
func TestStoreAppendListGetFiltersAndMax(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history", "h.jsonl")
	s := New(path, 2)
	_ = s.Append(Change{ChangeID: "1", Action: ActionCreate, RuleID: "a", Actor: "api"})
	_ = s.Append(Change{ChangeID: "2", Action: ActionUpdate, RuleID: "b", Actor: "api"})
	_ = s.Append(Change{ChangeID: "3", Action: ActionDelete, RuleID: "a", Actor: "api"})
	assertRuntimeFileAndDirModes(t, path)
	xs, count, err := s.List(Filter{Limit: 10})
	if err != nil || count != 2 || len(xs) != 2 {
		t.Fatalf("list %d %d %v", count, len(xs), err)
	}
	if _, ok, _ := s.Get("1"); ok {
		t.Fatal("max entries did not trim oldest")
	}
	xs, count, _ = s.List(Filter{RuleID: "a"})
	if count != 1 || xs[0].ChangeID != "3" {
		t.Fatalf("filter rule %+v", xs)
	}
	xs, count, _ = s.List(Filter{Action: "update"})
	if count != 1 || xs[0].ChangeID != "2" {
		t.Fatalf("filter action %+v", xs)
	}
}
func TestBatchStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "batches", "b.jsonl")
	b := NewBatchStore(path)
	if err := b.AppendBatch(ImportBatch{BatchID: "x", Source: "s", Status: "dry_run", DryRun: true}); err != nil {
		t.Fatal(err)
	}
	assertRuntimeFileAndDirModes(t, path)
	xs, count, err := b.List(BatchFilter{Status: "dry_run"})
	if err != nil || count != 1 || xs[0].BatchID != "x" {
		t.Fatalf("list %+v %d %v", xs, count, err)
	}
	if _, ok, _ := b.Get("x"); !ok {
		t.Fatal("get failed")
	}
}

func assertRuntimeFileAndDirModes(t *testing.T, path string) {
	t.Helper()
	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fileInfo.Mode().Perm(); got != safepath.RuntimeFilePerm {
		t.Fatalf("%s mode = %o want %o", path, got, safepath.RuntimeFilePerm)
	}
	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if got := dirInfo.Mode().Perm(); got != safepath.RuntimeDirPerm {
		t.Fatalf("%s mode = %o want %o", filepath.Dir(path), got, safepath.RuntimeDirPerm)
	}
}
