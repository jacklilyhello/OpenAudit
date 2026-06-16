package rulehistory

import "testing"

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
	s := New(t.TempDir()+"/h.jsonl", 2)
	_ = s.Append(Change{ChangeID: "1", Action: ActionCreate, RuleID: "a", Actor: "api"})
	_ = s.Append(Change{ChangeID: "2", Action: ActionUpdate, RuleID: "b", Actor: "api"})
	_ = s.Append(Change{ChangeID: "3", Action: ActionDelete, RuleID: "a", Actor: "api"})
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
	b := NewBatchStore(t.TempDir() + "/b.jsonl")
	if err := b.AppendBatch(ImportBatch{BatchID: "x", Source: "s", Status: "dry_run", DryRun: true}); err != nil {
		t.Fatal(err)
	}
	xs, count, err := b.List(BatchFilter{Status: "dry_run"})
	if err != nil || count != 1 || xs[0].BatchID != "x" {
		t.Fatalf("list %+v %d %v", xs, count, err)
	}
	if _, ok, _ := b.Get("x"); !ok {
		t.Fatal("get failed")
	}
}
