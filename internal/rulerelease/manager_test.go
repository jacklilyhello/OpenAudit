package rulerelease

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/openaudit/openaudit/internal/rules"
	"github.com/openaudit/openaudit/internal/safepath"
)

func writeTestRule(t *testing.T, root, rel, body string) {
	t.Helper()
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), safepath.RuntimeDirPerm); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), safepath.RuntimeFilePerm); err != nil {
		t.Fatal(err)
	}
}

func testRule(id, word string) rules.Rule {
	return rules.Rule{ID: id, Type: "keyword", Category: "custom", RiskLevel: "medium", Action: "review", Keywords: []string{word}}
}

func TestLifecyclePublishSimulateAndRollback(t *testing.T) {
	root := t.TempDir()
	writeTestRule(t, root, "keywords/base.yml", "id: base\ntype: keyword\ncategory: base\nrisk_level: medium\naction: review\nkeywords: [baseword]\n")
	mgr := NewManager(root, nil)
	ctx := context.Background()
	if _, err := mgr.UpsertDraft(ctx, testRule("draft1", "draftword"), "tester"); err != nil {
		t.Fatal(err)
	}
	if rs, err := mgr.ListState(StatePublished); err != nil || len(rs) != 1 || rs[0].State != StatePublished {
		t.Fatalf("published defaults failed rs=%+v err=%v", rs, err)
	}
	staged, err := mgr.StageDraft(ctx, "draft1", "tester")
	if err != nil {
		t.Fatal(err)
	}
	if staged.State != StateStaged {
		t.Fatalf("state=%s", staged.State)
	}
	pubBefore, err := mgr.Simulate(SimulateRequest{Text: "draftword", Scope: StatePublished})
	if err != nil {
		t.Fatal(err)
	}
	if pubBefore.Result.Matched {
		t.Fatal("staged rule affected published simulation before publish")
	}
	stagedSim, err := mgr.Simulate(SimulateRequest{Text: "draftword", Scope: StateStaged})
	if err != nil {
		t.Fatal(err)
	}
	if !stagedSim.Result.Matched || stagedSim.MatchedRuleIDs[0] != "draft1" {
		t.Fatalf("staged simulation=%+v", stagedSim)
	}
	published := false
	res, err := mgr.Publish(ctx, "tester", "", func() error {
		published = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !published || res.Release.Version != "v1" || res.Release.RuleCount != 2 || res.Release.AddedCount != 1 {
		t.Fatalf("publish result=%+v published=%v", res.Release, published)
	}
	pubAfter, err := mgr.Simulate(SimulateRequest{Text: "draftword", Scope: StatePublished})
	if err != nil {
		t.Fatal(err)
	}
	if !pubAfter.Result.Matched {
		t.Fatal("published rule did not match after publish")
	}
	if _, err := mgr.UpsertDraft(ctx, testRule("draft2", "secondword"), "tester"); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.StageDraft(ctx, "draft2", "tester"); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Publish(ctx, "tester", "", nil); err != nil {
		t.Fatal(err)
	}
	rollback, err := mgr.RollbackRelease(ctx, "v1", "tester", nil)
	if err != nil {
		t.Fatal(err)
	}
	if rollback.Release.Version != "v3" || rollback.Release.Status != "rollback" {
		t.Fatalf("rollback release=%+v", rollback.Release)
	}
	rolled, err := mgr.Simulate(SimulateRequest{Text: "secondword", Scope: StatePublished})
	if err != nil {
		t.Fatal(err)
	}
	if rolled.Result.Matched {
		t.Fatal("rollback left later rule active")
	}
}

func TestConflictsBulkAndImportRollback(t *testing.T) {
	root := t.TempDir()
	writeTestRule(t, root, "custom/old.yml", "id: old\ntype: keyword\ncategory: custom\nrisk_level: medium\naction: review\nkeywords: [oldword]\n")
	writeTestRule(t, root, "imported/generated.yml", "id: generated\ntype: keyword\ncategory: imported\nrisk_level: high\naction: block\nkeywords: [generatedword]\n")
	mgr := NewManager(root, nil)
	ctx := context.Background()
	conflicts := DetectConflicts([]rules.Rule{testRule("a", "same"), testRule("b", "same"), rules.Rule{ID: "r", Type: "regex", Category: "custom", Patterns: []string{"["}}})
	if len(conflicts) < 2 {
		t.Fatalf("expected keyword and regex conflicts: %+v", conflicts)
	}
	changes, err := mgr.BulkSetEnabled(ctx, BulkRequest{Category: "custom", State: StatePublished}, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || changes[0].RuleID != "old" {
		t.Fatalf("bulk changes=%+v", changes)
	}
	sim, err := mgr.Simulate(SimulateRequest{Text: "oldword", Scope: StatePublished})
	if err != nil {
		t.Fatal(err)
	}
	if sim.Result.Matched {
		t.Fatal("disabled rule still matched")
	}
	rollback, err := mgr.RollbackImportBatch("batch1", []string{"imported/generated.yml"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rollback.Files) != 1 {
		t.Fatalf("rollback=%+v", rollback)
	}
	if _, err := os.Stat(filepath.Join(root, "imported/generated.yml")); !os.IsNotExist(err) {
		t.Fatalf("generated file still exists or stat error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "custom/old.yml")); err != nil {
		t.Fatalf("unrelated rule removed: %v", err)
	}
}
