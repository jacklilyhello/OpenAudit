package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/openaudit/openaudit/internal/storage"
)

func openReviewTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), Options{Root: t.TempDir(), Path: "data/test.db", AutoMigrate: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestReviewCasePersistenceAndDeduplication(t *testing.T) {
	s := openReviewTestStore(t)
	c := storage.ReviewCase{CaseID: "rc_test", Source: "test", Status: "pending", Priority: "medium", TemporaryAction: "temporary_allow", ContextHash: "ctx", ContentHash: "hash", ContentExcerpt: "excerpt"}
	got, created, err := s.CreateReviewCase(context.Background(), c, storage.ReviewCaseEvent{CaseID: c.CaseID, Action: "created"})
	if err != nil || !created || got.CaseID != c.CaseID {
		t.Fatalf("create failed created=%v got=%#v err=%v", created, got, err)
	}
	got, created, err = s.CreateReviewCase(context.Background(), storage.ReviewCase{CaseID: "rc_duplicate", Source: "test", Status: "pending", Priority: "medium", TemporaryAction: "temporary_allow", ContextHash: "ctx"}, storage.ReviewCaseEvent{CaseID: "rc_duplicate", Action: "created"})
	if err != nil {
		t.Fatal(err)
	}
	if created || got.CaseID != c.CaseID {
		t.Fatalf("expected pending duplicate to return existing case, created=%v got=%#v", created, got)
	}
	item, events, ok, err := s.GetReviewCase(context.Background(), c.CaseID)
	if err != nil || !ok {
		t.Fatalf("get failed ok=%v err=%v", ok, err)
	}
	if item.ContentExcerpt != "excerpt" || len(events) != 1 {
		t.Fatalf("bad persisted review case item=%#v events=%#v", item, events)
	}
}

func TestReviewDecisionsAndBulkValidation(t *testing.T) {
	s := openReviewTestStore(t)
	for _, id := range []string{"rc_a", "rc_b"} {
		_, _, err := s.CreateReviewCase(context.Background(), storage.ReviewCase{CaseID: id, Source: "test", Status: "pending", Priority: "medium", TemporaryAction: "review_only", ContextHash: id}, storage.ReviewCaseEvent{CaseID: id, Action: "created"})
		if err != nil {
			t.Fatal(err)
		}
	}
	item, err := s.DecideReviewCase(context.Background(), "rc_a", "approve", "operator", "ok", "{}")
	if err != nil {
		t.Fatal(err)
	}
	if item.Status != "approved" || item.DecidedAt.IsZero() {
		t.Fatalf("approve did not decide case: %#v", item)
	}
	if _, err := s.BulkDecideReviewCases(context.Background(), []string{"rc_b", "missing"}, "reject", "operator", "bulk"); err == nil {
		t.Fatal("expected missing case to reject bulk operation")
	}
	item, _, _, err = s.GetReviewCase(context.Background(), "rc_b")
	if err != nil {
		t.Fatal(err)
	}
	if item.Status != "pending" {
		t.Fatalf("bulk failure should not partially update rc_b: %#v", item)
	}
	items, err := s.BulkDecideReviewCases(context.Background(), []string{"rc_b"}, "reject", "operator", "bulk")
	if err != nil || len(items) != 1 || items[0].Status != "rejected" {
		t.Fatalf("bulk reject failed items=%#v err=%v", items, err)
	}
}

func TestReviewPolicyAndStats(t *testing.T) {
	s := openReviewTestStore(t)
	rec := storage.ReviewPolicyRecord{PolicyJSON: `{"enabled":true}`, Version: "v1", UpdatedAt: time.Now().UTC(), Actor: "operator"}
	if err := s.UpsertReviewPolicy(context.Background(), rec); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.GetReviewPolicy(context.Background())
	if err != nil || !ok || got.Version != "v1" {
		t.Fatalf("policy read failed ok=%v got=%#v err=%v", ok, got, err)
	}
	_, _, err = s.CreateReviewCase(context.Background(), storage.ReviewCase{CaseID: "rc_stats", Source: "test", Status: "pending", Priority: "critical", TemporaryAction: "temporary_block", ContextHash: "stats"}, storage.ReviewCaseEvent{CaseID: "rc_stats", Action: "created"})
	if err != nil {
		t.Fatal(err)
	}
	stats, err := s.ReviewStats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Pending != 1 || stats.CriticalPending != 1 || stats.TemporaryBlocked != 1 {
		t.Fatalf("bad stats: %#v", stats)
	}
}
