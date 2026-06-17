package review

import (
	"context"
	"testing"

	"github.com/openaudit/openaudit/internal/config"
	"github.com/openaudit/openaudit/internal/engine"
	"github.com/openaudit/openaudit/internal/storage"
)

type fakeStore struct {
	cases []storage.ReviewCase
}

func (f *fakeStore) CreateReviewCase(ctx context.Context, c storage.ReviewCase, ev storage.ReviewCaseEvent) (storage.ReviewCase, bool, error) {
	for _, existing := range f.cases {
		if existing.ContextHash == c.ContextHash && (existing.Status == "pending" || existing.Status == "reviewing") {
			return existing, false, nil
		}
	}
	f.cases = append(f.cases, c)
	return c, true, nil
}

func TestUncertainAIReviewCreatesPendingCase(t *testing.T) {
	store := &fakeStore{}
	svc := NewService(config.Defaults().ReviewPolicy, store)
	res := engine.Result{Action: "pass", AIReview: &engine.AIReview{Enabled: true, Status: "success", Action: "review", Confidence: 0.75, RiskLevel: "high", Category: "abuse"}}
	if err := svc.Evaluate(context.Background(), "test", "uncertain content", &res); err != nil {
		t.Fatal(err)
	}
	if len(store.cases) != 1 {
		t.Fatalf("expected one review case, got %d", len(store.cases))
	}
	if res.ReviewCaseID == "" || res.TemporaryAction != ActionTemporaryAllow || res.Action != "pass" {
		t.Fatalf("missing additive review response fields: %#v", res)
	}
}

func TestLowAIReviewDoesNotCreateCase(t *testing.T) {
	store := &fakeStore{}
	svc := NewService(config.Defaults().ReviewPolicy, store)
	res := engine.Result{Action: "pass", AIReview: &engine.AIReview{Enabled: true, Status: "success", Action: "allow", Confidence: 0.2}}
	if err := svc.Evaluate(context.Background(), "test", "low risk", &res); err != nil {
		t.Fatal(err)
	}
	if len(store.cases) != 0 || res.ReviewCaseID != "" {
		t.Fatalf("low score should not create review case: cases=%d res=%#v", len(store.cases), res)
	}
}

func TestDeterministicBlockDoesNotCreateExtraCase(t *testing.T) {
	store := &fakeStore{}
	svc := NewService(config.Defaults().ReviewPolicy, store)
	res := engine.Result{Action: "block", AIReview: &engine.AIReview{Enabled: true, Status: "success", Action: "review", Confidence: 0.9}}
	if err := svc.Evaluate(context.Background(), "test", "blocked by rules", &res); err != nil {
		t.Fatal(err)
	}
	if len(store.cases) != 0 || res.Action != "block" {
		t.Fatalf("deterministic block should remain conclusive: cases=%d res=%#v", len(store.cases), res)
	}
}

func TestVariantReviewFirstCreatesCase(t *testing.T) {
	store := &fakeStore{}
	svc := NewService(config.Defaults().ReviewPolicy, store)
	res := engine.Result{Action: "review", RiskScore: 75, Hits: []engine.Hit{{Type: "pinyin", VariantType: "pinyin", Score: 75, RiskLevel: "medium", Category: "political"}}}
	if err := svc.Evaluate(context.Background(), "test", "f.l.g", &res); err != nil {
		t.Fatal(err)
	}
	if len(store.cases) != 1 {
		t.Fatalf("expected variant review case, got %d", len(store.cases))
	}
	if store.cases[0].VariantScore != 0.75 || store.cases[0].ContentExcerpt == "" {
		t.Fatalf("bad variant case: %#v", store.cases[0])
	}
}

func TestTemporaryBlockPolicyChangesOnlyTemporaryAction(t *testing.T) {
	p := config.Defaults().ReviewPolicy
	p.UncertainDefaultAction = ActionTemporaryBlock
	store := &fakeStore{}
	svc := NewService(p, store)
	res := engine.Result{Action: "pass", AIReview: &engine.AIReview{Enabled: true, Status: "success", Action: "review", Confidence: 0.95}}
	if err := svc.Evaluate(context.Background(), "test", "high uncertainty", &res); err != nil {
		t.Fatal(err)
	}
	if res.Action != "block" || res.TemporaryAction != ActionTemporaryBlock {
		t.Fatalf("temporary block policy not reflected: %#v", res)
	}
}

func TestLogOnlyPolicyDoesNotCreateQueueCase(t *testing.T) {
	p := config.Defaults().ReviewPolicy
	p.UncertainDefaultAction = ActionLogOnly
	store := &fakeStore{}
	svc := NewService(p, store)
	res := engine.Result{Action: "pass", AIReview: &engine.AIReview{Enabled: true, Status: "success", Action: "review", Confidence: 0.8}}
	if err := svc.Evaluate(context.Background(), "test", "log only", &res); err != nil {
		t.Fatal(err)
	}
	if len(store.cases) != 0 || res.ReviewStatus != ActionLogOnly || res.ReviewCaseID != "" {
		t.Fatalf("log-only should not create queue case: cases=%d res=%#v", len(store.cases), res)
	}
}

func TestContentExcerptCapped(t *testing.T) {
	p := config.Defaults().ReviewPolicy
	p.ContentExcerptMaxBytes = 5
	store := &fakeStore{}
	svc := NewService(p, store)
	res := engine.Result{Action: "pass", AIReview: &engine.AIReview{Enabled: true, Status: "success", Action: "review", Confidence: 0.8}}
	if err := svc.Evaluate(context.Background(), "test", "1234567890", &res); err != nil {
		t.Fatal(err)
	}
	if got := store.cases[0].ContentExcerpt; got != "12345" {
		t.Fatalf("excerpt not capped: %q", got)
	}
}
