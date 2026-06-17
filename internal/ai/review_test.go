package ai

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openaudit/openaudit/internal/config"
	"github.com/openaudit/openaudit/internal/engine"
)

type fakeProvider struct {
	calls int
	res   ReviewResult
	err   error
}

func (f *fakeProvider) Name() string { return "fake" }
func (f *fakeProvider) Health(context.Context) error {
	return nil
}
func (f *fakeProvider) Review(context.Context, ReviewRequest) (ReviewResult, error) {
	f.calls++
	return f.res, f.err
}

func testConfig() config.AIConfig {
	cfg := config.Defaults().AI
	cfg.Enabled = true
	cfg.Provider = "fake"
	cfg.Model = "fake-model"
	cfg.Cache.Enabled = true
	cfg.Cache.TTLSeconds = 60
	cfg.MaxRetries = 0
	cfg.AuditLogs.Enabled = false
	return cfg
}

func TestRenderPromptIncludesRuleContext(t *testing.T) {
	cfg := testConfig()
	p, err := RenderPrompt(cfg, ReviewRequest{TextExcerpt: "hello", RuleAction: "review", RiskScore: 55, Matched: true, RuleHits: []RuleHitContext{{RuleID: "r1", Category: "test"}}})
	if err != nil {
		t.Fatal(err)
	}
	if p.System == "" || p.User == "" {
		t.Fatal("prompt should render system and user sections")
	}
	if !containsAll(p.User, "hello", "r1", "review") {
		t.Fatalf("prompt missing expected context: %s", p.User)
	}
}

func TestServiceCachesByDeterministicInput(t *testing.T) {
	cfg := testConfig()
	fp := &fakeProvider{res: ReviewResult{Action: "warn", Confidence: 0.75, TokenUsage: TokenUsage{PromptTokens: 10, CompletionTokens: 5}}}
	s := NewServiceWithProviders(cfg, nil, map[string]Provider{"fake": fp})
	now := time.Date(2026, 6, 17, 1, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }

	res1 := s.Review(context.Background(), "cached text", engine.Result{Action: "pass"})
	res2 := s.Review(context.Background(), "cached text", engine.Result{Action: "pass"})
	if fp.calls != 1 {
		t.Fatalf("provider calls = %d, want 1", fp.calls)
	}
	if res1.CacheHit || !res2.CacheHit || res2.Status != StatusCached {
		t.Fatalf("unexpected cache metadata: first=%#v second=%#v", res1, res2)
	}

	now = now.Add(61 * time.Second)
	_ = s.Review(context.Background(), "cached text", engine.Result{Action: "pass"})
	if fp.calls != 2 {
		t.Fatalf("provider calls after TTL = %d, want 2", fp.calls)
	}
}

func TestServiceMapsProviderBlockToRecommendationByDefault(t *testing.T) {
	cfg := testConfig()
	fp := &fakeProvider{res: ReviewResult{Action: "block", Confidence: 1}}
	s := NewServiceWithProviders(cfg, nil, map[string]Provider{"fake": fp})
	res := s.Review(context.Background(), "text", engine.Result{Action: "pass"})
	if res.Action != ActionBlockRecommended {
		t.Fatalf("AI block should be recommendation by default, got %q", res.Action)
	}
}

func TestServiceFailureReturnsReviewMetadata(t *testing.T) {
	cfg := testConfig()
	fp := &fakeProvider{err: ProviderError{Class: "http_error", Message: "temporary failure", Status: 503, Transient: true}}
	s := NewServiceWithProviders(cfg, nil, map[string]Provider{"fake": fp})
	res := s.Review(context.Background(), "text", engine.Result{Action: "block"})
	if res.Status != StatusError || res.Action != ActionReview || res.ErrorClass != "http_error" {
		t.Fatalf("unexpected failure result: %#v", res)
	}
}

func TestCircuitBreakerOpensAfterFailures(t *testing.T) {
	cfg := testConfig()
	cfg.CircuitBreakerFailureThreshold = 1
	fp := &fakeProvider{err: errors.New("fail")}
	s := NewServiceWithProviders(cfg, nil, map[string]Provider{"fake": fp})
	first := s.Review(context.Background(), "text", engine.Result{Action: "pass"})
	second := s.Review(context.Background(), "text", engine.Result{Action: "pass"})
	if first.Status != StatusError || second.Status != StatusCircuitOpen {
		t.Fatalf("unexpected circuit states: first=%s second=%s", first.Status, second.Status)
	}
}

func containsAll(s string, parts ...string) bool {
	for _, p := range parts {
		if !strings.Contains(s, p) {
			return false
		}
	}
	return true
}
