package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/openaudit/openaudit/internal/ai"
	"github.com/openaudit/openaudit/internal/config"
	"github.com/openaudit/openaudit/internal/engine"
	"github.com/openaudit/openaudit/internal/rules"
)

type apiFakeProvider struct{}

func (apiFakeProvider) Name() string { return "fake" }
func (apiFakeProvider) Health(context.Context) error {
	return nil
}
func (apiFakeProvider) Review(context.Context, ai.ReviewRequest) (ai.ReviewResult, error) {
	return ai.ReviewResult{Action: "block", Confidence: 0.99, RiskLevel: "high", Category: "ai", Explanation: "AI recommends review"}, nil
}

func TestAIReviewDoesNotOverrideDeterministicDecision(t *testing.T) {
	set := rules.Set{Rules: []rules.Rule{{ID: "r1", Type: "keyword", Category: "test", RiskLevel: "critical", Action: "block", Score: 100, Keywords: []string{"bad"}}}, KeywordRules: []rules.Rule{{ID: "r1", Type: "keyword", Category: "test", RiskLevel: "critical", Action: "block", Score: 100, Keywords: []string{"bad"}}}}
	e, err := engine.NewFromSet(set)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults().AI
	cfg.Enabled = true
	cfg.Provider = "fake"
	cfg.Model = "fake-model"
	cfg.AuditLogs.Enabled = false
	svc := ai.NewServiceWithProviders(cfg, nil, map[string]ai.Provider{"fake": apiFakeProvider{}})

	r := gin.Default()
	RegisterAuditWithAI(r, e, config.Defaults().Limits, nil, svc)
	body, _ := json.Marshal(map[string]any{"text": "bad", "options": map[string]any{"ai": true}})
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/audit/text", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var res engine.Result
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.Action != "block" || !res.Matched {
		t.Fatalf("deterministic result changed: %#v", res)
	}
	if res.AIReview == nil || res.AIReview.Action != ai.ActionBlockRecommended {
		t.Fatalf("missing AI review recommendation: %#v", res.AIReview)
	}
}
