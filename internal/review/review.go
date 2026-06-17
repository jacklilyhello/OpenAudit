package review

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/openaudit/openaudit/internal/config"
	"github.com/openaudit/openaudit/internal/engine"
	"github.com/openaudit/openaudit/internal/storage"
)

const (
	StatusPending = "pending"

	ActionTemporaryAllow = "temporary_allow"
	ActionTemporaryBlock = "temporary_block"
	ActionReviewOnly     = "review_only"
	ActionLogOnly        = "log_only"
	ActionNone           = "none"

	PolicyVersion = "phase15-review-policy-v1"
)

type Store interface {
	CreateReviewCase(context.Context, storage.ReviewCase, storage.ReviewCaseEvent) (storage.ReviewCase, bool, error)
}

type Service struct {
	mu     sync.RWMutex
	policy config.ReviewPolicyConfig
	store  Store
	now    func() time.Time
}

func NewService(policy config.ReviewPolicyConfig, store Store) *Service {
	return &Service{policy: policy, store: store, now: func() time.Time { return time.Now().UTC() }}
}

func (s *Service) Policy() config.ReviewPolicyConfig {
	if s == nil {
		return config.Defaults().ReviewPolicy
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.policy
}

func (s *Service) SetPolicy(policy config.ReviewPolicyConfig) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.policy = policy
	s.mu.Unlock()
}

func (s *Service) Evaluate(ctx context.Context, source, text string, res *engine.Result) error {
	if s == nil || s.store == nil || res == nil {
		return nil
	}
	s.mu.RLock()
	policy := s.policy
	s.mu.RUnlock()
	if !policy.Enabled {
		return nil
	}
	local := &Service{policy: policy, store: s.store, now: s.now}
	if reason, aiScore, _, _ := local.reviewReason(*res); reason != "" && local.temporaryAction(aiScore) == ActionLogOnly {
		res.ReviewStatus = ActionLogOnly
		res.TemporaryAction = ActionLogOnly
		res.ReviewReason = reason
		res.ReviewPolicyVersion = PolicyVersion
		return nil
	}
	candidate, ok := local.candidate(source, text, *res)
	if !ok {
		return nil
	}
	created, isNew, err := s.store.CreateReviewCase(ctx, candidate, storage.ReviewCaseEvent{CaseID: candidate.CaseID, CreatedAt: candidate.CreatedAt, Actor: "system", Action: "created", NewStatus: candidate.Status, Note: candidate.MetadataJSON})
	if err != nil {
		res.ReviewStatus = "creation_failed"
		res.ReviewReason = err.Error()
		return err
	}
	res.ReviewStatus = created.Status
	res.ReviewCaseID = created.CaseID
	res.TemporaryAction = created.TemporaryAction
	res.ReviewReason = reasonFromMetadata(candidate.MetadataJSON)
	res.ReviewPriority = created.Priority
	res.ReviewPolicyVersion = PolicyVersion
	if !isNew {
		res.ReviewStatus = "deduplicated"
	}
	if created.TemporaryAction == ActionTemporaryBlock && res.Action != "block" {
		res.Action = "block"
	}
	if created.TemporaryAction == ActionTemporaryAllow && res.Action != "block" {
		res.Action = "pass"
	}
	return nil
}

func (s *Service) candidate(source, text string, res engine.Result) (storage.ReviewCase, bool) {
	reason, aiScore, variantScore, category := s.reviewReason(res)
	if reason == "" {
		return storage.ReviewCase{}, false
	}
	action := s.temporaryAction(aiScore)
	if action == ActionLogOnly && s.policy.UncertainDefaultAction == ActionLogOnly {
		return storage.ReviewCase{}, false
	}
	now := s.now()
	contentHash := hashString(text)
	matchedRulesJSON := compactJSON(res.Hits)
	aiJSON := compactJSON(res.AIReview)
	variantJSON := compactJSON(variantHits(res.Hits))
	contextHash := hashContext(contentHash, res.Action, matchedRulesJSON, aiJSON, variantJSON, PolicyVersion)
	priority := priorityFor(aiScore, variantScore, res.RiskScore)
	if category == "" {
		category = firstCategory(res.Hits)
	}
	meta := compactJSON(map[string]any{"reason": reason, "policy_version": PolicyVersion, "is_internal_platform_review": true})
	return storage.ReviewCase{
		CaseID:                "rc_" + contextHash[:24],
		Source:                source,
		Status:                StatusPending,
		Priority:              priority,
		DeterministicDecision: res.Action,
		TemporaryAction:       action,
		AIScore:               aiScore,
		AIRiskLevel:           aiRisk(res),
		AIRecommendation:      aiAction(res),
		VariantScore:          variantScore,
		VariantRiskLevel:      variantRisk(res.Hits),
		Category:              category,
		ContentExcerpt:        cappedBytes(text, s.policy.ContentExcerptMaxBytes),
		ContentHash:           contentHash,
		ContextHash:           contextHash,
		MatchedRulesJSON:      matchedRulesJSON,
		AIReviewJSON:          aiJSON,
		VariantReviewJSON:     variantJSON,
		DecisionJSON:          compactJSON(map[string]any{"deterministic_action": res.Action, "risk_score": res.RiskScore, "temporary_action": action}),
		MetadataJSON:          meta,
		CreatedAt:             now,
		UpdatedAt:             now,
		ExpiresAt:             expiresAt(now, s.policy.RetentionDays),
	}, true
}

func (s *Service) reviewReason(res engine.Result) (string, float64, float64, string) {
	if res.Action == "block" {
		return "", 0, maxVariantScore(res.Hits), firstCategory(res.Hits)
	}
	aiScore := 0.0
	category := ""
	if res.AIReview != nil && s.policy.AIReviewEnabled && res.AIReview.Enabled {
		aiScore = res.AIReview.Confidence
		category = res.AIReview.Category
		if res.AIReview.Status == "success" || res.AIReview.Status == "cached" {
			if aiScore >= s.policy.AIScoreReviewThreshold {
				return "ai_score_above_review_threshold", aiScore, maxVariantScore(res.Hits), category
			}
			if res.AIReview.Action == "block_recommended" && !s.policy.AllowAIHardBlock {
				return "ai_block_recommended_review_first", aiScore, maxVariantScore(res.Hits), category
			}
			if res.AIReview.Action == "review" && aiScore >= s.policy.AIScoreLogOnlyBelow {
				return "ai_uncertain_review", aiScore, maxVariantScore(res.Hits), category
			}
		}
	}
	variantScore := maxVariantScore(res.Hits)
	if s.policy.VariantReviewEnabled && variantScore >= s.policy.VariantScoreReviewThreshold {
		if hasVariant(res.Hits, "pinyin") && s.policy.RequireHumanReviewForPinyinMatches {
			return "pinyin_variant_review_first", aiScore, variantScore, firstCategory(res.Hits)
		}
		if hasVariant(res.Hits, "homophone") && s.policy.RequireHumanReviewForHomophoneMatch {
			return "homophone_variant_review_first", aiScore, variantScore, firstCategory(res.Hits)
		}
		return "variant_score_above_review_threshold", aiScore, variantScore, firstCategory(res.Hits)
	}
	return "", aiScore, variantScore, category
}

func (s *Service) temporaryAction(aiScore float64) string {
	if s.policy.UncertainDefaultAction == ActionTemporaryBlock && aiScore >= s.policy.AIScoreTemporaryBlockThreshold {
		return ActionTemporaryBlock
	}
	if s.policy.UncertainDefaultAction == ActionLogOnly {
		return ActionLogOnly
	}
	if s.policy.UncertainDefaultAction == ActionReviewOnly {
		return ActionReviewOnly
	}
	if s.policy.UncertainDefaultAction == ActionTemporaryBlock {
		return ActionReviewOnly
	}
	if s.policy.UncertainDefaultAction == "" {
		return ActionTemporaryAllow
	}
	return s.policy.UncertainDefaultAction
}

func maxVariantScore(hits []engine.Hit) float64 {
	max := 0
	for _, h := range hits {
		if isVariantHit(h) && h.Score > max {
			max = h.Score
		}
	}
	return float64(max) / 100
}

func hasVariant(hits []engine.Hit, typ string) bool {
	for _, h := range hits {
		if isVariantHit(h) && (h.Type == typ || h.VariantType == typ) {
			return true
		}
	}
	return false
}

func isVariantHit(h engine.Hit) bool {
	return h.VariantType != "" || h.Type == "pinyin" || h.Type == "homophone"
}

func variantHits(hits []engine.Hit) []engine.Hit {
	out := []engine.Hit{}
	for _, h := range hits {
		if isVariantHit(h) {
			out = append(out, h)
		}
	}
	return out
}

func aiRisk(res engine.Result) string {
	if res.AIReview == nil {
		return ""
	}
	return res.AIReview.RiskLevel
}

func aiAction(res engine.Result) string {
	if res.AIReview == nil {
		return ""
	}
	return res.AIReview.Action
}

func variantRisk(hits []engine.Hit) string {
	order := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
	best := ""
	for _, h := range hits {
		if isVariantHit(h) && order[h.RiskLevel] > order[best] {
			best = h.RiskLevel
		}
	}
	return best
}

func firstCategory(hits []engine.Hit) string {
	for _, h := range hits {
		if h.Category != "" {
			return h.Category
		}
	}
	return ""
}

func priorityFor(aiScore, variantScore float64, riskScore int) string {
	score := aiScore
	if variantScore > score {
		score = variantScore
	}
	switch {
	case score >= 0.95 || riskScore >= 95:
		return "critical"
	case score >= 0.85 || riskScore >= 85:
		return "high"
	case score >= 0.70 || riskScore >= 70:
		return "medium"
	default:
		return "low"
	}
}

func compactJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func hashString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func hashContext(parts ...string) string {
	sort.Strings(parts)
	return hashString(strings.Join(parts, "\x00"))
}

func cappedBytes(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.ValidString(s[:cut]) {
		cut--
	}
	return s[:cut]
}

func expiresAt(now time.Time, days int) time.Time {
	if days <= 0 {
		return time.Time{}
	}
	return now.Add(time.Duration(days) * 24 * time.Hour)
}

func reasonFromMetadata(meta string) string {
	var m map[string]any
	if err := json.Unmarshal([]byte(meta), &m); err != nil {
		return ""
	}
	if v, ok := m["reason"].(string); ok {
		return v
	}
	return ""
}

func PolicyHash(policy config.ReviewPolicyConfig) string {
	return hashString(fmt.Sprintf("%s:%s", PolicyVersion, compactJSON(policy)))[:16]
}
