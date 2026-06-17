package engine

import "github.com/openaudit/openaudit/internal/matcher"

type Hit = matcher.Hit
type RiskDetail struct {
	Strategy    string `json:"strategy"`
	MaxScore    int    `json:"max_score"`
	HitCount    int    `json:"hit_count"`
	BlockCount  int    `json:"block_count"`
	ReviewCount int    `json:"review_count"`
}
type TokenUsage struct {
	PromptTokens     int `json:"prompt_tokens,omitempty"`
	CompletionTokens int `json:"completion_tokens,omitempty"`
	TotalTokens      int `json:"total_tokens,omitempty"`
}
type AIReview struct {
	Enabled       bool       `json:"enabled"`
	RequestID     string     `json:"request_id,omitempty"`
	Provider      string     `json:"provider,omitempty"`
	Model         string     `json:"model,omitempty"`
	Status        string     `json:"status"`
	Action        string     `json:"action,omitempty"`
	Confidence    float64    `json:"confidence,omitempty"`
	RiskLevel     string     `json:"risk_level,omitempty"`
	Category      string     `json:"category,omitempty"`
	Explanation   string     `json:"explanation,omitempty"`
	Reasons       []string   `json:"reasons,omitempty"`
	CacheHit      bool       `json:"cache_hit"`
	LatencyMS     int64      `json:"latency_ms,omitempty"`
	TokenUsage    TokenUsage `json:"token_usage,omitempty"`
	EstimatedCost float64    `json:"estimated_cost,omitempty"`
	ErrorClass    string     `json:"error_class,omitempty"`
	Error         string     `json:"error,omitempty"`
}
type Result struct {
	Matched             bool       `json:"matched"`
	Action              string     `json:"action"`
	RiskScore           int        `json:"risk_score"`
	RiskDetail          RiskDetail `json:"risk_detail"`
	OriginalText        string     `json:"original_text"`
	NormalizedText      string     `json:"normalized_text,omitempty"`
	Hits                []Hit      `json:"hits"`
	AIReview            *AIReview  `json:"ai_review,omitempty"`
	ReviewStatus        string     `json:"review_status,omitempty"`
	ReviewCaseID        string     `json:"review_case_id,omitempty"`
	TemporaryAction     string     `json:"temporary_action,omitempty"`
	ReviewReason        string     `json:"review_reason,omitempty"`
	ReviewPriority      string     `json:"review_priority,omitempty"`
	ReviewPolicyVersion string     `json:"review_policy_version,omitempty"`
}
