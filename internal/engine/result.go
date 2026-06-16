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
type Result struct {
	Matched        bool       `json:"matched"`
	Action         string     `json:"action"`
	RiskScore      int        `json:"risk_score"`
	RiskDetail     RiskDetail `json:"risk_detail"`
	OriginalText   string     `json:"original_text"`
	NormalizedText string     `json:"normalized_text,omitempty"`
	Hits           []Hit      `json:"hits"`
}
