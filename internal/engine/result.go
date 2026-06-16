package engine

import "github.com/openaudit/openaudit/internal/matcher"

type Hit = matcher.Hit
type Result struct {
	Matched        bool   `json:"matched"`
	Action         string `json:"action"`
	RiskScore      int    `json:"risk_score"`
	OriginalText   string `json:"original_text"`
	NormalizedText string `json:"normalized_text"`
	Hits           []Hit  `json:"hits"`
}
