package matcher

type Hit struct {
	Type            string `json:"type"`
	RuleID          string `json:"rule_id"`
	Category        string `json:"category"`
	RiskLevel       string `json:"risk_level"`
	Action          string `json:"action"`
	Match           string `json:"match"`
	NormalizedMatch string `json:"normalized_match"`
	Canonical       string `json:"canonical,omitempty"`
	Start           int    `json:"start"`
	End             int    `json:"end"`
	Score           int    `json:"score"`
}
type Matcher interface{ Match(text string) []Hit }
