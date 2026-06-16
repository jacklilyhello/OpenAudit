package matcher

type Hit struct {
	Type                string   `json:"type"`
	RuleID              string   `json:"rule_id"`
	Category            string   `json:"category"`
	RiskLevel           string   `json:"risk_level"`
	Action              string   `json:"action"`
	Match               string   `json:"match"`
	NormalizedMatch     string   `json:"normalized_match"`
	Canonical           string   `json:"canonical,omitempty"`
	Variant             string   `json:"variant,omitempty"`
	Start               int      `json:"start"`
	End                 int      `json:"end"`
	PositionApproximate bool     `json:"position_approximate"`
	Score               int      `json:"score"`
	Description         string   `json:"description,omitempty"`
	Source              string   `json:"source,omitempty"`
	Tags                []string `json:"tags,omitempty"`
}
type Matcher interface{ Match(text string) []Hit }
