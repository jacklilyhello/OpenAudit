package matcher

type Hit struct {
	Type                string   `json:"type"`
	VariantType         string   `json:"variant_type,omitempty"`
	RuleID              string   `json:"rule_id"`
	MatchedRuleName     string   `json:"matched_rule_name,omitempty"`
	Category            string   `json:"category"`
	RiskLevel           string   `json:"risk_level"`
	Action              string   `json:"action"`
	Match               string   `json:"match"`
	NormalizedMatch     string   `json:"normalized_match"`
	SourceText          string   `json:"source_text,omitempty"`
	Canonical           string   `json:"canonical,omitempty"`
	Variant             string   `json:"variant,omitempty"`
	Start               int      `json:"start"`
	End                 int      `json:"end"`
	PositionApproximate bool     `json:"position_approximate"`
	Score               int      `json:"score"`
	Explanation         string   `json:"explanation,omitempty"`
	Description         string   `json:"description,omitempty"`
	Source              string   `json:"source,omitempty"`
	Tags                []string `json:"tags,omitempty"`
}
type Matcher interface{ Match(text string) []Hit }
