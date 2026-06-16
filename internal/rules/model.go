package rules

type Rule struct {
	ID        string   `yaml:"id" json:"id"`
	Type      string   `yaml:"type" json:"type"`
	Category  string   `yaml:"category" json:"category"`
	RiskLevel string   `yaml:"risk_level" json:"risk_level"`
	Action    string   `yaml:"action" json:"action"`
	Score     int      `yaml:"score" json:"score"`
	Keywords  []string `yaml:"keywords" json:"keywords,omitempty"`
	Patterns  []string `yaml:"patterns" json:"patterns,omitempty"`
	Domains   []string `yaml:"domains" json:"domains,omitempty"`
}

type Set struct {
	KeywordRules []Rule
	RegexRules   []Rule
	DomainRules  []Rule
}

type Stats struct {
	KeywordRules  int `json:"keyword_rules"`
	Keywords      int `json:"keywords"`
	RegexRules    int `json:"regex_rules"`
	RegexPatterns int `json:"regex_patterns"`
	DomainRules   int `json:"domain_rules"`
	Domains       int `json:"domains"`
	TotalRules    int `json:"total_rules"`
}

func (s Set) Stats() Stats {
	st := Stats{KeywordRules: len(s.KeywordRules), RegexRules: len(s.RegexRules), DomainRules: len(s.DomainRules)}
	for _, r := range s.KeywordRules {
		st.Keywords += len(r.Keywords)
	}
	for _, r := range s.RegexRules {
		st.RegexPatterns += len(r.Patterns)
	}
	for _, r := range s.DomainRules {
		st.Domains += len(r.Domains)
	}
	st.TotalRules = st.KeywordRules + st.RegexRules + st.DomainRules
	return st
}
