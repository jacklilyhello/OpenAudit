package rules

type Rule struct {
	ID          string              `yaml:"id" json:"id"`
	State       string              `yaml:"state,omitempty" json:"state,omitempty"`
	Type        string              `yaml:"type" json:"type"`
	Category    string              `yaml:"category" json:"category"`
	RiskLevel   string              `yaml:"risk_level" json:"risk_level"`
	Action      string              `yaml:"action" json:"action"`
	Score       int                 `yaml:"score" json:"score"`
	Description string              `yaml:"description" json:"description,omitempty"`
	Source      string              `yaml:"source" json:"source,omitempty"`
	Tags        []string            `yaml:"tags" json:"tags,omitempty"`
	Enabled     *bool               `yaml:"enabled" json:"enabled,omitempty"`
	Keywords    []string            `yaml:"keywords" json:"keywords,omitempty"`
	Patterns    []string            `yaml:"patterns" json:"patterns,omitempty"`
	Domains     []string            `yaml:"domains" json:"domains,omitempty"`
	Mapping     map[string][]string `yaml:"mapping" json:"mapping,omitempty"`
	Path        string              `yaml:"-" json:"-"`
}

func (r Rule) IsEnabled() bool { return r.Enabled == nil || *r.Enabled }

type Set struct {
	Rules          []Rule
	KeywordRules   []Rule
	RegexRules     []Rule
	DomainRules    []Rule
	PinyinRules    []Rule
	HomophoneRules []Rule
}

type Stats struct {
	Rules             int            `json:"rules"`
	EnabledRules      int            `json:"enabled_rules"`
	DisabledRules     int            `json:"disabled_rules"`
	Keywords          int            `json:"keywords"`
	Regex             int            `json:"regex"`
	Domains           int            `json:"domains"`
	PinyinVariants    int            `json:"pinyin_variants"`
	HomophoneVariants int            `json:"homophone_variants"`
	Categories        map[string]int `json:"categories"`
	RiskLevels        map[string]int `json:"risk_levels"`
	Actions           map[string]int `json:"actions"`
	Sources           map[string]int `json:"sources"`
	Version           string         `json:"version"`
}

func (s Set) Stats() Stats {
	st := Stats{Rules: len(s.Rules), Categories: map[string]int{}, RiskLevels: map[string]int{}, Actions: map[string]int{}, Sources: map[string]int{}, Version: "local"}
	for _, r := range s.Rules {
		if !r.IsEnabled() {
			st.DisabledRules++
			continue
		}
		st.EnabledRules++
		st.Categories[r.Category]++
		st.RiskLevels[r.RiskLevel]++
		st.Actions[r.Action]++
		src := r.Source
		if src == "" {
			src = "local"
		}
		st.Sources[src]++
		switch r.Type {
		case "keyword":
			st.Keywords += len(r.Keywords)
		case "regex":
			st.Regex += len(r.Patterns)
		case "domain":
			st.Domains += len(r.Domains)
		case "pinyin":
			st.PinyinVariants += mappingCount(r.Mapping)
		case "homophone":
			st.HomophoneVariants += mappingCount(r.Mapping)
		}
	}
	return st
}

func mappingCount(m map[string][]string) int {
	n := 0
	for _, v := range m {
		n += len(v)
	}
	return n
}
