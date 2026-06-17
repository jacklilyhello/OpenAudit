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
	Variant     VariantConfig       `yaml:"variant,omitempty" json:"variant,omitempty"`
	Path        string              `yaml:"-" json:"-"`
}

func (r Rule) IsEnabled() bool { return r.Enabled == nil || *r.Enabled }

type VariantConfig struct {
	Enabled               *bool    `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	TraditionalSimplified *bool    `yaml:"traditional_simplified,omitempty" json:"traditional_simplified,omitempty"`
	Pinyin                *bool    `yaml:"pinyin,omitempty" json:"pinyin,omitempty"`
	PinyinInitials        *bool    `yaml:"pinyin_initials,omitempty" json:"pinyin_initials,omitempty"`
	Homophone             *bool    `yaml:"homophone,omitempty" json:"homophone,omitempty"`
	MinScore              float64  `yaml:"min_score,omitempty" json:"min_score,omitempty"`
	Action                string   `yaml:"action,omitempty" json:"action,omitempty"`
	RiskLevel             string   `yaml:"risk_level,omitempty" json:"risk_level,omitempty"`
	Explanation           *bool    `yaml:"explanation,omitempty" json:"explanation,omitempty"`
	MinLength             int      `yaml:"min_length,omitempty" json:"min_length,omitempty"`
	InitialMinLength      int      `yaml:"initial_min_length,omitempty" json:"initial_min_length,omitempty"`
	MaxPinyinVariants     int      `yaml:"max_pinyin_variants,omitempty" json:"max_pinyin_variants,omitempty"`
	MaxHomophoneVariants  int      `yaml:"max_homophone_variants,omitempty" json:"max_homophone_variants,omitempty"`
	CategoryConstraints   []string `yaml:"category_constraints,omitempty" json:"category_constraints,omitempty"`
}

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
