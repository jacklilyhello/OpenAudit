package matcher

import (
	"fmt"
	"github.com/openaudit/openaudit/internal/risk"
	"github.com/openaudit/openaudit/internal/rules"
	"regexp"
)

type RegexRule struct {
	Rule     rules.Rule
	Patterns []*regexp.Regexp
}

func CompileRegexRules(rs []rules.Rule) ([]RegexRule, error) {
	out := make([]RegexRule, 0, len(rs))
	for _, r := range rs {
		rr := RegexRule{Rule: r}
		for _, p := range r.Patterns {
			re, err := regexp.Compile(p)
			if err != nil {
				return nil, fmt.Errorf("rule %s pattern %q: %w", r.ID, p, err)
			}
			rr.Patterns = append(rr.Patterns, re)
		}
		out = append(out, rr)
	}
	return out, nil
}
func MatchRegex(text string, rs []RegexRule) []Hit {
	var hits []Hit
	for _, rr := range rs {
		for _, re := range rr.Patterns {
			for _, loc := range re.FindAllStringIndex(text, -1) {
				m := text[loc[0]:loc[1]]
				r := rr.Rule
				hits = append(hits, Hit{Type: "regex", RuleID: r.ID, Category: r.Category, RiskLevel: r.RiskLevel, Action: r.Action, Match: m, NormalizedMatch: m, Start: loc[0], End: loc[1], Score: risk.Score(r.RiskLevel, r.Score)})
			}
		}
	}
	return hits
}
