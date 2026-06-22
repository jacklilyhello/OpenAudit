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
type RegexMatcher struct{ Rules []RegexRule }

func NewRegexMatcher(rs []RegexRule) RegexMatcher { return RegexMatcher{Rules: rs} }
func CompileRegexRules(rs []rules.Rule) ([]RegexRule, error) {
	out := make([]RegexRule, 0, len(rs))
	for _, r := range rs {
		rr := RegexRule{Rule: r}
		for _, p := range r.Patterns {
			re, err := regexp.Compile(p)
			if err != nil {
				return nil, fmt.Errorf("invalid regex in %s: %w", r.Path, err)
			}
			rr.Patterns = append(rr.Patterns, re)
		}
		out = append(out, rr)
	}
	return out, nil
}
func (m RegexMatcher) Match(text string) []Hit { return MatchRegex(text, m.Rules) }
func byteToRuneOffsets(s string, b0, b1 int) (int, int) {
	r0, r1 := 0, 0
	for i := range s {
		if i < b0 {
			r0++
		}
		if i < b1 {
			r1++
		}
	}
	return r0, r1
}
func MatchRegex(text string, rs []RegexRule) []Hit {
	var hits []Hit
	for _, rr := range rs {
		for _, re := range rr.Patterns {
			for _, loc := range re.FindAllStringIndex(text, -1) {
				m := text[loc[0]:loc[1]]
				s, e := byteToRuneOffsets(text, loc[0], loc[1])
				r := rr.Rule
				hits = append(hits, Hit{Type: "regex", RuleID: r.ID, Category: r.Category, RiskLevel: r.RiskLevel, Action: r.Action, Match: m, NormalizedMatch: m, Start: s, End: e, Score: risk.Score(r.RiskLevel, r.Score), Description: r.Description, Source: r.Source, Tags: r.Tags, Provenance: r.Provenance, Behavior: r.Behavior})
			}
		}
	}
	return hits
}
