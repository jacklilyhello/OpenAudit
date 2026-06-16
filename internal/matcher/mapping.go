package matcher

import (
	"github.com/openaudit/openaudit/internal/risk"
	"github.com/openaudit/openaudit/internal/rules"
	"strings"
)

type MappingMatcher struct {
	Type  string
	Rules []rules.Rule
}

func NewMappingMatcher(t string, rs []rules.Rule) MappingMatcher {
	return MappingMatcher{Type: t, Rules: rs}
}
func (m MappingMatcher) Match(text string) []Hit {
	var hits []Hit
	for _, r := range m.Rules {
		for canon, vars := range r.Mapping {
			for _, v := range vars {
				start := 0
				for {
					idx := strings.Index(text[start:], v)
					if idx < 0 {
						break
					}
					s := start + idx
					e := s + len(v)
					hits = append(hits, Hit{Type: m.Type, RuleID: r.ID, Category: r.Category, RiskLevel: r.RiskLevel, Action: r.Action, Match: v, NormalizedMatch: v, Canonical: canon, Start: s, End: e, Score: risk.Score(r.RiskLevel, r.Score)})
					start = e
				}
			}
		}
	}
	return hits
}
