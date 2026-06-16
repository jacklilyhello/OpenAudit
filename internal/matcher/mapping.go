package matcher

import (
	"github.com/openaudit/openaudit/internal/risk"
	"github.com/openaudit/openaudit/internal/rules"
)

type MappingMatcher struct {
	Type string
	aho  *AhoMatcher
}

func NewMappingMatcher(t string, rs []rules.Rule) MappingMatcher {
	a := NewAhoMatcher()
	for _, r := range rs {
		for canon, vars := range r.Mapping {
			for _, v := range vars {
				a.Add(v, AhoPayload{Type: t, RuleID: r.ID, Category: r.Category, RiskLevel: r.RiskLevel, Action: r.Action, Match: v, Canonical: canon, Variant: v, Score: risk.Score(r.RiskLevel, r.Score), Description: r.Description, Source: r.Source, Tags: r.Tags})
			}
		}
	}
	a.Build()
	return MappingMatcher{Type: t, aho: a}
}
func (m MappingMatcher) Match(text string) []Hit {
	var hits []Hit
	for _, x := range m.aho.Match(text) {
		p := x.Payload
		hits = append(hits, Hit{Type: p.Type, RuleID: p.RuleID, Category: p.Category, RiskLevel: p.RiskLevel, Action: p.Action, Match: p.Match, NormalizedMatch: p.Match, Canonical: p.Canonical, Variant: p.Variant, Start: x.Start, End: x.End, Score: p.Score, Description: p.Description, Source: p.Source, Tags: p.Tags})
	}
	return hits
}
