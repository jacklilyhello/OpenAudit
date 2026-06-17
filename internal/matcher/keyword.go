package matcher

import (
	"github.com/openaudit/openaudit/internal/normalizer"
	"github.com/openaudit/openaudit/internal/risk"
	"github.com/openaudit/openaudit/internal/rules"
	"github.com/openaudit/openaudit/internal/variant"
)

type KeywordMatcher struct{ aho *AhoMatcher }

func NewKeywordMatcher(rs []rules.Rule) KeywordMatcher {
	a := NewAhoMatcher()
	for _, r := range rs {
		for _, kw := range r.Keywords {
			added := map[string]bool{}
			for _, candidate := range variant.TraditionalSimplifiedVariants(kw) {
				pattern := normalizer.Normalize(candidate)
				if pattern == "" || added[pattern] {
					continue
				}
				added[pattern] = true
				a.Add(pattern, AhoPayload{Type: "keyword", RuleID: r.ID, MatchedRuleName: r.Description, Category: r.Category, RiskLevel: r.RiskLevel, Action: r.Action, Match: kw, NormalizedMatch: pattern, Score: risk.Score(r.RiskLevel, r.Score), Description: r.Description, Source: r.Source, Tags: r.Tags})
			}
		}
	}
	a.Build()
	return KeywordMatcher{aho: a}
}
func (m KeywordMatcher) Match(text string) []Hit {
	var hits []Hit
	for _, x := range m.aho.Match(text) {
		p := x.Payload
		hits = append(hits, Hit{Type: p.Type, RuleID: p.RuleID, MatchedRuleName: p.MatchedRuleName, Category: p.Category, RiskLevel: p.RiskLevel, Action: p.Action, Match: p.Match, NormalizedMatch: p.NormalizedMatch, SourceText: p.Match, Start: x.Start, End: x.End, Score: p.Score, Description: p.Description, Source: p.Source, Tags: p.Tags})
	}
	return hits
}
func MatchKeywords(text string, rs []rules.Rule) []Hit { return NewKeywordMatcher(rs).Match(text) }
