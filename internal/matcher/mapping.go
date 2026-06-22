package matcher

import (
	"fmt"
	"github.com/openaudit/openaudit/internal/normalizer"
	"github.com/openaudit/openaudit/internal/risk"
	"github.com/openaudit/openaudit/internal/rules"
	"github.com/openaudit/openaudit/internal/variant"
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
				for _, pattern := range mappingPatterns(t, v) {
					a.Add(pattern, AhoPayload{Type: t, VariantType: t, RuleID: r.ID, MatchedRuleName: r.Description, Category: r.Category, RiskLevel: r.RiskLevel, Action: r.Action, Match: v, NormalizedMatch: pattern, Canonical: canon, Variant: v, SourceText: canon, Score: risk.Score(r.RiskLevel, r.Score), Explanation: mappingExplanation(t, canon, v, r.Action, r.RiskLevel), Description: r.Description, Source: r.Source, Tags: r.Tags, Provenance: rules.CloneRuleProvenance(r.Provenance), Behavior: rules.CloneRuleBehavior(r.Behavior)})
				}
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
		hits = append(hits, Hit{Type: p.Type, VariantType: p.VariantType, RuleID: p.RuleID, MatchedRuleName: p.MatchedRuleName, Category: p.Category, RiskLevel: p.RiskLevel, Action: p.Action, Match: p.Match, NormalizedMatch: p.NormalizedMatch, SourceText: p.SourceText, Canonical: p.Canonical, Variant: p.Variant, Start: x.Start, End: x.End, Score: p.Score, Explanation: p.Explanation, Description: p.Description, Source: p.Source, Tags: p.Tags, Provenance: rules.CloneRuleProvenance(p.Provenance), Behavior: rules.CloneRuleBehavior(p.Behavior)})
	}
	return hits
}

func mappingPatterns(t, value string) []string {
	switch t {
	case "pinyin":
		return []string{variant.NormalizePinyinInput(value)}
	case "homophone":
		return []string{normalizer.Normalize(value)}
	default:
		return []string{value}
	}
}

func mappingExplanation(t, canon, value, action, level string) string {
	switch t {
	case "pinyin":
		return fmt.Sprintf("Pinyin variant matched %q for canonical text %q; tone and separator differences are normalized. Risk is %s and action is %s to control false positives.", value, canon, level, action)
	case "homophone":
		return fmt.Sprintf("Homophone variant matched %q for canonical text %q. Risk is %s and action is %s because homophone-only matches can be ambiguous.", value, canon, level, action)
	default:
		return ""
	}
}
