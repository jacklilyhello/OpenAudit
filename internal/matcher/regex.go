package matcher

import (
	"fmt"
	"regexp"

	"github.com/openaudit/openaudit/internal/risk"
	"github.com/openaudit/openaudit/internal/rules"
)

type RegexRule struct {
	Rule     rules.Rule
	Patterns []RegexBackend
}

type re2Pattern struct{ re *regexp.Regexp }

func (p re2Pattern) FindAllStringIndex(text string) [][]int { return p.re.FindAllStringIndex(text, -1) }

type RegexMatcher struct{ Rules []RegexRule }

func NewRegexMatcher(rs []RegexRule) RegexMatcher { return RegexMatcher{Rules: rs} }
func CompileRegexRules(rs []rules.Rule) ([]RegexRule, error) {
	return CompileRegexRulesWithEngine(rs, RegexEngineRE2)
}

func CompileRegexRulesWithEngine(rs []rules.Rule, engine string) ([]RegexRule, error) {
	out := make([]RegexRule, 0, len(rs))
	for _, r := range rs {
		rr := RegexRule{Rule: r}
		for _, p := range r.Patterns {
			re, err := compileRegexPattern(engine, p)
			if err != nil {
				return nil, fmt.Errorf("invalid %s regex in %s: %w", engine, r.Path, err)
			}
			rr.Patterns = append(rr.Patterns, re)
		}
		out = append(out, rr)
	}
	return out, nil
}
func compileRegexPattern(engine, pattern string) (RegexBackend, error) {
	switch engine {
	case "", RegexEngineRE2:
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, err
		}
		return re2Pattern{re: re}, nil
	case RegexEnginePCRE2:
		return CompilePCRE2Pattern(pattern)
	default:
		return nil, fmt.Errorf("unsupported regex engine %q", engine)
	}
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
			for _, loc := range re.FindAllStringIndex(text) {
				m := text[loc[0]:loc[1]]
				s, e := byteToRuneOffsets(text, loc[0], loc[1])
				r := rr.Rule
				hits = append(hits, Hit{Type: "regex", RuleID: r.ID, Category: r.Category, RiskLevel: r.RiskLevel, Action: r.Action, Match: m, NormalizedMatch: m, Start: s, End: e, Score: risk.Score(r.RiskLevel, r.Score), Description: r.Description, Source: r.Source, Tags: r.Tags, Provenance: rules.CloneRuleProvenance(r.Provenance), Behavior: rules.CloneRuleBehavior(r.Behavior)})
			}
		}
	}
	return hits
}
