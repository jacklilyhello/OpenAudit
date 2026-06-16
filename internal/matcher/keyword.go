package matcher

import (
	"github.com/openaudit/openaudit/internal/risk"
	"github.com/openaudit/openaudit/internal/rules"
	"strings"
)

func MatchKeywords(text string, rs []rules.Rule) []Hit {
	var hits []Hit
	for _, r := range rs {
		for _, kw := range r.Keywords {
			start := 0
			for {
				idx := strings.Index(text[start:], kw)
				if idx < 0 {
					break
				}
				s := start + idx
				e := s + len(kw)
				hits = append(hits, Hit{Type: "keyword", RuleID: r.ID, Category: r.Category, RiskLevel: r.RiskLevel, Action: r.Action, Match: kw, NormalizedMatch: kw, Start: s, End: e, Score: risk.Score(r.RiskLevel, r.Score)})
				start = e
			}
		}
	}
	return hits
}
