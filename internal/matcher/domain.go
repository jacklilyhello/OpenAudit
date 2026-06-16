package matcher

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/openaudit/openaudit/internal/risk"
	"github.com/openaudit/openaudit/internal/rules"
)

var domainToken = regexp.MustCompile(`(?i)(?:https?://)?[a-z0-9][a-z0-9.-]*\.[a-z]{2,}(?:/[^\s]*)?`)

type DomainMatcher struct{ Rules []rules.Rule }

func NewDomainMatcher(rs []rules.Rule) DomainMatcher { return DomainMatcher{Rules: rs} }
func (m DomainMatcher) Match(text string) []Hit      { return MatchDomains(text, m.Rules) }

func MatchDomains(text string, rs []rules.Rule) []Hit {
	var hits []Hit
	locs := domainToken.FindAllStringIndex(text, -1)
	for _, loc := range locs {
		token := strings.TrimSpace(text[loc[0]:loc[1]])
		host := NormalizeDomain(token)
		if host == "" {
			continue
		}
		for _, r := range rs {
			for _, d := range r.Domains {
				dom := NormalizeDomain(d)
				if host == dom || strings.HasSuffix(host, "."+dom) {
					hits = append(hits, Hit{Type: "domain", RuleID: r.ID, Category: r.Category, RiskLevel: r.RiskLevel, Action: r.Action, Match: token, NormalizedMatch: host, Start: loc[0], End: loc[1], Score: risk.Score(r.RiskLevel, r.Score)})
				}
			}
		}
	}
	return hits
}

func NormalizeDomain(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return ""
	}
	if !strings.Contains(s, "://") {
		s = "//" + s
	}
	if u, err := url.Parse(s); err == nil && u.Hostname() != "" {
		return strings.TrimSuffix(u.Hostname(), ".")
	}
	host := strings.TrimPrefix(s, "//")
	host = strings.Split(host, "/")[0]
	host = strings.Split(host, "?")[0]
	host = strings.Split(host, "#")[0]
	return strings.TrimSuffix(host, ".")
}
