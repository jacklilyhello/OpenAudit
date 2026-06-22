package matcher

import (
	"github.com/openaudit/openaudit/internal/normalizer"
	"github.com/openaudit/openaudit/internal/risk"
	"github.com/openaudit/openaudit/internal/rules"
	"net/url"
	"regexp"
	"strings"
)

var domainToken = regexp.MustCompile(`(?i)(?:https?://)?[a-z0-9][a-z0-9.-]*\.[a-z0-9-]{2,}(?::[0-9]+)?(?:/[^\s]*)?`)

type DomainMatcher struct{ Rules []rules.Rule }

func NewDomainMatcher(rs []rules.Rule) DomainMatcher { return DomainMatcher{Rules: rs} }
func (m DomainMatcher) Match(text string) []Hit      { return MatchDomains(text, m.Rules) }
func MatchDomains(text string, rs []rules.Rule) []Hit {
	var hits []Hit
	text = normalizer.Normalize(text)
	for _, loc := range domainToken.FindAllStringIndex(text, -1) {
		token := strings.TrimSpace(text[loc[0]:loc[1]])
		host := NormalizeDomain(token)
		if host == "" {
			continue
		}
		s, e := byteToRuneOffsets(text, loc[0], loc[1])
		for _, r := range rs {
			for _, d := range r.Domains {
				dom := NormalizeDomain(d)
				if host == dom || strings.HasSuffix(host, "."+dom) {
					hits = append(hits, Hit{Type: "domain", RuleID: r.ID, Category: r.Category, RiskLevel: r.RiskLevel, Action: r.Action, Match: token, NormalizedMatch: host, Start: s, End: e, Score: risk.Score(r.RiskLevel, r.Score), Description: r.Description, Source: r.Source, Tags: r.Tags, Provenance: r.Provenance, Behavior: r.Behavior})
				}
			}
		}
	}
	return hits
}
func NormalizeDomain(s string) string {
	s = normalizer.Normalize(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	if !strings.Contains(s, "://") {
		s = "//" + s
	}
	if u, err := url.Parse(s); err == nil && u.Hostname() != "" {
		return strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	}
	host := strings.TrimPrefix(s, "//")
	host = strings.Split(host, "/")[0]
	host = strings.Split(host, "?")[0]
	host = strings.Split(host, "#")[0]
	host = strings.Split(host, ":")[0]
	return strings.TrimSuffix(strings.ToLower(host), ".")
}
