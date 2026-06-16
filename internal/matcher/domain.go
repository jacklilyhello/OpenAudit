package matcher

import (
	"github.com/openaudit/openaudit/internal/risk"
	"github.com/openaudit/openaudit/internal/rules"
	"net/url"
	"regexp"
	"strings"
)

var domainToken = regexp.MustCompile(`[a-z0-9][a-z0-9.-]*\.[a-z]{2,}`)

func MatchDomains(text string, rs []rules.Rule) []Hit {
	var hits []Hit
	locs := domainToken.FindAllStringIndex(strings.ToLower(text), -1)
	for _, loc := range locs {
		token := strings.Trim(strings.ToLower(text[loc[0]:loc[1]]), ".")
		host := extractHost(token)
		for _, r := range rs {
			for _, d := range r.Domains {
				dom := strings.ToLower(strings.TrimSpace(d))
				if host == dom || strings.HasSuffix(host, "."+dom) {
					hits = append(hits, Hit{Type: "domain", RuleID: r.ID, Category: r.Category, RiskLevel: r.RiskLevel, Action: r.Action, Match: token, NormalizedMatch: host, Start: loc[0], End: loc[1], Score: risk.Score(r.RiskLevel, r.Score)})
				}
			}
		}
	}
	return hits
}
func extractHost(s string) string {
	if u, err := url.Parse(s); err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	return strings.TrimPrefix(s, "www.")
}
