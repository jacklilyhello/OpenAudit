package matcher

import (
	"github.com/openaudit/openaudit/internal/rules"
	"testing"
)

func TestDomainSuffix(t *testing.T) {
	r := []rules.Rule{{ID: "d", Type: "domain", Category: "c", RiskLevel: "medium", Action: "review", Domains: []string{"example.com"}}}
	for _, txt := range []string{"example.com", "www.example.com", "https://a.b.example.com/path?q=1"} {
		if len(MatchDomains(txt, r)) == 0 {
			t.Fatalf("expected match for %s", txt)
		}
	}
	if len(MatchDomains("fakeexample.com", r)) != 0 {
		t.Fatal("unexpected fakeexample match")
	}
}
