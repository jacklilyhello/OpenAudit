package bundled

import "strings"

type GroupMapping struct {
	Group, Action, Category string
	Enabled                 bool
	Metadata                RuleMetadata
}

var groupOrder = []string{"shield", "intercept", "replace", "nickname", "remind"}
var mappings = map[string]GroupMapping{
	"shield":    {"shield", "block", "netease_shield", true, RuleMetadata{UpstreamBehavior: "shield"}},
	"intercept": {"intercept", "block", "netease_intercept", true, RuleMetadata{UpstreamBehavior: "intercept"}},
	"replace":   {"replace", "review", "netease_replace", false, RuleMetadata{UpstreamBehavior: "replace", ReplacementTextAvailable: false}},
	"nickname":  {"nickname", "review", "nickname", false, RuleMetadata{UpstreamBehavior: "nickname"}},
	"remind":    {"remind", "review", "netease_remind", false, RuleMetadata{UpstreamBehavior: "remind", ReplacementTextAvailable: false}},
}

func CanonicalGroup(s string) (string, bool) {
	g := strings.ToLower(strings.TrimSpace(s))
	_, ok := mappings[g]
	return g, ok
}
func Mapping(g string) (GroupMapping, bool) { m, ok := mappings[g]; return m, ok }
func ValidDataset(d string) bool            { return d == "g79" || d == "x19" }
