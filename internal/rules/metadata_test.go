package rules

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRuleBehaviorJSONIncludesReplacementAvailabilityFalse(t *testing.T) {
	r := Rule{ID: "r", Type: "regex", Category: "c", Behavior: &RuleBehavior{UpstreamBehavior: "replace", ReplacementTextAvailable: false}}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"replacement_text_available":false`) {
		t.Fatalf("false replacement availability omitted: %s", b)
	}
}

func TestRuleBehaviorJSONIncludesReplacementAvailabilityTrue(t *testing.T) {
	r := Rule{ID: "r", Type: "regex", Category: "c", Behavior: &RuleBehavior{UpstreamBehavior: "replace", ReplacementTextAvailable: true}}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"replacement_text_available":true`) {
		t.Fatalf("true replacement availability omitted: %s", b)
	}
}

func TestCloneRuleDeepCopiesMutableFields(t *testing.T) {
	en := true
	ve := true
	r := Rule{ID: "r", Type: "regex", Category: "c", Tags: []string{"a"}, Provenance: &RuleProvenance{Provider: "p"}, Behavior: &RuleBehavior{UpstreamBehavior: "replace"}, Enabled: &en, Patterns: []string{"x"}, Mapping: map[string][]string{"k": {"v"}}, Variant: VariantConfig{Enabled: &ve, CategoryConstraints: []string{"c"}}}
	c := CloneRule(r)
	c.Tags[0] = "b"
	c.Provenance.Provider = "q"
	c.Behavior.UpstreamBehavior = "mutated"
	*c.Enabled = false
	c.Patterns[0] = "y"
	c.Mapping["k"][0] = "z"
	*c.Variant.Enabled = false
	c.Variant.CategoryConstraints[0] = "d"
	if r.Tags[0] != "a" || r.Provenance.Provider != "p" || r.Behavior.UpstreamBehavior != "replace" || !*r.Enabled || r.Patterns[0] != "x" || r.Mapping["k"][0] != "v" || !*r.Variant.Enabled || r.Variant.CategoryConstraints[0] != "c" {
		t.Fatalf("clone mutation leaked into original: %#v", r)
	}
}
