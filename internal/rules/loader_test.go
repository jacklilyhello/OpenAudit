package rules

import "testing"

func TestValidateDefaults(t *testing.T) {
	r := Rule{ID: "k", Type: "keyword", Category: "c", Keywords: []string{"x"}}
	if err := NormalizeAndValidate(&r); err != nil {
		t.Fatal(err)
	}
	if r.Action != "review" || r.RiskLevel != "medium" || r.Score != 60 {
		t.Fatalf("bad defaults %#v", r)
	}
}
func TestValidateRegexFailure(t *testing.T) {
	r := Rule{ID: "r", Type: "regex", Category: "c", Patterns: []string{"["}, Path: "bad.yml"}
	if err := NormalizeAndValidate(&r); err == nil {
		t.Fatal("expected regex error")
	}
}
func TestValidateMapping(t *testing.T) {
	r := Rule{ID: "p", Type: "pinyin", Category: "c", Mapping: map[string][]string{"法轮功": []string{"flg"}}}
	if err := NormalizeAndValidate(&r); err != nil {
		t.Fatal(err)
	}
}

func TestValidateVariantConfig(t *testing.T) {
	yes := true
	r := Rule{ID: "v", Type: "keyword", Category: "c", Keywords: []string{"法轮功"}, Variant: VariantConfig{Enabled: &yes, Pinyin: &yes, PinyinInitials: &yes, Homophone: &yes, MinScore: 0.72, Action: "review", RiskLevel: "medium", InitialMinLength: 3, MaxPinyinVariants: 4, MaxHomophoneVariants: 4}}
	if err := NormalizeAndValidate(&r); err != nil {
		t.Fatal(err)
	}
	if r.Variant.Action != "review" || r.Variant.RiskLevel != "medium" {
		t.Fatalf("variant config not normalized: %#v", r.Variant)
	}
}

func TestInvalidVariantConfigRejected(t *testing.T) {
	yes := true
	r := Rule{ID: "v", Type: "keyword", Category: "c", Keywords: []string{"法轮功"}, Variant: VariantConfig{Enabled: &yes, Pinyin: &yes, MinScore: 1.2}}
	if err := NormalizeAndValidate(&r); err == nil {
		t.Fatal("expected invalid min_score error")
	}
}
