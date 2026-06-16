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
