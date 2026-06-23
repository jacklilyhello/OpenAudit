//go:build pcre2

package matcher

import "testing"

func TestPCRE2LookaroundBackreference(t *testing.T) {
	cases := []struct{ pattern, text string }{
		{`a(?=b)`, "ab"},
		{`(?<=a)b`, "ab"},
		{`(a)\1`, "aa"},
	}
	for _, tc := range cases {
		re, err := CompilePCRE2Pattern(tc.pattern)
		if err != nil {
			t.Fatalf("compile PCRE2 pattern failed: %v", err)
		}
		if got := re.FindAllStringIndex(tc.text); len(got) == 0 {
			t.Fatalf("expected PCRE2 match for test case")
		}
	}
}

func TestPCRE2InvalidPatternSanitized(t *testing.T) {
	if _, err := CompilePCRE2Pattern(`[`); err == nil {
		t.Fatal("expected invalid PCRE2 pattern error")
	}
}
