package variant

import "testing"

func TestTraditionalSimplifiedPhraseOverrides(t *testing.T) {
	if got := Simplify("臺灣後臺頭髮"); got != "台湾后台头发" {
		t.Fatalf("simplify got %q", got)
	}
	if got := Traditionalize("台湾后台头发"); got != "臺灣後臺頭髮" {
		t.Fatalf("traditionalize got %q", got)
	}
}

func TestPinyinNormalizationToneAndSeparators(t *testing.T) {
	cases := map[string]string{
		"fǎ lún gōng":                   "falungong",
		"fa3-lun2.gong1":                "falungong",
		"F_A.L'U N G":                   "falung",
		"f\u200ba\u200cl\u200du\uFEFFn": "falun",
	}
	for in, want := range cases {
		if got := NormalizePinyinInput(in); got != want {
			t.Fatalf("%q got %q want %q", in, got, want)
		}
	}
}

func TestPinyinFormsBoundPolyphonicExpansion(t *testing.T) {
	forms := PinyinForms("重行", 2)
	if len(forms) != 2 {
		t.Fatalf("expected cap of 2 forms, got %#v", forms)
	}
	for _, f := range forms {
		if !f.Polyphonic {
			t.Fatalf("expected polyphonic marker in %#v", forms)
		}
	}
}

func TestHomophoneVariants(t *testing.T) {
	got := HomophoneVariants("法轮功", 10)
	if len(got) == 0 {
		t.Fatal("expected configured homophone variants")
	}
}
