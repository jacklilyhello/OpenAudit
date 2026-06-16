package normalizer

import "testing"

func TestPhase3Normalization(t *testing.T) {
	cases := map[string]string{"法-轮-功": "法轮功", "法_轮_功": "法轮功", "法*轮*功": "法轮功", "法 輪 功": "法轮功", "ＦＡＬＵＮＧＯＮＧ": "falungong", "Ｔ．ＭＥ/test": "t.me/test", "ＥＸＡＭＰＬＥ．ＣＯＭ": "example.com"}
	for in, w := range cases {
		if g := Normalize(in); g != w {
			t.Fatalf("%q got %q want %q", in, g, w)
		}
	}
}
func TestMapCJKSeparatorRange(t *testing.T) {
	r := NormalizeWithMap("法-轮-功")
	s, e, ap := MapRange(r, 0, 3)
	if s != 0 || e != 5 || !ap {
		t.Fatalf("got %d %d %v", s, e, ap)
	}
}
