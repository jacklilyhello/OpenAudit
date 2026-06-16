package matcher

import "testing"

func TestAhoOverlappingUnicode(t *testing.T) {
	a := NewAhoMatcher()
	for _, p := range []string{"法轮功", "轮功", "六四"} {
		a.Add(p, AhoPayload{RuleID: p, Type: "keyword", Match: p})
	}
	a.Build()
	got := a.Match("这是法轮功和六四")
	if len(got) != 3 {
		t.Fatalf("got %d", len(got))
	}
	want := []string{"法轮功", "轮功", "六四"}
	for i, w := range want {
		if got[i].Payload.Match != w {
			t.Fatalf("%d got %q want %q", i, got[i].Payload.Match, w)
		}
	}
}
