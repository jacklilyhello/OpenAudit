package normalizer

import "testing"

func TestNormalizeCJKSeparatorsAndMapping(t *testing.T) {
	got := Normalize("法-輪_功 ABC")
	if got != "法轮功 abc" {
		t.Fatalf("got %q", got)
	}
	res := NormalizeWithMap("法*轮*功")
	if res.Normalized != "法轮功" || len(res.IndexMap) != 3 {
		t.Fatalf("bad result %#v", res)
	}
}
func TestNormalizePreservesDomainDots(t *testing.T) {
	got := Normalize("WWW.EPOCHTIMES.COM")
	if got != "www.epochtimes.com" {
		t.Fatalf("got %q", got)
	}
}

func TestPhase13MixedTraditionalSimplified(t *testing.T) {
	got := Normalize("臺灣 法輪功 头髮")
	if got != "台湾法轮功头发" {
		t.Fatalf("got %q", got)
	}
}
