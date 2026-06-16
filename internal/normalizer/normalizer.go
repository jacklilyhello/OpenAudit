package normalizer

import (
	"strings"
	"unicode"
)

type Result struct {
	Original   string `json:"original"`
	Normalized string `json:"normalized"`
	IndexMap   []int  `json:"index_map"`
}

var tradToSimp = map[rune]rune{'輪': '轮', '臺': '台', '灣': '湾', '門': '门', '國': '国', '會': '会', '習': '习', '體': '体', '網': '网', '裏': '里'}
var cjkSep = map[rune]bool{'-': true, '_': true, '*': true, '·': true, ' ': true, '\t': true}

func Normalize(s string) string { return NormalizeWithMap(s).Normalized }
func NormalizeWithMap(s string) Result {
	orig := []rune(s)
	out := []rune{}
	idx := []int{}
	pending := -1
	for i, r := range orig {
		r = fold(r)
		if m, ok := tradToSimp[r]; ok {
			r = m
		}
		if unicode.IsSpace(r) {
			pending = i
			continue
		}
		if isSeparatorBetweenCJK(orig, i, r) {
			continue
		}
		if pending >= 0 && len(out) > 0 && !(isCJK(out[len(out)-1]) && isCJK(r)) {
			out = append(out, ' ')
			idx = append(idx, pending)
		}
		pending = -1
		out = append(out, r)
		idx = append(idx, i)
	}
	return Result{Original: s, Normalized: string(out), IndexMap: idx}
}
func MapRange(n Result, start, end int) (int, int, bool) {
	if start < 0 || end <= start || len(n.IndexMap) == 0 {
		return start, end, true
	}
	if start >= len(n.IndexMap) {
		return len([]rune(n.Original)), len([]rune(n.Original)), true
	}
	if end-1 >= len(n.IndexMap) {
		end = len(n.IndexMap)
	}
	s := n.IndexMap[start]
	e := n.IndexMap[end-1] + 1
	approx := (end - start) != (e - s)
	return s, e, approx
}
func fold(r rune) rune {
	if r == 0x3000 {
		return ' '
	}
	if r >= 0xFF01 && r <= 0xFF5E {
		r -= 0xFEE0
	}
	return unicode.ToLower(r)
}
func isSeparatorBetweenCJK(orig []rune, i int, r rune) bool {
	if !cjkSep[r] {
		return false
	}
	prev, next := rune(0), rune(0)
	for j := i - 1; j >= 0; j-- {
		p := fold(orig[j])
		if m, ok := tradToSimp[p]; ok {
			p = m
		}
		if cjkSep[p] || unicode.IsSpace(p) {
			continue
		}
		prev = p
		break
	}
	for j := i + 1; j < len(orig); j++ {
		n := fold(orig[j])
		if m, ok := tradToSimp[n]; ok {
			n = m
		}
		if cjkSep[n] || unicode.IsSpace(n) {
			continue
		}
		next = n
		break
	}
	return isCJK(prev) && isCJK(next)
}
func isCJK(r rune) bool              { return (r >= 0x4E00 && r <= 0x9FFF) || (r >= 0x3400 && r <= 0x4DBF) }
func CollapseSpaces(s string) string { return strings.Join(strings.Fields(s), " ") }
