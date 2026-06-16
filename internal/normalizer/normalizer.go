package normalizer

import "strings"

var tradToSimp = map[rune]rune{'輪': '轮', '臺': '台', '灣': '湾', '門': '门', '國': '国', '會': '会', '習': '习', '體': '体', '網': '网', '站': '站'}
var interference = map[rune]bool{'-': true, '_': true, '*': true, ' ': true, '\t': true, '\n': true, '\r': true, '·': true, '•': true}

func Normalize(s string) string {
	s = strings.ToLower(s)
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r == 0x3000 {
			r = ' '
		} else if r >= 0xFF01 && r <= 0xFF5E {
			r -= 0xFEE0
		}
		if mapped, ok := tradToSimp[r]; ok {
			r = mapped
		}
		if interference[r] {
			continue
		}
		out = append(out, r)
	}
	return string(out)
}
