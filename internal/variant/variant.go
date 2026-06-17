package variant

import (
	"sort"
	"strings"
	"unicode"
)

const (
	DefaultMaxPinyinVariants    = 8
	DefaultMaxHomophoneVariants = 16
	DefaultInitialMinLength     = 3
)

type TextMap struct {
	Text     string
	IndexMap []int
}

type PinyinForm struct {
	Text       string
	Initials   string
	Polyphonic bool
}

var phraseToSimplified = map[string]string{
	"法輪功": "法轮功",
	"臺灣":  "台湾",
	"台灣":  "台湾",
	"後臺":  "后台",
	"頭髮":  "头发",
	"發佈":  "发布",
	"發展":  "发展",
	"乾淨":  "干净",
	"幹部":  "干部",
	"電腦":  "电脑",
	"網絡":  "网络",
	"軟體":  "软件",
	"軟件":  "软件",
	"資料庫": "数据库",
}

var phraseToTraditional = map[string]string{
	"法轮功": "法輪功",
	"台湾":  "臺灣",
	"后台":  "後臺",
	"头发":  "頭髮",
	"发布":  "發佈",
	"发展":  "發展",
	"干净":  "乾淨",
	"干部":  "幹部",
	"电脑":  "電腦",
	"网络":  "網絡",
	"软件":  "軟體",
	"数据库": "資料庫",
}

var tradToSimp = map[rune]rune{
	'輪': '轮', '臺': '台', '颱': '台', '灣': '湾', '門': '门', '國': '国', '會': '会', '習': '习',
	'體': '体', '網': '网', '裏': '里', '裡': '里', '發': '发', '髮': '发', '後': '后', '乾': '干',
	'幹': '干', '電': '电', '腦': '脑', '軟': '软', '件': '件', '資': '资', '庫': '库', '數': '数',
	'據': '据', '學': '学', '車': '车', '黨': '党', '產': '产', '龍': '龙', '馬': '马', '貓': '猫',
	'愛': '爱', '時': '时', '間': '间', '話': '话', '語': '语', '長': '长', '東': '东', '點': '点',
	'華': '华', '萬': '万', '與': '与', '專': '专', '業': '业', '優': '优', '開': '开', '關': '关',
	'標': '标', '準': '准', '測': '测', '試': '试', '險': '险', '級': '级', '審': '审', '義': '义',
}

var simpToTrad = map[rune]rune{
	'轮': '輪', '台': '臺', '湾': '灣', '门': '門', '国': '國', '会': '會', '习': '習', '体': '體',
	'网': '網', '里': '裡', '发': '發', '后': '後', '干': '乾', '电': '電', '脑': '腦', '软': '軟',
	'资': '資', '库': '庫', '数': '數', '据': '據', '学': '學', '车': '車', '党': '黨', '产': '產',
	'龙': '龍', '马': '馬', '猫': '貓', '爱': '愛', '时': '時', '间': '間', '话': '話', '语': '語',
	'长': '長', '东': '東', '点': '點', '华': '華', '万': '萬', '与': '與', '专': '專', '业': '業',
	'优': '優', '开': '開', '关': '關', '标': '標', '准': '準', '测': '測', '试': '試', '险': '險',
	'级': '級', '审': '審', '义': '義',
}

var phrasePinyin = map[string][]string{
	"法轮功": {"fa", "lun", "gong"},
	"法輪功": {"fa", "lun", "gong"},
	"共产党": {"gong", "chan", "dang"},
	"共產黨": {"gong", "chan", "dang"},
	"重庆":  {"chong", "qing"},
	"重慶":  {"chong", "qing"},
	"银行":  {"yin", "hang"},
	"銀行":  {"yin", "hang"},
	"长安":  {"chang", "an"},
	"長安":  {"chang", "an"},
	"台湾":  {"tai", "wan"},
	"臺灣":  {"tai", "wan"},
	"发展":  {"fa", "zhan"},
	"發展":  {"fa", "zhan"},
	"头发":  {"tou", "fa"},
	"頭髮":  {"tou", "fa"},
}

var runePinyin = map[rune][]string{
	'法': {"fa"}, '轮': {"lun"}, '輪': {"lun"}, '功': {"gong"}, '发': {"fa"}, '發': {"fa"}, '髮': {"fa"},
	'共': {"gong"}, '产': {"chan"}, '產': {"chan"}, '党': {"dang"}, '黨': {"dang"}, '重': {"zhong", "chong"},
	'庆': {"qing"}, '慶': {"qing"}, '银': {"yin"}, '銀': {"yin"}, '行': {"xing", "hang"}, '长': {"chang", "zhang"},
	'長': {"chang", "zhang"}, '安': {"an"}, '台': {"tai"}, '臺': {"tai"}, '湾': {"wan"}, '灣': {"wan"},
	'习': {"xi"}, '習': {"xi"}, '近': {"jin"}, '平': {"ping"}, '政': {"zheng"}, '治': {"zhi"},
	'敏': {"min"}, '感': {"gan"}, '词': {"ci"}, '詞': {"ci"}, '网': {"wang"}, '網': {"wang"}, '络': {"luo"}, '絡': {"luo"},
	'电': {"dian"}, '電': {"dian"}, '脑': {"nao"}, '腦': {"nao"}, '软': {"ruan"}, '軟': {"ruan"}, '件': {"jian"},
	'数': {"shu"}, '數': {"shu"}, '据': {"ju"}, '據': {"ju"}, '库': {"ku"}, '庫': {"ku"},
}

var homophoneGroups = [][]string{
	{"法轮功", "发轮功", "法轮工", "珐轮功", "法輪功", "發輪功"},
	{"共产党", "共产挡", "共铲党", "共產黨"},
	{"敏感词", "敏感辞", "敏感詞"},
}

func Simplify(s string) string {
	return convertPhrases(s, phraseToSimplified, tradToSimp)
}

func Traditionalize(s string) string {
	return convertPhrases(s, phraseToTraditional, simpToTrad)
}

func TraditionalSimplifiedVariants(s string) []string {
	return uniqueSorted([]string{s, Simplify(s), Traditionalize(s)})
}

func NormalizePinyinInput(s string) string {
	return NormalizePinyinWithMap(s).Text
}

func NormalizePinyinWithMap(s string) TextMap {
	var out []rune
	var idx []int
	for i, r := range []rune(s) {
		if isZeroWidth(r) || isPinyinSeparator(r) || (r >= '1' && r <= '5') {
			continue
		}
		for _, x := range foldPinyinRune(r) {
			if unicode.IsLetter(x) || unicode.IsDigit(x) {
				out = append(out, unicode.ToLower(x))
				idx = append(idx, i)
			}
		}
	}
	return TextMap{Text: string(out), IndexMap: idx}
}

func PinyinForms(s string, max int) []PinyinForm {
	if max <= 0 {
		max = DefaultMaxPinyinVariants
	}
	if py, ok := phrasePinyin[s]; ok {
		return []PinyinForm{{Text: strings.Join(py, ""), Initials: initials(py)}}
	}
	if py, ok := phrasePinyin[Simplify(s)]; ok {
		return []PinyinForm{{Text: strings.Join(py, ""), Initials: initials(py)}}
	}
	forms := []struct {
		parts []string
		poly  bool
	}{{}}
	for _, r := range s {
		reads, ok := runePinyin[r]
		if !ok {
			if isCJK(r) {
				return nil
			}
			reads = []string{string(unicode.ToLower(r))}
		}
		next := []struct {
			parts []string
			poly  bool
		}{}
		for _, f := range forms {
			for _, read := range reads {
				cp := append(append([]string{}, f.parts...), read)
				next = append(next, struct {
					parts []string
					poly  bool
				}{parts: cp, poly: f.poly || len(reads) > 1})
				if len(next) >= max {
					break
				}
			}
			if len(next) >= max {
				break
			}
		}
		forms = next
	}
	out := make([]PinyinForm, 0, len(forms))
	for _, f := range forms {
		out = append(out, PinyinForm{Text: strings.Join(f.parts, ""), Initials: initials(f.parts), Polyphonic: f.poly})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Text < out[j].Text })
	return out
}

func HomophoneVariants(s string, max int) []string {
	if max <= 0 {
		max = DefaultMaxHomophoneVariants
	}
	want := Simplify(s)
	out := []string{}
	for _, group := range homophoneGroups {
		found := false
		for _, term := range group {
			if Simplify(term) == want {
				found = true
				break
			}
		}
		if !found {
			continue
		}
		for _, term := range group {
			if Simplify(term) != want {
				out = append(out, term)
				if len(out) >= max {
					return uniqueSorted(out)
				}
			}
		}
	}
	return uniqueSorted(out)
}

func ContainsCJK(s string) bool {
	for _, r := range s {
		if isCJK(r) {
			return true
		}
	}
	return false
}

func convertPhrases(s string, phrases map[string]string, chars map[rune]rune) string {
	keys := make([]string, 0, len(phrases))
	for k := range phrases {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return len([]rune(keys[i])) > len([]rune(keys[j])) })
	for _, k := range keys {
		s = strings.ReplaceAll(s, k, phrases[k])
	}
	rs := []rune(s)
	for i, r := range rs {
		if v, ok := chars[r]; ok {
			rs[i] = v
		}
	}
	return string(rs)
}

func initials(parts []string) string {
	var b strings.Builder
	for _, p := range parts {
		if p != "" {
			b.WriteByte(p[0])
		}
	}
	return b.String()
}

func uniqueSorted(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func isPinyinSeparator(r rune) bool {
	switch r {
	case ' ', '\t', '\n', '\r', '-', '_', '.', '\'', '`', '·', '/', '\\':
		return true
	default:
		return false
	}
}

func isZeroWidth(r rune) bool {
	return r == '\u200b' || r == '\u200c' || r == '\u200d' || r == '\ufeff'
}

func isCJK(r rune) bool {
	return (r >= 0x4E00 && r <= 0x9FFF) || (r >= 0x3400 && r <= 0x4DBF)
}

func foldPinyinRune(r rune) []rune {
	switch r {
	case 'ā', 'á', 'ǎ', 'à', 'Ā', 'Á', 'Ǎ', 'À':
		return []rune{'a'}
	case 'ē', 'é', 'ě', 'è', 'Ē', 'É', 'Ě', 'È':
		return []rune{'e'}
	case 'ī', 'í', 'ǐ', 'ì', 'Ī', 'Í', 'Ǐ', 'Ì':
		return []rune{'i'}
	case 'ō', 'ó', 'ǒ', 'ò', 'Ō', 'Ó', 'Ǒ', 'Ò':
		return []rune{'o'}
	case 'ū', 'ú', 'ǔ', 'ù', 'Ū', 'Ú', 'Ǔ', 'Ù':
		return []rune{'u'}
	case 'ǖ', 'ǘ', 'ǚ', 'ǜ', 'ü', 'Ü', 'Ǖ', 'Ǘ', 'Ǚ', 'Ǜ':
		return []rune{'v'}
	default:
		if r == 0x3000 {
			return []rune{' '}
		}
		if r >= 0xFF01 && r <= 0xFF5E {
			r -= 0xFEE0
		}
		return []rune{r}
	}
}
