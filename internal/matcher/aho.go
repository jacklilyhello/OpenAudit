package matcher

import "sort"

type AhoPayload struct {
	RuleID, Type, VariantType, MatchedRuleName, Category, RiskLevel, Action, Match, NormalizedMatch string
	Canonical, Variant, SourceText, Explanation, Description, Source                                string
	Tags                                                                                            []string
	Score                                                                                           int
}
type ahoOut struct {
	pat     []rune
	payload AhoPayload
}
type ahoNode struct {
	next map[rune]int
	fail int
	out  []ahoOut
}
type AhoMatcher struct{ nodes []ahoNode }
type AhoMatch struct {
	Start, End int
	Payload    AhoPayload
}

func NewAhoMatcher() *AhoMatcher { return &AhoMatcher{nodes: []ahoNode{{next: map[rune]int{}}}} }
func (a *AhoMatcher) Add(pattern string, p AhoPayload) {
	rs := []rune(pattern)
	if len(rs) == 0 {
		return
	}
	n := 0
	for _, r := range rs {
		if a.nodes[n].next == nil {
			a.nodes[n].next = map[rune]int{}
		}
		nx, ok := a.nodes[n].next[r]
		if !ok {
			nx = len(a.nodes)
			a.nodes[n].next[r] = nx
			a.nodes = append(a.nodes, ahoNode{next: map[rune]int{}})
		}
		n = nx
	}
	a.nodes[n].out = append(a.nodes[n].out, ahoOut{pat: rs, payload: p})
}
func (a *AhoMatcher) Build() {
	q := []int{}
	for _, v := range a.nodes[0].next {
		q = append(q, v)
	}
	for len(q) > 0 {
		r := q[0]
		q = q[1:]
		keys := make([]rune, 0, len(a.nodes[r].next))
		for ch := range a.nodes[r].next {
			keys = append(keys, ch)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
		for _, ch := range keys {
			u := a.nodes[r].next[ch]
			q = append(q, u)
			f := a.nodes[r].fail
			for f != 0 && a.nodes[f].next[ch] == 0 {
				f = a.nodes[f].fail
			}
			if v, ok := a.nodes[f].next[ch]; ok && v != u {
				a.nodes[u].fail = v
			}
			a.nodes[u].out = append(a.nodes[u].out, a.nodes[a.nodes[u].fail].out...)
		}
	}
}
func (a *AhoMatcher) Match(text string) []AhoMatch {
	if a == nil || len(a.nodes) == 0 {
		return nil
	}
	rs := []rune(text)
	var out []AhoMatch
	state := 0
	for i, ch := range rs {
		for state != 0 {
			if _, ok := a.nodes[state].next[ch]; ok {
				break
			}
			state = a.nodes[state].fail
		}
		if nx, ok := a.nodes[state].next[ch]; ok {
			state = nx
		}
		for _, o := range a.nodes[state].out {
			out = append(out, AhoMatch{Start: i - len(o.pat) + 1, End: i + 1, Payload: o.payload})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Start != out[j].Start {
			return out[i].Start < out[j].Start
		}
		if out[i].End != out[j].End {
			return out[i].End < out[j].End
		}
		return out[i].Payload.RuleID < out[j].Payload.RuleID
	})
	return out
}
