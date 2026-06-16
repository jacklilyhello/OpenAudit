package engine

import (
	"github.com/openaudit/openaudit/internal/matcher"
	"github.com/openaudit/openaudit/internal/model"
	"github.com/openaudit/openaudit/internal/normalizer"
	"github.com/openaudit/openaudit/internal/risk"
	"github.com/openaudit/openaudit/internal/rules"
	"sort"
	"sync"
)

type Engine struct {
	mu        sync.RWMutex
	root      string
	set       rules.Set
	keyword   matcher.Matcher
	regex     matcher.Matcher
	domain    matcher.Matcher
	pinyin    matcher.Matcher
	homophone matcher.Matcher
}

func New(root string) (*Engine, error) { e := &Engine{root: root}; return e, e.Reload() }
func Prepare(root string) (rules.Set, []matcher.Matcher, error) {
	set, err := rules.Load(root)
	if err != nil {
		return set, nil, err
	}
	rr, err := matcher.CompileRegexRules(set.RegexRules)
	if err != nil {
		return set, nil, err
	}
	ms := []matcher.Matcher{matcher.NewKeywordMatcher(set.KeywordRules), matcher.NewRegexMatcher(rr), matcher.NewDomainMatcher(set.DomainRules), matcher.NewMappingMatcher("pinyin", set.PinyinRules), matcher.NewMappingMatcher("homophone", set.HomophoneRules)}
	return set, ms, nil
}
func (e *Engine) Reload() error {
	set, ms, err := Prepare(e.root)
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.set = set
	e.keyword = ms[0]
	e.regex = ms[1]
	e.domain = ms[2]
	e.pinyin = ms[3]
	e.homophone = ms[4]
	e.mu.Unlock()
	return nil
}
func (e *Engine) Stats() rules.Stats { e.mu.RLock(); defer e.mu.RUnlock(); return e.set.Stats() }
func (e *Engine) Audit(text string, normalize bool) Result {
	b := normalize
	return e.AuditWithOptions(text, model.AuditOptions{Normalize: &b})
}
func (e *Engine) AuditWithOptions(text string, opt model.AuditOptions) Result {
	e.mu.RLock()
	ms := []matcher.Matcher{e.keyword, e.regex, e.domain}
	if model.BoolDefault(opt.Pinyin, true) {
		ms = append(ms, e.pinyin)
	}
	if model.BoolDefault(opt.Homophone, true) {
		ms = append(ms, e.homophone)
	}
	e.mu.RUnlock()
	nr := normalizer.Result{Original: text, Normalized: text}
	for i := range []rune(text) {
		nr.IndexMap = append(nr.IndexMap, i)
	}
	if model.BoolDefault(opt.Normalize, true) {
		nr = normalizer.NormalizeWithMap(text)
	}
	var hits []matcher.Hit
	for _, m := range ms {
		hits = append(hits, m.Match(nr.Normalized)...)
	}
	for i := range hits {
		s, e, ap := normalizer.MapRange(nr, hits[i].Start, hits[i].End)
		hits[i].Start = s
		hits[i].End = e
		hits[i].PositionApproximate = ap
		if !model.BoolDefault(opt.IncludeExplanations, true) {
			hits[i].Description = ""
			hits[i].Source = ""
			hits[i].Tags = nil
		}
		if !model.BoolDefault(opt.IncludePositions, true) {
			hits[i].Start = 0
			hits[i].End = 0
			hits[i].PositionApproximate = false
		}
	}
	hits = sortDedup(hits)
	max := opt.MaxHits
	if max <= 0 {
		max = 100
	}
	if len(hits) > max {
		hits = hits[:max]
	}
	res := Result{Matched: len(hits) > 0, Action: "pass", OriginalText: text, Hits: hits, RiskDetail: RiskDetail{Strategy: "max", HitCount: len(hits)}}
	if model.BoolDefault(opt.IncludeNormalizedText, true) {
		res.NormalizedText = nr.Normalized
	}
	for _, h := range hits {
		if h.Score > res.RiskScore {
			res.RiskScore = h.Score
		}
		res.Action = risk.HigherAction(res.Action, h.Action)
		if h.Score > res.RiskDetail.MaxScore {
			res.RiskDetail.MaxScore = h.Score
		}
		if h.Action == "block" {
			res.RiskDetail.BlockCount++
		}
		if h.Action == "review" {
			res.RiskDetail.ReviewCount++
		}
	}
	return res
}
func sortDedup(h []matcher.Hit) []matcher.Hit {
	sort.SliceStable(h, func(i, j int) bool {
		a, b := h[i], h[j]
		if a.Start != b.Start {
			return a.Start < b.Start
		}
		if a.End != b.End {
			return a.End < b.End
		}
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		return a.Match < b.Match
	})
	out := h[:0]
	seen := map[string]bool{}
	for _, x := range h {
		k := x.Type + "\x00" + x.RuleID + "\x00" + x.Match + "\x00" + string(rune(x.Start)) + "\x00" + string(rune(x.End))
		if !seen[k] {
			seen[k] = true
			out = append(out, x)
		}
	}
	return out
}
