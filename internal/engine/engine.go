package engine

import (
	"github.com/openaudit/openaudit/internal/bundled"
	"github.com/openaudit/openaudit/internal/config"
	"github.com/openaudit/openaudit/internal/matcher"
	"github.com/openaudit/openaudit/internal/model"
	"github.com/openaudit/openaudit/internal/normalizer"
	"github.com/openaudit/openaudit/internal/risk"
	"github.com/openaudit/openaudit/internal/rules"
	"github.com/openaudit/openaudit/internal/variant"
	"sort"
	"strconv"
	"sync"
)

type Engine struct {
	mu            sync.RWMutex
	root          string
	set           rules.Set
	keyword       matcher.Matcher
	regex         matcher.Matcher
	domain        matcher.Matcher
	pinyin        matcher.Matcher
	homophone     matcher.Matcher
	bundled       bundled.RuntimeStats
	bundledConfig *config.BundledRulesConfig
}

type Options struct {
	BundledRules *config.BundledRulesConfig
}

func New(root string) (*Engine, error) { return NewWithOptions(root, Options{}) }
func NewWithOptions(root string, opt Options) (*Engine, error) {
	e := &Engine{root: root, bundledConfig: cloneBundledRulesConfig(opt.BundledRules)}
	return e, e.Reload()
}

func cloneBundledRulesConfig(in *config.BundledRulesConfig) *config.BundledRulesConfig {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}
func Prepare(root string) (rules.Set, []matcher.Matcher, bundled.RuntimeStats, error) {
	return PrepareWithOptions(root, Options{})
}
func PrepareWithOptions(root string, opt Options) (rules.Set, []matcher.Matcher, bundled.RuntimeStats, error) {
	set, err := rules.Load(root)
	if err != nil {
		return set, nil, bundled.RuntimeStats{}, err
	}
	var bst bundled.RuntimeStats
	if opt.BundledRules != nil {
		extra, stats, err := bundled.LoadRuntime(*opt.BundledRules)
		if err != nil {
			return set, nil, stats, err
		}
		bst = stats
		set, err = bundled.MergeRules(set, extra)
		if err != nil {
			return set, nil, stats, err
		}
	}
	ms, err := PrepareSet(set)
	return set, ms, bst, err
}
func NewFromSet(set rules.Set) (*Engine, error) {
	set = rules.CloneSet(set)
	ms, err := PrepareSet(set)
	if err != nil {
		return nil, err
	}
	return &Engine{set: set, keyword: ms[0], regex: ms[1], domain: ms[2], pinyin: ms[3], homophone: ms[4]}, nil
}
func PrepareSet(set rules.Set) ([]matcher.Matcher, error) {
	set = rules.ExpandVariantRules(set)
	rr, err := matcher.CompileRegexRules(set.RegexRules)
	if err != nil {
		return nil, err
	}
	ms := []matcher.Matcher{matcher.NewKeywordMatcher(set.KeywordRules), matcher.NewRegexMatcher(rr), matcher.NewDomainMatcher(set.DomainRules), matcher.NewMappingMatcher("pinyin", set.PinyinRules), matcher.NewMappingMatcher("homophone", set.HomophoneRules)}
	return ms, nil
}
func (e *Engine) Reload() error {
	set, ms, bst, err := PrepareWithOptions(e.root, Options{BundledRules: e.bundledConfig})
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
	e.bundled = bst
	e.mu.Unlock()
	return nil
}
func (e *Engine) Stats() rules.Stats {
	e.mu.RLock()
	defer e.mu.RUnlock()
	st := e.set.Stats()
	if len(e.bundled.Providers) > 0 {
		st.BundledRules = bundled.CloneRuntimeStats(e.bundled)
	}
	return st
}
func (e *Engine) Rules() []rules.Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return rules.CloneRules(e.set.Rules)
}
func (e *Engine) Root() string { return e.root }
func (e *Engine) Audit(text string, normalize bool) Result {
	b := normalize
	return e.AuditWithOptions(text, model.AuditOptions{Normalize: &b})
}
func (e *Engine) AuditWithOptions(text string, opt model.AuditOptions) Result {
	e.mu.RLock()
	ms := []matcher.Matcher{e.keyword, e.regex, e.domain}
	pinyinMatcher := e.pinyin
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
	if model.BoolDefault(opt.Pinyin, true) {
		pm := variant.NormalizePinyinWithMap(nr.Normalized)
		for _, h := range pinyinMatcher.Match(pm.Text) {
			if h.Start >= 0 && h.End > h.Start && h.End-1 < len(pm.IndexMap) {
				h.Start = pm.IndexMap[h.Start]
				h.End = pm.IndexMap[h.End-1] + 1
				h.PositionApproximate = true
			}
			hits = append(hits, h)
		}
	}
	for i := range hits {
		s, e, ap := normalizer.MapRange(nr, hits[i].Start, hits[i].End)
		hits[i].Start = s
		hits[i].End = e
		hits[i].PositionApproximate = ap
		if !model.BoolDefault(opt.IncludeExplanations, true) {
			hits[i].Description = ""
			hits[i].Explanation = ""
			hits[i].Source = ""
			hits[i].Tags = nil
			hits[i].Provenance = nil
			hits[i].Behavior = nil
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
	hits = matcher.CloneHits(hits)
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
		k := x.Type + "\x00" + x.RuleID + "\x00" + x.Match + "\x00" + strconv.Itoa(x.Start) + "\x00" + strconv.Itoa(x.End)
		if !seen[k] {
			seen[k] = true
			out = append(out, x)
		}
	}
	return out
}
