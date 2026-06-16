package engine

import (
	"github.com/openaudit/openaudit/internal/matcher"
	"github.com/openaudit/openaudit/internal/normalizer"
	"github.com/openaudit/openaudit/internal/risk"
	"github.com/openaudit/openaudit/internal/rules"
	"sync"
)

type Engine struct {
	mu       sync.RWMutex
	root     string
	set      rules.Set
	matchers []matcher.Matcher
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
	e.matchers = ms
	e.mu.Unlock()
	return nil
}
func (e *Engine) Stats() rules.Stats { e.mu.RLock(); defer e.mu.RUnlock(); return e.set.Stats() }
func (e *Engine) Audit(text string, normalize bool) Result {
	e.mu.RLock()
	ms := append([]matcher.Matcher(nil), e.matchers...)
	e.mu.RUnlock()
	norm := text
	if normalize {
		norm = normalizer.Normalize(text)
	}
	var hits []matcher.Hit
	for _, m := range ms {
		hits = append(hits, m.Match(norm)...)
	}
	res := Result{Matched: len(hits) > 0, Action: "pass", OriginalText: text, NormalizedText: norm, Hits: hits}
	for _, h := range hits {
		if h.Score > res.RiskScore {
			res.RiskScore = h.Score
		}
		res.Action = risk.HigherAction(res.Action, h.Action)
	}
	return res
}
