package engine

import (
	"github.com/openaudit/openaudit/internal/matcher"
	"github.com/openaudit/openaudit/internal/normalizer"
	"github.com/openaudit/openaudit/internal/risk"
	"github.com/openaudit/openaudit/internal/rules"
	"sync"
)

type Engine struct {
	mu    sync.RWMutex
	root  string
	set   rules.Set
	regex []matcher.RegexRule
}

func New(root string) (*Engine, error) { e := &Engine{root: root}; return e, e.Reload() }
func (e *Engine) Reload() error {
	set, err := rules.Load(e.root)
	if err != nil {
		return err
	}
	rr, err := matcher.CompileRegexRules(set.RegexRules)
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.set = set
	e.regex = rr
	e.mu.Unlock()
	return nil
}
func (e *Engine) Stats() rules.Stats { e.mu.RLock(); defer e.mu.RUnlock(); return e.set.Stats() }
func (e *Engine) Audit(text string, normalize bool) Result {
	e.mu.RLock()
	set := e.set
	regex := e.regex
	e.mu.RUnlock()
	norm := text
	if normalize {
		norm = normalizer.Normalize(text)
	}
	hits := matcher.MatchKeywords(norm, set.KeywordRules)
	hits = append(hits, matcher.MatchRegex(norm, regex)...)
	hits = append(hits, matcher.MatchDomains(norm, set.DomainRules)...)
	res := Result{Matched: len(hits) > 0, Action: "pass", OriginalText: text, NormalizedText: norm, Hits: hits}
	for _, h := range hits {
		if h.Score > res.RiskScore {
			res.RiskScore = h.Score
		}
		res.Action = risk.HigherAction(res.Action, h.Action)
	}
	return res
}
