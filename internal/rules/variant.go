package rules

import (
	"strings"

	"github.com/openaudit/openaudit/internal/risk"
	"github.com/openaudit/openaudit/internal/variant"
)

func ExpandVariantRules(set Set) Set {
	out := set
	for _, r := range set.KeywordRules {
		if !variantEnabled(r.Variant) {
			continue
		}
		if variantBool(r.Variant.Pinyin, false) || variantBool(r.Variant.PinyinInitials, false) {
			if vr := buildPinyinRule(r); mappingCount(vr.Mapping) > 0 {
				out.PinyinRules = append(out.PinyinRules, vr)
			}
		}
		if variantBool(r.Variant.Homophone, false) {
			if vr := buildHomophoneRule(r); mappingCount(vr.Mapping) > 0 {
				out.HomophoneRules = append(out.HomophoneRules, vr)
			}
		}
	}
	return out
}

func variantEnabled(v VariantConfig) bool {
	return v.Enabled != nil && *v.Enabled
}

func variantBool(p *bool, d bool) bool {
	if p == nil {
		return d
	}
	return *p
}

func buildPinyinRule(r Rule) Rule {
	cfg := r.Variant
	max := cfg.MaxPinyinVariants
	if max <= 0 {
		max = variant.DefaultMaxPinyinVariants
	}
	initialMin := cfg.InitialMinLength
	if initialMin <= 0 {
		initialMin = variant.DefaultInitialMinLength
	}
	minLen := cfg.MinLength
	if minLen <= 0 {
		minLen = 2
	}
	mapping := map[string][]string{}
	for _, kw := range r.Keywords {
		if !variant.ContainsCJK(kw) {
			continue
		}
		for _, form := range variant.PinyinForms(kw, max) {
			if variantBool(cfg.Pinyin, false) && len([]rune(form.Text)) >= minLen {
				mapping[kw] = append(mapping[kw], form.Text)
			}
			if variantBool(cfg.PinyinInitials, false) && len([]rune(form.Initials)) >= initialMin {
				mapping[kw] = append(mapping[kw], form.Initials)
			}
		}
	}
	return generatedVariantRule(r, "pinyin", mapping, "pinyin")
}

func buildHomophoneRule(r Rule) Rule {
	cfg := r.Variant
	max := cfg.MaxHomophoneVariants
	if max <= 0 {
		max = variant.DefaultMaxHomophoneVariants
	}
	minLen := cfg.MinLength
	if minLen <= 0 {
		minLen = 2
	}
	mapping := map[string][]string{}
	for _, kw := range r.Keywords {
		if len([]rune(kw)) < minLen || !variant.ContainsCJK(kw) {
			continue
		}
		mapping[kw] = append(mapping[kw], variant.HomophoneVariants(kw, max)...)
	}
	return generatedVariantRule(r, "homophone", mapping, "homophone")
}

func generatedVariantRule(r Rule, typ string, mapping map[string][]string, source string) Rule {
	cfg := r.Variant
	action := cfg.Action
	if action == "" {
		action = "review"
	}
	level := cfg.RiskLevel
	if level == "" {
		level = "medium"
	}
	score := scoreFromConfig(cfg.MinScore, level, r.Score)
	return Rule{
		ID:          r.ID,
		Type:        typ,
		Category:    r.Category,
		RiskLevel:   level,
		Action:      action,
		Score:       score,
		Description: strings.TrimSpace(r.Description),
		Source:      "generated:" + source,
		Tags:        append(append([]string{}, r.Tags...), "variant", typ),
		Enabled:     r.Enabled,
		Mapping:     dedupMapping(mapping),
	}
}

func scoreFromConfig(minScore float64, level string, base int) int {
	if minScore > 0 {
		return int(minScore * 100)
	}
	score := risk.Score(level, 0)
	if base > 0 && base < score {
		score = base
	}
	return score
}

func dedupMapping(in map[string][]string) map[string][]string {
	out := map[string][]string{}
	for canon, values := range in {
		seen := map[string]bool{}
		for _, v := range values {
			v = strings.TrimSpace(v)
			if v == "" || seen[v] {
				continue
			}
			seen[v] = true
			out[canon] = append(out[canon], v)
		}
	}
	return out
}
