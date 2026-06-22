package rules

func CloneRuleProvenance(in *RuleProvenance) *RuleProvenance {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func CloneRuleBehavior(in *RuleBehavior) *RuleBehavior {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func CloneRule(in Rule) Rule {
	out := in
	out.Tags = cloneStrings(in.Tags)
	out.Provenance = CloneRuleProvenance(in.Provenance)
	out.Behavior = CloneRuleBehavior(in.Behavior)
	if in.Enabled != nil {
		v := *in.Enabled
		out.Enabled = &v
	}
	out.Keywords = cloneStrings(in.Keywords)
	out.Patterns = cloneStrings(in.Patterns)
	out.Domains = cloneStrings(in.Domains)
	out.Mapping = cloneMapping(in.Mapping)
	out.Variant = CloneVariantConfig(in.Variant)
	return out
}

func CloneRules(in []Rule) []Rule {
	if in == nil {
		return nil
	}
	out := make([]Rule, len(in))
	for i := range in {
		out[i] = CloneRule(in[i])
	}
	return out
}

func CloneSet(in Set) Set {
	return Set{Rules: CloneRules(in.Rules), KeywordRules: CloneRules(in.KeywordRules), RegexRules: CloneRules(in.RegexRules), DomainRules: CloneRules(in.DomainRules), PinyinRules: CloneRules(in.PinyinRules), HomophoneRules: CloneRules(in.HomophoneRules)}
}

func CloneVariantConfig(in VariantConfig) VariantConfig {
	out := in
	out.Enabled = cloneBoolPtr(in.Enabled)
	out.TraditionalSimplified = cloneBoolPtr(in.TraditionalSimplified)
	out.Pinyin = cloneBoolPtr(in.Pinyin)
	out.PinyinInitials = cloneBoolPtr(in.PinyinInitials)
	out.Homophone = cloneBoolPtr(in.Homophone)
	out.Explanation = cloneBoolPtr(in.Explanation)
	out.CategoryConstraints = cloneStrings(in.CategoryConstraints)
	return out
}

func cloneBoolPtr(in *bool) *bool {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func cloneStrings(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func cloneMapping(in map[string][]string) map[string][]string {
	if in == nil {
		return nil
	}
	out := make(map[string][]string, len(in))
	for k, v := range in {
		out[k] = cloneStrings(v)
	}
	return out
}
