package matcher

import "github.com/openaudit/openaudit/internal/rules"

func CloneHit(in Hit) Hit {
	out := in
	out.Tags = cloneStrings(in.Tags)
	out.Provenance = rules.CloneRuleProvenance(in.Provenance)
	out.Behavior = rules.CloneRuleBehavior(in.Behavior)
	return out
}

func CloneHits(in []Hit) []Hit {
	if in == nil {
		return nil
	}
	out := make([]Hit, len(in))
	for i := range in {
		out[i] = CloneHit(in[i])
	}
	return out
}

func cloneStrings(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}
