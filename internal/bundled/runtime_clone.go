package bundled

func CloneRuntimeStats(in RuntimeStats) RuntimeStats {
	out := RuntimeStats{}
	if in.Providers != nil {
		out.Providers = make(map[string]ProviderRuntimeStats, len(in.Providers))
		for k, v := range in.Providers {
			out.Providers[k] = CloneProviderRuntimeStats(v)
		}
	}
	return out
}

func CloneProviderRuntimeStats(in ProviderRuntimeStats) ProviderRuntimeStats {
	out := in
	if in.Datasets != nil {
		out.Datasets = make(map[string]DatasetStats, len(in.Datasets))
		for k, v := range in.Datasets {
			out.Datasets[k] = v
		}
	}
	if in.Groups != nil {
		out.Groups = make(map[string]int, len(in.Groups))
		for k, v := range in.Groups {
			out.Groups[k] = v
		}
	}
	if in.IncompatibleCompatibilityHint != nil {
		out.IncompatibleCompatibilityHint = make(map[string]int, len(in.IncompatibleCompatibilityHint))
		for k, v := range in.IncompatibleCompatibilityHint {
			out.IncompatibleCompatibilityHint[k] = v
		}
	}
	return out
}
