package bundled

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/openaudit/openaudit/internal/config"
	"github.com/openaudit/openaudit/internal/matcher"
	"github.com/openaudit/openaudit/internal/rules"
	"github.com/openaudit/openaudit/internal/safepath"
)

const (
	NetEaseG79Filename = "netease-g79.json.gz"
	NetEaseX19Filename = "netease-x19.json.gz"
)

type RuntimeStats struct {
	Providers map[string]ProviderRuntimeStats `json:"providers"`
}

type ProviderRuntimeStats struct {
	Enabled                        bool                    `json:"enabled"`
	Status                         string                  `json:"status"`
	Mode                           string                  `json:"mode"`
	Datasets                       map[string]DatasetStats `json:"datasets"`
	Groups                         map[string]int          `json:"groups"`
	TotalPackRulesExamined         int                     `json:"total_pack_rules_examined"`
	RegexEngine                    string                  `json:"regex_engine"`
	RegexBackendAvailable          bool                    `json:"regex_backend_available"`
	LastReloadSuccessAt            string                  `json:"last_reload_success_at,omitempty"`
	ActivatedRules                 int                     `json:"activated_rules"`
	ConfigurationDisabledRules     int                     `json:"configuration_disabled_rules"`
	BackendUnavailableSkippedRules int                     `json:"backend_unavailable_skipped_rules"`
	RE2CompatibleRules             int                     `json:"re2_compatible_rules"`
	RE2IncompatibleRules           int                     `json:"re2_incompatible_rules"`
	PCRE2CompatibleRules           int                     `json:"pcre2_compatible_rules"`
	PCRE2IncompatibleRules         int                     `json:"pcre2_incompatible_rules"`
	IncompatibleCompatibilityHint  map[string]int          `json:"incompatible_compatibility_hints,omitempty"`
}

type DatasetStats struct {
	Enabled                        bool   `json:"enabled"`
	Loaded                         bool   `json:"loaded"`
	PackRulesExamined              int    `json:"pack_rules_examined"`
	ActivatedRules                 int    `json:"activated_rules"`
	ConfigurationDisabled          int    `json:"configuration_disabled_rules"`
	BackendUnavailableSkippedRules int    `json:"backend_unavailable_skipped_rules"`
	RE2CompatibleRules             int    `json:"re2_compatible_rules"`
	RE2IncompatibleRules           int    `json:"re2_incompatible_rules"`
	PCRE2CompatibleRules           int    `json:"pcre2_compatible_rules"`
	PCRE2IncompatibleRules         int    `json:"pcre2_incompatible_rules"`
	SourceCommit                   string `json:"source_commit,omitempty"`
	SourceInputSHA256              string `json:"source_input_sha256,omitempty"`
	LicenseIdentifier              string `json:"license_identifier,omitempty"`
	DeterministicTimestamp         string `json:"deterministic_source_timestamp,omitempty"`
}

func LoadRuntime(cfg config.BundledRulesConfig) ([]rules.Rule, RuntimeStats, error) {
	st := RuntimeStats{Providers: map[string]ProviderRuntimeStats{}}
	engine := effectiveRegexEngine(cfg)
	ps := ProviderRuntimeStats{Enabled: cfg.Enabled && cfg.NetEase.Enabled, Mode: cfg.NetEase.Mode, RegexEngine: engine, RegexBackendAvailable: engine == matcher.RegexEngineRE2 || matcher.PCRE2Available(), Status: "disabled", Datasets: datasetEnabled(cfg), Groups: emptyGroups(), IncompatibleCompatibilityHint: map[string]int{}}
	st.Providers[ProviderNetEase] = ps
	if !cfg.Enabled || !cfg.NetEase.Enabled {
		return nil, st, nil
	}
	ps.Status = "enabled"
	if engine == matcher.RegexEnginePCRE2 && !matcher.PCRE2Available() {
		ps.RegexBackendAvailable = false
		st.Providers[ProviderNetEase] = ps
		return nil, st, errors.New("bundled_rules.netease.regex_engine pcre2 is unsupported: PCRE2 runtime support is not included in this build")
	}
	if engine != matcher.RegexEngineRE2 && engine != matcher.RegexEnginePCRE2 {
		st.Providers[ProviderNetEase] = ps
		return nil, st, fmt.Errorf("unsupported bundled_rules.netease.regex_engine %q", engine)
	}
	selected := selectedDatasets(cfg.NetEase.Datasets)
	if len(selected) == 0 {
		ps.Status = "no_enabled_datasets"
		st.Providers[ProviderNetEase] = ps
		return nil, st, nil
	}
	root, err := safepath.NewRoot(cfg.DataDir, safepath.RequireExistingDir(), safepath.RejectParentTraversal())
	if err != nil {
		return nil, st, fmt.Errorf("bundled rules data dir: %w", err)
	}
	var out []rules.Rule
	seen := map[string]string{}
	for _, ds := range selected {
		filename := NetEaseG79Filename
		if ds == "x19" {
			filename = NetEaseX19Filename
		}
		p, err := readPack(root, filename)
		if err != nil {
			return nil, st, fmt.Errorf("load NetEase %s pack %s: %w", ds, filename, err)
		}
		if p.Provider != ProviderNetEase || p.Dataset != ds {
			return nil, st, fmt.Errorf("NetEase %s pack has wrong provider/dataset", ds)
		}
		if err := ValidatePack(p, DefaultLimits()); err != nil {
			return nil, st, fmt.Errorf("validate NetEase %s pack: %w", ds, err)
		}
		dst := ps.Datasets[ds]
		dst.Loaded = true
		dst.SourceCommit = p.SourceCommit
		dst.SourceInputSHA256 = p.SourceInputSHA256
		dst.LicenseIdentifier = p.LicenseIdentifier
		dst.DeterministicTimestamp = p.SourceTimestamp
		for _, pr := range p.Rules {
			ps.TotalPackRulesExamined++
			dst.PackRulesExamined++
			if pr.RE2Compatible {
				ps.RE2CompatibleRules++
				dst.RE2CompatibleRules++
			} else {
				ps.RE2IncompatibleRules++
				dst.RE2IncompatibleRules++
				ps.IncompatibleCompatibilityHint[sanitizeHint(pr.RE2FeatureHint)]++
			}
			pcreOK := pr.RE2Compatible
			if engine == matcher.RegexEnginePCRE2 {
				pcreOK = pcre2Compatible(pr)
			}
			if pcreOK {
				ps.PCRE2CompatibleRules++
				dst.PCRE2CompatibleRules++
			} else {
				ps.PCRE2IncompatibleRules++
				dst.PCRE2IncompatibleRules++
			}
			if engine == matcher.RegexEngineRE2 && !pr.RE2Compatible {
				ps.BackendUnavailableSkippedRules++
				dst.BackendUnavailableSkippedRules++
				continue
			}
			if engine == matcher.RegexEnginePCRE2 && !pcreOK {
				continue
			}
			if !groupEnabled(cfg.NetEase.Groups, pr.Group) {
				ps.ConfigurationDisabledRules++
				dst.ConfigurationDisabled++
				continue
			}
			r := convertRule(pr)
			if prev, ok := seen[r.ID]; ok {
				return nil, st, fmt.Errorf("duplicate bundled rule ID %q across %s and %s", r.ID, prev, ds)
			}
			seen[r.ID] = ds
			out = append(out, r)
			ps.ActivatedRules++
			dst.ActivatedRules++
			ps.Groups[pr.Group]++
		}
		ps.Datasets[ds] = dst
	}
	if len(ps.IncompatibleCompatibilityHint) == 0 {
		ps.IncompatibleCompatibilityHint = nil
	}
	ps.LastReloadSuccessAt = time.Now().UTC().Format(time.RFC3339)
	st.Providers[ProviderNetEase] = ps
	return out, st, nil
}

func readPack(root safepath.Root, filename string) (Pack, error) {
	p, err := root.Join(filename)
	if err != nil {
		return Pack{}, err
	}
	f, err := root.OpenRead(p)
	if err != nil {
		return Pack{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return Pack{}, err
	}
	if !info.Mode().IsRegular() {
		return Pack{}, errors.New("pack is not a regular file")
	}
	lim := DefaultLimits()
	if info.Size() > lim.CompressedPackBytes {
		return Pack{}, errors.New("compressed pack exceeds limit")
	}
	b, err := io.ReadAll(io.LimitReader(f, lim.CompressedPackBytes+1))
	if err != nil {
		return Pack{}, err
	}
	if int64(len(b)) > lim.CompressedPackBytes {
		return Pack{}, errors.New("compressed pack exceeds limit")
	}
	return ReadPackGzip(b, lim)
}

func convertRule(pr PackRule) rules.Rule {
	en := true
	return rules.Rule{ID: pr.ID, State: "published", Type: "regex", Category: pr.Category, RiskLevel: pr.RiskLevel, Action: pr.Action, Score: pr.Score, Description: pr.Description, Source: pr.Source, Tags: append([]string(nil), pr.Tags...), Provenance: &rules.RuleProvenance{Provider: pr.Provider, Dataset: pr.Dataset, Group: pr.Group, UpstreamID: pr.UpstreamID}, Behavior: &rules.RuleBehavior{UpstreamBehavior: pr.Metadata.UpstreamBehavior, ReplacementTextAvailable: pr.Metadata.ReplacementTextAvailable}, Enabled: &en, Patterns: []string{pr.OriginalRegex}, Path: filepath.Join("bundled", pr.Provider, pr.Dataset, pr.Group, pr.ID)}
}
func selectedDatasets(d config.NetEaseDatasetsConfig) []string {
	var out []string
	if d.G79 {
		out = append(out, "g79")
	}
	if d.X19 {
		out = append(out, "x19")
	}
	return out
}
func datasetEnabled(cfg config.BundledRulesConfig) map[string]DatasetStats {
	return map[string]DatasetStats{"g79": {Enabled: cfg.NetEase.Datasets.G79}, "x19": {Enabled: cfg.NetEase.Datasets.X19}}
}
func emptyGroups() map[string]int {
	m := map[string]int{}
	for _, g := range groupOrder {
		m[g] = 0
	}
	return m
}
func groupEnabled(g config.NetEaseGroupsConfig, name string) bool {
	switch name {
	case "shield":
		return g.Shield
	case "intercept":
		return g.Intercept
	case "replace":
		return g.Replace
	case "nickname":
		return g.Nickname
	case "remind":
		return g.Remind
	default:
		return false
	}
}
func sanitizeHint(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if h == "" {
		return "unknown"
	}
	var b strings.Builder
	for _, r := range h {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}

func MergeRules(local rules.Set, extra []rules.Rule) (rules.Set, error) {
	seen := map[string]string{}
	for _, r := range local.Rules {
		if prev, ok := seen[r.ID]; ok {
			return rules.Set{}, fmt.Errorf("duplicate rule ID %q in %s and %s", r.ID, prev, r.Path)
		}
		seen[r.ID] = r.Path
	}
	for _, r := range extra {
		if prev, ok := seen[r.ID]; ok {
			return rules.Set{}, fmt.Errorf("duplicate rule ID %q in %s and %s", r.ID, prev, r.Path)
		}
		local.Rules = append(local.Rules, r)
		if r.IsEnabled() {
			local.RegexRules = append(local.RegexRules, r)
		}
	}
	sort.SliceStable(local.Rules, func(i, j int) bool { return local.Rules[i].ID < local.Rules[j].ID })
	return local, nil
}

func effectiveRegexEngine(cfg config.BundledRulesConfig) string {
	mode := strings.ToLower(strings.TrimSpace(cfg.NetEase.Mode))
	engine := strings.ToLower(strings.TrimSpace(cfg.NetEase.RegexEngine))
	if mode != "" && mode != engine && engine == matcher.RegexEngineRE2 {
		return mode
	}
	if engine != "" {
		return engine
	}
	return mode
}

func pcre2Compatible(pr PackRule) bool {
	switch pr.PCRE2Status {
	case PCRE2Compatible:
		return true
	case PCRE2Incompatible:
		return false
	}
	_, err := matcher.CompilePCRE2Pattern(pr.OriginalRegex)
	return err == nil
}
