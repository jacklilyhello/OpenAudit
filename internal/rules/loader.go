package rules

import (
	"fmt"
	"github.com/openaudit/openaudit/internal/risk"
	"github.com/openaudit/openaudit/internal/safepath"
	"gopkg.in/yaml.v3"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
)

func Load(root string) (Set, error) {
	var set Set
	safeRoot, err := safepath.NewRoot(root, safepath.RequireExistingDir())
	if err != nil {
		return set, err
	}
	walkRoot := filepath.Clean(root)
	err = safeRoot.Walk(func(path safepath.Path, d fs.DirEntry) error {
		if d.IsDir() && strings.HasPrefix(d.Name(), ".") {
			return fs.SkipDir
		}
		if d.IsDir() || !(strings.HasSuffix(path.String(), ".yml") || strings.HasSuffix(path.String(), ".yaml")) {
			return nil
		}
		rel, err := safeRoot.Rel(path)
		if err != nil {
			return err
		}
		b, err := safeRoot.ReadFile(path)
		if err != nil {
			return err
		}
		var r Rule
		if err := yaml.Unmarshal(b, &r); err != nil {
			return fmt.Errorf("%s: %w", path.String(), err)
		}
		r.Path = filepath.Join(walkRoot, rel)
		if err := NormalizeAndValidate(&r); err != nil {
			return err
		}
		if r.State == "" {
			r.State = "published"
		}
		set.Rules = append(set.Rules, r)
		if !r.IsEnabled() {
			return nil
		}
		switch r.Type {
		case "keyword":
			set.KeywordRules = append(set.KeywordRules, r)
		case "regex":
			set.RegexRules = append(set.RegexRules, r)
		case "domain":
			set.DomainRules = append(set.DomainRules, r)
		case "pinyin":
			set.PinyinRules = append(set.PinyinRules, r)
		case "homophone":
			set.HomophoneRules = append(set.HomophoneRules, r)
		}
		return nil
	})
	return set, err
}

func NormalizeAndValidate(r *Rule) error {
	r.Type = strings.ToLower(strings.TrimSpace(r.Type))
	r.RiskLevel = strings.ToLower(strings.TrimSpace(r.RiskLevel))
	r.Action = strings.ToLower(strings.TrimSpace(r.Action))
	if r.ID == "" {
		return fmt.Errorf("invalid rule in %s: id is required", r.Path)
	}
	if r.Type == "" {
		return fmt.Errorf("invalid rule %s: type is required", r.ID)
	}
	if r.Category == "" {
		return fmt.Errorf("invalid rule %s: category is required", r.ID)
	}
	if r.Action == "" {
		r.Action = "review"
	}
	if r.RiskLevel == "" {
		r.RiskLevel = "medium"
	}
	if r.Score == 0 {
		r.Score = risk.Score(r.RiskLevel, 0)
	}
	if r.Source == "" {
		r.Source = "local"
	}
	clean := func(in []string) []string {
		out := []string{}
		seen := map[string]bool{}
		for _, v := range in {
			v = strings.TrimSpace(v)
			if v != "" && !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
		return out
	}
	r.Keywords = clean(r.Keywords)
	r.Patterns = clean(r.Patterns)
	r.Domains = clean(r.Domains)
	switch r.Type {
	case "keyword":
		if len(r.Keywords) == 0 {
			return fmt.Errorf("invalid rule %s: keyword rules must contain at least one keyword", r.ID)
		}
	case "regex":
		if len(r.Patterns) == 0 {
			return fmt.Errorf("invalid rule %s: regex rules must contain at least one pattern", r.ID)
		}
		for _, p := range r.Patterns {
			if _, err := regexp.Compile(p); err != nil {
				return fmt.Errorf("invalid regex in %s: %w", r.Path, err)
			}
		}
	case "domain":
		if len(r.Domains) == 0 {
			return fmt.Errorf("invalid rule %s: domain rules must contain at least one domain", r.ID)
		}
	case "pinyin", "homophone":
		if mappingCount(r.Mapping) == 0 {
			return fmt.Errorf("invalid rule %s: %s rules must contain non-empty mapping", r.ID, r.Type)
		}
	default:
		return fmt.Errorf("invalid rule %s: unknown rule type %q", r.ID, r.Type)
	}
	return nil
}
