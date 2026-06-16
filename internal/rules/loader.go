package rules

import (
	"fmt"
	"github.com/openaudit/openaudit/internal/risk"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func Load(root string) (Set, error) {
	var set Set
	walkRoot, rootAbs, err := validateRulesRoot(root)
	if err != nil {
		return set, err
	}
	err = filepath.WalkDir(walkRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s: symlink rejected", path)
		}
		if d.IsDir() || !(strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml")) {
			return nil
		}
		fileAbs, err := validatedRuleFilePath(rootAbs, path)
		if err != nil {
			return err
		}
		b, err := readValidatedRuleFile(rootAbs, fileAbs)
		if err != nil {
			return err
		}
		var r Rule
		if err := yaml.Unmarshal(b, &r); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		r.Path = path
		if err := NormalizeAndValidate(&r); err != nil {
			return err
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

func validateRulesRoot(root string) (string, string, error) {
	if root == "" {
		return "", "", fmt.Errorf("rules root is empty")
	}
	if strings.ContainsRune(root, '\x00') {
		return "", "", fmt.Errorf("rules root contains NUL")
	}
	walkRoot := filepath.Clean(root)
	rootAbs, err := filepath.Abs(walkRoot)
	if err != nil {
		return "", "", err
	}
	rootAbs = filepath.Clean(rootAbs)
	info, err := os.Lstat(rootAbs)
	if err != nil {
		return "", "", err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", "", fmt.Errorf("%s: symlink rejected", rootAbs)
	}
	if !info.IsDir() {
		return "", "", fmt.Errorf("%s: not a directory", rootAbs)
	}
	return walkRoot, rootAbs, nil
}

func validatedRuleFilePath(rootAbs, path string) (string, error) {
	fileAbs, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	fileAbs = filepath.Clean(fileAbs)
	if err := ensureRulePathUnder(rootAbs, fileAbs); err != nil {
		return "", err
	}
	return fileAbs, nil
}

func readValidatedRuleFile(rootAbs, fileAbs string) ([]byte, error) {
	if err := ensureRulePathUnder(rootAbs, fileAbs); err != nil {
		return nil, err
	}
	info, err := os.Lstat(fileAbs)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s: symlink rejected", fileAbs)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%s: is a directory", fileAbs)
	}
	// #nosec G304,G122 -- fileAbs is absolute, filepath.Rel-constrained under the validated rules rootAbs, and symlinks are rejected with Lstat immediately before reading.
	return os.ReadFile(fileAbs)
}

func ensureRulePathUnder(rootAbs, fileAbs string) error {
	if !filepath.IsAbs(rootAbs) || !filepath.IsAbs(fileAbs) {
		return fmt.Errorf("rule path validation requires absolute paths")
	}
	rel, err := filepath.Rel(filepath.Clean(rootAbs), filepath.Clean(fileAbs))
	if err != nil {
		return err
	}
	if ruleLoaderRelEscapesBase(rel) || filepath.IsAbs(rel) {
		return fmt.Errorf("%q escapes %q", fileAbs, rootAbs)
	}
	return nil
}

func ruleLoaderRelEscapesBase(rel string) bool {
	if rel == "." {
		return false
	}
	if filepath.IsAbs(rel) {
		return true
	}
	for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
		if part == ".." {
			return true
		}
	}
	return false
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
