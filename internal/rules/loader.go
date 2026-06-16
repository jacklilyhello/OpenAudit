package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

func Load(root string) (Set, error) {
	var set Set
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !(strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml")) {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var r Rule
		if err := yaml.Unmarshal(b, &r); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		switch strings.ToLower(r.Type) {
		case "keyword":
			set.KeywordRules = append(set.KeywordRules, r)
		case "regex":
			set.RegexRules = append(set.RegexRules, r)
		case "domain":
			set.DomainRules = append(set.DomainRules, r)
		default:
			return fmt.Errorf("%s: unknown rule type %q", path, r.Type)
		}
		return nil
	})
	return set, err
}
