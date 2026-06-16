package importer

import (
	"fmt"
	"github.com/openaudit/openaudit/internal/rules"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var safeID = regexp.MustCompile(`[^a-zA-Z0-9_]+`)

func ImportSensitiveLexicon(o Options) (Result, error) {
	if o.Source == "" {
		o.Source = "sensitive-lexicon"
	}
	if o.Action == "" {
		o.Action = "review"
	}
	if o.Risk == "" {
		o.Risk = "medium"
	}
	if err := os.MkdirAll(o.Output, 0755); err != nil {
		return Result{}, err
	}
	res := Result{}
	err := filepath.WalkDir(o.Input, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(strings.ToLower(path), ".txt") {
			return nil
		}
		words, err := ReadWordlist(path)
		if err != nil {
			return err
		}
		if len(words) == 0 {
			return nil
		}
		rel, _ := filepath.Rel(o.Input, path)
		base := strings.TrimSuffix(rel, filepath.Ext(rel))
		id := strings.ToLower(safeID.ReplaceAllString(o.Category+"_"+base, "_"))
		r := rules.Rule{ID: id, Type: "keyword", Category: o.Category, RiskLevel: o.Risk, Action: o.Action, Description: "Imported txt wordlist", Source: o.Source, Tags: []string{o.Source, o.Category}, Keywords: words}
		b, err := yaml.Marshal(r)
		if err != nil {
			return err
		}
		out := filepath.Join(o.Output, id+".yml")
		if err := os.WriteFile(out, b, 0644); err != nil {
			return err
		}
		res.Files = append(res.Files, out)
		res.Keywords += len(words)
		return nil
	})
	if err != nil {
		return res, fmt.Errorf("import sensitive lexicon: %w", err)
	}
	return res, nil
}
