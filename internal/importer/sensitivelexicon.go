package importer

import (
	"fmt"
	"github.com/openaudit/openaudit/internal/rules"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var safeID = regexp.MustCompile(`[^a-zA-Z0-9_]+`)
var CategoryMap = map[string]string{"政治": "political", "色情": "porn", "赌博": "gambling", "诈骗": "scam", "毒品": "drugs", "广告": "spam", "网址": "domain"}

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
	if o.MaxKeywordsPerFile <= 0 {
		o.MaxKeywordsPerFile = 10000
	}
	if !o.DryRun {
		if err := os.MkdirAll(o.Output, 0755); err != nil {
			return Result{}, err
		}
	}
	res := Result{}
	groups := map[string][]string{}
	seen := map[string]bool{}
	err := filepath.WalkDir(o.Input, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(strings.ToLower(path), ".txt") {
			return nil
		}
		res.FilesScanned++
		words, err := ReadWordlist(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(o.Input, path)
		cat := inferCategory(o.Category, rel)
		for _, w := range words {
			res.KeywordsRead++
			key := cat + "\x00" + w
			if seen[key] {
				res.KeywordsDeduplicated++
				continue
			}
			seen[key] = true
			groups[cat] = append(groups[cat], w)
		}
		return nil
	})
	if err != nil {
		return res, fmt.Errorf("import sensitive lexicon: %w", err)
	}
	cats := make([]string, 0, len(groups))
	for c := range groups {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	for _, cat := range cats {
		words := groups[cat]
		sort.Strings(words)
		for part, start := 1, 0; start < len(words); part, start = part+1, start+o.MaxKeywordsPerFile {
			end := start + o.MaxKeywordsPerFile
			if end > len(words) {
				end = len(words)
			}
			id := strings.ToLower(safeID.ReplaceAllString(fmt.Sprintf("%s_import_%03d", cat, part), "_"))
			r := rules.Rule{ID: id, Type: "keyword", Category: cat, RiskLevel: o.Risk, Action: o.Action, Description: "Imported txt wordlist", Source: o.Source, Tags: []string{o.Source, cat}, Keywords: words[start:end]}
			out := filepath.Join(o.Output, id+".yml")
			if !o.DryRun {
				b, err := yaml.Marshal(r)
				if err != nil {
					return res, err
				}
				if err := os.WriteFile(out, b, 0644); err != nil {
					return res, err
				}
			}
			res.Files = append(res.Files, out)
			res.FilesWritten++
			res.Keywords += end - start
		}
	}
	return res, nil
}
func inferCategory(explicit, rel string) string {
	if explicit != "" {
		return explicit
	}
	dir := filepath.Dir(rel)
	if dir == "." {
		return "general"
	}
	first := strings.Split(filepath.ToSlash(dir), "/")[0]
	if v := CategoryMap[first]; v != "" {
		return v
	}
	s := strings.ToLower(safeID.ReplaceAllString(first, "_"))
	if s == "" {
		return "general"
	}
	return s
}
