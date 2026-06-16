package importer

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/openaudit/openaudit/internal/rules"
	"github.com/openaudit/openaudit/internal/safepath"
	"gopkg.in/yaml.v3"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

type Options struct {
	Input, Output, Category, Risk, Action, Source, Type, DedupeScope, ReportPath, ReportFormat, ReloadURL, APIKey string
	MaxKeywordsPerFile, MaxLineRunes                                                                              int
	DryRun, Strict, ReloadAfterImport                                                                             bool
}

type ValidatedOptions struct {
	Options
	inputRoot  safepath.Root
	outputRoot safepath.Root
}

type Result struct {
	Files                                                                    []string
	Keywords, FilesScanned, KeywordsRead, KeywordsDeduplicated, FilesWritten int
}
type Report struct {
	BatchID             string         `json:"batch_id"`
	Timestamp           time.Time      `json:"timestamp"`
	Source              string         `json:"source"`
	InputPath           string         `json:"input_path"`
	OutputPath          string         `json:"output_path"`
	DryRun              bool           `json:"dry_run"`
	ReloadAfterImport   bool           `json:"reload_after_import"`
	Status              string         `json:"status"`
	FilesScanned        int            `json:"files_scanned"`
	LinesRead           int            `json:"lines_read"`
	BlankCommentSkipped int            `json:"blank_comment_lines_skipped"`
	KeywordsRead        int            `json:"keywords_read"`
	DomainsRead         int            `json:"domains_read"`
	RegexRead           int            `json:"regex_read"`
	DuplicatesRemoved   int            `json:"duplicates_removed"`
	InvalidLines        int            `json:"invalid_lines"`
	InvalidRegex        int            `json:"invalid_regex"`
	OutputFiles         []string       `json:"output_files"`
	Categories          map[string]int `json:"categories"`
	RuleTypes           map[string]int `json:"rule_types"`
	Warnings            []string       `json:"warnings,omitempty"`
	Errors              []string       `json:"errors,omitempty"`
	DuplicateExamples   []string       `json:"duplicate_examples,omitempty"`
	DurationMS          int64          `json:"duration_ms"`
	Reload              *ReloadResult  `json:"reload,omitempty"`
}
type ReloadResult struct {
	Attempted  bool   `json:"attempted"`
	StatusCode int    `json:"status_code,omitempty"`
	Error      string `json:"error,omitempty"`
}

var safeID = regexp.MustCompile(`[^a-zA-Z0-9_]+`)
var CategoryMap = map[string]string{"政治": "political", "涉政": "political", "色情": "porn", "成人": "porn", "赌博": "gambling", "博彩": "gambling", "诈骗": "scam", "欺诈": "scam", "毒品": "drugs", "违禁": "prohibited", "广告": "spam", "垃圾": "spam", "网址": "domain", "域名": "domain", "链接": "url", "辱骂": "abuse", "暴恐": "violence", "恐怖": "violence", "枪支": "weapons", "武器": "weapons", "黑产": "cybercrime", "引流": "spam", "宗教": "religion", "民生": "public_affairs", "其他": "other"}

func NewBatchID() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return "import_" + time.Now().UTC().Format("20060102T150405Z") + "_" + hex.EncodeToString(b[:])
}
func defaults(o *Options) {
	if o.Source == "" {
		o.Source = "sensitive-lexicon"
	}
	if o.Action == "" {
		o.Action = "review"
	}
	if o.Risk == "" {
		o.Risk = "medium"
	}
	if o.Type == "" {
		o.Type = "auto"
	}
	if o.DedupeScope == "" {
		o.DedupeScope = "batch"
	}
	if o.MaxKeywordsPerFile <= 0 {
		o.MaxKeywordsPerFile = 10000
	}
	if o.MaxLineRunes <= 0 {
		o.MaxLineRunes = 4096
	}
	if o.ReportFormat == "" {
		o.ReportFormat = "json"
	}
}
func SanitizeCategory(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "imported"
	}
	if v := CategoryMap[s]; v != "" {
		return v
	}
	x := strings.ToLower(safeID.ReplaceAllString(strings.ReplaceAll(s, "-", "_"), "_"))
	x = strings.Trim(x, "_")
	if x == "" {
		return "imported"
	}
	return x
}
func inferCategory(explicit, rel string) string {
	if explicit != "" {
		return SanitizeCategory(explicit)
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	for _, p := range parts {
		base := strings.TrimSuffix(p, filepath.Ext(p))
		if v := CategoryMap[base]; v != "" {
			return v
		}
	}
	for _, p := range parts {
		if c := SanitizeCategory(strings.TrimSuffix(p, filepath.Ext(p))); c != "imported" {
			return c
		}
	}
	return "imported"
}
func isDomain(s string) (string, bool) {
	s = strings.TrimSpace(strings.TrimPrefix(s, "*."))
	if !strings.Contains(s, ".") || strings.ContainsAny(s, " \\[](){}^$+?|*") {
		return "", false
	}
	ok, _ := regexp.MatchString(`^[A-Za-z0-9.-]+$`, s)
	return strings.ToLower(s), ok
}
func isRegex(s string) bool {
	return strings.ContainsAny(s, "[]^$") || strings.Contains(s, "(?i)") || strings.Contains(s, `\b`) || strings.Contains(s, `\d`) || strings.Contains(s, ".*") || strings.Contains(s, "[a-z]")
}
func InferType(path, line, override string) string {
	if override != "" && override != "auto" {
		return override
	}
	low := strings.ToLower(path)
	if strings.Contains(low, "regex") || strings.Contains(path, "正则") || isRegex(line) {
		return "regex"
	}
	if strings.Contains(low, "domain") || strings.Contains(path, "域名") || strings.Contains(path, "网址") {
		return "domain"
	}
	if _, ok := isDomain(line); ok {
		return "domain"
	}
	return "keyword"
}
func isCommentLine(line string) bool {
	return len(line) >= 1 && line[:1] == "#" || len(line) >= 2 && line[:2] == "//" || len(line) >= 1 && line[:1] == ";"
}

func NewValidatedOptions(inputPath, outputPath string, opts Options) (ValidatedOptions, error) {
	defaults(&opts)
	if strings.TrimSpace(inputPath) != "" {
		opts.Input = inputPath
	}
	if strings.TrimSpace(outputPath) != "" {
		opts.Output = outputPath
	}
	return newValidatedOptions(opts)
}

func NewValidatedOptionsWithDefaults(rawInputPath, rawOutputPath, defaultInputRoot, defaultOutputRoot string, opts Options) (ValidatedOptions, error) {
	inputPath, err := resolvePathUnderDefaultRoot(rawInputPath, defaultInputRoot, "input_path")
	if err != nil {
		return ValidatedOptions{}, err
	}
	outputPath, err := resolvePathUnderDefaultRoot(rawOutputPath, defaultOutputRoot, "output_path")
	if err != nil {
		return ValidatedOptions{}, err
	}
	return NewValidatedOptions(inputPath, outputPath, opts)
}

func newValidatedOptions(opts Options) (ValidatedOptions, error) {
	defaults(&opts)
	inputRoot, err := safepath.NewRoot(opts.Input, safepath.RejectParentTraversal(), safepath.RequireExistingDir())
	if err != nil {
		return ValidatedOptions{}, err
	}
	outputOpts := []safepath.Option{}
	outputOpts = append(outputOpts, safepath.RejectParentTraversal())
	if !opts.DryRun {
		outputOpts = append(outputOpts, safepath.CreateRoot())
	}
	outputRoot, err := safepath.NewRoot(opts.Output, outputOpts...)
	if err != nil {
		return ValidatedOptions{}, err
	}
	opts.Input = inputRoot.String()
	opts.Output = outputRoot.String()
	return ValidatedOptions{Options: opts, inputRoot: inputRoot, outputRoot: outputRoot}, nil
}

func resolvePathUnderDefaultRoot(rawPath, defaultRoot, field string) (string, error) {
	defaultRootPath, err := safepath.NewRoot(defaultRoot, safepath.RejectParentTraversal())
	if err != nil {
		return "", fmt.Errorf("%s default root: %w", field, err)
	}
	provided := strings.TrimSpace(rawPath)
	if provided == "" {
		return defaultRootPath.String(), nil
	}
	candidate, err := defaultRootPath.Resolve(provided)
	if err != nil {
		return "", fmt.Errorf("%s: %w", field, err)
	}
	return candidate.String(), nil
}

func ReportFileName(batchID string) string {
	id := strings.ToLower(safeID.ReplaceAllString(batchID, "_"))
	id = strings.Trim(id, "_")
	if id == "" {
		id = "import_report"
	}
	return "import_" + id + ".json"
}

func ImportSensitiveLexicon(o Options) (Result, error) {
	rep, err := Run(o)
	r := Result{}
	if rep != nil {
		r.Files = rep.OutputFiles
		r.FilesScanned = rep.FilesScanned
		r.KeywordsRead = rep.KeywordsRead + rep.DomainsRead + rep.RegexRead
		r.KeywordsDeduplicated = rep.DuplicatesRemoved
		r.FilesWritten = len(rep.OutputFiles)
		r.Keywords = r.KeywordsRead - r.KeywordsDeduplicated
	}
	return r, err
}
func Run(o Options) (*Report, error) {
	validated, err := NewValidatedOptions(o.Input, o.Output, o)
	if err != nil {
		return nil, err
	}
	return RunValidated(validated)
}

func RunValidated(o ValidatedOptions) (*Report, error) {
	if o.inputRoot.String() == "" || o.outputRoot.String() == "" {
		return nil, errors.New("validated importer options are required")
	}
	start := time.Now()
	inputRoot := o.inputRoot
	outputRoot := o.outputRoot
	rep := &Report{BatchID: NewBatchID(), Timestamp: time.Now().UTC(), Source: o.Source, InputPath: o.Input, OutputPath: o.Output, DryRun: o.DryRun, ReloadAfterImport: o.ReloadAfterImport, Status: "ok", Categories: map[string]int{}, RuleTypes: map[string]int{}}
	if o.DryRun {
		rep.Status = "dry_run"
	}
	groups := map[string][]string{}
	seenBatch := map[string]bool{}
	err := inputRoot.Walk(func(path safepath.Path, d fs.DirEntry) error {
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink input path rejected: %s", path.String())
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path.String()))
		if ext != ".txt" && ext != ".list" && ext != ".csv" {
			return nil
		}
		rep.FilesScanned++
		rel, err := filepath.Rel(inputRoot.String(), path.String())
		if err != nil {
			return fmt.Errorf("relative input file path: %w", err)
		}
		cat := inferCategory(o.Category, rel)
		f, err := inputRoot.OpenRead(path)
		if err != nil {
			return err
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1024), o.MaxLineRunes*8+1024)
		seenFile := map[string]bool{}
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			rep.LinesRead++
			if strings.ContainsRune(line, 0) || !utf8.ValidString(line) || len([]rune(line)) > o.MaxLineRunes {
				rep.InvalidLines++
				rep.Warnings = append(rep.Warnings, "invalid line skipped in "+rel)
				if o.Strict {
					if closeErr := f.Close(); closeErr != nil {
						return fmt.Errorf("invalid line in %s; close input file: %w", rel, closeErr)
					}
					return errors.New("invalid line in " + rel)
				}
				continue
			}
			if line == "" || isCommentLine(line) {
				rep.BlankCommentSkipped++
				continue
			}
			typ := InferType(rel, line, o.Type)
			if typ == "domain" {
				if v, ok := isDomain(line); ok {
					line = v
				} else {
					rep.InvalidLines++
					if o.Strict {
						if closeErr := f.Close(); closeErr != nil {
							return fmt.Errorf("invalid domain in %s; close input file: %w", rel, closeErr)
						}
						return errors.New("invalid domain in " + rel)
					}
					continue
				}
			}
			if typ == "regex" {
				if _, err := regexp.Compile(line); err != nil {
					rep.InvalidRegex++
					rep.InvalidLines++
					rep.Warnings = append(rep.Warnings, "invalid regex skipped in "+rel+": "+line)
					if o.Strict {
						if closeErr := f.Close(); closeErr != nil {
							return fmt.Errorf("invalid regex in %s: %w; close input file: %v", rel, err, closeErr)
						}
						return err
					}
					continue
				}
			}
			key := typ + "\x00" + line
			if o.DedupeScope == "batch" {
				key = cat + "\x00" + key
				if seenBatch[key] {
					rep.DuplicatesRemoved++
					if len(rep.DuplicateExamples) < 100 {
						rep.DuplicateExamples = append(rep.DuplicateExamples, line)
					}
					continue
				}
				seenBatch[key] = true
			} else {
				if seenFile[key] {
					rep.DuplicatesRemoved++
					continue
				}
				seenFile[key] = true
			}
			groups[cat+"/"+typ] = append(groups[cat+"/"+typ], line)
			rep.Categories[cat]++
			rep.RuleTypes[typ]++
			switch typ {
			case "keyword":
				rep.KeywordsRead++
			case "domain":
				rep.DomainsRead++
			case "regex":
				rep.RegexRead++
			}
		}
		scanErr := sc.Err()
		closeErr := f.Close()
		if scanErr != nil {
			return scanErr
		}
		if closeErr != nil {
			return closeErr
		}
		return nil
	})
	if err != nil {
		rep.Status = "failed"
		rep.Errors = append(rep.Errors, err.Error())
		return rep, err
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		parts := strings.Split(k, "/")
		category := SanitizeCategory(parts[0])
		ruleType := SanitizeCategory(parts[1])
		vals := groups[k]
		sort.Strings(vals)
		for i, start := 1, 0; start < len(vals); i, start = i+1, start+o.MaxKeywordsPerFile {
			end := start + o.MaxKeywordsPerFile
			if end > len(vals) {
				end = len(vals)
			}
			sourceComponent := SanitizeCategory(o.Source)
			id := strings.ToLower(safeID.ReplaceAllString(fmt.Sprintf("%s_%s_%s_%03d", sourceComponent, category, ruleType, i), "_"))
			dst, err := outputRoot.Join(sourceComponent, category, ruleType, id+".yml")
			if err != nil {
				return rep, err
			}
			rep.OutputFiles = append(rep.OutputFiles, dst.String())
			if !o.DryRun {
				en := true
				rr := rules.Rule{ID: id, Type: ruleType, Category: category, RiskLevel: o.Risk, Action: o.Action, Score: 0, Description: "Imported from Sensitive-lexicon-compatible ruleset.", Source: o.Source, Tags: []string{"imported", o.Source, category, ruleType}, Enabled: &en}
				switch ruleType {
				case "keyword":
					rr.Keywords = vals[start:end]
				case "domain":
					rr.Domains = vals[start:end]
				case "regex":
					rr.Patterns = vals[start:end]
				}
				b, err := yaml.Marshal(rr)
				if err != nil {
					return rep, err
				}
				if err := outputRoot.WriteFileAtomic(dst, b); err != nil {
					return rep, err
				}
			}
		}
	}
	if o.ReloadAfterImport && !o.DryRun && o.ReloadURL != "" {
		rep.Reload = callReload(o.ReloadURL, o.APIKey)
		if rep.Reload.Error != "" || rep.Reload.StatusCode >= 300 {
			rep.Status = "reload_failed"
		}
	}
	rep.DurationMS = time.Since(start).Milliseconds()
	return rep, nil
}

func callReload(url, key string) *ReloadResult {
	rr := &ReloadResult{Attempted: true}
	c := http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		rr.Error = err.Error()
		return rr
	}
	if key != "" {
		req.Header.Set("X-API-Key", key)
	}
	resp, err := c.Do(req)
	if err != nil {
		rr.Error = err.Error()
		return rr
	}
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		rr.Error = err.Error()
	}
	if err := resp.Body.Close(); err != nil && rr.Error == "" {
		rr.Error = err.Error()
	}
	rr.StatusCode = resp.StatusCode
	if resp.StatusCode >= 300 {
		rr.Error = resp.Status
	}
	return rr
}
func WriteReport(rep *Report, path, format string) error {
	return WriteReportUnder(rep, "", path, format)
}

func WriteReportUnder(rep *Report, reportRoot, path, format string) error {
	if path == "" {
		return nil
	}
	var b []byte
	if format == "markdown" {
		b = []byte(fmt.Sprintf("# Import %s\n\nStatus: %s\nFiles scanned: %d\nLines read: %d\nDuplicates removed: %d\n", rep.BatchID, rep.Status, rep.FilesScanned, rep.LinesRead, rep.DuplicatesRemoved))
	} else {
		var err error
		b, err = json.MarshalIndent(rep, "", "  ")
		if err != nil {
			return err
		}
	}
	root, target, err := validatedReportTarget(reportRoot, path)
	if err != nil {
		return err
	}
	return root.WriteFileAtomic(target, b)
}

func validatedReportTarget(reportRoot, path string) (safepath.Root, safepath.Path, error) {
	if strings.TrimSpace(reportRoot) != "" {
		root, err := safepath.NewRoot(reportRoot, safepath.RejectParentTraversal(), safepath.CreateRoot())
		if err != nil {
			return safepath.Root{}, safepath.Path{}, fmt.Errorf("report root: %w", err)
		}
		target, err := root.Resolve(path)
		if err != nil {
			return safepath.Root{}, safepath.Path{}, err
		}
		return root, target, nil
	}
	root, target, err := safepath.NewFileTarget(path, safepath.CreateRoot())
	if err != nil {
		return safepath.Root{}, safepath.Path{}, err
	}
	return root, target, nil
}
