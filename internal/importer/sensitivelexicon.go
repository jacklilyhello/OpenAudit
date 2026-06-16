package importer

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/openaudit/openaudit/internal/rules"
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
	inputRoot  validatedRoot
	outputRoot validatedRoot
}

type validatedRoot struct {
	abs string
}

type validatedPath struct {
	abs string
}

func (p validatedPath) String() string { return p.abs }
func (r validatedRoot) String() string { return r.abs }

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
func cleanUserPath(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", errors.New("path is empty")
	}
	if strings.ContainsRune(p, 0) {
		return "", errors.New("path contains NUL")
	}
	if containsParentTraversal(p) {
		return "", errors.New("path contains parent traversal")
	}
	cleaned := filepath.Clean(p)
	if cleaned == "." {
		return "", errors.New("path resolves to current directory")
	}
	if containsParentTraversal(cleaned) {
		return "", errors.New("path contains parent traversal")
	}
	return cleaned, nil
}

func containsParentTraversal(p string) bool {
	p = strings.ReplaceAll(filepath.ToSlash(p), "\\", "/")
	for _, part := range strings.Split(p, "/") {
		if part == ".." {
			return true
		}
	}
	return false
}

func absCleanPath(p string) (string, error) {
	cleaned, err := cleanUserPath(p)
	if err != nil {
		return "", err
	}
	abs, err := filepath.Abs(cleaned)
	if err != nil {
		return "", fmt.Errorf("absolute path: %w", err)
	}
	return filepath.Clean(abs), nil
}

func ensurePathUnder(baseAbs, candidateAbs string) error {
	if !filepath.IsAbs(baseAbs) || !filepath.IsAbs(candidateAbs) {
		return errors.New("path safety check requires absolute paths")
	}
	baseAbs = filepath.Clean(baseAbs)
	candidateAbs = filepath.Clean(candidateAbs)
	rel, err := filepath.Rel(baseAbs, candidateAbs)
	if err != nil {
		return fmt.Errorf("relative path check: %w", err)
	}
	if relEscapesBase(rel) || filepath.IsAbs(rel) {
		return fmt.Errorf("path %q escapes base %q", candidateAbs, baseAbs)
	}
	return nil
}

func relEscapesBase(rel string) bool {
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

func isCommentLine(line string) bool {
	return len(line) >= 1 && line[:1] == "#" || len(line) >= 2 && line[:2] == "//" || len(line) >= 1 && line[:1] == ";"
}

func safeJoinUnder(baseAbs string, elems ...string) (string, error) {
	if !filepath.IsAbs(baseAbs) {
		return "", errors.New("safe join base must be absolute")
	}
	cleanElems := make([]string, 0, len(elems))
	for _, elem := range elems {
		if strings.TrimSpace(elem) == "" {
			return "", errors.New("empty path component")
		}
		if strings.ContainsRune(elem, 0) {
			return "", errors.New("path component contains NUL")
		}
		if filepath.IsAbs(elem) {
			return "", errors.New("absolute path component rejected")
		}
		if containsParentTraversal(elem) {
			return "", errors.New("path component contains parent traversal")
		}
		cleaned := filepath.Clean(elem)
		for _, part := range strings.Split(filepath.ToSlash(cleaned), "/") {
			if part == ".." {
				return "", errors.New("path component contains parent traversal")
			}
		}
		cleanElems = append(cleanElems, cleaned)
	}
	joined := filepath.Join(append([]string{baseAbs}, cleanElems...)...)
	joinedAbs, err := filepath.Abs(joined)
	if err != nil {
		return "", fmt.Errorf("absolute joined path: %w", err)
	}
	joinedAbs = filepath.Clean(joinedAbs)
	if err := ensurePathUnder(baseAbs, joinedAbs); err != nil {
		return "", err
	}
	return joinedAbs, nil
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
	inputRoot, err := newValidatedRoot(opts.Input, true, false)
	if err != nil {
		return ValidatedOptions{}, err
	}
	outputRoot, err := newValidatedRoot(opts.Output, false, !opts.DryRun)
	if err != nil {
		return ValidatedOptions{}, err
	}
	displayInput, _ := cleanUserPath(opts.Input)
	displayOutput, _ := cleanUserPath(opts.Output)
	opts.Input = displayInput
	opts.Output = displayOutput
	return ValidatedOptions{Options: opts, inputRoot: inputRoot, outputRoot: outputRoot}, nil
}

func resolvePathUnderDefaultRoot(rawPath, defaultRoot, field string) (string, error) {
	defaultRootAbs, err := absCleanPath(defaultRoot)
	if err != nil {
		return "", fmt.Errorf("%s default root: %w", field, err)
	}
	provided := strings.TrimSpace(rawPath)
	if provided == "" {
		return defaultRootAbs, nil
	}
	if strings.ContainsRune(provided, 0) {
		return "", fmt.Errorf("%s contains NUL", field)
	}
	if containsParentTraversal(provided) {
		return "", fmt.Errorf("%s contains parent traversal", field)
	}
	var candidateAbs string
	if filepath.IsAbs(provided) {
		candidateAbs, err = absCleanPath(provided)
	} else {
		candidateAbs, err = safeJoinUnder(defaultRootAbs, provided)
	}
	if err != nil {
		return "", fmt.Errorf("%s: %w", field, err)
	}
	if err := ensurePathUnder(defaultRootAbs, candidateAbs); err != nil {
		return "", fmt.Errorf("%s outside configured root: %w", field, err)
	}
	return candidateAbs, nil
}

func newValidatedRoot(raw string, requireExistingDir bool, create bool) (validatedRoot, error) {
	rootAbs, err := absCleanPath(raw)
	if err != nil {
		return validatedRoot{}, err
	}
	root := validatedRoot{abs: rootAbs}
	rootPath := root.path()
	info, err := root.lstat(rootPath)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return validatedRoot{}, errors.New("root symlink rejected")
		}
		if !info.IsDir() {
			return validatedRoot{}, errors.New("root is not a directory")
		}
		return root, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return validatedRoot{}, fmt.Errorf("stat root: %w", err)
	}
	if requireExistingDir {
		return validatedRoot{}, fmt.Errorf("stat root: %w", err)
	}
	if create {
		if err := root.MkdirAll0750(rootPath); err != nil {
			return validatedRoot{}, fmt.Errorf("create root: %w", err)
		}
	}
	return root, nil
}

func (r validatedRoot) path() validatedPath {
	return validatedPath{abs: r.abs}
}

func (r validatedRoot) ensureContains(p validatedPath) error {
	if r.abs == "" || strings.ContainsRune(r.abs, 0) || !filepath.IsAbs(r.abs) {
		return errors.New("validated root is invalid")
	}
	if p.abs == "" || strings.ContainsRune(p.abs, 0) || !filepath.IsAbs(p.abs) {
		return errors.New("validated path is invalid")
	}
	return ensurePathUnder(r.abs, p.abs)
}

func (r validatedRoot) ValidateAbs(candidate string) (validatedPath, error) {
	if candidate == "" {
		return validatedPath{}, errors.New("path is empty")
	}
	if strings.ContainsRune(candidate, 0) {
		return validatedPath{}, errors.New("path contains NUL")
	}
	if !filepath.IsAbs(candidate) {
		return validatedPath{}, errors.New("path must be absolute")
	}
	candidateAbs := filepath.Clean(candidate)
	if containsParentTraversal(candidateAbs) {
		return validatedPath{}, errors.New("path contains parent traversal")
	}
	p := validatedPath{abs: candidateAbs}
	if err := r.ensureContains(p); err != nil {
		return validatedPath{}, err
	}
	return p, nil
}

func (r validatedRoot) JoinClean(elems ...string) (validatedPath, error) {
	joinedAbs, err := safeJoinUnder(r.abs, elems...)
	if err != nil {
		return validatedPath{}, err
	}
	return r.ValidateAbs(joinedAbs)
}

func (r validatedRoot) joinUnderPath(base validatedPath, elems ...string) (validatedPath, error) {
	if err := r.ensureContains(base); err != nil {
		return validatedPath{}, err
	}
	joinedAbs, err := safeJoinUnder(base.abs, elems...)
	if err != nil {
		return validatedPath{}, err
	}
	return r.ValidateAbs(joinedAbs)
}

func (r validatedRoot) Parent(p validatedPath) (validatedPath, error) {
	if err := r.ensureContains(p); err != nil {
		return validatedPath{}, err
	}
	return r.ValidateAbs(filepath.Clean(filepath.Dir(p.abs)))
}

func (r validatedRoot) lstat(p validatedPath) (fs.FileInfo, error) {
	if err := r.ensureContains(p); err != nil {
		return nil, err
	}
	return os.Lstat(p.abs)
}

func (r validatedRoot) MkdirAll0750(p validatedPath) error {
	if err := r.ensureContains(p); err != nil {
		return err
	}
	if info, err := r.lstat(p); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("directory symlink rejected")
		}
		if !info.IsDir() {
			return errors.New("path exists and is not a directory")
		}
		return nil
	}
	if err := os.MkdirAll(p.abs, 0750); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}
	return nil
}

func (r validatedRoot) OpenInputFile(p validatedPath) (*os.File, error) {
	info, err := r.lstat(p)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("input file symlink rejected")
	}
	if info.IsDir() {
		return nil, errors.New("input file is a directory")
	}
	return os.Open(p.abs) // #nosec G304,G305 -- p is a validatedPath with unexported fields, constrained under validatedRoot, and symlink/directories are rejected before opening.
}

func (r validatedRoot) WriteFile0600Atomic(p validatedPath, data []byte) error {
	if err := r.ensureContains(p); err != nil {
		return err
	}
	parent, err := r.Parent(p)
	if err != nil {
		return err
	}
	if err := r.MkdirAll0750(parent); err != nil {
		return err
	}
	tmpPath, err := r.tempFilePath(parent)
	if err != nil {
		return err
	}
	tmp, err := r.openTempFile0600(tmpPath)
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = r.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		closeErr := tmp.Close()
		if closeErr != nil {
			return fmt.Errorf("write temp file: %w; close temp file: %v", err, closeErr)
		}
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Chmod(0600); err != nil {
		closeErr := tmp.Close()
		if closeErr != nil {
			return fmt.Errorf("chmod temp file: %w; close temp file: %v", err, closeErr)
		}
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := r.RenameWithinRoot(tmpPath, p); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}
	cleanup = false
	return nil
}

func (r validatedRoot) tempFilePath(parent validatedPath) (validatedPath, error) {
	tmpName := fmt.Sprintf(".openaudit-import-%d.tmp", time.Now().UnixNano())
	return r.joinUnderPath(parent, tmpName)
}

func (r validatedRoot) openTempFile0600(p validatedPath) (*os.File, error) {
	if err := r.ensureContains(p); err != nil {
		return nil, err
	}
	return os.OpenFile(p.abs, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600) // #nosec G304 -- p is a generated validatedPath under validatedRoot and is created with 0600 permissions.
}

func (r validatedRoot) Remove(p validatedPath) error {
	if err := r.ensureContains(p); err != nil {
		return err
	}
	return os.Remove(p.abs)
}

func (r validatedRoot) RenameWithinRoot(oldPath validatedPath, newPath validatedPath) error {
	if err := r.ensureContains(oldPath); err != nil {
		return err
	}
	if err := r.ensureContains(newPath); err != nil {
		return err
	}
	return os.Rename(oldPath.abs, newPath.abs)
}

func (r validatedRoot) Walk(fn func(validatedPath, fs.DirEntry) error) error {
	rootPath := r.path()
	info, err := r.lstat(rootPath)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("input root symlink rejected")
	}
	if !info.IsDir() {
		return errors.New("input root is not a directory")
	}
	return r.walkDir(rootPath, fn)
}

func (r validatedRoot) walkDir(dir validatedPath, fn func(validatedPath, fs.DirEntry) error) error {
	if err := r.ensureContains(dir); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir.abs)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		child, err := r.joinUnderPath(dir, entry.Name())
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink input path rejected: %s", child.abs)
		}
		if entry.IsDir() {
			if err := r.walkDir(child, fn); err != nil {
				return err
			}
			continue
		}
		if err := fn(child, entry); err != nil {
			return err
		}
	}
	return nil
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
	if o.inputRoot.abs == "" || o.outputRoot.abs == "" {
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
	err := inputRoot.Walk(func(path validatedPath, d fs.DirEntry) error {
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
		f, err := inputRoot.OpenInputFile(path)
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
					_ = f.Close()
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
						_ = f.Close()
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
						_ = f.Close()
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
			dst, err := outputRoot.JoinClean(sourceComponent, category, ruleType, id+".yml")
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
				if err := outputRoot.WriteFile0600Atomic(dst, b); err != nil {
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
	return root.WriteFile0600Atomic(target, b)
}

func validatedReportTarget(reportRoot, path string) (validatedRoot, validatedPath, error) {
	targetAbs, err := absCleanPath(path)
	if err != nil {
		return validatedRoot{}, validatedPath{}, err
	}
	if strings.TrimSpace(reportRoot) != "" {
		root, err := newValidatedRoot(reportRoot, false, true)
		if err != nil {
			return validatedRoot{}, validatedPath{}, fmt.Errorf("report root: %w", err)
		}
		target, err := root.ValidateAbs(targetAbs)
		if err != nil {
			return validatedRoot{}, validatedPath{}, err
		}
		return root, target, nil
	}
	parentAbs := filepath.Clean(filepath.Dir(targetAbs))
	root, err := newValidatedRoot(parentAbs, false, true)
	if err != nil {
		return validatedRoot{}, validatedPath{}, err
	}
	target, err := root.ValidateAbs(targetAbs)
	if err != nil {
		return validatedRoot{}, validatedPath{}, err
	}
	return root, target, nil
}
