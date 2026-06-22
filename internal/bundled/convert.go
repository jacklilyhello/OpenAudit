package bundled

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/openaudit/openaudit/internal/safepath"
)

type sourceRecord struct {
	Group, UpstreamID string
	Pattern           *string
	Empty             bool
	Malformed         *MalformedRecord
}
type parsedDoc struct {
	records []sourceRecord
	unknown []UnknownGroup
}

func BuildPack(input []byte, opt Options) (Pack, Report, []byte, []byte, error) {
	if opt.Limits == (Limits{}) {
		opt.Limits = DefaultLimits()
	}
	if int64(len(input)) > opt.Limits.InputJSONBytes {
		return Pack{}, Report{}, nil, nil, fmt.Errorf("input JSON exceeds limit")
	}
	if !ValidDataset(opt.Dataset) {
		return Pack{}, Report{}, nil, nil, fmt.Errorf("invalid dataset %q", opt.Dataset)
	}
	if opt.SourceCommit != "" && !isHexLen(opt.SourceCommit, 40) {
		return Pack{}, Report{}, nil, nil, errors.New("source commit must be a full 40-character SHA")
	}
	if opt.Timestamp.IsZero() {
		ts, err := reproducibleTime()
		if err != nil {
			return Pack{}, Report{}, nil, nil, err
		}
		opt.Timestamp = ts
	}
	if opt.LicenseIdentifier == "" {
		opt.LicenseIdentifier = "NOASSERTION"
	}
	doc, err := parse(input, opt.Dataset, opt.Limits)
	if err != nil {
		return Pack{}, Report{}, nil, nil, err
	}
	sum := sha256.Sum256(input)
	pack := Pack{SchemaVersion: SchemaVersion, Provider: ProviderNetEase, Dataset: opt.Dataset, SourceRepository: opt.SourceRepository, SourceCommit: strings.ToLower(opt.SourceCommit), SourceFilePath: opt.SourceFilePath, SourceInputSHA256: hex.EncodeToString(sum[:]), LicenseIdentifier: opt.LicenseIdentifier, SourceTimestamp: opt.Timestamp.UTC().Format(time.RFC3339), GeneratorName: GeneratorName, GeneratorVersion: GeneratorVersion}
	seenID, seenRegex := map[string]int{}, map[string]int{}
	failures := []CompatibilityFailure{}
	malformed := []MalformedRecord{}
	sort.SliceStable(doc.records, func(i, j int) bool {
		if doc.records[i].Group != doc.records[j].Group {
			return groupIndex(doc.records[i].Group) < groupIndex(doc.records[j].Group)
		}
		return idLess(doc.records[i].UpstreamID, doc.records[j].UpstreamID)
	})
	for _, r := range doc.records {
		pack.Counts.TotalSourceRules++
		if r.Empty {
			pack.Counts.EmptyRecords++
			continue
		}
		if r.Malformed != nil {
			pack.Counts.MalformedRecords++
			malformed = append(malformed, *r.Malformed)
			continue
		}
		pack.Counts.ParsedRules++
		pack.Counts.ImportedRecords++
		ident := opt.Dataset + "/" + r.Group + "/" + r.UpstreamID
		seenID[ident]++
		if seenID[ident] > 1 {
			pack.Counts.DuplicateIdentities++
		}
		if seenRegex[*r.Pattern] > 0 {
			pack.Counts.DuplicateRegexContent++
		}
		seenRegex[*r.Pattern]++
		m, _ := Mapping(r.Group)
		id := stableID(opt.Dataset, r.Group, r.UpstreamID, seenID[ident])
		pr := PackRule{ID: id, Provider: ProviderNetEase, Dataset: opt.Dataset, Group: r.Group, UpstreamID: r.UpstreamID, OriginalRegex: *r.Pattern, Type: "regex", Category: m.Category, RiskLevel: "high", Action: m.Action, Score: 90, Source: "bundled:netease", Tags: []string{"bundled", "provider:netease", "dataset:" + opt.Dataset, r.Group}, Description: "NetEase bundled " + r.Group + " regex", Enabled: m.Enabled, Metadata: m.Metadata, PCRE2Status: PCRE2NotChecked}
		if len([]byte(*r.Pattern)) > opt.Limits.PatternBytes {
			pr.RE2Error = "pattern exceeds size limit"
			pr.RE2FeatureHint = "invalid_syntax"
		} else if _, err := regexp.Compile(*r.Pattern); err != nil {
			pr.RE2Error = err.Error()
			pr.RE2FeatureHint = hint(*r.Pattern, err)
		} else {
			pr.RE2Compatible = true
		}
		if pr.RE2Compatible {
			pack.Counts.RE2Compatible++
		} else {
			pack.Counts.RE2Incompatible++
			ps := sha256.Sum256([]byte(*r.Pattern))
			failures = append(failures, CompatibilityFailure{Dataset: opt.Dataset, Group: r.Group, UpstreamID: r.UpstreamID, GeneratedRuleID: id, PatternSHA256: hex.EncodeToString(ps[:]), CompilerError: pr.RE2Error, FeatureHint: pr.RE2FeatureHint})
		}
		if !pr.Enabled {
			pack.Counts.DisabledRules++
		}
		pack.Rules = append(pack.Rules, pr)
	}
	pack.Counts.ByDataset = []NameCount{{opt.Dataset, len(pack.Rules)}}
	pack.Counts.ByGroup = groupCounts(pack.Rules)
	pack.Counts.PCRE2Status = statusCounts(pack.Rules)
	if err := ValidatePack(pack, opt.Limits); err != nil {
		return Pack{}, Report{}, nil, nil, err
	}
	jsonBytes, err := MarshalPack(pack)
	if err != nil {
		return Pack{}, Report{}, nil, nil, err
	}
	gz, err := GzipDeterministic(jsonBytes)
	if err != nil {
		return Pack{}, Report{}, nil, nil, err
	}
	ps := sha256.Sum256(gz)
	rep := Report{SchemaVersion: SchemaVersion, Provider: ProviderNetEase, Dataset: opt.Dataset, UpstreamRepository: opt.SourceRepository, PinnedSourceCommit: strings.ToLower(opt.SourceCommit), SourceFilePath: opt.SourceFilePath, SourceInputBytes: int64(len(input)), SourceInputSHA256: pack.SourceInputSHA256, GeneratedPackPath: opt.OutputPath, GeneratedReportPath: opt.ReportPath, GeneratedPackBytes: int64(len(gz)), GeneratedPackSHA256: hex.EncodeToString(ps[:]), TotalSourceRules: pack.Counts.TotalSourceRules, ParsedRules: pack.Counts.ParsedRules, ImportedRecords: pack.Counts.ImportedRecords, EmptyRecords: pack.Counts.EmptyRecords, MalformedRecords: pack.Counts.MalformedRecords, MalformedRecordDetails: malformed, DuplicateIdentities: pack.Counts.DuplicateIdentities, DuplicateRegexContent: pack.Counts.DuplicateRegexContent, RE2CompatibleRules: pack.Counts.RE2Compatible, RE2IncompatibleRules: pack.Counts.RE2Incompatible, PCRE2StatusCounts: pack.Counts.PCRE2Status, DisabledRules: pack.Counts.DisabledRules, CountsByDataset: pack.Counts.ByDataset, CountsByGroup: pack.Counts.ByGroup, UnknownGroups: doc.unknown, CompatibilityFailures: failures}
	if opt.OutputPath != "" {
		rep.GeneratedOutputFiles = append(rep.GeneratedOutputFiles, opt.OutputPath)
	}
	if opt.ReportPath != "" {
		rep.GeneratedOutputFiles = append(rep.GeneratedOutputFiles, opt.ReportPath)
	}
	return pack, rep, jsonBytes, gz, nil
}

func parse(input []byte, dataset string, lim Limits) (parsedDoc, error) {
	dec := json.NewDecoder(bytes.NewReader(input))
	tok, err := dec.Token()
	if err != nil {
		return parsedDoc{}, fmt.Errorf("invalid JSON: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return parsedDoc{}, errors.New("root JSON must be an object")
	}
	var out parsedDoc
	seenTop := map[string]bool{}
	seenGroup := map[string]bool{}
	sawRegex := false
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return parsedDoc{}, err
		}
		key := kt.(string)
		lk := strings.ToLower(key)
		if seenTop[lk] {
			return parsedDoc{}, fmt.Errorf("duplicate top-level key %q", key)
		}
		seenTop[lk] = true
		switch lk {
		case "regex":
			sawRegex = true
			if err := parseRegex(dec, dataset, lim, &out, seenGroup); err != nil {
				return parsedDoc{}, err
			}
		default:
			var discard json.RawMessage
			if err := dec.Decode(&discard); err != nil {
				return parsedDoc{}, err
			}
		}
	}
	if _, err := dec.Token(); err != nil {
		return parsedDoc{}, err
	}
	if !sawRegex {
		return parsedDoc{}, errors.New("missing regex object")
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return parsedDoc{}, errors.New("trailing JSON value rejected")
		}
		return parsedDoc{}, fmt.Errorf("trailing data rejected: %w", err)
	}
	sort.Slice(out.unknown, func(i, j int) bool { return out.unknown[i].Name < out.unknown[j].Name })
	return out, nil
}
func parseRegex(dec *json.Decoder, dataset string, lim Limits, out *parsedDoc, seenGroup map[string]bool) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return errors.New("regex must be an object")
	}
	for dec.More() {
		kt, _ := dec.Token()
		raw := kt.(string)
		g, ok := CanonicalGroup(raw)
		lower := strings.ToLower(raw)
		if seenGroup[lower] || (ok && seenGroup[g]) {
			return fmt.Errorf("duplicate group key %q", raw)
		}
		if ok {
			seenGroup[g] = true
		} else {
			seenGroup[lower] = true
		}
		if !ok {
			n, err := countObjectRecords(dec)
			if err != nil {
				return err
			}
			out.unknown = append(out.unknown, UnknownGroup{Name: raw, RecordCount: n})
			continue
		}
		if err := parseGroup(dec, dataset, g, lim, out); err != nil {
			return err
		}
	}
	_, err = dec.Token()
	return err
}
func parseGroup(dec *json.Decoder, dataset, group string, lim Limits, out *parsedDoc) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return fmt.Errorf("regex.%s must be an object", group)
	}
	seenIDs := map[string]bool{}
	for dec.More() {
		kt, _ := dec.Token()
		id := kt.(string)
		if id == "" {
			return fmt.Errorf("regex.%s contains empty upstream ID", group)
		}
		if seenIDs[id] {
			return fmt.Errorf("duplicate upstream ID regex.%s.%s", group, id)
		}
		seenIDs[id] = true
		if len(out.records) >= lim.RuleCount {
			return errors.New("rule count exceeds limit")
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return err
		}
		rec := sourceRecord{Group: group, UpstreamID: id}
		vt := valueType(raw)
		if bytes.Equal(raw, []byte("null")) {
			rec.Empty = true
		} else {
			var s string
			if err := json.Unmarshal(raw, &s); err != nil {
				rec.Malformed = &MalformedRecord{Dataset: dataset, Group: group, UpstreamID: id, Reason: "value must be a string or null", ValueType: vt}
			} else if strings.TrimSpace(s) == "" {
				rec.Empty = true
			} else {
				ss := s
				rec.Pattern = &ss
			}
		}
		out.records = append(out.records, rec)
	}
	_, err = dec.Token()
	return err
}
func countObjectRecords(dec *json.Decoder) (int, error) {
	tok, err := dec.Token()
	if err != nil {
		return 0, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		var discard json.RawMessage
		return 0, dec.Decode(&discard)
	}
	n := 0
	for dec.More() {
		if _, err := dec.Token(); err != nil {
			return n, err
		}
		n++
		var discard json.RawMessage
		if err := dec.Decode(&discard); err != nil {
			return n, err
		}
	}
	_, err = dec.Token()
	return n, err
}
func valueType(raw []byte) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return "empty"
	}
	switch raw[0] {
	case '"':
		return "string"
	case 'n':
		return "null"
	case 't', 'f':
		return "boolean"
	case '[':
		return "array"
	case '{':
		return "object"
	default:
		return "number"
	}
}

func ValidatePack(p Pack, lim Limits) error {
	if lim == (Limits{}) {
		lim = DefaultLimits()
	}
	if p.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported schema_version %d", p.SchemaVersion)
	}
	if p.Provider != ProviderNetEase {
		return errors.New("invalid provider")
	}
	if !ValidDataset(p.Dataset) {
		return errors.New("invalid dataset")
	}
	if strings.TrimSpace(p.SourceRepository) == "" {
		return errors.New("source repository is required")
	}
	if !isHexLen(p.SourceCommit, 40) {
		return errors.New("source commit must be 40 hex characters")
	}
	if err := validateRelativeSafePath(p.SourceFilePath); err != nil {
		return fmt.Errorf("source file path: %w", err)
	}
	if !isHexLen(p.SourceInputSHA256, 64) {
		return errors.New("source input sha256 must be 64 hex characters")
	}
	if p.LicenseIdentifier == "" || p.GeneratorName == "" || p.GeneratorVersion == "" {
		return errors.New("license and generator fields are required")
	}
	if len(p.Rules) > lim.RuleCount {
		return errors.New("rule count exceeds limit")
	}
	ids := map[string]bool{}
	regexSeen := map[string]int{}
	counts := Counts{ByDataset: []NameCount{{p.Dataset, len(p.Rules)}}}
	status := map[string]int{}
	group := map[string]int{}
	for _, g := range groupOrder {
		group[g] = 0
	}
	for _, r := range p.Rules {
		if r.Provider != p.Provider || r.Dataset != p.Dataset {
			return errors.New("rule provider/dataset mismatch")
		}
		m, ok := Mapping(r.Group)
		if !ok {
			return fmt.Errorf("invalid group %q", r.Group)
		}
		if r.UpstreamID == "" || r.ID == "" {
			return errors.New("rule IDs must be non-empty")
		}
		if ids[r.ID] {
			return fmt.Errorf("duplicate generated rule ID %q", r.ID)
		}
		ids[r.ID] = true
		if r.Type != "regex" {
			return errors.New("rule type must be regex")
		}
		if len([]byte(r.OriginalRegex)) > lim.PatternBytes {
			return errors.New("pattern exceeds size limit")
		}
		if metadataSize(r) > lim.MetadataBytes {
			return errors.New("metadata exceeds size limit")
		}
		if r.PCRE2Status != PCRE2NotChecked && r.PCRE2Status != PCRE2Compatible && r.PCRE2Status != PCRE2Incompatible {
			return errors.New("invalid PCRE2 status")
		}
		if r.RE2Compatible && r.RE2Error != "" {
			return errors.New("RE2 compatible rule has error")
		}
		if !r.RE2Compatible && r.RE2Error == "" {
			return errors.New("RE2 incompatible rule missing error")
		}
		if r.Action != m.Action || r.Category != m.Category || r.Enabled != m.Enabled {
			return errors.New("rule mapping mismatch")
		}
		counts.ImportedRecords++
		counts.ParsedRules++
		if r.RE2Compatible {
			counts.RE2Compatible++
		} else {
			counts.RE2Incompatible++
		}
		if !r.Enabled {
			counts.DisabledRules++
		}
		regexSeen[r.OriginalRegex]++
		if regexSeen[r.OriginalRegex] > 1 {
			counts.DuplicateRegexContent++
		}
		status[r.PCRE2Status]++
		group[r.Group]++
	}
	counts.TotalSourceRules = p.Counts.TotalSourceRules
	counts.EmptyRecords = p.Counts.EmptyRecords
	counts.MalformedRecords = p.Counts.MalformedRecords
	counts.DuplicateIdentities = p.Counts.DuplicateIdentities
	counts.ByGroup = groupNameCounts(group)
	counts.PCRE2Status = statusNameCounts(status)
	if counts.TotalSourceRules != counts.ImportedRecords+counts.EmptyRecords+counts.MalformedRecords {
		return errors.New("source record counts do not add up")
	}
	if p.Counts.ParsedRules != counts.ParsedRules || p.Counts.ImportedRecords != counts.ImportedRecords || p.Counts.DuplicateRegexContent != counts.DuplicateRegexContent || p.Counts.RE2Compatible != counts.RE2Compatible || p.Counts.RE2Incompatible != counts.RE2Incompatible || p.Counts.DisabledRules != counts.DisabledRules {
		return errors.New("pack counts do not match rules")
	}
	if !nameCountsEqual(p.Counts.ByDataset, counts.ByDataset) || !nameCountsEqual(p.Counts.ByGroup, counts.ByGroup) || !nameCountsEqual(p.Counts.PCRE2Status, counts.PCRE2Status) {
		return errors.New("pack aggregate counts do not match rules")
	}
	return nil
}

func ValidateReportForPack(rep Report, pack Pack, packBytes []byte) error {
	sum := sha256.Sum256(packBytes)
	if rep.GeneratedPackSHA256 != hex.EncodeToString(sum[:]) {
		return errors.New("report pack sha256 mismatch")
	}
	if rep.GeneratedPackBytes != int64(len(packBytes)) {
		return errors.New("report pack size mismatch")
	}
	if rep.Provider != pack.Provider || rep.Dataset != pack.Dataset || rep.UpstreamRepository != pack.SourceRepository || rep.PinnedSourceCommit != pack.SourceCommit || rep.SourceFilePath != pack.SourceFilePath {
		return errors.New("report provenance mismatch")
	}
	if rep.ImportedRecords != pack.Counts.ImportedRecords || rep.EmptyRecords != pack.Counts.EmptyRecords || rep.MalformedRecords != pack.Counts.MalformedRecords {
		return errors.New("report counts mismatch")
	}
	return nil
}
func MarshalReport(r Report) ([]byte, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
func MarshalPack(p Pack) ([]byte, error) {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
func GzipDeterministic(b []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	zw.Header.ModTime = time.Unix(0, 0).UTC()
	if _, err := zw.Write(b); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
func ReadPackGzip(b []byte, lim Limits) (Pack, error) {
	if lim == (Limits{}) {
		lim = DefaultLimits()
	}
	if int64(len(b)) > lim.CompressedPackBytes {
		return Pack{}, errors.New("compressed pack exceeds limit")
	}
	br := bytes.NewReader(b)
	zr, err := gzip.NewReader(br)
	if err != nil {
		return Pack{}, fmt.Errorf("invalid gzip: %w", err)
	}
	zr.Multistream(false)
	data, err := io.ReadAll(io.LimitReader(zr, lim.UncompressedPackBytes+1))
	closeErr := zr.Close()
	if err != nil {
		return Pack{}, fmt.Errorf("read gzip: %w", err)
	}
	if closeErr != nil {
		return Pack{}, fmt.Errorf("close gzip: %w", closeErr)
	}
	if br.Len() != 0 {
		return Pack{}, errors.New("trailing gzip data rejected")
	}
	if int64(len(data)) > lim.UncompressedPackBytes {
		return Pack{}, errors.New("uncompressed pack exceeds limit")
	}
	var p Pack
	if err := json.Unmarshal(data, &p); err != nil {
		return Pack{}, fmt.Errorf("invalid pack JSON: %w", err)
	}
	if err := ValidatePack(p, lim); err != nil {
		return Pack{}, err
	}
	return p, nil
}
func WriteAtomic(path string, data []byte) error {
	root, target, err := safepath.NewFileTarget(path)
	if err != nil {
		return err
	}
	return root.WriteFileAtomic(target, data)
}
func ConvertFile(inputPath string, opt Options, dry bool) (Report, error) {
	b, err := readLimitedFile(inputPath, opt.Limits)
	if err != nil {
		return Report{}, err
	}
	pack, rep, _, gz, err := BuildPack(b, opt)
	if err != nil {
		return rep, err
	}
	if _, err := ReadPackGzip(gz, opt.Limits); err != nil {
		return rep, err
	}
	if err := ValidatePack(pack, opt.Limits); err != nil {
		return rep, err
	}
	rb, err := MarshalReport(rep)
	if err != nil {
		return rep, err
	}
	if err := ValidateReportForPack(rep, pack, gz); err != nil {
		return rep, err
	}
	if !dry {
		if opt.OutputPath == "" || opt.ReportPath == "" {
			return rep, errors.New("output and report paths are required")
		}
		if err := WriteAtomic(opt.OutputPath, gz); err != nil {
			return rep, err
		}
		if err := WriteAtomic(opt.ReportPath, rb); err != nil {
			return rep, fmt.Errorf("write report after pack succeeded: %w", err)
		}
	}
	return rep, nil
}
func readLimitedFile(path string, lim Limits) ([]byte, error) {
	if lim == (Limits{}) {
		lim = DefaultLimits()
	}
	// #nosec G304 -- local operator-supplied converter input path; source JSON is parsed as untrusted data with explicit limits.
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && st.Size() > lim.InputJSONBytes {
		return nil, errors.New("input JSON exceeds limit")
	}
	data, err := io.ReadAll(io.LimitReader(f, lim.InputJSONBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > lim.InputJSONBytes {
		return nil, errors.New("input JSON exceeds limit")
	}
	return data, nil
}

func stableID(d, g, id string, n int) string {
	s := d + ":" + g + ":" + id + ":" + strconv.Itoa(n)
	h := sha256.Sum256([]byte(s))
	return "netease_" + d + "_" + g + "_" + hex.EncodeToString(h[:])[:16]
}
func idLess(a, b string) bool {
	ai, ae := strconv.ParseInt(a, 10, 64)
	bi, be := strconv.ParseInt(b, 10, 64)
	if ae == nil && be == nil {
		return ai < bi
	}
	return a < b
}
func groupIndex(g string) int {
	for i, v := range groupOrder {
		if v == g {
			return i
		}
	}
	return 99
}
func groupCounts(r []PackRule) []NameCount {
	m := map[string]int{}
	for _, g := range groupOrder {
		m[g] = 0
	}
	for _, x := range r {
		m[x.Group]++
	}
	return groupNameCounts(m)
}
func groupNameCounts(m map[string]int) []NameCount {
	out := []NameCount{}
	for _, g := range groupOrder {
		out = append(out, NameCount{g, m[g]})
	}
	return out
}
func statusCounts(r []PackRule) []NameCount {
	m := map[string]int{}
	for _, x := range r {
		m[x.PCRE2Status]++
	}
	return statusNameCounts(m)
}
func statusNameCounts(m map[string]int) []NameCount {
	order := []string{PCRE2NotChecked, PCRE2Compatible, PCRE2Incompatible}
	out := []NameCount{}
	for _, k := range order {
		if m[k] > 0 || k == PCRE2NotChecked {
			out = append(out, NameCount{k, m[k]})
		}
	}
	return out
}
func nameCountsEqual(a, b []NameCount) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func hint(p string, err error) string {
	switch {
	case strings.Contains(p, "(?="):
		return "lookahead"
	case strings.Contains(p, "(?<=") || strings.Contains(p, "(?<!"):
		return "lookbehind"
	case regexp.MustCompile(`\\[1-9]`).MatchString(p):
		return "backreference"
	case strings.Contains(err.Error(), "invalid escape"):
		return "unsupported_escape"
	case err != nil:
		return "invalid_syntax"
	}
	return "unknown"
}
func reproducibleTime() (time.Time, error) {
	if v := strings.TrimSpace(os.Getenv("SOURCE_DATE_EPOCH")); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return time.Time{}, fmt.Errorf("invalid SOURCE_DATE_EPOCH: %w", err)
		}
		return time.Unix(n, 0).UTC(), nil
	}
	return time.Unix(0, 0).UTC(), nil
}
func isHexLen(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}
func validateRelativeSafePath(p string) error {
	p = strings.TrimSpace(p)
	if p == "" {
		return errors.New("path is required")
	}
	if strings.ContainsRune(p, '\x00') {
		return errors.New("path contains NUL")
	}
	if filepath.IsAbs(p) {
		return errors.New("path must be relative")
	}
	cleaned := filepath.Clean(p)
	for _, part := range strings.Split(filepath.ToSlash(cleaned), "/") {
		if part == ".." {
			return errors.New("path contains parent traversal")
		}
	}
	return nil
}
func metadataSize(r PackRule) int {
	b, _ := json.Marshal(struct {
		Metadata                      RuleMetadata `json:"metadata"`
		Tags                          []string     `json:"tags"`
		Description, Category, Source string
	}{r.Metadata, r.Tags, r.Description, r.Category, r.Source})
	return len(b)
}
