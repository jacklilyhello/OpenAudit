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
	for _, u := range doc.unknown {
		pack.Counts.UnknownRecords += u.RecordCount
		pack.Counts.TotalSourceRules += u.RecordCount
	}
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
	rep := Report{SchemaVersion: SchemaVersion, Provider: ProviderNetEase, Dataset: opt.Dataset, UpstreamRepository: opt.SourceRepository, PinnedSourceCommit: strings.ToLower(opt.SourceCommit), SourceFilePath: opt.SourceFilePath, SourceInputBytes: int64(len(input)), SourceInputSHA256: pack.SourceInputSHA256, GeneratedPackPath: opt.OutputPath, GeneratedReportPath: opt.ReportPath, GeneratedPackBytes: int64(len(gz)), GeneratedPackSHA256: hex.EncodeToString(ps[:]), TotalSourceRules: pack.Counts.TotalSourceRules, ParsedRules: pack.Counts.ParsedRules, ImportedRecords: pack.Counts.ImportedRecords, EmptyRecords: pack.Counts.EmptyRecords, MalformedRecords: pack.Counts.MalformedRecords, UnknownRecords: pack.Counts.UnknownRecords, MalformedRecordDetails: malformed, DuplicateIdentities: pack.Counts.DuplicateIdentities, DuplicateRegexContent: pack.Counts.DuplicateRegexContent, RE2CompatibleRules: pack.Counts.RE2Compatible, RE2IncompatibleRules: pack.Counts.RE2Incompatible, PCRE2StatusCounts: pack.Counts.PCRE2Status, DisabledRules: pack.Counts.DisabledRules, CountsByDataset: pack.Counts.ByDataset, CountsByGroup: pack.Counts.ByGroup, UnknownGroups: doc.unknown, CompatibilityFailures: failures}
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
		key, okKey := kt.(string)
		if !okKey {
			return parsedDoc{}, errors.New("top-level key must be a string")
		}
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
		kt, err := dec.Token()
		if err != nil {
			return fmt.Errorf("read regex group key: %w", err)
		}
		raw, okKey := kt.(string)
		if !okKey {
			return errors.New("regex group key must be a string")
		}
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
		kt, err := dec.Token()
		if err != nil {
			return fmt.Errorf("read upstream ID for %s: %w", group, err)
		}
		id, okKey := kt.(string)
		if !okKey {
			return fmt.Errorf("regex.%s upstream ID must be a string", group)
		}
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
		return 0, fmt.Errorf("read unknown group object: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return 0, errors.New("unknown regex group must be an object")
	}
	seen := map[string]bool{}
	n := 0
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return n, fmt.Errorf("read unknown upstream ID: %w", err)
		}
		id, ok := kt.(string)
		if !ok {
			return n, errors.New("unknown upstream ID must be a string")
		}
		if id == "" {
			return n, errors.New("unknown upstream ID must be non-empty")
		}
		if seen[id] {
			return n, fmt.Errorf("duplicate upstream ID in unknown group %q", id)
		}
		seen[id] = true
		n++
		var discard json.RawMessage
		if err := dec.Decode(&discard); err != nil {
			return n, fmt.Errorf("decode unknown group value: %w", err)
		}
	}
	end, err := dec.Token()
	if err != nil {
		return n, fmt.Errorf("close unknown group object: %w", err)
	}
	if d, ok := end.(json.Delim); !ok || d != '}' {
		return n, errors.New("unknown group object not closed")
	}
	return n, nil
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
	if ts, err := time.Parse(time.RFC3339, p.SourceTimestamp); err != nil || !ts.Equal(ts.UTC()) {
		return errors.New("deterministic source timestamp must be valid UTC RFC3339")
	}
	if p.Counts.DuplicateIdentities != 0 {
		return errors.New("duplicate identities must be zero in Phase A packs")
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
		if r.OriginalRegex == "" {
			return errors.New("original regex must be non-empty")
		}
		if r.Source != "bundled:netease" || r.RiskLevel != "high" || r.Score != 90 {
			return errors.New("rule source/risk/score mismatch")
		}
		if !validTags(r.Tags, p.Dataset, r.Group) {
			return errors.New("rule tags mismatch")
		}
		if r.Description == "" || r.Metadata != m.Metadata {
			return errors.New("rule metadata mismatch")
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
	counts.UnknownRecords = p.Counts.UnknownRecords
	counts.ByGroup = groupNameCounts(group)
	counts.PCRE2Status = statusNameCounts(status)
	if counts.TotalSourceRules != counts.ImportedRecords+counts.EmptyRecords+counts.MalformedRecords+counts.UnknownRecords {
		return errors.New("source record counts do not add up")
	}
	if p.Counts.ParsedRules != counts.ParsedRules || p.Counts.ImportedRecords != counts.ImportedRecords || p.Counts.UnknownRecords != counts.UnknownRecords || p.Counts.DuplicateRegexContent != counts.DuplicateRegexContent || p.Counts.RE2Compatible != counts.RE2Compatible || p.Counts.RE2Incompatible != counts.RE2Incompatible || p.Counts.DisabledRules != counts.DisabledRules {
		return errors.New("pack counts do not match rules")
	}
	if !nameCountsEqual(p.Counts.ByDataset, counts.ByDataset) || !nameCountsEqual(p.Counts.ByGroup, counts.ByGroup) || !nameCountsEqual(p.Counts.PCRE2Status, counts.PCRE2Status) {
		return errors.New("pack aggregate counts do not match rules")
	}
	return nil
}

func ValidateReportForPack(rep Report, pack Pack, packBytes []byte) error {
	if rep.SchemaVersion != SchemaVersion {
		return errors.New("report schema version mismatch")
	}
	sum := sha256.Sum256(packBytes)
	if rep.GeneratedPackSHA256 != hex.EncodeToString(sum[:]) {
		return errors.New("report pack sha256 mismatch")
	}
	if rep.GeneratedPackBytes != int64(len(packBytes)) {
		return errors.New("report pack size mismatch")
	}
	if rep.Provider != pack.Provider || rep.Dataset != pack.Dataset || rep.UpstreamRepository != pack.SourceRepository || rep.PinnedSourceCommit != pack.SourceCommit || rep.SourceFilePath != pack.SourceFilePath || rep.SourceInputSHA256 != pack.SourceInputSHA256 {
		return errors.New("report provenance mismatch")
	}
	if rep.TotalSourceRules != pack.Counts.TotalSourceRules || rep.ParsedRules != pack.Counts.ParsedRules || rep.ImportedRecords != pack.Counts.ImportedRecords || rep.EmptyRecords != pack.Counts.EmptyRecords || rep.MalformedRecords != pack.Counts.MalformedRecords || rep.UnknownRecords != pack.Counts.UnknownRecords || rep.DuplicateIdentities != pack.Counts.DuplicateIdentities || rep.DuplicateRegexContent != pack.Counts.DuplicateRegexContent || rep.RE2CompatibleRules != pack.Counts.RE2Compatible || rep.RE2IncompatibleRules != pack.Counts.RE2Incompatible || rep.DisabledRules != pack.Counts.DisabledRules {
		return errors.New("report counts mismatch")
	}
	if !nameCountsEqual(rep.PCRE2StatusCounts, pack.Counts.PCRE2Status) || !nameCountsEqual(rep.CountsByDataset, pack.Counts.ByDataset) || !nameCountsEqual(rep.CountsByGroup, pack.Counts.ByGroup) {
		return errors.New("report aggregate counts mismatch")
	}
	unknownSum := 0
	seenUnknown := map[string]bool{}
	for _, u := range rep.UnknownGroups {
		if u.Name == "" || seenUnknown[u.Name] || u.RecordCount < 0 {
			return errors.New("invalid unknown group details")
		}
		seenUnknown[u.Name] = true
		unknownSum += u.RecordCount
	}
	if unknownSum != rep.UnknownRecords {
		return errors.New("unknown record count mismatch")
	}
	if len(rep.MalformedRecordDetails) != rep.MalformedRecords {
		return errors.New("malformed detail count mismatch")
	}
	for _, m := range rep.MalformedRecordDetails {
		if m.Dataset != pack.Dataset || m.UpstreamID == "" || m.Reason == "" || m.ValueType == "" {
			return errors.New("invalid malformed detail")
		}
		if _, ok := Mapping(m.Group); !ok {
			return errors.New("invalid malformed group")
		}
	}
	failures := map[string]CompatibilityFailure{}
	for _, f := range rep.CompatibilityFailures {
		key := f.GeneratedRuleID
		if key == "" || failures[key].GeneratedRuleID != "" {
			return errors.New("duplicate compatibility failure")
		}
		failures[key] = f
	}
	bad := 0
	for _, r := range pack.Rules {
		f, has := failures[r.ID]
		if r.RE2Compatible {
			if has {
				return errors.New("compatible rule has failure")
			}
			continue
		}
		bad++
		if !has {
			return errors.New("missing compatibility failure")
		}
		ps := sha256.Sum256([]byte(r.OriginalRegex))
		if f.Dataset != r.Dataset || f.Group != r.Group || f.UpstreamID != r.UpstreamID || f.PatternSHA256 != hex.EncodeToString(ps[:]) || f.CompilerError != r.RE2Error || f.FeatureHint != r.RE2FeatureHint {
			return errors.New("compatibility failure mismatch")
		}
	}
	if bad != len(rep.CompatibilityFailures) {
		return errors.New("compatibility failure count mismatch")
	}
	for _, pth := range rep.GeneratedOutputFiles {
		if strings.TrimSpace(pth) == "" {
			return errors.New("empty generated output path")
		}
	}
	return nil
}

func DecodeReportJSON(b []byte, lim Limits) (Report, error) {
	if lim == (Limits{}) {
		lim = DefaultLimits()
	}
	if int64(len(b)) > lim.ReportBytes {
		return Report{}, errors.New("report exceeds limit")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	var r Report
	if err := dec.Decode(&r); err != nil {
		return Report{}, fmt.Errorf("invalid report JSON: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return Report{}, errors.New("trailing report JSON value rejected")
		}
		return Report{}, fmt.Errorf("trailing report data rejected: %w", err)
	}
	if r.SchemaVersion != SchemaVersion {
		return Report{}, errors.New("unsupported report schema_version")
	}
	return r, nil
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
		if err := WritePairAtomic(opt.OutputPath, gz, opt.ReportPath, rb); err != nil {
			return rep, err
		}
	}
	return rep, nil
}
func ReadLimitedLocalFile(path string, limit int64) ([]byte, error) {
	// #nosec G304 -- local operator-supplied local path with explicit bounded read.
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && st.Size() > limit {
		return nil, errors.New("file exceeds limit")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("file exceeds limit")
	}
	return data, nil
}
func readLimitedFile(path string, lim Limits) ([]byte, error) {
	if lim == (Limits{}) {
		lim = DefaultLimits()
	}
	b, err := ReadLimitedLocalFile(path, lim.InputJSONBytes)
	if err != nil && strings.Contains(err.Error(), "file exceeds limit") {
		return nil, errors.New("input JSON exceeds limit")
	}
	return b, err
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
func validTags(tags []string, dataset, group string) bool {
	want := []string{"bundled", "provider:netease", "dataset:" + dataset, group}
	if len(tags) != len(want) {
		return false
	}
	seen := map[string]bool{}
	for i, tag := range tags {
		if tag != want[i] || seen[tag] {
			return false
		}
		seen[tag] = true
	}
	return true
}
func metadataSize(r PackRule) int {
	b, _ := json.Marshal(struct {
		Metadata                      RuleMetadata `json:"metadata"`
		Tags                          []string     `json:"tags"`
		Description, Category, Source string
	}{r.Metadata, r.Tags, r.Description, r.Category, r.Source})
	return len(b)
}

var pairOps = filePairOps{}

type filePairOps struct {
	writeFile func(string, []byte, os.FileMode) error
	rename    func(string, string) error
	remove    func(string) error
	readFile  func(string) ([]byte, error)
}

func (o filePairOps) wf(path string, data []byte, perm os.FileMode) error {
	if o.writeFile != nil {
		return o.writeFile(path, data, perm)
	}
	return os.WriteFile(path, data, perm)
}
func (o filePairOps) rn(old, new string) error {
	if o.rename != nil {
		return o.rename(old, new)
	}
	return os.Rename(old, new)
}
func (o filePairOps) rm(path string) error {
	if o.remove != nil {
		return o.remove(path)
	}
	return os.Remove(path)
}
func (o filePairOps) rf(path string) ([]byte, error) {
	if o.readFile != nil {
		return o.readFile(path)
	}
	// #nosec G304 -- internal rollback helper reads previously resolved operator-supplied staged paths.
	return os.ReadFile(path)
}

func WritePairAtomic(packPath string, packData []byte, reportPath string, reportData []byte) error {
	if packPath == reportPath {
		return errors.New("pack and report paths must differ")
	}
	_, packTarget, err := safepath.NewFileTarget(packPath)
	if err != nil {
		return err
	}
	_, reportTarget, err := safepath.NewFileTarget(reportPath)
	if err != nil {
		return err
	}
	if packTarget.Dir() != reportTarget.Dir() {
		return errors.New("pack and report must share the same parent directory for rollback-safe replacement")
	}
	parent := packTarget.Dir()
	if err := os.MkdirAll(parent, 0o750); err != nil {
		return err
	}
	base := ".openaudit-pair-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	packTmp := filepath.Join(parent, base+".pack.tmp")
	reportTmp := filepath.Join(parent, base+".report.tmp")
	packBak := filepath.Join(parent, base+".pack.bak")
	reportBak := filepath.Join(parent, base+".report.bak")
	cleanup := []string{packTmp, reportTmp, packBak, reportBak}
	defer func() {
		for _, p := range cleanup {
			_ = pairOps.rm(p)
		}
	}()
	if err := pairOps.wf(packTmp, packData, safepath.RuntimeFilePerm); err != nil {
		return fmt.Errorf("stage pack: %w", err)
	}
	if err := pairOps.wf(reportTmp, reportData, safepath.RuntimeFilePerm); err != nil {
		return fmt.Errorf("stage report: %w", err)
	}
	if b, err := pairOps.rf(packTmp); err != nil || !bytes.Equal(b, packData) {
		if err != nil {
			return fmt.Errorf("validate staged pack: %w", err)
		}
		return errors.New("validate staged pack: content mismatch")
	}
	if b, err := pairOps.rf(reportTmp); err != nil || !bytes.Equal(b, reportData) {
		if err != nil {
			return fmt.Errorf("validate staged report: %w", err)
		}
		return errors.New("validate staged report: content mismatch")
	}
	packExisted := false
	reportExisted := false
	if _, err := os.Stat(packTarget.String()); err == nil {
		packExisted = true
		if err := pairOps.rn(packTarget.String(), packBak); err != nil {
			return fmt.Errorf("backup pack: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	rollback := func(cause error) error {
		rbErrs := []string{}
		_ = pairOps.rm(packTarget.String())
		_ = pairOps.rm(reportTarget.String())
		if packExisted {
			if err := pairOps.rn(packBak, packTarget.String()); err != nil {
				rbErrs = append(rbErrs, "pack: "+err.Error())
			}
		}
		if reportExisted {
			if err := pairOps.rn(reportBak, reportTarget.String()); err != nil {
				rbErrs = append(rbErrs, "report: "+err.Error())
			}
		}
		if len(rbErrs) > 0 {
			return fmt.Errorf("%w; rollback failed: %s", cause, strings.Join(rbErrs, "; "))
		}
		return cause
	}
	if _, err := os.Stat(reportTarget.String()); err == nil {
		reportExisted = true
		if err := pairOps.rn(reportTarget.String(), reportBak); err != nil {
			return rollback(fmt.Errorf("backup report: %w", err))
		}
	} else if !os.IsNotExist(err) {
		return rollback(err)
	}
	if err := pairOps.rn(packTmp, packTarget.String()); err != nil {
		return rollback(fmt.Errorf("replace pack: %w", err))
	}
	if err := pairOps.rn(reportTmp, reportTarget.String()); err != nil {
		return rollback(fmt.Errorf("replace report: %w", err))
	}
	return nil
}
