package bundled

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/openaudit/openaudit/internal/safepath"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type sourceRecord struct {
	Group, UpstreamID string
	Pattern           *string
	Empty             bool
	Malformed         string
}
type rawDoc struct {
	Regex    map[string]json.RawMessage `json:"regex"`
	Settings json.RawMessage            `json:"settings"`
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
	if opt.SourceCommit != "" && !regexp.MustCompile(`^[0-9a-fA-F]{40}$`).MatchString(opt.SourceCommit) {
		return Pack{}, Report{}, nil, nil, errors.New("source commit must be a full 40-character SHA")
	}
	if opt.Timestamp.IsZero() {
		opt.Timestamp = reproducibleTime()
	}
	recs, unknown, err := parse(input, opt.Dataset, opt.Limits)
	if err != nil {
		return Pack{}, Report{}, nil, nil, err
	}
	sum := sha256.Sum256(input)
	pack := Pack{SchemaVersion: SchemaVersion, Provider: ProviderNetEase, Dataset: opt.Dataset, SourceRepository: opt.SourceRepository, SourceCommit: strings.ToLower(opt.SourceCommit), SourceFilePath: opt.SourceFilePath, SourceInputSHA256: hex.EncodeToString(sum[:]), LicenseIdentifier: opt.LicenseIdentifier, SourceTimestamp: opt.Timestamp.UTC().Format(time.RFC3339), GeneratorName: GeneratorName, GeneratorVersion: GeneratorVersion}
	seenID := map[string]int{}
	seenRegex := map[string]int{}
	failures := []CompatibilityFailure{}
	sort.SliceStable(recs, func(i, j int) bool {
		if recs[i].Group != recs[j].Group {
			return groupIndex(recs[i].Group) < groupIndex(recs[j].Group)
		}
		return idLess(recs[i].UpstreamID, recs[j].UpstreamID)
	})
	for _, r := range recs {
		pack.Counts.TotalSourceRules++
		if r.Empty {
			pack.Counts.EmptyRecords++
			continue
		}
		if r.Pattern == nil {
			continue
		}
		pack.Counts.ParsedRules++
		pack.Counts.ImportedRecords++
		ident := opt.Dataset + "/" + r.Group + "/" + r.UpstreamID
		if seenID[ident] > 0 {
			pack.Counts.DuplicateIdentities++
		}
		seenID[ident]++
		if seenRegex[*r.Pattern] > 0 {
			pack.Counts.DuplicateRegexContent++
		}
		seenRegex[*r.Pattern]++
		m, _ := Mapping(r.Group)
		id := stableID(opt.Dataset, r.Group, r.UpstreamID, seenID[ident])
		pr := PackRule{ID: id, Provider: ProviderNetEase, Dataset: opt.Dataset, Group: r.Group, UpstreamID: r.UpstreamID, OriginalRegex: *r.Pattern, Type: "regex", Category: m.Category, RiskLevel: "high", Action: m.Action, Score: 90, Source: "bundled:netease", Tags: []string{"bundled", "provider:netease", "dataset:" + opt.Dataset, r.Group}, Description: "NetEase bundled " + r.Group + " regex", Enabled: m.Enabled, Metadata: m.Metadata, PCRE2Status: "not_checked"}
		if len(*r.Pattern) > opt.Limits.PatternBytes {
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
	pack.Counts.PCRE2Status = []NameCount{{"not_checked", len(pack.Rules)}}
	jsonBytes, err := MarshalPack(pack)
	if err != nil {
		return Pack{}, Report{}, nil, nil, err
	}
	gz, err := GzipDeterministic(jsonBytes)
	if err != nil {
		return Pack{}, Report{}, nil, nil, err
	}
	ps := sha256.Sum256(gz)
	rep := Report{SchemaVersion: SchemaVersion, Provider: ProviderNetEase, Dataset: opt.Dataset, UpstreamRepository: opt.SourceRepository, PinnedSourceCommit: strings.ToLower(opt.SourceCommit), SourceFilePath: opt.SourceFilePath, SourceInputBytes: int64(len(input)), SourceInputSHA256: pack.SourceInputSHA256, GeneratedPackPath: opt.OutputPath, GeneratedPackBytes: int64(len(gz)), GeneratedPackSHA256: hex.EncodeToString(ps[:]), TotalSourceRules: pack.Counts.TotalSourceRules, ParsedRules: pack.Counts.ParsedRules, ImportedRecords: pack.Counts.ImportedRecords, EmptyRecords: pack.Counts.EmptyRecords, DuplicateIdentities: pack.Counts.DuplicateIdentities, DuplicateRegexContent: pack.Counts.DuplicateRegexContent, RE2CompatibleRules: pack.Counts.RE2Compatible, RE2IncompatibleRules: pack.Counts.RE2Incompatible, PCRE2StatusCounts: pack.Counts.PCRE2Status, DisabledRules: pack.Counts.DisabledRules, CountsByDataset: pack.Counts.ByDataset, CountsByGroup: pack.Counts.ByGroup, UnknownGroups: unknown, CompatibilityFailures: failures}
	if opt.OutputPath != "" {
		rep.GeneratedOutputFiles = []string{opt.OutputPath}
	}
	return pack, rep, jsonBytes, gz, nil
}

func parse(input []byte, dataset string, lim Limits) ([]sourceRecord, []string, error) {
	dec := json.NewDecoder(bytes.NewReader(input))
	var doc rawDoc
	if err := dec.Decode(&doc); err != nil {
		return nil, nil, fmt.Errorf("invalid JSON: %w", err)
	}
	if doc.Regex == nil {
		return nil, nil, errors.New("missing regex object")
	}
	var out []sourceRecord
	var unknown []string
	for raw, v := range doc.Regex {
		g, ok := CanonicalGroup(raw)
		if !ok {
			unknown = append(unknown, raw)
			continue
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(v, &obj); err != nil {
			return nil, nil, fmt.Errorf("malformed group %s: %w", raw, err)
		}
		for id, val := range obj {
			if len(out) >= lim.RuleCount {
				return nil, nil, errors.New("rule count exceeds limit")
			}
			if bytes.Equal(val, []byte("null")) {
				out = append(out, sourceRecord{Group: g, UpstreamID: id, Empty: true})
				continue
			}
			var s string
			if err := json.Unmarshal(val, &s); err != nil {
				out = append(out, sourceRecord{Group: g, UpstreamID: id, Malformed: err.Error(), Empty: true})
				continue
			}
			if s == "" {
				out = append(out, sourceRecord{Group: g, UpstreamID: id, Empty: true})
				continue
			}
			ss := s
			out = append(out, sourceRecord{Group: g, UpstreamID: id, Pattern: &ss})
		}
	}
	sort.Strings(unknown)
	return out, unknown, nil
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
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return Pack{}, fmt.Errorf("invalid gzip: %w", err)
	}
	defer zr.Close()
	data, err := io.ReadAll(io.LimitReader(zr, lim.UncompressedPackBytes+1))
	if err != nil {
		return Pack{}, fmt.Errorf("read gzip: %w", err)
	}
	if int64(len(data)) > lim.UncompressedPackBytes {
		return Pack{}, errors.New("uncompressed pack exceeds limit")
	}
	var p Pack
	if err := json.Unmarshal(data, &p); err != nil {
		return Pack{}, fmt.Errorf("invalid pack JSON: %w", err)
	}
	if p.SchemaVersion != SchemaVersion {
		return Pack{}, fmt.Errorf("unsupported schema_version %d", p.SchemaVersion)
	}
	if len(p.Rules) > lim.RuleCount {
		return Pack{}, errors.New("rule count exceeds limit")
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
	// #nosec G304 -- local operator-supplied converter input path; source JSON is parsed as untrusted data with explicit limits.
	b, err := os.ReadFile(inputPath)
	if err != nil {
		return Report{}, err
	}
	_, rep, _, gz, err := BuildPack(b, opt)
	if err != nil {
		return rep, err
	}
	if _, err := ReadPackGzip(gz, opt.Limits); err != nil {
		return rep, err
	}
	if !dry {
		if err := WriteAtomic(opt.OutputPath, gz); err != nil {
			return rep, err
		}
	}
	return rep, nil
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
	out := []NameCount{}
	for _, g := range groupOrder {
		out = append(out, NameCount{g, m[g]})
	}
	return out
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
func reproducibleTime() time.Time {
	if v := os.Getenv("SOURCE_DATE_EPOCH"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return time.Unix(n, 0).UTC()
		}
	}
	return time.Unix(0, 0).UTC()
}
