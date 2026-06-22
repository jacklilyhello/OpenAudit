package bundled

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

const sha = "0123456789abcdef0123456789abcdef01234567"

func opt(dataset string) Options {
	return Options{Dataset: dataset, SourceRepository: "https://example.test/repo", SourceCommit: sha, SourceFilePath: "SensitiveWords/G79SensitiveWords.json", Timestamp: time.Unix(1, 0).UTC(), LicenseIdentifier: "NOASSERTION"}
}
func fixture() []byte {
	b, err := os.ReadFile("../../testdata/bundled/g79_synthetic.json")
	if err != nil {
		panic(err)
	}
	return b
}
func TestBuildPackNetEasePhaseA(t *testing.T) {
	p, r, j, gz, err := BuildPack(fixture(), opt("g79"))
	if err != nil {
		t.Fatal(err)
	}
	if len(j) == 0 || len(gz) == 0 || p.Provider != ProviderNetEase {
		t.Fatal("empty output")
	}
	if len(r.UnknownGroups) != 1 || r.UnknownGroups[0].Name != "unknown" || r.UnknownGroups[0].RecordCount != 1 {
		t.Fatalf("unknown groups: %#v", r.UnknownGroups)
	}
	if r.EmptyRecords != 2 || r.MalformedRecords != 1 || len(r.MalformedRecordDetails) != 1 {
		t.Fatalf("empty/malformed=%d/%d", r.EmptyRecords, r.MalformedRecords)
	}
	if r.TotalSourceRules != r.ImportedRecords+r.EmptyRecords+r.MalformedRecords+r.UnknownRecords {
		t.Fatal("totals do not add up")
	}
	if r.DuplicateRegexContent != 1 {
		t.Fatalf("duplicate regex=%d", r.DuplicateRegexContent)
	}
	if r.RE2IncompatibleRules < 3 {
		t.Fatalf("expected incompatibilities: %d", r.RE2IncompatibleRules)
	}
	if p.Rules[0].UpstreamID != "1" {
		t.Fatalf("numeric sort failed: %s", p.Rules[0].UpstreamID)
	}
	for _, x := range p.Rules {
		if x.PCRE2Status != PCRE2NotChecked {
			t.Fatal("pcre2 checked")
		}
		if x.Group == "replace" && x.Metadata.UpstreamBehavior != "replace" {
			t.Fatal("replace metadata")
		}
	}
	if err := ValidatePack(p, DefaultLimits()); err != nil {
		t.Fatal(err)
	}
}
func TestReproducibility(t *testing.T) {
	o := opt("x19")
	_, _, j1, g1, err := BuildPack(fixture(), o)
	if err != nil {
		t.Fatal(err)
	}
	_, _, j2, g2, err := BuildPack(fixture(), o)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(j1, j2) || !bytes.Equal(g1, g2) || sha256.Sum256(g1) != sha256.Sum256(g2) {
		t.Fatal("same timestamp not deterministic")
	}
	t.Setenv("SOURCE_DATE_EPOCH", "42")
	o.Timestamp = time.Time{}
	_, _, j3, g3, err := BuildPack(fixture(), o)
	if err != nil {
		t.Fatal(err)
	}
	_, _, j4, g4, err := BuildPack(fixture(), o)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(j3, j4) || !bytes.Equal(g3, g4) {
		t.Fatal("SOURCE_DATE_EPOCH not deterministic")
	}
	o2 := opt("x19")
	o2.Timestamp = time.Unix(2, 0).UTC()
	_, _, j5, _, err := BuildPack(fixture(), o2)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(j1, j5) {
		t.Fatal("different timestamp should change provenance bytes")
	}
	t.Setenv("SOURCE_DATE_EPOCH", "bad")
	o.Timestamp = time.Time{}
	if _, _, _, _, err := BuildPack(fixture(), o); err == nil {
		t.Fatal("bad source date accepted")
	}
}
func TestStrictJSONAndDuplicateKeys(t *testing.T) {
	valid := append([]byte(`{"regex":{"shield":{"1":"ok"}},"settings":{}}`), ' ', '\n')
	if _, _, _, _, err := BuildPack(valid, opt("g79")); err != nil {
		t.Fatal(err)
	}
	cases := []string{`{"regex":{"shield":{"1":"ok"}}}{}`, `{"regex":{"shield":{"1":"ok"}}} junk`, `{"settings":{}}`, `{"regex":[]}`, `{"regex":{"Shield":{"1":"a"},"shield":{"2":"b"}}}`, `{"regex":{"shield":{"1":"a","1":"b"}}}`, `{"regex":{},"regex":{}}`}
	for _, c := range cases {
		if _, _, _, _, err := BuildPack([]byte(c), opt("g79")); err == nil {
			t.Fatalf("accepted malformed JSON: %s", c)
		}
	}
}
func TestLimitsBoundaryAndValidation(t *testing.T) {
	lim := DefaultLimits()
	lim.InputJSONBytes = int64(len(fixture()))
	if _, _, _, _, err := BuildPack(fixture(), withLim(opt("g79"), lim)); err != nil {
		t.Fatal(err)
	}
	lim.InputJSONBytes = int64(len(fixture()) - 1)
	if _, _, _, _, err := BuildPack(fixture(), withLim(opt("g79"), lim)); err == nil {
		t.Fatal("oversized accepted")
	}
	lim = DefaultLimits()
	lim.RuleCount = 1
	if _, _, _, _, err := BuildPack(fixture(), withLim(opt("g79"), lim)); err == nil {
		t.Fatal("rule count accepted")
	}
	lim = DefaultLimits()
	lim.PatternBytes = 2
	if _, _, _, _, err := BuildPack([]byte(`{"regex":{"shield":{"1":"abc"}},"settings":{}}`), withLim(opt("g79"), lim)); err == nil {
		t.Fatal("pattern limit accepted")
	}
	lim = DefaultLimits()
	lim.MetadataBytes = 1
	if _, _, _, _, err := BuildPack([]byte(`{"regex":{"shield":{"1":"a"}},"settings":{}}`), withLim(opt("g79"), lim)); err == nil {
		t.Fatal("metadata limit accepted")
	}
}
func TestGzipSafety(t *testing.T) {
	_, _, _, gz, err := BuildPack([]byte(`{"regex":{"shield":{"1":"ok"}},"settings":{}}`), opt("g79"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPackGzip(gz, DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPackGzip(gz[:len(gz)/2], DefaultLimits()); err == nil {
		t.Fatal("truncated accepted")
	}
	gz2 := append(append([]byte{}, gz...), gz...)
	if _, err := ReadPackGzip(gz2, DefaultLimits()); err == nil {
		t.Fatal("concatenated accepted")
	}
	trail := append(append([]byte{}, gz...), 'x')
	if _, err := ReadPackGzip(trail, DefaultLimits()); err == nil {
		t.Fatal("trailing bytes accepted")
	}
	bad := append([]byte{}, gz...)
	bad[len(bad)-8] ^= 0xff
	if _, err := ReadPackGzip(bad, DefaultLimits()); err == nil {
		t.Fatal("crc corruption accepted")
	}
	lim := DefaultLimits()
	lim.UncompressedPackBytes = 10
	if _, err := ReadPackGzip(gz, lim); err == nil {
		t.Fatal("oversized decompressed accepted")
	}
}
func TestReportWriteDryRunAndValidation(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.json")
	os.WriteFile(in, []byte(`{"regex":{"shield":{"1":"ok"}},"settings":{}}`), 0600)
	pack := filepath.Join(dir, "pack.gz")
	report := filepath.Join(dir, "report.json")
	rep, err := ConvertFile(in, withPaths(opt("g79"), pack, report), true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(pack); !os.IsNotExist(err) {
		t.Fatal("dry-run wrote pack")
	}
	if _, err := os.Stat(report); !os.IsNotExist(err) {
		t.Fatal("dry-run wrote report")
	}
	rep, err = ConvertFile(in, withPaths(opt("g79"), pack, report), false)
	if err != nil {
		t.Fatal(err)
	}
	gz, _ := os.ReadFile(pack)
	rb, _ := os.ReadFile(report)
	var r Report
	json.Unmarshal(rb, &r)
	p, err := ReadPackGzip(gz, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateReportForPack(r, p, gz); err != nil {
		t.Fatal(err)
	}
	if len(rep.GeneratedOutputFiles) != 2 {
		t.Fatal("missing output files")
	}
	r.GeneratedPackSHA256 = "bad"
	if err := ValidateReportForPack(r, p, gz); err == nil {
		t.Fatal("report mismatch accepted")
	}
}
func TestOversizedLocalFilePreservesOutputs(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "big.json")
	os.WriteFile(in, []byte(`{"regex":{}}xxx`), 0600)
	pack := filepath.Join(dir, "pack.gz")
	report := filepath.Join(dir, "report.json")
	os.WriteFile(pack, []byte("oldpack"), 0600)
	os.WriteFile(report, []byte("oldreport"), 0600)
	lim := DefaultLimits()
	lim.InputJSONBytes = 5
	_, err := ConvertFile(in, withPaths(withLim(opt("g79"), lim), pack, report), false)
	if err == nil {
		t.Fatal("expected error")
	}
	if b, _ := os.ReadFile(pack); string(b) != "oldpack" {
		t.Fatal("pack replaced")
	}
	if b, _ := os.ReadFile(report); string(b) != "oldreport" {
		t.Fatal("report replaced")
	}
}
func TestWriteAtomicPreservesPreviousOnBuildFailure(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "pack.json.gz")
	old := []byte("previous")
	os.WriteFile(out, old, 0600)
	_, err := ConvertFile(filepath.Join(dir, "missing.json"), withPaths(opt("g79"), out, filepath.Join(dir, "r.json")), false)
	if err == nil {
		t.Fatal("expected error")
	}
	got, _ := os.ReadFile(out)
	if string(got) != string(old) {
		t.Fatal("output not preserved")
	}
}
func TestNoLargeFixtures(t *testing.T) {
	filepath.WalkDir("../../testdata", func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if info, _ := d.Info(); info.Size() > 32*1024 || strings.Contains(path, "SensitiveWords.json") {
				t.Fatalf("large/full fixture: %s", path)
			}
		}
		return nil
	})
}
func withLim(o Options, l Limits) Options      { o.Limits = l; return o }
func withPaths(o Options, p, r string) Options { o.OutputPath = p; o.ReportPath = r; return o }

func TestUTCTimestampPolicy(t *testing.T) {
	p, _, _, _, err := BuildPack([]byte(`{"regex":{"shield":{"1":"ok"}},"settings":{}}`), opt("g79"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(p.SourceTimestamp, "Z") {
		t.Fatalf("generated timestamp is not canonical UTC: %s", p.SourceTimestamp)
	}
	p.SourceTimestamp = "2026-06-22T00:00:00Z"
	if err := ValidatePack(p, DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	p.SourceTimestamp = "2026-06-22T08:00:00+08:00"
	if err := ValidatePack(p, DefaultLimits()); err == nil {
		t.Fatal("non-UTC offset accepted")
	}
	p.SourceTimestamp = "2026-06-22T00:00:00+00:00"
	if err := ValidatePack(p, DefaultLimits()); err == nil {
		t.Fatal("+00:00 accepted despite non-canonical policy")
	}
	p.SourceTimestamp = "not-time"
	if err := ValidatePack(p, DefaultLimits()); err == nil {
		t.Fatal("malformed timestamp accepted")
	}
}

func TestDuplicateIdentitiesInvariant(t *testing.T) {
	p, _, _, _, err := BuildPack([]byte(`{"regex":{"shield":{"1":"ok"}},"settings":{}}`), opt("g79"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Counts.DuplicateIdentities != 0 {
		t.Fatal("valid pack has duplicate identities")
	}
	if err := ValidatePack(p, DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	p.Counts.DuplicateIdentities = 1
	if err := ValidatePack(p, DefaultLimits()); err == nil {
		t.Fatal("duplicate identities accepted")
	}
}

func TestUnknownGroupPolicies(t *testing.T) {
	valid := []byte(`{"regex":{"unknown":{"1":"x","2":7},"empty_unknown":{}},"settings":{}}`)
	_, r, _, _, err := BuildPack(valid, opt("g79"))
	if err != nil {
		t.Fatal(err)
	}
	if r.UnknownRecords != 2 || len(r.UnknownGroups) != 2 {
		t.Fatalf("unknown accounting: %#v", r.UnknownGroups)
	}
	bad := []string{`{"regex":{"unknown":1}}`, `{"regex":{"unknown":"x"}}`, `{"regex":{"unknown":true}}`, `{"regex":{"unknown":null}}`, `{"regex":{"unknown":[]}}`, `{"regex":{"unknown":{"1":"x","1":"y"}}}`, `{"regex":{"unknown":{"1": }}}`}
	for _, b := range bad {
		if _, _, _, _, err := BuildPack([]byte(b), opt("g79")); err == nil {
			t.Fatalf("bad unknown accepted: %s", b)
		}
	}
}

func TestMalformedCorpusNeverPanics(t *testing.T) {
	inputs := [][]byte{[]byte(`{`), []byte(`{"regex":{`), []byte(`{"regex":{"shield":{`), []byte(`{"regex":{"shield":{"1"`), []byte(`{"regex":{"shield":{"1":`), []byte(`{"regex":{"shield":{"1": [}`), []byte(`[]`), []byte(`{"regex":{"shield":[]}}`), []byte{0xff, 0xfe, '{'}}
	for _, in := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic for %q: %v", string(in), r)
				}
			}()
			if _, _, _, _, err := BuildPack(in, opt("g79")); err == nil {
				t.Fatalf("malformed accepted: %q", string(in))
			}
		}()
	}
}

func TestPackMappingMutations(t *testing.T) {
	p, _, _, _, err := BuildPack([]byte(`{"regex":{"shield":{"1":"ok"}},"settings":{}}`), opt("g79"))
	if err != nil {
		t.Fatal(err)
	}
	mutations := []func(*Pack){
		func(p *Pack) { p.Rules[0].Source = "x" }, func(p *Pack) { p.Rules[0].RiskLevel = "low" }, func(p *Pack) { p.Rules[0].Score = 1 }, func(p *Pack) { p.Rules[0].Tags = []string{"bundled"} }, func(p *Pack) { p.Rules[0].Metadata.UpstreamBehavior = "x" }, func(p *Pack) { p.Rules[0].Description = "" }, func(p *Pack) { p.Rules[0].OriginalRegex = "" }, func(p *Pack) { p.SourceTimestamp = "not-time" },
	}
	for i, m := range mutations {
		q := p
		q.Rules = append([]PackRule{}, p.Rules...)
		m(&q)
		if err := ValidatePack(q, DefaultLimits()); err == nil {
			t.Fatalf("mutation %d accepted", i)
		}
	}
}

func TestReportMutations(t *testing.T) {
	p, r, _, gz, err := BuildPack(fixture(), opt("g79"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateReportForPack(r, p, gz); err != nil {
		t.Fatal(err)
	}
	mut := []func(*Report){func(r *Report) { r.SchemaVersion = 99 }, func(r *Report) { r.SourceInputSHA256 = "bad" }, func(r *Report) { r.UnknownRecords++ }, func(r *Report) { r.DuplicateIdentities = 1 }, func(r *Report) { r.PCRE2StatusCounts = nil }, func(r *Report) { r.CountsByGroup = nil }, func(r *Report) { r.CompatibilityFailures = append(r.CompatibilityFailures, r.CompatibilityFailures[0]) }, func(r *Report) { r.MalformedRecordDetails = nil }, func(r *Report) { r.UnknownGroups = append(r.UnknownGroups, r.UnknownGroups[0]) }}
	for i, m := range mut {
		x := r
		x.PCRE2StatusCounts = append([]NameCount{}, r.PCRE2StatusCounts...)
		x.CountsByGroup = append([]NameCount{}, r.CountsByGroup...)
		x.CompatibilityFailures = append([]CompatibilityFailure{}, r.CompatibilityFailures...)
		x.MalformedRecordDetails = append([]MalformedRecord{}, r.MalformedRecordDetails...)
		x.UnknownGroups = append([]UnknownGroup{}, r.UnknownGroups...)
		m(&x)
		if err := ValidateReportForPack(x, p, gz); err == nil {
			t.Fatalf("report mutation %d accepted", i)
		}
	}
	rb, _ := MarshalReport(r)
	if _, err := DecodeReportJSON(append(rb, []byte(` {}`)...), DefaultLimits()); err == nil {
		t.Fatal("trailing report accepted")
	}
}

func TestWritePairAtomicScenarios(t *testing.T) {
	dir := t.TempDir()
	pack := filepath.Join(dir, "pack.gz")
	report := filepath.Join(dir, "report.json")
	if err := WritePairAtomic(pack, []byte("p1"), report, []byte("r1")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(pack); string(b) != "p1" {
		t.Fatal("pack missing")
	}
	if err := WritePairAtomic(pack, []byte("p2"), report, []byte("r2")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(report); string(b) != "r2" {
		t.Fatal("report not replaced")
	}
	if err := WritePairAtomic(pack, []byte("x"), pack, []byte("y")); err == nil {
		t.Fatal("identical paths accepted")
	}
	if err := WritePairAtomic(pack, []byte("x"), filepath.Join(t.TempDir(), "r"), []byte("y")); err == nil {
		t.Fatal("different parents accepted")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") || strings.Contains(e.Name(), ".bak") {
			t.Fatalf("left temp/backup %s", e.Name())
		}
	}
}

func TestWritePairAtomicRollbackFailures(t *testing.T) {
	dir := t.TempDir()
	pack := filepath.Join(dir, "pack.gz")
	report := filepath.Join(dir, "report.json")
	reset := func() { os.WriteFile(pack, []byte("oldp"), 0600); os.WriteFile(report, []byte("oldr"), 0600) }
	oldOps := pairOps
	defer func() { pairOps = oldOps }()
	assertOld := func(msg string) {
		if b, _ := os.ReadFile(pack); string(b) != "oldp" {
			t.Fatalf("pack changed after %s: %q", msg, string(b))
		}
		if b, _ := os.ReadFile(report); string(b) != "oldr" {
			t.Fatalf("report changed after %s: %q", msg, string(b))
		}
	}

	reset()
	pairOps = oldOps
	pairOps.createTemp = func(dir, pattern string) (*os.File, error) { return nil, os.ErrPermission }
	if err := WritePairAtomic(pack, []byte("newp"), report, []byte("newr")); err == nil {
		t.Fatal("pack staging failure accepted")
	}
	assertOld("pack staging failure")

	reset()
	pairOps = oldOps
	created := 0
	pairOps.createTemp = func(dir, pattern string) (*os.File, error) {
		created++
		if created == 2 {
			return nil, os.ErrPermission
		}
		return os.CreateTemp(dir, pattern)
	}
	if err := WritePairAtomic(pack, []byte("newp"), report, []byte("newr")); err == nil {
		t.Fatal("report staging failure accepted")
	}
	assertOld("report staging failure")

	reset()
	pairOps = oldOps
	pairOps.rename = func(old, new string) error {
		if old == pack && strings.HasSuffix(new, ".bak") {
			return os.ErrPermission
		}
		return os.Rename(old, new)
	}
	if err := WritePairAtomic(pack, []byte("newp"), report, []byte("newr")); err == nil {
		t.Fatal("pack backup failure accepted")
	}
	assertOld("pack backup failure")

	reset()
	pairOps = oldOps
	pairOps.rename = func(old, new string) error {
		if old == report && strings.HasSuffix(new, ".bak") {
			return os.ErrPermission
		}
		return os.Rename(old, new)
	}
	if err := WritePairAtomic(pack, []byte("newp"), report, []byte("newr")); err == nil {
		t.Fatal("report backup failure accepted")
	}
	assertOld("report backup failure")

	reset()
	pairOps = oldOps
	pairOps.rename = func(old, new string) error {
		if strings.HasSuffix(new, "pack.gz") && strings.HasSuffix(old, ".tmp") {
			return os.ErrPermission
		}
		return os.Rename(old, new)
	}
	if err := WritePairAtomic(pack, []byte("newp"), report, []byte("newr")); err == nil {
		t.Fatal("pack install failure accepted")
	}
	assertOld("pack install failure")

	reset()
	pairOps = oldOps
	pairOps.rename = func(old, new string) error {
		if strings.HasSuffix(new, "report.json") && strings.HasSuffix(old, ".tmp") {
			return os.ErrPermission
		}
		return os.Rename(old, new)
	}
	if err := WritePairAtomic(pack, []byte("newp"), report, []byte("newr")); err == nil {
		t.Fatal("report install failure accepted")
	}
	assertOld("report install failure")

	reset()
	pairOps = oldOps
	pairOps.rename = func(old, new string) error {
		if strings.HasSuffix(new, "pack.gz") && strings.Contains(old, ".bak") {
			return os.ErrPermission
		}
		if strings.HasSuffix(new, "report.json") && strings.HasSuffix(old, ".tmp") {
			return os.ErrPermission
		}
		return os.Rename(old, new)
	}
	if err := WritePairAtomic(pack, []byte("newp"), report, []byte("newr")); err == nil || !strings.Contains(err.Error(), "restore pack") {
		t.Fatalf("pack restore failure not reported: %v", err)
	}

	reset()
	pairOps = oldOps
	pairOps.rename = func(old, new string) error {
		if strings.HasSuffix(new, "report.json") && strings.Contains(old, ".bak") {
			return os.ErrPermission
		}
		if strings.HasSuffix(new, "report.json") && strings.HasSuffix(old, ".tmp") {
			return os.ErrPermission
		}
		return os.Rename(old, new)
	}
	if err := WritePairAtomic(pack, []byte("newp"), report, []byte("newr")); err == nil || !strings.Contains(err.Error(), "restore report") {
		t.Fatalf("report restore failure not reported: %v", err)
	}

	absentPack := filepath.Join(dir, "absent-pack.gz")
	absentReport := filepath.Join(dir, "absent-report.json")
	pairOps = oldOps
	pairOps.rename = func(old, new string) error {
		if strings.HasSuffix(new, "absent-report.json") && strings.HasSuffix(old, ".tmp") {
			return os.ErrPermission
		}
		return os.Rename(old, new)
	}
	if err := WritePairAtomic(absentPack, []byte("newp"), absentReport, []byte("newr")); err == nil {
		t.Fatal("absent target rollback failure accepted")
	}
	if _, err := os.Stat(absentPack); !os.IsNotExist(err) {
		t.Fatal("invented absent pack")
	}
	if _, err := os.Stat(absentReport); !os.IsNotExist(err) {
		t.Fatal("invented absent report")
	}
}

func TestReadLimitedLocalFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	os.WriteFile(p, []byte("abc"), 0600)
	if _, err := ReadLimitedLocalFile(p, 3); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadLimitedLocalFile(p, 2); err == nil {
		t.Fatal("oversized accepted")
	}
}

func TestWritePairAtomicRetainsFailedRestoreBackups(t *testing.T) {
	dir := t.TempDir()
	pack := filepath.Join(dir, "pack.gz")
	report := filepath.Join(dir, "report.json")
	oldOps := pairOps
	defer func() { pairOps = oldOps }()
	setup := func() {
		pairOps = oldOps
		os.WriteFile(pack, []byte("oldp"), 0600)
		os.WriteFile(report, []byte("oldr"), 0600)
	}
	backupFiles := func() []string {
		entries, _ := os.ReadDir(dir)
		out := []string{}
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".bak") {
				out = append(out, filepath.Join(dir, e.Name()))
			}
		}
		sort.Strings(out)
		return out
	}

	setup()
	pairOps.rename = func(old, new string) error {
		if strings.HasSuffix(new, "pack.gz") && strings.HasSuffix(old, ".bak") {
			return os.ErrPermission
		}
		if strings.HasSuffix(new, "report.json") && strings.HasSuffix(old, ".tmp") {
			return os.ErrPermission
		}
		return os.Rename(old, new)
	}
	err := WritePairAtomic(pack, []byte("newp"), report, []byte("newr"))
	if err == nil || !strings.Contains(err.Error(), "retained pack backup at") {
		t.Fatalf("pack restore retention not reported: %v", err)
	}
	baks := backupFiles()
	if len(baks) != 1 {
		t.Fatalf("expected one retained pack backup, got %v", baks)
	}
	if b, _ := os.ReadFile(baks[0]); string(b) != "oldp" {
		t.Fatalf("pack backup content=%q", string(b))
	}
	if b, _ := os.ReadFile(report); string(b) != "oldr" {
		t.Fatalf("report not restored: %q", string(b))
	}

	setup()
	pairOps.rename = func(old, new string) error {
		if strings.HasSuffix(new, "report.json") && strings.HasSuffix(old, ".bak") {
			return os.ErrPermission
		}
		if strings.HasSuffix(new, "report.json") && strings.HasSuffix(old, ".tmp") {
			return os.ErrPermission
		}
		return os.Rename(old, new)
	}
	err = WritePairAtomic(pack, []byte("newp"), report, []byte("newr"))
	if err == nil || !strings.Contains(err.Error(), "retained report backup at") {
		t.Fatalf("report restore retention not reported: %v", err)
	}
	baks = backupFiles()
	foundReport := false
	for _, bak := range baks {
		if b, _ := os.ReadFile(bak); string(b) == "oldr" {
			foundReport = true
		}
	}
	if !foundReport {
		t.Fatalf("report backup not retained with old data: %v", baks)
	}
	if b, _ := os.ReadFile(pack); string(b) != "oldp" {
		t.Fatalf("pack not restored: %q", string(b))
	}
}

func TestWritePairAtomicRetainsBothFailedRestoreBackups(t *testing.T) {
	dir := t.TempDir()
	pack := filepath.Join(dir, "pack.gz")
	report := filepath.Join(dir, "report.json")
	os.WriteFile(pack, []byte("oldp"), 0600)
	os.WriteFile(report, []byte("oldr"), 0600)
	oldOps := pairOps
	defer func() { pairOps = oldOps }()
	pairOps.rename = func(old, new string) error {
		if strings.HasSuffix(old, ".bak") {
			return os.ErrPermission
		}
		if strings.HasSuffix(new, "report.json") && strings.HasSuffix(old, ".tmp") {
			return os.ErrPermission
		}
		return os.Rename(old, new)
	}
	err := WritePairAtomic(pack, []byte("newp"), report, []byte("newr"))
	if err == nil || !strings.Contains(err.Error(), "retained pack backup at") || !strings.Contains(err.Error(), "retained report backup at") {
		t.Fatalf("retained backups not reported: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	gotP, gotR := false, false
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".bak") {
			b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
			gotP = gotP || string(b) == "oldp"
			gotR = gotR || string(b) == "oldr"
		}
	}
	if !gotP || !gotR {
		t.Fatalf("missing retained backups pack=%v report=%v", gotP, gotR)
	}
}

func TestWritePairAtomicBackupCleanupFailureKeepsNewPair(t *testing.T) {
	dir := t.TempDir()
	pack := filepath.Join(dir, "pack.gz")
	report := filepath.Join(dir, "report.json")
	os.WriteFile(pack, []byte("oldp"), 0600)
	os.WriteFile(report, []byte("oldr"), 0600)
	oldOps := pairOps
	defer func() { pairOps = oldOps }()
	pairOps.remove = func(path string) error {
		if strings.HasSuffix(path, ".bak") {
			return os.ErrPermission
		}
		return os.Remove(path)
	}
	err := WritePairAtomic(pack, []byte("newp"), report, []byte("newr"))
	if err == nil || !strings.Contains(err.Error(), "commit succeeded") || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("cleanup failure not reported: %v", err)
	}
	if b, _ := os.ReadFile(pack); string(b) != "newp" {
		t.Fatalf("new pack missing: %q", string(b))
	}
	if b, _ := os.ReadFile(report); string(b) != "newr" {
		t.Fatalf("new report missing: %q", string(b))
	}
	entries, _ := os.ReadDir(dir)
	backups := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".bak") {
			backups++
		}
	}
	if backups == 0 {
		t.Fatal("failed-to-delete backup was not retained")
	}
}
