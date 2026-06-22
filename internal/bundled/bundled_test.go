package bundled

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
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
	if r.TotalSourceRules != r.ImportedRecords+r.EmptyRecords+r.MalformedRecords {
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
