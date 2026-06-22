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

func fixture() []byte {
	b, err := os.ReadFile("../../testdata/bundled/g79_synthetic.json")
	if err != nil {
		panic(err)
	}
	return b
}
func TestBuildPackNetEasePhaseA(t *testing.T) {
	p, r, j, gz, err := BuildPack(fixture(), Options{Dataset: "g79", SourceRepository: "repo", SourceCommit: sha, SourceFilePath: "SensitiveWords/G79SensitiveWords.json", Timestamp: time.Unix(1, 0).UTC()})
	if err != nil {
		t.Fatal(err)
	}
	if len(j) == 0 || len(gz) == 0 || p.Provider != ProviderNetEase {
		t.Fatal("empty output")
	}
	if len(r.UnknownGroups) != 1 || r.UnknownGroups[0] != "unknown" {
		t.Fatalf("unknown groups: %#v", r.UnknownGroups)
	}
	if r.EmptyRecords != 3 {
		t.Fatalf("empty records=%d", r.EmptyRecords)
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
		if x.PCRE2Status != "not_checked" {
			t.Fatal("pcre2 checked")
		}
		if x.Group == "replace" && x.Metadata.UpstreamBehavior != "replace" {
			t.Fatal("replace metadata")
		}
	}
}
func TestX19DeterministicGzipAndSHA(t *testing.T) {
	opt := Options{Dataset: "x19", SourceRepository: "repo", SourceCommit: sha, SourceFilePath: "SensitiveWords/X19SensitiveWords.json", Timestamp: time.Unix(1, 0).UTC()}
	_, _, j1, g1, err := BuildPack(fixture(), opt)
	if err != nil {
		t.Fatal(err)
	}
	opt.Timestamp = time.Unix(999, 0)
	opt.Timestamp = time.Unix(1, 0).UTC()
	_, _, j2, g2, err := BuildPack(fixture(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(j1, j2) || !bytes.Equal(g1, g2) {
		t.Fatal("not deterministic")
	}
	if sha256.Sum256(g1) != sha256.Sum256(g2) {
		t.Fatal("sha mismatch")
	}
	if _, err := ReadPackGzip(g1, DefaultLimits()); err != nil {
		t.Fatal(err)
	}
}
func TestInvalidJSONOversizedAndLimits(t *testing.T) {
	if _, _, _, _, err := BuildPack([]byte(`{`), Options{Dataset: "g79"}); err == nil {
		t.Fatal("invalid json accepted")
	}
	lim := DefaultLimits()
	lim.InputJSONBytes = 3
	if _, _, _, _, err := BuildPack([]byte(`{"regex":{}}`), Options{Dataset: "g79", Limits: lim}); err == nil {
		t.Fatal("oversized accepted")
	}
	lim = DefaultLimits()
	lim.RuleCount = 1
	if _, _, _, _, err := BuildPack(fixture(), Options{Dataset: "g79", Limits: lim}); err == nil {
		t.Fatal("rule count accepted")
	}
}
func TestReadPackGzipSafety(t *testing.T) {
	_, _, _, gz, err := BuildPack([]byte(`{"regex":{"shield":{"1":"ok"}},"settings":{}}`), Options{Dataset: "g79", SourceCommit: sha})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPackGzip(gz[:len(gz)/2], DefaultLimits()); err == nil {
		t.Fatal("truncated accepted")
	}
	lim := DefaultLimits()
	lim.UncompressedPackBytes = 10
	if _, err := ReadPackGzip(gz, lim); err == nil {
		t.Fatal("oversized decompressed accepted")
	}
	var p Pack
	json.Unmarshal(bytes.ReplaceAll(mustGunzip(t, gz), []byte(`"schema_version": 1`), []byte(`"schema_version": 99`)), &p)
	b, _ := MarshalPack(p)
	gz2, _ := GzipDeterministic(b)
	if _, err := ReadPackGzip(gz2, DefaultLimits()); err == nil {
		t.Fatal("bad schema accepted")
	}
}
func TestWriteAtomicPreservesPreviousOnBuildFailure(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "pack.json.gz")
	old := []byte("previous")
	os.WriteFile(out, old, 0600)
	_, err := ConvertFile(filepath.Join(dir, "missing.json"), Options{Dataset: "g79", OutputPath: out}, false)
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
func mustGunzip(t *testing.T, b []byte) []byte {
	p, err := ReadPackGzip(b, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	out, _ := MarshalPack(p)
	return out
}
