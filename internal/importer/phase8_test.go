package importer

import (
	"github.com/openaudit/openaudit/internal/rules"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCategoryMappingAndSanitize(t *testing.T) {
	cases := map[string]string{"政治": "political", "涉政": "political", "色情": "porn", "民生": "public_affairs", "": "imported", "Weird Name!": "weird_name"}
	for in, want := range cases {
		if got := SanitizeCategory(in); got != want {
			t.Fatalf("%q got %q want %q", in, got, want)
		}
	}
}
func TestTypeInference(t *testing.T) {
	if got := InferType("x.txt", "hello", "auto"); got != "keyword" {
		t.Fatal(got)
	}
	if got := InferType("域名/a.txt", "*.example.com", "auto"); got != "domain" {
		t.Fatal(got)
	}
	if got := InferType("regex/a.txt", `(?i)bad\d+`, "auto"); got != "regex" {
		t.Fatal(got)
	}
	if got := InferType("x", "example.com", "keyword"); got != "keyword" {
		t.Fatal(got)
	}
}
func TestPreviewDryRunDedupeInvalidRegex(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "政治")
	if err := os.MkdirAll(in, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(in, "regex.txt"), []byte("#c\n\n(?i)bad\\d+\n[\n(?i)bad\\d+\n"), 0600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	rep, err := Run(Options{Input: dir, Output: out, Source: "sensitive-lexicon", Type: "regex", DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Status != "dry_run" || rep.FilesScanned != 1 || rep.LinesRead != 5 || rep.BlankCommentSkipped != 2 || rep.DuplicatesRemoved != 1 || rep.InvalidRegex != 1 {
		t.Fatalf("bad report: %+v", rep)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("dry run wrote output")
	}
}
func TestWriteDeterministicAndLoad(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "域名")
	_ = os.MkdirAll(in, 0750)
	_ = os.WriteFile(filepath.Join(in, "domains.txt"), []byte("example.com\n*.example.org\n"), 0600)
	out := filepath.Join(dir, "out")
	rep, err := Run(Options{Input: dir, Output: out, Source: "sensitive-lexicon", Type: "auto", MaxKeywordsPerFile: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.OutputFiles) != 2 {
		t.Fatalf("files=%v", rep.OutputFiles)
	}
	if !strings.Contains(rep.OutputFiles[0], filepath.Join("sensitive_lexicon", "domain", "domain")) {
		t.Fatalf("bad path %s", rep.OutputFiles[0])
	}
	set, err := rules.Load(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.DomainRules) != 2 || set.DomainRules[0].Source != "sensitive-lexicon" {
		t.Fatalf("bad rules: %+v", set.DomainRules)
	}
}
func TestPathSafety(t *testing.T) {
	if _, err := Run(Options{Input: "", Output: t.TempDir()}); err == nil {
		t.Fatal("empty input accepted")
	}
	if _, err := Run(Options{Input: "bad\x00", Output: t.TempDir()}); err == nil {
		t.Fatal("nul accepted")
	}
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "x.txt")
	_ = os.WriteFile(outside, []byte("x"), 0600)
	_ = os.Symlink(outside, filepath.Join(dir, "link.txt"))
	if _, err := Run(Options{Input: dir, Output: filepath.Join(dir, "out")}); err == nil {
		t.Fatal("symlink accepted")
	}
}
