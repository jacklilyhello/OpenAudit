package importer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestImporterDryRunAndSplitting(t *testing.T) {
	in := t.TempDir()
	out := t.TempDir()
	if err := os.MkdirAll(filepath.Join(in, "政治"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(in, "政治", "a.txt"), []byte("一\n二\n三\n"), 0644); err != nil {
		t.Fatal(err)
	}
	r, err := ImportSensitiveLexicon(Options{Input: in, Output: out, MaxKeywordsPerFile: 2, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if r.FilesScanned != 1 || r.KeywordsRead != 3 || r.FilesWritten != 2 {
		t.Fatalf("bad dry run %+v", r)
	}
	r, err = ImportSensitiveLexicon(Options{Input: in, Output: out, MaxKeywordsPerFile: 2})
	if err != nil {
		t.Fatal(err)
	}
	if r.FilesWritten != 2 {
		t.Fatalf("want split 2 %+v", r)
	}
}
