package safepath

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteFileAtomicCreatesOverwritesAndSetsPermissions(t *testing.T) {
	dir := t.TempDir()
	rootDir := filepath.Join(dir, "runtime")
	r, err := NewRoot(rootDir, CreateRoot())
	if err != nil {
		t.Fatal(err)
	}
	p, err := r.Join("nested", "out.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.WriteFileAtomic(p, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := r.WriteFileAtomic(p, []byte("two")); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p.String())
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "two" {
		t.Fatalf("contents = %q", string(b))
	}
	fileInfo, err := os.Stat(p.String())
	if err != nil {
		t.Fatal(err)
	}
	if got := fileInfo.Mode().Perm(); got != RuntimeFilePerm {
		t.Fatalf("file mode = %o want %o", got, RuntimeFilePerm)
	}
	dirInfo, err := os.Stat(filepath.Dir(p.String()))
	if err != nil {
		t.Fatal(err)
	}
	if got := dirInfo.Mode().Perm(); got != RuntimeDirPerm {
		t.Fatalf("dir mode = %o want %o", got, RuntimeDirPerm)
	}
}

func TestWriteFileAtomicCleansTempOnRenameFailure(t *testing.T) {
	dir := t.TempDir()
	r, err := NewRoot(dir, RequireExistingDir())
	if err != nil {
		t.Fatal(err)
	}
	target, err := r.Join("existing-dir")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.MkdirAll(target); err != nil {
		t.Fatal(err)
	}
	if err := r.WriteFileAtomic(target, []byte("not a file")); err == nil {
		t.Fatal("atomic write to directory succeeded")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".openaudit-") {
			t.Fatalf("temp file was not cleaned up: %s", entry.Name())
		}
	}
}
