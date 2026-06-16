package safepath

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWalkVisitsSafePathsAndRejectsSymlinkFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "nested"), RuntimeDirPerm); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "nested", "ok.txt"), []byte("ok"), RuntimeFilePerm); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("secret"), RuntimeFilePerm); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "nested", "link.txt")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	r, err := NewRoot(dir, RequireExistingDir())
	if err != nil {
		t.Fatal(err)
	}
	visited := 0
	err = r.Walk(func(p Path, _ os.DirEntry) error {
		if !r.Contains(p) {
			t.Fatalf("walk callback received escaping path %s", p.String())
		}
		visited++
		return nil
	})
	if !errors.Is(err, ErrSymlink) {
		t.Fatalf("walk symlink file error = %v", err)
	}
	if visited == 0 {
		t.Fatal("walk did not visit safe paths before symlink")
	}
}

func TestWalkRejectsSymlinkDirectory(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.MkdirAll(real, RuntimeDirPerm); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(dir, "linkdir")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	r, err := NewRoot(dir, RequireExistingDir())
	if err != nil {
		t.Fatal(err)
	}
	err = r.Walk(func(Path, os.DirEntry) error { return nil })
	if !errors.Is(err, ErrSymlink) {
		t.Fatalf("walk symlink dir error = %v", err)
	}
}
