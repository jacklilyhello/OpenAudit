package safepath

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestNewRootRejectsEmptyNULAndSymlinkRoot(t *testing.T) {
	if _, err := NewRoot(""); !errors.Is(err, ErrEmptyPath) {
		t.Fatalf("empty root error = %v", err)
	}
	if _, err := NewRoot("bad\x00root"); !errors.Is(err, ErrNULPath) {
		t.Fatalf("NUL root error = %v", err)
	}
	dir := t.TempDir()
	realRoot := filepath.Join(dir, "real")
	if err := os.MkdirAll(realRoot, RuntimeDirPerm); err != nil {
		t.Fatal(err)
	}
	linkRoot := filepath.Join(dir, "link")
	if err := os.Symlink(realRoot, linkRoot); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := NewRoot(linkRoot); !errors.Is(err, ErrSymlink) {
		t.Fatalf("symlink root error = %v", err)
	}
}

func TestResolveRejectsUnsafePathsAndAcceptsSafePaths(t *testing.T) {
	dir := t.TempDir()
	r, err := NewRoot(dir, RequireExistingDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve(""); !errors.Is(err, ErrEmptyPath) {
		t.Fatalf("empty path error = %v", err)
	}
	if _, err := r.Resolve("bad\x00path"); !errors.Is(err, ErrNULPath) {
		t.Fatalf("NUL path error = %v", err)
	}
	if _, err := r.Resolve("../secret"); !errors.Is(err, ErrParentTraversal) {
		t.Fatalf("traversal error = %v", err)
	}
	if _, err := r.Resolve(filepath.Join(t.TempDir(), "outside.txt")); err == nil {
		t.Fatal("absolute path outside root accepted")
	}
	rel, err := r.Resolve(filepath.Join("nested", "file.txt"))
	if err != nil {
		t.Fatal(err)
	}
	wantRel := filepath.Join(dir, "nested", "file.txt")
	if rel.String() != wantRel {
		t.Fatalf("relative path = %q want %q", rel.String(), wantRel)
	}
	absInside := filepath.Join(dir, "inside.txt")
	abs, err := r.Resolve(absInside)
	if err != nil {
		t.Fatal(err)
	}
	if abs.String() != absInside {
		t.Fatalf("absolute inside = %q want %q", abs.String(), absInside)
	}
	if got, err := r.ResolveAllowEmpty(""); err != nil || got.String() != dir {
		t.Fatalf("allow empty = %q %v", got.String(), err)
	}
}

func TestResolveRejectsPrefixTrickWithFilepathRel(t *testing.T) {
	dir := t.TempDir()
	rootDir := filepath.Join(dir, "root")
	evilDir := filepath.Join(dir, "root-evil")
	if err := os.MkdirAll(rootDir, RuntimeDirPerm); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(evilDir, RuntimeDirPerm); err != nil {
		t.Fatal(err)
	}
	r, err := NewRoot(rootDir, RequireExistingDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve(filepath.Join(evilDir, "file.txt")); err == nil {
		t.Fatal("prefix-sibling path accepted")
	}
}

func TestJoinAndContainsUseValidatedPaths(t *testing.T) {
	dir := t.TempDir()
	r, err := NewRoot(dir, RequireExistingDir())
	if err != nil {
		t.Fatal(err)
	}
	p, err := r.Join("a", "b.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !r.Contains(p) {
		t.Fatal("root does not contain joined path")
	}
	if _, err := r.Join("a", "..", "b.txt"); !errors.Is(err, ErrParentTraversal) {
		t.Fatalf("join traversal error = %v", err)
	}
}
