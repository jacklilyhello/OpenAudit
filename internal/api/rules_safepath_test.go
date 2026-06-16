package api

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/openaudit/openaudit/internal/safepath"
)

func TestCustomRulePathRejectsEscapesAndSymlinkRoot(t *testing.T) {
	root := t.TempDir()
	if _, _, err := customPath(root, "../evil"); err == nil {
		t.Fatal("custom rule path accepted traversal id")
	}
	realCustom := filepath.Join(t.TempDir(), "real-custom")
	if err := os.MkdirAll(realCustom, safepath.RuntimeDirPerm); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realCustom, filepath.Join(root, "custom")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, _, err := customPath(root, "safe_rule"); err == nil {
		t.Fatal("custom rule symlink root accepted")
	}
}

func TestCustomRuleWriteUsesRuntimePermissions(t *testing.T) {
	root := t.TempDir()
	customRoot, p, err := customPath(root, "safe_rule")
	if err != nil {
		t.Fatal(err)
	}
	if err := writeCustomRuleFile(customRoot, p, []byte("id: safe_rule\n")); err != nil {
		t.Fatal(err)
	}
	fileInfo, err := os.Stat(p.String())
	if err != nil {
		t.Fatal(err)
	}
	if got := fileInfo.Mode().Perm(); got != safepath.RuntimeFilePerm {
		t.Fatalf("file mode = %o want %o", got, safepath.RuntimeFilePerm)
	}
	dirInfo, err := os.Stat(filepath.Dir(p.String()))
	if err != nil {
		t.Fatal(err)
	}
	if got := dirInfo.Mode().Perm(); got != safepath.RuntimeDirPerm {
		t.Fatalf("dir mode = %o want %o", got, safepath.RuntimeDirPerm)
	}
}
