package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/openaudit/openaudit/internal/config"
)

func newImportTestRouter(t *testing.T) (*gin.Engine, config.Config) {
	t.Helper()
	root := t.TempDir()
	inputRoot := filepath.Join(root, "external-rules")
	outputRoot := filepath.Join(root, "data", "imported")
	reportRoot := filepath.Join(root, "storage", "imports", "reports")
	if err := os.MkdirAll(filepath.Join(inputRoot, "政治"), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inputRoot, "政治", "words.txt"), []byte("敏感词\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.Importer.DefaultInputDir = inputRoot
	cfg.Importer.DefaultOutputDir = outputRoot
	cfg.Importer.ReportDir = reportRoot
	cfg.Importer.DefaultSource = "sensitive-lexicon"
	r := gin.Default()
	RegisterImports(r, cfg, nil)
	return r, cfg
}

func postImportPreview(r *gin.Engine, body map[string]any) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/imports/preview", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	return w
}

func TestImportsAPIRejectsUnsafePaths(t *testing.T) {
	r, cfg := newImportTestRouter(t)
	cases := []map[string]any{
		{"input_path": "bad\x00"},
		{"input_path": "../secret"},
		{"output_path": "../out"},
		{"input_path": filepath.Join(t.TempDir(), "outside")},
	}
	for _, tc := range cases {
		w := postImportPreview(r, tc)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for %#v got %d %s; cfg=%+v", tc, w.Code, w.Body.String(), cfg.Importer)
		}
	}
}

func TestImportsAPIAcceptsRelativePathUnderRoot(t *testing.T) {
	r, _ := newImportTestRouter(t)
	w := postImportPreview(r, map[string]any{"input_path": "政治", "output_path": "", "source": "sensitive-lexicon"})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d %s", w.Code, w.Body.String())
	}
}
