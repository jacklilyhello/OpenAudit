package api

import (
	"bytes"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"github.com/openaudit/openaudit/internal/config"
	"github.com/openaudit/openaudit/internal/engine"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLimits(t *testing.T) {
	e, _ := engine.New("../../data")
	r := gin.Default()
	RegisterAuditWithOptions(r, e, config.LimitsConfig{MaxTextRunes: 3, MaxBatchItems: 1, MaxHits: 1}, nil)
	RegisterBatchWithOptions(r, e, config.LimitsConfig{MaxTextRunes: 10, MaxBatchItems: 1, MaxHits: 1})
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/audit/text", strings.NewReader(`{"text":"abcd"}`))
	r.ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatal(w.Code)
	}
	w = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/audit/batch", strings.NewReader(`{"items":["a","b"]}`))
	r.ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatal(w.Code)
	}
	b, _ := json.Marshal(map[string]any{"text": "敏感词", "options": map[string]any{"max_hits": 99}})
	w = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/audit/text", bytes.NewReader(b))
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
}
