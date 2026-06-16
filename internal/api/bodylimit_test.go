package api

import (
	"github.com/gin-gonic/gin"
	"github.com/openaudit/openaudit/internal/config"
	"github.com/openaudit/openaudit/internal/engine"
	"github.com/openaudit/openaudit/internal/security"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOversizedBodyReturns413(t *testing.T) {
	e, _ := engine.New("../../data")
	r := gin.Default()
	r.Use(security.BodyLimit(8))
	RegisterAuditWithOptions(r, e, config.Defaults().Limits, nil)
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/audit/text", strings.NewReader(`{"text":"hello world"}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != 413 {
		t.Fatalf("want 413 got %d body %s", w.Code, w.Body.String())
	}
}
