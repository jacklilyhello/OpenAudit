package security

import (
	"github.com/gin-gonic/gin"
	"github.com/openaudit/openaudit/internal/config"
	"net/http/httptest"
	"testing"
)

func TestAPIKeyHeadersAndInvalid(t *testing.T) {
	c := New(true, []string{" k "})
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer k")
	if !c.Valid(r) {
		t.Fatal("bearer")
	}
	r.Header.Del("Authorization")
	r.Header.Set("X-API-Key", "k")
	if !c.Valid(r) {
		t.Fatal("x-api")
	}
	r.Header.Set("X-API-Key", "bad")
	if c.Valid(r) {
		t.Fatal("bad")
	}
}
func TestClientIPTrustedProxy(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "8.8.8.8:1"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := ClientIP(r, []string{"127.0.0.1/32"}); got != "8.8.8.8" {
		t.Fatal(got)
	}
	r.RemoteAddr = "127.0.0.1:1"
	if got := ClientIP(r, []string{"127.0.0.1/32"}); got != "1.2.3.4" {
		t.Fatal(got)
	}
	r.Header.Set("CF-Connecting-IP", "5.6.7.8")
	if got := ClientIP(r, []string{"127.0.0.1/32"}); got != "5.6.7.8" {
		t.Fatal(got)
	}
}
func TestAdminGuard(t *testing.T) {
	cfg := config.Defaults()
	cfg.App.Env = "production"
	r := gin.Default()
	r.Use(AdminGuard(cfg))
	r.GET("/admin", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/admin", nil)
	req.RemoteAddr = "8.8.8.8:1"
	r.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
	cfg.Admin.RequireCloudflareAccess = true
	r = gin.Default()
	r.Use(AdminGuard(cfg))
	r.GET("/admin", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })
	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/admin", nil)
	req.RemoteAddr = "8.8.8.8:1"
	req.Header.Set("Cf-Access-Authenticated-User-Email", "a@example.com")
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
}
func TestCORSAllowedOrigin(t *testing.T) {
	cfg := config.CORSConfig{Enabled: true, AllowedOrigins: []string{"https://example.com"}, AllowedMethods: []string{"GET"}, AllowedHeaders: []string{"X-API-Key"}}
	r := gin.Default()
	r.Use(CORS(cfg))
	r.GET("/", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Origin", "https://example.com")
	r.ServeHTTP(w, req)
	if w.Header().Get("Access-Control-Allow-Origin") != "https://example.com" {
		t.Fatal("cors")
	}
}
func TestRateLimit(t *testing.T) {
	cfg := config.RateLimitConfig{Enabled: true, AuditPerMinute: 1, ManagementPerMinute: 1, AdminPerMinute: 1}
	r := gin.Default()
	r.Use(NewRateLimiter().Middleware(cfg, nil))
	r.POST("/audit/text", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })
	req := httptest.NewRequest("POST", "/audit/text", nil)
	req.RemoteAddr = "1.1.1.1:1"
	r.ServeHTTP(httptest.NewRecorder(), req)
	w := httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/audit/text", nil)
	req.RemoteAddr = "1.1.1.1:1"
	r.ServeHTTP(w, req)
	if w.Code != 429 {
		t.Fatal(w.Code)
	}
}
