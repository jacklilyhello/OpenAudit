package security

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/openaudit/openaudit/internal/config"
)

func IsProtected(path string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}
func APIKeyMiddleware(cfg config.Config, checker Checker) gin.MiddlewareFunc {
	return func(c *gin.Context) bool {
		p := c.Request.URL.Path
		protected := IsProtected(p, cfg.Security.ProtectedPaths) || (cfg.Security.ProtectAuditAPI && strings.HasPrefix(p, "/audit/"))
		if cfg.App.Env == "production" && cfg.Security.ProtectManagementAPI && isManagement(p) {
			protected = true
		}
		if protected && !cfg.UnsafeProduction && !checker.Valid(c.Request) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing or invalid API key"})
			return false
		}
		return true
	}
}
func isManagement(p string) bool {
	return p == "/config" || strings.HasPrefix(p, "/logs") || strings.HasPrefix(p, "/rules/reload") || strings.HasPrefix(p, "/rules/create") || strings.HasPrefix(p, "/rules/update") || strings.HasPrefix(p, "/rules/delete") || strings.HasPrefix(p, "/rules/history") || strings.Contains(p, "/history") || strings.Contains(p, "/diff") || strings.HasPrefix(p, "/rules/rollback") || strings.HasPrefix(p, "/imports/") || strings.HasPrefix(p, "/rules/changes/stats")
}

func SecurityHeaders() gin.MiddlewareFunc {
	return func(c *gin.Context) bool {
		h := c.ResponseWriter.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		if strings.HasPrefix(c.Request.URL.Path, "/admin") {
			h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'")
		}
		return true
	}
}
func CORS(cfg config.CORSConfig) gin.MiddlewareFunc {
	allowed := map[string]bool{}
	for _, o := range cfg.AllowedOrigins {
		allowed[o] = true
	}
	methods := strings.Join(cfg.AllowedMethods, ", ")
	headers := strings.Join(cfg.AllowedHeaders, ", ")
	return func(c *gin.Context) bool {
		if !cfg.Enabled {
			return true
		}
		origin := c.Request.Header.Get("Origin")
		if allowed[origin] || allowed["*"] {
			c.ResponseWriter.Header().Set("Access-Control-Allow-Origin", origin)
			c.ResponseWriter.Header().Set("Vary", "Origin")
			c.ResponseWriter.Header().Set("Access-Control-Allow-Methods", methods)
			c.ResponseWriter.Header().Set("Access-Control-Allow-Headers", headers)
			if cfg.AllowCredentials {
				c.ResponseWriter.Header().Set("Access-Control-Allow-Credentials", "true")
			}
		}
		if c.Request.Method == http.MethodOptions {
			c.ResponseWriter.WriteHeader(http.StatusNoContent)
			return false
		}
		return true
	}
}

func ClientIP(r *http.Request, trusted []string) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	rip := net.ParseIP(host)
	if rip == nil {
		return host
	}
	if !ipInCIDRs(rip, trusted) {
		return rip.String()
	}
	for _, h := range []string{"CF-Connecting-IP", "X-Real-IP"} {
		if ip := net.ParseIP(strings.TrimSpace(r.Header.Get(h))); ip != nil {
			return ip.String()
		}
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if ip := net.ParseIP(strings.TrimSpace(strings.Split(xff, ",")[0])); ip != nil {
			return ip.String()
		}
	}
	return rip.String()
}
func ipInCIDRs(ip net.IP, cidrs []string) bool {
	for _, s := range cidrs {
		_, n, err := net.ParseCIDR(s)
		if err == nil && n.Contains(ip) {
			return true
		}
	}
	return false
}
func BodyLimit(n int64) gin.MiddlewareFunc {
	return func(c *gin.Context) bool {
		c.Request.Body = http.MaxBytesReader(c.ResponseWriter, c.Request.Body, n)
		return true
	}
}

type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]bucket
	window  time.Duration
}
type bucket struct {
	start time.Time
	count int
}

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{buckets: map[string]bucket{}, window: time.Minute}
}
func (r *RateLimiter) Middleware(cfg config.RateLimitConfig, trusted []string) gin.MiddlewareFunc {
	return func(c *gin.Context) bool {
		if !cfg.Enabled {
			return true
		}
		limit := cfg.AuditPerMinute
		p := c.Request.URL.Path
		group := "audit"
		if strings.HasPrefix(p, "/admin") {
			group = "admin"
			limit = cfg.AdminPerMinute
		} else if isManagement(p) {
			group = "management"
			limit = cfg.ManagementPerMinute
		}
		if limit <= 0 {
			return true
		}
		key := group + ":" + ClientIP(c.Request, trusted)
		if !r.allow(key, limit) {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "rate limit exceeded"})
			return false
		}
		return true
	}
}
func (r *RateLimiter) allow(key string, limit int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	b := r.buckets[key]
	if b.start.IsZero() || now.Sub(b.start) >= r.window {
		b = bucket{start: now}
	}
	b.count++
	r.buckets[key] = b
	return b.count <= limit
}

func AdminGuard(cfg config.Config) gin.MiddlewareFunc {
	return func(c *gin.Context) bool {
		if !strings.HasPrefix(c.Request.URL.Path, cfg.Admin.Path) {
			return true
		}
		if cfg.UnsafeProduction {
			return true
		}
		ip := net.ParseIP(ClientIP(c.Request, append(cfg.Server.TrustedProxies, cfg.Admin.TrustedProxies...)))
		allowed := false
		if ip != nil && ipInCIDRs(ip, cfg.Admin.AllowedCIDRs) {
			allowed = true
		}
		if cfg.Admin.RequireCloudflareAccess {
			allowed = c.Request.Header.Get("Cf-Access-Authenticated-User-Email") != "" || c.Request.Header.Get("Cf-Access-Jwt-Assertion") != ""
		}
		if !allowed {
			c.JSON(http.StatusForbidden, gin.H{"error": "admin access denied"})
			return false
		}
		return true
	}
}
