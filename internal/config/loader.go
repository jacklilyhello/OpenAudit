package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const DevKey = "dev-key"

func Load(path string) (Config, error) {
	cfg := Defaults()
	if path == "" {
		path = os.Getenv("OPENAUDIT_CONFIG")
	}
	if path != "" {
		configPath, err := cleanConfigPath(path)
		if err != nil {
			return cfg, err
		}
		// #nosec G304 G703 -- configPath is an operator-supplied startup config path, not request-controlled input; cleanConfigPath validates it before reading.
		if b, err := os.ReadFile(configPath); err == nil {
			if err := yaml.Unmarshal(b, &cfg); err != nil {
				return cfg, err
			}
		} else if !os.IsNotExist(err) {
			return cfg, err
		}
	}
	fill(&cfg)
	applyEnv(&cfg)
	return cfg, Validate(cfg)
}
func cleanConfigPath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", nil
	}
	if strings.ContainsRune(path, '\x00') {
		return "", errors.New("config path contains NUL byte")
	}
	cleaned := filepath.Clean(path)
	for _, part := range strings.Split(cleaned, string(filepath.Separator)) {
		if part == ".." {
			return "", fmt.Errorf("config path %q contains parent directory traversal", path)
		}
	}
	return cleaned, nil
}

func applyEnv(c *Config) {
	if v := strings.TrimSpace(os.Getenv("OPENAUDIT_ENV")); v != "" {
		c.App.Env = v
	}
	if v := os.Getenv("OPENAUDIT_API_KEYS"); v != "" {
		c.Security.APIKeys = strings.Split(v, ",")
	}
	if v := strings.TrimSpace(os.Getenv("OPENAUDIT_ADMIN_API_KEY")); v != "" {
		c.Security.APIKeys = append(c.Security.APIKeys, v)
	}
	c.UnsafeProduction = strings.EqualFold(os.Getenv("OPENAUDIT_ALLOW_UNSAFE_PRODUCTION"), "true")
}
func fill(c *Config) {
	d := Defaults()
	if c.App.Env == "" {
		c.App.Env = d.App.Env
	}
	if c.Server.Addr == "" {
		c.Server.Addr = d.Server.Addr
	}
	if c.Server.ReadTimeoutSeconds == 0 {
		c.Server.ReadTimeoutSeconds = d.Server.ReadTimeoutSeconds
	}
	if c.Server.WriteTimeoutSeconds == 0 {
		c.Server.WriteTimeoutSeconds = d.Server.WriteTimeoutSeconds
	}
	if len(c.Server.TrustedProxies) == 0 {
		c.Server.TrustedProxies = d.Server.TrustedProxies
	}
	if c.Rules.DataDir == "" {
		c.Rules.DataDir = d.Rules.DataDir
	}
	if c.Admin.Path == "" {
		c.Admin.Path = d.Admin.Path
	}
	if len(c.Admin.AllowedCIDRs) == 0 {
		c.Admin.AllowedCIDRs = d.Admin.AllowedCIDRs
	}
	if len(c.Admin.TrustedProxies) == 0 {
		c.Admin.TrustedProxies = d.Admin.TrustedProxies
	}
	if len(c.Security.APIKeys) == 0 {
		c.Security.APIKeys = d.Security.APIKeys
	}
	if len(c.Security.ProtectedPaths) == 0 {
		c.Security.ProtectedPaths = d.Security.ProtectedPaths
	}
	if !c.Security.ProtectAuditAPI { /* default false */
	}
	if c.AuditLog.Path == "" {
		c.AuditLog.Path = d.AuditLog.Path
	}
	if c.AuditLog.MaxEntries == 0 {
		c.AuditLog.MaxEntries = d.AuditLog.MaxEntries
	}
	if c.Limits.MaxTextRunes == 0 {
		c.Limits.MaxTextRunes = d.Limits.MaxTextRunes
	}
	if c.Limits.MaxBatchItems == 0 {
		c.Limits.MaxBatchItems = d.Limits.MaxBatchItems
	}
	if c.Limits.MaxHits == 0 {
		c.Limits.MaxHits = d.Limits.MaxHits
	}
	if c.Limits.MaxBodyBytes == 0 {
		c.Limits.MaxBodyBytes = d.Limits.MaxBodyBytes
	}
	if len(c.CORS.AllowedMethods) == 0 {
		c.CORS.AllowedMethods = d.CORS.AllowedMethods
	}
	if len(c.CORS.AllowedHeaders) == 0 {
		c.CORS.AllowedHeaders = d.CORS.AllowedHeaders
	}
	if c.RateLimit.AuditPerMinute == 0 {
		c.RateLimit = d.RateLimit
	}
	c.SecurityHeaders.Enabled = true
}
func Validate(c Config) error {
	env := c.App.Env
	if env != "development" && env != "production" && env != "test" {
		return fmt.Errorf("invalid app.env %q: must be development, production, or test", env)
	}
	if c.CloudflareAccess.VerifyJWT {
		return errors.New("Cloudflare Access JWT verification is not implemented yet")
	}
	if c.App.Env != "production" {
		return nil
	}
	if c.CORS.Enabled && has(c.CORS.AllowedOrigins, "*") && !c.UnsafeProduction {
		return errors.New("production CORS wildcard origin is unsafe; set explicit origins or OPENAUDIT_ALLOW_UNSAFE_PRODUCTION=true")
	}
	if c.Security.ProtectManagementAPI == false && !c.UnsafeProduction {
		return errors.New("production requires security.protect_management_api=true unless OPENAUDIT_ALLOW_UNSAFE_PRODUCTION=true")
	}
	if !c.Security.APIKeyEnabled && c.Security.ProtectManagementAPI && !c.UnsafeProduction {
		return errors.New("production management APIs require security.api_key_enabled=true unless OPENAUDIT_ALLOW_UNSAFE_PRODUCTION=true")
	}
	if c.Security.APIKeyEnabled && !hasNonDevKey(c.Security.APIKeys) && !c.UnsafeProduction {
		return errors.New("production API key protection requires a non-dev API key from OPENAUDIT_API_KEYS or external secrets")
	}
	if c.Admin.Enabled && !c.Admin.RequireCloudflareAccess && !safeCIDRs(c.Admin.AllowedCIDRs) && !c.UnsafeProduction {
		return errors.New("production admin requires Cloudflare Access or narrow allowed_cidrs unless OPENAUDIT_ALLOW_UNSAFE_PRODUCTION=true")
	}
	return nil
}
func has(xs []string, want string) bool {
	for _, x := range xs {
		if strings.TrimSpace(x) == want {
			return true
		}
	}
	return false
}
func hasNonDevKey(xs []string) bool {
	for _, x := range xs {
		x = strings.TrimSpace(x)
		if x != "" && x != DevKey && x != "dev-admin-key" {
			return true
		}
	}
	return false
}
func safeCIDRs(xs []string) bool {
	if len(xs) == 0 {
		return false
	}
	for _, s := range xs {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return false
		}
		ones, bits := n.Mask.Size()
		if ones == 0 || (bits == 32 && ones < 8) || (bits == 128 && ones < 64) {
			return false
		}
	}
	return true
}
