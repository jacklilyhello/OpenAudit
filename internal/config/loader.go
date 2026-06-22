package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
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
	if err := applyEnv(&cfg); err != nil {
		return cfg, err
	}
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

func applyEnv(c *Config) error {
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
	boolEnv := func(name string, dst *bool) error {
		if v, ok := os.LookupEnv(name); ok {
			b, err := strconv.ParseBool(strings.TrimSpace(v))
			if err != nil {
				return fmt.Errorf("invalid boolean %s: %w", name, err)
			}
			*dst = b
		}
		return nil
	}
	for _, item := range []struct {
		name string
		dst  *bool
	}{
		{"OPENAUDIT_BUNDLED_RULES_ENABLED", &c.BundledRules.Enabled}, {"OPENAUDIT_BUNDLED_RULES_NETEASE_ENABLED", &c.BundledRules.NetEase.Enabled}, {"OPENAUDIT_BUNDLED_RULES_NETEASE_DATASETS_G79", &c.BundledRules.NetEase.Datasets.G79}, {"OPENAUDIT_BUNDLED_RULES_NETEASE_DATASETS_X19", &c.BundledRules.NetEase.Datasets.X19}, {"OPENAUDIT_BUNDLED_RULES_NETEASE_GROUPS_SHIELD", &c.BundledRules.NetEase.Groups.Shield}, {"OPENAUDIT_BUNDLED_RULES_NETEASE_GROUPS_INTERCEPT", &c.BundledRules.NetEase.Groups.Intercept}, {"OPENAUDIT_BUNDLED_RULES_NETEASE_GROUPS_REPLACE", &c.BundledRules.NetEase.Groups.Replace}, {"OPENAUDIT_BUNDLED_RULES_NETEASE_GROUPS_NICKNAME", &c.BundledRules.NetEase.Groups.Nickname}, {"OPENAUDIT_BUNDLED_RULES_NETEASE_GROUPS_REMIND", &c.BundledRules.NetEase.Groups.Remind},
	} {
		if err := boolEnv(item.name, item.dst); err != nil {
			return err
		}
	}
	if v := strings.TrimSpace(os.Getenv("OPENAUDIT_BUNDLED_RULES_DATA_DIR")); v != "" {
		c.BundledRules.DataDir = v
	}
	if v := strings.TrimSpace(os.Getenv("OPENAUDIT_BUNDLED_RULES_NETEASE_MODE")); v != "" {
		c.BundledRules.NetEase.Mode = v
	}
	return nil
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
	if c.BundledRules.DataDir == "" {
		c.BundledRules.DataDir = d.BundledRules.DataDir
	}
	if c.BundledRules.NetEase.Mode == "" {
		c.BundledRules.NetEase.Mode = d.BundledRules.NetEase.Mode
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
	if c.Storage.Backend == "" {
		c.Storage.Backend = d.Storage.Backend
	}
	if c.Storage.Root == "" {
		c.Storage.Root = d.Storage.Root
	}
	if c.Storage.SQLitePath == "" {
		c.Storage.SQLitePath = d.Storage.SQLitePath
	}
	if !c.Storage.AutoMigrate {
		c.Storage.AutoMigrate = d.Storage.AutoMigrate
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
	if c.AI.DefaultAction == "" {
		c.AI.DefaultAction = d.AI.DefaultAction
	}
	if c.AI.Provider == "" {
		c.AI.Provider = d.AI.Provider
	}
	if c.AI.TimeoutMS == 0 {
		c.AI.TimeoutMS = d.AI.TimeoutMS
	}
	if c.AI.MaxRetries == 0 {
		c.AI.MaxRetries = d.AI.MaxRetries
	}
	if c.AI.RetryBackoffMS == 0 {
		c.AI.RetryBackoffMS = d.AI.RetryBackoffMS
	}
	if c.AI.CircuitBreakerFailureThreshold == 0 {
		c.AI.CircuitBreakerFailureThreshold = d.AI.CircuitBreakerFailureThreshold
	}
	if c.AI.CircuitBreakerCooldownMS == 0 {
		c.AI.CircuitBreakerCooldownMS = d.AI.CircuitBreakerCooldownMS
	}
	if c.AI.MaxExcerptRunes == 0 {
		c.AI.MaxExcerptRunes = d.AI.MaxExcerptRunes
	}
	if c.AI.Cache.TTLSeconds == 0 {
		c.AI.Cache.TTLSeconds = d.AI.Cache.TTLSeconds
	}
	fillReviewPolicy(&c.ReviewPolicy, d.ReviewPolicy)
	fillAIProvider(&c.AI.Providers.OpenAI, d.AI.Providers.OpenAI)
	fillAIProvider(&c.AI.Providers.DeepSeek, d.AI.Providers.DeepSeek)
	fillAIProvider(&c.AI.Providers.Qwen, d.AI.Providers.Qwen)
	fillAIProvider(&c.AI.Providers.Gemini, d.AI.Providers.Gemini)
	fillAIProvider(&c.AI.Providers.Claude, d.AI.Providers.Claude)
	fillAIProvider(&c.AI.Providers.Local, d.AI.Providers.Local)
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
func fillAIProvider(p *AIProviderConfig, d AIProviderConfig) {
	if p.APIKeyEnv == "" {
		p.APIKeyEnv = d.APIKeyEnv
	}
	if p.BaseURL == "" {
		p.BaseURL = d.BaseURL
	}
	if p.Model == "" {
		p.Model = d.Model
	}
}
func fillReviewPolicy(p *ReviewPolicyConfig, d ReviewPolicyConfig) {
	if p.AIScoreReviewThreshold == 0 {
		p.AIScoreReviewThreshold = d.AIScoreReviewThreshold
	}
	if p.AIScoreTemporaryBlockThreshold == 0 {
		p.AIScoreTemporaryBlockThreshold = d.AIScoreTemporaryBlockThreshold
	}
	if p.AIScoreLogOnlyBelow == 0 {
		p.AIScoreLogOnlyBelow = d.AIScoreLogOnlyBelow
	}
	if p.VariantScoreReviewThreshold == 0 {
		p.VariantScoreReviewThreshold = d.VariantScoreReviewThreshold
	}
	if p.UncertainDefaultAction == "" {
		p.UncertainDefaultAction = d.UncertainDefaultAction
	}
	if p.RetentionDays == 0 {
		p.RetentionDays = d.RetentionDays
	}
	if p.ContentExcerptMaxBytes == 0 {
		p.ContentExcerptMaxBytes = d.ContentExcerptMaxBytes
	}
	if p.MaxExportRows == 0 {
		p.MaxExportRows = d.MaxExportRows
	}
}
func Validate(c Config) error {
	env := c.App.Env
	if env != "development" && env != "production" && env != "test" {
		return fmt.Errorf("invalid app.env %q: must be development, production, or test", env)
	}
	if c.CloudflareAccess.VerifyJWT {
		return errors.New("Cloudflare Access JWT verification is not implemented yet")
	}
	if err := validateBundledRules(c.BundledRules); err != nil {
		return err
	}
	if c.Storage.Backend != "sqlite" && c.Storage.Backend != "jsonl" && c.Storage.Backend != "memory" {
		return fmt.Errorf("invalid storage.backend %q: must be sqlite, jsonl, or memory", c.Storage.Backend)
	}
	if err := validateAI(c.AI); err != nil {
		return err
	}
	if err := ValidateReviewPolicy(c.ReviewPolicy); err != nil {
		return err
	}
	if strings.ContainsRune(c.Storage.SQLitePath, '\x00') || strings.Contains(c.Storage.SQLitePath, "..") || filepath.IsAbs(c.Storage.SQLitePath) {
		return errors.New("storage.sqlite_path must be a relative safepath without NUL or parent traversal")
	}
	if strings.ContainsRune(c.Storage.Root, '\x00') || strings.Contains(c.Storage.Root, "..") {
		return errors.New("storage.root must not contain NUL or parent traversal")
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
func ValidateReviewPolicy(p ReviewPolicyConfig) error {
	for name, v := range map[string]float64{
		"review_policy.ai_score_review_threshold":          p.AIScoreReviewThreshold,
		"review_policy.ai_score_temporary_block_threshold": p.AIScoreTemporaryBlockThreshold,
		"review_policy.ai_score_log_only_below":            p.AIScoreLogOnlyBelow,
		"review_policy.variant_score_review_threshold":     p.VariantScoreReviewThreshold,
	} {
		if v < 0 || v > 1 {
			return fmt.Errorf("%s must be between 0 and 1", name)
		}
	}
	if p.AIScoreTemporaryBlockThreshold < p.AIScoreReviewThreshold {
		return errors.New("review_policy.ai_score_temporary_block_threshold must be greater than or equal to ai_score_review_threshold")
	}
	if !has([]string{"temporary_allow", "temporary_block", "review_only", "log_only"}, p.UncertainDefaultAction) {
		return fmt.Errorf("invalid review_policy.uncertain_default_action %q", p.UncertainDefaultAction)
	}
	if p.RetentionDays < 0 || p.ContentExcerptMaxBytes < 0 || p.MaxExportRows < 0 {
		return errors.New("review_policy retention, excerpt, and export limits must be non-negative")
	}
	return nil
}
func validateAI(c AIConfig) error {
	if c.DefaultAction != "" && c.DefaultAction != "review" {
		return errors.New("ai.default_action must be review")
	}
	if c.Provider != "" && !has([]string{"openai", "deepseek", "qwen", "gemini", "claude", "local"}, c.Provider) {
		return fmt.Errorf("invalid ai.provider %q", c.Provider)
	}
	if c.TimeoutMS < 0 || c.MaxRetries < 0 || c.RetryBackoffMS < 0 || c.CircuitBreakerFailureThreshold < 0 || c.CircuitBreakerCooldownMS < 0 || c.MaxExcerptRunes < 0 {
		return errors.New("ai numeric limits must be non-negative")
	}
	if c.Cache.TTLSeconds < 0 {
		return errors.New("ai.cache.ttl_seconds must be non-negative")
	}
	for name, p := range map[string]AIProviderConfig{"openai": c.Providers.OpenAI, "deepseek": c.Providers.DeepSeek, "qwen": c.Providers.Qwen, "gemini": c.Providers.Gemini, "claude": c.Providers.Claude, "local": c.Providers.Local} {
		if err := validateAIProvider(name, p); err != nil {
			return err
		}
	}
	return nil
}
func validateAIProvider(name string, p AIProviderConfig) error {
	if p.BaseURL != "" {
		u, err := url.ParseRequestURI(p.BaseURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("ai.providers.%s.base_url must be an http or https URL", name)
		}
	}
	if p.InputCostPer1K < 0 || p.OutputCostPer1K < 0 {
		return fmt.Errorf("ai.providers.%s cost settings must be non-negative", name)
	}
	if name != "local" && p.Enabled && strings.TrimSpace(p.APIKeyEnv) == "" {
		return fmt.Errorf("ai.providers.%s.api_key_env is required when provider is enabled", name)
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

func validateBundledRules(b BundledRulesConfig) error {
	if b.NetEase.Mode != "re2" && b.NetEase.Mode != "pcre2" {
		return fmt.Errorf("invalid bundled_rules.netease.mode %q: must be re2 or pcre2", b.NetEase.Mode)
	}
	if strings.ContainsRune(b.DataDir, '\x00') || strings.Contains(b.DataDir, "..") {
		return errors.New("bundled_rules.data_dir must not contain NUL or parent traversal")
	}
	return nil
}
