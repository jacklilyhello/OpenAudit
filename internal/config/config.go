package config

type Config struct {
	App              AppConfig              `yaml:"app" json:"app"`
	Server           ServerConfig           `yaml:"server" json:"server"`
	Rules            RulesConfig            `yaml:"rules" json:"rules"`
	Admin            AdminConfig            `yaml:"admin" json:"admin"`
	CloudflareAccess CloudflareAccessConfig `yaml:"cloudflare_access" json:"cloudflare_access"`
	Security         SecurityConfig         `yaml:"security" json:"security"`
	SecurityHeaders  SecurityHeadersConfig  `yaml:"security_headers" json:"security_headers"`
	CORS             CORSConfig             `yaml:"cors" json:"cors"`
	RateLimit        RateLimitConfig        `yaml:"rate_limit" json:"rate_limit"`
	AuditLog         AuditLogConfig         `yaml:"audit_log" json:"audit_log"`
	RuleHistory      RuleHistoryConfig      `yaml:"rule_history" json:"rule_history"`
	Importer         ImporterConfig         `yaml:"importer" json:"importer"`
	Storage          StorageConfig          `yaml:"storage" json:"storage"`
	Limits           LimitsConfig           `yaml:"limits" json:"limits"`
	UnsafeProduction bool                   `yaml:"-" json:"unsafe_production"`
}
type AppConfig struct {
	Env string `yaml:"env" json:"env"`
}
type ServerConfig struct {
	Addr                string   `yaml:"addr" json:"addr"`
	ReadTimeoutSeconds  int      `yaml:"read_timeout_seconds" json:"read_timeout_seconds"`
	WriteTimeoutSeconds int      `yaml:"write_timeout_seconds" json:"write_timeout_seconds"`
	TrustedProxies      []string `yaml:"trusted_proxies" json:"trusted_proxies"`
}
type RulesConfig struct {
	DataDir    string `yaml:"data_dir" json:"data_dir"`
	AutoReload bool   `yaml:"auto_reload" json:"auto_reload"`
}
type AdminConfig struct {
	Enabled                    bool     `yaml:"enabled" json:"enabled"`
	Path                       string   `yaml:"path" json:"path"`
	AllowLocal                 bool     `yaml:"allow_local" json:"allow_local"`
	AllowPrivateNetworks       bool     `yaml:"allow_private_networks" json:"allow_private_networks"`
	RequireCloudflareAccess    bool     `yaml:"require_cloudflare_access" json:"require_cloudflare_access"`
	CloudflareAccessAud        string   `yaml:"cloudflare_access_aud" json:"cloudflare_access_aud"`
	CloudflareAccessTeamDomain string   `yaml:"cloudflare_access_team_domain" json:"cloudflare_access_team_domain"`
	TrustedProxies             []string `yaml:"trusted_proxies" json:"trusted_proxies"`
	AllowedCIDRs               []string `yaml:"allowed_cidrs" json:"allowed_cidrs"`
}
type CloudflareAccessConfig struct {
	Enabled        bool     `yaml:"enabled" json:"enabled"`
	VerifyJWT      bool     `yaml:"verify_jwt" json:"verify_jwt"`
	TeamDomain     string   `yaml:"team_domain" json:"team_domain"`
	Aud            string   `yaml:"aud" json:"aud"`
	AllowedEmails  []string `yaml:"allowed_emails" json:"allowed_emails"`
	AllowedDomains []string `yaml:"allowed_domains" json:"allowed_domains"`
}
type SecurityConfig struct {
	APIKeyEnabled        bool     `yaml:"api_key_enabled" json:"api_key_enabled"`
	APIKeys              []string `yaml:"api_keys" json:"-"`
	APIKeysConfigured    bool     `yaml:"-" json:"api_keys_configured"`
	ProtectedPaths       []string `yaml:"protected_paths" json:"protected_paths"`
	AllowAdminWithoutKey bool     `yaml:"allow_admin_without_key" json:"allow_admin_without_key"`
	ProtectAuditAPI      bool     `yaml:"protect_audit_api" json:"protect_audit_api"`
	ProtectManagementAPI bool     `yaml:"protect_management_api" json:"protect_management_api"`
}
type SecurityHeadersConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
}
type CORSConfig struct {
	Enabled          bool     `yaml:"enabled" json:"enabled"`
	AllowedOrigins   []string `yaml:"allowed_origins" json:"allowed_origins"`
	AllowedMethods   []string `yaml:"allowed_methods" json:"allowed_methods"`
	AllowedHeaders   []string `yaml:"allowed_headers" json:"allowed_headers"`
	AllowCredentials bool     `yaml:"allow_credentials" json:"allow_credentials"`
}
type RateLimitConfig struct {
	Enabled             bool `yaml:"enabled" json:"enabled"`
	AuditPerMinute      int  `yaml:"audit_per_minute" json:"audit_per_minute"`
	ManagementPerMinute int  `yaml:"management_per_minute" json:"management_per_minute"`
	AdminPerMinute      int  `yaml:"admin_per_minute" json:"admin_per_minute"`
}
type AuditLogConfig struct {
	Enabled        bool   `yaml:"enabled" json:"enabled"`
	Path           string `yaml:"path" json:"path"`
	MaxEntries     int    `yaml:"max_entries" json:"max_entries"`
	LogRequestText bool   `yaml:"log_request_text" json:"log_request_text"`
	LogHits        bool   `yaml:"log_hits" json:"log_hits"`
}
type RuleHistoryConfig struct {
	Enabled           bool   `yaml:"enabled" json:"enabled"`
	Path              string `yaml:"path" json:"path"`
	ImportBatchesPath string `yaml:"import_batches_path" json:"import_batches_path"`
	MaxEntries        int    `yaml:"max_entries" json:"max_entries"`
	SnapshotDir       string `yaml:"snapshot_dir" json:"snapshot_dir"`
}

type ImporterConfig struct {
	DefaultInputDir       string   `yaml:"default_input_dir" json:"default_input_dir"`
	DefaultOutputDir      string   `yaml:"default_output_dir" json:"default_output_dir"`
	ReportDir             string   `yaml:"report_dir" json:"report_dir"`
	BatchHistoryPath      string   `yaml:"batch_history_path" json:"batch_history_path"`
	MaxKeywordsPerFile    int      `yaml:"max_keywords_per_file" json:"max_keywords_per_file"`
	DefaultSource         string   `yaml:"default_source" json:"default_source"`
	AutoReloadAfterImport bool     `yaml:"auto_reload_after_import" json:"auto_reload_after_import"`
	AllowRemoteClone      bool     `yaml:"allow_remote_clone" json:"allow_remote_clone"`
	AllowedCloneHosts     []string `yaml:"allowed_clone_hosts" json:"allowed_clone_hosts"`
}

type StorageConfig struct {
	Backend             string `yaml:"backend" json:"backend"`
	Root                string `yaml:"root" json:"root"`
	SQLitePath          string `yaml:"sqlite_path" json:"sqlite_path"`
	LegacyJSONLFallback bool   `yaml:"legacy_jsonl_fallback" json:"legacy_jsonl_fallback"`
	AutoMigrate         bool   `yaml:"auto_migrate" json:"auto_migrate"`
}

type LimitsConfig struct {
	MaxTextRunes  int   `yaml:"max_text_runes" json:"max_text_runes"`
	MaxBatchItems int   `yaml:"max_batch_items" json:"max_batch_items"`
	MaxHits       int   `yaml:"max_hits" json:"max_hits"`
	MaxBodyBytes  int64 `yaml:"max_body_bytes" json:"max_body_bytes"`
}

func (c Config) Sanitized() Config {
	c.Security.APIKeysConfigured = len(c.Security.APIKeys) > 0
	c.Security.APIKeys = nil
	return c
}
