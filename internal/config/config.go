package config

type Config struct {
	Server   ServerConfig   `yaml:"server" json:"server"`
	Rules    RulesConfig    `yaml:"rules" json:"rules"`
	Admin    AdminConfig    `yaml:"admin" json:"admin"`
	Security SecurityConfig `yaml:"security" json:"security"`
	AuditLog AuditLogConfig `yaml:"audit_log" json:"audit_log"`
	Limits   LimitsConfig   `yaml:"limits" json:"limits"`
}
type ServerConfig struct {
	Addr                string `yaml:"addr" json:"addr"`
	ReadTimeoutSeconds  int    `yaml:"read_timeout_seconds" json:"read_timeout_seconds"`
	WriteTimeoutSeconds int    `yaml:"write_timeout_seconds" json:"write_timeout_seconds"`
}
type RulesConfig struct {
	DataDir    string `yaml:"data_dir" json:"data_dir"`
	AutoReload bool   `yaml:"auto_reload" json:"auto_reload"`
}
type AdminConfig struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	Path    string `yaml:"path" json:"path"`
}
type SecurityConfig struct {
	APIKeyEnabled        bool     `yaml:"api_key_enabled" json:"api_key_enabled"`
	APIKeys              []string `yaml:"api_keys" json:"-"`
	ProtectedPaths       []string `yaml:"protected_paths" json:"protected_paths"`
	AllowAdminWithoutKey bool     `yaml:"allow_admin_without_key" json:"allow_admin_without_key"`
}
type AuditLogConfig struct {
	Enabled        bool   `yaml:"enabled" json:"enabled"`
	Path           string `yaml:"path" json:"path"`
	MaxEntries     int    `yaml:"max_entries" json:"max_entries"`
	LogRequestText bool   `yaml:"log_request_text" json:"log_request_text"`
	LogHits        bool   `yaml:"log_hits" json:"log_hits"`
}
type LimitsConfig struct {
	MaxTextRunes  int `yaml:"max_text_runes" json:"max_text_runes"`
	MaxBatchItems int `yaml:"max_batch_items" json:"max_batch_items"`
	MaxHits       int `yaml:"max_hits" json:"max_hits"`
}

func (c Config) Sanitized() Config { c.Security.APIKeys = nil; return c }
