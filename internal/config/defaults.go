package config

func Defaults() Config {
	return Config{Server: ServerConfig{Addr: ":8080", ReadTimeoutSeconds: 10, WriteTimeoutSeconds: 30}, Rules: RulesConfig{DataDir: "./data"}, Admin: AdminConfig{Enabled: true, Path: "/admin"}, Security: SecurityConfig{APIKeys: []string{"dev-key"}, ProtectedPaths: []string{"/rules/reload", "/rules/create", "/rules/update", "/rules/delete", "/logs"}, AllowAdminWithoutKey: true}, AuditLog: AuditLogConfig{Enabled: true, Path: "./storage/audit.log", MaxEntries: 1000, LogRequestText: true, LogHits: true}, Limits: LimitsConfig{MaxTextRunes: 10000, MaxBatchItems: 100, MaxHits: 100}}
}
