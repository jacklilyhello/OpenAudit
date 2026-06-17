package config

func Defaults() Config {
	return Config{
		App: AppConfig{Env: "development"},
		Server: ServerConfig{
			Addr:                ":8080",
			ReadTimeoutSeconds:  10,
			WriteTimeoutSeconds: 30,
			TrustedProxies:      []string{"127.0.0.1/32", "::1/128"},
		},
		Rules: RulesConfig{DataDir: "./data"},
		Admin: AdminConfig{
			Enabled:              true,
			Path:                 "/admin",
			AllowLocal:           true,
			AllowPrivateNetworks: true,
			AllowedCIDRs:         []string{"127.0.0.1/32", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
			TrustedProxies:       []string{"127.0.0.1/32", "::1/128"},
		},
		Security: SecurityConfig{
			APIKeys:              []string{DevKey},
			ProtectedPaths:       []string{"/rules/reload", "/rules/create", "/rules/update", "/rules/delete", "/logs", "/config"},
			AllowAdminWithoutKey: true,
			ProtectManagementAPI: true,
		},
		SecurityHeaders: SecurityHeadersConfig{Enabled: true},
		CORS: CORSConfig{
			AllowedMethods: []string{"GET", "POST", "PATCH", "DELETE", "OPTIONS"},
			AllowedHeaders: []string{"Authorization", "Content-Type", "X-API-Key"},
		},
		RateLimit: RateLimitConfig{Enabled: true, AuditPerMinute: 120, ManagementPerMinute: 30, AdminPerMinute: 60},
		AuditLog:  AuditLogConfig{Enabled: true, Path: "./storage/audit.log", MaxEntries: 1000, LogRequestText: true, LogHits: true},
		RuleHistory: RuleHistoryConfig{
			Enabled:           true,
			Path:              "./storage/rule-history/history.jsonl",
			ImportBatchesPath: "./storage/rule-history/import-batches.jsonl",
			MaxEntries:        5000,
			SnapshotDir:       "./storage/rule-history/snapshots",
		},
		Storage: StorageConfig{Backend: "sqlite", Root: "./storage", SQLitePath: "data/openaudit.db", LegacyJSONLFallback: true, AutoMigrate: true},
		Importer: ImporterConfig{
			DefaultInputDir:       "./external-rules",
			DefaultOutputDir:      "./data/imported",
			ReportDir:             "./storage/imports/reports",
			BatchHistoryPath:      "./storage/rule-history/import-batches.jsonl",
			MaxKeywordsPerFile:    10000,
			DefaultSource:         "external",
			AutoReloadAfterImport: false,
			AllowRemoteClone:      false,
			AllowedCloneHosts:     []string{"github.com"},
		},
		Limits: LimitsConfig{MaxTextRunes: 10000, MaxBatchItems: 100, MaxHits: 100, MaxBodyBytes: 1048576},
		AI:     defaultAIConfig(),
	}
}

func defaultAIConfig() AIConfig {
	return AIConfig{
		DefaultAction:                  "review",
		Provider:                       "openai",
		TimeoutMS:                      8000,
		MaxRetries:                     2,
		RetryBackoffMS:                 250,
		CircuitBreakerFailureThreshold: 5,
		CircuitBreakerCooldownMS:       30000,
		MaxExcerptRunes:                2000,
		Cache:                          AICacheConfig{Enabled: true, TTLSeconds: 3600},
		CostTracking:                   AICostConfig{Enabled: true},
		AuditLogs:                      AIAuditLogConfig{Enabled: true},
		Providers: AIProvidersConfig{
			OpenAI: AIProviderConfig{
				APIKeyEnv: aiProviderEnv("OPENAI"),
				BaseURL:   "https://api.openai.com/v1",
				Model:     "gpt-4o-mini",
			},
			DeepSeek: AIProviderConfig{
				APIKeyEnv: aiProviderEnv("DEEPSEEK"),
				BaseURL:   "https://api.deepseek.com",
				Model:     "deepseek-chat",
			},
			Qwen: AIProviderConfig{
				APIKeyEnv: aiProviderEnv("QWEN"),
				BaseURL:   "https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
				Model:     "qwen-plus",
			},
			Gemini: AIProviderConfig{
				APIKeyEnv: aiProviderEnv("GEMINI"),
				BaseURL:   "https://generativelanguage.googleapis.com/v1beta",
				Model:     "gemini-1.5-flash",
			},
			Claude: AIProviderConfig{
				APIKeyEnv: "ANTHROPIC" + "_API" + "_KEY",
				BaseURL:   "https://api.anthropic.com/v1",
				Model:     "claude-3-5-haiku-latest",
			},
			Local: AIProviderConfig{
				BaseURL: "http://127.0.0.1:11434/v1",
				Model:   "llama3.1",
			},
		},
	}
}

func aiProviderEnv(provider string) string {
	return provider + "_API" + "_KEY"
}
