package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/openaudit/openaudit/internal/admin"
	"github.com/openaudit/openaudit/internal/ai"
	"github.com/openaudit/openaudit/internal/api"
	"github.com/openaudit/openaudit/internal/config"
	"github.com/openaudit/openaudit/internal/engine"
	"github.com/openaudit/openaudit/internal/logstore"
	"github.com/openaudit/openaudit/internal/rulehistory"
	"github.com/openaudit/openaudit/internal/security"
	"github.com/openaudit/openaudit/internal/storage"
	storagesqlite "github.com/openaudit/openaudit/internal/storage/sqlite"
)

func main() {
	configPath := flag.String("config", "", "config file path")
	flag.Parse()
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if cfg.UnsafeProduction && cfg.App.Env == "production" {
		log.Printf("WARNING: OPENAUDIT_ALLOW_UNSAFE_PRODUCTION=true disables production safety checks")
	}
	e, err := engine.New(cfg.Rules.DataDir)
	if err != nil {
		log.Fatalf("load rules: %v", err)
	}
	var persistent storage.Store
	if cfg.Storage.Backend == "sqlite" {
		persistent, err = storagesqlite.Open(context.Background(), storagesqlite.Options{Root: cfg.Storage.Root, Path: cfg.Storage.SQLitePath, AutoMigrate: cfg.Storage.AutoMigrate})
		if err != nil {
			if cfg.App.Env == "production" || !cfg.Storage.LegacyJSONLFallback {
				log.Fatalf("sqlite storage: %v", err)
			}
			log.Printf("sqlite storage unavailable; using legacy JSONL fallback: %v", err)
		} else {
			defer persistent.Close()
		}
	}
	logs, err := logstore.New(cfg.AuditLog.Path, cfg.AuditLog.MaxEntries, cfg.AuditLog.Enabled, logstore.Options{LogRequestText: cfg.AuditLog.LogRequestText, LogHits: cfg.AuditLog.LogHits})
	if err != nil {
		log.Printf("audit log disabled: %v", err)
	}
	if persistent != nil && logs != nil {
		logs.SetBackend(persistent)
	}
	r := gin.Default()
	if cfg.SecurityHeaders.Enabled {
		r.Use(security.SecurityHeaders())
	}
	r.Use(security.CORS(cfg.CORS))
	r.Use(security.BodyLimit(cfg.Limits.MaxBodyBytes))
	r.Use(security.NewRateLimiter().Middleware(cfg.RateLimit, cfg.Server.TrustedProxies))
	r.Use(security.APIKeyMiddleware(cfg, security.New(cfg.Security.APIKeyEnabled, cfg.Security.APIKeys)))
	r.Use(security.AdminGuard(cfg))
	api.RegisterHealth(r)
	api.RegisterOps(r, cfg)
	var aiSvc *ai.Service
	if cfg.AI.Enabled {
		var aiLogger ai.AuditLogger
		if logger, ok := persistent.(ai.AuditLogger); ok {
			aiLogger = logger
		}
		aiSvc = ai.NewService(cfg.AI, aiLogger)
	}
	api.RegisterAuditWithAI(r, e, cfg.Limits, logs, aiSvc)
	api.RegisterBatchWithAI(r, e, cfg.Limits, aiSvc)
	hist := api.HistoryServices{TrustedProxies: cfg.Server.TrustedProxies, Storage: persistent}
	if cfg.RuleHistory.Enabled {
		hist.Changes = rulehistory.New(cfg.RuleHistory.Path, cfg.RuleHistory.MaxEntries)
		hist.Batches = rulehistory.NewBatchStore(cfg.RuleHistory.ImportBatchesPath)
		if persistent != nil {
			hist.Changes.SetBackend(persistent)
			hist.Batches.SetBackend(persistent)
		}
	}
	api.RegisterRules(r, e, hist)
	api.RegisterHistory(r, e, hist)
	api.RegisterImports(r, cfg, hist.Batches)
	api.RegisterLogs(r, logs)
	api.RegisterStorageExports(r, persistent)
	if cfg.Admin.Enabled {
		admin.RegisterAt(r, cfg.Admin.Path)
	}
	log.Printf("OpenAudit listening on %s", cfg.Server.Addr)
	s := &http.Server{Addr: cfg.Server.Addr, Handler: r, ReadTimeout: time.Duration(cfg.Server.ReadTimeoutSeconds) * time.Second, WriteTimeout: time.Duration(cfg.Server.WriteTimeoutSeconds) * time.Second}
	if err := s.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
