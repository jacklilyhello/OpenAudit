package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/openaudit/openaudit/internal/admin"
	"github.com/openaudit/openaudit/internal/api"
	"github.com/openaudit/openaudit/internal/config"
	"github.com/openaudit/openaudit/internal/engine"
	"github.com/openaudit/openaudit/internal/logstore"
	"github.com/openaudit/openaudit/internal/rulehistory"
	"github.com/openaudit/openaudit/internal/security"
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
	logs, err := logstore.New(cfg.AuditLog.Path, cfg.AuditLog.MaxEntries, cfg.AuditLog.Enabled, logstore.Options{LogRequestText: cfg.AuditLog.LogRequestText, LogHits: cfg.AuditLog.LogHits})
	if err != nil {
		log.Printf("audit log disabled: %v", err)
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
	api.RegisterAuditWithOptions(r, e, cfg.Limits, logs)
	api.RegisterBatchWithOptions(r, e, cfg.Limits)
	hist := api.HistoryServices{TrustedProxies: cfg.Server.TrustedProxies}
	if cfg.RuleHistory.Enabled {
		hist.Changes = rulehistory.New(cfg.RuleHistory.Path, cfg.RuleHistory.MaxEntries)
		hist.Batches = rulehistory.NewBatchStore(cfg.RuleHistory.ImportBatchesPath)
	}
	api.RegisterRules(r, e, hist)
	api.RegisterHistory(r, e, hist)
	api.RegisterImports(r, cfg, hist.Batches)
	api.RegisterLogs(r, logs)
	if cfg.Admin.Enabled {
		admin.RegisterAt(r, cfg.Admin.Path)
	}
	log.Printf("OpenAudit listening on %s", cfg.Server.Addr)
	s := &http.Server{Addr: cfg.Server.Addr, Handler: r, ReadTimeout: time.Duration(cfg.Server.ReadTimeoutSeconds) * time.Second, WriteTimeout: time.Duration(cfg.Server.WriteTimeoutSeconds) * time.Second}
	if err := s.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
