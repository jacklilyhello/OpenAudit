package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/openaudit/openaudit/internal/admin"
	"github.com/openaudit/openaudit/internal/ai"
	"github.com/openaudit/openaudit/internal/api"
	"github.com/openaudit/openaudit/internal/bundled"
	"github.com/openaudit/openaudit/internal/config"
	"github.com/openaudit/openaudit/internal/engine"
	"github.com/openaudit/openaudit/internal/logstore"
	"github.com/openaudit/openaudit/internal/matcher"
	"github.com/openaudit/openaudit/internal/review"
	"github.com/openaudit/openaudit/internal/rulehistory"
	"github.com/openaudit/openaudit/internal/security"
	"github.com/openaudit/openaudit/internal/storage"
	storagesqlite "github.com/openaudit/openaudit/internal/storage/sqlite"
)

func main() {
	configPath := flag.String("config", "", "config file path")
	validateConfig := flag.Bool("validate-config", false, "validate configuration and bundled-rule runtime compatibility, then exit")
	printBundledSummary := flag.Bool("print-bundled-summary", false, "print safe bundled-rule runtime summary, then exit")
	flag.Parse()
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if cfg.UnsafeProduction && cfg.App.Env == "production" {
		log.Printf("WARNING: OPENAUDIT_ALLOW_UNSAFE_PRODUCTION=true disables production safety checks")
	}
	if *validateConfig || *printBundledSummary {
		if *printBundledSummary {
			_, stats, err := bundled.LoadRuntime(cfg.BundledRules)
			if err != nil {
				log.Fatalf("bundled rules: %v", err)
			}
			if err := json.NewEncoder(os.Stdout).Encode(stats); err != nil {
				log.Fatalf("print bundled summary: %v", err)
			}
		}
		if cfg.BundledRules.NetEase.RegexEngine == matcher.RegexEnginePCRE2 && !matcher.PCRE2Available() {
			log.Fatalf("bundled_rules.netease.regex_engine pcre2 requires a PCRE2-enabled binary built with CGO_ENABLED=1 -tags pcre2")
		}
		log.Printf("configuration valid; regex_engine=%s pcre2_available=%t", cfg.BundledRules.NetEase.RegexEngine, matcher.PCRE2Available())
		return
	}
	e, err := engine.NewWithOptions(cfg.Rules.DataDir, engine.Options{BundledRules: &cfg.BundledRules})
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
	var reviewSvc *review.Service
	if persistent != nil {
		if rec, ok, err := persistent.GetReviewPolicy(context.Background()); err == nil && ok {
			var stored config.ReviewPolicyConfig
			if err := json.Unmarshal([]byte(rec.PolicyJSON), &stored); err == nil {
				cfg.ReviewPolicy = stored
			}
		}
		reviewSvc = review.NewService(cfg.ReviewPolicy, persistent)
	}
	api.RegisterAuditWithReview(r, e, cfg.Limits, logs, aiSvc, reviewSvc)
	api.RegisterBatchWithReview(r, e, cfg.Limits, aiSvc, reviewSvc)
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
	api.RegisterReview(r, reviewSvc, persistent, hist)
	if cfg.Admin.Enabled {
		admin.RegisterAt(r, cfg.Admin.Path)
	}
	log.Printf("OpenAudit listening on %s", cfg.Server.Addr)
	s := &http.Server{Addr: cfg.Server.Addr, Handler: r, ReadTimeout: time.Duration(cfg.Server.ReadTimeoutSeconds) * time.Second, WriteTimeout: time.Duration(cfg.Server.WriteTimeoutSeconds) * time.Second}
	if err := s.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
