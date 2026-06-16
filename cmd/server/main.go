package main

import (
	"flag"
	"github.com/gin-gonic/gin"
	"github.com/openaudit/openaudit/internal/admin"
	"github.com/openaudit/openaudit/internal/api"
	"github.com/openaudit/openaudit/internal/config"
	"github.com/openaudit/openaudit/internal/engine"
	"github.com/openaudit/openaudit/internal/logstore"
	"github.com/openaudit/openaudit/internal/security"
	"log"
	"net/http"
	"time"
)

func main() {
	configPath := flag.String("config", "", "config file path")
	flag.Parse()
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
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
	checker := security.New(cfg.Security.APIKeyEnabled, cfg.Security.APIKeys)
	r.Use(func(c *gin.Context) bool {
		if security.IsProtected(c.Request.URL.Path, cfg.Security.ProtectedPaths) && !checker.Valid(c.Request) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing or invalid API key"})
			return false
		}
		return true
	})
	api.RegisterHealth(r)
	api.RegisterOps(r, cfg)
	api.RegisterAuditWithOptions(r, e, cfg.Limits, logs)
	api.RegisterBatchWithOptions(r, e, cfg.Limits)
	api.RegisterRules(r, e)
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
