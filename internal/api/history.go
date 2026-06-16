package api

import (
	"github.com/gin-gonic/gin"
	"github.com/openaudit/openaudit/internal/engine"
	"github.com/openaudit/openaudit/internal/rulehistory"
	"github.com/openaudit/openaudit/internal/rules"
	"github.com/openaudit/openaudit/internal/security"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"strings"
)

type HistoryServices struct {
	Changes        *rulehistory.Store
	Batches        *rulehistory.BatchStore
	TrustedProxies []string
}

func RegisterHistory(r gin.IRouter, e *engine.Engine, h HistoryServices) {
	if h.Changes == nil {
		return
	}
	r.GET("/rules/history", func(c *gin.Context) { listHistory(c, h.Changes) })
	r.GET("/rules/history/:change_id", func(c *gin.Context) { getHistory(c, h.Changes, c.Param("change_id")) })
	r.GET("/rules/:id/history", func(c *gin.Context) {
		items, count, err := h.Changes.List(rulehistory.Filter{RuleID: c.Param("id"), Limit: atoi(c.Request.URL.Query().Get("limit"), 50), Offset: atoi(c.Request.URL.Query().Get("offset"), 0)})
		if err != nil {
			writeError(c, 500, "history_error", err.Error(), nil)
			return
		}
		c.JSON(200, gin.H{"items": items, "count": count, "limit": atoi(c.Request.URL.Query().Get("limit"), 50), "offset": atoi(c.Request.URL.Query().Get("offset"), 0)})
	})
	r.GET("/rules/:id/diff", func(c *gin.Context) { ruleDiff(c, h.Changes, c.Param("id")) })
	r.POST("/rules/rollback/:id", func(c *gin.Context) { rollbackRule(c, e, h, c.Param("id")) })
	r.GET("/rules/changes/stats", func(c *gin.Context) {
		st, err := h.Changes.Stats()
		if err != nil {
			writeError(c, 500, "history_error", err.Error(), nil)
			return
		}
		c.JSON(200, st)
	})
	if h.Batches != nil {
		r.GET("/imports/batches", func(c *gin.Context) {
			xs, count, err := h.Batches.List(rulehistory.BatchFilter{Source: c.Request.URL.Query().Get("source"), Status: c.Request.URL.Query().Get("status"), Limit: atoi(c.Request.URL.Query().Get("limit"), 50), Offset: atoi(c.Request.URL.Query().Get("offset"), 0)})
			if err != nil {
				writeError(c, 500, "batch_error", err.Error(), nil)
				return
			}
			c.JSON(200, gin.H{"items": xs, "count": count, "limit": atoi(c.Request.URL.Query().Get("limit"), 50), "offset": atoi(c.Request.URL.Query().Get("offset"), 0)})
		})
		r.GET("/imports/batches/:batch_id", func(c *gin.Context) {
			x, ok, err := h.Batches.Get(c.Param("batch_id"))
			if err != nil {
				writeError(c, 500, "batch_error", err.Error(), nil)
				return
			}
			if !ok {
				writeError(c, 404, "not_found", "batch not found", nil)
				return
			}
			c.JSON(200, x)
		})
	}
}
func listHistory(c *gin.Context, s *rulehistory.Store) {
	items, count, err := s.List(rulehistory.Filter{RuleID: c.Request.URL.Query().Get("rule_id"), Action: c.Request.URL.Query().Get("action"), Actor: c.Request.URL.Query().Get("actor"), Source: c.Request.URL.Query().Get("source"), ImportBatchID: c.Request.URL.Query().Get("import_batch_id"), Limit: atoi(c.Request.URL.Query().Get("limit"), 50), Offset: atoi(c.Request.URL.Query().Get("offset"), 0)})
	if err != nil {
		writeError(c, 500, "history_error", err.Error(), nil)
		return
	}
	c.JSON(200, gin.H{"items": items, "count": count, "limit": atoi(c.Request.URL.Query().Get("limit"), 50), "offset": atoi(c.Request.URL.Query().Get("offset"), 0)})
}
func getHistory(c *gin.Context, s *rulehistory.Store, id string) {
	x, ok, err := s.Get(id)
	if err != nil {
		writeError(c, 500, "history_error", err.Error(), nil)
		return
	}
	if !ok {
		writeError(c, 404, "not_found", "history entry not found", nil)
		return
	}
	c.JSON(200, x)
}
func ruleDiff(c *gin.Context, s *rulehistory.Store, id string) {
	if a, b := c.Request.URL.Query().Get("from_change_id"), c.Request.URL.Query().Get("to_change_id"); a != "" && b != "" {
		ca, oka, _ := s.Get(a)
		cb, okb, _ := s.Get(b)
		if !oka || !okb {
			writeError(c, 404, "not_found", "history entry not found", nil)
			return
		}
		c.JSON(200, rulehistory.TextDiff(ca.After, cb.After))
		return
	}
	items, _, err := s.List(rulehistory.Filter{RuleID: id, Limit: 1})
	if err != nil || len(items) == 0 {
		writeError(c, 404, "not_found", "diff not found", nil)
		return
	}
	c.JSON(200, items[0].Diff)
}
func rollbackRule(c *gin.Context, e *engine.Engine, h HistoryServices, id string) {
	p, err := customPath(e.Root(), id)
	if err != nil || !strings.HasPrefix(filepath.Clean(p), filepath.Clean(filepath.Join(e.Root(), "custom"))+string(os.PathSeparator)) {
		writeError(c, 400, "unsupported", "rollback is only supported for API-managed custom rules in Phase 7", nil)
		return
	}
	var req struct {
		ChangeID string `json:"change_id"`
		Note     string `json:"note"`
	}
	_ = c.ShouldBindJSON(&req)
	ch, ok, err := h.Changes.Get(req.ChangeID)
	if err != nil {
		writeError(c, 500, "history_error", err.Error(), nil)
		return
	}
	if !ok || ch.RuleID != id {
		writeError(c, 404, "not_found", "history entry not found", nil)
		return
	}
	cur, _ := os.ReadFile(p)
	target := []byte(ch.Before)
	if ch.Before == "" && ch.Action == rulehistory.ActionCreate {
		target = nil
	}
	if len(target) == 0 {
		_ = os.Remove(p)
	} else {
		_ = os.MkdirAll(filepath.Dir(p), 0755)
		if err := os.WriteFile(p, target, 0644); err != nil {
			writeError(c, 500, "rollback_failed", err.Error(), nil)
			return
		}
	}
	if err := e.Reload(); err != nil {
		if len(cur) == 0 {
			_ = os.Remove(p)
		} else {
			_ = os.WriteFile(p, cur, 0644)
		}
		_ = e.Reload()
		writeError(c, 400, "reload_failed", err.Error(), nil)
		return
	}
	after, _ := os.ReadFile(p)
	entry := baseChange(c, h, id, rulehistory.ActionRollback, string(cur), string(after), p)
	entry.Note = req.Note
	entry.ReloadSuccess = true
	_ = h.Changes.Append(entry)
	var r rules.Rule
	_ = yaml.Unmarshal(after, &r)
	c.JSON(200, gin.H{"ok": true, "rule": r, "reload_success": true})
}
func baseChange(c *gin.Context, h HistoryServices, id string, act rulehistory.Action, before, after, path string) rulehistory.Change {
	actor := c.Request.Header.Get("Cf-Access-Authenticated-User-Email")
	if actor == "" {
		actor = "api"
	}
	return rulehistory.Change{Actor: actor, Action: act, RuleID: id, Before: before, After: after, Diff: rulehistory.TextDiff(before, after), FilePath: path, ReloadSuccess: true, RemoteAddr: security.ClientIP(c.Request, h.TrustedProxies), UserAgent: c.Request.UserAgent()}
}
