package api

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/openaudit/openaudit/internal/ai"
	"github.com/openaudit/openaudit/internal/logstore"
	"github.com/openaudit/openaudit/internal/storage"
	"strconv"
	"strings"
	"time"
)

func RegisterLogs(r gin.IRouter, s *logstore.Store) {
	r.GET("/logs/recent", func(c *gin.Context) {
		q := c.Request.URL.Query()
		lim := atoi(q.Get("limit"), 50)
		items := []logstore.Entry{}
		for _, e := range s.Recent() {
			if q.Get("action") != "" && e.Action != q.Get("action") {
				continue
			}
			if q.Get("matched") != "" && strconv.FormatBool(e.Matched) != q.Get("matched") {
				continue
			}
			if cat := q.Get("category"); cat != "" && !entryHasCat(e, cat) {
				continue
			}
			if text := strings.ToLower(q.Get("q")); text != "" && !strings.Contains(strings.ToLower(e.Text+" "+e.TextSHA256), text) {
				continue
			}
			items = append(items, e)
			if len(items) >= lim {
				break
			}
		}
		c.JSON(200, gin.H{"items": items, "count": len(items)})
	})
	r.GET("/logs/stats", func(c *gin.Context) { c.JSON(200, logstore.ComputeStats(s.Recent())) })
}
func entryHasCat(e logstore.Entry, cat string) bool {
	for _, h := range e.Hits {
		if h.Category == cat {
			return true
		}
	}
	return false
}

func RegisterStorageExports(r gin.IRouter, st storage.Store) {
	if st == nil {
		return
	}
	if aiLogs, ok := st.(interface {
		QueryAIReviewLogs(context.Context, int, int) ([]ai.AuditLog, storage.Page, error)
	}); ok {
		r.GET("/storage/ai_audit_logs", func(c *gin.Context) {
			pg, page, err := aiLogs.QueryAIReviewLogs(c.Request.Context(), atoi(c.Request.URL.Query().Get("limit"), 50), atoi(c.Request.URL.Query().Get("offset"), 0))
			if err != nil {
				writeError(c, 500, "storage_error", err.Error(), nil)
				return
			}
			c.JSON(200, gin.H{"items": pg, "count": page.Total, "limit": page.Limit, "offset": page.Offset, "has_more": page.HasMore})
		})
	}
	r.GET("/storage/audit_logs", func(c *gin.Context) {
		lim, off := atoi(c.Request.URL.Query().Get("limit"), 50), atoi(c.Request.URL.Query().Get("offset"), 0)
		var mp *bool
		if c.Request.URL.Query().Get("matched") != "" {
			v := c.Request.URL.Query().Get("matched") == "true"
			mp = &v
		}
		pg, err := st.QueryAuditLogs(c.Request.Context(), storage.AuditFilter{Action: c.Request.URL.Query().Get("action"), Category: c.Request.URL.Query().Get("category"), Query: c.Request.URL.Query().Get("q"), Matched: mp, Limit: lim, Offset: off})
		if err != nil {
			writeError(c, 500, "storage_error", err.Error(), nil)
			return
		}
		c.JSON(200, gin.H{"items": pg.Items, "count": pg.Page.Total, "limit": pg.Page.Limit, "offset": pg.Page.Offset, "has_more": pg.Page.HasMore})
	})
	r.GET("/storage/rule_changes", func(c *gin.Context) {
		pg, err := st.QueryRuleChanges(c.Request.Context(), storage.ChangeFilter{RuleID: c.Request.URL.Query().Get("rule_id"), Operation: c.Request.URL.Query().Get("operation"), Actor: c.Request.URL.Query().Get("actor"), Source: c.Request.URL.Query().Get("source"), Limit: atoi(c.Request.URL.Query().Get("limit"), 50), Offset: atoi(c.Request.URL.Query().Get("offset"), 0)})
		if err != nil {
			writeError(c, 500, "storage_error", err.Error(), nil)
			return
		}
		c.JSON(200, gin.H{"items": pg.Items, "count": pg.Page.Total, "limit": pg.Page.Limit, "offset": pg.Page.Offset, "has_more": pg.Page.HasMore})
	})
	r.GET("/storage/import_batches", func(c *gin.Context) {
		pg, err := st.QueryImportBatches(c.Request.Context(), storage.BatchFilter{Source: c.Request.URL.Query().Get("source"), Status: c.Request.URL.Query().Get("status"), Limit: atoi(c.Request.URL.Query().Get("limit"), 50), Offset: atoi(c.Request.URL.Query().Get("offset"), 0)})
		if err != nil {
			writeError(c, 500, "storage_error", err.Error(), nil)
			return
		}
		c.JSON(200, gin.H{"items": pg.Items, "count": pg.Page.Total, "limit": pg.Page.Limit, "offset": pg.Page.Offset, "has_more": pg.Page.HasMore})
	})
	r.GET("/storage/admin_operations", func(c *gin.Context) {
		pg, err := st.QueryAdminOperations(c.Request.Context(), storage.AdminFilter{Operation: c.Request.URL.Query().Get("operation"), Actor: c.Request.URL.Query().Get("actor"), ResourceType: c.Request.URL.Query().Get("resource_type"), ResourceID: c.Request.URL.Query().Get("resource_id"), Limit: atoi(c.Request.URL.Query().Get("limit"), 50), Offset: atoi(c.Request.URL.Query().Get("offset"), 0)})
		if err != nil {
			writeError(c, 500, "storage_error", err.Error(), nil)
			return
		}
		c.JSON(200, gin.H{"items": pg.Items, "count": pg.Page.Total, "limit": pg.Page.Limit, "offset": pg.Page.Offset, "has_more": pg.Page.HasMore})
	})
	r.GET("/storage/export/:target", func(c *gin.Context) { exportStorage(c, st, c.Param("target")) })
}

func exportStorage(c *gin.Context, st storage.Store, target string) {
	format := c.Request.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}
	limit := storage.NormalizeExportLimit(atoi(c.Request.URL.Query().Get("limit"), storage.ExportMax))
	c.ResponseWriter.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=openaudit-%s-%s.%s", target, time.Now().UTC().Format("20060102T150405Z"), format))
	var rows any
	var err error
	switch target {
	case "audit_logs":
		var pg storage.AuditPage
		pg, err = st.QueryAuditLogs(c.Request.Context(), storage.AuditFilter{Limit: limit})
		rows = pg.Items
	case "rule_changes":
		var pg storage.ChangePage
		pg, err = st.QueryRuleChanges(c.Request.Context(), storage.ChangeFilter{Limit: limit})
		rows = pg.Items
	case "import_batches":
		var pg storage.BatchPage
		pg, err = st.QueryImportBatches(c.Request.Context(), storage.BatchFilter{Limit: limit})
		rows = pg.Items
	case "admin_operations":
		var pg storage.AdminPage
		pg, err = st.QueryAdminOperations(c.Request.Context(), storage.AdminFilter{Limit: limit})
		rows = pg.Items
	default:
		writeError(c, 404, "not_found", "unknown export target", nil)
		return
	}
	if err != nil {
		writeError(c, 500, "storage_error", err.Error(), nil)
		return
	}
	if format == "csv" {
		c.ResponseWriter.Header().Set("Content-Type", "text/csv; charset=utf-8")
		writeCSV(c, rows)
		return
	}
	c.ResponseWriter.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(c.ResponseWriter).Encode(rows)
}
func writeCSV(c *gin.Context, rows any) {
	w := csv.NewWriter(c.ResponseWriter)
	b, _ := json.Marshal(rows)
	var xs []map[string]any
	_ = json.Unmarshal(b, &xs)
	if len(xs) == 0 {
		_ = w.Write([]string{"empty"})
		w.Flush()
		return
	}
	keys := make([]string, 0, len(xs[0]))
	for k := range xs[0] {
		keys = append(keys, k)
	}
	_ = w.Write(keys)
	for _, m := range xs {
		rec := make([]string, len(keys))
		for i, k := range keys {
			rec[i] = fmt.Sprint(m[k])
		}
		_ = w.Write(rec)
	}
	w.Flush()
}
