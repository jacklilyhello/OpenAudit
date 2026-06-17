package api

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/openaudit/openaudit/internal/config"
	"github.com/openaudit/openaudit/internal/review"
	"github.com/openaudit/openaudit/internal/storage"
)

const maxBulkReviewCases = 100

func RegisterReview(r gin.IRouter, svc *review.Service, st storage.Store, h HistoryServices) {
	if svc == nil || st == nil {
		return
	}
	r.GET("/review/cases", func(c *gin.Context) {
		f, ok := reviewFilterFrom(c)
		if !ok {
			return
		}
		pg, err := st.QueryReviewCases(c.Request.Context(), f)
		if err != nil {
			writeError(c, http.StatusInternalServerError, "review_query_error", err.Error(), nil)
			return
		}
		c.JSON(http.StatusOK, gin.H{"items": pg.Items, "count": pg.Page.Total, "limit": pg.Page.Limit, "offset": pg.Page.Offset, "has_more": pg.Page.HasMore})
	})
	r.GET("/review/cases/*case_path", func(c *gin.Context) { dispatchReviewCase(c, st, h) })
	r.POST("/review/cases/*case_path", func(c *gin.Context) { dispatchReviewCase(c, st, h) })
	r.GET("/review/stats", func(c *gin.Context) {
		stats, err := st.ReviewStats(c.Request.Context())
		if err != nil {
			writeError(c, http.StatusInternalServerError, "review_stats_error", err.Error(), nil)
			return
		}
		c.JSON(http.StatusOK, stats)
	})
	r.GET("/review/policy", func(c *gin.Context) {
		policy := svc.Policy()
		if rec, ok, err := st.GetReviewPolicy(c.Request.Context()); err == nil && ok {
			_ = json.Unmarshal([]byte(rec.PolicyJSON), &policy)
			c.JSON(http.StatusOK, gin.H{"policy": policy, "version": rec.Version, "updated_at": rec.UpdatedAt, "actor": rec.Actor})
			return
		}
		c.JSON(http.StatusOK, gin.H{"policy": policy, "version": review.PolicyHash(policy)})
	})
	r.PUT("/review/policy", func(c *gin.Context) {
		var req config.ReviewPolicyConfig
		if err := c.ShouldBindJSON(&req); err != nil {
			bad(c, err.Error())
			return
		}
		if err := config.ValidateReviewPolicy(req); err != nil {
			writeError(c, http.StatusBadRequest, "invalid_policy", err.Error(), nil)
			return
		}
		svc.SetPolicy(req)
		b, _ := json.Marshal(req)
		version := review.PolicyHash(req)
		if err := st.UpsertReviewPolicy(c.Request.Context(), storage.ReviewPolicyRecord{PolicyJSON: string(b), Version: version, Actor: actorFrom(c)}); err != nil {
			writeError(c, http.StatusInternalServerError, "policy_update_failed", err.Error(), nil)
			return
		}
		logAdminOperation(c, h, "review_policy_update", "review_policy", version, "success", http.StatusOK)
		c.JSON(http.StatusOK, gin.H{"ok": true, "policy": req, "version": version})
	})
	r.GET("/review/export", func(c *gin.Context) { exportReviewCases(c, st, svc.Policy().MaxExportRows) })
}

func decideReviewCase(c *gin.Context, st storage.Store, h HistoryServices, caseID, forcedAction string) {
	var req struct {
		Action string `json:"action"`
		Note   string `json:"note"`
	}
	_ = c.ShouldBindJSON(&req)
	if forcedAction != "" {
		req.Action = forcedAction
	}
	if !allowedReviewAction(req.Action, false) {
		writeError(c, http.StatusBadRequest, "invalid_action", "unsupported review action", nil)
		return
	}
	item, err := st.DecideReviewCase(c.Request.Context(), caseID, req.Action, actorFrom(c), cappedNote(req.Note), "{}")
	if err != nil {
		writeError(c, http.StatusBadRequest, "review_decision_failed", err.Error(), nil)
		return
	}
	logAdminOperation(c, h, "review_"+req.Action, "review_case", caseID, "success", http.StatusOK)
	c.JSON(http.StatusOK, gin.H{"ok": true, "case": item})
}

func dispatchReviewCase(c *gin.Context, st storage.Store, h HistoryServices) {
	parts := strings.Split(strings.Trim(c.Param("case_path"), "/"), "/")
	if len(parts) == 2 && parts[0] == "bulk" && parts[1] == "decide" && c.Request.Method == http.MethodPost {
		bulkDecideReviewCases(c, st, h)
		return
	}
	if len(parts) == 1 && c.Request.Method == http.MethodGet {
		item, events, ok, err := st.GetReviewCase(c.Request.Context(), parts[0])
		if err != nil {
			writeError(c, http.StatusInternalServerError, "review_query_error", err.Error(), nil)
			return
		}
		if !ok {
			writeError(c, http.StatusNotFound, "not_found", "review case not found", nil)
			return
		}
		c.JSON(http.StatusOK, gin.H{"case": item, "events": events})
		return
	}
	if len(parts) == 2 && c.Request.Method == http.MethodPost {
		switch parts[1] {
		case "decide":
			decideReviewCase(c, st, h, parts[0], "")
		case "note":
			decideReviewCase(c, st, h, parts[0], "add_note")
		case "reopen":
			decideReviewCase(c, st, h, parts[0], "reopen")
		case "escalate":
			decideReviewCase(c, st, h, parts[0], "escalate")
		default:
			writeError(c, http.StatusNotFound, "not_found", "unknown review case action", nil)
		}
		return
	}
	writeError(c, http.StatusNotFound, "not_found", "unknown review case route", nil)
}

func bulkDecideReviewCases(c *gin.Context, st storage.Store, h HistoryServices) {
	var req struct {
		CaseIDs []string `json:"case_ids"`
		Action  string   `json:"action"`
		Note    string   `json:"note"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err.Error())
		return
	}
	if len(req.CaseIDs) == 0 || len(req.CaseIDs) > maxBulkReviewCases {
		writeError(c, http.StatusBadRequest, "invalid_request", "case_ids must contain 1 to 100 cases", nil)
		return
	}
	if !allowedReviewAction(req.Action, true) {
		writeError(c, http.StatusBadRequest, "invalid_action", "unsupported bulk review action", nil)
		return
	}
	items, err := st.BulkDecideReviewCases(c.Request.Context(), req.CaseIDs, req.Action, actorFrom(c), cappedNote(req.Note))
	if err != nil {
		writeError(c, http.StatusBadRequest, "bulk_review_failed", err.Error(), nil)
		return
	}
	logAdminOperation(c, h, "review_bulk_"+req.Action, "review_case", strconv.Itoa(len(req.CaseIDs)), "success", http.StatusOK)
	c.JSON(http.StatusOK, gin.H{"ok": true, "count": len(items), "items": items})
}

func allowedReviewAction(action string, bulk bool) bool {
	switch action {
	case "approve", "reject", "ignore", "escalate":
		return true
	case "reopen", "add_note":
		return !bulk
	default:
		return false
	}
}

func reviewFilterFrom(c *gin.Context) (storage.ReviewFilter, bool) {
	q := c.Request.URL.Query()
	f := storage.ReviewFilter{Limit: atoi(q.Get("limit"), 50), Offset: atoi(q.Get("offset"), 0), Sort: q.Get("sort"), Direction: q.Get("direction")}
	for _, pair := range []struct {
		name string
		dst  *string
		oks  []string
	}{
		{"status", &f.Status, []string{"pending", "reviewing", "approved", "rejected", "ignored", "escalated", "expired"}},
		{"priority", &f.Priority, []string{"low", "medium", "high", "critical"}},
		{"temporary_action", &f.TemporaryAction, []string{"temporary_allow", "temporary_block", "review_only", "log_only", "none"}},
		{"ai_risk_level", &f.AIRiskLevel, []string{"low", "medium", "high", "critical"}},
		{"variant_risk_level", &f.VariantRiskLevel, []string{"low", "medium", "high", "critical"}},
	} {
		v := q.Get(pair.name)
		if v == "" {
			continue
		}
		if !hasString(pair.oks, v) {
			writeError(c, http.StatusBadRequest, "invalid_filter", "invalid "+pair.name, nil)
			return f, false
		}
		*pair.dst = v
	}
	f.Category = cappedQuery(q.Get("category"))
	f.Source = cappedQuery(q.Get("source"))
	if q.Get("sort") != "" && !hasString([]string{"created_at", "updated_at", "priority", "ai_score", "variant_score", "status"}, q.Get("sort")) {
		writeError(c, http.StatusBadRequest, "invalid_sort", "unsupported sort field", nil)
		return f, false
	}
	if q.Get("min_score") != "" {
		v, err := strconv.ParseFloat(q.Get("min_score"), 64)
		if err != nil || v < 0 || v > 1 {
			writeError(c, http.StatusBadRequest, "invalid_filter", "min_score must be between 0 and 1", nil)
			return f, false
		}
		f.MinScore, f.HasMinScore = v, true
	}
	if q.Get("max_score") != "" {
		v, err := strconv.ParseFloat(q.Get("max_score"), 64)
		if err != nil || v < 0 || v > 1 {
			writeError(c, http.StatusBadRequest, "invalid_filter", "max_score must be between 0 and 1", nil)
			return f, false
		}
		f.MaxScore, f.HasMaxScore = v, true
	}
	var ok bool
	if f.CreatedFrom, ok = parseReviewTime(c, "created_from"); !ok {
		return f, false
	}
	if f.CreatedTo, ok = parseReviewTime(c, "created_to"); !ok {
		return f, false
	}
	return f, true
}

func parseReviewTime(c *gin.Context, key string) (time.Time, bool) {
	v := c.Request.URL.Query().Get(key)
	if v == "" {
		return time.Time{}, true
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		writeError(c, http.StatusBadRequest, "invalid_filter", key+" must be RFC3339", nil)
		return time.Time{}, false
	}
	return t, true
}

func exportReviewCases(c *gin.Context, st storage.Store, maxRows int) {
	format := c.Request.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}
	if format != "json" && format != "csv" {
		writeError(c, http.StatusBadRequest, "invalid_format", "format must be json or csv", nil)
		return
	}
	limit := storage.NormalizeExportLimit(atoi(c.Request.URL.Query().Get("limit"), maxRows))
	if maxRows > 0 && limit > maxRows {
		limit = maxRows
	}
	f, ok := reviewFilterFrom(c)
	if !ok {
		return
	}
	f.Limit = limit
	pg, err := st.QueryReviewCases(c.Request.Context(), f)
	if err != nil {
		writeError(c, http.StatusInternalServerError, "review_export_error", err.Error(), nil)
		return
	}
	c.ResponseWriter.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=openaudit-review-cases-%s.%s", time.Now().UTC().Format("20060102T150405Z"), format))
	if format == "csv" {
		c.ResponseWriter.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w := csv.NewWriter(c.ResponseWriter)
		_ = w.Write([]string{"case_id", "status", "priority", "temporary_action", "ai_score", "variant_score", "category", "source", "created_at"})
		for _, item := range pg.Items {
			_ = w.Write([]string{item.CaseID, item.Status, item.Priority, item.TemporaryAction, fmt.Sprint(item.AIScore), fmt.Sprint(item.VariantScore), item.Category, item.Source, item.CreatedAt.Format(time.RFC3339)})
		}
		w.Flush()
		return
	}
	c.ResponseWriter.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(c.ResponseWriter).Encode(pg.Items)
}

func hasString(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func cappedQuery(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > 100 {
		return v[:100]
	}
	return v
}

func cappedNote(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > 2000 {
		return v[:2000]
	}
	return v
}
