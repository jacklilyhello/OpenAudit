package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/openaudit/openaudit/internal/engine"
	"github.com/openaudit/openaudit/internal/rulehistory"
	"github.com/openaudit/openaudit/internal/rulerelease"
	"github.com/openaudit/openaudit/internal/rules"
)

const maxSimulationRunes = 10000

func registerRuleReleaseRoutes(r gin.IRouter, e *engine.Engine, h HistoryServices, mgr *rulerelease.Manager) {
	r.GET("/rules/drafts", func(c *gin.Context) { listLifecycleRules(c, mgr, rulerelease.StateDraft) })
	r.POST("/rules/drafts", func(c *gin.Context) { upsertDraftRule(c, h, mgr) })
	r.PUT("/rules/drafts/:id", func(c *gin.Context) { updateDraftRule(c, h, mgr, c.Param("id")) })
	r.DELETE("/rules/drafts/:id", func(c *gin.Context) { deleteLifecycleRule(c, h, mgr, rulerelease.StateDraft, c.Param("id")) })
	r.POST("/rules/drafts/:id/stage", func(c *gin.Context) { stageDraftRule(c, h, mgr, c.Param("id")) })
	r.GET("/rules/staged", func(c *gin.Context) { listLifecycleRules(c, mgr, rulerelease.StateStaged) })
	r.POST("/rules/staged/:id/publish", func(c *gin.Context) { publishRules(c, e, h, mgr) })
	r.POST("/rules/publish", func(c *gin.Context) { publishRules(c, e, h, mgr) })
	r.GET("/rules/releases", func(c *gin.Context) { listReleases(c, mgr) })
	r.GET("/rules/releases/:version", func(c *gin.Context) { getRelease(c, mgr, c.Param("version")) })
	r.POST("/rules/releases/:version/rollback", func(c *gin.Context) { rollbackRelease(c, e, h, mgr, c.Param("version")) })
	r.GET("/rules/releases/:from/:to/diff", func(c *gin.Context) { diffReleases(c, mgr, c.Param("from"), c.Param("to")) })
	r.POST("/rules/bulk/enable", func(c *gin.Context) { bulkSetEnabled(c, e, h, mgr, true) })
	r.POST("/rules/bulk/disable", func(c *gin.Context) { bulkSetEnabled(c, e, h, mgr, false) })
	r.POST("/rules/conflicts", func(c *gin.Context) { detectRuleConflicts(c, mgr) })
	r.POST("/rules/simulate", func(c *gin.Context) { simulateRules(c, mgr) })
	r.POST("/rules/prepublish-test", func(c *gin.Context) { prepublishTest(c, h, mgr) })
}

func actorFrom(c *gin.Context) string {
	actor := c.Request.Header.Get("Cf-Access-Authenticated-User-Email")
	if actor == "" {
		actor = "api"
	}
	return actor
}

func listLifecycleRules(c *gin.Context, mgr *rulerelease.Manager, state string) {
	rs, err := mgr.ListState(state)
	if err != nil {
		writeError(c, http.StatusInternalServerError, "rule_lifecycle_error", err.Error(), nil)
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": rs, "count": len(rs), "state": state})
}

func upsertDraftRule(c *gin.Context, h HistoryServices, mgr *rulerelease.Manager) {
	var req createReq
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err.Error())
		return
	}
	r, err := mgr.UpsertDraft(c.Request.Context(), req.Rule, actorFrom(c))
	if err != nil {
		writeError(c, http.StatusBadRequest, "invalid_rule", err.Error(), nil)
		return
	}
	if h.Changes != nil {
		b, _ := json.Marshal(r)
		entry := baseChange(c, h, r.ID, rulehistory.ActionUpdate, "", string(b), "draft")
		entry.Note = "draft upsert"
		_ = h.Changes.Append(entry)
	}
	logAdminOperation(c, h, "draft_upsert", "rule", r.ID, "success", http.StatusOK)
	c.JSON(http.StatusOK, gin.H{"ok": true, "rule": r})
}

func updateDraftRule(c *gin.Context, h HistoryServices, mgr *rulerelease.Manager, id string) {
	var req createReq
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err.Error())
		return
	}
	req.Rule.ID = id
	r, err := mgr.UpsertDraft(c.Request.Context(), req.Rule, actorFrom(c))
	if err != nil {
		writeError(c, http.StatusBadRequest, "invalid_rule", err.Error(), nil)
		return
	}
	logAdminOperation(c, h, "draft_update", "rule", r.ID, "success", http.StatusOK)
	c.JSON(http.StatusOK, gin.H{"ok": true, "rule": r})
}

func deleteLifecycleRule(c *gin.Context, h HistoryServices, mgr *rulerelease.Manager, state, id string) {
	if err := mgr.DeleteState(c.Request.Context(), state, id, actorFrom(c)); err != nil {
		writeError(c, http.StatusBadRequest, "delete_failed", err.Error(), nil)
		return
	}
	logAdminOperation(c, h, state+"_delete", "rule", id, "success", http.StatusOK)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func stageDraftRule(c *gin.Context, h HistoryServices, mgr *rulerelease.Manager, id string) {
	r, err := mgr.StageDraft(c.Request.Context(), id, actorFrom(c))
	if err != nil {
		writeError(c, http.StatusBadRequest, "stage_failed", err.Error(), nil)
		return
	}
	if h.Changes != nil {
		b, _ := json.Marshal(r)
		entry := baseChange(c, h, id, rulehistory.ActionUpdate, "", string(b), "staged")
		entry.Note = "draft staged"
		_ = h.Changes.Append(entry)
	}
	logAdminOperation(c, h, "stage", "rule", id, "success", http.StatusOK)
	c.JSON(http.StatusOK, gin.H{"ok": true, "rule": r})
}

func publishRules(c *gin.Context, e *engine.Engine, h HistoryServices, mgr *rulerelease.Manager) {
	var req struct {
		SampleText string `json:"sample_text"`
	}
	_ = c.ShouldBindJSON(&req)
	res, err := mgr.Publish(c.Request.Context(), actorFrom(c), req.SampleText, e.Reload)
	if err != nil {
		writeError(c, http.StatusBadRequest, "publish_failed", err.Error(), nil)
		return
	}
	if !res.Result.OK {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "validation": res.Result})
		return
	}
	for _, item := range res.Items {
		if h.Changes != nil {
			entry := baseChange(c, h, item.RuleID, rulehistory.ActionUpdate, item.BeforeHash, item.AfterHash, item.FilePath)
			entry.Note = "ruleset publish " + res.Release.Version
			_ = h.Changes.Append(entry)
		}
	}
	logAdminOperation(c, h, "publish", "ruleset", res.Release.Version, "success", http.StatusOK)
	c.JSON(http.StatusOK, gin.H{"ok": true, "release": res.Release, "items": res.Items, "validation": res.Result, "stats": e.Stats()})
}

func listReleases(c *gin.Context, mgr *rulerelease.Manager) {
	limit := atoi(c.Request.URL.Query().Get("limit"), 50)
	offset := atoi(c.Request.URL.Query().Get("offset"), 0)
	pg, err := mgr.ListReleases(c.Request.Context(), limit, offset)
	if err != nil {
		writeError(c, http.StatusInternalServerError, "release_error", err.Error(), nil)
		return
	}
	c.JSON(http.StatusOK, pg)
}

func getRelease(c *gin.Context, mgr *rulerelease.Manager, version string) {
	rel, items, ok, err := mgr.GetRelease(c.Request.Context(), version)
	if err != nil {
		writeError(c, http.StatusBadRequest, "release_error", err.Error(), nil)
		return
	}
	if !ok {
		writeError(c, http.StatusNotFound, "not_found", "release not found", nil)
		return
	}
	c.JSON(http.StatusOK, gin.H{"release": rel, "items": items})
}

func rollbackRelease(c *gin.Context, e *engine.Engine, h HistoryServices, mgr *rulerelease.Manager, version string) {
	res, err := mgr.RollbackRelease(c.Request.Context(), version, actorFrom(c), e.Reload)
	if err != nil {
		writeError(c, http.StatusBadRequest, "rollback_failed", err.Error(), nil)
		return
	}
	if h.Changes != nil {
		for _, item := range res.Items {
			if item.Operation == "unchanged" {
				continue
			}
			entry := baseChange(c, h, item.RuleID, rulehistory.ActionRollback, item.BeforeHash, item.AfterHash, item.FilePath)
			entry.Note = "ruleset rollback to " + version
			_ = h.Changes.Append(entry)
		}
	}
	logAdminOperation(c, h, "rollback", "ruleset", version, "success", http.StatusOK)
	c.JSON(http.StatusOK, gin.H{"ok": true, "release": res.Release, "items": res.Items, "validation": res.Result, "stats": e.Stats()})
}

func diffReleases(c *gin.Context, mgr *rulerelease.Manager, from, to string) {
	_, fromItems, ok, err := mgr.GetRelease(c.Request.Context(), from)
	if err != nil || !ok {
		writeError(c, http.StatusNotFound, "not_found", "from release not found", nil)
		return
	}
	_, toItems, ok, err := mgr.GetRelease(c.Request.Context(), to)
	if err != nil || !ok {
		writeError(c, http.StatusNotFound, "not_found", "to release not found", nil)
		return
	}
	c.JSON(http.StatusOK, gin.H{"from": from, "to": to, "from_items": fromItems, "to_items": toItems})
}

func bulkSetEnabled(c *gin.Context, e *engine.Engine, h HistoryServices, mgr *rulerelease.Manager, enabled bool) {
	var req rulerelease.BulkRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err.Error())
		return
	}
	req.Actor = actorFrom(c)
	changes, err := mgr.BulkSetEnabled(c.Request.Context(), req, enabled, e.Reload)
	if err != nil {
		writeError(c, http.StatusBadRequest, "bulk_failed", err.Error(), nil)
		return
	}
	action := rulehistory.ActionDisable
	op := "bulk_disable"
	if enabled {
		action = rulehistory.ActionEnable
		op = "bulk_enable"
	}
	if h.Changes != nil {
		for _, ch := range changes {
			entry := baseChange(c, h, ch.RuleID, action, ch.Before, ch.After, ch.Path)
			entry.Note = op + " " + ch.State
			_ = h.Changes.Append(entry)
		}
	}
	logAdminOperation(c, h, op, "rule", strconv.Itoa(len(changes)), "success", http.StatusOK)
	c.JSON(http.StatusOK, gin.H{"ok": true, "count": len(changes), "items": changes, "stats": e.Stats()})
}

func detectRuleConflicts(c *gin.Context, mgr *rulerelease.Manager) {
	scope := c.Request.URL.Query().Get("scope")
	if scope == "" {
		scope = rulerelease.StatePublished
	}
	rs, err := mgr.ListState(scope)
	if scope == rulerelease.StateStaged {
		rs, err = mgr.ListState(rulerelease.StateStaged)
	}
	if err != nil {
		writeError(c, http.StatusBadRequest, "conflict_error", err.Error(), nil)
		return
	}
	conflicts := rulerelease.DetectConflicts(rs)
	stateConflicts, err := mgr.DetectStateConflicts()
	if err != nil {
		writeError(c, http.StatusInternalServerError, "conflict_error", err.Error(), nil)
		return
	}
	conflicts = append(conflicts, stateConflicts...)
	blocking := 0
	for _, x := range conflicts {
		if x.Severity == "critical" {
			blocking++
		}
	}
	c.JSON(http.StatusOK, gin.H{"ok": blocking == 0, "blocking_count": blocking, "conflicts": conflicts})
}

func simulateRules(c *gin.Context, mgr *rulerelease.Manager) {
	var req rulerelease.SimulateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err.Error())
		return
	}
	if len([]rune(req.Text)) > maxSimulationRunes {
		writeError(c, http.StatusRequestEntityTooLarge, "request_too_large", "sample text exceeds simulation limit", nil)
		return
	}
	res, err := mgr.Simulate(req)
	if err != nil {
		writeError(c, http.StatusBadRequest, "simulation_failed", err.Error(), nil)
		return
	}
	c.JSON(http.StatusOK, res)
}

func prepublishTest(c *gin.Context, h HistoryServices, mgr *rulerelease.Manager) {
	var req struct {
		SampleText string `json:"sample_text"`
	}
	_ = c.ShouldBindJSON(&req)
	res, sim, err := mgr.Prepublish(c.Request.Context(), actorFrom(c), req.SampleText)
	if err != nil {
		writeError(c, http.StatusBadRequest, "validation_failed", err.Error(), nil)
		return
	}
	status := "success"
	code := http.StatusOK
	if !res.OK {
		status = "failed"
		code = http.StatusBadRequest
	}
	logAdminOperation(c, h, "prepublish_test", "ruleset", "staged", status, code)
	c.JSON(code, gin.H{"ok": res.OK, "validation": res, "simulation": sim})
}

func registerImportRollback(r gin.IRouter, e *engine.Engine, h HistoryServices, mgr *rulerelease.Manager) {
	r.POST("/imports/batches/:batch_id/rollback", func(c *gin.Context) {
		if h.Batches == nil {
			writeError(c, http.StatusBadRequest, "rollback_unavailable", "import batch history is not enabled", nil)
			return
		}
		batch, ok, err := h.Batches.Get(c.Param("batch_id"))
		if err != nil {
			writeError(c, http.StatusInternalServerError, "batch_error", err.Error(), nil)
			return
		}
		if !ok {
			writeError(c, http.StatusNotFound, "not_found", "batch not found", nil)
			return
		}
		res, err := mgr.RollbackImportBatch(batch.BatchID, batch.GeneratedFiles, e.Reload)
		if err != nil {
			writeError(c, http.StatusBadRequest, "rollback_failed", err.Error(), nil)
			return
		}
		if h.Changes != nil {
			for _, ch := range res.Files {
				entry := baseChange(c, h, ch.RuleID, rulehistory.ActionRollback, ch.Before, "", ch.Path)
				entry.ImportBatchID = batch.BatchID
				entry.Note = "import batch rollback"
				_ = h.Changes.Append(entry)
			}
		}
		logAdminOperation(c, h, "rollback", "import_batch", batch.BatchID, "success", http.StatusOK)
		c.JSON(http.StatusOK, gin.H{"ok": true, "rollback": res, "stats": e.Stats()})
	})
}

func ruleFromJSON(raw json.RawMessage) (rules.Rule, error) {
	var r rules.Rule
	err := json.Unmarshal(raw, &r)
	return r, err
}
