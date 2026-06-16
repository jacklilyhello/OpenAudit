package api

import (
	"github.com/gin-gonic/gin"
	"github.com/openaudit/openaudit/internal/engine"
	"github.com/openaudit/openaudit/internal/rulehistory"
	"github.com/openaudit/openaudit/internal/rules"
	"gopkg.in/yaml.v3"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

func RegisterRules(r gin.IRouter, e *engine.Engine, h HistoryServices) {
	r.GET("/rules/stats", func(c *gin.Context) { c.JSON(200, e.Stats()) })
	r.POST("/rules/reload", func(c *gin.Context) {
		if err := e.Reload(); err != nil {
			c.JSON(http.StatusOK, gin.H{"ok": false, "message": "rules reload failed", "error": err.Error(), "stats": e.Stats()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "message": "rules reloaded", "stats": e.Stats()})
	})
	r.GET("/rules", func(c *gin.Context) { listRules(c, e) })
	r.GET("/rules/categories", func(c *gin.Context) { statRules(c, e, "category") })
	r.GET("/rules/sources", func(c *gin.Context) { statRules(c, e, "source") })
	r.GET("/rules/:id", func(c *gin.Context) { getRule(c, e, c.Param("id")) })
	r.POST("/rules/create", func(c *gin.Context) { createRule(c, e, h) })
	r.PATCH("/rules/update/:id", func(c *gin.Context) { updateRule(c, e, h, c.Param("id")) })
	r.DELETE("/rules/delete/:id", func(c *gin.Context) { deleteRule(c, e, h, c.Param("id")) })
}
func sortedRules(e *engine.Engine) []rules.Rule {
	rs := e.Rules()
	sort.Slice(rs, func(i, j int) bool { return rs[i].ID < rs[j].ID })
	return rs
}
func listRules(c *gin.Context, e *engine.Engine) {
	q := c.Request.URL.Query()
	out := []rules.Rule{}
	for _, r := range sortedRules(e) {
		if q.Get("type") != "" && r.Type != q.Get("type") {
			continue
		}
		if q.Get("category") != "" && r.Category != q.Get("category") {
			continue
		}
		if q.Get("risk_level") != "" && r.RiskLevel != q.Get("risk_level") {
			continue
		}
		if q.Get("action") != "" && r.Action != q.Get("action") {
			continue
		}
		if q.Get("source") != "" && r.Source != q.Get("source") {
			continue
		}
		if q.Get("enabled") != "" && strconv.FormatBool(r.IsEnabled()) != q.Get("enabled") {
			continue
		}
		if s := strings.ToLower(q.Get("q")); s != "" && !strings.Contains(strings.ToLower(r.ID+" "+r.Category+" "+r.Description), s) {
			continue
		}
		out = append(out, r)
	}
	count := len(out)
	limit := atoi(q.Get("limit"), 50)
	off := atoi(q.Get("offset"), 0)
	if off > len(out) {
		out = nil
	} else {
		end := off + limit
		if end > len(out) {
			end = len(out)
		}
		out = out[off:end]
	}
	c.JSON(200, gin.H{"items": out, "count": count, "limit": limit, "offset": off})
}
func getRule(c *gin.Context, e *engine.Engine, id string) {
	for _, r := range e.Rules() {
		if r.ID == id {
			c.JSON(200, r)
			return
		}
	}
	writeError(c, 404, "not_found", "rule not found", nil)
}
func statRules(c *gin.Context, e *engine.Engine, field string) {
	m := map[string]int{}
	for _, r := range e.Rules() {
		k := r.Category
		if field == "source" {
			k = r.Source
		}
		if k == "" {
			k = "local"
		}
		m[k]++
	}
	keys := []string{}
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	items := []gin.H{}
	for _, k := range keys {
		items = append(items, gin.H{field: k, "count": m[k]})
	}
	c.JSON(200, gin.H{"items": items, "count": len(items)})
}
func atoi(s string, d int) int {
	if v, err := strconv.Atoi(s); err == nil && v >= 0 {
		return v
	}
	return d
}

type createReq struct {
	Rule rules.Rule `json:"rule"`
	File string     `json:"file"`
}
type updateReq struct {
	Patch map[string]any `json:"patch"`
}

func customPath(root, id string) (string, error) {
	return safeRulePathUnderCustomRoot(root, id)
}

func safeRulePathUnderCustomRoot(root, id string) (string, error) {
	if err := validateCustomRuleID(id); err != nil {
		return "", err
	}
	customRoot := filepath.Clean(filepath.Join(root, "custom"))
	p := filepath.Clean(filepath.Join(customRoot, id+".yml"))
	rel, err := filepath.Rel(customRoot, p)
	if err != nil || rel == "." || ruleRelEscapesBase(rel) || filepath.IsAbs(rel) || strings.ContainsRune(rel, '\x00') {
		return "", os.ErrPermission
	}
	return p, nil
}

func validateCustomRuleID(id string) error {
	if id == "" || strings.ContainsRune(id, '\x00') || filepath.IsAbs(id) || strings.Contains(id, "/") || strings.Contains(id, "\\") || strings.Contains(id, "..") {
		return os.ErrPermission
	}
	return nil
}

func validateCustomRuleFileHint(file string) error {
	if file == "" {
		return nil
	}
	if strings.ContainsRune(file, '\x00') || filepath.IsAbs(file) || hasRuleParentTraversal(file) {
		return os.ErrPermission
	}
	return nil
}

func hasRuleParentTraversal(p string) bool {
	p = strings.ReplaceAll(filepath.ToSlash(p), "\\", "/")
	for _, part := range strings.Split(p, "/") {
		if part == ".." {
			return true
		}
	}
	return false
}

func ruleRelEscapesBase(rel string) bool {
	if rel == "." {
		return false
	}
	if filepath.IsAbs(rel) {
		return true
	}
	for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
		if part == ".." {
			return true
		}
	}
	return false
}

func readCustomRuleFile(p string) ([]byte, error) {
	// #nosec G304 -- p is produced by safeRulePathUnderCustomRoot and constrained with filepath.Rel to the API-managed custom rules directory.
	return os.ReadFile(p)
}

func writeCustomRuleFile(p string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(p), 0750); err != nil {
		return err
	}
	// #nosec G304 -- p is produced by safeRulePathUnderCustomRoot and constrained with filepath.Rel to the API-managed custom rules directory.
	return os.WriteFile(p, b, 0600)
}

func restoreCustomRuleFile(p string, b []byte) error {
	return writeCustomRuleFile(p, b)
}
func createRule(c *gin.Context, e *engine.Engine, h HistoryServices) {
	var req createReq
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err.Error())
		return
	}
	if err := validateCustomRuleFileHint(req.File); err != nil {
		writeError(c, 400, "invalid_request", "path traversal rejected", nil)
		return
	}
	p, err := customPath(e.Root(), req.Rule.ID)
	if err != nil {
		writeError(c, 400, "invalid_request", "invalid rule id", nil)
		return
	}
	if _, err := os.Stat(p); err == nil {
		writeError(c, 409, "conflict", "rule already exists", nil)
		return
	}
	if b, err := yaml.Marshal(req.Rule); err == nil {
		if err := writeCustomRuleFile(p, b); err != nil {
			writeError(c, 500, "write_failed", err.Error(), nil)
			return
		}
		if err := e.Reload(); err != nil {
			_ = os.Remove(p)
			writeError(c, 400, "reload_failed", err.Error(), nil)
			return
		}
		if h.Changes != nil {
			entry := baseChange(c, h, req.Rule.ID, rulehistory.ActionCreate, "", string(b), p)
			entry.RuleType = req.Rule.Type
			entry.Category = req.Rule.Category
			entry.Source = req.Rule.Source
			_ = h.Changes.Append(entry)
		}
		c.JSON(200, gin.H{"ok": true, "rule": req.Rule})
		return
	}
	bad(c, "invalid rule")
}
func updateRule(c *gin.Context, e *engine.Engine, h HistoryServices, id string) {
	p, err := customPath(e.Root(), id)
	if err != nil {
		bad(c, "invalid rule id")
		return
	}
	b, err := readCustomRuleFile(p)
	if err != nil {
		writeError(c, 400, "invalid_request", "only custom API-managed rules can be updated or deleted in Phase 4", nil)
		return
	}
	var rule rules.Rule
	_ = yaml.Unmarshal(b, &rule)
	var req updateReq
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err.Error())
		return
	}
	applyPatch(&rule, req.Patch)
	nb, err := yaml.Marshal(rule)
	if err != nil {
		bad(c, "invalid rule")
		return
	}
	if err := writeCustomRuleFile(p, nb); err != nil {
		writeError(c, 500, "write_failed", err.Error(), nil)
		return
	}
	if err := e.Reload(); err != nil {
		if restoreErr := restoreCustomRuleFile(p, b); restoreErr != nil {
			writeError(c, 400, "reload_failed", err.Error()+"; restore failed: "+restoreErr.Error(), nil)
			return
		}
		if restoreReloadErr := e.Reload(); restoreReloadErr != nil {
			writeError(c, 400, "reload_failed", err.Error()+"; restore reload failed: "+restoreReloadErr.Error(), nil)
			return
		}
		writeError(c, 400, "reload_failed", err.Error(), nil)
		return
	}
	if h.Changes != nil {
		act := detectAction(b, nb)
		entry := baseChange(c, h, id, act, string(b), string(nb), p)
		entry.RuleType = rule.Type
		entry.Category = rule.Category
		entry.Source = rule.Source
		_ = h.Changes.Append(entry)
	}
	c.JSON(200, gin.H{"ok": true, "rule": rule})
}
func applyPatch(r *rules.Rule, p map[string]any) {
	for k, v := range p {
		switch k {
		case "enabled":
			b := v.(bool)
			r.Enabled = &b
		case "score":
			r.Score = int(v.(float64))
		case "keywords":
			r.Keywords = toStrings(v)
		case "patterns":
			r.Patterns = toStrings(v)
		case "domains":
			r.Domains = toStrings(v)
		case "action":
			r.Action = v.(string)
		case "risk_level":
			r.RiskLevel = v.(string)
		case "category":
			r.Category = v.(string)
		}
	}
}
func toStrings(v any) []string {
	a, ok := v.([]any)
	if !ok {
		return nil
	}
	out := []string{}
	for _, x := range a {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
func deleteRule(c *gin.Context, e *engine.Engine, h HistoryServices, id string) {
	p, err := customPath(e.Root(), id)
	if err != nil {
		bad(c, "invalid rule id")
		return
	}
	b, err := readCustomRuleFile(p)
	if err != nil {
		writeError(c, 400, "invalid_request", "only custom API-managed rules can be updated or deleted in Phase 4", nil)
		return
	}
	if err := os.Remove(p); err != nil {
		writeError(c, 500, "delete_failed", err.Error(), nil)
		return
	}
	if err := e.Reload(); err != nil {
		if restoreErr := restoreCustomRuleFile(p, b); restoreErr != nil {
			writeError(c, 400, "reload_failed", err.Error()+"; restore failed: "+restoreErr.Error(), nil)
			return
		}
		if restoreReloadErr := e.Reload(); restoreReloadErr != nil {
			writeError(c, 400, "reload_failed", err.Error()+"; restore reload failed: "+restoreReloadErr.Error(), nil)
			return
		}
		writeError(c, 400, "reload_failed", err.Error(), nil)
		return
	}
	if h.Changes != nil {
		var oldRule rules.Rule
		_ = yaml.Unmarshal(b, &oldRule)
		entry := baseChange(c, h, id, rulehistory.ActionDelete, string(b), "", p)
		entry.RuleType = oldRule.Type
		entry.Category = oldRule.Category
		entry.Source = oldRule.Source
		_ = h.Changes.Append(entry)
	}
	c.JSON(200, gin.H{"ok": true})
}

func detectAction(before, after []byte) rulehistory.Action {
	var a, b rules.Rule
	_ = yaml.Unmarshal(before, &a)
	_ = yaml.Unmarshal(after, &b)
	ae, be := a.IsEnabled(), b.IsEnabled()
	a.Enabled = nil
	b.Enabled = nil
	ab, errA := yaml.Marshal(a)
	bb, errB := yaml.Marshal(b)
	if errA == nil && errB == nil && string(ab) == string(bb) && ae != be {
		if be {
			return rulehistory.ActionEnable
		}
		return rulehistory.ActionDisable
	}
	return rulehistory.ActionUpdate
}
