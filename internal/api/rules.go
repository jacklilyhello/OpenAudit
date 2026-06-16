package api

import (
	"github.com/gin-gonic/gin"
	"github.com/openaudit/openaudit/internal/engine"
	"github.com/openaudit/openaudit/internal/rules"
	"gopkg.in/yaml.v3"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

func RegisterRules(r gin.IRouter, e *engine.Engine) {
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
	r.POST("/rules/create", func(c *gin.Context) { createRule(c, e) })
	r.PATCH("/rules/update/:id", func(c *gin.Context) { updateRule(c, e, c.Param("id")) })
	r.DELETE("/rules/delete/:id", func(c *gin.Context) { deleteRule(c, e, c.Param("id")) })
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
	if strings.Contains(id, "/") || strings.Contains(id, "..") {
		return "", os.ErrPermission
	}
	return filepath.Join(root, "custom", id+".yml"), nil
}
func createRule(c *gin.Context, e *engine.Engine) {
	var req createReq
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err.Error())
		return
	}
	if strings.Contains(req.File, "..") {
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
	old := []byte(nil)
	if b, err := yaml.Marshal(req.Rule); err == nil {
		_ = old
		os.MkdirAll(filepath.Dir(p), 0755)
		if err := os.WriteFile(p, b, 0644); err != nil {
			writeError(c, 500, "write_failed", err.Error(), nil)
			return
		}
		if err := e.Reload(); err != nil {
			_ = os.Remove(p)
			writeError(c, 400, "reload_failed", err.Error(), nil)
			return
		}
		c.JSON(200, gin.H{"ok": true, "rule": req.Rule})
		return
	}
	bad(c, "invalid rule")
}
func updateRule(c *gin.Context, e *engine.Engine, id string) {
	p, err := customPath(e.Root(), id)
	if err != nil {
		bad(c, "invalid rule id")
		return
	}
	b, err := os.ReadFile(p)
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
	nb, _ := yaml.Marshal(rule)
	if err := os.WriteFile(p, nb, 0644); err != nil {
		writeError(c, 500, "write_failed", err.Error(), nil)
		return
	}
	if err := e.Reload(); err != nil {
		_ = os.WriteFile(p, b, 0644)
		_ = e.Reload()
		writeError(c, 400, "reload_failed", err.Error(), nil)
		return
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
func deleteRule(c *gin.Context, e *engine.Engine, id string) {
	p, err := customPath(e.Root(), id)
	if err != nil {
		bad(c, "invalid rule id")
		return
	}
	b, err := os.ReadFile(p)
	if err != nil {
		writeError(c, 400, "invalid_request", "only custom API-managed rules can be updated or deleted in Phase 4", nil)
		return
	}
	if err := os.Remove(p); err != nil {
		writeError(c, 500, "delete_failed", err.Error(), nil)
		return
	}
	if err := e.Reload(); err != nil {
		_ = os.WriteFile(p, b, 0644)
		_ = e.Reload()
		writeError(c, 400, "reload_failed", err.Error(), nil)
		return
	}
	c.JSON(200, gin.H{"ok": true})
}
