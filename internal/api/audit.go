package api

import (
	"github.com/gin-gonic/gin"
	"github.com/openaudit/openaudit/internal/ai"
	"github.com/openaudit/openaudit/internal/config"
	"github.com/openaudit/openaudit/internal/engine"
	"github.com/openaudit/openaudit/internal/logstore"
	"github.com/openaudit/openaudit/internal/model"
	"github.com/openaudit/openaudit/internal/review"
	"net/http"
	"time"
)

func RegisterAudit(r gin.IRouter, e *engine.Engine) {
	RegisterAuditWithOptions(r, e, config.Defaults().Limits, nil)
}
func RegisterAuditWithOptions(r gin.IRouter, e *engine.Engine, limits config.LimitsConfig, logs *logstore.Store) {
	RegisterAuditWithAI(r, e, limits, logs, nil)
}
func RegisterAuditWithAI(r gin.IRouter, e *engine.Engine, limits config.LimitsConfig, logs *logstore.Store, aiSvc *ai.Service) {
	RegisterAuditWithReview(r, e, limits, logs, aiSvc, nil)
}
func RegisterAuditWithReview(r gin.IRouter, e *engine.Engine, limits config.LimitsConfig, logs *logstore.Store, aiSvc *ai.Service, reviewSvc *review.Service) {
	handle := func(c *gin.Context) {
		start := time.Now()
		var req model.AuditTextRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			status := http.StatusBadRequest
			if err.Error() == "http: request body too large" {
				status = http.StatusRequestEntityTooLarge
			}
			writeError(c, status, "invalid_request", err.Error(), nil)
			return
		}
		if req.Text == "" {
			bad(c, "text is required")
			return
		}
		if len([]rune(req.Text)) > limits.MaxTextRunes {
			writeError(c, http.StatusRequestEntityTooLarge, "request_too_large", "text exceeds max_text_runes", gin.H{"max_text_runes": limits.MaxTextRunes})
			return
		}
		if req.Options.MaxHits > limits.MaxHits || req.Options.MaxHits <= 0 {
			req.Options.MaxHits = limits.MaxHits
		}
		res := e.AuditWithOptions(req.Text, req.Options)
		if shouldRunAI(req.Options, aiSvc) {
			res.AIReview = ai.ToEngineReview(aiSvc.Review(c.Request.Context(), req.Text, res))
		}
		if reviewSvc != nil {
			_ = reviewSvc.Evaluate(c.Request.Context(), "audit_text", req.Text, &res)
		}
		if logs != nil {
			logs.Append(logstore.NewEntry("text", req.Text, res, time.Since(start).Milliseconds(), c.Request.RemoteAddr, c.Request.UserAgent(), logs.Options()))
		}
		c.JSON(200, res)
	}
	r.POST("/audit/text", handle)
	r.POST("/audit/url", handle)
	r.POST("/audit/domain", handle)
}
func shouldRunAI(opt model.AuditOptions, svc *ai.Service) bool {
	if svc == nil {
		return false
	}
	if opt.AI != nil {
		return *opt.AI
	}
	return svc.Enabled()
}
