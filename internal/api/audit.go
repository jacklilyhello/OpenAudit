package api

import (
	"github.com/gin-gonic/gin"
	"github.com/openaudit/openaudit/internal/config"
	"github.com/openaudit/openaudit/internal/engine"
	"github.com/openaudit/openaudit/internal/logstore"
	"github.com/openaudit/openaudit/internal/model"
	"net/http"
	"time"
)

func RegisterAudit(r gin.IRouter, e *engine.Engine) {
	RegisterAuditWithOptions(r, e, config.Defaults().Limits, nil)
}
func RegisterAuditWithOptions(r gin.IRouter, e *engine.Engine, limits config.LimitsConfig, logs *logstore.Store) {
	handle := func(c *gin.Context) {
		start := time.Now()
		var req model.AuditTextRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			writeError(c, http.StatusBadRequest, "invalid_request", err.Error(), nil)
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
		if logs != nil {
			logs.Append(logstore.NewEntry("text", req.Text, res, time.Since(start).Milliseconds(), c.Request.RemoteAddr, c.Request.UserAgent(), logs.Options()))
		}
		c.JSON(200, res)
	}
	r.POST("/audit/text", handle)
	r.POST("/audit/url", handle)
	r.POST("/audit/domain", handle)
}
