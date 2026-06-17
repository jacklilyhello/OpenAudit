package api

import (
	"github.com/gin-gonic/gin"
	"github.com/openaudit/openaudit/internal/ai"
	"github.com/openaudit/openaudit/internal/config"
	"github.com/openaudit/openaudit/internal/engine"
	"github.com/openaudit/openaudit/internal/model"
	"net/http"
)

func RegisterBatch(r gin.IRouter, e *engine.Engine) {
	RegisterBatchWithOptions(r, e, config.Defaults().Limits)
}
func RegisterBatchWithOptions(r gin.IRouter, e *engine.Engine, limits config.LimitsConfig) {
	RegisterBatchWithAI(r, e, limits, nil)
}
func RegisterBatchWithAI(r gin.IRouter, e *engine.Engine, limits config.LimitsConfig, aiSvc *ai.Service) {
	r.POST("/audit/batch", func(c *gin.Context) {
		var req model.AuditBatchRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			status := http.StatusBadRequest
			if err.Error() == "http: request body too large" {
				status = http.StatusRequestEntityTooLarge
			}
			writeError(c, status, "invalid_request", err.Error(), nil)
			return
		}
		if len(req.Items) > limits.MaxBatchItems {
			writeError(c, http.StatusRequestEntityTooLarge, "request_too_large", "batch exceeds max_batch_items", gin.H{"max_batch_items": limits.MaxBatchItems})
			return
		}
		if req.Options.MaxHits > limits.MaxHits || req.Options.MaxHits <= 0 {
			req.Options.MaxHits = limits.MaxHits
		}
		results := make([]engine.Result, 0, len(req.Items))
		for _, item := range req.Items {
			if len([]rune(item)) > limits.MaxTextRunes {
				writeError(c, http.StatusRequestEntityTooLarge, "request_too_large", "text exceeds max_text_runes", nil)
				return
			}
			res := e.AuditWithOptions(item, req.Options)
			if shouldRunAI(req.Options, aiSvc) {
				res.AIReview = ai.ToEngineReview(aiSvc.Review(c.Request.Context(), item, res))
			}
			results = append(results, res)
		}
		c.JSON(200, gin.H{"results": results})
	})
}
