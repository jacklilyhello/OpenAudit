package api

import (
	"github.com/gin-gonic/gin"
	"github.com/openaudit/openaudit/internal/engine"
	"github.com/openaudit/openaudit/internal/model"
	"net/http"
)

func RegisterBatch(r gin.IRouter, e *engine.Engine) {
	r.POST("/audit/batch", func(c *gin.Context) {
		var req model.AuditBatchRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		results := make([]engine.Result, 0, len(req.Items))
		for _, item := range req.Items {
			results = append(results, e.Audit(item, req.Options.Normalize))
		}
		c.JSON(200, gin.H{"results": results})
	})
}
