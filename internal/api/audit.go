package api

import (
	"github.com/gin-gonic/gin"
	"github.com/openaudit/openaudit/internal/engine"
	"github.com/openaudit/openaudit/internal/model"
	"net/http"
)

func RegisterAudit(r gin.IRouter, e *engine.Engine) {
	r.POST("/audit/text", func(c *gin.Context) {
		var req model.AuditTextRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, e.Audit(req.Text, req.Options.Normalize))
	})
}
