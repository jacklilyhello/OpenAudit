package api

import (
	"github.com/gin-gonic/gin"
	"github.com/openaudit/openaudit/internal/engine"
	"net/http"
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
}
