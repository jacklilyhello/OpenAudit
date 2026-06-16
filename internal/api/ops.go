package api

import (
	"github.com/gin-gonic/gin"
	"github.com/openaudit/openaudit/internal/config"
)

var Version = "dev"
var Commit = "unknown"
var BuildTime = "unknown"

func RegisterOps(r gin.IRouter, cfg config.Config) {
	r.GET("/version", func(c *gin.Context) {
		c.JSON(200, gin.H{"service": "OpenAudit", "version": Version, "commit": Commit, "build_time": BuildTime})
	})
	r.GET("/config", func(c *gin.Context) { c.JSON(200, cfg.Sanitized()) })
}
