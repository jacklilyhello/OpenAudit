package api

import "github.com/gin-gonic/gin"

func RegisterHealth(r gin.IRouter) {
	r.GET("/health", func(c *gin.Context) { c.JSON(200, gin.H{"status": "ok", "service": "OpenAudit"}) })
}
