package admin

import "github.com/gin-gonic/gin"

func Register(r *gin.Engine) {
	r.StaticFile("/admin", "web/admin/index.html")
	r.Static("/admin/assets", "web/admin")
}
