package admin

import "github.com/gin-gonic/gin"

func Register(r *gin.Engine) { RegisterAt(r, "/admin") }
func RegisterAt(r *gin.Engine, path string) {
	r.StaticFile(path, "web/admin/index.html")
	r.Static(path+"/assets", "web/admin")
}
