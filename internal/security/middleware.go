package security

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
)

func Protect(h gin.HandlerFunc, checker Checker) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !checker.Valid(c.Request) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing or invalid API key"})
			return
		}
		h(c)
	}
}
func IsProtected(path string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}
