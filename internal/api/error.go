package api

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

type ErrorBody struct {
	Error ErrorDetail `json:"error"`
}
type ErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

func writeError(c *gin.Context, status int, code, msg string, details any) {
	c.JSON(status, ErrorBody{Error: ErrorDetail{Code: code, Message: msg, Details: details}})
}
func bad(c *gin.Context, msg string) {
	writeError(c, http.StatusBadRequest, "invalid_request", msg, nil)
}
