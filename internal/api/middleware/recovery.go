package middleware

import (
	"fmt"
	"net/http"
	"runtime/debug"

	"github.com/gin-gonic/gin"
	"pqc-authenticator/internal/utils"
)

func Recovery(logger utils.Logger) gin.HandlerFunc {
	return gin.RecoveryWithWriter(gin.DefaultWriter, func(c *gin.Context, recovered interface{}) {
		stack := string(debug.Stack())
		
		logger.Error("Panic recovered",
			"error", fmt.Sprintf("%v", recovered),
			"stack", stack,
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"ip", c.ClientIP(),
			"user_agent", c.Request.UserAgent(),
		)

		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal server error",
			"message": "An unexpected error occurred",
		})
	})
}