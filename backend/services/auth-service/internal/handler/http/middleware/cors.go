// File: backend/services/auth-service/internal/handler/http/middleware/cors.go
package middleware

import (
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// CorsMiddleware настраивает CORS для API
// Allowed origins are loaded from the CORS_ALLOWED_ORIGINS environment variable.
func CorsMiddleware() gin.HandlerFunc {
	originsStr := os.Getenv("CORS_ALLOWED_ORIGINS")
	var allowedOrigins []string
	if originsStr != "" {
		allowedOrigins = strings.Split(originsStr, ",")
	} else {
		// Default to an empty list, effectively denying all cross-origin requests
		// if not specified. Alternatively, log a warning or use a restrictive default.
		allowedOrigins = []string{}
	}

	return cors.New(cors.Config{
		AllowOrigins:     allowedOrigins,
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Content-Length", "Accept-Encoding", "X-CSRF-Token", "Authorization", "Accept", "Cache-Control", "X-Requested-With"},
		ExposeHeaders:    []string{"Content-Length", "Content-Type"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	})
}
