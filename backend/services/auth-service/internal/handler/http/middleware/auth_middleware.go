// File: backend/services/auth-service/internal/handler/http/middleware/auth_middleware.go
package middleware

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/your-org/auth-service/internal/domain/service" // For TokenManagementService and Claims
	// httpHandler "github.com/your-org/auth-service/internal/handler/http" // For ErrorResponse, if it's made public
	"go.uber.org/zap"
	domainErrors "github.com/your-org/auth-service/internal/domain/errors"
)

const (
	AuthHeaderKey = "Authorization"
	AuthTypeBearer = "Bearer"
	GinContextUserIDKey = "userID"
	GinContextSessionIDKey = "sessionID"
	GinContextRolesKey = "roles"
	GinContextPermissionsKey = "permissions"
	GinContextUsernameKey = "username"
	GinContextClaimsKey = "claims"
)

// AuthMiddleware creates a gin.HandlerFunc for JWT authentication and authorization.
// It uses the provided TokenManagementService to validate access tokens.
func AuthMiddleware(tokenManager service.TokenManagementService, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader(AuthHeaderKey)
		if authHeader == "" {
			logger.Warn("AuthMiddleware: Authorization header missing")
			// Using a generic ErrorResponse structure, assuming it exists in http package or is defined globally
			// For now, direct c.AbortWithStatusJSON
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != strings.ToLower(AuthTypeBearer) {
			logger.Warn("AuthMiddleware: Authorization header format must be Bearer <token>")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header format must be Bearer <token>"})
			return
		}

		tokenString := parts[1]
		claims, err := tokenManager.ValidateAccessToken(tokenString)
		if err != nil {
			logger.Warn("AuthMiddleware: Invalid access token", zap.Error(err))
			status := http.StatusUnauthorized
			errMsg := "Invalid or expired token"
			if errors.Is(err, domainErrors.ErrExpiredToken) { // Assuming tokenManager returns a wrapped ErrExpiredToken
				errMsg = "Token has expired"
			}
			c.AbortWithStatusJSON(status, gin.H{"error": errMsg, "details": err.Error()})
			return
		}

		// Store claims in context for downstream handlers
		c.Set(GinContextClaimsKey, claims) // Store all claims
		c.Set(GinContextUserIDKey, claims.UserID)
		c.Set(GinContextSessionIDKey, claims.SessionID)
		c.Set(GinContextRolesKey, claims.Roles)
		c.Set(GinContextPermissionsKey, claims.Permissions)
		c.Set(GinContextUsernameKey, claims.Username) // If username is in claims

		c.Next()
	}
}
