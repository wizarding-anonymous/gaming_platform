package middleware

import (
	"net/http"
	// "slices" // Available in Go 1.21+ for checking if slice contains element

	"github.com/gin-gonic/gin"
	// httpHandler "github.com/your-org/auth-service/internal/handler/http" // For ErrorResponse
	"go.uber.org/zap"
)

// RoleMiddleware creates a gin.HandlerFunc for role-based access control.
// It checks if the user associated with the request has at least one of the required roles.
// User roles are expected to be set in the Gin context by a preceding AuthMiddleware,
// typically under the key GinContextRolesKey (e.g., "roles").
func RoleMiddleware(requiredRoles []string, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(requiredRoles) == 0 {
			c.Next() // No specific roles required, pass through
			return
		}

		userRolesInterface, exists := c.Get(GinContextRolesKey)
		if !exists {
			logger.Warn("RoleMiddleware: Roles not found in context. AuthMiddleware might be missing or did not set roles.")
			// Using direct c.AbortWithStatusJSON as ErrorResponse might not be accessible directly here
			// or to avoid circular dependencies if ErrorResponse is in the http handler package.
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Access denied: user roles not available"})
			return
		}

		userRoles, ok := userRolesInterface.([]string)
		if !ok {
			logger.Error("RoleMiddleware: Roles in context are not of expected type []string.")
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal server error: role processing failed"})
			return
		}

		hasRequiredRole := false
		for _, userRole := range userRoles {
			for _, requiredRole := range requiredRoles {
				if userRole == requiredRole {
					hasRequiredRole = true
					break
				}
			}
			if hasRequiredRole {
				break
			}
		}

		if !hasRequiredRole {
			logger.Warn("RoleMiddleware: User does not have required role(s)",
				zap.Strings("user_roles", userRoles),
				zap.Strings("required_roles", requiredRoles),
			)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Access denied: insufficient permissions"})
			return
		}

		c.Next()
	}
}
