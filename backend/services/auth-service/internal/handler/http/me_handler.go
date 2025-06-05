// File: backend/services/auth-service/internal/handler/http/me_handler.go
package http

import (
	"net/http"
	// "time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/gameplatform/auth-service/internal/domain/service" // For Claims and other services
	// "github.com/gameplatform/auth-service/internal/middleware" // For auth middleware
)

// MeHandler handles HTTP requests for the current authenticated user (`/me/...`).
type MeHandler struct {
	logger         *zap.Logger
	authLogicSvc   service.AuthLogicService   // For getting claims from token
	userService    service.UserService      // For richer user object if needed
	mfaLogicSvc    service.MFALogicService
	apiKeySvc      service.APIKeyService
	// sessionService service.SessionService // If needed for session listing/revocation directly
}

// NewMeHandler creates a new MeHandler.
func NewMeHandler(
	logger *zap.Logger,
	authLogicSvc service.AuthLogicService,
	userService service.UserService,
	mfaLogicSvc service.MFALogicService,
	apiKeySvc service.APIKeyService,
) *MeHandler {
	return &MeHandler{
		logger:       logger.Named("me_handler"),
		authLogicSvc: authLogicSvc,
		userService:  userService,
		mfaLogicSvc:  mfaLogicSvc,
		apiKeySvc:    apiKeySvc,
	}
}

// GetMe handles fetching the current authenticated user's information.
// GET /me
func (h *MeHandler) GetMe(c *gin.Context) {
	// This endpoint is protected by auth middleware.
	// The user's claims should be available in the Gin context if set by middleware.
	// Example: claims, exists := c.Get(middleware.AuthClaimsKey)
	// For this example, we'll simulate getting UserID from context.
	
	userIDFromToken, exists := c.Get("userID") // Assuming middleware sets this
	if !exists {
		h.logger.Error("GetMe: userID not found in context, auth middleware might not be working")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized: User ID not found in token claims"})
		return
	}
	
	userIDStr, ok := userIDFromToken.(string)
	if !ok || userIDStr == "" {
		h.logger.Error("GetMe: userID in context is not a valid string", zap.Any("userID", userIDFromToken))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized: Invalid User ID in token claims"})
		return
	}

	// Fetch more complete user information using UserService
	user, mfaEnabled, err := h.userService.GetUserFullInfo(c.Request.Context(), userIDStr)
	if err != nil {
		// Handle user not found or other errors
		h.logger.Error("GetMe: failed to get user full info", zap.Error(err), zap.String("userID", userIDStr))
		// Map error appropriately
		if strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve user information"})
		}
		return
	}

	// Use UserResponse DTO from auth_handler.go or a more specific MeResponseDTO
	meResponse := UserResponse{ // Re-using UserResponse for simplicity
		ID:        user.ID,
		Username:  user.Username,
		Email:     user.Email,
		Status:    string(user.Status),
		CreatedAt: user.CreatedAt,
		// Add mfa_enabled to UserResponse or create a MeUserResponse DTO
	}
	// Add mfa_enabled if UserResponse DTO is extended or use a map
	 responseMap := map[string]interface{}{
        "id":          meResponse.ID,
        "username":    meResponse.Username,
        "email":       meResponse.Email,
        "status":      meResponse.Status,
        "created_at":  meResponse.CreatedAt,
        "mfa_enabled": mfaEnabled,
    }

	c.JSON(http.StatusOK, responseMap)
}


// TODO: Implement other /me handlers:
// - PUT /me/password
// - GET /me/sessions
// - DELETE /me/sessions/{session_id}
// - POST /me/2fa/totp/enable
// - POST /me/2fa/totp/verify
// - POST /me/2fa/disable
// - POST /me/2fa/backup-codes/regenerate
// - GET /me/api-keys
// - POST /me/api-keys
// - DELETE /me/api-keys/{key_id}

// RegisterMeRoutes registers /me related HTTP routes.
// All routes in this group should be protected by an authentication middleware.
func RegisterMeRoutes(router *gin.RouterGroup, meHandler *MeHandler /*, authMiddleware gin.HandlerFunc */) {
	me := router.Group("/me")
	// me.Use(authMiddleware) // Apply auth middleware to all /me routes
	{
		me.GET("", meHandler.GetMe)
		// Add other /me routes here
		// me.PUT("/password", meHandler.ChangePassword)
		// ... MFA routes, API key routes etc.
	}
}

// Need to import "strings" for error checking example
import "strings"
