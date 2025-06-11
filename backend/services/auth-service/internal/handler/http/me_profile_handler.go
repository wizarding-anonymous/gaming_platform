// File: backend/services/auth-service/internal/handler/http/me_profile_handler.go
package http

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors"
)

// GetMe returns information about the current authenticated user.
func (h *MeHandler) GetMe(c *gin.Context) {
	userIDFromToken, exists := c.Get("userID")
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

	user, mfaEnabled, err := h.userService.GetUserFullInfo(c.Request.Context(), userIDStr)
	if err != nil {
		h.logger.Error("GetMe: failed to get user full info", zap.Error(err), zap.String("userID", userIDStr))
		if strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve user information"})
		}
		return
	}

	responseMap := map[string]interface{}{
		"id":          user.ID,
		"username":    user.Username,
		"email":       user.Email,
		"status":      string(user.Status),
		"created_at":  user.CreatedAt,
		"mfa_enabled": mfaEnabled,
	}
	c.JSON(http.StatusOK, responseMap)
}

// ChangePassword updates the authenticated user's password.
func (h *MeHandler) ChangePassword(c *gin.Context) {
	userIDStr, exists := c.Get("userID")
	if !exists {
		h.logger.Error("ChangePassword: userID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized: User ID not found in token claims"})
		return
	}

	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		h.logger.Error("ChangePassword: failed to parse userID from context", zap.String("rawUserID", userIDStr.(string)), zap.Error(err))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized: Invalid User ID format"})
		return
	}

	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("ChangePassword: failed to bind request JSON", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload: " + err.Error()})
		return
	}

	err = h.authService.ChangePassword(c.Request.Context(), userID, req.CurrentPassword, req.NewPassword)
	if err != nil {
		h.logger.Error("ChangePassword: authService.ChangePassword failed", zap.Error(err), zap.String("userID", userID.String()))
		if domainErrors.ErrInvalidCredentials.Is(err) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid current password"})
		} else if domainErrors.ErrUserNotFound.Is(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to change password"})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully"})
}
