// File: backend/services/auth-service/internal/handler/http/me_handler.go
package http

import (
	"net/http"
	// "time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid" // Added for userID parsing
	"go.uber.org/zap"

	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"                // For request/response structs if any become shared
	domainService "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/service" // For service interfaces
	appService "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/service"           // For concrete service like AuthService
	// "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/middleware" // For auth middleware
)

// ChangePasswordRequest defines the structure for the change password request body.
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" binding:"required"`
	NewPassword     string `json:"new_password" binding:"required,min=8"`
}

// VerifyTOTPRequest defines the structure for the TOTP verification request body.
type VerifyTOTPRequest struct {
	MFASecretID string `json:"mfa_secret_id" binding:"required,uuid"`
	TOTPCode    string `json:"totp_code" binding:"required,len=6,numeric"`
}

// Disable2FARequest defines the structure for the 2FA disable request body.
type Disable2FARequest struct {
	VerificationToken  string `json:"verification_token" binding:"required"`
	VerificationMethod string `json:"verification_method" binding:"required,oneof=password totp backup"`
}

// SessionResponse defines the structure for session information returned to the user.
type SessionResponse struct {
	SessionID      string          `json:"session_id"`
	IPAddress      *string         `json:"ip_address,omitempty"`
	UserAgent      *string         `json:"user_agent,omitempty"`
	DeviceInfo     json.RawMessage `json:"device_info,omitempty"` // Assuming models.Session.DeviceInfo is json.RawMessage
	LastActivityAt time.Time       `json:"last_activity_at"`
	CreatedAt      time.Time       `json:"created_at"`
	IsCurrent      bool            `json:"is_current"`
}

// MeHandler handles HTTP requests for the current authenticated user (`/me/...`).
type MeHandler struct {
	logger         *zap.Logger
	authService    *appService.AuthService
	userService    domainService.UserService
	mfaLogicSvc    domainService.MFALogicService
	apiKeySvc      domainService.APIKeyService
	sessionService domainService.SessionService // Added SessionService dependency
}

// NewMeHandler creates a new MeHandler.
func NewMeHandler(
	logger *zap.Logger,
	authService *appService.AuthService,
	userService domainService.UserService,
	mfaLogicSvc domainService.MFALogicService,
	apiKeySvc domainService.APIKeyService,
	sessionService domainService.SessionService, // Added SessionService dependency
) *MeHandler {
	return &MeHandler{
		logger:         logger.Named("me_handler"),
		authService:    authService,
		userService:    userService,
		mfaLogicSvc:    mfaLogicSvc,
		apiKeySvc:      apiKeySvc,
		sessionService: sessionService, // Store SessionService
	}
}

// RegisterMeRoutes registers /me related HTTP routes.
// All routes in this group should be protected by an authentication middleware.
func RegisterMeRoutes(router *gin.RouterGroup, meHandler *MeHandler /*, authMiddleware gin.HandlerFunc */) {
	me := router.Group("/me")
	// me.Use(authMiddleware) // Apply auth middleware to all /me routes
	{
		me.GET("", meHandler.GetMe)
		me.PUT("/password", meHandler.ChangePassword)
		me.POST("/2fa/totp/enable", meHandler.EnableTOTP)
		me.POST("/2fa/totp/verify", meHandler.VerifyTOTP)
		me.POST("/2fa/totp/disable", meHandler.DisableTOTP)
		me.POST("/2fa/backup-codes/regenerate", meHandler.RegenerateBackupCodes)
		me.GET("/2fa/backup-codes", meHandler.GetBackupCodeStatus)
		me.GET("/sessions", meHandler.ListMySessions)                 // Added ListMySessions route
		me.DELETE("/sessions/:session_id", meHandler.DeleteMySession) // Added DeleteMySession route

		// API Key Routes
		me.GET("/api-keys", meHandler.GetMyAPIKeys)
		me.POST("/api-keys", meHandler.CreateMyAPIKey)
		me.DELETE("/api-keys/:key_id", meHandler.DeleteMyAPIKey)
	}
}

// ChangePassword updates the authenticated user's password.
// PUT /me/password
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
		if errors.Is(err, domainErrors.ErrInvalidCredentials) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid current password"})
		} else if errors.Is(err, domainErrors.ErrUserNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to change password"})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully"})
}

// EnableTOTP handles the initiation of TOTP-based 2FA for the authenticated user.
// POST /me/2fa/totp/enable
func (h *MeHandler) EnableTOTP(c *gin.Context) {
	userIDStr, exists := c.Get("userID")
	if !exists {
		h.logger.Error("EnableTOTP: userID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized: User ID not found"})
		return
	}
	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		h.logger.Error("EnableTOTP: failed to parse userID from context", zap.String("rawUserID", userIDStr.(string)), zap.Error(err))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized: Invalid User ID format"})
		return
	}

	// Use username from context, set by auth middleware, as the account name for OTP
	usernameFromContext, exists := c.Get("username") // Assuming middleware.GinContextUsernameKey is "username"
	if !exists || usernameFromContext.(string) == "" {
		h.logger.Error("EnableTOTP: username not found in context for OTP account name", zap.String("userID", userID.String()))
		// Fallback or error - for now, using a generic name if not found, or user's email if available
		// For better user experience, ensure username or email is reliably in context.
		// As a fallback, could fetch user email via h.userService if critical.
		// For now, let's assume if username is missing, it's an issue with claims population.
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not determine account name for 2FA setup"})
		return
	}
	accountName := usernameFromContext.(string)

	mfaSecretID, secretBase32, otpAuthURL, err := h.mfaLogicSvc.Enable2FAInitiate(c.Request.Context(), userID, accountName)
	if err != nil {
		h.logger.Error("EnableTOTP: mfaLogicSvc.Enable2FAInitiate failed", zap.Error(err), zap.String("userID", userID.String()))
		if errors.Is(err, domainErrors.Err2FAAlreadyEnabled) {
			c.JSON(http.StatusConflict, gin.H{"error": "2FA is already enabled and verified for this account."})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to initiate 2FA setup. Please try again."})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"mfa_secret_id":     mfaSecretID.String(),
			"secret_key_base32": secretBase32,
			"otp_auth_url":      otpAuthURL,
		},
	})
}

// VerifyTOTP handles the verification and activation of TOTP-based 2FA.
// POST /me/2fa/totp/verify
func (h *MeHandler) VerifyTOTP(c *gin.Context) {
	userIDStr, exists := c.Get("userID")
	if !exists {
		h.logger.Error("VerifyTOTP: userID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized: User ID not found"})
		return
	}
	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		h.logger.Error("VerifyTOTP: failed to parse userID from context", zap.String("rawUserID", userIDStr.(string)), zap.Error(err))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized: Invalid User ID format"})
		return
	}

	var req VerifyTOTPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("VerifyTOTP: failed to bind request JSON", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload: " + err.Error()})
		return
	}

	mfaSecretID_uuid, err := uuid.Parse(req.MFASecretID)
	if err != nil {
		h.logger.Error("VerifyTOTP: failed to parse MFASecretID from request", zap.String("rawMFASecretID", req.MFASecretID), zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid mfa_secret_id format"})
		return
	}

	backupCodes, err := h.mfaLogicSvc.VerifyAndActivate2FA(c.Request.Context(), userID, req.TOTPCode, mfaSecretID_uuid)
	if err != nil {
		h.logger.Error("VerifyTOTP: mfaLogicSvc.VerifyAndActivate2FA failed", zap.Error(err), zap.String("userID", userID.String()))
		if errors.Is(err, domainErrors.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "MFA setup not found or invalid mfa_secret_id. Please initiate 2FA setup again."})
			return
		}
		if errors.Is(err, domainErrors.ErrInvalid2FACode) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid TOTP code."})
			return
		}
		if errors.Is(err, domainErrors.Err2FAAlreadyEnabled) { // Or ErrMFANotVerified if it was already verified
			c.JSON(http.StatusConflict, gin.H{"error": "2FA is already enabled and verified."})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify and activate 2FA. Please try again."})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"message":      "Two-factor authentication (TOTP) successfully enabled.",
			"backup_codes": backupCodes,
		},
	})
}

// DisableTOTP handles disabling TOTP-based 2FA for the authenticated user.
// POST /me/2fa/totp/disable
func (h *MeHandler) DisableTOTP(c *gin.Context) {
	userIDStr, exists := c.Get("userID")
	if !exists {
		h.logger.Error("DisableTOTP: userID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized: User ID not found"})
		return
	}
	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		h.logger.Error("DisableTOTP: failed to parse userID from context", zap.String("rawUserID", userIDStr.(string)), zap.Error(err))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized: Invalid User ID format"})
		return
	}

	var req Disable2FARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("DisableTOTP: failed to bind request JSON", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload: " + err.Error()})
		return
	}

	err = h.mfaLogicSvc.Disable2FA(c.Request.Context(), userID, req.VerificationToken, req.VerificationMethod)
	if err != nil {
		h.logger.Error("DisableTOTP: mfaLogicSvc.Disable2FA failed", zap.Error(err), zap.String("userID", userID.String()))
		if errors.Is(err, domainErrors.ErrForbidden) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid verification token or method."})
			return
		}
		if errors.Is(err, domainErrors.Err2FANotEnabled) {
			// Service method handles this gracefully, but if it were to return an error for this:
			// c.JSON(http.StatusBadRequest, gin.H{"error": "2FA is not currently enabled for this account."})
			// For now, assuming service returns nil if already not enabled, so this path might not be hit with an error.
			// If it does error, a 400 or 409 might be appropriate.
			// Let's assume the service returns nil if it was already disabled or not set up.
		}
		// Other unexpected errors
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to disable 2FA. Please try again."})
		return
	}

	// The service's Disable2FA method is expected to return nil if 2FA was not enabled,
	// or if it was successfully disabled.
	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"message": "Two-factor authentication successfully disabled.",
		},
	})
}

// RegenerateBackupCodes handles regenerating MFA backup codes for the authenticated user.
// POST /me/2fa/backup-codes/regenerate
func (h *MeHandler) RegenerateBackupCodes(c *gin.Context) {
	userIDStr, exists := c.Get("userID")
	if !exists {
		h.logger.Error("RegenerateBackupCodes: userID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized: User ID not found"})
		return
	}
	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		h.logger.Error("RegenerateBackupCodes: failed to parse userID from context", zap.String("rawUserID", userIDStr.(string)), zap.Error(err))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized: Invalid User ID format"})
		return
	}

	// Reuse Disable2FARequest for authorization, as it has the same fields.
	var req Disable2FARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("RegenerateBackupCodes: failed to bind request JSON", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload: " + err.Error()})
		return
	}

	backupCodes, err := h.mfaLogicSvc.RegenerateBackupCodes(c.Request.Context(), userID, req.VerificationToken, req.VerificationMethod)
	if err != nil {
		h.logger.Error("RegenerateBackupCodes: mfaLogicSvc.RegenerateBackupCodes failed", zap.Error(err), zap.String("userID", userID.String()))
		if errors.Is(err, domainErrors.ErrForbidden) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid verification token or method."})
			return
		}
		if errors.Is(err, domainErrors.Err2FANotEnabled) || errors.Is(err, domainErrors.ErrMFANotVerified) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "2FA (TOTP) must be enabled and verified to regenerate backup codes."})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to regenerate backup codes. Please try again."})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"message":      "Backup codes successfully regenerated.",
			"backup_codes": backupCodes,
		},
	})
}

// GetBackupCodeStatus handles fetching the count of active backup codes for the authenticated user.
// GET /me/2fa/backup-codes
func (h *MeHandler) GetBackupCodeStatus(c *gin.Context) {
	userIDStr, exists := c.Get("userID")
	if !exists {
		h.logger.Error("GetBackupCodeStatus: userID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized: User ID not found"})
		return
	}
	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		h.logger.Error("GetBackupCodeStatus: failed to parse userID from context", zap.String("rawUserID", userIDStr.(string)), zap.Error(err))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized: Invalid User ID format"})
		return
	}

	count, err := h.mfaLogicSvc.GetActiveBackupCodeCount(c.Request.Context(), userID)
	if err != nil {
		h.logger.Error("GetBackupCodeStatus: mfaLogicSvc.GetActiveBackupCodeCount failed", zap.Error(err), zap.String("userID", userID.String()))
		if errors.Is(err, domainErrors.Err2FANotEnabled) || errors.Is(err, domainErrors.ErrMFANotVerified) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "2FA (TOTP) must be enabled and verified to access backup code status."})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve backup code status."})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"active_backup_codes_count": count,
		},
	})
}

// ListMySessions handles fetching all active sessions for the authenticated user.
// GET /me/sessions
func (h *MeHandler) ListMySessions(c *gin.Context) {
	userIDStr, exists := c.Get("userID")
	if !exists {
		h.logger.Error("ListMySessions: userID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized: User ID not found"})
		return
	}
	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		h.logger.Error("ListMySessions: failed to parse userID from context", zap.String("rawUserID", userIDStr.(string)), zap.Error(err))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized: Invalid User ID format"})
		return
	}

	currentSessionIDStr, currentSessionExists := c.Get("sessionID") // Assuming middleware.GinContextSessionIDKey is "sessionID"

	// Get all active sessions
	sessions, err := h.sessionService.GetActiveUserSessions(c.Request.Context(), userID)
	if err != nil {
		h.logger.Error("ListMySessions: sessionService.GetActiveUserSessions failed", zap.Error(err), zap.String("userID", userID.String()))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve sessions."})
		return
	}

	sessionResponses := make([]SessionResponse, len(sessions))
	for i, session := range sessions {
		isCurrent := false
		if currentSessionExists {
			if currentSessIDTyped, ok := currentSessionIDStr.(string); ok {
				isCurrent = (session.ID.String() == currentSessIDTyped)
			}
		}
		sessionResponses[i] = SessionResponse{
			SessionID:      session.ID.String(),
			IPAddress:      session.IPAddress,
			UserAgent:      session.UserAgent,
			DeviceInfo:     session.DeviceInfo,
			LastActivityAt: session.LastActivityAt,
			CreatedAt:      session.CreatedAt,
			IsCurrent:      isCurrent,
		}
	}

	c.JSON(http.StatusOK, gin.H{"data": sessionResponses})
}

// DeleteMySession handles revoking a specific session for the authenticated user.
// DELETE /me/sessions/:session_id
func (h *MeHandler) DeleteMySession(c *gin.Context) {
	requestingUserIDStr, exists := c.Get("userID")
	if !exists {
		h.logger.Error("DeleteMySession: requestingUserID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized: User ID not found"})
		return
	}
	requestingUserID, err := uuid.Parse(requestingUserIDStr.(string))
	if err != nil {
		h.logger.Error("DeleteMySession: failed to parse requestingUserID", zap.String("rawUserID", requestingUserIDStr.(string)), zap.Error(err))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized: Invalid User ID format"})
		return
	}

	currentSessionIDStr, existsCurrent := c.Get("sessionID")

	sessionIDToDeleteStr := c.Param("session_id")
	sessionIDToDelete, err := uuid.Parse(sessionIDToDeleteStr)
	if err != nil {
		h.logger.Error("DeleteMySession: failed to parse session_id_to_delete from path", zap.String("rawSessionID", sessionIDToDeleteStr), zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid session ID format."})
		return
	}

	if existsCurrent {
		if currentSessIDTyped, ok := currentSessionIDStr.(string); ok {
			if sessionIDToDeleteStr == currentSessIDTyped {
				h.logger.Warn("DeleteMySession: attempt to delete current session", zap.String("sessionID", sessionIDToDeleteStr))
				c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot revoke the current session using this endpoint. Please use /logout."})
				return
			}
		}
	}

	// Ownership Check
	sessionToRevoke, err := h.sessionService.GetSessionByID(c.Request.Context(), sessionIDToDelete)
	if err != nil {
		if errors.Is(err, domainErrors.ErrSessionNotFound) {
			h.logger.Warn("DeleteMySession: session not found", zap.String("sessionIDToDelete", sessionIDToDeleteStr), zap.Error(err))
			c.JSON(http.StatusNotFound, gin.H{"error": "Session not found."})
			return
		}
		h.logger.Error("DeleteMySession: failed to get session for ownership check", zap.Error(err), zap.String("sessionIDToDelete", sessionIDToDeleteStr))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve session information."})
		return
	}

	if sessionToRevoke.UserID != requestingUserID {
		h.logger.Warn("DeleteMySession: user attempted to delete session not belonging to them",
			zap.String("requestingUserID", requestingUserID.String()),
			zap.String("ownerUserID", sessionToRevoke.UserID.String()),
			zap.String("sessionIDToDelete", sessionIDToDeleteStr))
		c.JSON(http.StatusForbidden, gin.H{"error": "Forbidden: You can only revoke your own sessions."})
		return
	}

	// Deactivate (soft delete) the session
	err = h.sessionService.DeactivateSession(c.Request.Context(), sessionIDToDelete)
	if err != nil {
		// If service returns ErrSessionNotFound because it was already deleted, treat as success for idempotency.
		if errors.Is(err, domainErrors.ErrSessionNotFound) {
			h.logger.Info("DeleteMySession: Session already deactivated or not found during deactivation attempt.", zap.String("sessionID", sessionIDToDeleteStr))
			c.Status(http.StatusNoContent)
			return
		}
		h.logger.Error("DeleteMySession: sessionService.DeactivateSession failed", zap.Error(err), zap.String("sessionIDToDelete", sessionIDToDeleteStr))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke session."})
		return
	}

	c.Status(http.StatusNoContent)
}

// --- API Key Management Handlers ---

// CreateAPIKeyRequest defines the structure for creating a new API key.
type CreateAPIKeyRequest struct {
	Name      string     `json:"name" binding:"required,max=255"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"` // Optional expiration date
}

// APIKeyResponse defines the structure for an API key returned to the user.
// The Key field is only populated on creation.
type APIKeyResponse struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Key        *string    `json:"key,omitempty"` // Only present on creation
	KeyPrefix  string     `json:"key_prefix"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	// UserID     string     `json:"user_id"` // Typically not included in response to self
}

// ListAPIKeysResponse defines the structure for a list of API keys.
type ListAPIKeysResponse struct {
	Data []APIKeyResponse `json:"data"`
}

// GetMyAPIKeys handles fetching all API keys for the authenticated user.
// GET /me/api-keys
func (h *MeHandler) GetMyAPIKeys(c *gin.Context) {
	ctx := c.Request.Context()
	logger := h.logger.With(zap.String("handler", "GetMyAPIKeys"))

	userIDStr, exists := c.Get("userID")
	if !exists {
		logger.Error("UserID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized: User ID not found"})
		return
	}
	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		logger.Error("Failed to parse userID from context", zap.String("rawUserID", userIDStr.(string)), zap.Error(err))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized: Invalid User ID format"})
		return
	}
	logger = logger.With(zap.String("userID", userID.String()))

	keys, err := h.apiKeySvc.GetKeysByUserID(ctx, userID)
	if err != nil {
		logger.Error("Failed to get API keys by user ID", zap.Error(err))
		// Specific error handling can be added here if apiKeySvc returns distinct error types
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve API keys"})
		return
	}

	responseKeys := make([]APIKeyResponse, len(keys))
	for i, key := range keys {
		responseKeys[i] = APIKeyResponse{
			ID:         key.ID.String(),
			Name:       key.Name,
			KeyPrefix:  key.KeyPrefix,
			CreatedAt:  key.CreatedAt,
			ExpiresAt:  key.ExpiresAt,
			LastUsedAt: key.LastUsedAt,
			// Key: nil, // Key is never returned on list
		}
	}

	logger.Info("Successfully retrieved API keys", zap.Int("count", len(responseKeys)))
	c.JSON(http.StatusOK, ListAPIKeysResponse{Data: responseKeys})
}

// CreateMyAPIKey handles creating a new API key for the authenticated user.
// POST /me/api-keys
func (h *MeHandler) CreateMyAPIKey(c *gin.Context) {
	ctx := c.Request.Context()
	logger := h.logger.With(zap.String("handler", "CreateMyAPIKey"))

	userIDStr, exists := c.Get("userID")
	if !exists {
		logger.Error("UserID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized: User ID not found"})
		return
	}
	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		logger.Error("Failed to parse userID from context", zap.String("rawUserID", userIDStr.(string)), zap.Error(err))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized: Invalid User ID format"})
		return
	}
	logger = logger.With(zap.String("userID", userID.String()))

	var req CreateAPIKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Error("Failed to bind request JSON", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload: " + err.Error()})
		return
	}

	// Optional: Validate ExpiresAt is in the future if provided
	if req.ExpiresAt != nil && req.ExpiresAt.Before(time.Now()) {
		logger.Warn("Expiration date is in the past", zap.Timep("expires_at", req.ExpiresAt))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Expiration date cannot be in the past"})
		return
	}

	createdKey, fullKeyValue, err := h.apiKeySvc.CreateKey(ctx, userID, req.Name, req.ExpiresAt)
	if err != nil {
		logger.Error("Failed to create API key", zap.Error(err))
		if errors.Is(err, domainErrors.ErrLimitExceeded) { // Example of specific domain error
			c.JSON(http.StatusConflict, gin.H{"error": "API key limit reached"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create API key"})
		return
	}
	logger = logger.With(zap.String("apiKeyID", createdKey.ID.String()))

	response := APIKeyResponse{
		ID:         createdKey.ID.String(),
		Name:       createdKey.Name,
		Key:        &fullKeyValue, // Full key is returned ONLY on creation
		KeyPrefix:  createdKey.KeyPrefix,
		CreatedAt:  createdKey.CreatedAt,
		ExpiresAt:  createdKey.ExpiresAt,
		LastUsedAt: createdKey.LastUsedAt,
	}

	logger.Info("Successfully created API key")
	c.JSON(http.StatusCreated, response)
}

// DeleteMyAPIKey handles deleting a specific API key for the authenticated user.
// DELETE /me/api-keys/:key_id
func (h *MeHandler) DeleteMyAPIKey(c *gin.Context) {
	ctx := c.Request.Context()
	logger := h.logger.With(zap.String("handler", "DeleteMyAPIKey"))

	userIDStr, exists := c.Get("userID")
	if !exists {
		logger.Error("UserID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized: User ID not found"})
		return
	}
	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		logger.Error("Failed to parse userID from context", zap.String("rawUserID", userIDStr.(string)), zap.Error(err))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized: Invalid User ID format"})
		return
	}
	logger = logger.With(zap.String("userID", userID.String()))

	keyIDStr := c.Param("key_id")
	keyID, err := uuid.Parse(keyIDStr)
	if err != nil {
		logger.Error("Failed to parse key_id from path", zap.String("rawKeyID", keyIDStr), zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid API key ID format"})
		return
	}
	logger = logger.With(zap.String("apiKeyID", keyID.String()))

	err = h.apiKeySvc.DeleteKey(ctx, userID, keyID)
	if err != nil {
		logger.Error("Failed to delete API key", zap.Error(err))
		if errors.Is(err, domainErrors.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "API key not found or does not belong to user"})
			return
		}
		// If apiKeySvc.DeleteKey checks ownership and could return ErrForbidden:
		if errors.Is(err, domainErrors.ErrForbidden) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Forbidden: API key does not belong to user"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete API key"})
		return
	}

	logger.Info("Successfully deleted API key")
	c.Status(http.StatusNoContent)
}
