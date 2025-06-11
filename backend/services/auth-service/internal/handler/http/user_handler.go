// File: internal/handler/http/user_handler.go

package http

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/service"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/utils/validator"
	"go.uber.org/zap"
)

// UserHandler обрабатывает HTTP-запросы, связанные с пользователями, включая /me scope.
type UserHandler struct {
	userService     *service.UserService
	authService     *service.AuthService          // For ChangePassword
	sessionService  *service.SessionService       // For session management
	mfaLogicService domainService.MFALogicService // Added for 2FA management
	apiKeyService   domainService.APIKeyService   // Added for API key management (interface)
	logger          *zap.Logger
}

// NewUserHandler создает новый экземпляр UserHandler
func NewUserHandler(
	userService *service.UserService,
	authService *service.AuthService,
	sessionService *service.SessionService,
	mfaLogicService domainService.MFALogicService, // Added
	apiKeyService domainService.APIKeyService, // Added
	logger *zap.Logger,
) *UserHandler {
	return &UserHandler{
		userService:     userService,
		authService:     authService,
		sessionService:  sessionService,
		mfaLogicService: mfaLogicService, // Added
		apiKeyService:   apiKeyService,   // Added
		logger:          logger.Named("user_handler"),
	}
}

// handleError обрабатывает ошибки и возвращает соответствующий HTTP-ответ
func (h *UserHandler) handleError(c *gin.Context, err error) {
	h.logger.Error("Error in user handler", zap.Error(err))

	status := http.StatusInternalServerError
	errMsg := "Internal server error"
	errCode := "internal_error"

	switch {
	case err == nil:
		return
	case err == models.ErrUserNotFound:
		status = http.StatusNotFound
		errMsg = "User not found"
		errCode = "user_not_found"
	case err == models.ErrInvalidCredentials:
		status = http.StatusUnauthorized
		errMsg = "Invalid credentials"
		errCode = "invalid_credentials"
	case err == models.ErrEmailExists:
		status = http.StatusConflict
		errMsg = "Email already exists"
		errCode = "email_exists"
	case err == models.ErrUsernameExists:
		status = http.StatusConflict
		errMsg = "Username already exists"
		errCode = "username_exists"
	case err == models.ErrUserBlocked:
		status = http.StatusForbidden
		errMsg = "User is blocked"
		errCode = "user_blocked"
	// Add other domain errors as needed
	case errors.Is(err, domainErrors.ErrUserLockedOut):
		status = http.StatusForbidden
		errMsg = "User account is temporarily locked"
		errCode = "user_locked_out"
	case errors.Is(err, domainErrors.ErrEmailNotVerified):
		status = http.StatusForbidden
		errMsg = "Email not verified"
		errCode = "email_not_verified"
	}

	c.JSON(status, gin.H{
		"error": errMsg,
		"code":  errCode,
	})
}

// ListSessions handles listing active sessions for the current user.
// GET /me/sessions
func (h *UserHandler) ListSessions(c *gin.Context) {
	userIDStr, exists := c.Get(middleware.GinContextUserIDKey)
	if !exists {
		ErrorResponse(c.Writer, h.logger, http.StatusUnauthorized, "User not authenticated", nil)
		return
	}
	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid user ID in context", err)
		return
	}

	// Prepare params for listing (e.g., active only, pagination if needed)
	// For now, list all, activeOnly true by default in service or repo if not specified.
	// The SessionService.GetUserSessions expects ListSessionsParams
	listParams := models.ListSessionsParams{ActiveOnly: true, PageSize: 100, Page: 1} // Example params

	sessions, totalCount, err := h.sessionService.GetUserSessions(c.Request.Context(), userID, listParams)
	if err != nil {
		h.handleError(c, err) // Use existing handleError or a more specific one
		return
	}

	// Convert []*models.Session to []models.SessionResponse
	sessionResponses := make([]models.SessionResponse, len(sessions))
	for i, s := range sessions {
		sessionResponses[i] = s.ToResponse()
	}

	SuccessResponse(c.Writer, h.logger, http.StatusOK, gin.H{
		"sessions":    sessionResponses,
		"total_count": totalCount,
		"page":        listParams.Page,
		"page_size":   listParams.PageSize,
	})
}

// RevokeSession handles revoking a specific session for the current user.
// DELETE /me/sessions/:session_id
func (h *UserHandler) RevokeSession(c *gin.Context) {
	userIDStr, exists := c.Get(middleware.GinContextUserIDKey)
	if !exists {
		ErrorResponse(c.Writer, h.logger, http.StatusUnauthorized, "User not authenticated", nil)
		return
	}
	currentUserID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid user ID in context", err)
		return
	}

	sessionIDToRevokeStr := c.Param("session_id")
	sessionIDToRevoke, err := uuid.Parse(sessionIDToRevokeStr)
	if err != nil {
		ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid session ID format", err)
		return
	}

	// Service layer should verify ownership: does sessionIDToRevoke belong to currentUserID?
	// SessionService.DeactivateSession (now Delete in repo) needs this check or a dedicated method.
	// For now, assume SessionService.DeactivateUserSession(ctx, userID, sessionID) exists.
	// Let's use a conceptual method on AuthService for this, or SessionService needs to be enhanced.
	// Current SessionService.DeactivateSession only takes sessionID.
	// This requires a change in SessionService or its repository to check ownership.
	// For now, let's assume a direct call to a method that implies ownership check or is specific.

	// Fetch the session first to check ownership
	session, err := h.sessionService.GetSession(c.Request.Context(), sessionIDToRevoke)
	if err != nil {
		if errors.Is(err, domainErrors.ErrSessionNotFound) {
			ErrorResponse(c.Writer, h.logger, http.StatusNotFound, "Session not found", err)
		} else {
			ErrorResponse(c.Writer, h.logger, http.StatusInternalServerError, "Failed to retrieve session", err)
		}
		return
	}

	if session.UserID != currentUserID {
		ErrorResponse(c.Writer, h.logger, http.StatusForbidden, "Cannot revoke session belonging to another user", nil)
		return
	}

	// DeactivateSession now effectively deletes the session record.
	// It also needs to ensure the corresponding refresh token is dealt with.
	// This might be better handled by AuthService orchestrating SessionService and TokenService.
	// For now, direct call to SessionService.DeactivateSession:
	err = h.sessionService.DeactivateSession(c.Request.Context(), sessionIDToRevoke)
	if err != nil {
		// DeactivateSession might return ErrNotFound if already gone, which is fine.
		if !errors.Is(err, domainErrors.ErrSessionNotFound) {
			ErrorResponse(c.Writer, h.logger, http.StatusInternalServerError, "Failed to revoke session", err)
			return
		}
	}

	SuccessResponse(c.Writer, h.logger, http.StatusNoContent, nil)
}

// --- 2FA Management Handlers ---

// Enable2FAInitiate handles the request to start enabling TOTP 2FA.
// POST /me/2fa/totp/enable
func (h *UserHandler) Enable2FAInitiate(c *gin.Context) {
	userIDStr, exists := c.Get(middleware.GinContextUserIDKey)
	if !exists {
		ErrorResponse(c.Writer, h.logger, http.StatusUnauthorized, "User not authenticated", nil)
		return
	}
	userID, _ := uuid.Parse(userIDStr.(string)) // Error handling for parse already in middleware/previous Get

	// Fetch user details to get email or username for accountName in TOTP
	// Assuming UserService has a method to get basic user info.
	// Or, if claims from AuthMiddleware contain email/username, use that.
	claims, claimsExists := c.Get(middleware.GinContextClaimsKey)
	var accountName string
	if claimsExists {
		if jwtClaims, ok := claims.(*domainService.Claims); ok { // Using Claims from domainService
			accountName = jwtClaims.Username // Or Email
		}
	}
	if accountName == "" { // Fallback if not in claims or if a fresh fetch is preferred
		userDetails, err := h.userService.GetUserByID(c.Request.Context(), userID) // Assuming GetUserByID exists on UserService
		if err != nil {
			ErrorResponse(c.Writer, h.logger, http.StatusInternalServerError, "Failed to retrieve user details", err)
			return
		}
		accountName = userDetails.Email // Or Username
	}

	mfaSecretID, secretBase32, otpAuthURL, err := h.mfaLogicService.Enable2FAInitiate(c.Request.Context(), userID, accountName)
	if err != nil {
		if errors.Is(err, domainErrors.Err2FAAlreadyEnabled) {
			ErrorResponse(c.Writer, h.logger, http.StatusConflict, err.Error(), err)
		} else {
			ErrorResponse(c.Writer, h.logger, http.StatusInternalServerError, "Failed to initiate 2FA enablement", err)
		}
		return
	}

	SuccessResponse(c.Writer, h.logger, http.StatusOK, models.Enable2FAInitiateResponse{
		MFASecretID: mfaSecretID.String(),
		SecretKey:   secretBase32, // This is the key for manual entry
		QRCodeImage: otpAuthURL,   // This is the otpauth:// URL for QR code
	})
}

// VerifyAndActivate2FA handles verification of TOTP code and activation of 2FA.
// POST /me/2fa/totp/verify
func (h *UserHandler) VerifyAndActivate2FA(c *gin.Context) {
	userIDStr, exists := c.Get(middleware.GinContextUserIDKey)
	if !exists {
		ErrorResponse(c.Writer, h.logger, http.StatusUnauthorized, "User not authenticated", nil)
		return
	}
	userID, _ := uuid.Parse(userIDStr.(string))

	var req models.Verify2FARequest // This DTO now has MFASecretID and TOTPCode
	if err := c.ShouldBindJSON(&req); err != nil {
		ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid request payload", err)
		return
	}

	mfaSecretID, err := uuid.Parse(req.MFASecretID)
	if err != nil {
		ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid mfa_secret_id format", err)
		return
	}

	backupCodes, err := h.mfaLogicService.VerifyAndActivate2FA(c.Request.Context(), userID, req.TOTPCode, mfaSecretID)
	if err != nil {
		if errors.Is(err, domainErrors.ErrInvalid2FACode) {
			ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid TOTP code", err)
		} else if errors.Is(err, domainErrors.Err2FAAlreadyEnabled) {
			ErrorResponse(c.Writer, h.logger, http.StatusConflict, "2FA already enabled and verified", err)
		} else if errors.Is(err, domainErrors.ErrForbidden) { // e.g. MFA secret mismatch
			ErrorResponse(c.Writer, h.logger, http.StatusForbidden, "MFA secret does not belong to user", err)
		} else {
			ErrorResponse(c.Writer, h.logger, http.StatusInternalServerError, "Failed to verify and activate 2FA", err)
		}
		return
	}

	SuccessResponse(c.Writer, h.logger, http.StatusOK, models.VerifyAndActivate2FAResponse{
		Message:     "2FA enabled successfully. Please save your backup codes securely.",
		BackupCodes: backupCodes,
	})
}

// Disable2FA handles disabling 2FA for the current user.
// POST /me/2fa/disable
func (h *UserHandler) Disable2FA(c *gin.Context) {
	userIDStr, exists := c.Get(middleware.GinContextUserIDKey)
	if !exists {
		ErrorResponse(c.Writer, h.logger, http.StatusUnauthorized, "User not authenticated", nil)
		return
	}
	userID, _ := uuid.Parse(userIDStr.(string))

	var req models.Disable2FARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid request payload", err)
		return
	}

	err := h.mfaLogicService.Disable2FA(c.Request.Context(), userID, req.VerificationToken, req.VerificationMethod)
	if err != nil {
		if errors.Is(err, domainErrors.ErrForbidden) || errors.Is(err, domainErrors.ErrInvalidCredentials) || errors.Is(err, domainErrors.ErrInvalid2FACode) {
			ErrorResponse(c.Writer, h.logger, http.StatusForbidden, "Disabling 2FA failed: verification failed", err)
		} else if errors.Is(err, domainErrors.Err2FANotEnabled) {
			ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "2FA is not currently enabled for this account.", err)
		} else {
			ErrorResponse(c.Writer, h.logger, http.StatusInternalServerError, "Failed to disable 2FA", err)
		}
		return
	}
	SuccessResponse(c.Writer, h.logger, http.StatusOK, gin.H{"message": "2FA disabled successfully."})
}

// RegenerateBackupCodes handles regenerating backup codes for 2FA.
// POST /me/2fa/backup-codes/regenerate
func (h *UserHandler) RegenerateBackupCodes(c *gin.Context) {
	userIDStr, exists := c.Get(middleware.GinContextUserIDKey)
	if !exists {
		ErrorResponse(c.Writer, h.logger, http.StatusUnauthorized, "User not authenticated", nil)
		return
	}
	userID, _ := uuid.Parse(userIDStr.(string))

	var req models.RegenerateBackupCodesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid request payload", err)
		return
	}

	backupCodes, err := h.mfaLogicService.RegenerateBackupCodes(c.Request.Context(), userID, req.VerificationToken, req.VerificationMethod)
	if err != nil {
		if errors.Is(err, domainErrors.ErrForbidden) || errors.Is(err, domainErrors.ErrInvalidCredentials) || errors.Is(err, domainErrors.ErrInvalid2FACode) {
			ErrorResponse(c.Writer, h.logger, http.StatusForbidden, "Backup code regeneration failed: verification failed", err)
		} else if errors.Is(err, domainErrors.Err2FANotEnabled) { // Or if 2FA not active
			ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "2FA is not active for this account.", err)
		} else {
			ErrorResponse(c.Writer, h.logger, http.StatusInternalServerError, "Failed to regenerate backup codes", err)
		}
		return
	}
	SuccessResponse(c.Writer, h.logger, http.StatusOK, models.RegenerateBackupCodesResponse{
		Message:     "New backup codes generated successfully. Please save them securely.",
		BackupCodes: backupCodes,
	})
}

// ListAPIKeys handles listing API keys for the current user.
// GET /me/api-keys
func (h *UserHandler) ListAPIKeys(c *gin.Context) {
	userIDStr, exists := c.Get(middleware.GinContextUserIDKey)
	if !exists {
		ErrorResponse(c.Writer, h.logger, http.StatusUnauthorized, "User not authenticated", nil)
		return
	}
	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid user ID in context", err)
		return
	}

	apiKeys, err := h.apiKeyService.ListUserAPIKeys(c.Request.Context(), userID)
	if err != nil {
		h.logger.Error("Failed to list API keys", zap.Error(err), zap.String("userID", userID.String()))
		ErrorResponse(c.Writer, h.logger, http.StatusInternalServerError, "Failed to retrieve API keys", err)
		return
	}

	responses := make([]models.APIKeyResponse, len(apiKeys))
	for i, key := range apiKeys {
		responses[i] = key.ToResponse()
	}
	SuccessResponse(c.Writer, h.logger, http.StatusOK, responses)
}

// CreateAPIKey handles creating a new API key for the current user.
// POST /me/api-keys
func (h *UserHandler) CreateAPIKey(c *gin.Context) {
	userIDStr, exists := c.Get(middleware.GinContextUserIDKey)
	if !exists {
		ErrorResponse(c.Writer, h.logger, http.StatusUnauthorized, "User not authenticated", nil)
		return
	}
	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid user ID in context", err)
		return
	}

	var req models.CreateAPIKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid request payload for CreateAPIKey", err)
		return
	}

	// TODO: Validate permissions in req.Permissions if they need to conform to a predefined set

	apiKeyModel, plainFullAPIKey, err := h.apiKeyService.CreateAPIKey(c.Request.Context(), userID, req)
	if err != nil {
		h.logger.Error("Failed to create API key", zap.Error(err), zap.String("userID", userID.String()))
		if errors.Is(err, domainErrors.ErrDuplicateValue) { // Example of specific error handling
			ErrorResponse(c.Writer, h.logger, http.StatusConflict, "Failed to create API key due to conflict", err)
		} else {
			ErrorResponse(c.Writer, h.logger, http.StatusInternalServerError, "Failed to create API key", err)
		}
		return
	}

	response := models.APIKeyCreateResponse{
		APIKeyMetadata: apiKeyModel.ToResponse(),
		PlainAPIKey:    plainFullAPIKey,
	}
	SuccessResponse(c.Writer, h.logger, http.StatusCreated, response)
}

// DeleteAPIKey handles deleting an API key for the current user.
// DELETE /me/api-keys/:key_id
func (h *UserHandler) DeleteAPIKey(c *gin.Context) {
	userIDStr, exists := c.Get(middleware.GinContextUserIDKey)
	if !exists {
		ErrorResponse(c.Writer, h.logger, http.StatusUnauthorized, "User not authenticated", nil)
		return
	}
	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid user ID in context", err)
		return
	}

	keyIDStr := c.Param("key_id")
	keyID, err := uuid.Parse(keyIDStr)
	if err != nil {
		ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid API key ID format", err)
		return
	}

	err = h.apiKeyService.DeleteAPIKey(c.Request.Context(), userID, keyID)
	if err != nil {
		if errors.Is(err, domainErrors.ErrNotFound) {
			ErrorResponse(c.Writer, h.logger, http.StatusNotFound, "API key not found or not owned by user", err)
		} else if errors.Is(err, domainErrors.ErrForbidden) {
			ErrorResponse(c.Writer, h.logger, http.StatusForbidden, "User not authorized to delete this API key", err)
		} else {
			h.logger.Error("Failed to delete API key", zap.Error(err), zap.String("userID", userID.String()), zap.String("keyID", keyIDStr))
			ErrorResponse(c.Writer, h.logger, http.StatusInternalServerError, "Failed to delete API key", err)
		}
		return
	}
	SuccessResponse(c.Writer, h.logger, http.StatusNoContent, nil)
}
