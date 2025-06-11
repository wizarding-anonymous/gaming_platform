// File: backend/services/auth-service/internal/handler/http/auth_handler.go
package http

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time" // For time.Now() in one of the handlers, can be removed if not strictly needed here

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/config"
	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	domainService "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/service"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/service" // For concrete AuthService
)

// AuthHandler handles core authentication HTTP requests.
type AuthHandler struct {
	logger                 *zap.Logger
	authService            *service.AuthService // Using concrete AuthService
	mfaLogicService        domainService.MFALogicService
	tokenManagementService domainService.TokenManagementService
	cfg                    *config.Config
}

// NewAuthHandler creates a new AuthHandler.
func NewAuthHandler(
	logger *zap.Logger,
	authService *service.AuthService,
	mfaLogicService domainService.MFALogicService,
	tokenManagementService domainService.TokenManagementService,
	cfg *config.Config,
	// Placeholder for other services that were in the old router.go, add if needed:
	// tokenService *service.TokenService, (old one, now part of authService or replaced by tokenManagementService)
	// sessionService *service.SessionService, (now part of authService)
	// twoFactorService *service.TwoFactorService, (replaced by mfaLogicService)
	// telegramService *service.TelegramService,
) *AuthHandler {
	return &AuthHandler{
		logger:                 logger.Named("auth_handler"),
		authService:            authService,
		mfaLogicService:        mfaLogicService,
		tokenManagementService: tokenManagementService,
		cfg:                    cfg,
	}
}

// RegisterUser handles user registration.
// POST /api/v1/auth/register
func (h *AuthHandler) RegisterUser(c *gin.Context) {
	var req models.RegisterRequest // Changed to models.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid request payload", err)
		return
	}

	// Assuming AuthService.Register now returns (user *models.User, tokenPair *models.TokenPair, err error)
	// And the verification token step is handled within AuthService or a subsequent flow.
	user, tokenPair, err := h.authService.Register(c.Request.Context(), req) // Pass models.RegisterRequest
	if err != nil {
		h.logger.Error("RegisterUser: service error", zap.Error(err), zap.String("username", req.Username), zap.String("email", req.Email))
		if errors.Is(err, domainErrors.ErrEmailExists) || errors.Is(err, domainErrors.ErrUsernameExists) {
			ErrorResponse(c.Writer, h.logger, http.StatusConflict, err.Error(), err)
		} else if errors.Is(err, domainErrors.ErrInvalidCaptcha) {
			ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, domainErrors.ErrInvalidCaptcha.Error(), err)
		} else if errors.Is(err, domainErrors.ErrPasswordPwned) {
			// Using 422 Unprocessable Entity as password itself is valid but pwned
			ErrorResponse(c.Writer, h.logger, http.StatusUnprocessableEntity, domainErrors.ErrPasswordPwned.Error(), err)
		} else {
			ErrorResponse(c.Writer, h.logger, http.StatusInternalServerError, "Failed to register user", err)
		}
		return
	}

	// If registration implies immediate login (which the new Register signature suggests by returning TokenPair)
	h.logger.Info("User registration successful and logged in", zap.String("userID", user.ID.String()))

	// SetAuthCookies(c, tokenPair.AccessToken, tokenPair.RefreshToken, h.cfg.JWT.AccessTokenTTL, h.cfg.JWT.RefreshTokenTTL)

	SuccessResponse(c.Writer, h.logger, http.StatusCreated, gin.H{
		"message": "User registered successfully.", // Simplified message if tokens are returned
		"user":    user.ToResponse(),
		"tokens":  tokenPair, // Return tokens if registration logs the user in
	})
}

// VerifyEmail handles email verification requests.
// POST /api/v1/auth/verify-email
func (h *AuthHandler) VerifyEmail(c *gin.Context) {
	var req models.VerifyEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid request payload", err)
		return
	}

	err := h.authService.VerifyEmail(c.Request.Context(), req.Token)
	if err != nil {
		if errors.Is(err, domainErrors.ErrInvalidToken) {
			ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid or expired verification token", err)
		} else if errors.Is(err, domainErrors.ErrEmailAlreadyVerified) {
			ErrorResponse(c.Writer, h.logger, http.StatusConflict, "Email already verified", err)
		} else {
			ErrorResponse(c.Writer, h.logger, http.StatusInternalServerError, "Failed to verify email", err)
		}
		return
	}
	SuccessResponse(c.Writer, h.logger, http.StatusOK, gin.H{"message": "Email verified successfully"})
}

// ResendVerificationEmail handles requests to resend the email verification link.
// POST /api/v1/auth/resend-verification
func (h *AuthHandler) ResendVerificationEmail(c *gin.Context) {
	var req models.ResendVerificationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid request payload", err)
		return
	}
	err := h.authService.ResendVerificationEmail(c.Request.Context(), req.Email)
	if err != nil {
		if errors.Is(err, domainErrors.ErrUserNotFound) {
			// Still return a generic success to prevent email enumeration
			SuccessResponse(c.Writer, h.logger, http.StatusOK, gin.H{"message": "If your email is registered and not verified, a new verification link has been sent."})
			return
		}
		if errors.Is(err, domainErrors.ErrEmailAlreadyVerified) {
			ErrorResponse(c.Writer, h.logger, http.StatusConflict, "Email already verified", err)
			return
		}
		ErrorResponse(c.Writer, h.logger, http.StatusInternalServerError, "Failed to resend verification email", err)
		return
	}
	SuccessResponse(c.Writer, h.logger, http.StatusOK, gin.H{"message": "If your email is registered and not verified, a new verification link has been sent."})
}

// ForgotPassword handles forgot password requests.
// POST /api/v1/auth/forgot-password
func (h *AuthHandler) ForgotPassword(c *gin.Context) {
	var req models.ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid request payload", err)
		return
	}
	// AuthService.ForgotPassword is designed to not reveal if user exists
	err := h.authService.ForgotPassword(c.Request.Context(), req.Email)
	if err != nil {
		// Log internal errors but return generic success to client
		h.logger.Error("ForgotPassword internal error", zap.Error(err), zap.String("email", req.Email))
	}
	SuccessResponse(c.Writer, h.logger, http.StatusOK, gin.H{"message": "If your email is registered, a password reset link has been sent."})
}

// ResetPassword handles password reset requests using a token.
// POST /api/v1/auth/reset-password
func (h *AuthHandler) ResetPassword(c *gin.Context) {
	var req models.ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid request payload", err)
		return
	}
	err := h.authService.ResetPassword(c.Request.Context(), req.Token, req.NewPassword)
	if err != nil {
		if errors.Is(err, domainErrors.ErrInvalidToken) {
			ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid or expired reset token", err)
		} else {
			ErrorResponse(c.Writer, h.logger, http.StatusInternalServerError, "Failed to reset password", err)
		}
		return
	}
	SuccessResponse(c.Writer, h.logger, http.StatusOK, gin.H{"message": "Password reset successfully."})
}

// Logout handles user logout.
// POST /api/v1/auth/logout
func (h *AuthHandler) Logout(c *gin.Context) {
	// Extract access token from header for blacklisting
	authHeader := c.GetHeader(middleware.AuthHeaderKey)
	parts := strings.Split(authHeader, " ")
	accessTokenString := ""
	if len(parts) == 2 && strings.ToLower(parts[0]) == strings.ToLower(middleware.AuthTypeBearer) {
		accessTokenString = parts[1]
	}

	var req models.LogoutRequest // Might contain refresh_token in body
	_ = c.ShouldBindJSON(&req)   // Ignore binding error, refresh_token is optional in body

	// UserID and SessionID should be available from AuthMiddleware if route is protected
	// For logout, we might not strictly need them if we only act on tokens.
	// However, AuthService.Logout might use them.
	// Let's assume AuthService.Logout handles cases where claims might not be fully available
	// if the access token itself is what's being revoked based on its JTI.

	err := h.authService.Logout(c.Request.Context(), accessTokenString, req.RefreshToken)
	if err != nil {
		ErrorResponse(c.Writer, h.logger, http.StatusInternalServerError, "Logout failed", err)
		return
	}
	SuccessResponse(c.Writer, h.logger, http.StatusNoContent, nil)
}

// LogoutAll handles logout from all user sessions.
// POST /api/v1/auth/logout-all
func (h *AuthHandler) LogoutAll(c *gin.Context) {
	accessTokenString := ""
	authHeader := c.GetHeader(middleware.AuthHeaderKey)
	parts := strings.Split(authHeader, " ")
	if len(parts) == 2 && strings.ToLower(parts[0]) == strings.ToLower(middleware.AuthTypeBearer) {
		accessTokenString = parts[1]
	}
	// If accessTokenString is empty, AuthService.LogoutAll should ideally handle it (e.g. error if auth is strictly required)

	err := h.authService.LogoutAll(c.Request.Context(), accessTokenString)
	if err != nil {
		if errors.Is(err, domainErrors.ErrInvalidToken) {
			ErrorResponse(c.Writer, h.logger, http.StatusUnauthorized, "Invalid access token", err)
		} else {
			ErrorResponse(c.Writer, h.logger, http.StatusInternalServerError, "Logout from all sessions failed", err)
		}
		return
	}
	SuccessResponse(c.Writer, h.logger, http.StatusNoContent, nil)
}

// Helper functions for standard responses
func SuccessResponse(w http.ResponseWriter, logger *zap.Logger, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if data != nil {
		if err := json.NewEncoder(w).Encode(data); err != nil {
			logger.Error("Failed to write success response", zap.Error(err))
		}
	}
}

func ErrorResponse(w http.ResponseWriter, logger *zap.Logger, statusCode int, message string, details error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	errPayload := gin.H{"error": message}
	if details != nil {
		// Log the full error for debugging
		logger.Debug("Error details for response", zap.Error(details))
		// Optionally include parts of the error details in the response if it's safe and useful
		// For example, if it's a validation error, details might be included.
		// For security, avoid exposing too much internal error detail.
		// Here, we just use the main error message.
	}
	if err := json.NewEncoder(w).Encode(errPayload); err != nil {
		logger.Error("Failed to write error response", zap.Error(err))
	}
}
