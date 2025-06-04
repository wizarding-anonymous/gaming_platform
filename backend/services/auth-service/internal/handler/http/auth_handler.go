package http

import (
	"errors"
	"net/http"
	"time" // For time.Now() in one of the handlers, can be removed if not strictly needed here

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/your-org/auth-service/internal/config"
	"github.com/your-org/auth-service/internal/domain/models"
	domainErrors "github.com/your-org/auth-service/internal/domain/errors"
	domainService "github.com/your-org/auth-service/internal/domain/service"
	"github.com/your-org/auth-service/internal/service" // For concrete AuthService
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
	var req models.CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid request payload", err)
		return
	}

	user, verificationTokenPlain, err := h.authService.Register(c.Request.Context(), req)
	if err != nil {
		h.logger.Error("RegisterUser: service error", zap.Error(err))
		if errors.Is(err, domainErrors.ErrEmailExists) || errors.Is(err, domainErrors.ErrUsernameExists) {
			ErrorResponse(c.Writer, h.logger, http.StatusConflict, err.Error(), err)
		} else {
			ErrorResponse(c.Writer, h.logger, http.StatusInternalServerError, "Failed to register user", err)
		}
		return
	}
	h.logger.Info("User registration successful, verification token generated (for out-of-band delivery)",
		zap.String("userID", user.ID.String()),
		zap.String("verificationToken_DEV_ONLY", verificationTokenPlain),
	)
	SuccessResponse(c.Writer, h.logger, http.StatusCreated, gin.H{
		"message": "User registered successfully. Please check your email to verify your account.",
		"user":    user.ToResponse(),
	})
}

// LoginUser handles user login.
// POST /api/v1/auth/login
func (h *AuthHandler) LoginUser(c *gin.Context) {
	var req models.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid request payload", err)
		return
	}

	tokenPair, user, challengeToken, err := h.authService.Login(c.Request.Context(), req)
	if err != nil {
		if errors.Is(err, domainErrors.Err2FARequired) {
			h.logger.Info("2FA required for user", zap.String("email", req.Email))
			c.JSON(http.StatusAccepted, gin.H{
				"message":         "2FA_required",
				"user_id":         user.ID,
				"challenge_token": challengeToken,
			})
			return
		}
		if errors.Is(err, domainErrors.ErrInvalidCredentials) || errors.Is(err, domainErrors.ErrUserNotFound) {
			ErrorResponse(c.Writer, h.logger, http.StatusUnauthorized, "Invalid credentials", err)
		} else if errors.Is(err, domainErrors.ErrUserBlocked) {
			ErrorResponse(c.Writer, h.logger, http.StatusForbidden, "User account is blocked", err)
		} else if errors.Is(err, domainErrors.ErrUserLockedOut) {
			ErrorResponse(c.Writer, h.logger, http.StatusForbidden, "User account is temporarily locked", err)
		} else if errors.Is(err, domainErrors.ErrEmailNotVerified) {
			ErrorResponse(c.Writer, h.logger, http.StatusForbidden, "Email not verified", err)
		} else {
			ErrorResponse(c.Writer, h.logger, http.StatusInternalServerError, "Login failed", err)
		}
		return
	}

	SuccessResponse(c.Writer, h.logger, http.StatusOK, gin.H{
		"user":   user.ToResponse(),
		"tokens": tokenPair,
	})
}

// TelegramLogin handles user login/registration via Telegram data.
// POST /api/v1/auth/telegram-login
func (h *AuthHandler) TelegramLogin(c *gin.Context) {
	var req models.TelegramLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid request payload for Telegram login", err)
		return
	}

	deviceInfo := map[string]string{ // Basic device info
		"user_agent": c.Request.UserAgent(),
		"ip_address": c.ClientIP(),
	}

	// Assuming AuthService has a method LoginWithTelegram
	// LoginWithTelegram(ctx context.Context, tgData models.TelegramLoginRequest, deviceInfo map[string]string) (*models.TokenPair, *models.User, error)
	tokenPair, user, err := h.authService.LoginWithTelegram(c.Request.Context(), req, deviceInfo)
	if err != nil {
		// Use more specific domain errors if available from the service layer
		if errors.Is(err, domainErrors.ErrTelegramAuthFailed) {
			ErrorResponse(c.Writer, h.logger, http.StatusUnauthorized, "Telegram authentication failed: invalid hash or old data", err)
		} else if errors.Is(err, domainErrors.ErrUserBlocked) {
			ErrorResponse(c.Writer, h.logger, http.StatusForbidden, "User account is blocked", err)
		} else if errors.Is(err, domainErrors.ErrInvalidRequest) { // e.g. if auth_date is too old
			ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid Telegram data", err)
		} else {
			ErrorResponse(c.Writer, h.logger, http.StatusInternalServerError, "Telegram login processing failed", err)
		}
		return
	}

	SuccessResponse(c.Writer, h.logger, http.StatusOK, gin.H{
		"user":   user.ToResponse(),
		"tokens": tokenPair,
	})
}

// VerifyLogin2FA handles the second factor of authentication during login.
// POST /api/v1/auth/login/2fa/verify
func (h *AuthHandler) VerifyLogin2FA(c *gin.Context) {
	var req models.Login2FARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid 2FA verification payload", err)
		return
	}

	userIDStr, err := h.tokenManagementService.Validate2FAChallengeToken(req.ChallengeToken)
	if err != nil {
		ErrorResponse(c.Writer, h.logger, http.StatusUnauthorized, "Invalid or expired challenge token", err)
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		ErrorResponse(c.Writer, h.logger, http.StatusInternalServerError, "Invalid user ID in challenge token", err)
		return
	}

	mfaType := models.MFAType(req.Method)
	if mfaType != models.MFATypeTOTP && req.Method != "backup" {
		ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid 2FA method", nil)
		return
	}

	isValid, err := h.mfaLogicService.Verify2FACode(c.Request.Context(), userID, req.Code, mfaType)
	if err != nil {
		// Log the specific error from mfaLogicService for internal review
		h.logger.Error("Error during 2FA code verification", zap.Error(err), zap.String("userID", userID.String()), zap.String("method", req.Method))
		ErrorResponse(c.Writer, h.logger, http.StatusInternalServerError, "Error verifying 2FA code", nil) // Generic to client
		return
	}
	if !isValid {
		ErrorResponse(c.Writer, h.logger, http.StatusUnauthorized, "Invalid 2FA code", nil)
		return
	}

	deviceInfo := map[string]string{
		"user_agent": c.Request.UserAgent(),
		"ip_address": c.ClientIP(),
	}

	tokenPair, user, err := h.authService.CompleteLoginAfter2FA(c.Request.Context(), userID, deviceInfo)
	if err != nil {
		ErrorResponse(c.Writer, h.logger, http.StatusInternalServerError, "Failed to complete login after 2FA", err)
		return
	}

	SuccessResponse(c.Writer, h.logger, http.StatusOK, gin.H{
		"user":   user.ToResponse(),
		"tokens": tokenPair,
	})
}


// --- OAuth 2.0 Handlers ---

// OAuthLogin initiates the OAuth 2.0 login flow by redirecting the user to the provider.
// GET /api/v1/auth/oauth/{provider}
func (h *AuthHandler) OAuthLogin(c *gin.Context) {
	provider := c.Param("provider")
	clientRedirectURI := c.Query("redirect_uri") // Optional: client can specify where to be redirected after our callback
	clientState := c.Query("state")             // Optional: client can pass its own state

	// Service generates the actual auth URL and might store state/redirect_uri in a cookie
	authURL, err := h.authService.InitiateOAuthLogin(c.Request.Context(), provider, clientRedirectURI, clientState)
	if err != nil {
		if errors.Is(err, domainErrors.ErrUnsupportedOAuthProvider) {
			ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Unsupported OAuth provider", err)
		} else {
			ErrorResponse(c.Writer, h.logger, http.StatusInternalServerError, "Failed to initiate OAuth login", err)
		}
		return
	}

	// Store state in a short-lived, secure cookie if not handled by service directly
	// For now, assume service handles state storage if needed (e.g., via server-side session or signed state in URL)
	// http.SetCookie(c.Writer, &http.Cookie{...})

	c.Redirect(http.StatusTemporaryRedirect, authURL)
}

// OAuthCallback handles the callback from the OAuth 2.0 provider.
// GET /api/v1/auth/oauth/{provider}/callback
func (h *AuthHandler) OAuthCallback(c *gin.Context) {
	provider := c.Param("provider")
	code := c.Query("code")
	state := c.Query("state") // State from provider
	providerError := c.Query("error")
	errorDescription := c.Query("error_description")

	if providerError != "" {
		h.logger.Warn("OAuth callback error from provider",
			zap.String("provider", provider),
			zap.String("error", providerError),
			zap.String("description", errorDescription),
		)
		// Redirect to a frontend error page or return JSON
		ErrorResponse(c.Writer, h.logger, http.StatusUnauthorized, fmt.Sprintf("OAuth provider error: %s", errorDescription), errors.New(providerError))
		return
	}

	if code == "" {
		ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Authorization code missing in OAuth callback", nil)
		return
	}

	// State validation should occur within AuthService.HandleOAuthCallback

	deviceInfo := map[string]string{
		"user_agent": c.Request.UserAgent(),
		"ip_address": c.ClientIP(),
	}

	tokenPair, user, err := h.authService.HandleOAuthCallback(c.Request.Context(), provider, code, state, deviceInfo)
	if err != nil {
		if errors.Is(err, domainErrors.ErrOAuthStateMismatch) || errors.Is(err, domainErrors.ErrInvalidRequest) {
			ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "OAuth callback error: invalid state or request", err)
		} else if errors.Is(err, domainErrors.ErrUserBlocked) {
			ErrorResponse(c.Writer, h.logger, http.StatusForbidden, "User account is blocked", err)
		} else {
			ErrorResponse(c.Writer, h.logger, http.StatusInternalServerError, "OAuth callback processing failed", err)
		}
		return
	}

	// On success, typically redirect to frontend with tokens in query/fragment, or set cookies.
	// For API consistency with /login, returning JSON.
	SuccessResponse(c.Writer, h.logger, http.StatusOK, gin.H{
		"user":   user.ToResponse(),
		"tokens": tokenPair,
	})
}


// Placeholder for other handlers from the old router.go that would need similar refactoring:
// Enable2FA, VerifyAndActivate2FAHandler, Disable2FAHandler, RegenerateBackupCodesHandler (new MFA handlers)


// RefreshToken handles token refresh requests.
// POST /api/v1/auth/refresh-token
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req models.RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid request payload", err)
		return
	}

	tokenPair, err := h.authService.RefreshToken(c.Request.Context(), req.RefreshToken)
	if err != nil {
		if errors.Is(err, domainErrors.ErrInvalidRefreshToken) || errors.Is(err, domainErrors.ErrSessionNotFound) || errors.Is(err, domainErrors.ErrUserNotFound) {
			ErrorResponse(c.Writer, h.logger, http.StatusUnauthorized, "Invalid or expired refresh token", err)
		} else {
			ErrorResponse(c.Writer, h.logger, http.StatusInternalServerError, "Failed to refresh token", err)
		}
		return
	}
	SuccessResponse(c.Writer, h.logger, http.StatusOK, tokenPair)
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
