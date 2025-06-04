package http

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/gameplatform/auth-service/internal/domain/entity"
	"github.com/gameplatform/auth-service/internal/domain/service"
	// "github.com/go-playground/validator/v10"
)

// AuthHandler handles core authentication HTTP requests.
type AuthHandler struct {
	logger         *zap.Logger
	authLogicSvc   service.AuthLogicService
	mfaLogicSvc    service.MFALogicService
	tokenService   service.TokenService
	// validate       *validator.Validate
}

// NewAuthHandler creates a new AuthHandler.
func NewAuthHandler(
	logger *zap.Logger,
	authLogicSvc service.AuthLogicService,
	mfaLogicSvc service.MFALogicService,
	tokenService service.TokenService,
) *AuthHandler {
	return &AuthHandler{
		logger:       logger.Named("auth_handler"),
		authLogicSvc: authLogicSvc,
		mfaLogicSvc:  mfaLogicSvc,
		tokenService: tokenService,
		// validate:       validator.New(),
	}
}

// --- DTOs ---

type RegisterRequest struct {
	Username string `json:"username" binding:"required,min=3,max=50"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8,max=100"`
}

type UserResponse struct { 
	ID              string     `json:"id"`
	Username        string     `json:"username"`
	Email           string     `json:"email"`
	Status          string     `json:"status"`
	CreatedAt       time.Time  `json:"created_at"`
	EmailVerifiedAt *time.Time `json:"email_verified_at,omitempty"`
	LastLoginAt     *time.Time `json:"last_login_at,omitempty"`
	MFAEnabled      bool       `json:"mfa_enabled,omitempty"` 
}

type LoginRequest struct {
	LoginIdentifier string `json:"login_identifier" binding:"required"`
	Password        string `json:"password" binding:"required"`
}

type LoginResponse struct {
	User          *UserResponse `json:"user,omitempty"`
	AccessToken   string        `json:"access_token"`
	RefreshToken  string        `json:"refresh_token,omitempty"`
	TokenType     string        `json:"token_type"`
	ExpiresIn     int64         `json:"expires_in"`
	TwoFARequired bool          `json:"two_fa_required,omitempty"`
	UserIDFor2FA  string        `json:"user_id_for_2fa,omitempty"` 
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

type LogoutRequest struct { 
	RefreshToken string `json:"refresh_token,omitempty"`
}

type VerifyEmailRequest struct {
	Token string `json:"token" binding:"required"`
}

type ResendVerificationRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8,max=100"`
}

type Verify2FACodeLoginRequest struct {
	UserIDOrTempToken string `json:"user_id_or_temp_token" binding:"required"`
	Code              string `json:"code" binding:"required,len=6"` // Assuming 6-digit codes
	Method            string `json:"method,omitempty"`              // e.g., "totp", "backup_code"
}


// --- Handlers ---

func (h *AuthHandler) RegisterUser(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithError(c, http.StatusBadRequest, "Invalid request payload: "+err.Error())
		return
	}
	user, _, err := h.authLogicSvc.RegisterUser(c.Request.Context(), req.Username, req.Email, req.Password)
	if err != nil {
		h.logger.Error("RegisterUser: service error", zap.Error(err))
		if strings.Contains(err.Error(), "already exists") { 
			h.respondWithError(c, http.StatusConflict, err.Error())
		} else if strings.Contains(err.Error(), "validation failed") { 
			h.respondWithError(c, http.StatusBadRequest, err.Error())
		} else {
			h.respondWithError(c, http.StatusInternalServerError, "Failed to register user")
		}
		return
	}
	c.JSON(http.StatusCreated, gin.H{
		"message": "User registered successfully. Please check your email to verify your account.",
		"user": UserResponse{
			ID: user.ID, Username: user.Username, Email: user.Email,
			Status: string(user.Status), CreatedAt: user.CreatedAt,
		},
	})
}

func (h *AuthHandler) LoginUser(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithError(c, http.StatusBadRequest, "Invalid request payload: "+err.Error())
		return
	}
	deviceInfo := map[string]string{"ip_address": c.ClientIP(), "user_agent": c.Request.UserAgent()}

	user, accessToken, refreshToken, err := h.authLogicSvc.LoginUser(c.Request.Context(), req.LoginIdentifier, req.Password, deviceInfo)
	if err != nil {
		if err.Error() == "2FA_required" && user != nil { 
			c.JSON(http.StatusOK, LoginResponse{ 
				TwoFARequired: true,
				UserIDFor2FA:  user.ID, 
				AccessToken:   "",      
			})
			return
		}
		if strings.Contains(err.Error(), "invalid credentials") || strings.Contains(err.Error(), "not found") {
			h.respondWithError(c, http.StatusUnauthorized, "Invalid credentials")
		} else if strings.Contains(err.Error(), "blocked") || strings.Contains(err.Error(), "not active") || strings.Contains(err.Error(), "not verified") {
			h.respondWithError(c, http.StatusForbidden, err.Error())
		} else {
			h.logger.Error("LoginUser: service error", zap.Error(err), zap.String("login_id", req.LoginIdentifier))
			h.respondWithError(c, http.StatusInternalServerError, "Login failed")
		}
		return
	}

	accessTokenTTL := h.tokenService.GetAccessTokenExpiryDuration()
	c.JSON(http.StatusOK, LoginResponse{
		User: &UserResponse{
			ID: user.ID, Username: user.Username, Email: user.Email,
			Status: string(user.Status), CreatedAt: user.CreatedAt,
		},
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(accessTokenTTL.Seconds()),
	})
}

func (h *AuthHandler) RefreshTokenHandler(c *gin.Context) {
	var req RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithError(c, http.StatusBadRequest, "Invalid request: "+err.Error())
		return
	}
	deviceInfo := map[string]string{"ip_address": c.ClientIP(), "user_agent": c.Request.UserAgent()}
	
	newAccessToken, newRefreshToken, user, err := h.authLogicSvc.RefreshToken(c.Request.Context(), req.RefreshToken, deviceInfo)
	if err != nil {
		h.logger.Warn("RefreshToken: service error", zap.Error(err))
		if strings.Contains(err.Error(), "invalid") || strings.Contains(err.Error(), "expired") || strings.Contains(err.Error(), "not found") {
			h.respondWithError(c, http.StatusUnauthorized, "Invalid or expired refresh token")
		} else {
			h.respondWithError(c, http.StatusInternalServerError, "Failed to refresh token")
		}
		return
	}
	
	accessTokenTTL := h.tokenService.GetAccessTokenExpiryDuration()
	var userResp *UserResponse
	if user != nil { 
	    userResp = &UserResponse{ID: user.ID, Username: user.Username, Email: user.Email, Status: string(user.Status), CreatedAt: user.CreatedAt}
	}

	c.JSON(http.StatusOK, LoginResponse{
		User:         userResp,
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(accessTokenTTL.Seconds()),
	})
}

func (h *AuthHandler) LogoutHandler(c *gin.Context) {
	userIDVal, _ := c.Get("userID") 
	userID, _ := userIDVal.(string)
	
	sessionIDVal, _ := c.Get("sessionID") 
	sessionID, _ := sessionIDVal.(string)
	
	var req LogoutRequest 
	_ = c.ShouldBindJSON(&req) 

	err := h.authLogicSvc.LogoutUser(c.Request.Context(), userID, sessionID, req.RefreshToken)
	if err != nil {
		h.logger.Error("LogoutHandler: service error", zap.Error(err), zap.String("userID", userID))
		h.respondWithError(c, http.StatusInternalServerError, "Logout failed")
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *AuthHandler) VerifyEmailHandler(c *gin.Context) {
	var req VerifyEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithError(c, http.StatusBadRequest, "Invalid request: "+err.Error())
		return
	}
	err := h.authLogicSvc.VerifyEmailWithToken(c.Request.Context(), req.Token)
	if err != nil {
		if strings.Contains(err.Error(), "invalid or expired") || strings.Contains(err.Error(), "not found") {
			h.respondWithError(c, http.StatusBadRequest, err.Error())
		} else {
			h.logger.Error("VerifyEmailHandler: service error", zap.Error(err))
			h.respondWithError(c, http.StatusInternalServerError, "Email verification failed")
		}
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Email verified successfully."})
}

func (h *AuthHandler) ResendVerificationEmailHandler(c *gin.Context) {
	var req ResendVerificationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithError(c, http.StatusBadRequest, "Invalid request: "+err.Error())
		return
	}
	err := h.authLogicSvc.ResendVerificationEmail(c.Request.Context(), req.Email)
	if err != nil {
		if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "already verified") {
			h.respondWithError(c, http.StatusBadRequest, err.Error())
		} else {
			h.logger.Error("ResendVerificationEmailHandler: service error", zap.Error(err))
			h.respondWithError(c, http.StatusInternalServerError, "Failed to resend verification email")
		}
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Verification email sent. Please check your inbox."})
}

func (h *AuthHandler) ForgotPasswordHandler(c *gin.Context) {
	var req ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithError(c, http.StatusBadRequest, "Invalid request: "+err.Error())
		return
	}
	err := h.authLogicSvc.InitiatePasswordReset(c.Request.Context(), req.Email)
	if err != nil {
		h.logger.Error("ForgotPasswordHandler: service error", zap.Error(err))
	}
	c.JSON(http.StatusOK, gin.H{"message": "If an account with that email exists, a password reset link has been sent."})
}

func (h *AuthHandler) ResetPasswordHandler(c *gin.Context) {
	var req ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithError(c, http.StatusBadRequest, "Invalid request: "+err.Error())
		return
	}
	if len(req.NewPassword) < 8 { 
		h.respondWithError(c, http.StatusBadRequest, "New password is too short (minimum 8 characters)")
		return
	}

	err := h.authLogicSvc.ResetPasswordWithToken(c.Request.Context(), req.Token, req.NewPassword)
	if err != nil {
		if strings.Contains(err.Error(), "invalid or expired") || strings.Contains(err.Error(), "not found") {
			h.respondWithError(c, http.StatusBadRequest, err.Error())
		} else if strings.Contains(err.Error(), "weak") { 
			h.respondWithError(c, http.StatusBadRequest, err.Error())
		} else {
			h.logger.Error("ResetPasswordHandler: service error", zap.Error(err))
			h.respondWithError(c, http.StatusInternalServerError, "Password reset failed")
		}
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Password has been reset successfully."})
}

func (h *AuthHandler) Verify2FACodeLoginHandler(c *gin.Context) {
	var req Verify2FACodeLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithError(c, http.StatusBadRequest, "Invalid request: "+err.Error())
		return
	}

	codeType := req.Method
	if codeType == "" {
		codeType = "totp" 
	}

	isValid, err := h.mfaLogicSvc.Verify2FACode(c.Request.Context(), req.UserIDOrTempToken, req.Code, codeType)
	if err != nil || !isValid {
		h.logger.Warn("Verify2FACodeLoginHandler: MFA code verification failed", zap.Error(err), zap.String("identifier", req.UserIDOrTempToken))
		h.respondWithError(c, http.StatusUnauthorized, "Invalid 2FA code or method.")
		return
	}

	deviceInfo := map[string]string{"ip_address": c.ClientIP(), "user_agent": c.Request.UserAgent()}
	user, accessToken, refreshToken, err := h.authLogicSvc.CompleteLoginAfter2FA(c.Request.Context(), req.UserIDOrTempToken, deviceInfo)
	if err != nil {
		h.logger.Error("Verify2FACodeLoginHandler: CompleteLoginAfter2FA failed", zap.Error(err), zap.String("identifier", req.UserIDOrTempToken))
		h.respondWithError(c, http.StatusInternalServerError, "Failed to complete login after 2FA verification.")
		return
	}
	
	accessTokenTTL := h.tokenService.GetAccessTokenExpiryDuration()
	c.JSON(http.StatusOK, LoginResponse{
		User: &UserResponse{
			ID: user.ID, Username: user.Username, Email: user.Email,
			Status: string(user.Status), CreatedAt: user.CreatedAt,
		},
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(accessTokenTTL.Seconds()),
	})
}

// --- Helper ---
func (h *AuthHandler) respondWithError(c *gin.Context, code int, message string) {
	c.AbortWithStatusJSON(code, gin.H{"error": message})
}

// RegisterAuthRoutes registers auth-related HTTP routes.
func RegisterAuthRoutes(
	routerGroup *gin.RouterGroup, 
	authHandler *AuthHandler, 
	authMiddleware gin.HandlerFunc, // For routes like /logout that need user context
	// externalAuthHandler *ExternalAuthHandler, // If Telegram login is separate
) {
	auth := routerGroup.Group("/auth")
	{
		auth.POST("/register", authHandler.RegisterUser)
		auth.POST("/login", authHandler.LoginUser)
		auth.POST("/refresh-token", authHandler.RefreshTokenHandler)
		auth.POST("/logout", authMiddleware, authHandler.LogoutHandler)
		
		auth.POST("/verify-email", authHandler.VerifyEmailHandler)
		auth.POST("/resend-verification", authHandler.ResendVerificationEmailHandler)
		auth.POST("/forgot-password", authHandler.ForgotPasswordHandler)
		auth.POST("/reset-password", authHandler.ResetPasswordHandler)
		auth.POST("/login/2fa/verify", authHandler.Verify2FACodeLoginHandler)
		
		// Example if Telegram handler was part of this:
		// auth.POST("/telegram-login", authHandler.HandleTelegramLogin) 
		// Or register from externalAuthHandler separately if it exists.
	}
}
