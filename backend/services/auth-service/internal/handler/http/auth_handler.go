package http

import (
	"encoding/json"
	"net/http"
	"strings"
	"time" // For DTOs

	"github.com/gin-gonic/gin" // Assuming Gin is the chosen framework based on common Go practices
	"go.uber.org/zap"

	"github.com/gameplatform/auth-service/internal/domain/entity" // For entity types
	"github.com/gameplatform/auth-service/internal/domain/service"
	// "github.com/go-playground/validator/v10" // For input validation
)

// AuthHandler handles core authentication HTTP requests.
type AuthHandler struct {
	logger         *zap.Logger
	authLogicSvc   service.AuthLogicService
	mfaLogicSvc    service.MFALogicService
	// validate       *validator.Validate // For input validation
}

// NewAuthHandler creates a new AuthHandler.
func NewAuthHandler(logger *zap.Logger, authLogicSvc service.AuthLogicService, mfaLogicSvc service.MFALogicService) *AuthHandler {
	return &AuthHandler{
		logger:       logger.Named("auth_handler"),
		authLogicSvc: authLogicSvc,
		mfaLogicSvc:  mfaLogicSvc,
		// validate:       validator.New(),
	}
}

// RegisterRequest DTO
type RegisterRequest struct {
	Username string `json:"username" binding:"required,min=3,max=50"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8,max=100"`
}

// UserResponse DTO (simplified, might need more fields or a dedicated UserDTO)
type UserResponse struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

// RegisterUser handles user registration.
// POST /register
func (h *AuthHandler) RegisterUser(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("RegisterUser: bad request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload", "details": err.Error()})
		return
	}

	// TODO: Add more sophisticated validation using validator package if needed.

	user, verificationTokenPlain, err := h.authLogicSvc.RegisterUser(c.Request.Context(), req.Username, req.Email, req.Password)
	if err != nil {
		h.logger.Error("RegisterUser: service error", zap.Error(err))
		// Map domain errors to HTTP errors
		if strings.Contains(err.Error(), "already exists") {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		} else if strings.Contains(err.Error(), "required") { // Basic validation error from service
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register user"})
		}
		return
	}

	// Note: verificationTokenPlain should be sent to the user (e.g., via email), not typically in the API response.
	// The response here is simplified.
	c.JSON(http.StatusCreated, gin.H{
		"message": "User registered successfully. Please check your email to verify your account.",
		"user": UserResponse{
			ID:        user.ID,
			Username:  user.Username,
			Email:     user.Email,
			Status:    string(user.Status),
			CreatedAt: user.CreatedAt,
		},
		// "verification_token_for_testing": verificationTokenPlain, // ONLY FOR TESTING/DEBUG
	})
}


// LoginRequest DTO
type LoginRequest struct {
	LoginIdentifier string `json:"login_identifier" binding:"required"` // Username or email
	Password        string `json:"password" binding:"required"`
	// DeviceInfo can be added here if needed by the service for session creation
}

// LoginResponse DTO
type LoginResponse struct {
	User         UserResponse `json:"user"`
	AccessToken  string       `json:"access_token"`
	RefreshToken string       `json:"refresh_token"` // Opaque refresh token
	TokenType    string       `json:"token_type"`    // Usually "Bearer"
	ExpiresIn    int64        `json:"expires_in"`    // Access token expiry in seconds
	TwoFARequired bool        `json:"two_fa_required,omitempty"` // To signal client 2FA step is next
}

// LoginUser handles user login.
// POST /login
func (h *AuthHandler) LoginUser(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("LoginUser: bad request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload", "details": err.Error()})
		return
	}

	// Placeholder for deviceInfo
	deviceInfo := make(map[string]string) 
	deviceInfo["ip_address"] = c.ClientIP()
	deviceInfo["user_agent"] = c.Request.UserAgent()

	user, accessToken, refreshToken, err := h.authLogicSvc.LoginUser(c.Request.Context(), req.LoginIdentifier, req.Password, deviceInfo)
	if err != nil {
		h.logger.Warn("LoginUser: service error", zap.Error(err), zap.String("login_id", req.LoginIdentifier))
		if strings.Contains(err.Error(), "2FA_required") {
			c.JSON(http.StatusOK, LoginResponse{ // Or a different status code like 202 Accepted / 401 with specific error
				User: UserResponse{ // Send minimal user info if needed
					ID: user.ID, // Assuming user is returned even if 2FA is required
				},
				TwoFARequired: true,
			})
			return
		}
		if strings.Contains(err.Error(), "invalid credentials") || strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		} else if strings.Contains(err.Error(), "blocked") || strings.Contains(err.Error(), "not active") || strings.Contains(err.Error(), "not verified") {
			c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Login failed"})
		}
		return
	}

	// TODO: Get AccessTokenTTL from config or token service to populate ExpiresIn
	// For now, using a placeholder (e.g. 15 minutes from TokenService config)
	// This should ideally come from the claims or TokenService.
	accessTokenTTL := 15 * 60 // Example

	c.JSON(http.StatusOK, LoginResponse{
		User: UserResponse{
			ID:        user.ID,
			Username:  user.Username,
			Email:     user.Email,
			Status:    string(user.Status),
			CreatedAt: user.CreatedAt,
		},
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(accessTokenTTL),
	})
}

// TODO: Implement other handlers:
// - Logout (POST /logout)
// - RefreshToken (POST /refresh-token)
// - VerifyEmail (POST /verify-email)
// - ResendVerification (POST /resend-verification)
// - ForgotPassword (POST /forgot-password)
// - ResetPassword (POST /reset-password)
// - Verify2FACode (POST /login/2fa/verify)
//   - This one would call mfaLogicSvc.Verify2FACode and then, if successful,
//     proceed to generate tokens similar to the final part of LoginUser.


// RegisterAuthRoutes registers auth-related HTTP routes.
func RegisterAuthRoutes(router *gin.RouterGroup, authHandler *AuthHandler /*, authMiddleware gin.HandlerFunc */) {
	auth := router.Group("/auth")
	{
		auth.POST("/register", authHandler.RegisterUser)
		auth.POST("/login", authHandler.LoginUser)
		// Add other routes here
		// auth.POST("/logout", authMiddleware, authHandler.Logout) // Example with auth middleware
		// auth.POST("/refresh-token", authHandler.RefreshToken)
		// auth.POST("/login/2fa/verify", authHandler.Verify2FACodeHandler)
	}
}
