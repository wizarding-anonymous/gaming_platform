// File: backend/services/auth-service/internal/handler/http/auth_login_handler.go
package http

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/handler/http/middleware"
)

// LoginUser handles user login.
func (h *AuthHandler) LoginUser(c *gin.Context) {
	var req models.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid request payload", err)
		return
	}

	tokenPair, user, challengeToken, err := h.authService.Login(c.Request.Context(), req)
	if err != nil {
		if domainErrors.Err2FARequired.Is(err) {
			h.logger.Info("2FA required for user", zap.String("identifier", req.Identifier))
			c.JSON(http.StatusAccepted, gin.H{
				"message":         "2FA_required",
				"user_id":         user.ID,
				"challenge_token": challengeToken,
			})
			return
		}
		if domainErrors.ErrInvalidCredentials.Is(err) || domainErrors.ErrUserNotFound.Is(err) {
			ErrorResponse(c.Writer, h.logger, http.StatusUnauthorized, "Invalid credentials", err)
		} else if domainErrors.ErrUserBlocked.Is(err) {
			ErrorResponse(c.Writer, h.logger, http.StatusForbidden, "User account is blocked", err)
		} else if domainErrors.ErrUserLockedOut.Is(err) {
			ErrorResponse(c.Writer, h.logger, http.StatusForbidden, "User account is temporarily locked", err)
		} else if domainErrors.ErrEmailNotVerified.Is(err) {
			ErrorResponse(c.Writer, h.logger, http.StatusForbidden, "Email not verified", err)
		} else if domainErrors.ErrRateLimitExceeded.Is(err) {
			ErrorResponse(c.Writer, h.logger, http.StatusTooManyRequests, "Too many login attempts. Please try again later.", err)
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

// TelegramLogin handles Telegram based login.
func (h *AuthHandler) TelegramLogin(c *gin.Context) {
	var req models.TelegramLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid request payload for Telegram login", err)
		return
	}

	deviceInfo := map[string]string{
		"user_agent": c.Request.UserAgent(),
		"ip_address": c.ClientIP(),
	}

	tokenPair, user, err := h.authService.LoginWithTelegram(c.Request.Context(), req, deviceInfo)
	if err != nil {
		switch {
		case domainErrors.ErrTelegramAuthFailed.Is(err):
			ErrorResponse(c.Writer, h.logger, http.StatusUnauthorized, "Telegram authentication failed: invalid hash or old data", err)
		case domainErrors.ErrUserBlocked.Is(err):
			ErrorResponse(c.Writer, h.logger, http.StatusForbidden, "User account is blocked", err)
		case domainErrors.ErrInvalidRequest.Is(err):
			ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid Telegram data", err)
		default:
			ErrorResponse(c.Writer, h.logger, http.StatusInternalServerError, "Telegram login processing failed", err)
		}
		return
	}

	SuccessResponse(c.Writer, h.logger, http.StatusOK, gin.H{
		"user":   user.ToResponse(),
		"tokens": tokenPair,
	})
}

// VerifyLogin2FA verifies the 2FA code during login.
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
		h.logger.Error("Error during 2FA code verification", zap.Error(err), zap.String("userID", userID.String()), zap.String("method", req.Method))
		ErrorResponse(c.Writer, h.logger, http.StatusInternalServerError, "Error verifying 2FA code", nil)
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

// OAuthLogin initiates the OAuth flow.
func (h *AuthHandler) OAuthLogin(c *gin.Context) {
	provider := c.Param("provider")
	clientRedirectURI := c.Query("redirect_uri")
	clientState := c.Query("state")

	authURL, stateCookieJWT, err := h.authService.InitiateOAuthLogin(c.Request.Context(), provider, clientRedirectURI, clientState)
	if err != nil {
		if domainErrors.ErrUnsupportedOAuthProvider.Is(err) {
			ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Unsupported OAuth provider", err)
		} else if domainErrors.ErrInternal.Is(err) {
			ErrorResponse(c.Writer, h.logger, http.StatusInternalServerError, "Failed to initiate OAuth login (internal)", err)
		} else {
			ErrorResponse(c.Writer, h.logger, http.StatusInternalServerError, "Failed to initiate OAuth login", err)
		}
		return
	}

	http.SetCookie(c.Writer, &http.Cookie{
		Name:     h.cfg.Security.OAuth.StateCookieName,
		Value:    stateCookieJWT,
		Expires:  time.Now().Add(h.cfg.Security.OAuth.StateCookieTTL),
		Path:     "/api/v1/auth/oauth/" + provider + "/callback",
		Domain:   c.Request.URL.Host,
		Secure:   c.Request.TLS != nil,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	c.Redirect(http.StatusTemporaryRedirect, authURL)
}

// OAuthCallback handles provider callback.
func (h *AuthHandler) OAuthCallback(c *gin.Context) {
	provider := c.Param("provider")
	authorizationCode := c.Query("code")
	receivedStateCSRF := c.Query("state")

	providerError := c.Query("error")
	errorDescription := c.Query("error_description")
	if providerError != "" {
		h.logger.Warn("OAuth callback error from provider", zap.String("provider", provider), zap.String("error", providerError), zap.String("description", errorDescription))
		msg := fmt.Sprintf("OAuth provider error: %s", errorDescription)
		v := url.Values{"error": []string{msg}}
		c.Redirect(http.StatusTemporaryRedirect, h.cfg.OAuthErrorPageURL+"?"+v.Encode())
		return
	}
	if authorizationCode == "" {
		msg := "Authorization code missing in OAuth callback"
		v := url.Values{"error": []string{msg}}
		c.Redirect(http.StatusTemporaryRedirect, h.cfg.OAuthErrorPageURL+"?"+v.Encode())
		return
	}

	stateCookieJWT, err := c.Cookie(h.cfg.Security.OAuth.StateCookieName)
	if err != nil {
		h.logger.Warn("OAuthCallback: State cookie not found or failed to read", zap.Error(err))
		msg := "OAuth state validation failed: missing state cookie"
		v := url.Values{"error": []string{msg}}
		c.Redirect(http.StatusTemporaryRedirect, h.cfg.OAuthErrorPageURL+"?"+v.Encode())
		return
	}
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     h.cfg.Security.OAuth.StateCookieName,
		Value:    "",
		Path:     "/api/v1/auth/oauth/" + provider + "/callback",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   c.Request.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})

	deviceInfo := map[string]string{
		"user_agent": c.Request.UserAgent(),
		"ip_address": c.ClientIP(),
	}

	tokenPair, user, err := h.authService.HandleOAuthCallback(c.Request.Context(), provider, authorizationCode, receivedStateCSRF, stateCookieJWT, deviceInfo)
	if err != nil {
		var msg string
		if domainErrors.ErrOAuthStateMismatch.Is(err) || domainErrors.ErrInvalidRequest.Is(err) {
			msg = "OAuth callback error: invalid state or request"
		} else if domainErrors.ErrUserBlocked.Is(err) {
			msg = "User account is blocked"
		} else {
			msg = "OAuth callback processing failed"
		}
		v := url.Values{"error": []string{msg}}
		c.Redirect(http.StatusTemporaryRedirect, h.cfg.OAuthErrorPageURL+"?"+v.Encode())
		return
	}

	SuccessResponse(c.Writer, h.logger, http.StatusOK, gin.H{
		"user":   user.ToResponse(),
		"tokens": tokenPair,
	})
}

// RefreshToken refreshes JWT tokens.
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req models.RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid request payload", err)
		return
	}

	tokenPair, err := h.authService.RefreshToken(c.Request.Context(), req.RefreshToken)
	if err != nil {
		if domainErrors.ErrInvalidRefreshToken.Is(err) || domainErrors.ErrSessionNotFound.Is(err) || domainErrors.ErrUserNotFound.Is(err) {
			ErrorResponse(c.Writer, h.logger, http.StatusUnauthorized, "Invalid or expired refresh token", err)
		} else {
			ErrorResponse(c.Writer, h.logger, http.StatusInternalServerError, "Failed to refresh token", err)
		}
		return
	}
	SuccessResponse(c.Writer, h.logger, http.StatusOK, tokenPair)
}

// Logout handles user logout.
func (h *AuthHandler) Logout(c *gin.Context) {
	authHeader := c.GetHeader(middleware.AuthHeaderKey)
	parts := strings.Split(authHeader, " ")
	accessTokenString := ""
	if len(parts) == 2 && strings.ToLower(parts[0]) == strings.ToLower(middleware.AuthTypeBearer) {
		accessTokenString = parts[1]
	}

	var req models.LogoutRequest
	_ = c.ShouldBindJSON(&req)

	err := h.authService.Logout(c.Request.Context(), accessTokenString, req.RefreshToken)
	if err != nil {
		ErrorResponse(c.Writer, h.logger, http.StatusInternalServerError, "Logout failed", err)
		return
	}
	SuccessResponse(c.Writer, h.logger, http.StatusNoContent, nil)
}

// LogoutAll logs out from all sessions.
func (h *AuthHandler) LogoutAll(c *gin.Context) {
	accessTokenString := ""
	authHeader := c.GetHeader(middleware.AuthHeaderKey)
	parts := strings.Split(authHeader, " ")
	if len(parts) == 2 && strings.ToLower(parts[0]) == strings.ToLower(middleware.AuthTypeBearer) {
		accessTokenString = parts[1]
	}
	err := h.authService.LogoutAll(c.Request.Context(), accessTokenString)
	if err != nil {
		if domainErrors.ErrInvalidToken.Is(err) {
			ErrorResponse(c.Writer, h.logger, http.StatusUnauthorized, "Invalid access token", err)
		} else {
			ErrorResponse(c.Writer, h.logger, http.StatusInternalServerError, "Logout from all sessions failed", err)
		}
		return
	}
	SuccessResponse(c.Writer, h.logger, http.StatusNoContent, nil)
}
