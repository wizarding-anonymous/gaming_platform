// File: backend/services/auth-service/internal/handler/http/oauth_handler.go
package http

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors" // Required for errors.Is
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/config"
	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	appService "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/service"
)

const (
	oauthStateCookieName = "oauth_state"
)

type OAuthHandler struct {
	authService *appService.AuthService
	logger      *zap.Logger
	cfg         *config.Config
	// frontendRedirectURL string // Можно добавить, если URL фронтенда для редиректа один
}

func NewOAuthHandler(authService *appService.AuthService, logger *zap.Logger, cfg *config.Config) *OAuthHandler {
	return &OAuthHandler{
		authService: authService,
		logger:      logger.Named("oauth_handler"),
		cfg:         cfg,
	}
}

// InitiateOAuthHandler handles the initiation of the OAuth2 flow.
// GET /api/v1/auth/oauth/:provider
func (h *OAuthHandler) InitiateOAuthHandler(c *gin.Context) {
	providerName := c.Param("provider")
	if providerName == "" {
		ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Provider name is required", nil)
		return
	}

	// 1. Generate state
	state := uuid.NewString() //  Неподписанный state для AuthCodeURL

	// 2. Generate signed state for cookie
	mac := hmac.New(sha256.New, []byte(h.cfg.JWT.OAuthStateSecret))
	mac.Write([]byte(state))
	signedState := hex.EncodeToString(mac.Sum(nil)) + ":" + state

	// 3. Set cookie
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     oauthStateCookieName,
		Value:    signedState,
		Path:     "/",
		Expires:  time.Now().Add(h.cfg.JWT.OAuthStateCookieTTL),
		HttpOnly: true,
		Secure:   c.Request.TLS != nil, // Secure if HTTPS
		SameSite: http.SameSiteLaxMode,
	})

	// 4. Get AuthCodeURL from AuthService
	authURL, err := h.authService.InitiateOAuth(providerName, state)
	if err != nil {
		h.logger.Error("Failed to initiate OAuth", zap.String("provider", providerName), zap.Error(err))
		// Определить, какая ошибка и какой статус вернуть
		if errors.Is(err, domainErrors.ErrOAuthProviderNotFound) {
			ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, fmt.Sprintf("OAuth provider '%s' not supported", providerName), err)
		} else {
			ErrorResponse(c.Writer, h.logger, http.StatusInternalServerError, "Could not initiate OAuth flow", err)
		}
		return
	}

	// 5. Redirect user
	c.Redirect(http.StatusTemporaryRedirect, authURL)
}

// OAuthCallbackHandler handles the callback from the OAuth2 provider.
// GET /api/v1/auth/oauth/:provider/callback
func (h *OAuthHandler) OAuthCallbackHandler(c *gin.Context) {
	providerName := c.Param("provider")
	code := c.Query("code")
	receivedState := c.Query("state")

	if code == "" {
		ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Authorization code is missing", nil)
		return
	}
	if receivedState == "" {
		ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "State is missing", nil)
		return
	}

	// 1. Get and validate state from cookie
	stateCookie, err := c.Request.Cookie(oauthStateCookieName)
	if err != nil {
		ErrorResponse(c.Writer, h.logger, http.StatusForbidden, "OAuth state cookie not found", err)
		return
	}
	// Delete cookie immediately
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     oauthStateCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   c.Request.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})

	parts := strings.Split(stateCookie.Value, ":")
	if len(parts) != 2 {
		ErrorResponse(c.Writer, h.logger, http.StatusForbidden, "Invalid OAuth state cookie format", nil)
		return
	}
	expectedMAC, originalState := parts[0], parts[1]

	mac := hmac.New(sha256.New, []byte(h.cfg.JWT.OAuthStateSecret))
	mac.Write([]byte(originalState))
	calculatedMAC := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(calculatedMAC), []byte(expectedMAC)) {
		ErrorResponse(c.Writer, h.logger, http.StatusForbidden, "OAuth state signature mismatch (CSRF suspected)", domainErrors.ErrOAuthStateMismatch)
		return
	}

	if originalState != receivedState {
		ErrorResponse(c.Writer, h.logger, http.StatusForbidden, "OAuth state value mismatch (CSRF suspected)", domainErrors.ErrOAuthStateMismatch)
		return
	}

	// 2. Call AuthService to handle the callback
	ipAddress := c.ClientIP()
	userAgent := c.Request.UserAgent()
	// clientDeviceInfo можно будет добавить позже, если потребуется

	user, accessToken, refreshToken, err := h.authService.HandleOAuthCallback(c.Request.Context(), providerName, code, ipAddress, userAgent, nil) // Pass nil for clientDeviceInfo for now
	if err != nil {
		h.logger.Error("OAuth callback handling failed", zap.String("provider", providerName), zap.Error(err))
		errMsg := "oauth_error"
		if h.cfg.OAuthErrorPageURL != "" {
			if errors.Is(err, domainErrors.ErrOAuthProviderNotFound) || errors.Is(err, domainErrors.ErrOAuthExchangeCode) || errors.Is(err, domainErrors.ErrFailedToFetchUserInfoFromProvider) {
				errMsg = "provider_error"
			} else if errors.Is(err, domainErrors.ErrUserBlocked) {
				errMsg = "user_blocked"
			}
			redirectErr := fmt.Sprintf("%s?error=%s", h.cfg.OAuthErrorPageURL, url.QueryEscape(errMsg))
			c.Redirect(http.StatusTemporaryRedirect, redirectErr)
		} else {
			if errors.Is(err, domainErrors.ErrOAuthProviderNotFound) || errors.Is(err, domainErrors.ErrOAuthExchangeCode) || errors.Is(err, domainErrors.ErrFailedToFetchUserInfoFromProvider) {
				ErrorResponse(c.Writer, h.logger, http.StatusBadGateway, fmt.Sprintf("Error communicating with OAuth provider '%s'", providerName), err)
			} else if errors.Is(err, domainErrors.ErrUserBlocked) {
				ErrorResponse(c.Writer, h.logger, http.StatusForbidden, "User account is blocked", err)
			} else {
				ErrorResponse(c.Writer, h.logger, http.StatusInternalServerError, "Failed to process OAuth callback", err)
			}
		}
		return
	}

	// 3. Set session cookies for the platform
	// (Предполагается, что утилита SetAuthCookies существует и работает аналогично AuthHandler)
	SetAuthCookies(c, accessToken, refreshToken, h.cfg.JWT.AccessTokenTTL, h.cfg.JWT.RefreshTokenTTL)

	// 4. Redirect to frontend
	frontendRedirectURL := h.cfg.OAuthSuccessRedirectURL
	if frontendRedirectURL == "" {
		frontendRedirectURL = "/"
	}
	// Append query parameters to indicate success, or potentially user info if it's a first-time login
	redirectURL := fmt.Sprintf("%s?oauth_success=true&provider=%s", frontendRedirectURL, providerName)
	if user.CreatedAt.Equal(user.UpdatedAt) { // Heuristic for new user
		// Could add more info like ?new_user=true, or redirect to a profile completion page
	}

	c.Redirect(http.StatusTemporaryRedirect, redirectURL)
	h.logger.Info("OAuth login successful", zap.String("provider", providerName), zap.String("userID", user.ID.String()))
}
