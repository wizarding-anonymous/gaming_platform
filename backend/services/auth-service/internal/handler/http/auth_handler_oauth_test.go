// File: backend/services/auth-service/internal/handler/http/auth_handler_oauth_test.go
package http

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
)

// --- OAuthLogin Tests ---
func TestAuthHandler_OAuthLogin_Success(t *testing.T) {
	ts := setupAuthHandlerTestSuite(t)
	provider := "google" // Example provider
	expectedAuthURL := "https://provider.com/auth?client_id=123"
	expectedStateCookieJWT := "state.jwt.token"

	ts.mockAuthService.On("InitiateOAuthLogin", mock.Anything, provider, "", "").Return(expectedAuthURL, expectedStateCookieJWT, nil).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/auth/oauth/"+provider, nil)
	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusTemporaryRedirect, w.Code)
	assert.Equal(t, expectedAuthURL, w.Header().Get("Location"))

	// Check for state cookie
	foundCookie := false
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == "oauth_state" {
			foundCookie = true
			assert.Equal(t, expectedStateCookieJWT, cookie.Value)
			assert.True(t, cookie.HttpOnly)
			break
		}
	}
	assert.True(t, foundCookie, "oauth_state cookie not set")
	ts.mockAuthService.AssertExpectations(t)
}

func TestAuthHandler_OAuthLogin_UnsupportedProvider(t *testing.T) {
	ts := setupAuthHandlerTestSuite(t)
	provider := "unknownprovider"

	ts.mockAuthService.On("InitiateOAuthLogin", mock.Anything, provider, "", "").Return("", "", domainErrors.ErrUnsupportedOAuthProvider).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/auth/oauth/"+provider, nil)
	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	ts.mockAuthService.AssertExpectations(t)
}

// --- OAuthCallback Tests ---
func TestAuthHandler_OAuthCallback_Success(t *testing.T) {
	ts := setupAuthHandlerTestSuite(t)
	provider := "google"
	authCode := "auth_code_from_provider"
	stateFromProvider := "state_from_provider"
	stateCookieValue := "state.jwt.from.cookie" // This is the JWT from the cookie

	mockTokenPair := &models.TokenPair{AccessToken: "access_token", RefreshToken: "refresh_token"}
	mockUser := &models.User{ID: uuid.New(), Email: "oauth@example.com"}

	ts.mockAuthService.On("HandleOAuthCallback", mock.Anything, provider, authCode, stateFromProvider, stateCookieValue, mock.AnythingOfType("map[string]string")).Return(mockTokenPair, mockUser, nil).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/auth/oauth/"+provider+"/callback?code="+authCode+"&state="+stateFromProvider, nil)
	req.AddCookie(&http.Cookie{Name: "oauth_state", Value: stateCookieValue})
	req.Header.Set("User-Agent", "test-callback-agent")

	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var respBody LoginUserResponse
	err := json.Unmarshal(w.Body.Bytes(), &respBody)
	assert.NoError(t, err)
	assert.Equal(t, mockTokenPair.AccessToken, respBody.AccessToken)
	ts.mockAuthService.AssertExpectations(t)
}

func TestAuthHandler_OAuthCallback_StateMismatch(t *testing.T) {
	ts := setupAuthHandlerTestSuite(t)
	provider := "google"
	authCode := "auth_code"
	stateFromProvider := "state_A"
	stateCookieValue := "state_jwt_B" // Mismatch or invalid JWT

	ts.mockAuthService.On("HandleOAuthCallback", mock.Anything, provider, authCode, stateFromProvider, stateCookieValue, mock.AnythingOfType("map[string]string")).Return(nil, nil, domainErrors.ErrOAuthStateMismatch).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/auth/oauth/"+provider+"/callback?code="+authCode+"&state="+stateFromProvider, nil)
	req.AddCookie(&http.Cookie{Name: "oauth_state", Value: stateCookieValue})
	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusTemporaryRedirect, w.Code)
	expectedURL := "https://example.com/error?error=" + url.QueryEscape("OAuth callback error: invalid state or request")
	assert.Equal(t, expectedURL, w.Header().Get("Location"))
	ts.mockAuthService.AssertExpectations(t)
}

func TestAuthHandler_OAuthCallback_NoStateCookie(t *testing.T) {
	ts := setupAuthHandlerTestSuite(t)
	provider := "google"
	authCode := "auth_code"
	stateFromProvider := "state_A"
	ts.mockAuthService.On("HandleOAuthCallback", mock.Anything, provider, authCode, stateFromProvider, "", mock.AnythingOfType("map[string]string")).Return(nil, nil, domainErrors.ErrOAuthStateMismatch).Maybe()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/auth/oauth/"+provider+"/callback?code="+authCode+"&state="+stateFromProvider, nil)
	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusTemporaryRedirect, w.Code)
	expectedURL := "https://example.com/error?error=" + url.QueryEscape("OAuth state validation failed: missing state cookie")
	assert.Equal(t, expectedURL, w.Header().Get("Location"))
}

func TestAuthHandler_OAuthCallback_ProviderError(t *testing.T) {
	ts := setupAuthHandlerTestSuite(t)
	provider := "google"

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/auth/oauth/"+provider+"/callback?error=access_denied&error_description=denied", nil)
	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusTemporaryRedirect, w.Code)
	expectedURL := "https://example.com/error?error=" + url.QueryEscape("OAuth provider error: denied")
	assert.Equal(t, expectedURL, w.Header().Get("Location"))
}
