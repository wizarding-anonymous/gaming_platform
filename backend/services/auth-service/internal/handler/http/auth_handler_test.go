// File: backend/services/auth-service/internal/handler/http/auth_handler_test.go
package http

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/config"
	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	domainService "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/service"
	"go.uber.org/zap"
)

// --- Mocks ---

type MockAuthServiceForHandler struct {
	mock.Mock
}

func (m *MockAuthServiceForHandler) Register(ctx context.Context, req models.CreateUserRequest) (*models.User, string, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.String(1), args.Error(2)
	}
	return args.Get(0).(*models.User), args.String(1), args.Error(2)
}
func (m *MockAuthServiceForHandler) Login(ctx context.Context, req models.LoginRequest) (*models.TokenPair, *models.User, string, error) {
	args := m.Called(ctx, req)
	r0, r1, r2, r3 := args.Get(0), args.Get(1), args.String(2), args.Error(3)
	var tp *models.TokenPair
	if r0 != nil {
		tp = r0.(*models.TokenPair)
	}
	var user *models.User
	if r1 != nil {
		user = r1.(*models.User)
	}
	return tp, user, r2, r3
}
func (m *MockAuthServiceForHandler) CompleteLoginAfter2FA(ctx context.Context, userID uuid.UUID, deviceInfo map[string]string) (*models.TokenPair, *models.User, error) {
	args := m.Called(ctx, userID, deviceInfo)
	r0, r1, r2 := args.Get(0), args.Get(1), args.Error(2)
	var tp *models.TokenPair
	if r0 != nil {
		tp = r0.(*models.TokenPair)
	}
	var user *models.User
	if r1 != nil {
		user = r1.(*models.User)
	}
	return tp, user, r2
}
func (m *MockAuthServiceForHandler) RefreshToken(ctx context.Context, plainOpaqueRefreshToken string) (*models.TokenPair, error) {
	args := m.Called(ctx, plainOpaqueRefreshToken)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.TokenPair), args.Error(1)
}
func (m *MockAuthServiceForHandler) Logout(ctx context.Context, accessToken, refreshToken string) error {
	args := m.Called(ctx, accessToken, refreshToken)
	return args.Error(0)
}
func (m *MockAuthServiceForHandler) LogoutAll(ctx context.Context, accessToken string) error {
	args := m.Called(ctx, accessToken)
	return args.Error(0)
}
func (m *MockAuthServiceForHandler) SystemLogoutAllUserSessions(ctx context.Context, userID uuid.UUID, actorID string, reason string) error {
	args := m.Called(ctx, userID, actorID, reason)
	return args.Error(0)
}
func (m *MockAuthServiceForHandler) VerifyEmail(ctx context.Context, plainVerificationTokenValue string) error {
	args := m.Called(ctx, plainVerificationTokenValue)
	return args.Error(0)
}
func (m *MockAuthServiceForHandler) ResendVerificationEmail(ctx context.Context, email string) error {
	args := m.Called(ctx, email)
	return args.Error(0)
}
func (m *MockAuthServiceForHandler) ForgotPassword(ctx context.Context, email string) error {
	args := m.Called(ctx, email)
	return args.Error(0)
}
func (m *MockAuthServiceForHandler) ResetPassword(ctx context.Context, plainToken, newPassword string) error {
	args := m.Called(ctx, plainToken, newPassword)
	return args.Error(0)
}
func (m *MockAuthServiceForHandler) ChangePassword(ctx context.Context, userID uuid.UUID, oldPlainPassword, newPlainPassword string) error {
	args := m.Called(ctx, userID, oldPlainPassword, newPlainPassword)
	return args.Error(0)
}
func (m *MockAuthServiceForHandler) CheckUserPermission(ctx context.Context, userID uuid.UUID, permissionKey string, resourceID *string) (bool, error) {
	args := m.Called(ctx, userID, permissionKey, resourceID)
	return args.Bool(0), args.Error(1)
}
func (m *MockAuthServiceForHandler) LoginWithTelegram(ctx context.Context, tgData models.TelegramLoginRequest, deviceInfo map[string]string) (*models.TokenPair, *models.User, error) {
	args := m.Called(ctx, tgData, deviceInfo)
	var tp *models.TokenPair
	if args.Get(0) != nil {
		tp = args.Get(0).(*models.TokenPair)
	}
	var user *models.User
	if args.Get(1) != nil {
		user = args.Get(1).(*models.User)
	}
	return tp, user, args.Error(2)
}
func (m *MockAuthServiceForHandler) InitiateOAuthLogin(ctx context.Context, providerName string, clientProvidedRedirectURI string, clientProvidedState string) (string, string, error) {
	args := m.Called(ctx, providerName, clientProvidedRedirectURI, clientProvidedState)
	return args.String(0), args.String(1), args.Error(2)
}
func (m *MockAuthServiceForHandler) HandleOAuthCallback(ctx context.Context, providerName string, authorizationCode string, receivedCSRFState string, stateCookieJWT string, deviceInfo map[string]string) (*models.TokenPair, *models.User, error) {
	args := m.Called(ctx, providerName, authorizationCode, receivedCSRFState, stateCookieJWT, deviceInfo)
	var tp *models.TokenPair
	if args.Get(0) != nil {
		tp = args.Get(0).(*models.TokenPair)
	}
	var user *models.User
	if args.Get(1) != nil {
		user = args.Get(1).(*models.User)
	}
	return tp, user, args.Error(2)
}

type MockMFALogicServiceForHandler struct {
	mock.Mock
}

func (m *MockMFALogicServiceForHandler) Verify2FACode(ctx context.Context, userID uuid.UUID, code string, codeType models.MFAType) (bool, error) {
	args := m.Called(ctx, userID, code, codeType)
	return args.Bool(0), args.Error(1)
}
func (m *MockMFALogicServiceForHandler) Enable2FAInitiate(ctx context.Context, userID uuid.UUID, accountName string) (mfaSecretID uuid.UUID, secretBase32 string, otpAuthURL string, err error) {
	args := m.Called(ctx, userID, accountName)
	// Need to handle potential nil for uuid.UUID if error occurs early
	var id uuid.UUID
	if val, ok := args.Get(0).(uuid.UUID); ok {
		id = val
	}
	return id, args.String(1), args.String(2), args.Error(3)
}
func (m *MockMFALogicServiceForHandler) VerifyAndActivate2FA(ctx context.Context, userID uuid.UUID, plainTOTPCode string, mfaSecretID uuid.UUID) (backupCodes []string, err error) {
	args := m.Called(ctx, userID, plainTOTPCode, mfaSecretID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}
func (m *MockMFALogicServiceForHandler) Disable2FA(ctx context.Context, userID uuid.UUID, verificationToken string, verificationMethod string) error {
	args := m.Called(ctx, userID, verificationToken, verificationMethod)
	return args.Error(0)
}
func (m *MockMFALogicServiceForHandler) RegenerateBackupCodes(ctx context.Context, userID uuid.UUID, verificationToken string, verificationMethod string) (backupCodes []string, err error) {
	args := m.Called(ctx, userID, verificationToken, verificationMethod)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

type MockTokenManagementServiceForHandler struct {
	mock.Mock
}

func (m *MockTokenManagementServiceForHandler) Validate2FAChallengeToken(challengeToken string) (string, error) {
	args := m.Called(challengeToken)
	return args.String(0), args.Error(1)
}
func (m *MockTokenManagementServiceForHandler) GenerateAccessToken(userID, username string, roles, permissions []string, sessionID string) (string, error) {
	panic("not implemented for this mock")
}
func (m *MockTokenManagementServiceForHandler) ValidateAccessToken(tokenString string) (*domainService.Claims, error) {
	panic("not implemented for this mock")
}
func (m *MockTokenManagementServiceForHandler) GenerateRefreshTokenValue() (string, error) {
	panic("not implemented for this mock")
}
func (m *MockTokenManagementServiceForHandler) GetRefreshTokenExpiry() time.Time {
	panic("not implemented for this mock")
}
func (m *MockTokenManagementServiceForHandler) GetJWKS() ([]byte, error) {
	panic("not implemented for this mock")
}
func (m *MockTokenManagementServiceForHandler) GenerateStateJWT(claims *domainService.OAuthStateClaims, secret string, ttl time.Duration) (string, error) {
	panic("not implemented for this mock")
}
func (m *MockTokenManagementServiceForHandler) ValidateStateJWT(tokenString string, secret string) (*domainService.OAuthStateClaims, error) {
	panic("not implemented for this mock")
}

// Generate2FAChallengeToken on TokenManagementService is actually defined with (userID string) (string, error)
// This mock already has Validate2FAChallengeToken, so Generate2FAChallengeToken is not strictly needed here
// unless AuthHandler calls it directly (which it doesn't seem to).

// --- Test Suite Setup ---
type AuthHandlerTestSuite struct {
	router           *gin.Engine
	mockAuthService  *MockAuthServiceForHandler
	mockMfaLogicSvc  *MockMFALogicServiceForHandler
	mockTokenMgmtSvc *MockTokenManagementServiceForHandler
	authHandler      *AuthHandler
}

func setupAuthHandlerTestSuite(t *testing.T) *AuthHandlerTestSuite {
	gin.SetMode(gin.TestMode)
	ts := &AuthHandlerTestSuite{}

	ts.mockAuthService = new(MockAuthServiceForHandler)
	ts.mockMfaLogicSvc = new(MockMFALogicServiceForHandler)
	ts.mockTokenMgmtSvc = new(MockTokenManagementServiceForHandler)

	logger := zap.NewNop()
	testConfig := &config.Config{OAuthErrorPageURL: "https://example.com/error"}

	ts.authHandler = NewAuthHandler(
		logger,
		ts.mockAuthService,
		ts.mockMfaLogicSvc,
		ts.mockTokenMgmtSvc,
		testConfig,
	)

	ts.router = gin.New()
	// Register only routes being tested in this file for focus
	authRoutes := ts.router.Group("/api/v1/auth")
	{
		authRoutes.POST("/register", ts.authHandler.RegisterUser)
		authRoutes.POST("/login", ts.authHandler.LoginUser)
		authRoutes.POST("/login/2fa/verify", ts.authHandler.VerifyLogin2FA)
		authRoutes.POST("/token/refresh", ts.authHandler.RefreshToken)
		authRoutes.POST("/password/forgot", ts.authHandler.ForgotPassword)
		authRoutes.POST("/password/reset", ts.authHandler.ResetPassword)
		authRoutes.POST("/email/verify", ts.authHandler.VerifyEmailHandler)
		authRoutes.POST("/email/resend-verification", ts.authHandler.ResendVerificationEmailHandler)
		authRoutes.POST("/logout", ts.authHandler.Logout)        // Assuming auth middleware handles getting user from token
		authRoutes.POST("/logout/all", ts.authHandler.LogoutAll) // Assuming auth middleware

		// OAuth & Telegram
		authRoutes.GET("/oauth/:provider", ts.authHandler.OAuthLogin)
		authRoutes.GET("/oauth/:provider/callback", ts.authHandler.OAuthCallback)
		authRoutes.POST("/telegram/login", ts.authHandler.TelegramLogin)
	}
	return ts
}

// --- Tests ---
// ... (RegisterUser, LoginUser tests from previous steps) ...

// --- RefreshToken Tests ---
func TestAuthHandler_RefreshToken_Success(t *testing.T) {
	ts := setupAuthHandlerTestSuite(t)
	reqBody := RefreshTokenRequest{RefreshToken: "valid_refresh_token"}
	jsonBody, _ := json.Marshal(reqBody)

	mockTokenPair := &models.TokenPair{AccessToken: "new_access_token", RefreshToken: "new_refresh_token"}
	ts.mockAuthService.On("RefreshToken", mock.Anything, reqBody.RefreshToken).Return(mockTokenPair, nil).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/token/refresh", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var respBody TokenResponse
	err := json.Unmarshal(w.Body.Bytes(), &respBody)
	require.NoError(t, err)
	assert.Equal(t, mockTokenPair.AccessToken, respBody.AccessToken)
	assert.Equal(t, mockTokenPair.RefreshToken, respBody.RefreshToken)
	ts.mockAuthService.AssertExpectations(t)
}

func TestAuthHandler_RefreshToken_Failure(t *testing.T) {
	ts := setupAuthHandlerTestSuite(t)
	reqBody := RefreshTokenRequest{RefreshToken: "invalid_refresh_token"}
	jsonBody, _ := json.Marshal(reqBody)

	ts.mockAuthService.On("RefreshToken", mock.Anything, reqBody.RefreshToken).Return(nil, domainErrors.ErrInvalidToken).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/token/refresh", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	ts.mockAuthService.AssertExpectations(t)
}

func TestAuthHandler_RefreshToken_BadRequest(t *testing.T) {
	ts := setupAuthHandlerTestSuite(t)

	// Empty request body
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/token/refresh", bytes.NewBuffer([]byte("{}")))
	req.Header.Set("Content-Type", "application/json")
	ts.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code) // Assuming RefreshToken field is required

	// Malformed JSON
	w = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodPost, "/api/v1/auth/token/refresh", bytes.NewBuffer([]byte(`{"refresh_token":`)))
	req.Header.Set("Content-Type", "application/json")
	ts.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- ForgotPassword Tests ---
func TestAuthHandler_ForgotPassword_Success(t *testing.T) {
	ts := setupAuthHandlerTestSuite(t)
	reqBody := ForgotPasswordRequest{Email: "user@example.com"}
	jsonBody, _ := json.Marshal(reqBody)

	ts.mockAuthService.On("ForgotPassword", mock.Anything, reqBody.Email).Return(nil).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/password/forgot", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code) // Should return 200 OK even if email doesn't exist to prevent enumeration
	// Check for a generic success message if applicable
	var respBody map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &respBody)
	require.NoError(t, err)
	assert.Contains(t, respBody["message"], "processed successfully")

	ts.mockAuthService.AssertExpectations(t)
}

func TestAuthHandler_ForgotPassword_BadRequest(t *testing.T) {
	ts := setupAuthHandlerTestSuite(t)

	// Empty request body
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/password/forgot", bytes.NewBuffer([]byte("{}")))
	req.Header.Set("Content-Type", "application/json")
	ts.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code) // Assuming Email field is required

	// Malformed JSON
	w = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodPost, "/api/v1/auth/password/forgot", bytes.NewBuffer([]byte(`{"email":`)))
	req.Header.Set("Content-Type", "application/json")
	ts.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// Example for ResetPassword - Bad Request
func TestAuthHandler_ResetPassword_BadRequest(t *testing.T) {
	ts := setupAuthHandlerTestSuite(t)
	ts.router.POST("/api/v1/auth/password/reset", ts.authHandler.ResetPassword) // Ensure route is registered

	// Missing token
	reqBodyNoToken := ResetPasswordRequest{NewPassword: "newPassword123!"}
	jsonBody, _ := json.Marshal(reqBodyNoToken)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/password/reset", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	ts.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Missing password
	reqBodyNoPassword := ResetPasswordRequest{Token: "resetToken"}
	jsonBody, _ = json.Marshal(reqBodyNoPassword)
	w = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodPost, "/api/v1/auth/password/reset", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	ts.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// Example for ResetPassword - Service Error (e.g. invalid token)
func TestAuthHandler_ResetPassword_InvalidTokenError(t *testing.T) {
	ts := setupAuthHandlerTestSuite(t)
	ts.router.POST("/api/v1/auth/password/reset", ts.authHandler.ResetPassword)

	reqBody := ResetPasswordRequest{Token: "invalidToken", NewPassword: "newPassword123!"}
	jsonBody, _ := json.Marshal(reqBody)

	ts.mockAuthService.On("ResetPassword", mock.Anything, reqBody.Token, reqBody.NewPassword).Return(domainErrors.ErrInvalidToken).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/password/reset", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code) // Or StatusBadRequest based on how ErrInvalidToken should be treated
	ts.mockAuthService.AssertExpectations(t)
}

func TestAuthHandler_ResetPassword_Success(t *testing.T) {
	ts := setupAuthHandlerTestSuite(t)
	// Route already registered in setup for previous ResetPassword tests

	reqBody := ResetPasswordRequest{Token: "validToken", NewPassword: "newPassword123!"}
	jsonBody, _ := json.Marshal(reqBody)

	ts.mockAuthService.On("ResetPassword", mock.Anything, reqBody.Token, reqBody.NewPassword).Return(nil).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/password/reset", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	ts.mockAuthService.AssertExpectations(t)
}

// --- VerifyEmailHandler Tests ---
func TestAuthHandler_VerifyEmailHandler_Success(t *testing.T) {
	ts := setupAuthHandlerTestSuite(t)
	reqBody := VerifyEmailRequest{Token: "validVerifyToken"}
	jsonBody, _ := json.Marshal(reqBody)

	ts.mockAuthService.On("VerifyEmail", mock.Anything, reqBody.Token).Return(nil).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/email/verify", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	ts.mockAuthService.AssertExpectations(t)
}

func TestAuthHandler_VerifyEmailHandler_BadRequest(t *testing.T) {
	ts := setupAuthHandlerTestSuite(t)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/email/verify", bytes.NewBuffer([]byte(`{"token":""}`))) // Empty token
	req.Header.Set("Content-Type", "application/json")
	ts.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_VerifyEmailHandler_InvalidToken(t *testing.T) {
	ts := setupAuthHandlerTestSuite(t)
	reqBody := VerifyEmailRequest{Token: "invalidToken"}
	jsonBody, _ := json.Marshal(reqBody)

	ts.mockAuthService.On("VerifyEmail", mock.Anything, reqBody.Token).Return(domainErrors.ErrInvalidToken).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/email/verify", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code) // Or BadRequest
	ts.mockAuthService.AssertExpectations(t)
}

// --- ResendVerificationEmailHandler Tests ---
func TestAuthHandler_ResendVerificationEmailHandler_Success(t *testing.T) {
	ts := setupAuthHandlerTestSuite(t)
	reqBody := ResendVerificationEmailRequest{Email: "user@example.com"}
	jsonBody, _ := json.Marshal(reqBody)

	ts.mockAuthService.On("ResendVerificationEmail", mock.Anything, reqBody.Email).Return(nil).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/email/resend-verification", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	ts.mockAuthService.AssertExpectations(t)
}

func TestAuthHandler_ResendVerificationEmailHandler_BadRequest(t *testing.T) {
	ts := setupAuthHandlerTestSuite(t)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/email/resend-verification", bytes.NewBuffer([]byte(`{"email":""}`))) // Empty email
	req.Header.Set("Content-Type", "application/json")
	ts.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_ResendVerificationEmailHandler_UserNotFound(t *testing.T) {
	ts := setupAuthHandlerTestSuite(t)
	reqBody := ResendVerificationEmailRequest{Email: "notfound@example.com"}
	jsonBody, _ := json.Marshal(reqBody)

	ts.mockAuthService.On("ResendVerificationEmail", mock.Anything, reqBody.Email).Return(domainErrors.ErrUserNotFound).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/email/resend-verification", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	ts.router.ServeHTTP(w, req)

	// Service returns ErrUserNotFound, handler should probably still return OK to prevent enumeration
	assert.Equal(t, http.StatusOK, w.Code)
	ts.mockAuthService.AssertExpectations(t)
}

// --- Logout / LogoutAll Tests (Basic) ---
// These tests assume middleware correctly extracts user/token info and passes to handler via context.
// For Logout, the handler itself is simple, most logic is in service.
// For LogoutAll, also simple.

func TestAuthHandler_Logout_Success(t *testing.T) {
	ts := setupAuthHandlerTestSuite(t)

	// Simulate middleware providing tokens (actual values don't matter much for handler logic itself if service is mocked)
	// The handler reads them from cookies.

	ts.mockAuthService.On("Logout", mock.Anything, "test-access-token", "test-refresh-token").Return(nil).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	// Simulate cookies being present
	req.AddCookie(&http.Cookie{Name: "access_token", Value: "test-access-token"})
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "test-refresh-token"})

	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	// Check cookies are cleared
	clearedAccess := false
	clearedRefresh := false
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == "access_token" && cookie.MaxAge < 0 {
			clearedAccess = true
		}
		if cookie.Name == "refresh_token" && cookie.MaxAge < 0 {
			clearedRefresh = true
		}
	}
	assert.True(t, clearedAccess, "Access token cookie should be cleared")
	assert.True(t, clearedRefresh, "Refresh token cookie should be cleared")
	ts.mockAuthService.AssertExpectations(t)
}

func TestAuthHandler_LogoutAll_Success(t *testing.T) {
	ts := setupAuthHandlerTestSuite(t)

	ts.mockAuthService.On("LogoutAll", mock.Anything, "test-access-token").Return(nil).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/logout/all", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: "test-access-token"})
	// refresh_token cookie is not strictly needed by LogoutAll handler if AT is primary for identifying user.

	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	// Check cookies are cleared
	clearedAccess := false
	clearedRefresh := false
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == "access_token" && cookie.MaxAge < 0 {
			clearedAccess = true
		}
		if cookie.Name == "refresh_token" && cookie.MaxAge < 0 { // Also expect refresh to be cleared
			clearedRefresh = true
		}
	}
	assert.True(t, clearedAccess, "Access token cookie should be cleared on logout all")
	assert.True(t, clearedRefresh, "Refresh token cookie should be cleared on logout all")
	ts.mockAuthService.AssertExpectations(t)
}

func TestAuthHandler_Logout_ServiceError(t *testing.T) {
	ts := setupAuthHandlerTestSuite(t)

	ts.mockAuthService.On("Logout", mock.Anything, "test-access-token", "test-refresh-token").Return(errors.New("svc error")).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: "test-access-token"})
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "test-refresh-token"})

	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	ts.mockAuthService.AssertExpectations(t)
}

func TestAuthHandler_LogoutAll_InvalidToken(t *testing.T) {
	ts := setupAuthHandlerTestSuite(t)

	ts.mockAuthService.On("LogoutAll", mock.Anything, "bad-token").Return(domainErrors.ErrInvalidToken).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/logout/all", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: "bad-token"})

	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	ts.mockAuthService.AssertExpectations(t)
}

func TestAuthHandler_LogoutAll_ServiceError(t *testing.T) {
	ts := setupAuthHandlerTestSuite(t)

	ts.mockAuthService.On("LogoutAll", mock.Anything, "test-access-token").Return(errors.New("svc error")).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/logout/all", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: "test-access-token"})

	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	ts.mockAuthService.AssertExpectations(t)
}

// --- TelegramLogin Tests ---
func TestAuthHandler_TelegramLogin_Success(t *testing.T) {
	ts := setupAuthHandlerTestSuite(t)

	tgReq := models.TelegramLoginRequest{ID: 12345, FirstName: "Tele", Username: "teleUser", AuthDate: time.Now().Unix(), Hash: "validhash"}
	jsonBody, _ := json.Marshal(tgReq)

	mockTokenPair := &models.TokenPair{AccessToken: "tg_access_token", RefreshToken: "tg_refresh_token"}
	mockUser := &models.User{ID: uuid.New(), Username: "teleUser"}

	ts.mockAuthService.On("LoginWithTelegram", mock.Anything, tgReq, mock.AnythingOfType("map[string]string")).Return(mockTokenPair, mockUser, nil).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/telegram/login", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "test-telegram-agent")
	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var respBody LoginUserResponse
	err := json.Unmarshal(w.Body.Bytes(), &respBody)
	require.NoError(t, err)
	assert.Equal(t, mockTokenPair.AccessToken, respBody.AccessToken)
	ts.mockAuthService.AssertExpectations(t)
}

func TestAuthHandler_TelegramLogin_AuthFailed(t *testing.T) {
	ts := setupAuthHandlerTestSuite(t)
	tgReq := models.TelegramLoginRequest{ID: 12345, Hash: "invalidhash"} // Incomplete/invalid data
	jsonBody, _ := json.Marshal(tgReq)

	ts.mockAuthService.On("LoginWithTelegram", mock.Anything, tgReq, mock.AnythingOfType("map[string]string")).Return(nil, nil, domainErrors.ErrTelegramAuthFailed).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/telegram/login", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	ts.mockAuthService.AssertExpectations(t)
}

func TestAuthHandler_TelegramLogin_BadRequest(t *testing.T) {
	ts := setupAuthHandlerTestSuite(t)

	w := httptest.NewRecorder()
	// Missing 'id' which is required by struct binding
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/telegram/login", bytes.NewBuffer([]byte(`{"username":"test"}`)))
	req.Header.Set("Content-Type", "application/json")
	ts.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func init() {
	gin.SetMode(gin.TestMode)
}

var _ domainService.AuthLogicService = (*MockAuthServiceForHandler)(nil)
var _ domainService.MFALogicService = (*MockMFALogicServiceForHandler)(nil)
var _ domainService.TokenManagementService = (*MockTokenManagementServiceForHandler)(nil)
