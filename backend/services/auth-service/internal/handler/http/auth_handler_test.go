package http

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/your-org/auth-service/internal/config"
	"github.com/your-org/auth-service/internal/domain/models"
	domainErrors "github.com/your-org/auth-service/internal/domain/errors"
	domainService "github.com/your-org/auth-service/internal/domain/service"
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
	if r0 != nil { tp = r0.(*models.TokenPair) }
	var user *models.User
	if r1 != nil { user = r1.(*models.User) }
	return tp, user, r2, r3
}
func (m *MockAuthServiceForHandler) CompleteLoginAfter2FA(ctx context.Context, userID uuid.UUID, deviceInfo map[string]string) (*models.TokenPair, *models.User, error) {
    args := m.Called(ctx, userID, deviceInfo)
    r0, r1, r2 := args.Get(0), args.Get(1), args.Error(2)
    var tp *models.TokenPair
    if r0 != nil { tp = r0.(*models.TokenPair) }
    var user *models.User
    if r1 != nil { user = r1.(*models.User) }
    return tp, user, r2
}
func (m *MockAuthServiceForHandler) RefreshToken(ctx context.Context, plainOpaqueRefreshToken string) (*models.TokenPair, error) {
	args := m.Called(ctx, plainOpaqueRefreshToken)
	if args.Get(0) == nil { return nil, args.Error(1) }
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
	var tp *models.TokenPair; if args.Get(0) != nil {tp = args.Get(0).(*models.TokenPair)}
	var user *models.User; if args.Get(1) != nil {user = args.Get(1).(*models.User)}
	return tp, user, args.Error(2)
}
func (m *MockAuthServiceForHandler) InitiateOAuthLogin(ctx context.Context, providerName string, clientProvidedRedirectURI string, clientProvidedState string) (string, string, error) {
    args := m.Called(ctx, providerName, clientProvidedRedirectURI, clientProvidedState)
    return args.String(0), args.String(1), args.Error(2)
}
func (m *MockAuthServiceForHandler) HandleOAuthCallback(ctx context.Context, providerName string, authorizationCode string, receivedCSRFState string, stateCookieJWT string, deviceInfo map[string]string) (*models.TokenPair, *models.User, error) {
	args := m.Called(ctx, providerName, authorizationCode, receivedCSRFState, stateCookieJWT, deviceInfo)
	var tp *models.TokenPair; if args.Get(0) != nil {tp = args.Get(0).(*models.TokenPair)}
	var user *models.User; if args.Get(1) != nil {user = args.Get(1).(*models.User)}
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
	if args.Get(0) == nil { return nil, args.Error(1) }
	return args.Get(0).([]string), args.Error(1)
}
func (m *MockMFALogicServiceForHandler) Disable2FA(ctx context.Context, userID uuid.UUID, verificationToken string, verificationMethod string) error {
	args := m.Called(ctx, userID, verificationToken, verificationMethod)
	return args.Error(0)
}
func (m *MockMFALogicServiceForHandler) RegenerateBackupCodes(ctx context.Context, userID uuid.UUID, verificationToken string, verificationMethod string) (backupCodes []string, err error){
	args := m.Called(ctx, userID, verificationToken, verificationMethod)
	if args.Get(0) == nil { return nil, args.Error(1) }
	return args.Get(0).([]string), args.Error(1)
}


type MockTokenManagementServiceForHandler struct {
	mock.Mock
}
func (m *MockTokenManagementServiceForHandler) Validate2FAChallengeToken(challengeToken string) (string, error) {
    args := m.Called(challengeToken)
    return args.String(0), args.Error(1)
}
func (m *MockTokenManagementServiceForHandler) GenerateAccessToken(userID, username string, roles, permissions []string, sessionID string) (string, error) { panic("not implemented for this mock") }
func (m *MockTokenManagementServiceForHandler) ValidateAccessToken(tokenString string) (*domainService.Claims, error) { panic("not implemented for this mock") }
func (m *MockTokenManagementServiceForHandler) GenerateRefreshTokenValue() (string, error) { panic("not implemented for this mock") }
func (m *MockTokenManagementServiceForHandler) GetRefreshTokenExpiry() time.Time { panic("not implemented for this mock") }
func (m *MockTokenManagementServiceForHandler) GetJWKS() ([]byte, error) { panic("not implemented for this mock") }
func (m *MockTokenManagementServiceForHandler) GenerateStateJWT(claims *domainService.OAuthStateClaims, secret string, ttl time.Duration) (string, error) { panic("not implemented for this mock") }
func (m *MockTokenManagementServiceForHandler) ValidateStateJWT(tokenString string, secret string) (*domainService.OAuthStateClaims, error) { panic("not implemented for this mock") }
// Generate2FAChallengeToken on TokenManagementService is actually defined with (userID string) (string, error)
// This mock already has Validate2FAChallengeToken, so Generate2FAChallengeToken is not strictly needed here
// unless AuthHandler calls it directly (which it doesn't seem to).

// --- Test Suite Setup ---
type AuthHandlerTestSuite struct {
	router             *gin.Engine
	mockAuthService    *MockAuthServiceForHandler
	mockMfaLogicSvc    *MockMFALogicServiceForHandler
	mockTokenMgmtSvc   *MockTokenManagementServiceForHandler
	authHandler        *AuthHandler
}

func setupAuthHandlerTestSuite(t *testing.T) *AuthHandlerTestSuite {
	gin.SetMode(gin.TestMode)
	ts := &AuthHandlerTestSuite{}

	ts.mockAuthService = new(MockAuthServiceForHandler)
	ts.mockMfaLogicSvc = new(MockMFALogicServiceForHandler)
	ts.mockTokenMgmtSvc = new(MockTokenManagementServiceForHandler)

	logger := zap.NewNop()
	testConfig := &config.Config{ /* Populate with minimal needed config for handlers */ }

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
		// Add other routes as their tests are written
	}
	return ts
}


// --- Tests ---
// ... (RegisterUser, LoginUser tests from previous steps) ...

func TestAuthHandler_RegisterUser_Success(t *testing.T) {
	ts := setupAuthHandlerTestSuite(t)

	reqBody := RegisterUserRequest{
		Email:    "test@example.com",
		Username: "testuser",
		Password: "password123",
	}
	jsonBody, _ := json.Marshal(reqBody)

	mockUser := &models.User{ID: uuid.New(), Email: reqBody.Email, Username: reqBody.Username, CreatedAt: time.Now()}
	mockVerificationToken := "mockVerificationToken"

	ts.mockAuthService.On("Register", mock.Anything, mock.MatchedBy(func(r models.CreateUserRequest) bool {
		return r.Email == reqBody.Email && r.Username == reqBody.Username
	})).Return(mockUser, mockVerificationToken, nil).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var respBody map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &respBody)
	require.NoError(t, err)
	assert.Equal(t, mockUser.ID.String(), respBody["user_id"])
	assert.Equal(t, reqBody.Email, respBody["email"])
	assert.Contains(t, respBody, "message")

	ts.mockAuthService.AssertExpectations(t)
}

func TestAuthHandler_RegisterUser_Failure_EmailExists(t *testing.T) {
	ts := setupAuthHandlerTestSuite(t)

	reqBody := RegisterUserRequest{Email: "exists@example.com", Username: "user", Password: "password"}
	jsonBody, _ := json.Marshal(reqBody)

	ts.mockAuthService.On("Register", mock.Anything, mock.AnythingOfType("models.CreateUserRequest")).Return(nil, "", domainErrors.ErrEmailExists).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)
	ts.mockAuthService.AssertExpectations(t)
}

// --- LoginUser Tests ---
func TestAuthHandler_LoginUser_Success_No2FA(t *testing.T) {
	ts := setupAuthHandlerTestSuite(t)
	reqBody := LoginRequest{Email: "test@example.com", Password: "password123"}
	jsonBody, _ := json.Marshal(reqBody)

	mockTokenPair := &models.TokenPair{AccessToken: "access_token", RefreshToken: "refresh_token"}
	mockUser := &models.User{ID: uuid.New(), Email: reqBody.Email}

	ts.mockAuthService.On("Login", mock.Anything, mock.AnythingOfType("models.LoginRequest")).Return(mockTokenPair, mockUser, "", nil).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var respBody LoginUserResponse
	err := json.Unmarshal(w.Body.Bytes(), &respBody)
	require.NoError(t, err)
	assert.Equal(t, mockTokenPair.AccessToken, respBody.AccessToken)
	assert.Equal(t, mockTokenPair.RefreshToken, respBody.RefreshToken)
	assert.Empty(t, respBody.ChallengeToken, "ChallengeToken should be empty for no 2FA")

	ts.mockAuthService.AssertExpectations(t)
}

func TestAuthHandler_LoginUser_Success_2FARequired(t *testing.T) {
	ts := setupAuthHandlerTestSuite(t)
	reqBody := LoginRequest{Email: "test2fa@example.com", Password: "password123"}
	jsonBody, _ := json.Marshal(reqBody)

	mockUser := &models.User{ID: uuid.New(), Email: reqBody.Email}
	challengeToken := "2fa_challenge_token"

	ts.mockAuthService.On("Login", mock.Anything, mock.AnythingOfType("models.LoginRequest")).Return(nil, mockUser, challengeToken, domainErrors.Err2FARequired).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusAccepted, w.Code)
	var respBody LoginUserResponse
	err := json.Unmarshal(w.Body.Bytes(), &respBody)
	require.NoError(t, err)
	assert.Empty(t, respBody.AccessToken)
	assert.Empty(t, respBody.RefreshToken)
	assert.Equal(t, challengeToken, respBody.ChallengeToken)
	assert.Equal(t, mockUser.ID.String(), respBody.UserID)

	ts.mockAuthService.AssertExpectations(t)
}

func TestAuthHandler_LoginUser_Failure_InvalidCredentials(t *testing.T) {
	ts := setupAuthHandlerTestSuite(t)
	reqBody := LoginRequest{Email: "test@example.com", Password: "wrongpassword"}
	jsonBody, _ := json.Marshal(reqBody)

	ts.mockAuthService.On("Login", mock.Anything, mock.AnythingOfType("models.LoginRequest")).Return(nil, nil, "", domainErrors.ErrInvalidCredentials).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	ts.mockAuthService.AssertExpectations(t)
}

// --- VerifyLogin2FA Tests ---
func TestAuthHandler_VerifyLogin2FA_Success(t *testing.T) {
	ts := setupAuthHandlerTestSuite(t)
	userID := uuid.New()
	reqBody := VerifyLogin2FARequest{ChallengeToken: "valid_challenge", Code: "123456"}
	jsonBody, _ := json.Marshal(reqBody)

	mockTokenPair := &models.TokenPair{AccessToken: "access_token_final", RefreshToken: "refresh_token_final"}
	mockUser := &models.User{ID: userID}

	ts.mockTokenMgmtSvc.On("Validate2FAChallengeToken", reqBody.ChallengeToken).Return(userID.String(), nil).Once()
	ts.mockMfaLogicSvc.On("Verify2FACode", mock.Anything, userID, reqBody.Code, models.MFATypeTOTP).Return(true, nil).Once()
	ts.mockAuthService.On("CompleteLoginAfter2FA", mock.Anything, userID, mock.AnythingOfType("map[string]string")).Return(mockTokenPair, mockUser, nil).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login/2fa/verify", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "test-agent")
	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var respBody LoginUserResponse
	err := json.Unmarshal(w.Body.Bytes(), &respBody)
	require.NoError(t, err)
	assert.Equal(t, mockTokenPair.AccessToken, respBody.AccessToken)
	assert.Equal(t, mockTokenPair.RefreshToken, respBody.RefreshToken)

	ts.mockTokenMgmtSvc.AssertExpectations(t)
	ts.mockMfaLogicSvc.AssertExpectations(t)
	ts.mockAuthService.AssertExpectations(t)
}

func TestAuthHandler_VerifyLogin2FA_Failure_InvalidChallengeToken(t *testing.T) {
	ts := setupAuthHandlerTestSuite(t)
	reqBody := VerifyLogin2FARequest{ChallengeToken: "invalid_challenge", Code: "123456"}
	jsonBody, _ := json.Marshal(reqBody)

	ts.mockTokenMgmtSvc.On("Validate2FAChallengeToken", reqBody.ChallengeToken).Return("", errors.New("invalid token")).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login/2fa/verify", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	ts.mockTokenMgmtSvc.AssertExpectations(t)
	ts.mockMfaLogicSvc.AssertNotCalled(t, "Verify2FACode")
	ts.mockAuthService.AssertNotCalled(t, "CompleteLoginAfter2FA")
}

func TestAuthHandler_VerifyLogin2FA_Failure_Invalid2FACode(t *testing.T) {
	ts := setupAuthHandlerTestSuite(t)
	userID := uuid.New()
	reqBody := VerifyLogin2FARequest{ChallengeToken: "valid_challenge", Code: "wrong_code"}
	jsonBody, _ := json.Marshal(reqBody)

	ts.mockTokenMgmtSvc.On("Validate2FAChallengeToken", reqBody.ChallengeToken).Return(userID.String(), nil).Once()
	ts.mockMfaLogicSvc.On("Verify2FACode", mock.Anything, userID, reqBody.Code, models.MFATypeTOTP).Return(false, nil).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login/2fa/verify", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	ts.mockTokenMgmtSvc.AssertExpectations(t)
	ts.mockMfaLogicSvc.AssertExpectations(t)
	ts.mockAuthService.AssertNotCalled(t, "CompleteLoginAfter2FA")
}

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


func init() {
	gin.SetMode(gin.TestMode)
}


var _ domainService.AuthLogicService = (*MockAuthServiceForHandler)(nil)
var _ domainService.MFALogicService = (*MockMFALogicServiceForHandler)(nil)
var _ domainService.TokenManagementService = (*MockTokenManagementServiceForHandler)(nil)
