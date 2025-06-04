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
	"github.com/your-org/auth-service/internal/utils/middleware"
	"go.uber.org/zap"
)

// --- Mocks ---

type MockUserServiceForUserHandler struct {
	mock.Mock
}
func (m *MockUserServiceForUserHandler) GetUserByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil { return nil, args.Error(1) }
	return args.Get(0).(*models.User), args.Error(1)
}
func (m *MockUserServiceForUserHandler) CreateUser(ctx context.Context, req models.CreateUserRequest, actorID *uuid.UUID) (*models.User, error) { panic("not implemented in mock for UserHandler tests") }
func (m *MockUserServiceForUserHandler) UpdateUser(ctx context.Context, id uuid.UUID, req models.UpdateUserRequest, actorID *uuid.UUID) (*models.User, error) { panic("not implemented in mock for UserHandler tests") }
func (m *MockUserServiceForUserHandler) DeleteUser(ctx context.Context, id uuid.UUID, actorID *uuid.UUID) error { panic("not implemented in mock for UserHandler tests") }
func (m *MockUserServiceForUserHandler) ChangePassword(ctx context.Context, id uuid.UUID, oldPassword, newPassword string) error { panic("not implemented in mock for UserHandler tests") }
func (m *MockUserServiceForUserHandler) BlockUser(ctx context.Context, id uuid.UUID, actorID *uuid.UUID, reason string) error { panic("not implemented in mock for UserHandler tests") }
func (m *MockUserServiceForUserHandler) UnblockUser(ctx context.Context, id uuid.UUID, actorID *uuid.UUID) error { panic("not implemented in mock for UserHandler tests") }


type MockAuthServiceForUserHandler struct {
	mock.Mock
}
func (m *MockAuthServiceForUserHandler) ChangePassword(ctx context.Context, userID uuid.UUID, oldPlainPassword, newPlainPassword string) error {
	args := m.Called(ctx, userID, oldPlainPassword, newPlainPassword)
	return args.Error(0)
}
func (m *MockAuthServiceForUserHandler) Register(ctx context.Context, req models.CreateUserRequest) (*models.User, string, error) {panic("not used by UserHandler tests")}
func (m *MockAuthServiceForUserHandler) Login(ctx context.Context, req models.LoginRequest) (*models.TokenPair, *models.User, string, error) {panic("not used by UserHandler tests")}
func (m *MockAuthServiceForUserHandler) CompleteLoginAfter2FA(ctx context.Context, userID uuid.UUID, deviceInfo map[string]string) (*models.TokenPair, *models.User, error) {panic("not used by UserHandler tests")}
func (m *MockAuthServiceForUserHandler) RefreshToken(ctx context.Context, plainOpaqueRefreshToken string) (*models.TokenPair, error) {panic("not used by UserHandler tests")}
func (m *MockAuthServiceForUserHandler) Logout(ctx context.Context, accessToken, refreshToken string) error {panic("not used by UserHandler tests")}
func (m *MockAuthServiceForUserHandler) LogoutAll(ctx context.Context, accessToken string) error {panic("not used by UserHandler tests")}
func (m *MockAuthServiceForUserHandler) SystemLogoutAllUserSessions(ctx context.Context, userID uuid.UUID, actorID string, reason string) error {panic("not used by UserHandler tests")}
func (m *MockAuthServiceForUserHandler) VerifyEmail(ctx context.Context, plainVerificationTokenValue string) error {panic("not used by UserHandler tests")}
func (m *MockAuthServiceForUserHandler) ResendVerificationEmail(ctx context.Context, email string) error {panic("not used by UserHandler tests")}
func (m *MockAuthServiceForUserHandler) ForgotPassword(ctx context.Context, email string) error {panic("not used by UserHandler tests")}
func (m *MockAuthServiceForUserHandler) ResetPassword(ctx context.Context, plainToken, newPassword string) error {panic("not used by UserHandler tests")}
func (m *MockAuthServiceForUserHandler) CheckUserPermission(ctx context.Context, userID uuid.UUID, permissionKey string, resourceID *string) (bool, error) {panic("not used by UserHandler tests")}
func (m *MockAuthServiceForUserHandler) LoginWithTelegram(ctx context.Context, tgData models.TelegramLoginRequest, deviceInfo map[string]string) (*models.TokenPair, *models.User, error) {panic("not used by UserHandler tests")}
func (m *MockAuthServiceForUserHandler) InitiateOAuthLogin(ctx context.Context, providerName string, clientProvidedRedirectURI string, clientProvidedState string) (string, string, error) {panic("not used by UserHandler tests")}
func (m *MockAuthServiceForUserHandler) HandleOAuthCallback(ctx context.Context, providerName string, authorizationCode string, receivedCSRFState string, stateCookieJWT string, deviceInfo map[string]string) (*models.TokenPair, *models.User, error) {panic("not used by UserHandler tests")}


type MockSessionServiceForUserHandler struct {
    mock.Mock
}
func (m *MockSessionServiceForUserHandler) GetUserSessions(ctx context.Context, userID uuid.UUID, params models.ListSessionsParams) ([]*models.Session, int64, error) {
    args := m.Called(ctx, userID, params)
    if args.Get(0) == nil { return nil, int64(args.Int(1)), args.Error(2) }
    return args.Get(0).([]*models.Session), int64(args.Int(1)), args.Error(2)
}
func (m *MockSessionServiceForUserHandler) DeactivateSession(ctx context.Context, sessionID uuid.UUID, actorID *uuid.UUID) error {
    args := m.Called(ctx, sessionID, actorID)
    return args.Error(0)
}
func (m *MockSessionServiceForUserHandler) FindByID(ctx context.Context, sessionID uuid.UUID) (*models.Session, error) { panic("not implemented in mock") }
func (m *MockSessionServiceForUserHandler) DeleteByUserID(ctx context.Context, userID uuid.UUID, excludeSessionID *uuid.UUID) (int64, error) { panic("not implemented in mock") }
func (m *MockSessionServiceForUserHandler) CleanupExpiredSessions(ctx context.Context) (int64, error) {panic("not implemented in mock")}
func (m *MockSessionServiceForUserHandler) CreateSession(ctx context.Context, userID uuid.UUID, userAgent string, ipAddress string) (*models.Session, error) {panic("not implemented in mock")}



type MockMFALogicServiceForUserHandler struct {
	mock.Mock
}
func (m *MockMFALogicServiceForUserHandler) Enable2FAInitiate(ctx context.Context, userID uuid.UUID, accountName string) (mfaSecretID uuid.UUID, secretBase32 string, otpAuthURL string, err error) {
	args := m.Called(ctx, userID, accountName)
	var id uuid.UUID; if val, ok := args.Get(0).(uuid.UUID); ok { id = val }
	return id, args.String(1), args.String(2), args.Error(3)
}
func (m *MockMFALogicServiceForUserHandler) VerifyAndActivate2FA(ctx context.Context, userID uuid.UUID, plainTOTPCode string, mfaSecretID uuid.UUID) (backupCodes []string, err error) {
	args := m.Called(ctx, userID, plainTOTPCode, mfaSecretID)
	if args.Get(0) == nil { return nil, args.Error(1) }
	return args.Get(0).([]string), args.Error(1)
}
func (m *MockMFALogicServiceForUserHandler) Disable2FA(ctx context.Context, userID uuid.UUID, verificationToken string, verificationMethod string) error {
	args := m.Called(ctx, userID, verificationToken, verificationMethod)
	return args.Error(0)
}
func (m *MockMFALogicServiceForUserHandler) RegenerateBackupCodes(ctx context.Context, userID uuid.UUID, verificationToken string, verificationMethod string) (backupCodes []string, err error){
	args := m.Called(ctx, userID, verificationToken, verificationMethod)
	if args.Get(0) == nil { return nil, args.Error(1) }
	return args.Get(0).([]string), args.Error(1)
}
func (m *MockMFALogicServiceForUserHandler) Verify2FACode(ctx context.Context, userID uuid.UUID, code string, codeType models.MFAType) (bool, error) {
    args := m.Called(ctx, userID, code, codeType)
    return args.Bool(0), args.Error(1)
}


type MockAPIKeyServiceForUserHandler struct {
	mock.Mock
}
func (m *MockAPIKeyServiceForUserHandler) CreateAPIKey(ctx context.Context, userID uuid.UUID, req models.CreateAPIKeyRequest) (*models.APIKey, string, error) {
    args := m.Called(ctx, userID, req)
    r0, r1, r2 := args.Get(0), args.String(1), args.Error(2)
    var apiKey *models.APIKey; if r0 != nil { apiKey = r0.(*models.APIKey) }
    return apiKey, r1, r2
}
func (m *MockAPIKeyServiceForUserHandler) ListUserAPIKeys(ctx context.Context, userID uuid.UUID) ([]*models.APIKey, error) {
    args := m.Called(ctx, userID)
    if args.Get(0) == nil { return nil, args.Error(1) }
    return args.Get(0).([]*models.APIKey), args.Error(1)
}
func (m *MockAPIKeyServiceForUserHandler) DeleteAPIKey(ctx context.Context, userID uuid.UUID, keyID uuid.UUID) error {
    args := m.Called(ctx, userID, keyID)
    return args.Error(0)
}


// --- Test Suite Setup ---
type UserHandlerTestSuite struct {
	router             *gin.Engine
	mockUserService    domainService.UserService
	mockAuthService    domainService.AuthLogicService
	mockSessionService domainService.SessionManager
	mockMfaLogicSvc    domainService.MFALogicService
	mockApiKeyService  domainService.APIKeyService
	userHandler        *UserHandler
	testConfig         *config.Config
}

func setupUserHandlerTestSuite(t *testing.T) *UserHandlerTestSuite {
	gin.SetMode(gin.TestMode)
	ts := &UserHandlerTestSuite{}

	ts.mockUserService = new(MockUserServiceForUserHandler)
	ts.mockAuthService = new(MockAuthServiceForUserHandler)
	ts.mockSessionService = new(MockSessionServiceForUserHandler)
	ts.mockMfaLogicSvc = new(MockMFALogicServiceForUserHandler)
	ts.mockApiKeyService = new(MockAPIKeyServiceForUserHandler)

	logger := zap.NewNop()
	ts.testConfig = &config.Config{ /* ... */ }

	ts.userHandler = NewUserHandler(
		ts.mockUserService,
		ts.mockAuthService,
		ts.mockSessionService,
		ts.mockMfaLogicSvc,
		ts.mockApiKeyService,
		logger,
	)

	ts.router = gin.New()
	meRoutes := ts.router.Group("/api/v1/me")
	meRoutes.Use(func(c *gin.Context) { c.Next() })
	{
		meRoutes.GET("", ts.userHandler.GetCurrentUser)
		meRoutes.POST("/change-password", ts.userHandler.ChangePassword)
		meRoutes.POST("/2fa/totp/enable", ts.userHandler.Enable2FAInitiate)
		meRoutes.POST("/api-keys", ts.userHandler.CreateAPIKey)
	}
	return ts
}


// --- Test GetCurrentUser (GetMe) ---
func TestUserHandler_GetCurrentUser_Success(t *testing.T) {
	ts := setupUserHandlerTestSuite(t)
	userID := uuid.New()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set(middleware.GinContextUserIDKey, userID.String())
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/me", nil)
	c.Request = req


	mockUser := &models.User{
		ID:        userID,
		Email:     "me@example.com",
		Username:  "me_user",
		CreatedAt: time.Now().Add(-time.Hour),
		UpdatedAt: time.Now(),
	}
	ts.mockUserService.On("GetUserByID", c.Request.Context(), userID).Return(mockUser, nil).Once()

	ts.userHandler.GetCurrentUser(c)

	assert.Equal(t, http.StatusOK, w.Code)
	var respBody models.UserResponse
	err := json.Unmarshal(w.Body.Bytes(), &respBody)
	require.NoError(t, err)
	assert.Equal(t, userID, respBody.ID)
	assert.Equal(t, mockUser.Email, respBody.Email)
	assert.Equal(t, mockUser.Username, respBody.Username)

	ts.mockUserService.AssertExpectations(t)
}

// --- Test ChangePassword ---
func TestUserHandler_ChangePassword_Success(t *testing.T) {
	ts := setupUserHandlerTestSuite(t)
	userID := uuid.New()

	reqBody := models.ChangePasswordRequest{OldPassword: "oldPassword", NewPassword: "newPassword123"}
	jsonBody, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set(middleware.GinContextUserIDKey, userID.String())
	httpRequest, _ := http.NewRequest(http.MethodPost, "/api/v1/me/change-password", bytes.NewBuffer(jsonBody))
	httpRequest.Header.Set("Content-Type", "application/json")
	c.Request = httpRequest


	ts.mockAuthService.On("ChangePassword", c.Request.Context(), userID, reqBody.OldPassword, reqBody.NewPassword).Return(nil).Once()

	ts.userHandler.ChangePassword(c)

	assert.Equal(t, http.StatusOK, w.Code)
	var respBody map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &respBody)
	require.NoError(t, err)
	assert.Equal(t, "Password successfully changed", respBody["message"])

	ts.mockAuthService.AssertExpectations(t)
}

func TestUserHandler_ChangePassword_Failure_WrongOldPassword(t *testing.T) {
	ts := setupUserHandlerTestSuite(t)
	userID := uuid.New()

	reqBody := models.ChangePasswordRequest{OldPassword: "wrongOldPassword", NewPassword: "newPassword123"}
	jsonBody, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set(middleware.GinContextUserIDKey, userID.String())
	httpRequest, _ := http.NewRequest(http.MethodPost, "/api/v1/me/change-password", bytes.NewBuffer(jsonBody))
	httpRequest.Header.Set("Content-Type", "application/json")
	c.Request = httpRequest

	ts.mockAuthService.On("ChangePassword", c.Request.Context(), userID, reqBody.OldPassword, reqBody.NewPassword).Return(domainErrors.ErrInvalidCredentials).Once()

	ts.userHandler.ChangePassword(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	ts.mockAuthService.AssertExpectations(t)
}

// --- Test Enable2FAInitiate ---
func TestUserHandler_Enable2FAInitiate_Success(t *testing.T) {
	ts := setupUserHandlerTestSuite(t)
	userID := uuid.New()
	userEmail := "test@example.com"

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set(middleware.GinContextUserIDKey, userID.String())
	c.Set(middleware.GinContextClaimsKey, &domainService.Claims{Email: userEmail, Username: "testuser"}) // Simulate claims
	httpRequest, _ := http.NewRequest(http.MethodPost, "/api/v1/me/2fa/totp/enable", nil)
	c.Request = httpRequest


	mfaSecretID := uuid.New()
	secretKey := "TESTSECRET32"
	qrCodeURL := "otpauth://..."

	// UserHandler's Enable2FAInitiate extracts username from claims if available, then email as fallback for accountName.
	// If claims has username "testuser", it should be used.
	ts.mockMfaLogicSvc.On("Enable2FAInitiate", c.Request.Context(), userID, "testuser").Return(mfaSecretID, secretKey, qrCodeURL, nil).Once()

	ts.userHandler.Enable2FAInitiate(c)

	assert.Equal(t, http.StatusOK, w.Code)
	var respBody models.Enable2FAInitiateResponse
	err := json.Unmarshal(w.Body.Bytes(), &respBody)
	require.NoError(t, err)
	assert.Equal(t, mfaSecretID.String(), respBody.MFASecretID)
	assert.Equal(t, secretKey, respBody.SecretKey)
	assert.Equal(t, qrCodeURL, respBody.QRCodeImage)

	ts.mockMfaLogicSvc.AssertExpectations(t)
}

// --- Test CreateAPIKey ---
func TestUserHandler_CreateAPIKey_Success(t *testing.T) {
	ts := setupUserHandlerTestSuite(t)
	userID := uuid.New()

	reqBody := models.CreateAPIKeyRequest{Name: "Test Key", ExpiresInDays: 30}
	jsonBody, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set(middleware.GinContextUserIDKey, userID.String())
	httpRequest, _ := http.NewRequest(http.MethodPost, "/api/v1/me/api-keys", bytes.NewBuffer(jsonBody))
	httpRequest.Header.Set("Content-Type", "application/json")
	c.Request = httpRequest

	apiKeyID := uuid.New()
	mockAPIKeyModel := &models.APIKey{
		ID:        apiKeyID,
		UserID:    userID,
		Name:      reqBody.Name,
		KeyPrefix: "testprefix_",
		CreatedAt: time.Now(),
		// ExpiresAt will be set by service
	}
	plainFullAPIKey := "testprefix_plainsecretpart"

	ts.mockApiKeyService.On("CreateAPIKey", c.Request.Context(), userID, reqBody).Return(mockAPIKeyModel, plainFullAPIKey, nil).Once()

	ts.userHandler.CreateAPIKey(c)

	assert.Equal(t, http.StatusCreated, w.Code)
	var respBody models.APIKeyCreateResponse
	err := json.Unmarshal(w.Body.Bytes(), &respBody)
	require.NoError(t, err)
	assert.Equal(t, plainFullAPIKey, respBody.PlainAPIKey)
	assert.Equal(t, apiKeyID, respBody.APIKeyMetadata.ID)
	assert.Equal(t, reqBody.Name, respBody.APIKeyMetadata.Name)

	ts.mockApiKeyService.AssertExpectations(t)
}


func init() {
	gin.SetMode(gin.TestMode)
}

var _ domainService.UserService = (*MockUserServiceForUserHandler)(nil)
var _ domainService.AuthLogicService = (*MockAuthServiceForUserHandler)(nil)
var _ domainService.SessionManager = (*MockSessionServiceForUserHandler)(nil)
var _ domainService.MFALogicService = (*MockMFALogicServiceForUserHandler)(nil)
var _ domainService.APIKeyService = (*MockAPIKeyServiceForUserHandler)(nil)

// Added missing methods to satisfy interfaces (if UserHandler was refactored to use interfaces)
// For SessionManager
func (m *MockSessionServiceForUserHandler) FindByID(ctx context.Context, sessionID uuid.UUID) (*models.Session, error) { panic("not implemented in mock") }
func (m *MockSessionServiceForUserHandler) DeleteByUserID(ctx context.Context, userID uuid.UUID, excludeSessionID *uuid.UUID) (int64, error) { panic("not implemented in mock") }
func (m *MockSessionServiceForUserHandler) CleanupExpiredSessions(ctx context.Context) (int64, error) {panic("not implemented in mock")}
func (m *MockSessionServiceForUserHandler) CreateSession(ctx context.Context, userID uuid.UUID, userAgent string, ipAddress string) (*models.Session, error) {panic("not implemented in mock")}

// For TokenManagementService (mock was already mostly complete from auth_handler_test)
func (m *MockTokenManagementServiceForHandler) Generate2FAChallengeToken(userID string) (string, error) { // This was missing for the interface
	args := m.Called(userID)
	return args.String(0), args.Error(1)
}
var _ domainService.TokenManagementService = (*MockTokenManagementServiceForHandler)(nil) // Re-assert for completeness
