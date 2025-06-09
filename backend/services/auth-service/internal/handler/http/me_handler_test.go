// File: backend/services/auth-service/internal/handler/http/me_handler_test.go
package http

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/config"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors"
	domainService "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/service"
	"go.uber.org/zap"
)

// --- Mocks for MeHandler Dependencies ---

// MockUserServiceForMeHandler (subset of methods called by MeHandler)
type MockUserServiceForMeHandler struct {
	mock.Mock
}

func (m *MockUserServiceForMeHandler) GetUserFullInfo(ctx context.Context, userID uuid.UUID) (*models.UserFullInfo, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.UserFullInfo), args.Error(1)
}
func (m *MockUserServiceForMeHandler) UpdateUserProfile(ctx context.Context, userID uuid.UUID, req models.UpdateUserProfileRequest) (*models.User, error) {
	args := m.Called(ctx, userID, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}
// Add other UserService methods if MeHandler calls them. For now, assuming ChangePassword is via AuthService.

// MockAuthServiceForMeHandler (subset for MeHandler, e.g., ChangePassword, ListSessions, RevokeSession)
type MockAuthServiceForMeHandler struct {
	mock.Mock
}
func (m *MockAuthServiceForMeHandler) ChangePassword(ctx context.Context, userID uuid.UUID, oldPassword, newPassword string) error {
	args := m.Called(ctx, userID, oldPassword, newPassword)
	return args.Error(0)
}
func (m *MockAuthServiceForMeHandler) ListUserSessions(ctx context.Context, userID uuid.UUID) ([]*models.Session, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Session), args.Error(1)
}
func (m *MockAuthServiceForMeHandler) RevokeSession(ctx context.Context, userID uuid.UUID, sessionID uuid.UUID) error {
	args := m.Called(ctx, userID, sessionID)
	return args.Error(0)
}


// MockMFALogicServiceForMeHandler (already defined in auth_handler_test, can be shared or redefined)
type MockMFALogicServiceForMeHandler struct {
	mock.Mock
}
func (m *MockMFALogicServiceForMeHandler) Enable2FAInitiate(ctx context.Context, userID uuid.UUID, accountName string) (mfaSecretID uuid.UUID, secretBase32 string, otpAuthURL string, err error) {
	args := m.Called(ctx, userID, accountName)
	var id uuid.UUID; if val, ok := args.Get(0).(uuid.UUID); ok { id = val }
	return id, args.String(1), args.String(2), args.Error(3)
}
func (m *MockMFALogicServiceForMeHandler) VerifyAndActivate2FA(ctx context.Context, userID uuid.UUID, plainTOTPCode string, mfaSecretID uuid.UUID) (backupCodes []string, err error) {
	args := m.Called(ctx, userID, plainTOTPCode, mfaSecretID)
	if args.Get(0) == nil { return nil, args.Error(1) }
	return args.Get(0).([]string), args.Error(1)
}
func (m *MockMFALogicServiceForMeHandler) Disable2FA(ctx context.Context, userID uuid.UUID, verificationToken string, verificationMethod string) error {
	args := m.Called(ctx, userID, verificationToken, verificationMethod)
	return args.Error(0)
}
func (m *MockMFALogicServiceForMeHandler) RegenerateBackupCodes(ctx context.Context, userID uuid.UUID, verificationToken string, verificationMethod string) (backupCodes []string, err error){
	args := m.Called(ctx, userID, verificationToken, verificationMethod)
	if args.Get(0) == nil { return nil, args.Error(1) }
	return args.Get(0).([]string), args.Error(1)
}


// MockAPIKeyServiceForMeHandler
type MockAPIKeyServiceForMeHandler struct {
	mock.Mock
}
func (m *MockAPIKeyServiceForMeHandler) CreateAPIKey(ctx context.Context, userID uuid.UUID, name string, expiresAt *time.Time) (*models.APIKeyWithSecret, error) {
	args := m.Called(ctx, userID, name, expiresAt)
	if args.Get(0) == nil { return nil, args.Error(1) }
	return args.Get(0).(*models.APIKeyWithSecret), args.Error(1)
}
func (m *MockAPIKeyServiceForMeHandler) ListAPIKeysForUser(ctx context.Context, userID uuid.UUID) ([]*models.APIKey, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil { return nil, args.Error(1) }
	return args.Get(0).([]*models.APIKey), args.Error(1)
}
func (m *MockAPIKeyServiceForMeHandler) RevokeAPIKey(ctx context.Context, userID uuid.UUID, apiKeyID uuid.UUID) error {
	args := m.Called(ctx, userID, apiKeyID)
	return args.Error(0)
}


// --- MeHandler Test Suite ---
type MeHandlerTestSuite struct {
	suite.Suite
	router             *gin.Engine
	mockUserService    *MockUserServiceForMeHandler
	mockAuthService    *MockAuthServiceForMeHandler // For ChangePassword, sessions
	mockMfaLogicSvc    *MockMFALogicServiceForMeHandler
	mockApiKeyService  *MockAPIKeyServiceForMeHandler
	meHandler          *MeHandler
	cfg                *config.Config
	logger             *zap.Logger
}

// Helper function to setup the test suite
func setupMeHandlerTestSuite(t *testing.T) *MeHandlerTestSuite {
	gin.SetMode(gin.TestMode)
	ts := &MeHandlerTestSuite{}

	ts.mockUserService = new(MockUserServiceForMeHandler)
	ts.mockAuthService = new(MockAuthServiceForMeHandler)
	ts.mockMfaLogicSvc = new(MockMFALogicServiceForMeHandler)
	ts.mockApiKeyService = new(MockAPIKeyServiceForMeHandler)

	ts.logger = zap.NewNop()
	ts.cfg = &config.Config{ /* Minimal config for handler tests */ }

	// Assuming NewMeHandler takes these mocks. Adjust if signature is different.
	// Based on user_handler.go (which MeHandler likely is), it takes:
	// logger, authService, userService, mfaLogicService, apiKeyService, sessionService (if direct)
	// For now, assuming authService handles session logic for simplicity in MeHandler tests.
	ts.meHandler = NewMeHandler(
		ts.logger,
		ts.mockAuthService, // Provides ChangePassword, Session ops
		ts.mockUserService,
		ts.mockMfaLogicSvc,
		ts.mockApiKeyService,
		ts.cfg,
	)

	ts.router = gin.New()
	// Middleware to simulate setting UserID in context (like AuthMiddleware would do)
	ts.router.Use(func(c *gin.Context) {
		c.Set("userID", uuid.New()) // Default test user ID
		c.Next()
	})

	meRoutes := ts.router.Group("/api/v1/me")
	{
		meRoutes.GET("", ts.meHandler.GetMe)
		meRoutes.PUT("", ts.meHandler.UpdateMe)
		meRoutes.POST("/change-password", ts.meHandler.ChangePassword)

		meRoutes.GET("/sessions", ts.meHandler.ListSessions)
		meRoutes.DELETE("/sessions/:session_id", ts.meHandler.RevokeSession)

		meRoutes.POST("/2fa/initiate", ts.meHandler.Enable2FAInitiate)
		meRoutes.POST("/2fa/verify", ts.meHandler.VerifyAndActivate2FA)
		meRoutes.POST("/2fa/disable", ts.meHandler.Disable2FA)
		meRoutes.POST("/2fa/regenerate-backup", ts.meHandler.RegenerateBackupCodes)

		meRoutes.GET("/api-keys", ts.meHandler.ListAPIKeys)
		meRoutes.POST("/api-keys", ts.meHandler.CreateAPIKey)
		meRoutes.DELETE("/api-keys/:key_id", ts.meHandler.DeleteAPIKey)
	}
	return ts
}

func TestMeHandlerTestSuite(t *testing.T) {
	suite.Run(t, new(MeHandlerTestSuite))
}


// --- Test Cases ---

// GetMe
func (s *MeHandlerTestSuite) TestGetMe_Success() {
	userID := uuid.New()
	// Override userID in context for this specific test
	s.router.Use(func(c *gin.Context) { c.Set("userID", userID); c.Next() })

	mockUserInfo := &models.UserFullInfo{ID: userID, Email: "me@example.com", Username: "me_user"}
	s.mockUserService.On("GetUserFullInfo", mock.Anything, userID).Return(mockUserInfo, nil).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/me", nil)
	s.router.ServeHTTP(w, req)

	assert.Equal(s.T(), http.StatusOK, w.Code)
	var respBody models.UserFullInfo
	err := json.Unmarshal(w.Body.Bytes(), &respBody)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), mockUserInfo.Email, respBody.Email)
	s.mockUserService.AssertExpectations(s.T())
}

func (s *MeHandlerTestSuite) TestGetMe_NotFound() {
	userID := uuid.New()
	s.router.Use(func(c *gin.Context) { c.Set("userID", userID); c.Next() })

	s.mockUserService.On("GetUserFullInfo", mock.Anything, userID).Return(nil, domainErrors.ErrUserNotFound).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/me", nil)
	s.router.ServeHTTP(w, req)

	assert.Equal(s.T(), http.StatusNotFound, w.Code)
	s.mockUserService.AssertExpectations(s.T())
}


// UpdateMe
func (s *MeHandlerTestSuite) TestUpdateMe_Success() {
	userID := uuid.New()
	s.router.Use(func(c *gin.Context) { c.Set("userID", userID); c.Next() })

	updateReq := models.UpdateUserProfileRequest{DisplayName: "My New Name"}
	jsonBody, _ := json.Marshal(updateReq)

	updatedUser := &models.User{ID: userID, DisplayName: updateReq.DisplayName}
	s.mockUserService.On("UpdateUserProfile", mock.Anything, userID, updateReq).Return(updatedUser, nil).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPut, "/api/v1/me", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	s.router.ServeHTTP(w, req)

	assert.Equal(s.T(), http.StatusOK, w.Code)
	var respBody models.User
	err := json.Unmarshal(w.Body.Bytes(), &respBody)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), updatedUser.DisplayName, respBody.DisplayName)
	s.mockUserService.AssertExpectations(s.T())
}

func (s *MeHandlerTestSuite) TestUpdateMe_BadRequest() {
	// No need to setup userID in context as binding should fail first
	w := httptest.NewRecorder()
	// Example: make display_name too long if there's validation, or send malformed JSON
	malformedJson := []byte(`{"display_name": 123`) // display_name should be string
	req, _ := http.NewRequest(http.MethodPut, "/api/v1/me", bytes.NewBuffer(malformedJson))
	req.Header.Set("Content-Type", "application/json")
	s.router.ServeHTTP(w, req)
	assert.Equal(s.T(), http.StatusBadRequest, w.Code)
}

// ChangePassword
func (s *MeHandlerTestSuite) TestChangePassword_Success() {
    userID := uuid.New()
	s.router.Use(func(c *gin.Context) { c.Set("userID", userID); c.Next() })

    reqBody := ChangePasswordRequest{OldPassword: "oldPass", NewPassword: "newValidPassword1!"}
    jsonBody, _ := json.Marshal(reqBody)

    s.mockAuthService.On("ChangePassword", mock.Anything, userID, reqBody.OldPassword, reqBody.NewPassword).Return(nil).Once()

    w := httptest.NewRecorder()
    req, _ := http.NewRequest(http.MethodPost, "/api/v1/me/change-password", bytes.NewBuffer(jsonBody))
    req.Header.Set("Content-Type", "application/json")
    s.router.ServeHTTP(w, req)

    assert.Equal(s.T(), http.StatusOK, w.Code)
    s.mockAuthService.AssertExpectations(s.T())
}

func (s *MeHandlerTestSuite) TestChangePassword_BadRequest() {
    w := httptest.NewRecorder()
    // Missing NewPassword
    reqBody := ChangePasswordRequest{OldPassword: "oldPass"}
    jsonBody, _ := json.Marshal(reqBody)
    req, _ := http.NewRequest(http.MethodPost, "/api/v1/me/change-password", bytes.NewBuffer(jsonBody))
    req.Header.Set("Content-Type", "application/json")
    s.router.ServeHTTP(w, req)
    assert.Equal(s.T(), http.StatusBadRequest, w.Code)
}

func (s *MeHandlerTestSuite) TestChangePassword_InvalidCredentials() {
    userID := uuid.New()
	s.router.Use(func(c *gin.Context) { c.Set("userID", userID); c.Next() })
    reqBody := ChangePasswordRequest{OldPassword: "wrongOldPass", NewPassword: "newValidPassword1!"}
    jsonBody, _ := json.Marshal(reqBody)

    s.mockAuthService.On("ChangePassword", mock.Anything, userID, reqBody.OldPassword, reqBody.NewPassword).Return(domainErrors.ErrInvalidCredentials).Once()

    w := httptest.NewRecorder()
    req, _ := http.NewRequest(http.MethodPost, "/api/v1/me/change-password", bytes.NewBuffer(jsonBody))
    req.Header.Set("Content-Type", "application/json")
    s.router.ServeHTTP(w, req)

    assert.Equal(s.T(), http.StatusUnauthorized, w.Code)
    s.mockAuthService.AssertExpectations(s.T())
}

// TODO: Add tests for Session Management, 2FA Management, API Key Management
// Following the pattern: Success, BadRequest (invalid payload), Service Errors (NotFound, Forbidden, etc.)
// Ensure AuthMiddleware simulation (setting userID in context) is correctly handled for each test.
// For DELETE with path params, ensure param binding is tested.
// e.g., /me/sessions/:session_id - test with invalid UUID for session_id.

// --- Session Management Tests ---

// ListSessions
func (s *MeHandlerTestSuite) TestListSessions_Success() {
	userID := uuid.New()
	s.router.Use(func(c *gin.Context) { c.Set("userID", userID); c.Next() })

	mockSessions := []*models.Session{
		{ID: uuid.New(), UserID: userID, UserAgent: "Chrome", IPAddress: "127.0.0.1", LastActivityAt: time.Now()},
		{ID: uuid.New(), UserID: userID, UserAgent: "Firefox", IPAddress: "127.0.0.2", LastActivityAt: time.Now().Add(-time.Hour)},
	}
	s.mockAuthService.On("ListUserSessions", mock.Anything, userID).Return(mockSessions, nil).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/me/sessions", nil)
	s.router.ServeHTTP(w, req)

	assert.Equal(s.T(), http.StatusOK, w.Code)
	var respBody []models.Session
	err := json.Unmarshal(w.Body.Bytes(), &respBody)
	require.NoError(s.T(), err)
	assert.Len(s.T(), respBody, 2)
	assert.Equal(s.T(), mockSessions[0].ID, respBody[0].ID)
	s.mockAuthService.AssertExpectations(s.T())
}

func (s *MeHandlerTestSuite) TestListSessions_ServiceError() {
	userID := uuid.New()
	s.router.Use(func(c *gin.Context) { c.Set("userID", userID); c.Next() })

	s.mockAuthService.On("ListUserSessions", mock.Anything, userID).Return(nil, errors.New("internal service error")).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/me/sessions", nil)
	s.router.ServeHTTP(w, req)

	assert.Equal(s.T(), http.StatusInternalServerError, w.Code)
	s.mockAuthService.AssertExpectations(s.T())
}

// RevokeSession
func (s *MeHandlerTestSuite) TestRevokeSession_Success() {
	userID := uuid.New()
	sessionIDToRevoke := uuid.New()
	s.router.Use(func(c *gin.Context) { c.Set("userID", userID); c.Next() })

	s.mockAuthService.On("RevokeSession", mock.Anything, userID, sessionIDToRevoke).Return(nil).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodDelete, "/api/v1/me/sessions/"+sessionIDToRevoke.String(), nil)
	s.router.ServeHTTP(w, req)

	assert.Equal(s.T(), http.StatusNoContent, w.Code)
	s.mockAuthService.AssertExpectations(s.T())
}

func (s *MeHandlerTestSuite) TestRevokeSession_BadRequest_InvalidSessionID() {
	// No need to set userID in context as path param binding should fail first.
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodDelete, "/api/v1/me/sessions/not-a-uuid", nil)
	s.router.ServeHTTP(w, req)
	assert.Equal(s.T(), http.StatusBadRequest, w.Code)
}

func (s *MeHandlerTestSuite) TestRevokeSession_NotFound() {
	userID := uuid.New()
	sessionIDToRevoke := uuid.New()
	s.router.Use(func(c *gin.Context) { c.Set("userID", userID); c.Next() })

	s.mockAuthService.On("RevokeSession", mock.Anything, userID, sessionIDToRevoke).Return(domainErrors.ErrSessionNotFound).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodDelete, "/api/v1/me/sessions/"+sessionIDToRevoke.String(), nil)
	s.router.ServeHTTP(w, req)

	assert.Equal(s.T(), http.StatusNotFound, w.Code)
	s.mockAuthService.AssertExpectations(s.T())
}

func (s *MeHandlerTestSuite) TestRevokeSession_Forbidden() {
	userID := uuid.New() // User making the request
	anotherUserID := uuid.New() // Owner of the session
	sessionIDToRevoke := uuid.New() // Session belongs to anotherUserID

	s.router.Use(func(c *gin.Context) { c.Set("userID", userID); c.Next() })

	// Service returns ErrForbidden if userID from token doesn't match session's UserID (or general permission error)
	s.mockAuthService.On("RevokeSession", mock.Anything, userID, sessionIDToRevoke).Return(domainErrors.ErrForbidden).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodDelete, "/api/v1/me/sessions/"+sessionIDToRevoke.String(), nil)
	s.router.ServeHTTP(w, req)

	assert.Equal(s.T(), http.StatusForbidden, w.Code)
	s.mockAuthService.AssertExpectations(s.T())
}


// TODO: Add tests for 2FA Management, API Key Management
// Following the pattern: Success, BadRequest (invalid payload), Service Errors (NotFound, Forbidden, etc.)
// Ensure AuthMiddleware simulation (setting userID in context) is correctly handled for each test.


// --- 2FA Management Tests ---

// Enable2FAInitiate
func (s *MeHandlerTestSuite) TestEnable2FAInitiate_Success() {
	userID := uuid.New()
	s.router.Use(func(c *gin.Context) { c.Set("userID", userID); c.Next() }) // Simulate AuthMiddleware

	mockSecretID := uuid.New()
	mockSecretBase32 := "BASE32SECRETKEY"
	mockOtpAuthURL := "otpauth://totp/Test:user@example.com?secret=BASE32SECRETKEY&issuer=Test"

	// Assuming MeHandler gets user's email/account name via UserService or it's passed in request (not in current DTO)
	// For now, let's assume the handler gets user's email/username from UserService to pass to MFALogicService.
	// However, Enable2FAInitiateRequest DTO is empty. So service must fetch user info.
	// The handler passes "" for accountName for now, service should handle it.
	s.mockMfaLogicSvc.On("Enable2FAInitiate", mock.Anything, userID, "").Return(mockSecretID, mockSecretBase32, mockOtpAuthURL, nil).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/me/2fa/initiate", nil) // No request body
	s.router.ServeHTTP(w, req)

	assert.Equal(s.T(), http.StatusOK, w.Code)
	var respBody Enable2FAInitiateResponse
	err := json.Unmarshal(w.Body.Bytes(), &respBody)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), mockSecretID, respBody.MFASecretID)
	assert.Equal(s.T(), mockSecretBase32, respBody.Secret)
	assert.Equal(s.T(), mockOtpAuthURL, respBody.OTPAuthURL)
	s.mockMfaLogicSvc.AssertExpectations(s.T())
}

func (s *MeHandlerTestSuite) TestEnable2FAInitiate_AlreadyEnabled() {
	userID := uuid.New()
	s.router.Use(func(c *gin.Context) { c.Set("userID", userID); c.Next() })

	s.mockMfaLogicSvc.On("Enable2FAInitiate", mock.Anything, userID, "").Return(uuid.Nil, "", "", domainErrors.Err2FAAlreadyEnabled).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/me/2fa/initiate", nil)
	s.router.ServeHTTP(w, req)

	assert.Equal(s.T(), http.StatusConflict, w.Code)
	s.mockMfaLogicSvc.AssertExpectations(s.T())
}

// VerifyAndActivate2FA
func (s *MeHandlerTestSuite) TestVerifyAndActivate2FA_Success() {
	userID := uuid.New()
	s.router.Use(func(c *gin.Context) { c.Set("userID", userID); c.Next() })

	secretID := uuid.New()
	reqBody := VerifyAndActivate2FARequest{MFASecretID: secretID, TOTPCode: "123456"}
	jsonBody, _ := json.Marshal(reqBody)

	mockBackupCodes := []string{"backup1", "backup2"}
	s.mockMfaLogicSvc.On("VerifyAndActivate2FA", mock.Anything, userID, reqBody.TOTPCode, reqBody.MFASecretID).Return(mockBackupCodes, nil).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/me/2fa/verify", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	s.router.ServeHTTP(w, req)

	assert.Equal(s.T(), http.StatusOK, w.Code)
	var respBody VerifyAndActivate2FAResponse
	err := json.Unmarshal(w.Body.Bytes(), &respBody)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), mockBackupCodes, respBody.BackupCodes)
	s.mockMfaLogicSvc.AssertExpectations(s.T())
}

func (s *MeHandlerTestSuite) TestVerifyAndActivate2FA_BadRequest() {
	userID := uuid.New()
	s.router.Use(func(c *gin.Context) { c.Set("userID", userID); c.Next() })

	// Missing TOTPCode
	reqBody := VerifyAndActivate2FARequest{MFASecretID: uuid.New()}
	jsonBody, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/me/2fa/verify", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	s.router.ServeHTTP(w, req)
	assert.Equal(s.T(), http.StatusBadRequest, w.Code)
}

func (s *MeHandlerTestSuite) TestVerifyAndActivate2FA_InvalidCode() {
	userID := uuid.New()
	s.router.Use(func(c *gin.Context) { c.Set("userID", userID); c.Next() })

	secretID := uuid.New()
	reqBody := VerifyAndActivate2FARequest{MFASecretID: secretID, TOTPCode: "invalid"}
	jsonBody, _ := json.Marshal(reqBody)

	s.mockMfaLogicSvc.On("VerifyAndActivate2FA", mock.Anything, userID, reqBody.TOTPCode, reqBody.MFASecretID).Return(nil, domainErrors.ErrInvalid2FACode).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/me/2fa/verify", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	s.router.ServeHTTP(w, req)

	assert.Equal(s.T(), http.StatusUnauthorized, w.Code) // Or BadRequest
	s.mockMfaLogicSvc.AssertExpectations(s.T())
}

// Disable2FA
func (s *MeHandlerTestSuite) TestDisable2FA_Success() {
	userID := uuid.New()
	s.router.Use(func(c *gin.Context) { c.Set("userID", userID); c.Next() })

	reqBody := Disable2FARequest{Password: "userpassword"} // Assuming password verification method
	jsonBody, _ := json.Marshal(reqBody)

	s.mockMfaLogicSvc.On("Disable2FA", mock.Anything, userID, reqBody.Password, "password").Return(nil).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/me/2fa/disable", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	s.router.ServeHTTP(w, req)

	assert.Equal(s.T(), http.StatusNoContent, w.Code)
	s.mockMfaLogicSvc.AssertExpectations(s.T())
}

func (s *MeHandlerTestSuite) TestDisable2FA_Forbidden() {
	userID := uuid.New()
	s.router.Use(func(c *gin.Context) { c.Set("userID", userID); c.Next() })

	reqBody := Disable2FARequest{Password: "wrongpassword"}
	jsonBody, _ := json.Marshal(reqBody)

	s.mockMfaLogicSvc.On("Disable2FA", mock.Anything, userID, reqBody.Password, "password").Return(domainErrors.ErrForbidden).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/me/2fa/disable", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	s.router.ServeHTTP(w, req)

	assert.Equal(s.T(), http.StatusForbidden, w.Code)
	s.mockMfaLogicSvc.AssertExpectations(s.T())
}

// RegenerateBackupCodes
func (s *MeHandlerTestSuite) TestRegenerateBackupCodes_Success() {
	userID := uuid.New()
	s.router.Use(func(c *gin.Context) { c.Set("userID", userID); c.Next() })

	reqBody := RegenerateBackupCodesRequest{Password: "userpassword"} // Assuming password verification
	jsonBody, _ := json.Marshal(reqBody)

	mockBackupCodes := []string{"newcode1", "newcode2"}
	s.mockMfaLogicSvc.On("RegenerateBackupCodes", mock.Anything, userID, reqBody.Password, "password").Return(mockBackupCodes, nil).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/me/2fa/regenerate-backup", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	s.router.ServeHTTP(w, req)

	assert.Equal(s.T(), http.StatusOK, w.Code)
	var respBody RegenerateBackupCodesResponse
	err := json.Unmarshal(w.Body.Bytes(), &respBody)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), mockBackupCodes, respBody.BackupCodes)
	s.mockMfaLogicSvc.AssertExpectations(s.T())
}

func (s *MeHandlerTestSuite) TestRegenerateBackupCodes_2FANotEnabled() {
	userID := uuid.New()
	s.router.Use(func(c *gin.Context) { c.Set("userID", userID); c.Next() })

	reqBody := RegenerateBackupCodesRequest{Password: "userpassword"}
	jsonBody, _ := json.Marshal(reqBody)

	s.mockMfaLogicSvc.On("RegenerateBackupCodes", mock.Anything, userID, reqBody.Password, "password").Return(nil, domainErrors.Err2FANotEnabled).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/me/2fa/regenerate-backup", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	s.router.ServeHTTP(w, req)

	assert.Equal(s.T(), http.StatusConflict, w.Code) // Or BadRequest
	s.mockMfaLogicSvc.AssertExpectations(s.T())
}

// --- API Key Management Tests ---

// ListAPIKeys
func (s *MeHandlerTestSuite) TestListAPIKeys_Success() {
	userID := uuid.New()
	s.router.Use(func(c *gin.Context) { c.Set("userID", userID); c.Next() })

	mockAPIKeys := []*models.APIKey{
		{ID: uuid.New(), UserID: userID, Name: "Key1", Prefix: "pfx1", LastUsedAt: &time.Time{}, ExpiresAt: nil},
		{ID: uuid.New(), UserID: userID, Name: "Key2", Prefix: "pfx2"},
	}
	s.mockApiKeyService.On("ListAPIKeysForUser", mock.Anything, userID).Return(mockAPIKeys, nil).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/me/api-keys", nil)
	s.router.ServeHTTP(w, req)

	assert.Equal(s.T(), http.StatusOK, w.Code)
	var respBody []models.APIKey
	err := json.Unmarshal(w.Body.Bytes(), &respBody)
	require.NoError(s.T(), err)
	assert.Len(s.T(), respBody, 2)
	assert.Equal(s.T(), mockAPIKeys[0].Name, respBody[0].Name)
	s.mockApiKeyService.AssertExpectations(s.T())
}

func (s *MeHandlerTestSuite) TestListAPIKeys_ServiceError() {
	userID := uuid.New()
	s.router.Use(func(c *gin.Context) { c.Set("userID", userID); c.Next() })

	s.mockApiKeyService.On("ListAPIKeysForUser", mock.Anything, userID).Return(nil, errors.New("db error")).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/me/api-keys", nil)
	s.router.ServeHTTP(w, req)

	assert.Equal(s.T(), http.StatusInternalServerError, w.Code)
	s.mockApiKeyService.AssertExpectations(s.T())
}

// CreateAPIKey
func (s *MeHandlerTestSuite) TestCreateAPIKey_Success() {
	userID := uuid.New()
	s.router.Use(func(c *gin.Context) { c.Set("userID", userID); c.Next() })

	reqBody := CreateAPIKeyRequest{Name: "MyNewKey"} // ExpiresAt is optional
	jsonBody, _ := json.Marshal(reqBody)

	mockAPIKeyWithSecret := &models.APIKeyWithSecret{
		APIKey: models.APIKey{ID: uuid.New(), UserID: userID, Name: reqBody.Name, Prefix: "newpfx"},
		Secret: "supersecretkey",
	}
	s.mockApiKeyService.On("CreateAPIKey", mock.Anything, userID, reqBody.Name, (*time.Time)(nil)).Return(mockAPIKeyWithSecret, nil).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/me/api-keys", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	s.router.ServeHTTP(w, req)

	assert.Equal(s.T(), http.StatusCreated, w.Code)
	var respBody models.APIKeyWithSecret
	err := json.Unmarshal(w.Body.Bytes(), &respBody)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), mockAPIKeyWithSecret.Name, respBody.Name)
	assert.Equal(s.T(), mockAPIKeyWithSecret.Secret, respBody.Secret)
	s.mockApiKeyService.AssertExpectations(s.T())
}

func (s *MeHandlerTestSuite) TestCreateAPIKey_BadRequest_MissingName() {
	userID := uuid.New()
	s.router.Use(func(c *gin.Context) { c.Set("userID", userID); c.Next() })

	reqBody := CreateAPIKeyRequest{} // Name is missing
	jsonBody, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/me/api-keys", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	s.router.ServeHTTP(w, req)
	assert.Equal(s.T(), http.StatusBadRequest, w.Code)
}

func (s *MeHandlerTestSuite) TestCreateAPIKey_ServiceError_LimitReached() {
	userID := uuid.New()
	s.router.Use(func(c *gin.Context) { c.Set("userID", userID); c.Next() })

	reqBody := CreateAPIKeyRequest{Name: "AnotherKey"}
	jsonBody, _ := json.Marshal(reqBody)

	s.mockApiKeyService.On("CreateAPIKey", mock.Anything, userID, reqBody.Name, (*time.Time)(nil)).Return(nil, domainErrors.ErrAPIKeyLimitReached).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/me/api-keys", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	s.router.ServeHTTP(w, req)

	assert.Equal(s.T(), http.StatusConflict, w.Code) // 409 Conflict for limit reached
	s.mockApiKeyService.AssertExpectations(s.T())
}

// DeleteAPIKey
func (s *MeHandlerTestSuite) TestDeleteAPIKey_Success() {
	userID := uuid.New()
	keyIDToDelete := uuid.New()
	s.router.Use(func(c *gin.Context) { c.Set("userID", userID); c.Next() })

	s.mockApiKeyService.On("RevokeAPIKey", mock.Anything, userID, keyIDToDelete).Return(nil).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodDelete, "/api/v1/me/api-keys/"+keyIDToDelete.String(), nil)
	s.router.ServeHTTP(w, req)

	assert.Equal(s.T(), http.StatusNoContent, w.Code)
	s.mockApiKeyService.AssertExpectations(s.T())
}

func (s *MeHandlerTestSuite) TestDeleteAPIKey_BadRequest_InvalidKeyID() {
	userID := uuid.New()
	s.router.Use(func(c *gin.Context) { c.Set("userID", userID); c.Next() })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodDelete, "/api/v1/me/api-keys/not-a-uuid", nil)
	s.router.ServeHTTP(w, req)
	assert.Equal(s.T(), http.StatusBadRequest, w.Code)
}

func (s *MeHandlerTestSuite) TestDeleteAPIKey_NotFound() {
	userID := uuid.New()
	keyIDToDelete := uuid.New()
	s.router.Use(func(c *gin.Context) { c.Set("userID", userID); c.Next() })

	s.mockApiKeyService.On("RevokeAPIKey", mock.Anything, userID, keyIDToDelete).Return(domainErrors.ErrNotFound).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodDelete, "/api/v1/me/api-keys/"+keyIDToDelete.String(), nil)
	s.router.ServeHTTP(w, req)

	assert.Equal(s.T(), http.StatusNotFound, w.Code)
	s.mockApiKeyService.AssertExpectations(s.T())
}


func init() {
	gin.SetMode(gin.TestMode)
}
