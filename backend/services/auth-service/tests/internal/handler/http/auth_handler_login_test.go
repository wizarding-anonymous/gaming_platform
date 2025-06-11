// File: backend/services/auth-service/tests/internal/handler/http/auth_handler_login_test.go
package http

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
)

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

func TestAuthHandler_LoginUser_BadRequest_MissingFields(t *testing.T) {
	ts := setupAuthHandlerTestSuite(t)

	// Missing email
	reqBodyMissingEmail := LoginRequest{Password: "password123"}
	jsonBody, _ := json.Marshal(reqBodyMissingEmail)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	ts.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Missing password
	reqBodyMissingPassword := LoginRequest{Email: "test@example.com"}
	jsonBody, _ = json.Marshal(reqBodyMissingPassword)

	w = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	ts.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_LoginUser_Failure_UserNotFound(t *testing.T) { // Example of another service error
	ts := setupAuthHandlerTestSuite(t)
	reqBody := LoginRequest{Email: "notfound@example.com", Password: "password123"}
	jsonBody, _ := json.Marshal(reqBody)

	ts.mockAuthService.On("Login", mock.Anything, mock.AnythingOfType("models.LoginRequest")).Return(nil, nil, "", domainErrors.ErrUserNotFound).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	ts.router.ServeHTTP(w, req)

	// ErrUserNotFound should map to ErrInvalidCredentials by the service, then to 401 by handler
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	ts.mockAuthService.AssertExpectations(t)
}

func TestAuthHandler_LoginUser_Failure_UserBlocked(t *testing.T) {
	ts := setupAuthHandlerTestSuite(t)
	reqBody := LoginRequest{Email: "blocked@example.com", Password: "password123"}
	jsonBody, _ := json.Marshal(reqBody)

	ts.mockAuthService.On("Login", mock.Anything, mock.AnythingOfType("models.LoginRequest")).Return(nil, nil, "", domainErrors.ErrUserBlocked).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
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

func TestAuthHandler_VerifyLogin2FA_BadRequest(t *testing.T) {
	ts := setupAuthHandlerTestSuite(t)

	// Missing ChallengeToken
	reqBodyNoChallenge := VerifyLogin2FARequest{Code: "123456"}
	jsonBody, _ := json.Marshal(reqBodyNoChallenge)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login/2fa/verify", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	ts.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Missing Code
	reqBodyNoCode := VerifyLogin2FARequest{ChallengeToken: "challenge"}
	jsonBody, _ = json.Marshal(reqBodyNoCode)
	w = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodPost, "/api/v1/auth/login/2fa/verify", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	ts.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}
