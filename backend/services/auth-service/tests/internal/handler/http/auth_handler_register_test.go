// File: backend/services/auth-service/tests/internal/handler/http/auth_handler_register_test.go
package http

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
)

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

func TestAuthHandler_RegisterUser_BadRequest_InvalidPayload(t *testing.T) {
	ts := setupAuthHandlerTestSuite(t)

	// Malformed JSON
	malformedJsonBody := []byte(`{"email": "test@example.com", "username": "testuser", "password":`)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewBuffer(malformedJsonBody))
	req.Header.Set("Content-Type", "application/json")
	ts.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Missing required field (e.g., password)
	missingFieldBody := RegisterUserRequest{Email: "test@example.com", Username: "testuser"} // Password missing
	jsonBody, _ := json.Marshal(missingFieldBody)

	w = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	ts.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code) // Gin's binding should catch this
}

func TestAuthHandler_RegisterUser_Failure_InternalServiceError(t *testing.T) {
	ts := setupAuthHandlerTestSuite(t)

	reqBody := RegisterUserRequest{Email: "test@example.com", Username: "testuser", Password: "password123"}
	jsonBody, _ := json.Marshal(reqBody)

	// Mock service to return a generic internal error
	ts.mockAuthService.On("Register", mock.Anything, mock.AnythingOfType("models.CreateUserRequest")).Return(nil, "", errors.New("internal server error")).Once()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	ts.mockAuthService.AssertExpectations(t)
}
