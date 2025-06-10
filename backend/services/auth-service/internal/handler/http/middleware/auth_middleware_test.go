// File: internal/handler/http/middleware/auth_middleware_test.go
package middleware_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/handler/http/middleware"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/service" // For service.TokenService
	"go.uber.org/zap"
)

// MockTokenService is a mock implementation of service.TokenService
type MockTokenService struct {
	mock.Mock
}

// ValidateAccessToken mocks the ValidateAccessToken method
func (m *MockTokenService) ValidateAccessToken(ctx context.Context, tokenString string) (*jwt.Token, map[string]interface{}, error) {
	args := m.Called(ctx, tokenString)
	var token *jwt.Token
	if args.Get(0) != nil {
		token = args.Get(0).(*jwt.Token)
	}
	var claims map[string]interface{}
	if args.Get(1) != nil {
		claims = args.Get(1).(map[string]interface{})
	}
	return token, claims, args.Error(2)
}

// Helper to setup router and apply middleware
func setupAuthRouter(mockService *MockTokenService) *gin.Engine {
	gin.SetMode(gin.TestMode)
	logger := zap.NewNop()
	router := gin.New()
	authMiddleware := middleware.AuthMiddleware(mockService, logger) // Pass the mock
	router.Use(authMiddleware)
	router.GET("/test", func(c *gin.Context) {
		userID, _ := c.Get("user_id")
		claims, _ := c.Get("claims")
		token, _ := c.Get("token")
		c.JSON(http.StatusOK, gin.H{
			"message":    "passed",
			"user_id":    userID,
			"claims_map": claims,
			"token_obj":  token,
		})
	})
	return router
}

type ErrorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

func TestAuthMiddleware_NoAuthHeader(t *testing.T) {
	mockService := new(MockTokenService) // Mock service is not called in this case
	router := setupAuthRouter(mockService)

	req, _ := http.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	var errResp ErrorResponse
	err := json.Unmarshal(rr.Body.Bytes(), &errResp)
	assert.NoError(t, err)
	assert.Equal(t, "Authorization header is required", errResp.Error)
	assert.Equal(t, "unauthorized", errResp.Code)

	mockService.AssertExpectations(t)
}

func TestAuthMiddleware_InvalidAuthFormat_NoBearer(t *testing.T) {
	mockService := new(MockTokenService)
	router := setupAuthRouter(mockService)

	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "NotBearer token")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	var errResp ErrorResponse
	err := json.Unmarshal(rr.Body.Bytes(), &errResp)
	assert.NoError(t, err)
	assert.Equal(t, "Invalid authorization format, expected 'Bearer {token}'", errResp.Error)
	assert.Equal(t, "unauthorized", errResp.Code)
	mockService.AssertExpectations(t)
}

func TestAuthMiddleware_InvalidAuthFormat_OnlyBearer(t *testing.T) {
	mockService := new(MockTokenService)
	router := setupAuthRouter(mockService)

	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer") // Missing token part
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	var errResp ErrorResponse
	err := json.Unmarshal(rr.Body.Bytes(), &errResp)
	assert.NoError(t, err)
	assert.Equal(t, "Invalid authorization format, expected 'Bearer {token}'", errResp.Error)
	assert.Equal(t, "unauthorized", errResp.Code)
	mockService.AssertExpectations(t)
}

func TestAuthMiddleware_InvalidAuthFormat_BearerSpaceOnly(t *testing.T) {
	mockService := new(MockTokenService)
	router := setupAuthRouter(mockService)

	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer ") // Missing token part, space only
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// Depending on strings.Split behavior, "Bearer " might result in parts := ["Bearer", ""]
	// The middleware checks `len(parts) != 2 || parts[0] != "Bearer"`.
	// If `tokenString := parts[1]` and parts[1] is empty, ValidateAccessToken might be called.
	// Let's assume it passes the format check but then fails validation.
	// The current code `tokenString := parts[1]` would make tokenString empty.
	// Let's assume ValidateAccessToken is called with empty string.
	mockService.On("ValidateAccessToken", mock.Anything, "").Return(nil, nil, errors.ErrInvalidToken)


	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	var errResp ErrorResponse
	err := json.Unmarshal(rr.Body.Bytes(), &errResp)
	assert.NoError(t, err)

	// If ValidateAccessToken is called with empty string and returns ErrInvalidToken,
	// the message should be "Invalid token"
	assert.Equal(t, "Invalid token", errResp.Error)
	assert.Equal(t, "unauthorized", errResp.Code)
	mockService.AssertExpectations(t)
}


func TestAuthMiddleware_ValidToken(t *testing.T) {
	mockService := new(MockTokenService)
	router := setupAuthRouter(mockService)

	sampleToken := &jwt.Token{Raw: "sampletokenstring", Method: jwt.SigningMethodHS256, Valid: true}
	sampleClaims := map[string]interface{}{
		"sub": "test-user-id",
		"iss": "auth-service",
		"exp": float64(jwt.NewNumericDate(nil).AddDate(0,0,1).Unix()), // Example, ensure it's float64
		"custom_claim": "test_value",
	}

	mockService.On("ValidateAccessToken", mock.Anything, "validtoken123").Return(sampleToken, sampleClaims, nil)

	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer validtoken123")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var respBody map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &respBody)
	assert.NoError(t, err)
	assert.Equal(t, "passed", respBody["message"])
	assert.Equal(t, "test-user-id", respBody["user_id"])

	// Check claims in response (set by dummy handler from context)
	claimsInResponse, ok := respBody["claims_map"].(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, sampleClaims["sub"], claimsInResponse["sub"])
	assert.Equal(t, sampleClaims["iss"], claimsInResponse["iss"])
	assert.Equal(t, sampleClaims["custom_claim"], claimsInResponse["custom_claim"])

	// Check token object in response
	tokenObjInResponse, ok := respBody["token_obj"].(map[string]interface{}) // jwt.Token serializes to map
	assert.True(t, ok)
	assert.Equal(t, sampleToken.Raw, tokenObjInResponse["Raw"])


	mockService.AssertExpectations(t)
}

func TestAuthMiddleware_ExpiredToken(t *testing.T) {
	mockService := new(MockTokenService)
	router := setupAuthRouter(mockService)

	mockService.On("ValidateAccessToken", mock.Anything, "expiredtoken").Return(nil, nil, errors.ErrExpiredToken)

	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer expiredtoken")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	var errResp ErrorResponse
	err := json.Unmarshal(rr.Body.Bytes(), &errResp)
	assert.NoError(t, err)
	assert.Equal(t, "Token expired", errResp.Error)
	assert.Equal(t, "token_expired", errResp.Code)
	mockService.AssertExpectations(t)
}

func TestAuthMiddleware_RevokedToken(t *testing.T) {
	mockService := new(MockTokenService)
	router := setupAuthRouter(mockService)

	mockService.On("ValidateAccessToken", mock.Anything, "revokedtoken").Return(nil, nil, errors.ErrRevokedToken)

	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer revokedtoken")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	var errResp ErrorResponse
	err := json.Unmarshal(rr.Body.Bytes(), &errResp)
	assert.NoError(t, err)
	assert.Equal(t, "Token revoked", errResp.Error)
	assert.Equal(t, "token_revoked", errResp.Code)
	mockService.AssertExpectations(t)
}

func TestAuthMiddleware_OtherValidationError(t *testing.T) {
	mockService := new(MockTokenService)
	router := setupAuthRouter(mockService)

	// Any error other than ErrExpiredToken or ErrRevokedToken
	mockService.On("ValidateAccessToken", mock.Anything, "othervaliderror").Return(nil, nil, errors.ErrInvalidToken)

	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer othervaliderror")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	var errResp ErrorResponse
	err := json.Unmarshal(rr.Body.Bytes(), &errResp)
	assert.NoError(t, err)
	assert.Equal(t, "Invalid token", errResp.Error) // Default message for other errors
	assert.Equal(t, "unauthorized", errResp.Code)  // Default code for other errors
	mockService.AssertExpectations(t)
}

func TestAuthMiddleware_GenericError(t *testing.T) {
	mockService := new(MockTokenService)
	router := setupAuthRouter(mockService)

	// A generic error that is not one of the specific domainErrors
	mockService.On("ValidateAccessToken", mock.Anything, "genericerror").Return(nil, nil, stdlib_errors.New("some generic validation issue"))

	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer genericerror")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	var errResp ErrorResponse
	err := json.Unmarshal(rr.Body.Bytes(), &errResp)
	assert.NoError(t, err)
	assert.Equal(t, "Invalid token", errResp.Error)
	assert.Equal(t, "unauthorized", errResp.Code)
	mockService.AssertExpectations(t)
}

// Standard library errors for the generic error test
import stdlib_errors "errors"

func TestAuthMiddleware_EmptyTokenString(t *testing.T) {
    mockService := new(MockTokenService)
    router := setupAuthRouter(mockService)

    // This situation arises if Authorization header is "Bearer " (with a trailing space)
    // The split logic in the middleware would pass " " as tokenString.
    // Or if it's "Bearer" (no space, no token), it's caught by len(parts) !=2.
    // If "Bearer ", parts is ["Bearer", ""]. tokenString is "".
    mockService.On("ValidateAccessToken", mock.Anything, "").Return(nil, nil, errors.ErrInvalidToken)

    req, _ := http.NewRequest("GET", "/test", nil)
    req.Header.Set("Authorization", "Bearer ") // Token string is effectively empty
    rr := httptest.NewRecorder()
    router.ServeHTTP(rr, req)

    assert.Equal(t, http.StatusUnauthorized, rr.Code)
    var errResp ErrorResponse
    _ = json.Unmarshal(rr.Body.Bytes(), &errResp)
    assert.Equal(t, "Invalid token", errResp.Error)
    assert.Equal(t, "unauthorized", errResp.Code)
    mockService.AssertExpectations(t)
}

// Ensure MockTokenService satisfies the interface implicitly expected by AuthMiddleware.
// The AuthMiddleware takes `*service.TokenService` which is a concrete type, not an interface.
// For robust mocking, AuthMiddleware should ideally depend on an interface.
// However, since service.TokenService is a struct with methods, we can mock its methods.
// This check is more for interfaces. If TokenService were an interface:
// var _ expected_interface.TokenServiceInterface = (*MockTokenService)(nil)
// For now, the mock is structured to match the methods of service.TokenService.

// Example of how `github.com/golang-jwt/jwt/v5` claims are often float64 for numbers
// This is relevant for `sampleClaims` in `TestAuthMiddleware_ValidToken`
func TestJwtNumericDateIsFloat64(t *testing.T) {
	claims := jwt.MapClaims{
		"exp": jwt.NewNumericDate(nil).AddDate(0,0,1),
	}
	jsonData, err := json.Marshal(claims)
	assert.NoError(t, err)

	var unmarshaledClaims map[string]interface{}
	err = json.Unmarshal(jsonData, &unmarshaledClaims)
	assert.NoError(t, err)

	_, isFloat64 := unmarshaledClaims["exp"].(float64)
	assert.True(t, isFloat64, "Expected 'exp' claim to be unmarshaled as float64")
}
