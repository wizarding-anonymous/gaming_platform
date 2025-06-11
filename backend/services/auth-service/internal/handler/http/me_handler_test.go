// File: backend/services/auth-service/internal/handler/http/me_handler_test.go
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
	"go.uber.org/zap"

	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	domainService "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/service"
)

// --- Mocks ---

// DummyUserService implements UserService but does nothing.
type DummyUserService struct{}

func (d *DummyUserService) GetUserFullInfo(ctx context.Context, userID string) (*models.User, bool, error) {
	return nil, false, nil
}

// MockAuthService mocks password change calls.
type MockAuthService struct{ mock.Mock }

func (m *MockAuthService) ChangePassword(ctx context.Context, userID uuid.UUID, oldPwd, newPwd string) error {
	args := m.Called(ctx, userID, oldPwd, newPwd)
	return args.Error(0)
}

// MockSessionService mocks session operations.
type MockSessionService struct{ mock.Mock }

func (m *MockSessionService) GetActiveUserSessions(ctx context.Context, userID uuid.UUID) ([]*models.Session, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Session), args.Error(1)
}

func (m *MockSessionService) GetSessionByID(ctx context.Context, sessionID uuid.UUID) (*models.Session, error) {
	args := m.Called(ctx, sessionID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Session), args.Error(1)
}

func (m *MockSessionService) DeactivateSession(ctx context.Context, sessionID uuid.UUID) error {
	args := m.Called(ctx, sessionID)
	return args.Error(0)
}

// MockMFALogicService mocks MFA operations.
type MockMFALogicService struct{ mock.Mock }

func (m *MockMFALogicService) Enable2FAInitiate(ctx context.Context, userID uuid.UUID, accountName string) (uuid.UUID, string, string, error) {
	args := m.Called(ctx, userID, accountName)
	return args.Get(0).(uuid.UUID), args.String(1), args.String(2), args.Error(3)
}

func (m *MockMFALogicService) VerifyAndActivate2FA(ctx context.Context, userID uuid.UUID, code string, secretID uuid.UUID) ([]string, error) {
	args := m.Called(ctx, userID, code, secretID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockMFALogicService) Disable2FA(ctx context.Context, userID uuid.UUID, token string, method string) error {
	args := m.Called(ctx, userID, token, method)
	return args.Error(0)
}

func (m *MockMFALogicService) RegenerateBackupCodes(ctx context.Context, userID uuid.UUID, token string, method string) ([]string, error) {
	args := m.Called(ctx, userID, token, method)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockMFALogicService) GetActiveBackupCodeCount(ctx context.Context, userID uuid.UUID) (int, error) {
	args := m.Called(ctx, userID)
	return args.Int(0), args.Error(1)
}

// --- Helpers ---

func setupRouter(authSvc *MockAuthService, sessSvc *MockSessionService, mfaSvc *MockMFALogicService) (*gin.Engine, *MeHandler) {
	gin.SetMode(gin.TestMode)
	h := NewMeHandler(zap.NewNop(), nil, &DummyUserService{}, mfaSvc, nil, sessSvc)
	h.authService = authSvc
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("userID", uuid.New().String())
		c.Set("sessionID", uuid.New().String())
		c.Set("username", "tester")
	})
	RegisterMeRoutes(r.Group(""), h)
	return r, h
}

// --- Tests ---

func TestChangePasswordSuccess(t *testing.T) {
	authSvc := new(MockAuthService)
	sessSvc := new(MockSessionService)
	mfaSvc := new(MockMFALogicService)
	router, _ := setupRouter(authSvc, sessSvc, mfaSvc)

	userID := uuid.New()
	router.Use(func(c *gin.Context) { c.Set("userID", userID.String()) })

	req := ChangePasswordRequest{CurrentPassword: "old", NewPassword: "newStrong1"}
	body, _ := json.Marshal(req)
	authSvc.On("ChangePassword", mock.Anything, userID, req.CurrentPassword, req.NewPassword).Return(nil).Once()

	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodPut, "/me/password", bytes.NewBuffer(body))
	r.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	authSvc.AssertExpectations(t)
}

func TestChangePasswordInvalidCreds(t *testing.T) {
	authSvc := new(MockAuthService)
	sessSvc := new(MockSessionService)
	mfaSvc := new(MockMFALogicService)
	router, _ := setupRouter(authSvc, sessSvc, mfaSvc)

	userID := uuid.New()
	router.Use(func(c *gin.Context) { c.Set("userID", userID.String()) })

	req := ChangePasswordRequest{CurrentPassword: "bad", NewPassword: "new"}
	body, _ := json.Marshal(req)
	authSvc.On("ChangePassword", mock.Anything, userID, req.CurrentPassword, req.NewPassword).Return(domainErrors.ErrInvalidCredentials).Once()

	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodPut, "/me/password", bytes.NewBuffer(body))
	r.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, r)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	authSvc.AssertExpectations(t)
}

func TestListMySessionsSuccess(t *testing.T) {
	authSvc := new(MockAuthService)
	sessSvc := new(MockSessionService)
	mfaSvc := new(MockMFALogicService)
	router, _ := setupRouter(authSvc, sessSvc, mfaSvc)

	userID := uuid.New()
	router.Use(func(c *gin.Context) { c.Set("userID", userID.String()) })

	sessions := []*models.Session{{ID: uuid.New(), UserID: userID, CreatedAt: time.Now(), LastActivityAt: time.Now()}}
	sessSvc.On("GetActiveUserSessions", mock.Anything, userID).Return(sessions, nil).Once()

	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodGet, "/me/sessions", nil)
	router.ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	sessSvc.AssertExpectations(t)
}

func TestDeleteMySessionForbidden(t *testing.T) {
	authSvc := new(MockAuthService)
	sessSvc := new(MockSessionService)
	mfaSvc := new(MockMFALogicService)
	router, _ := setupRouter(authSvc, sessSvc, mfaSvc)

	userID := uuid.New()
	router.Use(func(c *gin.Context) { c.Set("userID", userID.String()); c.Set("sessionID", uuid.New().String()) })

	targetSession := uuid.New()
	sessSvc.On("GetSessionByID", mock.Anything, targetSession).Return(&models.Session{ID: targetSession, UserID: uuid.New()}, nil).Once()

	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodDelete, "/me/sessions/"+targetSession.String(), nil)
	router.ServeHTTP(w, r)

	assert.Equal(t, http.StatusForbidden, w.Code)
	sessSvc.AssertExpectations(t)
}

func TestEnableTOTPSuccess(t *testing.T) {
	authSvc := new(MockAuthService)
	sessSvc := new(MockSessionService)
	mfaSvc := new(MockMFALogicService)
	router, _ := setupRouter(authSvc, sessSvc, mfaSvc)

	userID := uuid.New()
	router.Use(func(c *gin.Context) { c.Set("userID", userID.String()); c.Set("username", "tester") })

	secretID := uuid.New()
	mfaSvc.On("Enable2FAInitiate", mock.Anything, userID, "tester").Return(secretID, "AAA", "otp://url", nil).Once()

	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodPost, "/me/2fa/totp/enable", nil)
	router.ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	mfaSvc.AssertExpectations(t)
}

func TestVerifyTOTPInvalid(t *testing.T) {
	authSvc := new(MockAuthService)
	sessSvc := new(MockSessionService)
	mfaSvc := new(MockMFALogicService)
	router, _ := setupRouter(authSvc, sessSvc, mfaSvc)

	userID := uuid.New()
	router.Use(func(c *gin.Context) { c.Set("userID", userID.String()) })

	req := VerifyTOTPRequest{MFASecretID: uuid.New().String(), TOTPCode: "123456"}
	body, _ := json.Marshal(req)
	secretID, _ := uuid.Parse(req.MFASecretID)
	mfaSvc.On("VerifyAndActivate2FA", mock.Anything, userID, req.TOTPCode, secretID).Return(nil, domainErrors.ErrInvalid2FACode).Once()

	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodPost, "/me/2fa/totp/verify", bytes.NewBuffer(body))
	r.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	mfaSvc.AssertExpectations(t)
}

func TestDisableTOTPSuccess(t *testing.T) {
	authSvc := new(MockAuthService)
	sessSvc := new(MockSessionService)
	mfaSvc := new(MockMFALogicService)
	router, _ := setupRouter(authSvc, sessSvc, mfaSvc)

	userID := uuid.New()
	router.Use(func(c *gin.Context) { c.Set("userID", userID.String()) })

	req := Disable2FARequest{VerificationToken: "tok", VerificationMethod: "password"}
	body, _ := json.Marshal(req)
	mfaSvc.On("Disable2FA", mock.Anything, userID, req.VerificationToken, req.VerificationMethod).Return(nil).Once()

	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodPost, "/me/2fa/totp/disable", bytes.NewBuffer(body))
	r.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	mfaSvc.AssertExpectations(t)
}

func TestRegenerateBackupCodesNotEnabled(t *testing.T) {
	authSvc := new(MockAuthService)
	sessSvc := new(MockSessionService)
	mfaSvc := new(MockMFALogicService)
	router, _ := setupRouter(authSvc, sessSvc, mfaSvc)

	userID := uuid.New()
	router.Use(func(c *gin.Context) { c.Set("userID", userID.String()) })

	req := Disable2FARequest{VerificationToken: "tok", VerificationMethod: "password"}
	body, _ := json.Marshal(req)
	mfaSvc.On("RegenerateBackupCodes", mock.Anything, userID, req.VerificationToken, req.VerificationMethod).Return(nil, domainErrors.Err2FANotEnabled).Once()

	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodPost, "/me/2fa/backup-codes/regenerate", bytes.NewBuffer(body))
	r.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	mfaSvc.AssertExpectations(t)
}
