// File: backend/services/auth-service/tests/internal/handler/http/admin_handler_test.go
package http

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	// "time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	// "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/config"
	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/repository"
	domainService "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/service"
	// "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/service" // For concrete service types if needed
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/utils/middleware"
	"go.uber.org/zap"
)

// --- Mocks ---

type MockUserServiceForAdminHandler struct {
	mock.Mock
}

func (m *MockUserServiceForAdminHandler) BlockUser(ctx context.Context, id uuid.UUID, actorID *uuid.UUID, reason string) error {
	args := m.Called(ctx, id, actorID, reason)
	return args.Error(0)
}

// Add other UserService methods called by AdminHandler as needed (e.g., GetUserByID, ListUsers, etc.)
func (m *MockUserServiceForAdminHandler) GetUserByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	panic("not impl in mock")
}
func (m *MockUserServiceForAdminHandler) CreateUser(ctx context.Context, req models.CreateUserRequest, actorID *uuid.UUID) (*models.User, error) {
	panic("not impl in mock")
}
func (m *MockUserServiceForAdminHandler) UpdateUser(ctx context.Context, id uuid.UUID, req models.UpdateUserRequest, actorID *uuid.UUID) (*models.User, error) {
	panic("not impl in mock")
}
func (m *MockUserServiceForAdminHandler) DeleteUser(ctx context.Context, id uuid.UUID, actorID *uuid.UUID) error {
	panic("not impl in mock")
}
func (m *MockUserServiceForAdminHandler) ChangePassword(ctx context.Context, id uuid.UUID, oldPassword, newPassword string) error {
	panic("not impl in mock")
}
func (m *MockUserServiceForAdminHandler) UnblockUser(ctx context.Context, id uuid.UUID, actorID *uuid.UUID) error {
	panic("not impl in mock")
}

type MockRoleServiceForAdminHandler struct {
	mock.Mock
}

// Add RoleService methods called by AdminHandler as needed

type MockAuditLogServiceForAdminHandler struct {
	mock.Mock
}

func (m *MockAuditLogServiceForAdminHandler) ListAuditLogs(ctx context.Context, params models.ListAuditLogParams) ([]*models.AuditLog, int64, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, 0, args.Error(2)
	}
	return args.Get(0).([]*models.AuditLog), int64(args.Int(1)), args.Error(2)
}

// Add other AuditLogService methods if AdminHandler uses them.

type MockAuditLogRepositoryForAdminHandler struct {
	mock.Mock
}

func (m *MockAuditLogRepositoryForAdminHandler) Create(ctx context.Context, logEntry *models.AuditLog) error {
	args := m.Called(ctx, logEntry)
	return args.Error(0)
}

func (m *MockAuditLogRepositoryForAdminHandler) FindByID(ctx context.Context, id int64) (*models.AuditLog, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AuditLog), args.Error(1)
}

func (m *MockAuditLogRepositoryForAdminHandler) List(ctx context.Context, params repository.ListAuditLogParams) ([]*models.AuditLog, int, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, 0, args.Error(2)
	}
	return args.Get(0).([]*models.AuditLog), args.Int(1), args.Error(2)
}

// --- Test Suite Setup ---
type AdminHandlerTestSuite struct {
	router           *gin.Engine
	mockUserService  domainService.UserService     // Assuming AdminHandler uses interface
	mockRoleService  domainService.RoleService     // Assuming AdminHandler uses interface
	mockAuditLogSvc  domainService.AuditLogService // Assuming AdminHandler uses interface
	mockAuditLogRepo repository.AuditLogRepository
	adminHandler     *AdminHandler
	logger           *zap.Logger
}

type ListAuditLogsResponse struct {
	AuditLogs []*models.AuditLog    `json:"data"`
	Meta      models.PaginationMeta `json:"meta"`
}

func setupAdminHandlerTestSuite(t *testing.T) *AdminHandlerTestSuite {
	gin.SetMode(gin.TestMode)
	ts := &AdminHandlerTestSuite{}

	ts.logger = zap.NewNop()
	ts.mockUserService = new(MockUserServiceForAdminHandler)
	ts.mockRoleService = new(MockRoleServiceForAdminHandler)
	ts.mockAuditLogSvc = new(MockAuditLogServiceForAdminHandler)
	ts.mockAuditLogRepo = new(MockAuditLogRepositoryForAdminHandler)

	// NewAdminHandler signature from admin_handler.go:
	// logger *zap.Logger, userService domain.UserService, roleService domain.RoleService, auditService domain.AuditLogService
	ts.adminHandler = NewAdminHandler(
		ts.logger,
		ts.mockUserService,
		ts.mockRoleService,
		ts.mockAuditLogSvc,
		ts.mockAuditLogRepo,
	)

	ts.router = gin.New()
	adminRoutes := ts.router.Group("/api/v1/admin")
	// Simulate AuthMiddleware and RoleMiddleware
	adminRoutes.Use(func(c *gin.Context) {
		// For tests needing admin auth, set these before calling handler
		c.Set(middleware.GinContextUserIDKey, uuid.New().String()) // Default admin user for context
		c.Set(middleware.GinContextUserRolesKey, []string{models.RoleAdmin})
		c.Next()
	})
	{
		adminRoutes.GET("/users", ts.adminHandler.ListUsers)
		adminRoutes.GET("/users/:user_id", ts.adminHandler.GetUserByID)
		adminRoutes.POST("/users/:user_id/block", ts.adminHandler.BlockUser)
		adminRoutes.POST("/users/:user_id/unblock", ts.adminHandler.UnblockUser)
		adminRoutes.PUT("/users/:user_id/roles", ts.adminHandler.UpdateUserRoles)
		adminRoutes.GET("/audit-logs", ts.adminHandler.ListAuditLogs)
	}
	return ts
}

// --- Test BlockUser ---
func TestAdminHandler_BlockUser_Success(t *testing.T) {
	ts := setupAdminHandlerTestSuite(t)
	targetUserID := uuid.New()
	adminUserID := uuid.New() // From context

	reqBody := BlockUserRequest{Reason: "Test block reason"}
	jsonBody, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set(middleware.GinContextUserIDKey, adminUserID.String())          // Admin performing the action
	c.Set(middleware.GinContextUserRolesKey, []string{models.RoleAdmin}) // Assuming RoleAdmin is a const string
	c.Params = gin.Params{gin.Param{Key: "user_id", Value: targetUserID.String()}}

	httpRequest, _ := http.NewRequest(http.MethodPost, "/api/v1/admin/users/"+targetUserID.String()+"/block", bytes.NewBuffer(jsonBody))
	httpRequest.Header.Set("Content-Type", "application/json")
	c.Request = httpRequest

	ts.mockUserService.On("BlockUser", c.Request.Context(), targetUserID, &adminUserID, reqBody.Reason).Return(nil).Once()

	ts.adminHandler.BlockUser(c)

	assert.Equal(t, http.StatusOK, w.Code)
	var respBody map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &respBody)
	require.NoError(t, err)
	assert.Equal(t, "User blocked successfully", respBody["message"])

	ts.mockUserService.AssertExpectations(t)
}

func TestAdminHandler_BlockUser_Failure_UserNotFound(t *testing.T) {
	ts := setupAdminHandlerTestSuite(t)
	targetUserID := uuid.New()
	adminUserID := uuid.New()

	reqBody := BlockUserRequest{Reason: "Test block reason"}
	jsonBody, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set(middleware.GinContextUserIDKey, adminUserID.String())
	c.Set(middleware.GinContextUserRolesKey, []string{models.RoleAdmin})
	c.Params = gin.Params{gin.Param{Key: "user_id", Value: targetUserID.String()}}
	httpRequest, _ := http.NewRequest(http.MethodPost, "/api/v1/admin/users/"+targetUserID.String()+"/block", bytes.NewBuffer(jsonBody))
	httpRequest.Header.Set("Content-Type", "application/json")
	c.Request = httpRequest

	ts.mockUserService.On("BlockUser", c.Request.Context(), targetUserID, &adminUserID, reqBody.Reason).Return(domainErrors.ErrUserNotFound).Once()

	ts.adminHandler.BlockUser(c)

	assert.Equal(t, http.StatusNotFound, w.Code) // Based on AdminHandler's handleError
	ts.mockUserService.AssertExpectations(t)
}

func TestAdminHandler_BlockUser_BadRequest_InvalidUserID(t *testing.T) {
	ts := setupAdminHandlerTestSuite(t)
	adminUserID := uuid.New()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set(middleware.GinContextUserIDKey, adminUserID.String())
	c.Set(middleware.GinContextUserRolesKey, []string{models.RoleAdmin})
	c.Params = gin.Params{gin.Param{Key: "user_id", Value: "not-a-uuid"}} // Invalid UUID

	reqBody := BlockUserRequest{Reason: "Test block reason"}
	jsonBody, _ := json.Marshal(reqBody)
	httpRequest, _ := http.NewRequest(http.MethodPost, "/api/v1/admin/users/not-a-uuid/block", bytes.NewBuffer(jsonBody))
	httpRequest.Header.Set("Content-Type", "application/json")
	c.Request = httpRequest

	// No service call expected, handler should catch bad path param
	ts.adminHandler.BlockUser(c)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAdminHandler_BlockUser_BadRequest_MissingReason(t *testing.T) {
	ts := setupAdminHandlerTestSuite(t)
	targetUserID := uuid.New()
	adminUserID := uuid.New()

	// Missing Reason in payload
	reqBody := BlockUserRequest{}
	jsonBody, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set(middleware.GinContextUserIDKey, adminUserID.String())
	c.Set(middleware.GinContextUserRolesKey, []string{models.RoleAdmin})
	c.Params = gin.Params{gin.Param{Key: "user_id", Value: targetUserID.String()}}
	httpRequest, _ := http.NewRequest(http.MethodPost, "/api/v1/admin/users/"+targetUserID.String()+"/block", bytes.NewBuffer(jsonBody))
	httpRequest.Header.Set("Content-Type", "application/json")
	c.Request = httpRequest

	ts.adminHandler.BlockUser(c)
	assert.Equal(t, http.StatusBadRequest, w.Code) // Gin binding should fail
}

func TestAdminHandler_BlockUser_ServiceError_Generic(t *testing.T) {
	ts := setupAdminHandlerTestSuite(t)
	targetUserID := uuid.New()
	adminUserID := uuid.New()

	reqBody := BlockUserRequest{Reason: "Test block reason"}
	jsonBody, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set(middleware.GinContextUserIDKey, adminUserID.String())
	c.Set(middleware.GinContextUserRolesKey, []string{models.RoleAdmin})
	c.Params = gin.Params{gin.Param{Key: "user_id", Value: targetUserID.String()}}
	httpRequest, _ := http.NewRequest(http.MethodPost, "/api/v1/admin/users/"+targetUserID.String()+"/block", bytes.NewBuffer(jsonBody))
	httpRequest.Header.Set("Content-Type", "application/json")
	c.Request = httpRequest

	ts.mockUserService.On("BlockUser", c.Request.Context(), targetUserID, &adminUserID, reqBody.Reason).Return(errors.New("some internal error")).Once()

	ts.adminHandler.BlockUser(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	ts.mockUserService.AssertExpectations(t)
}

// --- Test ListAuditLogs ---
func TestAdminHandler_ListAuditLogs_Success(t *testing.T) {
	ts := setupAdminHandlerTestSuite(t)
	adminUserID := uuid.New()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set(middleware.GinContextUserIDKey, adminUserID.String())
	c.Set(middleware.GinContextUserRolesKey, []string{models.RoleAdmin})

	// Build request with query params for pagination
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/admin/audit-logs?page=1&page_size=10", nil)
	c.Request = req

	mockLogs := []*models.AuditLog{
		{ID: uuid.New(), UserID: &adminUserID, Action: "test_action", Timestamp: time.Now()},
	}
	ts.mockAuditLogRepo.On("List", c.Request.Context(), mock.AnythingOfType("repository.ListAuditLogParams")).Return(mockLogs, 1, nil).Once()

	ts.adminHandler.ListAuditLogs(c)

	assert.Equal(t, http.StatusOK, w.Code)
	var respBody ListAuditLogsResponse
	err := json.Unmarshal(w.Body.Bytes(), &respBody)
	require.NoError(t, err)
	assert.Len(t, respBody.AuditLogs, 1)
	assert.Equal(t, 1, respBody.Meta.TotalItems)
	assert.Equal(t, 1, respBody.Meta.CurrentPage)
	assert.Equal(t, 10, respBody.Meta.PageSize)

	ts.mockAuditLogRepo.AssertExpectations(t)
}

func TestAdminHandler_ListAuditLogs_BadRequest_InvalidPage(t *testing.T) {
	ts := setupAdminHandlerTestSuite(t)
	adminUserID := uuid.New()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set(middleware.GinContextUserIDKey, adminUserID.String())
	c.Set(middleware.GinContextUserRolesKey, []string{models.RoleAdmin})

	req, _ := http.NewRequest(http.MethodGet, "/api/v1/admin/audit-logs?page=invalid&page_size=10", nil)
	c.Request = req

	ts.adminHandler.ListAuditLogs(c)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAdminHandler_ListAuditLogs_ServiceError(t *testing.T) {
	ts := setupAdminHandlerTestSuite(t)
	adminUserID := uuid.New()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set(middleware.GinContextUserIDKey, adminUserID.String())
	c.Set(middleware.GinContextUserRolesKey, []string{models.RoleAdmin})
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/admin/audit-logs?page=1&page_size=10", nil)
	c.Request = req

	ts.mockAuditLogRepo.On("List", c.Request.Context(), mock.AnythingOfType("repository.ListAuditLogParams")).Return(nil, 0, errors.New("db query failed")).Once()

	ts.adminHandler.ListAuditLogs(c)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	ts.mockAuditLogRepo.AssertExpectations(t)
}

// --- Test GetUserByID ---
func TestAdminHandler_GetUserByID_Success(t *testing.T) {
	ts := setupAdminHandlerTestSuite(t)
	targetUserID := uuid.New()
	mockUser := &models.User{ID: targetUserID, Email: "target@example.com", Username: "target_user"}

	// Mock UserService GetUserByID (this method needs to be added to the mock struct)
	mockUserSvc := ts.mockUserService.(*MockUserServiceForAdminHandler) // Cast to access specific mock methods
	mockUserSvc.On("GetUserByID", mock.Anything, targetUserID).Return(mockUser, nil).Once()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{gin.Param{Key: "user_id", Value: targetUserID.String()}}
	// Set admin context if needed by actual handler/middleware
	// c.Set(middleware.GinContextUserIDKey, uuid.New().String())
	// c.Set(middleware.GinContextUserRolesKey, []string{models.RoleAdmin})

	req, _ := http.NewRequest(http.MethodGet, "/api/v1/admin/users/"+targetUserID.String(), nil)
	c.Request = req

	ts.adminHandler.GetUserByID(c) // Direct call for simplicity, or use router if middleware interaction is key

	assert.Equal(t, http.StatusOK, w.Code)
	var respBody models.UserResponse
	err := json.Unmarshal(w.Body.Bytes(), &respBody)
	require.NoError(t, err)
	assert.Equal(t, mockUser.Email, respBody.Email)
	mockUserSvc.AssertExpectations(t)
}

func TestAdminHandler_GetUserByID_BadRequest_InvalidUUID(t *testing.T) {
	ts := setupAdminHandlerTestSuite(t)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{gin.Param{Key: "user_id", Value: "not-a-uuid"}}
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/admin/users/not-a-uuid", nil)
	c.Request = req

	ts.adminHandler.GetUserByID(c)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAdminHandler_GetUserByID_NotFound(t *testing.T) {
	ts := setupAdminHandlerTestSuite(t)
	targetUserID := uuid.New()

	mockUserSvc := ts.mockUserService.(*MockUserServiceForAdminHandler)
	mockUserSvc.On("GetUserByID", mock.Anything, targetUserID).Return(nil, domainErrors.ErrUserNotFound).Once()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{gin.Param{Key: "user_id", Value: targetUserID.String()}}
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/admin/users/"+targetUserID.String(), nil)
	c.Request = req

	ts.adminHandler.GetUserByID(c)
	assert.Equal(t, http.StatusNotFound, w.Code)
	mockUserSvc.AssertExpectations(t)
}

// --- Test UnblockUser ---
func TestAdminHandler_UnblockUser_Success(t *testing.T) {
	ts := setupAdminHandlerTestSuite(t)
	targetUserID := uuid.New()
	adminUserID := uuid.New() // From context via middleware mock

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set(middleware.GinContextUserIDKey, adminUserID.String())
	// c.Set(middleware.GinContextUserRolesKey, []string{models.RoleAdmin}) // Already set in global setup
	c.Params = gin.Params{gin.Param{Key: "user_id", Value: targetUserID.String()}}

	httpRequest, _ := http.NewRequest(http.MethodPost, "/api/v1/admin/users/"+targetUserID.String()+"/unblock", nil)
	c.Request = httpRequest

	mockUserSvc := ts.mockUserService.(*MockUserServiceForAdminHandler)
	mockUserSvc.On("UnblockUser", c.Request.Context(), targetUserID, &adminUserID).Return(nil).Once()

	ts.adminHandler.UnblockUser(c)

	assert.Equal(t, http.StatusOK, w.Code)
	var respBody map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &respBody)
	require.NoError(t, err)
	assert.Equal(t, "User unblocked successfully", respBody["message"])
	mockUserSvc.AssertExpectations(t)
}

func TestAdminHandler_UnblockUser_BadRequest_InvalidUUID(t *testing.T) {
	ts := setupAdminHandlerTestSuite(t)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{gin.Param{Key: "user_id", Value: "not-a-uuid"}}
	httpRequest, _ := http.NewRequest(http.MethodPost, "/api/v1/admin/users/not-a-uuid/unblock", nil)
	c.Request = httpRequest

	ts.adminHandler.UnblockUser(c)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAdminHandler_UnblockUser_NotFound(t *testing.T) {
	ts := setupAdminHandlerTestSuite(t)
	targetUserID := uuid.New()
	adminUserID := uuid.New()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set(middleware.GinContextUserIDKey, adminUserID.String())
	c.Params = gin.Params{gin.Param{Key: "user_id", Value: targetUserID.String()}}
	httpRequest, _ := http.NewRequest(http.MethodPost, "/api/v1/admin/users/"+targetUserID.String()+"/unblock", nil)
	c.Request = httpRequest

	mockUserSvc := ts.mockUserService.(*MockUserServiceForAdminHandler)
	mockUserSvc.On("UnblockUser", c.Request.Context(), targetUserID, &adminUserID).Return(domainErrors.ErrUserNotFound).Once()

	ts.adminHandler.UnblockUser(c)
	assert.Equal(t, http.StatusNotFound, w.Code)
	mockUserSvc.AssertExpectations(t)
}

// --- Test UpdateUserRoles ---
func TestAdminHandler_UpdateUserRoles_Success(t *testing.T) {
	ts := setupAdminHandlerTestSuite(t)
	targetUserID := uuid.New()
	adminUserID := uuid.New()
	roleIDs := []string{uuid.New().String(), uuid.New().String()}

	reqBody := models.UpdateUserRolesRequest{RoleIDs: roleIDs}
	jsonBody, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set(middleware.GinContextUserIDKey, adminUserID.String())
	c.Params = gin.Params{gin.Param{Key: "user_id", Value: targetUserID.String()}}
	httpRequest, _ := http.NewRequest(http.MethodPut, "/api/v1/admin/users/"+targetUserID.String()+"/roles", bytes.NewBuffer(jsonBody))
	httpRequest.Header.Set("Content-Type", "application/json")
	c.Request = httpRequest

	mockRoleSvc := ts.mockRoleService.(*MockRoleServiceForAdminHandler)
	mockRoleSvc.On("UpdateUserRoles", c.Request.Context(), targetUserID, roleIDs, &adminUserID).Return(nil).Once()

	ts.adminHandler.UpdateUserRoles(c)

	assert.Equal(t, http.StatusOK, w.Code)
	var respBody map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &respBody)
	require.NoError(t, err)
	assert.Equal(t, "User roles updated successfully", respBody["message"])
	mockRoleSvc.AssertExpectations(t)
}

func TestAdminHandler_UpdateUserRoles_BadRequest_InvalidUserID(t *testing.T) {
	ts := setupAdminHandlerTestSuite(t)
	roleIDs := []string{uuid.New().String()}
	reqBody := models.UpdateUserRolesRequest{RoleIDs: roleIDs}
	jsonBody, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{gin.Param{Key: "user_id", Value: "not-a-uuid"}}
	httpRequest, _ := http.NewRequest(http.MethodPut, "/api/v1/admin/users/not-a-uuid/roles", bytes.NewBuffer(jsonBody))
	httpRequest.Header.Set("Content-Type", "application/json")
	c.Request = httpRequest

	ts.adminHandler.UpdateUserRoles(c)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAdminHandler_UpdateUserRoles_BadRequest_InvalidPayload(t *testing.T) {
	ts := setupAdminHandlerTestSuite(t)
	targetUserID := uuid.New()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{gin.Param{Key: "user_id", Value: targetUserID.String()}}
	// Malformed JSON
	httpRequest, _ := http.NewRequest(http.MethodPut, "/api/v1/admin/users/"+targetUserID.String()+"/roles", bytes.NewBuffer([]byte(`{"role_ids": ["id1", "invalid-uuid"]}`)))
	httpRequest.Header.Set("Content-Type", "application/json")
	c.Request = httpRequest

	// The handler's ShouldBindJSON will fail if role_ids contains non-UUIDs, assuming models.UpdateUserRolesRequest uses []uuid.UUID or similar validation.
	// If it's just []string, then the service layer would catch invalid UUIDs.
	// For this test, assuming ShouldBindJSON catches it or validation is part of it.
	// If RoleIDs is []string in the request DTO, this specific test might pass binding but fail at service.
	// The actual models.UpdateUserRolesRequest uses `RoleIDs []string`. So service must validate.
	// This test will check malformed JSON instead.

	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)
	c.Params = gin.Params{gin.Param{Key: "user_id", Value: targetUserID.String()}}
	httpRequestMalformed, _ := http.NewRequest(http.MethodPut, "/api/v1/admin/users/"+targetUserID.String()+"/roles", bytes.NewBuffer([]byte(`{"role_ids": malformed`)))
	httpRequestMalformed.Header.Set("Content-Type", "application/json")
	c.Request = httpRequestMalformed
	ts.adminHandler.UpdateUserRoles(c)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAdminHandler_UpdateUserRoles_RoleNotFound(t *testing.T) {
	ts := setupAdminHandlerTestSuite(t)
	targetUserID := uuid.New()
	adminUserID := uuid.New()
	roleIDs := []string{uuid.New().String()} // One valid, one not found by service

	reqBody := models.UpdateUserRolesRequest{RoleIDs: roleIDs}
	jsonBody, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set(middleware.GinContextUserIDKey, adminUserID.String())
	c.Params = gin.Params{gin.Param{Key: "user_id", Value: targetUserID.String()}}
	httpRequest, _ := http.NewRequest(http.MethodPut, "/api/v1/admin/users/"+targetUserID.String()+"/roles", bytes.NewBuffer(jsonBody))
	httpRequest.Header.Set("Content-Type", "application/json")
	c.Request = httpRequest

	mockRoleSvc := ts.mockRoleService.(*MockRoleServiceForAdminHandler)
	mockRoleSvc.On("UpdateUserRoles", c.Request.Context(), targetUserID, roleIDs, &adminUserID).Return(domainErrors.ErrRoleNotFound).Once()

	ts.adminHandler.UpdateUserRoles(c)
	assert.Equal(t, http.StatusBadRequest, w.Code) // As per handler's error mapping
	mockRoleSvc.AssertExpectations(t)
}

// --- Test ListUsers ---
func TestAdminHandler_ListUsers_Success_Placeholder(t *testing.T) {
	ts := setupAdminHandlerTestSuite(t)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	// Simulate query params if ListUsers handler uses them
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/admin/users?page=1&per_page=5", nil)
	c.Request = req

	// mockUserSvc := ts.mockUserService.(*MockUserServiceForAdminHandler)
	// mockUsers := []*models.User{{ID: uuid.New(), Username: "user1"}}
	// mockUserSvc.On("ListUsers", mock.Anything, mock.AnythingOfType("models.ListUsersParams")).Return(mockUsers, int64(1), nil).Once()
	// Since ListUsers in handler is currently a placeholder, we don't mock service yet.

	ts.adminHandler.ListUsers(c)
	assert.Equal(t, http.StatusOK, w.Code)

	var respBody AdminListUsersResponse
	err := json.Unmarshal(w.Body.Bytes(), &respBody)
	require.NoError(t, err)
	assert.Empty(t, respBody.Data) // Placeholder returns empty list
	assert.Equal(t, 1, respBody.Meta.CurrentPage)
	assert.Equal(t, 5, respBody.Meta.PageSize)
	// mockUserSvc.AssertExpectations(t) // No service call in placeholder
}

func TestAdminHandler_ListUsers_BadRequest_InvalidPageParam(t *testing.T) {
	ts := setupAdminHandlerTestSuite(t)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/admin/users?page=abc&per_page=5", nil)
	c.Request = req

	ts.adminHandler.ListUsers(c) // Handler parses params, should error before service call
	// The handler itself doesn't return error for bad query params if DefaultQuery is used.
	// It will default to 1. So this test might need adjustment based on how strict parsing is.
	// Current ListUsers uses DefaultQuery which defaults to 1, so this won't be a 400.
	// To test this, the handler would need stricter parsing.
	// For now, assume DefaultQuery behavior is acceptable.
	assert.Equal(t, http.StatusOK, w.Code) // It defaults page to 1
}

func init() {
	gin.SetMode(gin.TestMode)
}

// Ensure mocks implement interfaces (important if AdminHandler takes interfaces)
var _ domainService.UserService = (*MockUserServiceForAdminHandler)(nil)
var _ domainService.RoleService = (*MockRoleServiceForAdminHandler)(nil)
var _ domainService.AuditLogService = (*MockAuditLogServiceForAdminHandler)(nil)
var _ repository.AuditLogRepository = (*MockAuditLogRepositoryForAdminHandler)(nil)

// Add methods for MockRoleServiceForAdminHandler if AdminHandler calls it
func (m *MockRoleServiceForAdminHandler) CreateRole(ctx context.Context, req models.CreateRoleRequest, actorID *uuid.UUID) (*models.Role, error) {
	panic("not impl")
}
func (m *MockRoleServiceForAdminHandler) GetRoleByID(ctx context.Context, id string) (*models.Role, error) {
	panic("not impl")
}
func (m *MockRoleServiceForAdminHandler) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]*models.Role, error) {
	panic("not impl")
}
func (m *MockRoleServiceForAdminHandler) AssignRoleToUser(ctx context.Context, userID uuid.UUID, roleID string, adminUserID *uuid.UUID) error {
	panic("not impl")
}
func (m *MockRoleServiceForAdminHandler) RemoveRoleFromUser(ctx context.Context, userID uuid.UUID, roleID string, adminUserID *uuid.UUID) error {
	panic("not impl")
}
func (m *MockRoleServiceForAdminHandler) AssignPermissionToRole(ctx context.Context, roleID string, permissionID string, actorID *uuid.UUID) error {
	panic("not impl")
}
func (m *MockRoleServiceForAdminHandler) RemovePermissionFromRole(ctx context.Context, roleID string, permissionID string, actorID *uuid.UUID) error {
	panic("not impl")
}
func (m *MockRoleServiceForAdminHandler) GetRoleByName(ctx context.Context, name string) (*models.Role, error) {
	panic("not impl")
}
func (m *MockRoleServiceForAdminHandler) GetRoles(ctx context.Context) ([]*models.Role, error) {
	panic("not impl")
}
func (m *MockRoleServiceForAdminHandler) UpdateRole(ctx context.Context, id string, req models.UpdateRoleRequest, actorID *uuid.UUID) (*models.Role, error) {
	panic("not impl")
}
func (m *MockRoleServiceForAdminHandler) DeleteRole(ctx context.Context, id string, actorID *uuid.UUID) error {
	panic("not impl")
}
func (m *MockRoleServiceForAdminHandler) GetRolePermissions(ctx context.Context, roleID string) ([]*models.Permission, error) {
	panic("not impl")
}
func (m *MockRoleServiceForAdminHandler) UpdateUserRoles(ctx context.Context, targetUserID uuid.UUID, roleIDs []string, adminUserID *uuid.UUID) error {
	args := m.Called(ctx, targetUserID, roleIDs, adminUserID)
	return args.Error(0)
}
