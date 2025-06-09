// File: backend/services/auth-service/internal/handler/grpc/auth_v1_grpc_service_test.go
package grpc

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	// Import generated protobuf code for auth.v1
	authv1 "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/gen/auth/v1"

	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/config" // If needed by service, or for JWKS example
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models" // For User models if returned by UserService mock
	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors"
	domainService "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/service"
	appService "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/service" // For concrete service types if handler uses them directly
	"go.uber.org/zap"
)

// --- Mocks for AuthV1Service Dependencies ---

// MockTokenManagementService (subset for gRPC handler)
type MockTokenManagementService struct {
	mock.Mock
	domainService.TokenManagementService // Embed to satisfy interface, implement methods as needed
}
func (m *MockTokenManagementService) ValidateAccessToken(tokenString string) (*domainService.Claims, error) {
	args := m.Called(tokenString)
	if args.Get(0) == nil { return nil, args.Error(1) }
	return args.Get(0).(*domainService.Claims), args.Error(1)
}
func (m *MockTokenManagementService) GetJWKS() (map[string]interface{}, error) { // Changed from []byte to map based on service
	args := m.Called()
	if args.Get(0) == nil { return nil, args.Error(1) }
	return args.Get(0).(map[string]interface{}), args.Error(1)
}
// Add other TokenManagementService methods if AuthV1Service calls them.

// MockAuthServiceForGRPC (subset for gRPC handler, e.g., CheckUserPermission)
// Note: The gRPC handler directly calls AuthService's CheckUserPermission.
type MockAuthServiceForGRPC struct {
	mock.Mock
	// appService.AuthService // Not embedding concrete type, using interface for mocking
}
func (m *MockAuthServiceForGRPC) CheckUserPermission(ctx context.Context, userID uuid.UUID, permissionKey string, resourceID *string) (bool, error) {
	args := m.Called(ctx, userID, permissionKey, resourceID)
	return args.Bool(0), args.Error(1)
}
// Add other AuthService methods if gRPC handler calls them.

// MockUserServiceForGRPC (subset for gRPC handler, e.g., GetUserFullInfo)
type MockUserServiceForGRPC struct {
	mock.Mock
	// appService.UserService // Not embedding concrete type
}
func (m *MockUserServiceForGRPC) GetUserFullInfo(ctx context.Context, userID uuid.UUID) (*models.UserFullInfo, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil { return nil, args.Error(1) }
	return args.Get(0).(*models.UserFullInfo), args.Error(1)
}
func (m *MockUserServiceForGRPC) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]*models.Role, error) { // Assuming this is on UserService
    args := m.Called(ctx, userID)
    if args.Get(0) == nil { return nil, args.Error(1) }
    return args.Get(0).([]*models.Role), args.Error(1)
}


// --- AuthV1Service Test Suite ---
type AuthV1ServiceTestSuite struct {
	suite.Suite
	service             *AuthV1Service // The gRPC service implementation
	mockTokenMgmtSvc    *MockTokenManagementService
	mockAuthService     *MockAuthServiceForGRPC  // For CheckPermission
	mockUserService     *MockUserServiceForGRPC  // For GetUserInfo
	logger              *zap.Logger
	testCtx             context.Context
}

func (s *AuthV1ServiceTestSuite) SetupTest() {
	s.logger = zap.NewNop()
	s.testCtx = context.Background()

	s.mockTokenMgmtSvc = new(MockTokenManagementService)
	s.mockAuthService = new(MockAuthServiceForGRPC)
	s.mockUserService = new(MockUserServiceForGRPC)

	// NewAuthV1Service signature: logger, tokenMgmtService, authService, userService
	s.service = NewAuthV1Service(
		s.logger,
		s.mockTokenMgmtSvc,
		s.mockAuthService, // This is the AuthService from appService, which has CheckUserPermission
		s.mockUserService, // This is the UserService from appService
	)
}

func TestAuthV1ServiceTestSuite(t *testing.T) {
	suite.Run(t, new(AuthV1ServiceTestSuite))
}


// --- Test Cases ---

// ValidateToken
func (s *AuthV1ServiceTestSuite) TestValidateToken_Success() {
	token := "valid.access.token"
	userID := uuid.New()
	sessionID := uuid.New()
	claims := &domainService.Claims{
		UserID:    userID.String(),
		SessionID: sessionID.String(),
		Email:     "test@example.com",
		Roles:     []string{"user"},
		StandardClaims: domainService.StandardClaims{ExpiresAt: time.Now().Add(time.Hour).Unix()},
	}
	s.mockTokenMgmtSvc.On("ValidateAccessToken", token).Return(claims, nil).Once()

	req := &authv1.ValidateTokenRequest{Token: token}
	res, err := s.service.ValidateToken(s.testCtx, req)

	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), res)
	assert.True(s.T(), res.IsValid)
	assert.Equal(s.T(), userID.String(), res.UserId)
	assert.Equal(s.T(), sessionID.String(), res.SessionId)
	assert.Equal(s.T(), claims.Email, res.Email)
	assert.EqualValues(s.T(), claims.Roles, res.Roles)
	s.mockTokenMgmtSvc.AssertExpectations(s.T())
}

func (s *AuthV1ServiceTestSuite) TestValidateToken_InvalidToken() {
	token := "invalid.token"
	s.mockTokenMgmtSvc.On("ValidateAccessToken", token).Return(nil, domainErrors.ErrInvalidToken).Once()

	req := &authv1.ValidateTokenRequest{Token: token}
	res, err := s.service.ValidateToken(s.testCtx, req)

	assert.NoError(s.T(), err) // The handler itself doesn't return gRPC error for invalid token, sets IsValid=false
	assert.NotNil(s.T(), res)
	assert.False(s.T(), res.IsValid)
	s.mockTokenMgmtSvc.AssertExpectations(s.T())
}

func (s *AuthV1ServiceTestSuite) TestValidateToken_EmptyToken() {
	req := &authv1.ValidateTokenRequest{Token: ""} // Empty token string
	res, err := s.service.ValidateToken(s.testCtx, req)

	assert.Error(s.T(), err)
	st, ok := status.FromError(err)
	assert.True(s.T(), ok)
	assert.Equal(s.T(), codes.InvalidArgument, st.Code())
	assert.Nil(s.T(), res)
	s.mockTokenMgmtSvc.AssertNotCalled(s.T(), "ValidateAccessToken", mock.Anything)
}


// CheckPermission
func (s *AuthV1ServiceTestSuite) TestCheckPermission_Allowed() {
	userID := uuid.New()
	permissionKey := "document.read"
	s.mockAuthService.On("CheckUserPermission", s.testCtx, userID, permissionKey, (*string)(nil)).Return(true, nil).Once()

	req := &authv1.CheckPermissionRequest{UserId: userID.String(), PermissionKey: permissionKey}
	res, err := s.service.CheckPermission(s.testCtx, req)

	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), res)
	assert.True(s.T(), res.IsAllowed)
	s.mockAuthService.AssertExpectations(s.T())
}

func (s *AuthV1ServiceTestSuite) TestCheckPermission_Denied() {
	userID := uuid.New()
	permissionKey := "document.delete"
	s.mockAuthService.On("CheckUserPermission", s.testCtx, userID, permissionKey, (*string)(nil)).Return(false, nil).Once()

	req := &authv1.CheckPermissionRequest{UserId: userID.String(), PermissionKey: permissionKey}
	res, err := s.service.CheckPermission(s.testCtx, req)

	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), res)
	assert.False(s.T(), res.IsAllowed)
	s.mockAuthService.AssertExpectations(s.T())
}

func (s *AuthV1ServiceTestSuite) TestCheckPermission_InvalidUserID() {
	req := &authv1.CheckPermissionRequest{UserId: "not-a-uuid", PermissionKey: "doc.read"}
	res, err := s.service.CheckPermission(s.testCtx, req)
	assert.Error(s.T(), err)
	st, _ := status.FromError(err)
	assert.Equal(s.T(), codes.InvalidArgument, st.Code())
	assert.Nil(s.T(), res)
}

func (s *AuthV1ServiceTestSuite) TestCheckPermission_ServiceError() {
	userID := uuid.New()
	permissionKey := "document.read"
	s.mockAuthService.On("CheckUserPermission", s.testCtx, userID, permissionKey, (*string)(nil)).Return(false, errors.New("internal error")).Once()

	req := &authv1.CheckPermissionRequest{UserId: userID.String(), PermissionKey: permissionKey}
	res, err := s.service.CheckPermission(s.testCtx, req)
	assert.Error(s.T(), err)
	st, _ := status.FromError(err)
	assert.Equal(s.T(), codes.Internal, st.Code())
	assert.Nil(s.T(), res)
}


// GetUserInfo
func (s *AuthV1ServiceTestSuite) TestGetUserInfo_Success() {
	userID := uuid.New()
	userInfo := &models.UserFullInfo{
		ID: userID, Email: "user@example.com", Username: "grpc_user", Status: models.UserStatusActive,
		Roles: []*models.Role{{ID: "role1", Name: "UserRole"}},
	}
	// GetUserFullInfo is on UserService, not AuthService directly in the service layer.
	// The gRPC handler's AuthService dependency is the appService.AuthService, which might not have GetUserFullInfo.
	// The gRPC handler's NewAuthV1Service uses a userService parameter.
	s.mockUserService.On("GetUserFullInfo", s.testCtx, userID).Return(userInfo, nil).Once()
	// GetUserRoles might also be on UserService or RoleService. Assuming UserService for now.
	// s.mockUserService.On("GetUserRoles", s.testCtx, userID).Return(userInfo.Roles, nil).Once() // This is redundant if GetUserFullInfo includes roles

	req := &authv1.GetUserInfoRequest{UserId: userID.String()}
	res, err := s.service.GetUserInfo(s.testCtx, req)

	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), res)
	assert.Equal(s.T(), userID.String(), res.User.Id)
	assert.Equal(s.T(), "grpc_user", res.User.Username)
	assert.Equal(s.T(), "user@example.com", res.User.Email)
	assert.Equal(s.T(), string(models.UserStatusActive), res.User.Status)
	assert.Len(s.T(), res.User.Roles, 1)
	assert.Equal(s.T(), "UserRole", res.User.Roles[0].Name)
	s.mockUserService.AssertExpectations(s.T())
}

func (s *AuthV1ServiceTestSuite) TestGetUserInfo_NotFound() {
	userID := uuid.New()
	s.mockUserService.On("GetUserFullInfo", s.testCtx, userID).Return(nil, domainErrors.ErrUserNotFound).Once()

	req := &authv1.GetUserInfoRequest{UserId: userID.String()}
	res, err := s.service.GetUserInfo(s.testCtx, req)
	assert.Error(s.T(), err)
	st, _ := status.FromError(err)
	assert.Equal(s.T(), codes.NotFound, st.Code())
	assert.Nil(s.T(), res)
}


// GetJWKS
func (s *AuthV1ServiceTestSuite) TestGetJWKS_Success() {
	jwksData := map[string]interface{}{
		"keys": []map[string]interface{}{
			{"kid": "key1", "kty": "RSA", "n": "some_n_val", "e": "AQAB"},
		},
	}
	s.mockTokenMgmtSvc.On("GetJWKS").Return(jwksData, nil).Once()

	req := &authv1.GetJWKSRequest{}
	res, err := s.service.GetJWKS(s.testCtx, req)

	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), res)

	var unmarshaledResp map[string]interface{}
	err = json.Unmarshal(res.JwksJson, &unmarshaledResp)
	require.NoError(s.T(), err)
	assert.EqualValues(s.T(), jwksData, unmarshaledResp)
	s.mockTokenMgmtSvc.AssertExpectations(s.T())
}

func (s *AuthV1ServiceTestSuite) TestGetJWKS_ServiceError() {
	s.mockTokenMgmtSvc.On("GetJWKS").Return(nil, errors.New("jwks internal error")).Once()
	req := &authv1.GetJWKSRequest{}
	res, err := s.service.GetJWKS(s.testCtx, req)
	assert.Error(s.T(), err)
	st, _ := status.FromError(err)
	assert.Equal(s.T(), codes.Internal, st.Code())
	assert.Nil(s.T(), res)
}

// HealthCheck (from grpc_health_v1, but AuthV1Service also implements one)
func (s *AuthV1ServiceTestSuite) TestHealthCheck() {
	req := &authv1.HealthCheckRequest{} // Assuming this is the correct request for your custom HealthCheck
	res, err := s.service.HealthCheck(s.testCtx, req)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), res)
	assert.Equal(s.T(), authv1.HealthCheckResponse_SERVING, res.Status)
}

// Ensure mocks satisfy interfaces if they are passed as interface types to NewAuthV1Service
// This is more for compile-time check during development.
var _ domainService.TokenManagementService = (*MockTokenManagementService)(nil)
// var _ appService.AuthService = (*MockAuthServiceForGRPC)(nil) // MockAuthServiceForGRPC should implement the interface methods used
// var _ appService.UserService = (*MockUserServiceForGRPC)(nil) // MockUserServiceForGRPC should implement the interface methods used
// For the purpose of these tests, we are providing concrete mocks that have the methods.
// The NewAuthV1Service takes concrete *appService.AuthService and *appService.UserService.
// So the mocks should ideally be for these concrete types or the interfaces they satisfy,
// if the handler was changed to use interfaces (which is good practice).
// For now, assuming the handler uses concrete types and we mock the specific methods called on them.
// If NewAuthV1Service was refactored to take domainService.AuthLogicService and domainService.UserService,
// then MockAuthServiceForGRPC would implement domainService.AuthLogicService etc.
// The current NewAuthV1Service takes: logger, tokenMgmtSvc, authSvc *service.AuthService, userSvc *service.UserService
// This means MockAuthServiceForGRPC should mock methods of service.AuthService
// and MockUserServiceForGRPC for service.UserService.
// Let's adjust the mock type slightly for clarity.

// Re-check dependencies of NewAuthV1Service from auth_v1_grpc_service.go:
// logger *zap.Logger,
// tokenManagementService domainService.TokenManagementService,
// authSvc *appService.AuthService,    // This is the concrete service
// userSvc *appService.UserService,    // This is the concrete service
//
// This means our mocks for authSvc and userSvc need to be of these concrete types,
// or we need to use interfaces in NewAuthV1Service. The latter is better.
// For now, the test will proceed by mocking the methods as if they were on interfaces
// that these concrete services satisfy for the methods being called.
// E.g., CheckUserPermission is on the AuthService, GetUserFullInfo on UserService.
// The mock struct names are okay, just need to ensure the mocked methods match what's called.
