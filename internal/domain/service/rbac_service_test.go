package service

import (
	"context"
	"errors"
	"sort"
	"testing"
	// "time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/your-org/auth-service/internal/domain/entity"
	domainErrors "github.com/your-org/auth-service/internal/domain/errors"
	"github.com/your-org/auth-service/internal/domain/repository"
)

// --- Mocks ---

type MockUserRepositoryForRBAC struct {
	mock.Mock
}

func (m *MockUserRepositoryForRBAC) FindByID(ctx context.Context, id string) (*entity.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.User), args.Error(1)
}


type MockRoleRepositoryForRBAC struct {
	mock.Mock
}

func (m *MockRoleRepositoryForRBAC) FindByID(ctx context.Context, id string) (*entity.Role, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.Role), args.Error(1)
}
func (m *MockRoleRepositoryForRBAC) AssignToUser(ctx context.Context, userID string, roleID string, assignedByUserID *string) error {
	args := m.Called(ctx, userID, roleID, assignedByUserID)
	return args.Error(0)
}
func (m *MockRoleRepositoryForRBAC) RemoveFromUser(ctx context.Context, userID string, roleID string) error {
	args := m.Called(ctx, userID, roleID)
	return args.Error(0)
}
func (m *MockRoleRepositoryForRBAC) GetRolesForUser(ctx context.Context, userID string) ([]*entity.Role, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entity.Role), args.Error(1)
}
func (m *MockRoleRepositoryForRBAC) GetPermissionsForRole(ctx context.Context, roleID string) ([]*entity.Permission, error) {
	args := m.Called(ctx, roleID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entity.Permission), args.Error(1)
}

type MockPermissionRepositoryForRBAC struct {
	mock.Mock
}


// --- Test Suite Setup ---

type RBACServiceTestSuite struct {
	service        RBACService
	mockUserRepo   *MockUserRepositoryForRBAC
	mockRoleRepo   *MockRoleRepositoryForRBAC
	mockPermRepo   *MockPermissionRepositoryForRBAC
}

func setupRBACServiceTestSuite(t *testing.T) *RBACServiceTestSuite {
	ts := &RBACServiceTestSuite{}
	ts.mockUserRepo = new(MockUserRepositoryForRBAC)
	ts.mockRoleRepo = new(MockRoleRepositoryForRBAC)
	ts.mockPermRepo = new(MockPermissionRepositoryForRBAC)

	cfg := RBACServiceConfig{
		UserRepo:       ts.mockUserRepo,
		RoleRepo:       ts.mockRoleRepo,
		PermissionRepo: ts.mockPermRepo,
	}
	ts.service = NewRBACService(cfg)
	return ts
}

// --- Test NewRBACService ---
func TestNewRBACService_Success(t *testing.T) {
	ts := setupRBACServiceTestSuite(t)
	assert.NotNil(t, ts.service)
}

// --- Test AssignRoleToUser ---
// ... AssignRoleToUser tests ...
func TestRBACService_AssignRoleToUser_Success(t *testing.T) {
	ts := setupRBACServiceTestSuite(t)
	ctx := context.Background()
	userID := uuid.New().String()
	roleID := "admin_role_id"
	adminID := uuid.New().String()

	ts.mockUserRepo.On("FindByID", ctx, userID).Return(&entity.User{ID: userID}, nil).Once()
	ts.mockRoleRepo.On("FindByID", ctx, roleID).Return(&entity.Role{ID: roleID, Name: "Admin"}, nil).Once()
	ts.mockRoleRepo.On("AssignToUser", ctx, userID, roleID, &adminID).Return(nil).Once()

	err := ts.service.AssignRoleToUser(ctx, userID, roleID, &adminID)
	assert.NoError(t, err)
	ts.mockUserRepo.AssertExpectations(t)
	ts.mockRoleRepo.AssertExpectations(t)
}

func TestRBACService_AssignRoleToUser_Failure_UserNotFound(t *testing.T) {
	ts := setupRBACServiceTestSuite(t)
	ctx := context.Background()
	userID := uuid.New().String()
	roleID := "admin_role_id"
	adminID := uuid.New().String()

	ts.mockUserRepo.On("FindByID", ctx, userID).Return(nil, domainErrors.ErrUserNotFound).Once()

	err := ts.service.AssignRoleToUser(ctx, userID, roleID, &adminID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to find user for role assignment")

	ts.mockUserRepo.AssertExpectations(t)
	ts.mockRoleRepo.AssertNotCalled(t, "FindByID", mock.Anything, mock.Anything)
	ts.mockRoleRepo.AssertNotCalled(t, "AssignToUser", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestRBACService_AssignRoleToUser_Failure_RoleNotFound(t *testing.T) {
	ts := setupRBACServiceTestSuite(t)
	ctx := context.Background()
	userID := uuid.New().String()
	roleID := "non_existent_role_id"
	adminID := uuid.New().String()

	ts.mockUserRepo.On("FindByID", ctx, userID).Return(&entity.User{ID: userID}, nil).Once()
	ts.mockRoleRepo.On("FindByID", ctx, roleID).Return(nil, domainErrors.ErrRoleNotFound).Once()

	err := ts.service.AssignRoleToUser(ctx, userID, roleID, &adminID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to find role for assignment")

	ts.mockUserRepo.AssertExpectations(t)
	ts.mockRoleRepo.AssertExpectations(t)
	ts.mockRoleRepo.AssertNotCalled(t, "AssignToUser", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}


func TestRBACService_AssignRoleToUser_Failure_AssignFails(t *testing.T) {
	ts := setupRBACServiceTestSuite(t)
	ctx := context.Background()
	userID := uuid.New().String()
	roleID := "admin_role_id"
	adminID := uuid.New().String()
	assignError := errors.New("db error during assignment")

	ts.mockUserRepo.On("FindByID", ctx, userID).Return(&entity.User{ID: userID}, nil).Once()
	ts.mockRoleRepo.On("FindByID", ctx, roleID).Return(&entity.Role{ID: roleID, Name: "Admin"}, nil).Once()
	ts.mockRoleRepo.On("AssignToUser", ctx, userID, roleID, &adminID).Return(assignError).Once()

	err := ts.service.AssignRoleToUser(ctx, userID, roleID, &adminID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to assign role to user")

	ts.mockUserRepo.AssertExpectations(t)
	ts.mockRoleRepo.AssertExpectations(t)
}

// --- Test RevokeRoleFromUser ---
func TestRBACService_RevokeRoleFromUser_Success(t *testing.T) {
	ts := setupRBACServiceTestSuite(t)
	ctx := context.Background()
	userID := uuid.New().String()
	roleID := "admin_role_id"

	ts.mockRoleRepo.On("RemoveFromUser", ctx, userID, roleID).Return(nil).Once()

	err := ts.service.RevokeRoleFromUser(ctx, userID, roleID)
	assert.NoError(t, err)
	ts.mockRoleRepo.AssertExpectations(t)
}

func TestRBACService_RevokeRoleFromUser_Failure_RepoFails(t *testing.T) {
	ts := setupRBACServiceTestSuite(t)
	ctx := context.Background()
	userID := uuid.New().String()
	roleID := "admin_role_id"
	repoError := errors.New("db error during revoke")

	ts.mockRoleRepo.On("RemoveFromUser", ctx, userID, roleID).Return(repoError).Once()

	err := ts.service.RevokeRoleFromUser(ctx, userID, roleID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to revoke role from user")

	ts.mockRoleRepo.AssertExpectations(t)
}

// --- Test GetUserRoles ---
func TestRBACService_GetUserRoles_Success(t *testing.T) {
	ts := setupRBACServiceTestSuite(t)
	ctx := context.Background()
	userID := uuid.New().String()
	expectedRoles := []*entity.Role{
		{ID: "role1", Name: "Role One"},
		{ID: "role2", Name: "Role Two"},
	}

	ts.mockRoleRepo.On("GetRolesForUser", ctx, userID).Return(expectedRoles, nil).Once()

	roles, err := ts.service.GetUserRoles(ctx, userID)
	assert.NoError(t, err)
	assert.Equal(t, expectedRoles, roles)
	ts.mockRoleRepo.AssertExpectations(t)
}

func TestRBACService_GetUserRoles_Failure_RepoFails(t *testing.T) {
	ts := setupRBACServiceTestSuite(t)
	ctx := context.Background()
	userID := uuid.New().String()
	repoError := errors.New("db error getting roles for user")

	ts.mockRoleRepo.On("GetRolesForUser", ctx, userID).Return(nil, repoError).Once()

	roles, err := ts.service.GetUserRoles(ctx, userID)
	require.Error(t, err)
	assert.Nil(t, roles)
	assert.Contains(t, err.Error(), "failed to get user roles")
	ts.mockRoleRepo.AssertExpectations(t)
}

// --- Test GetRolePermissions ---
func TestRBACService_GetRolePermissions_Success(t *testing.T) {
	ts := setupRBACServiceTestSuite(t)
	ctx := context.Background()
	roleID := "role_with_perms"
	expectedPermissions := []*entity.Permission{
		{ID: "perm1", Name: "Permission One"},
		{ID: "perm2", Name: "Permission Two"},
	}

	ts.mockRoleRepo.On("GetPermissionsForRole", ctx, roleID).Return(expectedPermissions, nil).Once()

	permissions, err := ts.service.GetRolePermissions(ctx, roleID)
	assert.NoError(t, err)
	assert.Equal(t, expectedPermissions, permissions)
	ts.mockRoleRepo.AssertExpectations(t)
}

func TestRBACService_GetRolePermissions_Failure_RepoFails(t *testing.T) {
	ts := setupRBACServiceTestSuite(t)
	ctx := context.Background()
	roleID := "role_with_perms"
	repoError := errors.New("db error getting permissions for role")

	ts.mockRoleRepo.On("GetPermissionsForRole", ctx, roleID).Return(nil, repoError).Once()

	permissions, err := ts.service.GetRolePermissions(ctx, roleID)
	require.Error(t, err)
	assert.Nil(t, permissions)
	assert.Contains(t, err.Error(), "failed to get role permissions")
	ts.mockRoleRepo.AssertExpectations(t)
}

// --- Test GetAllUserPermissions ---
func TestRBACService_GetAllUserPermissions_Success(t *testing.T) {
	ts := setupRBACServiceTestSuite(t)
	ctx := context.Background()
	userID := uuid.New().String()

	role1 := &entity.Role{ID: "role1", Name: "Editor"}
	role2 := &entity.Role{ID: "role2", Name: "Viewer"}

	perm1 := &entity.Permission{ID: "perm_read", Name: "Read Articles"}
	perm2 := &entity.Permission{ID: "perm_write", Name: "Write Articles"}
	perm3 := &entity.Permission{ID: "perm_comment", Name: "Comment on Articles"}

	ts.mockRoleRepo.On("GetRolesForUser", ctx, userID).Return([]*entity.Role{role1, role2}, nil).Once()
	ts.mockRoleRepo.On("GetPermissionsForRole", ctx, role1.ID).Return([]*entity.Permission{perm1, perm2}, nil).Once()
	ts.mockRoleRepo.On("GetPermissionsForRole", ctx, role2.ID).Return([]*entity.Permission{perm1, perm3}, nil).Once()


	permissions, err := ts.service.GetAllUserPermissions(ctx, userID)
	assert.NoError(t, err)
	assert.Len(t, permissions, 3)
	assert.Contains(t, permissions, perm1)
	assert.Contains(t, permissions, perm2)
	assert.Contains(t, permissions, perm3)

	ids := make([]string, len(permissions))
	for i, p := range permissions {
		ids[i] = p.ID
	}
	assert.True(t, sort.StringsAreSorted(ids), "Permissions should be sorted by ID")


	ts.mockRoleRepo.AssertExpectations(t)
}

func TestRBACService_GetAllUserPermissions_NoRoles(t *testing.T) {
	ts := setupRBACServiceTestSuite(t)
	ctx := context.Background()
	userID := uuid.New().String()

	ts.mockRoleRepo.On("GetRolesForUser", ctx, userID).Return([]*entity.Role{}, nil).Once()

	permissions, err := ts.service.GetAllUserPermissions(ctx, userID)
	assert.NoError(t, err)
	assert.Empty(t, permissions)
	ts.mockRoleRepo.AssertExpectations(t)
}

func TestRBACService_GetAllUserPermissions_Failure_GetUserRolesFails(t *testing.T) {
	ts := setupRBACServiceTestSuite(t)
	ctx := context.Background()
	userID := uuid.New().String()
	repoError := errors.New("error getting user roles")

	ts.mockRoleRepo.On("GetRolesForUser", ctx, userID).Return(nil, repoError).Once()

	permissions, err := ts.service.GetAllUserPermissions(ctx, userID)
	assert.Error(t, err)
	assert.Nil(t, permissions)
	assert.Contains(t, err.Error(), "failed to get user roles for permissions lookup")
	ts.mockRoleRepo.AssertExpectations(t)
}

func TestRBACService_GetAllUserPermissions_Failure_GetRolePermissionsFails(t *testing.T) {
	ts := setupRBACServiceTestSuite(t)
	ctx := context.Background()
	userID := uuid.New().String()
	role1 := &entity.Role{ID: "role1", Name: "Editor"}
	repoError := errors.New("error getting role permissions")

	ts.mockRoleRepo.On("GetRolesForUser", ctx, userID).Return([]*entity.Role{role1}, nil).Once()
	ts.mockRoleRepo.On("GetPermissionsForRole", ctx, role1.ID).Return(nil, repoError).Once()

	permissions, err := ts.service.GetAllUserPermissions(ctx, userID)
	assert.Error(t, err)
	assert.Nil(t, permissions)
	assert.Contains(t, err.Error(), "failed to get permissions for role role1")
	ts.mockRoleRepo.AssertExpectations(t)
}

// --- Test CheckUserPermission ---
func TestRBACService_CheckUserPermission_Success_HasPermission(t *testing.T) {
	ts := setupRBACServiceTestSuite(t)
	ctx := context.Background()
	userID := uuid.New().String()
	permissionID := "perm_write"

	// Mocking the chain: GetUserRoles -> GetPermissionsForRole (for each role)
	role1 := &entity.Role{ID: "role1"}
	permWrite := &entity.Permission{ID: permissionID}
	ts.mockRoleRepo.On("GetRolesForUser", ctx, userID).Return([]*entity.Role{role1}, nil).Once()
	ts.mockRoleRepo.On("GetPermissionsForRole", ctx, role1.ID).Return([]*entity.Permission{permWrite}, nil).Once()

	hasPerm, err := ts.service.CheckUserPermission(ctx, userID, permissionID)
	assert.NoError(t, err)
	assert.True(t, hasPerm)
	ts.mockRoleRepo.AssertExpectations(t)
}

func TestRBACService_CheckUserPermission_Failure_DoesNotHavePermission(t *testing.T) {
	ts := setupRBACServiceTestSuite(t)
	ctx := context.Background()
	userID := uuid.New().String()
	requiredPermissionID := "perm_publish"

	role1 := &entity.Role{ID: "role1"}
	permRead := &entity.Permission{ID: "perm_read"}
	ts.mockRoleRepo.On("GetRolesForUser", ctx, userID).Return([]*entity.Role{role1}, nil).Once()
	ts.mockRoleRepo.On("GetPermissionsForRole", ctx, role1.ID).Return([]*entity.Permission{permRead}, nil).Once()

	hasPerm, err := ts.service.CheckUserPermission(ctx, userID, requiredPermissionID)
	assert.NoError(t, err)
	assert.False(t, hasPerm)
	ts.mockRoleRepo.AssertExpectations(t)
}

func TestRBACService_CheckUserPermission_Failure_ErrorGettingPermissions(t *testing.T) {
	ts := setupRBACServiceTestSuite(t)
	ctx := context.Background()
	userID := uuid.New().String()
	permissionID := "perm_write"
	getRolesError := errors.New("error getting roles")

	ts.mockRoleRepo.On("GetRolesForUser", ctx, userID).Return(nil, getRolesError).Once()

	hasPerm, err := ts.service.CheckUserPermission(ctx, userID, permissionID)
	assert.Error(t, err)
	assert.False(t, hasPerm)
	assert.Contains(t, err.Error(), "failed to get user permissions for check")
	ts.mockRoleRepo.AssertExpectations(t)
}


func init() {
	// Global test setup
}
