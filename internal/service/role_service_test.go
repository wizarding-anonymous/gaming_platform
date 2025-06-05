// File: internal/service/role_service_test.go
package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/your-org/auth-service/internal/config"
	"github.com/your-org/auth-service/internal/domain/models"
	domainErrors "github.com/your-org/auth-service/internal/domain/errors"
	domainService "github.com/your-org/auth-service/internal/domain/service"
	eventModels "github.com/your-org/auth-service/internal/events/models"
	kafkaPkg "github.com/your-org/auth-service/internal/events/kafka"
	repoInterfaces "github.com/your-org/auth-service/internal/repository/interfaces"
	"go.uber.org/zap"
)

// --- Mocks ---

type MockRoleRepositoryForRoleSvc struct {
	mock.Mock
}

func (m *MockRoleRepositoryForRoleSvc) GetAll(ctx context.Context) ([]*models.Role, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil { return nil, args.Error(1) }
	return args.Get(0).([]*models.Role), args.Error(1)
}
func (m *MockRoleRepositoryForRoleSvc) GetByID(ctx context.Context, id string) (*models.Role, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil { return nil, args.Error(1) }
	return args.Get(0).(*models.Role), args.Error(1)
}
func (m *MockRoleRepositoryForRoleSvc) GetByName(ctx context.Context, name string) (*models.Role, error) {
	args := m.Called(ctx, name)
	if args.Get(0) == nil { return nil, args.Error(1) }
	return args.Get(0).(*models.Role), args.Error(1)
}
func (m *MockRoleRepositoryForRoleSvc) Create(ctx context.Context, role *models.Role) error {
	args := m.Called(ctx, role)
	return args.Error(0)
}
func (m *MockRoleRepositoryForRoleSvc) Update(ctx context.Context, role *models.Role) error {
	args := m.Called(ctx, role)
	return args.Error(0)
}
func (m *MockRoleRepositoryForRoleSvc) Delete(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}
func (m *MockRoleRepositoryForRoleSvc) AssignPermissionToRole(ctx context.Context, roleID string, permissionID string) error {
    args := m.Called(ctx, roleID, permissionID)
    return args.Error(0)
}
func (m *MockRoleRepositoryForRoleSvc) RemovePermissionFromRole(ctx context.Context, roleID string, permissionID string) error {
    args := m.Called(ctx, roleID, permissionID)
    return args.Error(0)
}
func (m *MockRoleRepositoryForRoleSvc) GetPermissionsForRole(ctx context.Context, roleID string) ([]*models.Permission, error) {
	args := m.Called(ctx, roleID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Permission), args.Error(1)
}


type MockUserRepositoryForRoleSvc struct {
	mock.Mock
}
func (m *MockUserRepositoryForRoleSvc) FindByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil { return nil, args.Error(1) }
	return args.Get(0).(*models.User), args.Error(1)
}

type MockUserRolesRepositoryForRoleSvc struct {
    mock.Mock
}
func (m *MockUserRolesRepositoryForRoleSvc) AssignRoleToUser(ctx context.Context, userID uuid.UUID, roleID string, assignedByUserID *uuid.UUID) error {
    args := m.Called(ctx, userID, roleID, assignedByUserID)
    return args.Error(0)
}
func (m *MockUserRolesRepositoryForRoleSvc) RemoveRoleFromUser(ctx context.Context, userID uuid.UUID, roleID string) error {
    args := m.Called(ctx, userID, roleID)
    return args.Error(0)
}
func (m *MockUserRolesRepositoryForRoleSvc) GetRoleIDsForUser(ctx context.Context, userID uuid.UUID) ([]string, error) {
    args := m.Called(ctx, userID)
    if args.Get(0) == nil { return nil, args.Error(1) }
    return args.Get(0).([]string), args.Error(1)
}


type MockKafkaProducerForRoleSvc struct {
	mock.Mock
}
func (m *MockKafkaProducerForRoleSvc) PublishCloudEvent(ctx context.Context, topic string, eventType eventModels.EventType, subject string, dataPayload interface{}) error {
	args := m.Called(ctx, topic, eventType, subject, dataPayload)
	return args.Error(0)
}
func (m *MockKafkaProducerForRoleSvc) Close() error {
	args := m.Called()
	return args.Error(0)
}

type MockAuditLogRecorderForRoleSvc struct {
	mock.Mock
}
func (m *MockAuditLogRecorderForRoleSvc) RecordEvent(ctx context.Context, actorID *uuid.UUID, action string, status models.AuditLogStatus, targetID interface{}, targetType models.AuditTargetType, details map[string]interface{}, ipAddress string, userAgent string) {
	m.Called(ctx, actorID, action, status, targetID, targetType, details, ipAddress, userAgent)
}


// --- Test Suite Setup ---
type RoleServiceTestSuite struct {
	service         *RoleService
	mockRoleRepo    *MockRoleRepositoryForRoleSvc
	mockUserRepo    *MockUserRepositoryForRoleSvc
	mockUserRolesRepo *MockUserRolesRepositoryForRoleSvc
	mockKafka       *MockKafkaProducerForRoleSvc
	mockAudit       *MockAuditLogRecorderForRoleSvc
	testConfig      *config.Config
}

func setupRoleServiceTestSuite(t *testing.T) *RoleServiceTestSuite {
	ts := &RoleServiceTestSuite{}
	ts.mockRoleRepo = new(MockRoleRepositoryForRoleSvc)
	ts.mockUserRepo = new(MockUserRepositoryForRoleSvc)
	ts.mockUserRolesRepo = new(MockUserRolesRepositoryForRoleSvc)
	ts.mockKafka = new(MockKafkaProducerForRoleSvc)
	ts.mockAudit = new(MockAuditLogRecorderForRoleSvc)

	ts.testConfig = &config.Config{
		Kafka: config.KafkaConfig{Producer: config.KafkaProducerConfig{Topic: "auth-events"}},
	}

	ts.service = NewRoleService(
		ts.mockRoleRepo,
		ts.mockUserRepo,
		ts.mockUserRolesRepo,
		ts.mockKafka,
		zap.NewNop(),
		ts.mockAudit,
		ts.testConfig,
	)
	return ts
}

// --- Test NewRoleService ---
func TestNewRoleService_Success(t *testing.T) {
	ts := setupRoleServiceTestSuite(t)
	assert.NotNil(t, ts.service)
}

// --- Test CreateRole ---
// ... (CreateRole tests) ...
func TestRoleService_CreateRole_Success(t *testing.T) {
	ts := setupRoleServiceTestSuite(t)
	ctx := context.Background()
	adminActorID := uuid.New()
	req := models.CreateRoleRequest{
		ID:          "new-role-id",
		Name:        "New Role",
		Description: "A shiny new role.",
	}

	ts.mockRoleRepo.On("GetByName", ctx, req.Name).Return(nil, domainErrors.ErrRoleNotFound).Once()
	ts.mockRoleRepo.On("Create", ctx, mock.MatchedBy(func(r *models.Role) bool {
		return r.ID == req.ID && r.Name == req.Name
	})).Return(nil).Once()
	createdRole := &models.Role{ID: req.ID, Name: req.Name, Description: req.Description, CreatedAt: time.Now()}
	ts.mockRoleRepo.On("GetByID", ctx, req.ID).Return(createdRole, nil).Once()

	ts.mockKafka.On("PublishCloudEvent", ctx, ts.testConfig.Kafka.Producer.Topic, eventModels.AuthRoleCreatedV1, req.ID, mock.AnythingOfType("eventModels.RoleCreatedPayload")).Return(nil).Once()
	ts.mockAudit.On("RecordEvent", ctx, &adminActorID, "role_create", models.AuditLogStatusSuccess, &req.ID, models.AuditTargetTypeRole, mock.Anything, "unknown", "unknown").Once()

	role, err := ts.service.CreateRole(ctx, req, &adminActorID)

	assert.NoError(t, err)
	assert.NotNil(t, role)
	assert.Equal(t, req.ID, role.ID)
	assert.Equal(t, req.Name, role.Name)

	ts.mockRoleRepo.AssertExpectations(t)
	ts.mockKafka.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
}

func TestRoleService_CreateRole_Failure_NameExists(t *testing.T) {
	ts := setupRoleServiceTestSuite(t)
	ctx := context.Background()
	adminActorID := uuid.New()
	req := models.CreateRoleRequest{ID: "role1", Name: "Existing Role"}
	existingRole := &models.Role{ID: "some-other-id", Name: "Existing Role"}

	ts.mockRoleRepo.On("GetByName", ctx, req.Name).Return(existingRole, nil).Once()
	ts.mockAudit.On("RecordEvent", ctx, &adminActorID, "role_create", models.AuditLogStatusFailure, &existingRole.ID, models.AuditTargetTypeRole, mock.Anything, "unknown", "unknown").Once()


	role, err := ts.service.CreateRole(ctx, req, &adminActorID)
	assert.ErrorIs(t, err, models.ErrRoleNameExists)
	assert.Nil(t, role)
	ts.mockRoleRepo.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
	ts.mockRoleRepo.AssertNotCalled(t, "Create")
}

func TestRoleService_CreateRole_Failure_RepoCreateFails(t *testing.T) {
	ts := setupRoleServiceTestSuite(t)
	ctx := context.Background()
	adminActorID := uuid.New()
	req := models.CreateRoleRequest{ID: "role-fail", Name: "Fail Role"}
	repoError := errors.New("db create error")

	ts.mockRoleRepo.On("GetByName", ctx, req.Name).Return(nil, domainErrors.ErrRoleNotFound).Once()
	ts.mockRoleRepo.On("Create", ctx, mock.AnythingOfType("*models.Role")).Return(repoError).Once()

	var targetRoleIDArg *string
	ts.mockAudit.On("RecordEvent", ctx, &adminActorID, "role_create", models.AuditLogStatusFailure,
		mock.MatchedBy(func(targetID *string) bool { targetRoleIDArg = targetID; return true}),
		models.AuditTargetTypeRole, mock.Anything, "unknown", "unknown").Run(func(args mock.Arguments){
			assert.NotNil(t, targetRoleIDArg)
			if targetRoleIDArg != nil {
				assert.Equal(t, req.ID, *targetRoleIDArg)
			}
		}).Once()


	role, err := ts.service.CreateRole(ctx, req, &adminActorID)
	assert.ErrorIs(t, err, repoError)
	assert.Nil(t, role)
	ts.mockRoleRepo.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
}


// --- Test GetRoleByID, GetRoleByName, GetRoles ---
// ... (Get tests) ...
func TestRoleService_GetRoleByID_Success(t *testing.T) {
	ts := setupRoleServiceTestSuite(t)
	ctx := context.Background()
	roleID := "test-role-id"
	expectedRole := &models.Role{ID: roleID, Name: "Test Role"}

	ts.mockRoleRepo.On("GetByID", ctx, roleID).Return(expectedRole, nil).Once()
	role, err := ts.service.GetRoleByID(ctx, roleID)
	assert.NoError(t, err)
	assert.Equal(t, expectedRole, role)
	ts.mockRoleRepo.AssertExpectations(t)
}

func TestRoleService_GetRoleByID_Failure_NotFound(t *testing.T) {
	ts := setupRoleServiceTestSuite(t)
	ctx := context.Background()
	roleID := "not-found-id"
	ts.mockRoleRepo.On("GetByID", ctx, roleID).Return(nil, domainErrors.ErrRoleNotFound).Once()
	role, err := ts.service.GetRoleByID(ctx, roleID)
	assert.ErrorIs(t, err, domainErrors.ErrRoleNotFound)
	assert.Nil(t, role)
	ts.mockRoleRepo.AssertExpectations(t)
}

func TestRoleService_GetRoleByName_Success(t *testing.T) {
	ts := setupRoleServiceTestSuite(t)
	ctx := context.Background()
	roleName := "Test Role Name"
	expectedRole := &models.Role{ID: "some-id", Name: roleName}

	ts.mockRoleRepo.On("GetByName", ctx, roleName).Return(expectedRole, nil).Once()
	role, err := ts.service.GetRoleByName(ctx, roleName)
	assert.NoError(t, err)
	assert.Equal(t, expectedRole, role)
	ts.mockRoleRepo.AssertExpectations(t)
}

func TestRoleService_GetRoles_Success(t *testing.T) {
	ts := setupRoleServiceTestSuite(t)
	ctx := context.Background()
	expectedRoles := []*models.Role{
		{ID: "role1", Name: "Role One"},
		{ID: "role2", Name: "Role Two"},
	}
	ts.mockRoleRepo.On("GetAll", ctx).Return(expectedRoles, nil).Once()
	roles, err := ts.service.GetRoles(ctx)
	assert.NoError(t, err)
	assert.Equal(t, expectedRoles, roles)
	ts.mockRoleRepo.AssertExpectations(t)
}

// --- Test UpdateRole ---
// ... (UpdateRole tests) ...
func TestRoleService_UpdateRole_Success(t *testing.T) {
	ts := setupRoleServiceTestSuite(t)
	ctx := context.Background()
	adminActorID := uuid.New()
	roleID := "role-to-update"
	newName := "Updated Role Name"
	newDesc := "Updated description."

	req := models.UpdateRoleRequest{Name: &newName, Description: &newDesc}
	existingRole := &models.Role{ID: roleID, Name: "Old Name", Description: "Old Desc"}
	updatedRoleFetched := &models.Role{ID: roleID, Name: newName, Description: newDesc, UpdatedAt: time.Now()}

	ts.mockRoleRepo.On("GetByID", ctx, roleID).Return(existingRole, nil).Once()
	ts.mockRoleRepo.On("GetByName", ctx, newName).Return(nil, domainErrors.ErrRoleNotFound).Once()
	ts.mockRoleRepo.On("Update", ctx, mock.MatchedBy(func(r *models.Role) bool {
		return r.ID == roleID && r.Name == newName && r.Description == newDesc
	})).Return(nil).Once()
	ts.mockRoleRepo.On("GetByID", ctx, roleID).Return(updatedRoleFetched, nil).Once()

	ts.mockKafka.On("PublishCloudEvent", ctx, ts.testConfig.Kafka.Producer.Topic, eventModels.AuthRoleUpdatedV1, roleID,
		mock.MatchedBy(func(p eventModels.RoleUpdatedPayload) bool {
			return p.RoleID == roleID && *p.Name == newName && *p.Description == newDesc && len(p.ChangedFields) == 2
	})).Return(nil).Once()
	ts.mockAudit.On("RecordEvent", ctx, &adminActorID, "role_update", models.AuditLogStatusSuccess, &roleID, models.AuditTargetTypeRole, mock.Anything, "unknown", "unknown").Once()

	role, err := ts.service.UpdateRole(ctx, roleID, req, &adminActorID)
	assert.NoError(t, err)
	assert.NotNil(t, role)
	assert.Equal(t, newName, role.Name)
	assert.Equal(t, newDesc, role.Description)

	ts.mockRoleRepo.AssertExpectations(t)
	ts.mockKafka.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
}

func TestRoleService_UpdateRole_Failure_NotFound(t *testing.T) {
	ts := setupRoleServiceTestSuite(t)
	ctx := context.Background()
	adminActorID := uuid.New()
	roleID := "non-existent-role"
	newName := "Updated Name"
	req := models.UpdateRoleRequest{Name: &newName}

	ts.mockRoleRepo.On("GetByID", ctx, roleID).Return(nil, domainErrors.ErrRoleNotFound).Once()
	ts.mockAudit.On("RecordEvent", ctx, &adminActorID, "role_update", models.AuditLogStatusFailure, &roleID, models.AuditTargetTypeRole, mock.Anything, "unknown", "unknown").Once()

	role, err := ts.service.UpdateRole(ctx, roleID, req, &adminActorID)
	assert.ErrorIs(t, err, domainErrors.ErrRoleNotFound)
	assert.Nil(t, role)
	ts.mockRoleRepo.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
}

func TestRoleService_UpdateRole_Failure_NameConflict(t *testing.T) {
	ts := setupRoleServiceTestSuite(t)
	ctx := context.Background()
	adminActorID := uuid.New()
	roleID := "role-to-update"
	conflictingName := "Conflicting Name"
	req := models.UpdateRoleRequest{Name: &conflictingName}

	existingRole := &models.Role{ID: roleID, Name: "Old Name"}
	conflictingRoleEntity := &models.Role{ID: "other-id", Name: conflictingName}

	ts.mockRoleRepo.On("GetByID", ctx, roleID).Return(existingRole, nil).Once()
	ts.mockRoleRepo.On("GetByName", ctx, conflictingName).Return(conflictingRoleEntity, nil).Once()
	ts.mockAudit.On("RecordEvent", ctx, &adminActorID, "role_update", models.AuditLogStatusFailure, &roleID, models.AuditTargetTypeRole, mock.Anything, "unknown", "unknown").Once()


	role, err := ts.service.UpdateRole(ctx, roleID, req, &adminActorID)
	assert.ErrorIs(t, err, domainErrors.ErrDuplicateValue)
	assert.Nil(t, role)
	ts.mockRoleRepo.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
}


// --- Test DeleteRole ---
// ... (DeleteRole tests) ...
func TestRoleService_DeleteRole_Success(t *testing.T) {
	ts := setupRoleServiceTestSuite(t)
	ctx := context.Background()
	adminActorID := uuid.New()
	roleID := "role-to-delete"
	roleToDelete := &models.Role{ID: roleID, Name: "To Delete"}

	ts.mockRoleRepo.On("GetByID", ctx, roleID).Return(roleToDelete, nil).Once()
	ts.mockRoleRepo.On("Delete", ctx, roleID).Return(nil).Once()
	ts.mockKafka.On("PublishCloudEvent", ctx, ts.testConfig.Kafka.Producer.Topic, eventModels.AuthRoleDeletedV1, roleID, mock.AnythingOfType("eventModels.RoleDeletedPayload")).Return(nil).Once()
	ts.mockAudit.On("RecordEvent", ctx, &adminActorID, "role_delete", models.AuditLogStatusSuccess, &roleID, models.AuditTargetTypeRole, mock.Anything, "unknown", "unknown").Once()

	err := ts.service.DeleteRole(ctx, roleID, &adminActorID)
	assert.NoError(t, err)
	ts.mockRoleRepo.AssertExpectations(t)
	ts.mockKafka.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
}

func TestRoleService_DeleteRole_Success_AlreadyNotFound(t *testing.T) {
	ts := setupRoleServiceTestSuite(t)
	ctx := context.Background()
	adminActorID := uuid.New()
	roleID := "already-deleted-role"

	ts.mockRoleRepo.On("GetByID", ctx, roleID).Return(nil, domainErrors.ErrRoleNotFound).Once()
	ts.mockAudit.On("RecordEvent", ctx, &adminActorID, "role_delete", models.AuditLogStatusSuccess, &roleID, models.AuditTargetTypeRole, mock.Anything, "unknown", "unknown").Once()


	err := ts.service.DeleteRole(ctx, roleID, &adminActorID)
	assert.NoError(t, err)
	ts.mockRoleRepo.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
	ts.mockRoleRepo.AssertNotCalled(t, "Delete", mock.Anything, mock.Anything)
	ts.mockKafka.AssertNotCalled(t, "PublishCloudEvent")
}

func TestRoleService_DeleteRole_Failure_RepoDeleteFails(t *testing.T) {
	ts := setupRoleServiceTestSuite(t)
	ctx := context.Background()
	adminActorID := uuid.New()
	roleID := "role-to-delete"
	roleToDelete := &models.Role{ID: roleID, Name: "To Delete"}
	repoError := errors.New("db delete error")

	ts.mockRoleRepo.On("GetByID", ctx, roleID).Return(roleToDelete, nil).Once()
	ts.mockRoleRepo.On("Delete", ctx, roleID).Return(repoError).Once()
	ts.mockAudit.On("RecordEvent", ctx, &adminActorID, "role_delete", models.AuditLogStatusFailure, &roleID, models.AuditTargetTypeRole, mock.Anything, "unknown", "unknown").Once()

	err := ts.service.DeleteRole(ctx, roleID, &adminActorID)
	assert.ErrorIs(t, err, repoError)
	ts.mockRoleRepo.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
	ts.mockKafka.AssertNotCalled(t, "PublishCloudEvent")
}


// --- Test AssignRoleToUser (RoleService context) ---
// ... (AssignRoleToUser tests) ...
func TestRoleService_AssignRoleToUser_Success(t *testing.T) {
	ts := setupRoleServiceTestSuite(t)
	ctx := context.Background()
	userID := uuid.New()
	roleID := "test-role"
	adminActorID := uuid.New()

	ts.mockUserRepo.On("FindByID", ctx, userID).Return(&models.User{ID: userID}, nil).Once()
	ts.mockRoleRepo.On("GetByID", ctx, roleID).Return(&models.Role{ID: roleID}, nil).Once()
	ts.mockUserRolesRepo.On("GetRoleIDsForUser", ctx, userID).Return([]string{"other-role"}, nil).Once()
	ts.mockUserRolesRepo.On("AssignRoleToUser", ctx, userID, roleID, &adminActorID).Return(nil).Once()
	ts.mockUserRolesRepo.On("GetRoleIDsForUser", ctx, userID).Return([]string{"other-role", roleID}, nil).Once()

	ts.mockKafka.On("PublishCloudEvent", ctx, ts.testConfig.Kafka.Producer.Topic, eventModels.AuthUserRoleAssignedV1, userID.String(), mock.AnythingOfType("models.UserRolesChangedEvent")).Return(nil).Once()
	ts.mockAudit.On("RecordEvent", ctx, &adminActorID, "user_role_assign", models.AuditLogStatusSuccess, &userID, models.AuditTargetTypeUser, mock.Anything, "unknown", "unknown").Once()

	err := ts.service.AssignRoleToUser(ctx, userID, roleID, &adminActorID)
	assert.NoError(t, err)
	ts.mockUserRepo.AssertExpectations(t)
	ts.mockRoleRepo.AssertExpectations(t)
	ts.mockUserRolesRepo.AssertExpectations(t)
	ts.mockKafka.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
}

func TestRoleService_AssignRoleToUser_Failure_UserNotFound(t *testing.T) {
	ts := setupRoleServiceTestSuite(t)
	ctx := context.Background()
	userID := uuid.New()
	roleID := "test-role"
	adminActorID := uuid.New()

	ts.mockUserRepo.On("FindByID", ctx, userID).Return(nil, domainErrors.ErrUserNotFound).Once()
	ts.mockAudit.On("RecordEvent", ctx, &adminActorID, "user_role_assign", models.AuditLogStatusFailure, &userID, models.AuditTargetTypeUser, mock.Anything, "unknown", "unknown").Once()

	err := ts.service.AssignRoleToUser(ctx, userID, roleID, &adminActorID)
	assert.ErrorIs(t, err, domainErrors.ErrUserNotFound)
	ts.mockUserRepo.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
	ts.mockRoleRepo.AssertNotCalled(t, "GetByID")
	ts.mockUserRolesRepo.AssertNotCalled(t, "AssignRoleToUser")
}

func TestRoleService_AssignRoleToUser_Failure_RoleNotFound(t *testing.T) {
	ts := setupRoleServiceTestSuite(t)
	ctx := context.Background()
	userID := uuid.New()
	roleID := "test-role"
	adminActorID := uuid.New()

	ts.mockUserRepo.On("FindByID", ctx, userID).Return(&models.User{ID: userID}, nil).Once()
	ts.mockRoleRepo.On("GetByID", ctx, roleID).Return(nil, domainErrors.ErrRoleNotFound).Once()
	ts.mockAudit.On("RecordEvent", ctx, &adminActorID, "user_role_assign", models.AuditLogStatusFailure, &userID, models.AuditTargetTypeUser, mock.Anything, "unknown", "unknown").Once()

	err := ts.service.AssignRoleToUser(ctx, userID, roleID, &adminActorID)
	assert.ErrorIs(t, err, domainErrors.ErrRoleNotFound)
	ts.mockUserRepo.AssertExpectations(t)
	ts.mockRoleRepo.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
	ts.mockUserRolesRepo.AssertNotCalled(t, "AssignRoleToUser")
}

func TestRoleService_AssignRoleToUser_Failure_AssignFails(t *testing.T) {
	ts := setupRoleServiceTestSuite(t)
	ctx := context.Background()
	userID := uuid.New()
	roleID := "test-role"
	adminActorID := uuid.New()
	repoError := errors.New("db assign error")

	ts.mockUserRepo.On("FindByID", ctx, userID).Return(&models.User{ID: userID}, nil).Once()
	ts.mockRoleRepo.On("GetByID", ctx, roleID).Return(&models.Role{ID: roleID}, nil).Once()
	ts.mockUserRolesRepo.On("GetRoleIDsForUser", ctx, userID).Return([]string{}, nil).Once()
	ts.mockUserRolesRepo.On("AssignRoleToUser", ctx, userID, roleID, &adminActorID).Return(repoError).Once()
	ts.mockAudit.On("RecordEvent", ctx, &adminActorID, "user_role_assign", models.AuditLogStatusFailure, &userID, models.AuditTargetTypeUser, mock.Anything, "unknown", "unknown").Once()

	err := ts.service.AssignRoleToUser(ctx, userID, roleID, &adminActorID)
	assert.ErrorIs(t, err, repoError)
	ts.mockUserRepo.AssertExpectations(t)
	ts.mockRoleRepo.AssertExpectations(t)
	ts.mockUserRolesRepo.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
	ts.mockKafka.AssertNotCalled(t, "PublishCloudEvent")
}

// --- Test RemoveRoleFromUser (RoleService context) ---
// ... (RemoveRoleFromUser tests) ...
func TestRoleService_RemoveRoleFromUser_Success(t *testing.T) {
	ts := setupRoleServiceTestSuite(t)
	ctx := context.Background()
	userID := uuid.New()
	roleID := "test-role-to-remove"
	adminActorID := uuid.New()

	ts.mockUserRepo.On("FindByID", ctx, userID).Return(&models.User{ID: userID}, nil).Once()
	ts.mockRoleRepo.On("GetByID", ctx, roleID).Return(&models.Role{ID: roleID}, nil).Once()
	ts.mockUserRolesRepo.On("GetRoleIDsForUser", ctx, userID).Return([]string{roleID, "other-role"}, nil).Once()
	ts.mockUserRolesRepo.On("RemoveRoleFromUser", ctx, userID, roleID).Return(nil).Once()
	ts.mockUserRolesRepo.On("GetRoleIDsForUser", ctx, userID).Return([]string{"other-role"}, nil).Once()

	ts.mockKafka.On("PublishCloudEvent", ctx, ts.testConfig.Kafka.Producer.Topic, eventModels.AuthUserRoleRevokedV1, userID.String(), mock.AnythingOfType("models.UserRolesChangedEvent")).Return(nil).Once()
	ts.mockAudit.On("RecordEvent", ctx, &adminActorID, "user_role_revoke", models.AuditLogStatusSuccess, &userID, models.AuditTargetTypeUser, mock.Anything, "unknown", "unknown").Once()

	err := ts.service.RemoveRoleFromUser(ctx, userID, roleID, &adminActorID)
	assert.NoError(t, err)
	ts.mockUserRepo.AssertExpectations(t)
	ts.mockRoleRepo.AssertExpectations(t)
	ts.mockUserRolesRepo.AssertExpectations(t)
	ts.mockKafka.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
}

func TestRoleService_RemoveRoleFromUser_Failure_UserNotFound(t *testing.T) {
	ts := setupRoleServiceTestSuite(t)
	ctx := context.Background()
	userID := uuid.New()
	roleID := "test-role"
	adminActorID := uuid.New()

	ts.mockUserRepo.On("FindByID", ctx, userID).Return(nil, domainErrors.ErrUserNotFound).Once()
	ts.mockAudit.On("RecordEvent", ctx, &adminActorID, "user_role_revoke", models.AuditLogStatusFailure, &userID, models.AuditTargetTypeUser, mock.Anything, "unknown", "unknown").Once()

	err := ts.service.RemoveRoleFromUser(ctx, userID, roleID, &adminActorID)
	assert.ErrorIs(t, err, domainErrors.ErrUserNotFound)
	ts.mockUserRepo.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
}

func TestRoleService_RemoveRoleFromUser_Failure_RoleNotFound(t *testing.T) {
	ts := setupRoleServiceTestSuite(t)
	ctx := context.Background()
	userID := uuid.New()
	roleID := "test-role"
	adminActorID := uuid.New()

	ts.mockUserRepo.On("FindByID", ctx, userID).Return(&models.User{ID: userID}, nil).Once()
	ts.mockRoleRepo.On("GetByID", ctx, roleID).Return(nil, domainErrors.ErrRoleNotFound).Once()
	ts.mockAudit.On("RecordEvent", ctx, &adminActorID, "user_role_revoke", models.AuditLogStatusFailure, &userID, models.AuditTargetTypeUser, mock.Anything, "unknown", "unknown").Once()

	err := ts.service.RemoveRoleFromUser(ctx, userID, roleID, &adminActorID)
	assert.ErrorIs(t, err, domainErrors.ErrRoleNotFound)
	ts.mockUserRepo.AssertExpectations(t)
	ts.mockRoleRepo.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
}

func TestRoleService_RemoveRoleFromUser_Failure_RevokeFails(t *testing.T) {
	ts := setupRoleServiceTestSuite(t)
	ctx := context.Background()
	userID := uuid.New()
	roleID := "test-role"
	adminActorID := uuid.New()
	repoError := errors.New("db revoke error")

	ts.mockUserRepo.On("FindByID", ctx, userID).Return(&models.User{ID: userID}, nil).Once()
	ts.mockRoleRepo.On("GetByID", ctx, roleID).Return(&models.Role{ID: roleID}, nil).Once()
	ts.mockUserRolesRepo.On("GetRoleIDsForUser", ctx, userID).Return([]string{roleID}, nil).Once()
	ts.mockUserRolesRepo.On("RemoveRoleFromUser", ctx, userID, roleID).Return(repoError).Once()
	ts.mockAudit.On("RecordEvent", ctx, &adminActorID, "user_role_revoke", models.AuditLogStatusFailure, &userID, models.AuditTargetTypeUser, mock.Anything, "unknown", "unknown").Once()

	err := ts.service.RemoveRoleFromUser(ctx, userID, roleID, &adminActorID)
	assert.ErrorIs(t, err, repoError)
	ts.mockUserRepo.AssertExpectations(t)
	ts.mockRoleRepo.AssertExpectations(t)
	ts.mockUserRolesRepo.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
	ts.mockKafka.AssertNotCalled(t, "PublishCloudEvent")
}

// --- Test AssignPermissionToRole & RemovePermissionFromRole ---
func TestRoleService_AssignPermissionToRole_Success(t *testing.T) {
	ts := setupRoleServiceTestSuite(t)
	ctx := context.Background()
	roleID := "role1"
	permissionID := "perm101"
	adminActorID := uuid.New()

	ts.mockRoleRepo.On("GetByID", ctx, roleID).Return(&models.Role{ID: roleID}, nil).Once()
	ts.mockRoleRepo.On("AssignPermissionToRole", ctx, roleID, permissionID).Return(nil).Once()
	// Kafka event for AuthRolePermissionAssignedV1
	ts.mockKafka.On("PublishCloudEvent", ctx, ts.testConfig.Kafka.Producer.Topic, eventModels.AuthRolePermissionAssignedV1, roleID, mock.AnythingOfType("eventModels.RolePermissionChangePayload")).Return(nil).Once()
	ts.mockAudit.On("RecordEvent", ctx, &adminActorID, "role_permission_assign", models.AuditLogStatusSuccess, &roleID, models.AuditTargetTypeRole, mock.Anything, "unknown", "unknown").Once()

	err := ts.service.AssignPermissionToRole(ctx, roleID, permissionID, &adminActorID)
	assert.NoError(t, err)
	ts.mockRoleRepo.AssertExpectations(t)
	ts.mockKafka.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
}

func TestRoleService_RemovePermissionFromRole_Success(t *testing.T) {
	ts := setupRoleServiceTestSuite(t)
	ctx := context.Background()
	roleID := "role1"
	permissionID := "perm101"
	adminActorID := uuid.New()

	ts.mockRoleRepo.On("GetByID", ctx, roleID).Return(&models.Role{ID: roleID}, nil).Once()
	ts.mockRoleRepo.On("RemovePermissionFromRole", ctx, roleID, permissionID).Return(nil).Once()
	// Kafka event for AuthRolePermissionRevokedV1
	ts.mockKafka.On("PublishCloudEvent", ctx, ts.testConfig.Kafka.Producer.Topic, eventModels.AuthRolePermissionRevokedV1, roleID, mock.AnythingOfType("eventModels.RolePermissionChangePayload")).Return(nil).Once()
	ts.mockAudit.On("RecordEvent", ctx, &adminActorID, "role_permission_revoke", models.AuditLogStatusSuccess, &roleID, models.AuditTargetTypeRole, mock.Anything, "unknown", "unknown").Once()

	err := ts.service.RemovePermissionFromRole(ctx, roleID, permissionID, &adminActorID)
	assert.NoError(t, err)
	ts.mockRoleRepo.AssertExpectations(t)
	ts.mockKafka.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
}


func init() {
	// Global test setup
}
