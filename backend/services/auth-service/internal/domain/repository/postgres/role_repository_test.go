// File: backend/services/auth-service/internal/domain/repository/postgres/role_repository_test.go
package postgres_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/your-org/auth-service/internal/domain/models"
	"github.com/your-org/auth-service/internal/domain/repository/postgres"
	domainErrors "github.com/your-org/auth-service/internal/domain/errors"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

// DSN and migrations path constants (ensure these are consistent)
// const (
// 	testPostgresDSNEnv = "TEST_AUTH_POSTGRES_DSN" // Defined in user_repository_test.go
// 	defaultTestDSN     = "postgres://testuser:testpassword@localhost:5433/auth_test_db?sslmode=disable" // Defined in user_repository_test.go
// 	defaultMigrationsPath = "file://../../../../migrations" // Defined in user_repository_test.go
// )

type RoleRepositoryTestSuite struct {
	suite.Suite
	pool       *pgxpool.Pool
	repo       *postgres.RoleRepositoryPostgres
	migrations *migrate.Migrate
	dsn        string
}

func TestRoleRepositoryTestSuite(t *testing.T) {
	dsn := os.Getenv(testPostgresDSNEnv)
	if dsn == "" {
		dsn = defaultTestDSN
	}

	migrationsPath := os.Getenv("MIGRATIONS_PATH")
	if migrationsPath == "" {
		migrationsPath = defaultMigrationsPath
	}
	if !strings.HasPrefix(migrationsPath, "file://") {
		migrationsPath = "file://" + migrationsPath
	}

	if os.Getenv(testPostgresDSNEnv) == "" && dsn == defaultTestDSN {
		_, errCfg := pgxpool.ParseConfig(dsn)
		if errCfg != nil {
			t.Logf("Default test DSN is invalid, skipping repo tests: %v", errCfg)
			t.Skip("Skipping repository tests: TEST_AUTH_POSTGRES_DSN not set and default DSN is invalid.")
			return
		}
		tempPool, errConn := pgxpool.New(context.Background(), dsn)
		if errConn != nil {
			t.Logf("Default test DSN not connectable, skipping repo tests: %v", errConn)
			t.Skip("Skipping repository tests: TEST_AUTH_POSTGRES_DSN not set and default DSN not connectable.")
			return
		}
		tempPool.Close()
	}

	m, err := migrate.New(migrationsPath, dsn)
	if err != nil {
		t.Fatalf("Failed to create migration instance (path: %s, dsn: %s): %v", migrationsPath, dsn, err)
	}
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("Failed to apply migrations: %v", err)
	}
	t.Log("Migrations applied successfully for role tests")

	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("Failed to connect to test database using DSN '%s': %v", dsn, err)
	}

	testSuite := &RoleRepositoryTestSuite{
		Suite:      suite.Suite{},
		pool:       pool,
		migrations: m,
		dsn:        dsn,
	}
	suite.Run(t, testSuite)
}

func (s *RoleRepositoryTestSuite) SetupSuite() {}

func (s *RoleRepositoryTestSuite) TearDownSuite() {
	if s.pool != nil {
		s.pool.Close()
	}
	if s.migrations != nil {
		s.T().Log("Rolling back migrations for role tests...")
		if err := s.migrations.Down(); err != nil && err != migrate.ErrNoChange {
			s.T().Logf("Warning: failed to rollback migrations in TearDownSuite: %v", err)
		} else {
			s.T().Log("Migrations for role tests rolled back successfully.")
		}
	}
}

func (s *RoleRepositoryTestSuite) SetupTest() {
	s.repo = postgres.NewRoleRepositoryPostgres(s.pool)
	_, err := s.pool.Exec(context.Background(), `
		TRUNCATE TABLE roles CASCADE;
		TRUNCATE TABLE permissions CASCADE;
		TRUNCATE TABLE role_permissions CASCADE;
	`) // users table is not directly related here but CASCADE from user_roles might affect it if linked.
	   // For role tests, primarily roles, permissions, and role_permissions matter.
	require.NoError(s.T(), err, "Failed to clean tables before test")
}

// Helper to create a role
func (s *RoleRepositoryTestSuite) helperCreateRole(id, name, desc string) *models.Role {
	ctx := context.Background()
	role := &models.Role{
		ID:          id,
		Name:        name,
		Description: desc,
		CreatedAt:   time.Now().UTC().Truncate(time.Millisecond),
	}
	err := s.repo.Create(ctx, role)
	require.NoError(s.T(), err)
	return role
}

// Helper to create a permission (using direct SQL for test setup simplicity)
func (s *RoleRepositoryTestSuite) helperCreatePermission(id, name, desc, resource, action string) *models.Permission {
	ctx := context.Background()
	permission := &models.Permission{
		ID:          id,
		Name:        name,
		Description: desc,
		Resource:    resource,
		Action:      action,
		CreatedAt:   time.Now().UTC().Truncate(time.Millisecond),
	}
	query := "INSERT INTO permissions (id, name, description, resource, action, created_at) VALUES ($1, $2, $3, $4, $5, $6)"
	_, err := s.pool.Exec(ctx, query, permission.ID, permission.Name, permission.Description, permission.Resource, permission.Action, permission.CreatedAt)
	require.NoError(s.T(), err)
	return permission
}


// --- Role CRUD Tests ---
func (s *RoleRepositoryTestSuite) TestCreateRole_Success() {
	ctx := context.Background()
	role := &models.Role{
		ID:          "role_create_success",
		Name:        "Test Role Success",
		Description: "A role for successful creation test",
	}
	err := s.repo.Create(ctx, role)
	require.NoError(s.T(), err)

	fetched, errFetch := s.repo.GetByID(ctx, role.ID)
	require.NoError(s.T(), errFetch)
	require.NotNil(s.T(), fetched)
	assert.Equal(s.T(), role.Name, fetched.Name)
	assert.Equal(s.T(), role.Description, fetched.Description)
}

func (s *RoleRepositoryTestSuite) TestCreateRole_DuplicateID() {
	ctx := context.Background()
	s.helperCreateRole("dup_id_role", "Role With Dup ID Test 1", "Desc1")

	role2 := &models.Role{ID: "dup_id_role", Name: "Another Role", Description: "Desc2"}
	err := s.repo.Create(ctx, role2)
	require.Error(s.T(), err) // Expect unique constraint violation
	assert.ErrorIs(s.T(), err, domainErrors.ErrDuplicateValue)
}

func (s *RoleRepositoryTestSuite) TestCreateRole_DuplicateName() {
	ctx := context.Background()
	s.helperCreateRole("role_dup_name1", "Duplicate Role Name", "Desc1")

	role2 := &models.Role{ID: "role_dup_name2", Name: "Duplicate Role Name", Description: "Desc2"}
	err := s.repo.Create(ctx, role2)
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrDuplicateValue)
}

func (s *RoleRepositoryTestSuite) TestGetByID_SuccessAndNotFound() {
	ctx := context.Background()
	role := s.helperCreateRole("get_by_id", "Get By ID Role", "Desc")

	// Success
	fetched, err := s.repo.GetByID(ctx, role.ID)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), fetched)
	assert.Equal(s.T(), role.Name, fetched.Name)

	// Not Found
	_, err = s.repo.GetByID(ctx, "non_existent_id")
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrRoleNotFound)
}

func (s *RoleRepositoryTestSuite) TestGetByName_SuccessAndNotFound() {
	ctx := context.Background()
	roleName := "Get By Name Role"
	role := s.helperCreateRole("get_by_name_id", roleName, "Desc")

	// Success
	fetched, err := s.repo.GetByName(ctx, roleName)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), fetched)
	assert.Equal(s.T(), role.ID, fetched.ID)

	// Not Found
	_, err = s.repo.GetByName(ctx, "Non Existent Role Name")
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrRoleNotFound)
}

func (s *RoleRepositoryTestSuite) TestUpdateRole_Success() {
	ctx := context.Background()
	role := s.helperCreateRole("update_me", "Original Name", "Original Desc")

	newName := "Updated Role Name"
	newDesc := "Updated Description"
	role.Name = newName
	role.Description = newDesc
	now := time.Now().UTC().Truncate(time.Millisecond)
	role.UpdatedAt = &now

	err := s.repo.Update(ctx, role)
	require.NoError(s.T(), err)

	fetched, _ := s.repo.GetByID(ctx, role.ID)
	require.NotNil(s.T(), fetched)
	assert.Equal(s.T(), newName, fetched.Name)
	assert.Equal(s.T(), newDesc, fetched.Description)
	require.NotNil(s.T(), fetched.UpdatedAt)
	assert.WithinDuration(s.T(), now, *fetched.UpdatedAt, time.Second)
}

func (s *RoleRepositoryTestSuite) TestDeleteRole_Success() {
	ctx := context.Background()
	role := s.helperCreateRole("delete_me", "To Be Deleted", "Desc")
	perm := s.helperCreatePermission("perm_for_delete_role", "Perm For Delete", "Desc", "res", "act")
	s.repo.AssignPermissionToRole(ctx, role.ID, perm.ID)


	err := s.repo.Delete(ctx, role.ID)
	require.NoError(s.T(), err)

	_, errFind := s.repo.GetByID(ctx, role.ID)
	assert.ErrorIs(s.T(), errFind, domainErrors.ErrRoleNotFound)

	// Verify cascade delete in role_permissions (this requires a way to check role_permissions table)
	// For simplicity, if RoleHasPermission now returns false, it implies the link is gone.
	hasPerm, errPerm := s.repo.RoleHasPermission(ctx, role.ID, perm.ID)
	require.NoError(s.T(), errPerm) // Should not error, just return false
	assert.False(s.T(), hasPerm)
}

func (s *RoleRepositoryTestSuite) TestListRoles() {
	ctx := context.Background()
	s.helperCreateRole("role_list1", "Role List 1", "Desc A")
	s.helperCreateRole("role_list2", "Role List 2", "Desc B")

	roles, total, err := s.repo.List(ctx, models.ListRolesParams{})
	require.NoError(s.T(), err)
	assert.Equal(s.T(), 2, total)
	assert.Len(s.T(), roles, 2)

	// Empty
	s.SetupTest() // Clean tables
	roles, total, err = s.repo.List(ctx, models.ListRolesParams{})
	require.NoError(s.T(), err)
	assert.Equal(s.T(), 0, total)
	assert.Empty(s.T(), roles)
}

// --- Role-Permission Management Tests ---
func (s *RoleRepositoryTestSuite) TestAssignPermissionToRole_SuccessAndIdempotency() {
	ctx := context.Background()
	role := s.helperCreateRole("role_perm_assign", "Role For Perms", "Desc")
	perm := s.helperCreatePermission("perm_assign", "Perm To Assign", "Desc", "res", "act")

	// Success
	err := s.repo.AssignPermissionToRole(ctx, role.ID, perm.ID)
	require.NoError(s.T(), err)
	hasPerm, _ := s.repo.RoleHasPermission(ctx, role.ID, perm.ID)
	assert.True(s.T(), hasPerm)

	// Idempotency
	err = s.repo.AssignPermissionToRole(ctx, role.ID, perm.ID)
	require.NoError(s.T(), err) // Should not error if already assigned (or handle specific duplicate error)
}

func (s *RoleRepositoryTestSuite) TestGetPermissionsForRole() {
	ctx := context.Background()
	role := s.helperCreateRole("role_get_perms", "Role With Multiple Perms", "Desc")
	perm1 := s.helperCreatePermission("perm_get1", "Perm Get 1", "D1", "r1", "a1")
	perm2 := s.helperCreatePermission("perm_get2", "Perm Get 2", "D2", "r2", "a2")
	s.helperCreatePermission("perm_not_assigned", "Perm Not Assigned", "D3", "r3", "a3")


	s.repo.AssignPermissionToRole(ctx, role.ID, perm1.ID)
	s.repo.AssignPermissionToRole(ctx, role.ID, perm2.ID)

	perms, err := s.repo.GetPermissionsForRole(ctx, role.ID)
	require.NoError(s.T(), err)
	require.Len(s.T(), perms, 2)
	permIDs := make([]string, len(perms))
	for i, p := range perms {
		permIDs[i] = p.ID
	}
	assert.Contains(s.T(), permIDs, perm1.ID)
	assert.Contains(s.T(), permIDs, perm2.ID)

	// Role with no perms
	roleNoPerms := s.helperCreateRole("role_no_perms", "Role No Perms", "Desc")
	perms, err = s.repo.GetPermissionsForRole(ctx, roleNoPerms.ID)
	require.NoError(s.T(), err)
	assert.Empty(s.T(), perms)

	// Non-existent role
	perms, err = s.repo.GetPermissionsForRole(ctx, "non_existent_role_perms")
	require.NoError(s.T(), err) // Should return empty list, not error, if role not found
	assert.Empty(s.T(), perms)
}

func (s *RoleRepositoryTestSuite) TestRemovePermissionFromRole() {
	ctx := context.Background()
	role := s.helperCreateRole("role_remove_perm", "Role For Removing Perms", "Desc")
	perm := s.helperCreatePermission("perm_remove", "Perm To Remove", "Desc", "res", "act")
	s.repo.AssignPermissionToRole(ctx, role.ID, perm.ID)

	// Success
	err := s.repo.RemovePermissionFromRole(ctx, role.ID, perm.ID)
	require.NoError(s.T(), err)
	hasPerm, _ := s.repo.RoleHasPermission(ctx, role.ID, perm.ID)
	assert.False(s.T(), hasPerm)

	// Idempotency (removing already removed)
	err = s.repo.RemovePermissionFromRole(ctx, role.ID, perm.ID)
	require.NoError(s.T(), err) // Should not error if already removed or link doesn't exist

	// Attempt to remove unassigned permission
	permOther := s.helperCreatePermission("perm_other_remove", "Other Perm", "Desc", "r", "a")
	err = s.repo.RemovePermissionFromRole(ctx, role.ID, permOther.ID)
	require.NoError(s.T(), err) // Should not error
}

func (s *RoleRepositoryTestSuite) TestRoleHasPermission() {
	ctx := context.Background()
	role := s.helperCreateRole("role_has_perm_test", "Role For HasPerm", "Desc")
	permAssigned := s.helperCreatePermission("perm_assigned_has", "Assigned Perm", "D", "r", "a")
	permNotAssigned := s.helperCreatePermission("perm_not_assigned_has", "Not Assigned Perm", "D", "r", "a")
	s.repo.AssignPermissionToRole(ctx, role.ID, permAssigned.ID)

	// True when assigned
	has, err := s.repo.RoleHasPermission(ctx, role.ID, permAssigned.ID)
	require.NoError(s.T(), err)
	assert.True(s.T(), has)

	// False when not assigned
	has, err = s.repo.RoleHasPermission(ctx, role.ID, permNotAssigned.ID)
	require.NoError(s.T(), err)
	assert.False(s.T(), has)

	// False for non-existent role
	has, err = s.repo.RoleHasPermission(ctx, "non_existent_role_has", permAssigned.ID)
	require.NoError(s.T(), err) // Should not error, just return false
	assert.False(s.T(), has)

	// False for non-existent permission
	has, err = s.repo.RoleHasPermission(ctx, role.ID, "non_existent_perm_has")
	require.NoError(s.T(), err)
	assert.False(s.T(), has)
}
