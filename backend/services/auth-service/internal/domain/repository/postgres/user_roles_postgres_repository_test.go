// File: backend/services/auth-service/internal/domain/repository/postgres/user_roles_repository_test.go
package postgres_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
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
// 	testPostgresDSNEnv = "TEST_AUTH_POSTGRES_DSN"
// 	defaultTestDSN     = "postgres://testuser:testpassword@localhost:5433/auth_test_db?sslmode=disable"
// 	defaultMigrationsPath = "file://../../../../migrations"
// )

type UserRolesRepositoryTestSuite struct {
	suite.Suite
	pool       *pgxpool.Pool
	repo       *postgres.UserRolesRepositoryPostgres
	migrations *migrate.Migrate
	dsn        string
}

func TestUserRolesRepositoryTestSuite(t *testing.T) {
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
	t.Log("Migrations applied successfully for user_roles tests")

	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("Failed to connect to test database using DSN '%s': %v", dsn, err)
	}

	testSuite := &UserRolesRepositoryTestSuite{
		Suite:      suite.Suite{},
		pool:       pool,
		migrations: m,
		dsn:        dsn,
	}
	suite.Run(t, testSuite)
}

func (s *UserRolesRepositoryTestSuite) SetupSuite() {}

func (s *UserRolesRepositoryTestSuite) TearDownSuite() {
	if s.pool != nil {
		s.pool.Close()
	}
	if s.migrations != nil {
		s.T().Log("Rolling back migrations for user_roles tests...")
		if err := s.migrations.Down(); err != nil && err != migrate.ErrNoChange {
			s.T().Logf("Warning: failed to rollback migrations in TearDownSuite: %v", err)
		} else {
			s.T().Log("Migrations for user_roles tests rolled back successfully.")
		}
	}
}

func (s *UserRolesRepositoryTestSuite) SetupTest() {
	s.repo = postgres.NewUserRolesRepositoryPostgres(s.pool)
	_, err := s.pool.Exec(context.Background(), `
		TRUNCATE TABLE user_roles CASCADE;
		TRUNCATE TABLE users CASCADE;
		TRUNCATE TABLE roles CASCADE;
	`)
	require.NoError(s.T(), err, "Failed to clean tables before test")
}

// Helper to create a user for tests
func (s *UserRolesRepositoryTestSuite) helperCreateUserForRolesTest(usernameSuffix string) *models.User {
	ctx := context.Background()
	user := &models.User{
		ID:           uuid.New(),
		Username:     fmt.Sprintf("user_ur_%s", usernameSuffix),
		Email:        fmt.Sprintf("user_ur_%s@example.com", usernameSuffix),
		PasswordHash: "hash",
		Status:       models.UserStatusActive,
		CreatedAt:    time.Now().UTC().Truncate(time.Millisecond),
	}
	query := "INSERT INTO users (id, username, email, password_hash, status, created_at) VALUES ($1, $2, $3, $4, $5, $6)"
	_, err := s.pool.Exec(ctx, query, user.ID, user.Username, user.Email, user.PasswordHash, user.Status, user.CreatedAt)
	require.NoError(s.T(), err)
	return user
}

// Helper to create a role for tests
func (s *UserRolesRepositoryTestSuite) helperCreateRoleForRolesTest(roleID, roleName string) *models.Role {
	ctx := context.Background()
	role := &models.Role{
		ID:          roleID,
		Name:        roleName,
		Description: fmt.Sprintf("Description for %s", roleName),
		CreatedAt:   time.Now().UTC().Truncate(time.Millisecond),
	}
	query := "INSERT INTO roles (id, name, description, created_at) VALUES ($1, $2, $3, $4)"
	_, err := s.pool.Exec(ctx, query, role.ID, role.Name, role.Description, role.CreatedAt)
	require.NoError(s.T(), err)
	return role
}

// --- Test Cases ---

func (s *UserRolesRepositoryTestSuite) TestAssignRoleToUser_Success() {
	ctx := context.Background()
	user := s.helperCreateUserForRolesTest("assign_success")
	role := s.helperCreateRoleForRolesTest("role_admin", "Admin Role")
	assigner := s.helperCreateUserForRolesTest("assigner")

	err := s.repo.AssignRoleToUser(ctx, user.ID, role.ID, &assigner.ID)
	require.NoError(s.T(), err)

	roleIDs, err := s.repo.GetRoleIDsForUser(ctx, user.ID)
	require.NoError(s.T(), err)
	assert.Contains(s.T(), roleIDs, role.ID)

	// Verify assigned_by_user_id (this requires a direct query or an enhanced GetRoleIDsForUser)
	var assignedBy uuid.UUID
	checkQuery := "SELECT assigned_by_user_id FROM user_roles WHERE user_id = $1 AND role_id = $2"
	err = s.pool.QueryRow(ctx, checkQuery, user.ID, role.ID).Scan(&assignedBy)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), assigner.ID, assignedBy)
}

func (s *UserRolesRepositoryTestSuite) TestAssignRoleToUser_Idempotency() {
	ctx := context.Background()
	user := s.helperCreateUserForRolesTest("assign_idem")
	role := s.helperCreateRoleForRolesTest("role_editor", "Editor Role")

	err := s.repo.AssignRoleToUser(ctx, user.ID, role.ID, nil) // Assigned by system (nil)
	require.NoError(s.T(), err)

	err = s.repo.AssignRoleToUser(ctx, user.ID, role.ID, nil) // Assign again
	require.NoError(s.T(), err) // Should not error due to ON CONFLICT DO NOTHING

	roleIDs, _ := s.repo.GetRoleIDsForUser(ctx, user.ID)
	assert.Len(s.T(), roleIDs, 1, "Role should only be assigned once")
}

func (s *UserRolesRepositoryTestSuite) TestAssignRoleToUser_NonExistentUser() {
	ctx := context.Background()
	role := s.helperCreateRoleForRolesTest("role_for_ghost_user", "Ghost Role")
	err := s.repo.AssignRoleToUser(ctx, uuid.New(), role.ID, nil)
	require.Error(s.T(), err) // Foreign key violation
}

func (s *UserRolesRepositoryTestSuite) TestAssignRoleToUser_NonExistentRole() {
	ctx := context.Background()
	user := s.helperCreateUserForRolesTest("assign_ghost_role")
	err := s.repo.AssignRoleToUser(ctx, user.ID, "non_existent_role_id", nil)
	require.Error(s.T(), err) // Foreign key violation
}

func (s *UserRolesRepositoryTestSuite) TestRemoveRoleFromUser_Success() {
	ctx := context.Background()
	user := s.helperCreateUserForRolesTest("remove_role_success")
	role := s.helperCreateRoleForRolesTest("role_to_remove", "Temporary Role")
	s.repo.AssignRoleToUser(ctx, user.ID, role.ID, nil)

	err := s.repo.RemoveRoleFromUser(ctx, user.ID, role.ID)
	require.NoError(s.T(), err)

	roleIDs, _ := s.repo.GetRoleIDsForUser(ctx, user.ID)
	assert.NotContains(s.T(), roleIDs, role.ID)
}

func (s *UserRolesRepositoryTestSuite) TestRemoveRoleFromUser_Unassigned() {
	ctx := context.Background()
	user := s.helperCreateUserForRolesTest("remove_unassigned")
	role := s.helperCreateRoleForRolesTest("role_not_assigned", "Unassigned Role")

	err := s.repo.RemoveRoleFromUser(ctx, user.ID, role.ID) // Removing a role that wasn't assigned
	require.NoError(s.T(), err) // Should not error, 0 rows affected by delete
}

func (s *UserRolesRepositoryTestSuite) TestGetRoleIDsForUser() {
	ctx := context.Background()
	user1 := s.helperCreateUserForRolesTest("user_multi_roles")
	user2 := s.helperCreateUserForRolesTest("user_no_roles")
	roleAdmin := s.helperCreateRoleForRolesTest("admin_for_get", "Admin")
	roleEditor := s.helperCreateRoleForRolesTest("editor_for_get", "Editor")

	s.repo.AssignRoleToUser(ctx, user1.ID, roleAdmin.ID, nil)
	s.repo.AssignRoleToUser(ctx, user1.ID, roleEditor.ID, nil)

	// User with multiple roles
	roleIDs1, err := s.repo.GetRoleIDsForUser(ctx, user1.ID)
	require.NoError(s.T(), err)
	assert.ElementsMatch(s.T(), []string{roleAdmin.ID, roleEditor.ID}, roleIDs1)

	// User with no roles
	roleIDs2, err := s.repo.GetRoleIDsForUser(ctx, user2.ID)
	require.NoError(s.T(), err)
	assert.Empty(s.T(), roleIDs2)

	// Non-existent user
	roleIDsNonExistent, err := s.repo.GetRoleIDsForUser(ctx, uuid.New())
	require.NoError(s.T(), err) // Repository returns empty slice, not error
	assert.Empty(s.T(), roleIDsNonExistent)
}

func (s *UserRolesRepositoryTestSuite) TestGetUserIDsForRole() {
	ctx := context.Background()
	user1 := s.helperCreateUserForRolesTest("user1_for_role")
	user2 := s.helperCreateUserForRolesTest("user2_for_role")
	userNoRole := s.helperCreateUserForRolesTest("user_no_role_get")
	roleManager := s.helperCreateRoleForRolesTest("manager_role_get", "Manager")
	roleOther := s.helperCreateRoleForRolesTest("other_role_get", "Other")


	s.repo.AssignRoleToUser(ctx, user1.ID, roleManager.ID, nil)
	s.repo.AssignRoleToUser(ctx, user2.ID, roleManager.ID, nil)
	s.repo.AssignRoleToUser(ctx, userNoRole.ID, roleOther.ID, nil)


	// Role assigned to multiple users
	userIDsManager, err := s.repo.GetUserIDsForRole(ctx, roleManager.ID)
	require.NoError(s.T(), err)
	assert.ElementsMatch(s.T(), []uuid.UUID{user1.ID, user2.ID}, userIDsManager)

	// Role assigned to no users (after removing assignments)
	s.repo.RemoveRoleFromUser(ctx, user1.ID, roleManager.ID)
	s.repo.RemoveRoleFromUser(ctx, user2.ID, roleManager.ID)
	userIDsManagerEmpty, err := s.repo.GetUserIDsForRole(ctx, roleManager.ID)
	require.NoError(s.T(), err)
	assert.Empty(s.T(), userIDsManagerEmpty)

	// Non-existent role
	userIDsNonExistent, err := s.repo.GetUserIDsForRole(ctx, "non_existent_role_get_users")
	require.NoError(s.T(), err) // Repository returns empty slice, not error
	assert.Empty(s.T(), userIDsNonExistent)
}

func (s *UserRolesRepositoryTestSuite) TestUserHasRole() {
	ctx := context.Background()
	user := s.helperCreateUserForRolesTest("user_has_role_check")
	roleAssigned := s.helperCreateRoleForRolesTest("assigned_role_check", "Assigned")
	roleNotAssigned := s.helperCreateRoleForRolesTest("not_assigned_role_check", "NotAssigned")

	s.repo.AssignRoleToUser(ctx, user.ID, roleAssigned.ID, nil)

	// True when role is assigned
	has, err := s.repo.UserHasRole(ctx, user.ID, roleAssigned.ID)
	require.NoError(s.T(), err)
	assert.True(s.T(), has)

	// False when role is not assigned
	has, err = s.repo.UserHasRole(ctx, user.ID, roleNotAssigned.ID)
	require.NoError(s.T(), err)
	assert.False(s.T(), has)

	// False for non-existent user
	has, err = s.repo.UserHasRole(ctx, uuid.New(), roleAssigned.ID)
	require.NoError(s.T(), err) // Should not error, just return false
	assert.False(s.T(), has)

	// False for non-existent role
	has, err = s.repo.UserHasRole(ctx, user.ID, "non_existent_role_check_has")
	require.NoError(s.T(), err)
	assert.False(s.T(), has)
}
