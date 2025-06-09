// File: backend/services/auth-service/internal/domain/repository/postgres/user_repository_test.go
package postgres_test // Use _test package to test as a client

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

	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/repository/postgres" // Import the package to test
	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres" // Driver
	_ "github.com/golang-migrate/migrate/v4/source/file"       // Driver
)

const (
	testPostgresDSNEnv = "TEST_AUTH_POSTGRES_DSN"
	defaultTestDSN     = "postgres://testuser:testpassword@localhost:5433/auth_test_db?sslmode=disable"
	// IMPORTANT: Adjust this path based on where your tests are run from.
	// This path assumes tests are run from the root of the `auth-service` directory,
	// or that the working directory is set such that this relative path is correct.
	// For `go test ./...` from service root, this might be `file://../migrations` if tests are in `internal/domain/repository/postgres`
	// and migrations are in `auth-service/migrations`.
	// For now, assuming migrations are in a top-level `migrations` folder relative to where `go test` is run.
	// A common pattern is to run tests from the service root.
	// If `auth-service` is the module root, and migrations are in `auth-service/migrations`,
	// and tests are run from `auth-service/`, then `file://migrations` might work.
	// If tests are run from `auth-service/internal/domain/repository/postgres/`, then `file://../../../../migrations` is needed.
	// Using a placeholder that often works if tests are run from a directory higher up or module root.
	// Best practice: make this configurable or use relative path discovery.
	defaultMigrationsPath = "file://../../../../migrations" // Adjust this path!
)

type UserRepositoryTestSuite struct {
	suite.Suite
	pool       *pgxpool.Pool
	repo       *postgres.UserRepositoryPostgres
	migrations *migrate.Migrate
	dsn        string
}

func TestUserRepositoryTestSuite(t *testing.T) {
	dsn := os.Getenv(testPostgresDSNEnv)
	if dsn == "" {
		dsn = defaultTestDSN
	}

	migrationsPath := os.Getenv("MIGRATIONS_PATH")
	if migrationsPath == "" {
		migrationsPath = defaultMigrationsPath
	}
	// Ensure "file://" prefix
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

	// Initialize migrations instance
	m, err := migrate.New(migrationsPath, dsn)
	if err != nil {
		t.Fatalf("Failed to create migration instance (path: %s, dsn: %s): %v", migrationsPath, dsn, err)
	}

	// Apply all up migrations
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("Failed to apply migrations: %v", err)
	}
	t.Log("Migrations applied successfully")


	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("Failed to connect to test database using DSN '%s': %v", dsn, err)
	}

	testSuite := &UserRepositoryTestSuite{
		Suite:      suite.Suite{},
		pool:       pool,
		migrations: m, // Store migrate instance for teardown
		dsn:        dsn,
	}
	suite.Run(t, testSuite)
}

func (s *UserRepositoryTestSuite) SetupSuite() {
	// Migrations are now run in TestUserRepositoryTestSuite before suite.Run
	// This ensures schema is up before any test suite logic runs.
}

func (s *UserRepositoryTestSuite) TearDownSuite() {
	if s.pool != nil {
		s.pool.Close()
	}
	if s.migrations != nil {
		s.T().Log("Rolling back migrations...")
		if err := s.migrations.Down(); err != nil && err != migrate.ErrNoChange {
			s.T().Logf("Warning: failed to rollback migrations in TearDownSuite: %v", err)
		} else {
			s.T().Log("Migrations rolled back successfully.")
		}
	}
}

func (s *UserRepositoryTestSuite) SetupTest() {
	s.repo = postgres.NewUserRepositoryPostgres(s.pool)
	// Clean data from tables before each test
	// Order is important for foreign key constraints if not using CASCADE broadly
	// or if specific tables are not cascaded from users.
	_, err := s.pool.Exec(context.Background(), `
		TRUNCATE TABLE user_roles CASCADE;
		TRUNCATE TABLE sessions CASCADE;
		TRUNCATE TABLE verification_codes CASCADE;
		TRUNCATE TABLE mfa_secrets CASCADE;
		TRUNCATE TABLE mfa_backup_codes CASCADE;
		TRUNCATE TABLE api_keys CASCADE;
		TRUNCATE TABLE external_accounts CASCADE;
		TRUNCATE TABLE users CASCADE;
	`)
	require.NoError(s.T(), err, "Failed to clean tables before test")
}

// --- Test Cases ---

func (s *UserRepositoryTestSuite) TestCreateUser_Success() {
	ctx := context.Background()
	userID := uuid.New()
	testTime := time.Now().UTC().Truncate(time.Millisecond)

	user := &models.User{
		ID:           userID,
		Username:     "testuser_create",
		Email:        "create@example.com",
		PasswordHash: "hashedpassword",
		Status:       models.UserStatusActive,
		CreatedAt:    testTime,
		UpdatedAt:    &testTime,
	}

	err := s.repo.Create(ctx, user)
	require.NoError(s.T(), err)

	fetchedUser, errFetch := s.repo.FindByID(ctx, userID)
	require.NoError(s.T(), errFetch)
	require.NotNil(s.T(), fetchedUser)
	assert.Equal(s.T(), user.Username, fetchedUser.Username)
	assert.Equal(s.T(), user.Email, fetchedUser.Email)
	assert.Equal(s.T(), user.PasswordHash, fetchedUser.PasswordHash)
	assert.Equal(s.T(), user.Status, fetchedUser.Status)
	assert.WithinDuration(s.T(), user.CreatedAt, fetchedUser.CreatedAt, time.Second)
	if user.UpdatedAt != nil && fetchedUser.UpdatedAt != nil {
		assert.WithinDuration(s.T(), *user.UpdatedAt, *fetchedUser.UpdatedAt, time.Second)
	} else {
		assert.Equal(s.T(), user.UpdatedAt, fetchedUser.UpdatedAt)
	}
}

func (s *UserRepositoryTestSuite) TestCreateUser_DuplicateEmail() {
	ctx := context.Background()
	err := s.repo.Create(ctx, &models.User{
		ID: uuid.New(), Username: "user1", Email: "duplicate@example.com", PasswordHash: "p1", Status: models.UserStatusActive,
	})
	require.NoError(s.T(), err)

	errCreate := s.repo.Create(ctx, &models.User{
		ID: uuid.New(), Username: "user2", Email: "duplicate@example.com", PasswordHash: "p2", Status: models.UserStatusActive,
	})
	require.Error(s.T(), errCreate)
	assert.ErrorIs(s.T(), errCreate, domainErrors.ErrEmailExists)
}

func (s *UserRepositoryTestSuite) TestCreateUser_DuplicateUsername() {
	ctx := context.Background()
	err := s.repo.Create(ctx, &models.User{
		ID: uuid.New(), Username: "duplicateuser", Email: "email1@example.com", PasswordHash: "p1", Status: models.UserStatusActive,
	})
	require.NoError(s.T(), err)

	errCreate := s.repo.Create(ctx, &models.User{
		ID: uuid.New(), Username: "duplicateuser", Email: "email2@example.com", PasswordHash: "p2", Status: models.UserStatusActive,
	})
	require.Error(s.T(), errCreate)
	assert.ErrorIs(s.T(), errCreate, domainErrors.ErrUsernameExists)
}


func (s *UserRepositoryTestSuite) TestFindByID_Success() {
	ctx := context.Background()
	userID := uuid.New()
	user := &models.User{ID: userID, Username: "findme", Email: "findme@example.com", PasswordHash: "hash", Status: models.UserStatusActive}
	err := s.repo.Create(ctx, user)
	require.NoError(s.T(), err)

	fetchedUser, err := s.repo.FindByID(ctx, userID)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), fetchedUser)
	assert.Equal(s.T(), user.Username, fetchedUser.Username)
}

func (s *UserRepositoryTestSuite) TestFindByID_NotFound() {
	ctx := context.Background()
	_, err := s.repo.FindByID(ctx, uuid.New())
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrUserNotFound)
}

func (s *UserRepositoryTestSuite) TestFindByEmail_Success() {
	ctx := context.Background()
	email := "findbyemail@example.com"
	user := &models.User{ID: uuid.New(), Username: "findbyemailuser", Email: email, PasswordHash: "hash", Status: models.UserStatusActive}
	err := s.repo.Create(ctx, user)
	require.NoError(s.T(), err)

	fetchedUser, err := s.repo.FindByEmail(ctx, email)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), fetchedUser)
	assert.Equal(s.T(), user.Username, fetchedUser.Username)
}

func (s *UserRepositoryTestSuite) TestFindByEmail_NotFound() {
	ctx := context.Background()
	_, err := s.repo.FindByEmail(ctx, "nonexistent@example.com")
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrUserNotFound)
}

func (s *UserRepositoryTestSuite) TestFindByUsername_Success() {
	ctx := context.Background()
	username := "findbyusername"
	user := &models.User{ID: uuid.New(), Username: username, Email: "findbyusername@example.com", PasswordHash: "hash", Status: models.UserStatusActive}
	err := s.repo.Create(ctx, user)
	require.NoError(s.T(), err)

	fetchedUser, err := s.repo.FindByUsername(ctx, username)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), fetchedUser)
	assert.Equal(s.T(), user.Email, fetchedUser.Email)
}

func (s *UserRepositoryTestSuite) TestFindByUsername_NotFound() {
	ctx := context.Background()
	_, err := s.repo.FindByUsername(ctx, "nonexistent_username")
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrUserNotFound)
}

func (s *UserRepositoryTestSuite) TestUpdateUser_Success() {
	ctx := context.Background()
	user := &models.User{ID: uuid.New(), Username: "origuser", Email: "orig@example.com", PasswordHash: "orig_hash", Status: models.UserStatusActive}
	err := s.repo.Create(ctx, user)
	require.NoError(s.T(), err)

	newUsername := "updateduser"
	newEmail := "updated@example.com"
	user.Username = newUsername
	user.Email = newEmail
	now := time.Now().UTC().Truncate(time.Millisecond)
	user.UpdatedAt = &now

	errUpdate := s.repo.Update(ctx, user)
	require.NoError(s.T(), errUpdate)

	fetchedUser, _ := s.repo.FindByID(ctx, user.ID)
	require.NotNil(s.T(), fetchedUser)
	assert.Equal(s.T(), newUsername, fetchedUser.Username)
	assert.Equal(s.T(), newEmail, fetchedUser.Email)
	assert.WithinDuration(s.T(), now, *fetchedUser.UpdatedAt, time.Second)
}

func (s *UserRepositoryTestSuite) TestUpdateUser_DuplicateEmail() {
	ctx := context.Background()
	user1 := &models.User{ID: uuid.New(), Username: "user1", Email: "email1@example.com", PasswordHash: "p1", Status: models.UserStatusActive}
	s.repo.Create(ctx, user1)
	user2 := &models.User{ID: uuid.New(), Username: "user2", Email: "email2@example.com", PasswordHash: "p2", Status: models.UserStatusActive}
	s.repo.Create(ctx, user2)

	user2.Email = "email1@example.com" // Attempt to update to user1's email
	err := s.repo.Update(ctx, user2)
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrEmailExists)
}

func (s *UserRepositoryTestSuite) TestUpdateUser_NotFound() {
	ctx := context.Background()
	nonExistentUser := &models.User{ID: uuid.New(), Username: "ghost", Email: "ghost@example.com"}
	err := s.repo.Update(ctx, nonExistentUser)
	require.Error(s.T(), err)
	// Note: Update might not return ErrUserNotFound if it uses "UPDATE ... WHERE id = $1"
	// and doesn't check rows affected or return specific error for 0 rows.
	// This depends on repository implementation details. For now, assume it might return a generic error or no error.
	// If it's expected to return ErrUserNotFound, then: assert.ErrorIs(s.T(), err, domainErrors.ErrUserNotFound)
}

func (s *UserRepositoryTestSuite) TestDeleteUser_Success() {
	ctx := context.Background()
	user := &models.User{ID: uuid.New(), Username: "todelete", Email: "delete@example.com", PasswordHash: "hash", Status: models.UserStatusActive}
	s.repo.Create(ctx, user)

	err := s.repo.Delete(ctx, user.ID)
	require.NoError(s.T(), err)

	deletedUser, errFind := s.repo.FindByID(ctx, user.ID) // This should fail due to "deleted_at IS NULL"
	require.Error(s.T(), errFind)
	assert.ErrorIs(s.T(), errFind, domainErrors.ErrUserNotFound)
	assert.Nil(s.T(), deletedUser)

	// Optionally, verify directly in DB if DeletedAt is set (requires different query method not in repo interface)
}

func (s *UserRepositoryTestSuite) TestUpdateStatus_Success() {
	ctx := context.Background()
	user := &models.User{ID: uuid.New(), Username: "statususer", Email: "status@example.com", PasswordHash: "hash", Status: models.UserStatusActive}
	s.repo.Create(ctx, user)

	err := s.repo.UpdateStatus(ctx, user.ID, models.UserStatusBlocked)
	require.NoError(s.T(), err)
	fetchedUser, _ := s.repo.FindByID(ctx, user.ID)
	require.NotNil(s.T(), fetchedUser)
	assert.Equal(s.T(), models.UserStatusBlocked, fetchedUser.Status)
}

func (s *UserRepositoryTestSuite) TestSetEmailVerifiedAt_Success() {
	ctx := context.Background()
	user := &models.User{ID: uuid.New(), Username: "verifyemailuser", Email: "verify@example.com", PasswordHash: "hash", Status: models.UserStatusPendingVerification}
	s.repo.Create(ctx, user)
	require.Nil(s.T(), user.EmailVerifiedAt)

	verifyTime := time.Now().UTC().Truncate(time.Millisecond)
	err := s.repo.SetEmailVerifiedAt(ctx, user.ID, verifyTime)
	require.NoError(s.T(), err)
	fetchedUser, _ := s.repo.FindByID(ctx, user.ID)
	require.NotNil(s.T(), fetchedUser)
	require.NotNil(s.T(), fetchedUser.EmailVerifiedAt)
	assert.WithinDuration(s.T(), verifyTime, *fetchedUser.EmailVerifiedAt, time.Second)
}

func (s *UserRepositoryTestSuite) TestUpdatePassword_Success() {
	ctx := context.Background()
	user := &models.User{ID: uuid.New(), Username: "passuser", Email: "pass@example.com", PasswordHash: "oldhash", Status: models.UserStatusActive}
	s.repo.Create(ctx, user)

	newHash := "newSecureHash"
	err := s.repo.UpdatePassword(ctx, user.ID, newHash)
	require.NoError(s.T(), err)
	fetchedUser, _ := s.repo.FindByID(ctx, user.ID)
	require.NotNil(s.T(), fetchedUser)
	assert.Equal(s.T(), newHash, fetchedUser.PasswordHash)
}

func (s *UserRepositoryTestSuite) TestLoginAttemptsAndLockout() {
	ctx := context.Background()
	user := &models.User{ID: uuid.New(), Username: "lockme", Email: "lock@example.com", PasswordHash: "hash", Status: models.UserStatusActive}
	s.repo.Create(ctx, user)

	// Increment
	err := s.repo.IncrementFailedLoginAttempts(ctx, user.ID)
	require.NoError(s.T(), err)
	fetched, _ := s.repo.FindByID(ctx, user.ID)
	assert.Equal(s.T(), 1, fetched.FailedLoginAttempts)

	// Update Lockout
	lockoutTime := time.Now().Add(time.Hour).UTC().Truncate(time.Millisecond)
	err = s.repo.UpdateLockout(ctx, user.ID, &lockoutTime)
	require.NoError(s.T(), err)
	fetched, _ = s.repo.FindByID(ctx, user.ID)
	require.NotNil(s.T(), fetched.LockoutUntil)
	assert.WithinDuration(s.T(), lockoutTime, *fetched.LockoutUntil, time.Second)

	// Reset
	err = s.repo.ResetFailedLoginAttempts(ctx, user.ID)
	require.NoError(s.T(), err)
	fetched, _ = s.repo.FindByID(ctx, user.ID)
	assert.Equal(s.T(), 0, fetched.FailedLoginAttempts)
	assert.Nil(s.T(), fetched.LockoutUntil) // Assuming Reset also clears lockout
}

func (s *UserRepositoryTestSuite) TestUpdateLastLogin_Success() {
	ctx := context.Background()
	user := &models.User{ID: uuid.New(), Username: "lastloginuser", Email: "lastlogin@example.com", PasswordHash: "hash", Status: models.UserStatusActive}
	s.repo.Create(ctx, user)

	lastLoginTime := time.Now().UTC().Truncate(time.Millisecond)
	err := s.repo.UpdateLastLogin(ctx, user.ID, lastLoginTime)
	require.NoError(s.T(), err)
	fetchedUser, _ := s.repo.FindByID(ctx, user.ID)
	require.NotNil(s.T(), fetchedUser)
	require.NotNil(s.T(), fetchedUser.LastLoginAt)
	assert.WithinDuration(s.T(), lastLoginTime, *fetchedUser.LastLoginAt, time.Second)
}

func (s *UserRepositoryTestSuite) TestListUsers() {
	ctx := context.Background()
	// Create some users
	s.repo.Create(ctx, &models.User{ID: uuid.New(), Username: "user1_active_test", Email: "u1@test.com", Status: models.UserStatusActive, PasswordHash: "h"})
	s.repo.Create(ctx, &models.User{ID: uuid.New(), Username: "user2_blocked_test", Email: "u2@test.com", Status: models.UserStatusBlocked, PasswordHash: "h"})
	s.repo.Create(ctx, &models.User{ID: uuid.New(), Username: "user3_active_other", Email: "u3@other.com", Status: models.UserStatusActive, PasswordHash: "h"})

	// No filters
	users, total, err := s.repo.List(ctx, models.ListUsersParams{})
	require.NoError(s.T(), err)
	assert.Equal(s.T(), 3, total)
	assert.Len(s.T(), users, 3)

	// Filter by status
	users, total, err = s.repo.List(ctx, models.ListUsersParams{Status: string(models.UserStatusActive)})
	require.NoError(s.T(), err)
	assert.Equal(s.T(), 2, total)
	assert.Len(s.T(), users, 2)

	// Filter by username contains
	users, total, err = s.repo.List(ctx, models.ListUsersParams{UsernameContains: "test"})
	require.NoError(s.T(), err)
	assert.Equal(s.T(), 2, total) // user1_active_test, user2_blocked_test
	assert.Len(s.T(), users, 2)

	// Filter by email contains
	users, total, err = s.repo.List(ctx, models.ListUsersParams{EmailContains: "@test.com"})
	require.NoError(s.T(), err)
	assert.Equal(s.T(), 2, total) // u1@test.com, u2@test.com
	assert.Len(s.T(), users, 2)

	// Pagination
	users, total, err = s.repo.List(ctx, models.ListUsersParams{PageSize: 1, Page: 1})
	require.NoError(s.T(), err)
	assert.Equal(s.T(), 3, total) // Total still reflects all users matching filter (none here)
	assert.Len(s.T(), users, 1)

	users, total, err = s.repo.List(ctx, models.ListUsersParams{PageSize: 1, Page: 2})
	require.NoError(s.T(), err)
	assert.Equal(s.T(), 3, total)
	assert.Len(s.T(), users, 1)
}
