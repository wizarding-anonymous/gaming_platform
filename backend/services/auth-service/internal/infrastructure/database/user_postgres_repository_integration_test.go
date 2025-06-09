// File: backend/services/auth-service/internal/infrastructure/database/user_postgres_repository_integration_test.go
package database

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/config" // For DB config if loaded directly
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors"
	repoPostgres "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/repository/postgres" // Alias for clarity
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/infrastructure/security" // For password hashing

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

var testDB *pgxpool.Pool
var argon2Service domainService.PasswordService // For hashing passwords in tests

// TestMain sets up the test database and runs migrations.
func TestMain(m *testing.M) {
	// 1. Load Test Configuration (simplified for this example)
	// In a real scenario, this might come from a specific test config file or env vars
	dbHost := os.Getenv("TEST_DB_HOST")
	if dbHost == "" { dbHost = "localhost" }
	dbPort := os.Getenv("TEST_DB_PORT")
	if dbPort == "" { dbPort = "5433" } // Often use a different port for test DB
	dbUser := os.Getenv("TEST_DB_USER")
	if dbUser == "" { dbUser = "test_auth_user" }
	dbPassword := os.Getenv("TEST_DB_PASSWORD")
	if dbPassword == "" { dbPassword = "test_auth_password" }
	dbName := os.Getenv("TEST_DB_NAME")
	if dbName == "" { dbName = "test_auth_db" }
	sslMode := os.Getenv("TEST_DB_SSLMODE")
	if sslMode == "" { sslMode = "disable" }

	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
		dbUser, dbPassword, dbHost, dbPort, dbName, sslMode)

	// 2. Connect to Test Database
	var err error
	testDB, err = pgxpool.New(context.Background(), dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to test database: %v\n", err)
		os.Exit(1)
	}
	defer testDB.Close()

	// 3. Run Migrations
	// Ensure migrations path is correct relative to where tests are run.
	// This usually means running tests from the service root.
	migrationPath := "file://../../../migrations" // Adjust if your migrations folder is elsewhere relative to this test file's execution

	mig, err := migrate.New(migrationPath, dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create migration instance: %v\n", err)
		os.Exit(1)
	}
	if err := mig.Up(); err != nil && err != migrate.ErrNoChange {
		fmt.Fprintf(os.Stderr, "Failed to apply migrations: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Test database migrations applied successfully.")

	// Initialize Argon2id service for password hashing in tests
    // Use default params or load from a test config if specific params matter
    argon2Params := security.Argon2idParams{Memory: 64 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}
    argon2Service, err = security.NewArgon2idPasswordService(argon2Params)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to init argon2service: %v\n", err)
        os.Exit(1)
    }

	// 4. Run Tests
	exitCode := m.Run()

	// 5. Teardown (optional: drop test database or tables if needed, but usually transactions are preferred)
	os.Exit(exitCode)
}

// Helper to clear all user-related tables (use with caution, prefer transactions)
func clearUserTables(t *testing.T, db *pgxpool.Pool) {
	t.Helper()
	// Order matters due to foreign key constraints
	tables := []string{"user_roles", "sessions", "refresh_tokens", "api_keys", "mfa_secrets", "mfa_backup_codes", "verification_codes", "external_accounts", "users"}
	for _, table := range tables {
		_, err := db.Exec(context.Background(), fmt.Sprintf("DELETE FROM %s", table)) // Or TRUNCATE if FKs allow
		require.NoError(t, err, "Failed to clear table %s", table)
	}
}

// TestUserRepository_CreateAndFind tests creating a user and finding it by various means.
func TestUserRepository_CreateAndFind(t *testing.T) {
	ctx := context.Background()
	userRepo := repoPostgres.NewUserRepositoryPostgres(testDB)

	// Use a transaction for test isolation
	tx, err := testDB.Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx) // Ensure rollback after test

	// Create a user within the transaction
	userRepoTx := userRepo.WithTx(tx) // Assuming WithTx method exists or adapt

	hashedPassword, err := argon2Service.HashPassword("password123")
	require.NoError(t, err)

	newUser := &models.User{
		ID:           uuid.New(),
		Username:     "testuser_cf",
		Email:        "testuser_cf@example.com",
		PasswordHash: hashedPassword,
		Status:       models.UserStatusActive,
		DisplayName:  "Test User CF",
		CreatedAt:    time.Now(), // DB should set this, but good for comparison later
		UpdatedAt:    time.Now(), // DB should set this
	}

	err = userRepoTx.Create(ctx, newUser)
	require.NoError(t, err, "Failed to create user")

	// Find by ID
	foundByID, err := userRepoTx.FindByID(ctx, newUser.ID)
	require.NoError(t, err, "FindByID failed")
	require.NotNil(t, foundByID, "User not found by ID")
	assert.Equal(t, newUser.Username, foundByID.Username)
	assert.Equal(t, newUser.Email, foundByID.Email)
	assert.Equal(t, newUser.Status, foundByID.Status)

	// Find by Email
	foundByEmail, err := userRepoTx.FindByEmail(ctx, newUser.Email)
	require.NoError(t, err, "FindByEmail failed")
	require.NotNil(t, foundByEmail, "User not found by Email")
	assert.Equal(t, newUser.ID, foundByEmail.ID)

	// Find by Username
	foundByUsername, err := userRepoTx.FindByUsername(ctx, newUser.Username)
	require.NoError(t, err, "FindByUsername failed")
	require.NotNil(t, foundByUsername, "User not found by Username")
	assert.Equal(t, newUser.ID, foundByUsername.ID)

	err = tx.Commit(ctx)
	require.NoError(t, err) // Commit if all assertions passed

	// Cleanup (if not using transactions or want to double-check rollback)
	// clearUserTables(t, testDB) // Or specific delete
    _, err = testDB.Exec(ctx, "DELETE FROM users WHERE id = $1", newUser.ID)
    require.NoError(t, err)
}


// TestUserRepository_Create_DuplicateEmailOrUsername tests duplicate constraints.
func TestUserRepository_Create_DuplicateEmailOrUsername(t *testing.T) {
	ctx := context.Background()
	userRepo := repoPostgres.NewUserRepositoryPostgres(testDB)

	// No transaction here to test actual DB constraints across test runs if needed,
	// but for this specific test, a transaction is fine if we create the first user inside.
	// For robust duplicate testing, ensure the first user is committed or test without transaction.
	clearUserTables(t, testDB) // Clean slate for this specific test

	hashedPassword, _ := argon2Service.HashPassword("password123")

	firstUser := &models.User{
		ID:           uuid.New(),
		Username:     "duplicate_user",
		Email:        "duplicate@example.com",
		PasswordHash: hashedPassword,
		Status:       models.UserStatusActive,
	}
	err := userRepo.Create(ctx, firstUser)
	require.NoError(t, err, "Failed to create first user for duplicate test")

	// Test duplicate email
	userWithDupEmail := &models.User{
		ID:           uuid.New(),
		Username:     "another_user_dup_email",
		Email:        firstUser.Email, // Duplicate email
		PasswordHash: hashedPassword,
		Status:       models.UserStatusActive,
	}
	err = userRepo.Create(ctx, userWithDupEmail)
	require.Error(t, err, "Should have failed due to duplicate email")
	var pgErr *pgconn.PgError
	require.True(t, errors.As(err, &pgErr), "Error should be a PgError")
	assert.Equal(t, "23505", pgErr.Code, "PostgreSQL error code for unique_violation should be 23505") // unique_violation

	// Test duplicate username
	userWithDupUsername := &models.User{
		ID:           uuid.New(),
		Username:     firstUser.Username, // Duplicate username
		Email:        "another_email_dup_user@example.com",
		PasswordHash: hashedPassword,
		Status:       models.UserStatusActive,
	}
	err = userRepo.Create(ctx, userWithDupUsername)
	require.Error(t, err, "Should have failed due to duplicate username")
	require.True(t, errors.As(err, &pgErr), "Error should be a PgError")
	assert.Equal(t, "23505", pgErr.Code, "PostgreSQL error code for unique_violation should be 23505")

	// Cleanup
	_, delErr := testDB.Exec(ctx, "DELETE FROM users WHERE username = $1 OR email = $1", firstUser.Username)
	require.NoError(t, delErr)
}

// TODO: Implement other UserRepository tests: Update, Delete (Soft), UpdateStatus, etc.
// Each test should use transactions or manage its own data cleanup.
// Example for Update:
func TestUserRepository_Update(t *testing.T) {
    ctx := context.Background()
    userRepo := repoPostgres.NewUserRepositoryPostgres(testDB)
    clearUserTables(t, testDB) // Clean before test

    hashedPassword, _ := argon2Service.HashPassword("password123")
    userID := uuid.New()
    initialUser := &models.User{
        ID:           userID,
        Username:     "update_me",
        Email:        "update_me@example.com",
        PasswordHash: hashedPassword,
        Status:       models.UserStatusPendingVerification,
        DisplayName:  "Initial Name",
    }
    err := userRepo.Create(ctx, initialUser)
    require.NoError(t, err)

    // Fetch, modify, and update
    userToUpdate, err := userRepo.FindByID(ctx, userID)
    require.NoError(t, err)
    require.NotNil(t, userToUpdate)

    userToUpdate.DisplayName = "Updated Name"
    userToUpdate.Status = models.UserStatusActive
    now := time.Now()
    userToUpdate.EmailVerifiedAt = &now // Verify email

    err = userRepo.Update(ctx, userToUpdate) // Assuming Update updates all relevant fields
    require.NoError(t, err)

    updatedUser, err := userRepo.FindByID(ctx, userID)
    require.NoError(t, err)
    require.NotNil(t, updatedUser)
    assert.Equal(t, "Updated Name", updatedUser.DisplayName)
    assert.Equal(t, models.UserStatusActive, updatedUser.Status)
    require.NotNil(t, updatedUser.EmailVerifiedAt)
    assert.WithinDuration(t, now, *updatedUser.EmailVerifiedAt, time.Second)
    assert.True(t, updatedUser.UpdatedAt.After(initialUser.UpdatedAt), "UpdatedAt should be more recent")


    _, delErr := testDB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	require.NoError(t, delErr)
}

func TestUserRepository_Delete_SoftDelete(t *testing.T) {
	ctx := context.Background()
	userRepo := repoPostgres.NewUserRepositoryPostgres(testDB)
	clearUserTables(t, testDB)

	hashedPassword, _ := argon2Service.HashPassword("password123")
	user := &models.User{
		ID:           uuid.New(),
		Username:     "delete_me_soft",
		Email:        "delete_me_soft@example.com",
		PasswordHash: hashedPassword,
		Status:       models.UserStatusActive,
	}
	err := userRepo.Create(ctx, user)
	require.NoError(t, err)

	// Call Delete (soft delete)
	err = userRepo.Delete(ctx, user.ID)
	require.NoError(t, err)

	// Try to FindByID - should fail as it usually only finds non-deleted users
	_, err = userRepo.FindByID(ctx, user.ID)
	assert.ErrorIs(t, err, domainErrors.ErrUserNotFound, "Expected ErrUserNotFound after soft delete")

	// Query DB directly to confirm deleted_at is set
	var deletedAt time.Time
	var email string
	// Check that PII is not nulled out by current soft delete (as per task description)
	err = testDB.QueryRow(ctx, "SELECT email, deleted_at FROM users WHERE id = $1", user.ID).Scan(&email, &deletedAt)
	require.NoError(t, err, "Failed to query user directly after soft delete")
	assert.NotNil(t, deletedAt, "deleted_at should be set")
	assert.False(t, deletedAt.IsZero(), "deleted_at should not be zero")
	assert.Equal(t, user.Email, email, "Email should not be nulled after soft delete")


	// Hard delete for cleanup
	_, delErr := testDB.Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	require.NoError(t, delErr)
}

func TestUserRepository_UpdateStatus(t *testing.T) {
	ctx := context.Background()
	userRepo := repoPostgres.NewUserRepositoryPostgres(testDB)
	clearUserTables(t, testDB)

	user := &models.User{ID: uuid.New(), Username: "status_user", Email: "status@example.com", PasswordHash: "hash", Status: models.UserStatusActive}
	err := userRepo.Create(ctx, user)
	require.NoError(t, err)

	err = userRepo.UpdateStatus(ctx, user.ID, models.UserStatusBlocked)
	require.NoError(t, err)

	updatedUser, err := userRepo.FindByID(ctx, user.ID)
	require.NoError(t, err)
	assert.Equal(t, models.UserStatusBlocked, updatedUser.Status)

	_, delErr := testDB.Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	require.NoError(t, delErr)
}

func TestUserRepository_SetEmailVerifiedAt(t *testing.T) {
	ctx := context.Background()
	userRepo := repoPostgres.NewUserRepositoryPostgres(testDB)
	clearUserTables(t, testDB)

	user := &models.User{ID: uuid.New(), Username: "email_verify_user", Email: "emailverify@example.com", PasswordHash: "hash", Status: models.UserStatusPendingVerification}
	err := userRepo.Create(ctx, user)
	require.NoError(t, err)
	require.Nil(t, user.EmailVerifiedAt, "EmailVerifiedAt should be nil initially")

	verificationTime := time.Now()
	err = userRepo.SetEmailVerifiedAt(ctx, user.ID, verificationTime)
	require.NoError(t, err)

	updatedUser, err := userRepo.FindByID(ctx, user.ID)
	require.NoError(t, err)
	require.NotNil(t, updatedUser.EmailVerifiedAt)
	assert.WithinDuration(t, verificationTime, *updatedUser.EmailVerifiedAt, time.Second)
	// Check if status was also updated if that's the expected behavior (not specified, depends on service logic usually)
	// For this repo test, just check EmailVerifiedAt.

	_, delErr := testDB.Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	require.NoError(t, delErr)
}

func TestUserRepository_UpdatePassword(t *testing.T) {
	ctx := context.Background()
	userRepo := repoPostgres.NewUserRepositoryPostgres(testDB)
	clearUserTables(t, testDB)

	oldPassword := "oldPassword123"
	newPassword := "newPassword456!"
	hashedOldPassword, _ := argon2Service.HashPassword(oldPassword)

	user := &models.User{ID: uuid.New(), Username: "password_update_user", Email: "pwupdate@example.com", PasswordHash: hashedOldPassword, Status: models.UserStatusActive}
	err := userRepo.Create(ctx, user)
	require.NoError(t, err)

	hashedNewPassword, _ := argon2Service.HashPassword(newPassword)
	err = userRepo.UpdatePassword(ctx, user.ID, hashedNewPassword)
	require.NoError(t, err)

	updatedUser, err := userRepo.FindByID(ctx, user.ID)
	require.NoError(t, err)
	assert.Equal(t, hashedNewPassword, updatedUser.PasswordHash)

	// Verify with argon2Service
	match, _ := argon2Service.CheckPasswordHash(newPassword, updatedUser.PasswordHash)
	assert.True(t, match, "New password should match")
	matchOld, _ := argon2Service.CheckPasswordHash(oldPassword, updatedUser.PasswordHash)
	assert.False(t, matchOld, "Old password should not match")

	_, delErr := testDB.Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	require.NoError(t, delErr)
}

func TestUserRepository_IncrementFailedLoginAttempts_And_Lockout(t *testing.T) {
	ctx := context.Background()
	userRepo := repoPostgres.NewUserRepositoryPostgres(testDB)
	clearUserTables(t, testDB)

	user := &models.User{ID: uuid.New(), Username: "login_attempts_user", Email: "loginattempts@example.com", PasswordHash: "hash", Status: models.UserStatusActive}
	err := userRepo.Create(ctx, user)
	require.NoError(t, err)

	// Increment a few times
	for i := 1; i <= 3; i++ {
		err = userRepo.IncrementFailedLoginAttempts(ctx, user.ID)
		require.NoError(t, err)
		updatedUser, _ := userRepo.FindByID(ctx, user.ID)
		assert.Equal(t, i, updatedUser.FailedLoginAttempts)
	}

	// Lockout (assuming MaxFailedAttempts is, say, 5, and Increment does not auto-lock)
	// We'll manually call UpdateLockout for this test.
	lockoutTime := time.Now().Add(15 * time.Minute)
	err = userRepo.UpdateLockout(ctx, user.ID, &lockoutTime)
	require.NoError(t, err)

	lockedUser, _ := userRepo.FindByID(ctx, user.ID)
	require.NotNil(t, lockedUser.LockoutUntil)
	assert.WithinDuration(t, lockoutTime, *lockedUser.LockoutUntil, time.Second)

	_, delErr := testDB.Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	require.NoError(t, delErr)
}

func TestUserRepository_ResetFailedLoginAttempts(t *testing.T) {
	ctx := context.Background()
	userRepo := repoPostgres.NewUserRepositoryPostgres(testDB)
	clearUserTables(t, testDB)

	lockoutTime := time.Now().Add(15 * time.Minute)
	user := &models.User{
		ID: uuid.New(), Username: "reset_attempts_user", Email: "resetattempts@example.com", PasswordHash: "hash", Status: models.UserStatusActive,
		FailedLoginAttempts: 5, LockoutUntil: &lockoutTime,
	}
	// Need to create user with these fields already set, or update them first.
	// Create doesn't set these, so let's update after create.
	err := userRepo.Create(ctx, user)
	require.NoError(t, err)

	// Manually update to simulate failed attempts and lockout (since Create doesn't set these)
	_, err = testDB.Exec(ctx, "UPDATE users SET failed_login_attempts = $1, lockout_until = $2 WHERE id = $3",
		user.FailedLoginAttempts, user.LockoutUntil, user.ID)
	require.NoError(t, err)


	err = userRepo.ResetFailedLoginAttempts(ctx, user.ID)
	require.NoError(t, err)

	updatedUser, _ := userRepo.FindByID(ctx, user.ID)
	assert.Equal(t, 0, updatedUser.FailedLoginAttempts)
	assert.Nil(t, updatedUser.LockoutUntil)

	_, delErr := testDB.Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	require.NoError(t, delErr)
}

func TestUserRepository_UpdateLastLogin(t *testing.T) {
	ctx := context.Background()
	userRepo := repoPostgres.NewUserRepositoryPostgres(testDB)
	clearUserTables(t, testDB)

	user := &models.User{ID: uuid.New(), Username: "lastlogin_user", Email: "lastlogin@example.com", PasswordHash: "hash", Status: models.UserStatusActive}
	err := userRepo.Create(ctx, user)
	require.NoError(t, err)
	require.Nil(t, user.LastLoginAt, "LastLoginAt should be nil initially or zero time")

	lastLoginTime := time.Now()
	err = userRepo.UpdateLastLogin(ctx, user.ID, lastLoginTime)
	require.NoError(t, err)

	updatedUser, err := userRepo.FindByID(ctx, user.ID)
	require.NoError(t, err)
	require.NotNil(t, updatedUser.LastLoginAt)
	assert.WithinDuration(t, lastLoginTime, *updatedUser.LastLoginAt, time.Second)

	_, delErr := testDB.Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	require.NoError(t, delErr)
}

// TestUserRepository_UpdateUserStatusFields is largely covered by TestUserRepository_Update
// and TestUserRepository_UpdateStatus / TestUserRepository_IncrementFailedLoginAttempts_And_Lockout.
// If there were a specific repo method `UpdateUserStatusFields(ctx, id, status, reason, lockout, updatedBy)`
// then a dedicated test would be here. The current `Update` method handles general field updates.
// status_reason and updated_by are not explicitly managed by separate repo methods yet beyond the general Update.

func TestUserRepository_UpdateUserStatusFields(t *testing.T) {
	ctx := context.Background()
	userRepo := repoPostgres.NewUserRepositoryPostgres(testDB)
	clearUserTables(t, testDB)

	user := &models.User{
		ID:           uuid.New(),
		Username:     "statusfields_user",
		Email:        "statusfields@example.com",
		PasswordHash: "hash",
		Status:       models.UserStatusActive,
	}
	err := userRepo.Create(ctx, user)
	require.NoError(t, err)

	newStatus := models.UserStatusBlocked
	statusReason := "account_compromised"
	lockoutUntil := time.Now().Add(7 * 24 * time.Hour) // Lock for 7 days

	// Assuming the interface UserRepository has UpdateUserStatusFields
	// If not, this test will highlight the discrepancy or fail if the method doesn't exist on the concrete type.
	// The interface defined in a previous subtask was:
	// UpdateUserStatusFields(ctx context.Context, userID uuid.UUID, status models.UserStatus, statusReason *string, lockoutUntil *time.Time) error

	err = userRepo.UpdateUserStatusFields(ctx, user.ID, newStatus, &statusReason, &lockoutUntil)
	require.NoError(t, err, "UpdateUserStatusFields failed")

	updatedUser, err := userRepo.FindByID(ctx, user.ID)
	require.NoError(t, err)
	require.NotNil(t, updatedUser)

	assert.Equal(t, newStatus, updatedUser.Status)
	require.NotNil(t, updatedUser.StatusReason, "StatusReason should be set")
	assert.Equal(t, statusReason, *updatedUser.StatusReason)
	require.NotNil(t, updatedUser.LockoutUntil, "LockoutUntil should be set")
	assert.WithinDuration(t, lockoutUntil, *updatedUser.LockoutUntil, time.Second)
	assert.True(t, updatedUser.UpdatedAt.After(user.CreatedAt), "UpdatedAt should have been updated")

	// Test clearing the fields
	clearedStatusReason := "" // Empty string to clear, or specific logic if repo handles nil to clear
	err = userRepo.UpdateUserStatusFields(ctx, user.ID, models.UserStatusActive, &clearedStatusReason, nil) // nil for lockoutUntil
	require.NoError(t, err)

	clearedUser, err := userRepo.FindByID(ctx, user.ID)
	require.NoError(t, err)
	require.NotNil(t, clearedUser)
	assert.Equal(t, models.UserStatusActive, clearedUser.Status)
	// Note: StatusReason might be an empty string or NULL in DB. The model uses *string.
	// If it's set to empty string, it won't be nil. If repo sets to NULL for empty string, it would be nil.
	// Assuming it's set to the value provided:
	require.NotNil(t, clearedUser.StatusReason, "StatusReason should be set to empty string, not nil pointer")
	assert.Equal(t, "", *clearedUser.StatusReason)
	assert.Nil(t, clearedUser.LockoutUntil, "LockoutUntil should be cleared (nil)")


	_, delErr := testDB.Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	require.NoError(t, delErr)
}
