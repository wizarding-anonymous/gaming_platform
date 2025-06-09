// File: backend/services/auth-service/internal/domain/repository/postgres/mfa_backup_code_repository_test.go
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
	"github.com/your-org/auth-service/internal/infrastructure/security" // For hashing backup codes

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

type MFABackupCodeRepositoryTestSuite struct {
	suite.Suite
	pool       *pgxpool.Pool
	userRepo   *postgres.UserRepositoryPostgres // For creating prerequisite users
	repo       *postgres.MFABackupCodeRepositoryPostgres
	migrations *migrate.Migrate
	dsn        string
	testUser   *models.User // A common user for most tests
	// PasswordService is needed for hashing if FindByUserIDAndCodeHash takes plain code
	// For this test, we'll assume FindByUserIDAndCodeHash takes already hashed code,
	// or we hash it manually in tests using a simple utility.
	// If PasswordService is required by repository methods, it should be mocked or provided.
	// The actual MFABackupCodeRepositoryPostgres does not take PasswordService.
	// It expects code_hash to be provided.
}

func TestMFABackupCodeRepositoryTestSuite(t *testing.T) {
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
	t.Log("Migrations applied successfully for MFA backup code tests")

	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("Failed to connect to test database using DSN '%s': %v", dsn, err)
	}

	testSuite := &MFABackupCodeRepositoryTestSuite{
		Suite:      suite.Suite{},
		pool:       pool,
		migrations: m,
		dsn:        dsn,
	}
	suite.Run(t, testSuite)
}

func (s *MFABackupCodeRepositoryTestSuite) SetupSuite() {
	s.userRepo = postgres.NewUserRepositoryPostgres(s.pool)
}

func (s *MFABackupCodeRepositoryTestSuite) TearDownSuite() {
	if s.pool != nil {
		s.pool.Close()
	}
	if s.migrations != nil {
		s.T().Log("Rolling back migrations for MFA backup code tests...")
		if err := s.migrations.Down(); err != nil && err != migrate.ErrNoChange {
			s.T().Logf("Warning: failed to rollback migrations in TearDownSuite: %v", err)
		} else {
			s.T().Log("Migrations for MFA backup code tests rolled back successfully.")
		}
	}
}

func (s *MFABackupCodeRepositoryTestSuite) SetupTest() {
	s.repo = postgres.NewMFABackupCodeRepositoryPostgres(s.pool)
	ctx := context.Background()
	_, err := s.pool.Exec(ctx, `TRUNCATE TABLE mfa_backup_codes CASCADE; TRUNCATE TABLE users CASCADE;`)
	require.NoError(s.T(), err, "Failed to clean tables before test")

	s.testUser = &models.User{
		ID: uuid.New(), Username: "mfabackup_test_user", Email: "mfabackup@example.com", PasswordHash: "hash", Status: models.UserStatusActive,
	}
	err = s.userRepo.Create(ctx, s.testUser)
	require.NoError(s.T(), err)
}

// Helper to create a single backup code
func (s *MFABackupCodeRepositoryTestSuite) helperCreateBackupCode(userID uuid.UUID, plainCode string, usedAt *time.Time) *models.MFABackupCode {
	ctx := context.Background()
	hashedCode := security.HashToken(plainCode) // Using simple token hasher for test, real one might use Argon2/bcrypt

	backupCode := &models.MFABackupCode{
		ID:       uuid.New(),
		UserID:   userID,
		CodeHash: hashedCode,
		UsedAt:   usedAt,
	}
	err := s.repo.Create(ctx, backupCode)
	require.NoError(s.T(), err)
	return backupCode
}


func (s *MFABackupCodeRepositoryTestSuite) TestCreateBackupCode_Success() {
	ctx := context.Background()
	plainCode := "123456"
	hashedCode := security.HashToken(plainCode)
	backupCode := &models.MFABackupCode{
		ID:       uuid.New(),
		UserID:   s.testUser.ID,
		CodeHash: hashedCode,
	}
	err := s.repo.Create(ctx, backupCode)
	require.NoError(s.T(), err)

	// Verify by trying to fetch it (or a direct query if no GetByID)
	// Assuming FindByUserIDAndCodeHash can be used for verification if it takes hashed code
	fetched, errFetch := s.repo.FindByUserIDAndCodeHash(ctx, s.testUser.ID, hashedCode)
	require.NoError(s.T(), errFetch)
	require.NotNil(s.T(), fetched)
	assert.Equal(s.T(), backupCode.ID, fetched.ID)
}

func (s *MFABackupCodeRepositoryTestSuite) TestCreateBackupCode_DuplicateUserAndHash() {
	ctx := context.Background()
	plainCode := "abcdef"
	s.helperCreateBackupCode(s.testUser.ID, plainCode, nil)

	backupCode2 := &models.MFABackupCode{
		ID:       uuid.New(),
		UserID:   s.testUser.ID,
		CodeHash: security.HashToken(plainCode), // Same user, same hash
	}
	err := s.repo.Create(ctx, backupCode2)
	require.Error(s.T(), err) // unique constraint (user_id, code_hash)
	assert.ErrorIs(s.T(), err, domainErrors.ErrDuplicateValue)
}

func (s *MFABackupCodeRepositoryTestSuite) TestCreateMultipleBackupCodes_Success() {
	ctx := context.Background()
	codesToCreate := []*models.MFABackupCode{
		{ID: uuid.New(), UserID: s.testUser.ID, CodeHash: security.HashToken("code1")},
		{ID: uuid.New(), UserID: s.testUser.ID, CodeHash: security.HashToken("code2")},
		{ID: uuid.New(), UserID: s.testUser.ID, CodeHash: security.HashToken("code3")},
	}
	err := s.repo.CreateMultiple(ctx, codesToCreate)
	require.NoError(s.T(), err)

	count, errCount := s.repo.CountActiveByUserID(ctx, s.testUser.ID)
	require.NoError(s.T(), errCount)
	assert.EqualValues(s.T(), 3, count)
}

func (s *MFABackupCodeRepositoryTestSuite) TestCreateMultipleBackupCodes_PartialInsertOrError() {
	ctx := context.Background()
	// Create one code that will cause a duplicate error
	s.helperCreateBackupCode(s.testUser.ID, "code_dup", nil)

	codesToCreate := []*models.MFABackupCode{
		{ID: uuid.New(), UserID: s.testUser.ID, CodeHash: security.HashToken("code_new1")},
		{ID: uuid.New(), UserID: s.testUser.ID, CodeHash: security.HashToken("code_dup")}, // Duplicate
		{ID: uuid.New(), UserID: s.testUser.ID, CodeHash: security.HashToken("code_new2")},
	}
	// pgx.CopyFrom is transactional. If one row fails, none are inserted.
	err := s.repo.CreateMultiple(ctx, codesToCreate)
	require.Error(s.T(), err)
	// Depending on DB error, could be ErrDuplicateValue or a more generic pgx error.
	// For now, just assert an error occurred.

	count, _ := s.repo.CountActiveByUserID(ctx, s.testUser.ID)
	assert.EqualValues(s.T(), 1, count, "Only the initially created code should exist") // "code_dup" from helper
}


func (s *MFABackupCodeRepositoryTestSuite) TestFindByUserIDAndCodeHash_Scenarios() {
	ctx := context.Background()
	plainActive := "active123"
	plainUsed := "used456"
	usedTime := time.Now().Add(-time.Minute).UTC().Truncate(time.Millisecond)

	s.helperCreateBackupCode(s.testUser.ID, plainActive, nil)
	s.helperCreateBackupCode(s.testUser.ID, plainUsed, &usedTime)

	// Success (unused code)
	fetched, err := s.repo.FindByUserIDAndCodeHash(ctx, s.testUser.ID, security.HashToken(plainActive))
	require.NoError(s.T(), err)
	require.NotNil(s.T(), fetched)
	assert.Nil(s.T(), fetched.UsedAt)

	// Code already used
	_, err = s.repo.FindByUserIDAndCodeHash(ctx, s.testUser.ID, security.HashToken(plainUsed))
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrBackupCodeAlreadyUsed)

	// Code not found
	_, err = s.repo.FindByUserIDAndCodeHash(ctx, s.testUser.ID, security.HashToken("nonexistent_code"))
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrBackupCodeNotFound)
}

func (s *MFABackupCodeRepositoryTestSuite) TestMarkAsUsed_Scenarios() {
	ctx := context.Background()
	activeCode := s.helperCreateBackupCode(s.testUser.ID, "markme_active", nil)
	usedCode := s.helperCreateBackupCode(s.testUser.ID, "markme_used", PtrToTime(time.Now()))

	// Success
	err := s.repo.MarkAsUsed(ctx, activeCode.ID, time.Now().UTC().Truncate(time.Millisecond))
	require.NoError(s.T(), err)
	// Verify (direct query or enhance repo to get any code by ID)
	var usedAtActual *time.Time
	query := "SELECT used_at FROM mfa_backup_codes WHERE id = $1"
	s.pool.QueryRow(ctx, query, activeCode.ID).Scan(&usedAtActual)
	require.NotNil(s.T(), usedAtActual)

	// Code already used (MarkAsUsed updates UsedAt, so no specific error for "already used" from this method)
	err = s.repo.MarkAsUsed(ctx, usedCode.ID, time.Now().UTC().Truncate(time.Millisecond))
	require.NoError(s.T(), err) // It will just update the UsedAt timestamp again

	// Code not found
	err = s.repo.MarkAsUsed(ctx, uuid.New(), time.Now().UTC().Truncate(time.Millisecond))
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrBackupCodeNotFound)
}


func (s *MFABackupCodeRepositoryTestSuite) TestDeleteByUserID_Success() {
	ctx := context.Background()
	s.helperCreateBackupCode(s.testUser.ID, "del_bc1", nil)
	s.helperCreateBackupCode(s.testUser.ID, "del_bc2", nil)
	otherUser := s.helperCreateUserForAuditTest("other_mfa_backup") // Reusing user helper
	otherCode := s.helperCreateBackupCode(otherUser.ID, "other_user_bc", nil)


	deletedCount, err := s.repo.DeleteByUserID(ctx, s.testUser.ID)
	require.NoError(s.T(), err)
	assert.EqualValues(s.T(), 2, deletedCount)

	count, _ := s.repo.CountActiveByUserID(ctx, s.testUser.ID)
	assert.EqualValues(s.T(), 0, count)

	// Ensure other user's code is untouched
	_, err = s.repo.FindByUserIDAndCodeHash(ctx, otherUser.ID, otherCode.CodeHash)
	assert.NoError(s.T(), err, "Other user's backup code should still exist")

	// User with no codes
	userNoCodes := s.helperCreateUserForAuditTest("no_codes_backup")
	deletedCount, err = s.repo.DeleteByUserID(ctx, userNoCodes.ID)
	require.NoError(s.T(), err)
	assert.EqualValues(s.T(), 0, deletedCount)
}

func (s *MFABackupCodeRepositoryTestSuite) TestCountActiveByUserID() {
	ctx := context.Background()

	// User with active codes
	s.helperCreateBackupCode(s.testUser.ID, "active_c1", nil)
	s.helperCreateBackupCode(s.testUser.ID, "active_c2", nil)
	s.helperCreateBackupCode(s.testUser.ID, "used_c1", PtrToTime(time.Now()))

	count, err := s.repo.CountActiveByUserID(ctx, s.testUser.ID)
	require.NoError(s.T(), err)
	assert.EqualValues(s.T(), 2, count)

	// User with no codes
	userNoCodes := s.helperCreateUserForAuditTest("count_no_codes")
	count, err = s.repo.CountActiveByUserID(ctx, userNoCodes.ID)
	require.NoError(s.T(), err)
	assert.EqualValues(s.T(), 0, count)

	// User with all codes used
	userAllUsed := s.helperCreateUserForAuditTest("count_all_used")
	s.helperCreateBackupCode(userAllUsed.ID, "allused_c1", PtrToTime(time.Now()))
	s.helperCreateBackupCode(userAllUsed.ID, "allused_c2", PtrToTime(time.Now()))
	count, err = s.repo.CountActiveByUserID(ctx, userAllUsed.ID)
	require.NoError(s.T(), err)
	assert.EqualValues(s.T(), 0, count)
}

// TestFindByUserID (if it exists in the repository)
// func (s *MFABackupCodeRepositoryTestSuite) TestFindByUserID() {
// 	ctx := context.Background()
// 	bc1 := s.helperCreateBackupCode(s.testUser.ID, "find_uid1", nil)
// 	bc2 := s.helperCreateBackupCode(s.testUser.ID, "find_uid2", PtrToTime(time.Now())) // one used
// 	s.helperCreateBackupCode(s.helperCreateUserForAuditTest("other_find_uid").ID, "other_uid1", nil)

// 	codes, err := s.repo.FindByUserID(ctx, s.testUser.ID)
// 	require.NoError(s.T(), err)
// 	assert.Len(s.T(), codes, 2)
//
// 	var foundBc1, foundBc2 bool
// 	for _, c := range codes {
// 		if c.ID == bc1.ID { foundBc1 = true }
// 		if c.ID == bc2.ID { foundBc2 = true }
// 	}
// 	assert.True(s.T(), foundBc1, "Expected to find bc1")
// 	assert.True(s.T(), foundBc2, "Expected to find bc2")
// }

// Note: The method MarkAsUsedByCodeHash is not in the provided MFABackupCodeRepository interface
// in mfa_logic_service_test.go. If it was added to the actual repository, tests would be needed.
// For now, assuming it's not part of the current interface to be tested.
// If it is:
// func (s *MFABackupCodeRepositoryTestSuite) TestMarkAsUsedByCodeHash_Success() { ... }
