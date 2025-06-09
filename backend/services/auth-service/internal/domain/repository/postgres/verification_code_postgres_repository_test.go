// File: backend/services/auth-service/internal/domain/repository/postgres/verification_code_repository_test.go
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

	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/repository/postgres"
	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/infrastructure/security" // For hashing codes

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

type VerificationCodeRepositoryTestSuite struct {
	suite.Suite
	pool       *pgxpool.Pool
	userRepo   *postgres.UserRepositoryPostgres // For creating prerequisite users
	repo       *postgres.VerificationCodeRepositoryPostgres
	migrations *migrate.Migrate
	dsn        string
	testUser   *models.User // A common user for most tests
}

func TestVerificationCodeRepositoryTestSuite(t *testing.T) {
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
	t.Log("Migrations applied successfully for verification code tests")

	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("Failed to connect to test database using DSN '%s': %v", dsn, err)
	}

	testSuite := &VerificationCodeRepositoryTestSuite{
		Suite:      suite.Suite{},
		pool:       pool,
		migrations: m,
		dsn:        dsn,
	}
	suite.Run(t, testSuite)
}

func (s *VerificationCodeRepositoryTestSuite) SetupSuite() {
	s.userRepo = postgres.NewUserRepositoryPostgres(s.pool)
}

func (s *VerificationCodeRepositoryTestSuite) TearDownSuite() {
	if s.pool != nil {
		s.pool.Close()
	}
	if s.migrations != nil {
		s.T().Log("Rolling back migrations for verification code tests...")
		if err := s.migrations.Down(); err != nil && err != migrate.ErrNoChange {
			s.T().Logf("Warning: failed to rollback migrations in TearDownSuite: %v", err)
		} else {
			s.T().Log("Migrations for verification code tests rolled back successfully.")
		}
	}
}

func (s *VerificationCodeRepositoryTestSuite) SetupTest() {
	s.repo = postgres.NewVerificationCodeRepositoryPostgres(s.pool)
	ctx := context.Background()
	_, err := s.pool.Exec(ctx, `TRUNCATE TABLE verification_codes CASCADE; TRUNCATE TABLE users CASCADE;`)
	require.NoError(s.T(), err, "Failed to clean tables before test")

	s.testUser = &models.User{
		ID: uuid.New(), Username: "verify_code_user", Email: "verify_code@example.com", PasswordHash: "hash", Status: models.UserStatusActive,
	}
	err = s.userRepo.Create(ctx, s.testUser)
	require.NoError(s.T(), err)
}

// Helper to create a verification code
func (s *VerificationCodeRepositoryTestSuite) helperCreateVerificationCode(userID uuid.UUID, codeType models.VerificationCodeType, plainCode string, expiresAt time.Time, usedAt *time.Time) *models.VerificationCode {
	ctx := context.Background()
	hashedCode := security.HashToken(plainCode) // Use same hashing as in service layer

	vc := &models.VerificationCode{
		ID:        uuid.New(),
		UserID:    userID,
		Type:      codeType,
		CodeHash:  hashedCode,
		ExpiresAt: expiresAt,
		UsedAt:    usedAt,
	}
	err := s.repo.Create(ctx, vc)
	require.NoError(s.T(), err)
	return vc
}

func (s *VerificationCodeRepositoryTestSuite) TestCreateVerificationCode_Success() {
	ctx := context.Background()
	codeID := uuid.New()
	plainCode := "123456"
	hashedCode := security.HashToken(plainCode)
	expiresAt := time.Now().Add(time.Hour).UTC().Truncate(time.Millisecond)

	vc := &models.VerificationCode{
		ID:        codeID,
		UserID:    s.testUser.ID,
		Type:      models.VerificationCodeTypeEmailVerification,
		CodeHash:  hashedCode,
		ExpiresAt: expiresAt,
	}
	err := s.repo.Create(ctx, vc)
	require.NoError(s.T(), err)

	fetched, errFetch := s.repo.FindByID(ctx, codeID) // Assuming FindByID exists
	require.NoError(s.T(), errFetch)
	require.NotNil(s.T(), fetched)
	assert.Equal(s.T(), s.testUser.ID, fetched.UserID)
	assert.Equal(s.T(), models.VerificationCodeTypeEmailVerification, fetched.Type)
	assert.Equal(s.T(), hashedCode, fetched.CodeHash)
	assert.WithinDuration(s.T(), expiresAt, fetched.ExpiresAt, time.Second)
	assert.Nil(s.T(), fetched.UsedAt)
}

func (s *VerificationCodeRepositoryTestSuite) TestFindByUserIDAndType_SuccessAndNotFound() {
	ctx := context.Background()
	plainCode := "findme_type"
	expiresAt := time.Now().Add(time.Hour)
	s.helperCreateVerificationCode(s.testUser.ID, models.VerificationCodeTypeEmailVerification, plainCode, expiresAt, nil)

	// Create an older one to ensure latest is fetched
	s.helperCreateVerificationCode(s.testUser.ID, models.VerificationCodeTypeEmailVerification, "old_"+plainCode, expiresAt.Add(-time.Minute), nil)


	fetched, err := s.repo.FindByUserIDAndType(ctx, s.testUser.ID, models.VerificationCodeTypeEmailVerification)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), fetched)
	assert.Equal(s.T(), security.HashToken(plainCode), fetched.CodeHash) // Should be the latest one created by helper
	assert.Nil(s.T(), fetched.UsedAt)
	assert.True(s.T(), fetched.ExpiresAt.After(time.Now()))

	// Not found for type
	_, err = s.repo.FindByUserIDAndType(ctx, s.testUser.ID, models.VerificationCodeTypePasswordReset)
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrNotFound)

	// Not found for user
	_, err = s.repo.FindByUserIDAndType(ctx, uuid.New(), models.VerificationCodeTypeEmailVerification)
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrNotFound)
}

func (s *VerificationCodeRepositoryTestSuite) TestFindByCodeHashAndType_Scenarios() {
	ctx := context.Background()
	plainActive := "active_code"
	activeHash := security.HashToken(plainActive)
	activeExpires := time.Now().Add(time.Hour)
	s.helperCreateVerificationCode(s.testUser.ID, models.VerificationCodeTypePasswordReset, plainActive, activeExpires, nil)

	plainExpired := "expired_code"
	expiredHash := security.HashToken(plainExpired)
	s.helperCreateVerificationCode(s.testUser.ID, models.VerificationCodeTypePasswordReset, plainExpired, time.Now().Add(-time.Hour), nil)

	plainUsed := "used_code"
	usedHash := security.HashToken(plainUsed)
	usedTime := time.Now().Add(-time.Minute)
	s.helperCreateVerificationCode(s.testUser.ID, models.VerificationCodeTypePasswordReset, plainUsed, time.Now().Add(time.Hour), &usedTime)

	// Success (active, unused)
	fetched, err := s.repo.FindByCodeHashAndType(ctx, activeHash, models.VerificationCodeTypePasswordReset)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), fetched)
	assert.Nil(s.T(), fetched.UsedAt)

	// Code not found (wrong hash)
	_, err = s.repo.FindByCodeHashAndType(ctx, security.HashToken("wrong_hash"), models.VerificationCodeTypePasswordReset)
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrNotFound)

	// Code expired
	_, err = s.repo.FindByCodeHashAndType(ctx, expiredHash, models.VerificationCodeTypePasswordReset)
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrVerificationCodeExpired)

	// Code already used
	_, err = s.repo.FindByCodeHashAndType(ctx, usedHash, models.VerificationCodeTypePasswordReset)
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrVerificationCodeUsed)
}

func (s *VerificationCodeRepositoryTestSuite) TestFindByID_SuccessAndNotFound() {
	ctx := context.Background()
	vc := s.helperCreateVerificationCode(s.testUser.ID, models.VerificationCodeTypeEmailVerification, "findbyidcode", time.Now().Add(time.Hour), nil)

	fetched, err := s.repo.FindByID(ctx, vc.ID)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), fetched)
	assert.Equal(s.T(), vc.CodeHash, fetched.CodeHash)

	_, err = s.repo.FindByID(ctx, uuid.New())
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrNotFound)
}

func (s *VerificationCodeRepositoryTestSuite) TestMarkAsUsed_Scenarios() {
	ctx := context.Background()
	activeCode := s.helperCreateVerificationCode(s.testUser.ID, models.VerificationCodeTypeEmailVerification, "markme_active", time.Now().Add(time.Hour), nil)

	now := time.Now().UTC().Truncate(time.Millisecond)
	err := s.repo.MarkAsUsed(ctx, activeCode.ID, now)
	require.NoError(s.T(), err)
	fetched, _ := s.repo.FindByID(ctx, activeCode.ID)
	require.NotNil(s.T(), fetched.UsedAt)
	assert.WithinDuration(s.T(), now, *fetched.UsedAt, time.Second)

	// Already used
	err = s.repo.MarkAsUsed(ctx, activeCode.ID, time.Now().Add(time.Minute).UTC().Truncate(time.Millisecond))
	require.Error(s.T(), err) // Should fail as it's already used (or update timestamp, depends on desired behavior)
	assert.ErrorIs(s.T(), err, domainErrors.ErrVerificationCodeUsed) // Assuming this specific error

	// Code not found
	err = s.repo.MarkAsUsed(ctx, uuid.New(), time.Now())
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrNotFound)

	// Expired code (should fail to mark as used if already expired - repo might check this or rely on FindByCodeHashAndType)
	expiredCode := s.helperCreateVerificationCode(s.testUser.ID, models.VerificationCodeTypeEmailVerification, "markme_expired", time.Now().Add(-time.Hour), nil)
	err = s.repo.MarkAsUsed(ctx, expiredCode.ID, time.Now())
	require.Error(s.T(), err) // Or depends on how strict MarkAsUsed is; it might just update UsedAt.
	                         // If FindByCodeHashAndType is always called first, this scenario might not be hit directly by service.
													 // Assuming MarkAsUsed itself might return an error if the code is expired.
	assert.ErrorIs(s.T(), err, domainErrors.ErrVerificationCodeExpired)
}

func (s *VerificationCodeRepositoryTestSuite) TestDeleteVerificationCode_SuccessAndNotFound() {
	ctx := context.Background()
	vc := s.helperCreateVerificationCode(s.testUser.ID, models.VerificationCodeTypeEmailVerification, "delete_code", time.Now().Add(time.Hour), nil)

	err := s.repo.Delete(ctx, vc.ID)
	require.NoError(s.T(), err)
	_, errFind := s.repo.FindByID(ctx, vc.ID)
	assert.ErrorIs(s.T(), errFind, domainErrors.ErrNotFound)

	err = s.repo.Delete(ctx, uuid.New())
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrNotFound)
}

func (s *VerificationCodeRepositoryTestSuite) TestDeleteByUserIDAndType_Success() {
	ctx := context.Background()
	s.helperCreateVerificationCode(s.testUser.ID, models.VerificationCodeTypeEmailVerification, "del_uid_type1", time.Now().Add(time.Hour), nil)
	s.helperCreateVerificationCode(s.testUser.ID, models.VerificationCodeTypeEmailVerification, "del_uid_type2", time.Now().Add(time.Hour), nil)
	s.helperCreateVerificationCode(s.testUser.ID, models.VerificationCodeTypePasswordReset, "del_uid_type_other", time.Now().Add(time.Hour), nil)

	otherUser := s.helperCreateUserForAuditTest("other_vc_del") // Reusing user helper
	s.helperCreateVerificationCode(otherUser.ID, models.VerificationCodeTypeEmailVerification, "other_user_vc", time.Now().Add(time.Hour), nil)


	deletedCount, err := s.repo.DeleteByUserIDAndType(ctx, s.testUser.ID, models.VerificationCodeTypeEmailVerification)
	require.NoError(s.T(), err)
	assert.EqualValues(s.T(), 2, deletedCount)

	// Verify they are gone
	_, err = s.repo.FindByUserIDAndType(ctx, s.testUser.ID, models.VerificationCodeTypeEmailVerification)
	assert.ErrorIs(s.T(), err, domainErrors.ErrNotFound)

	// Verify other type for same user still exists
	otherTypeVc, err := s.repo.FindByUserIDAndType(ctx, s.testUser.ID, models.VerificationCodeTypePasswordReset)
	require.NoError(s.T(), err)
	assert.NotNil(s.T(), otherTypeVc)

	// Verify other user's code still exists
	otherUserVc, err := s.repo.FindByUserIDAndType(ctx, otherUser.ID, models.VerificationCodeTypeEmailVerification)
	require.NoError(s.T(), err)
	assert.NotNil(s.T(), otherUserVc)


	// User with no codes of type
	deletedCount, err = s.repo.DeleteByUserIDAndType(ctx, s.testUser.ID, "non_existent_type_for_del")
	require.NoError(s.T(), err)
	assert.EqualValues(s.T(), 0, deletedCount)
}

func (s *VerificationCodeRepositoryTestSuite) TestDeleteExpiredVerificationCodes() {
	ctx := context.Background()
	s.helperCreateVerificationCode(s.testUser.ID, models.VerificationCodeTypeEmailVerification, "exp1_vc", time.Now().Add(-time.Hour), nil)
	s.helperCreateVerificationCode(s.testUser.ID, models.VerificationCodeTypePasswordReset, "exp2_vc", time.Now().Add(-time.Minute), nil)
	activeVc := s.helperCreateVerificationCode(s.testUser.ID, models.VerificationCodeTypeEmailVerification, "active_vc", time.Now().Add(time.Hour), nil)

	deletedCount, err := s.repo.DeleteExpired(ctx)
	require.NoError(s.T(), err)
	assert.EqualValues(s.T(), 2, deletedCount)

	_, err = s.repo.FindByID(ctx, activeVc.ID)
	assert.NoError(s.T(), err, "Active code should not be deleted")

	// Call again, no expired codes left
	deletedCount, err = s.repo.DeleteExpired(ctx)
	require.NoError(s.T(), err)
	assert.EqualValues(s.T(), 0, deletedCount)
}
