// File: backend/services/auth-service/tests/internal/domain/repository/postgres/mfa_secret_postgres_repository_test.go
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

	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/repository/postgres"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

// DSN and migrations path constants (ensure these are consistent)
// const (
// 	testPostgresDSNEnv = "TEST_AUTH_POSTGRES_DSN"
// 	defaultTestDSN     = "postgres://testuser:testpassword@localhost:5433/auth_test_db?sslmode=disable"
// 	defaultMigrationsPath = "file://../../../../../migrations"
// )

type MFASecretRepositoryTestSuite struct {
	suite.Suite
	pool       *pgxpool.Pool
	userRepo   *postgres.UserRepositoryPostgres // For creating prerequisite users
	repo       *postgres.MFASecretRepositoryPostgres
	migrations *migrate.Migrate
	dsn        string
	testUser   *models.User // A common user for most tests
}

func TestMFASecretRepositoryTestSuite(t *testing.T) {
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
	t.Log("Migrations applied successfully for MFA secret tests")

	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("Failed to connect to test database using DSN '%s': %v", dsn, err)
	}

	testSuite := &MFASecretRepositoryTestSuite{
		Suite:      suite.Suite{},
		pool:       pool,
		migrations: m,
		dsn:        dsn,
	}
	suite.Run(t, testSuite)
}

func (s *MFASecretRepositoryTestSuite) SetupSuite() {
	s.userRepo = postgres.NewUserRepositoryPostgres(s.pool)
}

func (s *MFASecretRepositoryTestSuite) TearDownSuite() {
	if s.pool != nil {
		s.pool.Close()
	}
	if s.migrations != nil {
		s.T().Log("Rolling back migrations for MFA secret tests...")
		if err := s.migrations.Down(); err != nil && err != migrate.ErrNoChange {
			s.T().Logf("Warning: failed to rollback migrations in TearDownSuite: %v", err)
		} else {
			s.T().Log("Migrations for MFA secret tests rolled back successfully.")
		}
	}
}

func (s *MFASecretRepositoryTestSuite) SetupTest() {
	s.repo = postgres.NewMFASecretRepositoryPostgres(s.pool)
	ctx := context.Background()
	_, err := s.pool.Exec(ctx, `TRUNCATE TABLE mfa_secrets CASCADE; TRUNCATE TABLE users CASCADE;`)
	require.NoError(s.T(), err, "Failed to clean tables before test")

	s.testUser = &models.User{
		ID: uuid.New(), Username: "mfa_test_user", Email: "mfa@example.com", PasswordHash: "hash", Status: models.UserStatusActive,
	}
	err = s.userRepo.Create(ctx, s.testUser)
	require.NoError(s.T(), err)
}

// Helper to create an MFA Secret
func (s *MFASecretRepositoryTestSuite) helperCreateMFASecret(userID uuid.UUID, mfaType models.MFAType, secret string, verified bool) *models.MFASecret {
	ctx := context.Background()
	mfaSecret := &models.MFASecret{
		ID:                 uuid.New(),
		UserID:             userID,
		Type:               mfaType,
		SecretKeyEncrypted: secret,
		Verified:           verified,
	}
	err := s.repo.Create(ctx, mfaSecret)
	require.NoError(s.T(), err)
	return mfaSecret
}

func (s *MFASecretRepositoryTestSuite) TestCreateMFASecret_Success() {
	ctx := context.Background()
	secretID := uuid.New()
	mfaSecret := &models.MFASecret{
		ID:                 secretID,
		UserID:             s.testUser.ID,
		Type:               models.MFATypeTOTP,
		SecretKeyEncrypted: "encrypted_secret_totp",
		Verified:           false,
	}
	err := s.repo.Create(ctx, mfaSecret)
	require.NoError(s.T(), err)

	fetched, errFetch := s.repo.FindByID(ctx, secretID)
	require.NoError(s.T(), errFetch)
	require.NotNil(s.T(), fetched)
	assert.Equal(s.T(), mfaSecret.UserID, fetched.UserID)
	assert.Equal(s.T(), mfaSecret.Type, fetched.Type)
	assert.Equal(s.T(), mfaSecret.SecretKeyEncrypted, fetched.SecretKeyEncrypted)
	assert.False(s.T(), fetched.Verified)
}

func (s *MFASecretRepositoryTestSuite) TestCreateMFASecret_DuplicateUserAndType() {
	ctx := context.Background()
	s.helperCreateMFASecret(s.testUser.ID, models.MFATypeTOTP, "secret1", false)

	mfaSecret2 := &models.MFASecret{
		ID: uuid.New(), UserID: s.testUser.ID, Type: models.MFATypeTOTP, SecretKeyEncrypted: "secret2", Verified: false,
	}
	err := s.repo.Create(ctx, mfaSecret2)
	require.Error(s.T(), err) // unique constraint (user_id, type)
	assert.ErrorIs(s.T(), err, domainErrors.ErrDuplicateValue)
}

func (s *MFASecretRepositoryTestSuite) TestFindByID_SuccessAndNotFound() {
	ctx := context.Background()
	mfaSecret := s.helperCreateMFASecret(s.testUser.ID, models.MFATypeTOTP, "s1", true)

	fetched, err := s.repo.FindByID(ctx, mfaSecret.ID)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), fetched)
	assert.Equal(s.T(), mfaSecret.SecretKeyEncrypted, fetched.SecretKeyEncrypted)

	_, err = s.repo.FindByID(ctx, uuid.New())
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrNotFound)
}

func (s *MFASecretRepositoryTestSuite) TestFindByUserIDAndType_SuccessAndNotFound() {
	ctx := context.Background()
	s.helperCreateMFASecret(s.testUser.ID, models.MFATypeTOTP, "s_totp", true)
	s.helperCreateMFASecret(s.testUser.ID, models.MFATypeBackup, "s_backup", false) // Example if backup secrets were stored here

	// Success
	fetchedTOTP, err := s.repo.FindByUserIDAndType(ctx, s.testUser.ID, models.MFATypeTOTP)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), fetchedTOTP)
	assert.Equal(s.T(), "s_totp", fetchedTOTP.SecretKeyEncrypted)

	// Not found for type
	_, err = s.repo.FindByUserIDAndType(ctx, s.testUser.ID, "non_existent_type")
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrNotFound)

	// Not found for user
	_, err = s.repo.FindByUserIDAndType(ctx, uuid.New(), models.MFATypeTOTP)
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrNotFound)
}

func (s *MFASecretRepositoryTestSuite) TestUpdateMFASecret_Success() {
	ctx := context.Background()
	mfaSecret := s.helperCreateMFASecret(s.testUser.ID, models.MFATypeTOTP, "initial_secret", false)

	mfaSecret.SecretKeyEncrypted = "updated_secret"
	mfaSecret.Verified = true
	now := time.Now().UTC().Truncate(time.Millisecond)
	mfaSecret.UpdatedAt = &now

	err := s.repo.Update(ctx, mfaSecret)
	require.NoError(s.T(), err)

	fetched, _ := s.repo.FindByID(ctx, mfaSecret.ID)
	require.NotNil(s.T(), fetched)
	assert.Equal(s.T(), "updated_secret", fetched.SecretKeyEncrypted)
	assert.True(s.T(), fetched.Verified)
	assert.WithinDuration(s.T(), now, *fetched.UpdatedAt, time.Second)
}

func (s *MFASecretRepositoryTestSuite) TestDeleteByUserIDAndType_Success() {
	ctx := context.Background()
	mfaSecret := s.helperCreateMFASecret(s.testUser.ID, models.MFATypeTOTP, "delete_me", false)

	deleted, err := s.repo.DeleteByUserIDAndType(ctx, s.testUser.ID, models.MFATypeTOTP)
	require.NoError(s.T(), err)
	assert.True(s.T(), deleted)

	_, err = s.repo.FindByID(ctx, mfaSecret.ID)
	assert.ErrorIs(s.T(), err, domainErrors.ErrNotFound)

	// Not found for deletion
	deleted, err = s.repo.DeleteByUserIDAndType(ctx, s.testUser.ID, "other_type")
	require.NoError(s.T(), err) // Should not error if not found
	assert.False(s.T(), deleted)
}

func (s *MFASecretRepositoryTestSuite) TestDeleteAllForUser_Success() {
	ctx := context.Background()
	s.helperCreateMFASecret(s.testUser.ID, models.MFATypeTOTP, "s1_del_all", false)
	s.helperCreateMFASecret(s.testUser.ID, models.MFATypeBackup, "s2_del_all", true) // Another type for same user

	otherUser := s.helperCreateUser("other_mfa")
	s.helperCreateMFASecret(otherUser.ID, models.MFATypeTOTP, "s_other_user", false)

	deletedCount, err := s.repo.DeleteAllForUser(ctx, s.testUser.ID)
	require.NoError(s.T(), err)
	assert.EqualValues(s.T(), 2, deletedCount)

	_, err = s.repo.FindByUserIDAndType(ctx, s.testUser.ID, models.MFATypeTOTP)
	assert.ErrorIs(s.T(), err, domainErrors.ErrNotFound)
	_, err = s.repo.FindByUserIDAndType(ctx, s.testUser.ID, models.MFATypeBackup)
	assert.ErrorIs(s.T(), err, domainErrors.ErrNotFound)

	// Ensure other user's secret is untouched
	fetchedOther, err := s.repo.FindByUserIDAndType(ctx, otherUser.ID, models.MFATypeTOTP)
	require.NoError(s.T(), err)
	assert.NotNil(s.T(), fetchedOther)

	// User with no secrets
	userNoSecrets := s.helperCreateUser("no_secrets_mfa")
	deletedCount, err = s.repo.DeleteAllForUser(ctx, userNoSecrets.ID)
	require.NoError(s.T(), err)
	assert.EqualValues(s.T(), 0, deletedCount)
}

func (s *MFASecretRepositoryTestSuite) TestDeleteByUserIDAndTypeIfUnverified_Scenarios() {
	ctx := context.Background()

	// Unverified secret
	unverifiedSecret := s.helperCreateMFASecret(s.testUser.ID, models.MFATypeTOTP, "unverified_s", false)
	// Verified secret
	verifiedSecret := s.helperCreateMFASecret(s.testUser.ID, models.MFATypeBackup, "verified_s", true)

	// Delete unverified: Success
	deleted, err := s.repo.DeleteByUserIDAndTypeIfUnverified(ctx, s.testUser.ID, models.MFATypeTOTP)
	require.NoError(s.T(), err)
	assert.True(s.T(), deleted)
	_, err = s.repo.FindByID(ctx, unverifiedSecret.ID)
	assert.ErrorIs(s.T(), err, domainErrors.ErrNotFound)

	// Attempt on verified: Not deleted
	deleted, err = s.repo.DeleteByUserIDAndTypeIfUnverified(ctx, s.testUser.ID, models.MFATypeBackup)
	require.NoError(s.T(), err)
	assert.False(s.T(), deleted)
	_, err = s.repo.FindByID(ctx, verifiedSecret.ID) // Should still exist
	assert.NoError(s.T(), err)

	// Secret not found
	deleted, err = s.repo.DeleteByUserIDAndTypeIfUnverified(ctx, uuid.New(), "some_other_type")
	require.NoError(s.T(), err)
	assert.False(s.T(), deleted)
}
