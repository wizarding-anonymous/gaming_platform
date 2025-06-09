// File: backend/services/auth-service/internal/domain/repository/postgres/external_account_repository_test.go
package postgres_test

import (
	"context"
	"encoding/json"
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

type ExternalAccountRepositoryTestSuite struct {
	suite.Suite
	pool       *pgxpool.Pool
	userRepo   *postgres.UserRepositoryPostgres // For creating prerequisite users
	repo       *postgres.ExternalAccountRepositoryPostgres
	migrations *migrate.Migrate
	dsn        string
	testUser   *models.User // A common user for most tests
}

func TestExternalAccountRepositoryTestSuite(t *testing.T) {
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
	t.Log("Migrations applied successfully for external account tests")

	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("Failed to connect to test database using DSN '%s': %v", dsn, err)
	}

	testSuite := &ExternalAccountRepositoryTestSuite{
		Suite:      suite.Suite{},
		pool:       pool,
		migrations: m,
		dsn:        dsn,
	}
	suite.Run(t, testSuite)
}

func (s *ExternalAccountRepositoryTestSuite) SetupSuite() {
	s.userRepo = postgres.NewUserRepositoryPostgres(s.pool)
}

func (s *ExternalAccountRepositoryTestSuite) TearDownSuite() {
	if s.pool != nil {
		s.pool.Close()
	}
	if s.migrations != nil {
		s.T().Log("Rolling back migrations for external account tests...")
		if err := s.migrations.Down(); err != nil && err != migrate.ErrNoChange {
			s.T().Logf("Warning: failed to rollback migrations in TearDownSuite: %v", err)
		} else {
			s.T().Log("Migrations for external account tests rolled back successfully.")
		}
	}
}

func (s *ExternalAccountRepositoryTestSuite) SetupTest() {
	s.repo = postgres.NewExternalAccountRepositoryPostgres(s.pool)
	ctx := context.Background()
	_, err := s.pool.Exec(ctx, `TRUNCATE TABLE external_accounts CASCADE; TRUNCATE TABLE users CASCADE;`)
	require.NoError(s.T(), err, "Failed to clean tables before test")

	s.testUser = &models.User{
		ID: uuid.New(), Username: "ext_acc_test_user", Email: "ext_acc@example.com", PasswordHash: "hash", Status: models.UserStatusActive,
	}
	err = s.userRepo.Create(ctx, s.testUser)
	require.NoError(s.T(), err)
}

// Helper to create an external account
func (s *ExternalAccountRepositoryTestSuite) helperCreateExternalAccount(userID uuid.UUID, provider, externalUserID, accessTokenHash, refreshTokenHash string, profileData map[string]interface{}, expiresAt *time.Time) *models.ExternalAccount {
	ctx := context.Background()
	var profileDataJSON json.RawMessage
	if profileData != nil {
		var errMarshal error
		profileDataJSON, errMarshal = json.Marshal(profileData)
		require.NoError(s.T(), errMarshal)
	}

	extAccount := &models.ExternalAccount{
		ID:               uuid.New(),
		UserID:           userID,
		Provider:         provider,
		ExternalUserID:   externalUserID,
		AccessTokenHash:  &accessTokenHash,
		RefreshTokenHash: &refreshTokenHash,
		TokenExpiresAt:   expiresAt,
		ProfileData:      profileDataJSON,
	}
	if accessTokenHash == "" { extAccount.AccessTokenHash = nil }
	if refreshTokenHash == "" { extAccount.RefreshTokenHash = nil }


	err := s.repo.Create(ctx, extAccount)
	require.NoError(s.T(), err)
	return extAccount
}


func (s *ExternalAccountRepositoryTestSuite) TestCreateExternalAccount_Success() {
	ctx := context.Background()
	provider := "google"
	externalID := "google_user_123"
	profile := map[string]interface{}{"name": "Google User", "email": "google@example.com"}
	expires := time.Now().Add(time.Hour).UTC().Truncate(time.Millisecond)

	extAccount := &models.ExternalAccount{
		ID:               uuid.New(),
		UserID:           s.testUser.ID,
		Provider:         provider,
		ExternalUserID:   externalID,
		AccessTokenHash:  PtrToString("google_access_token_hash"),
		RefreshTokenHash: PtrToString("google_refresh_token_hash"),
		TokenExpiresAt:   &expires,
		ProfileData:      json.RawMessage(`{"name": "Google User", "email": "google@example.com"}`),
	}

	err := s.repo.Create(ctx, extAccount)
	require.NoError(s.T(), err)

	fetched, errFetch := s.repo.FindByID(ctx, extAccount.ID)
	require.NoError(s.T(), errFetch)
	require.NotNil(s.T(), fetched)
	assert.Equal(s.T(), provider, fetched.Provider)
	assert.Equal(s.T(), externalID, fetched.ExternalUserID)
	require.NotNil(s.T(), fetched.AccessTokenHash)
	assert.Equal(s.T(), "google_access_token_hash", *fetched.AccessTokenHash)
	var fetchedProfile map[string]interface{}
	json.Unmarshal(fetched.ProfileData, &fetchedProfile)
	assert.Equal(s.T(), profile["name"], fetchedProfile["name"])
}

func (s *ExternalAccountRepositoryTestSuite) TestCreateExternalAccount_DuplicateProviderExternalID() {
	ctx := context.Background()
	provider := "facebook"
	externalID := "fb_user_456"
	s.helperCreateExternalAccount(s.testUser.ID, provider, externalID, "token1", "", nil, nil)

	extAccount2 := &models.ExternalAccount{
		ID: uuid.New(), UserID: s.testUser.ID, Provider: provider, ExternalUserID: externalID,
	}
	err := s.repo.Create(ctx, extAccount2)
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrDuplicateValue) // unique constraint (provider, external_user_id)
}

func (s *ExternalAccountRepositoryTestSuite) TestFindByID_SuccessAndNotFound() {
	ctx := context.Background()
	extAccount := s.helperCreateExternalAccount(s.testUser.ID, "twitter", "twitter_789", "twt_token", "", nil, nil)

	fetched, err := s.repo.FindByID(ctx, extAccount.ID)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), fetched)
	assert.Equal(s.T(), "twitter", fetched.Provider)

	_, err = s.repo.FindByID(ctx, uuid.New())
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrNotFound)
}

func (s *ExternalAccountRepositoryTestSuite) TestFindByProviderAndExternalID_SuccessAndNotFound() {
	ctx := context.Background()
	provider := "github"
	externalID := "gh_user_001"
	s.helperCreateExternalAccount(s.testUser.ID, provider, externalID, "gh_token", "", nil, nil)

	fetched, err := s.repo.FindByProviderAndExternalID(ctx, provider, externalID)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), fetched)
	assert.Equal(s.T(), s.testUser.ID, fetched.UserID)

	_, err = s.repo.FindByProviderAndExternalID(ctx, provider, "non_existent_ext_id")
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrNotFound)

	_, err = s.repo.FindByProviderAndExternalID(ctx, "unknown_provider", externalID)
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrNotFound)
}

func (s *ExternalAccountRepositoryTestSuite) TestFindByUserID_VariousScenarios() {
	ctx := context.Background()
	user2 := s.helperCreateUser("ext_acc_user2")

	s.helperCreateExternalAccount(s.testUser.ID, "google", "g_1", "", "", nil, nil)
	s.helperCreateExternalAccount(s.testUser.ID, "facebook", "fb_1", "", "", nil, nil)
	s.helperCreateExternalAccount(user2.ID, "google", "g_2", "", "", nil, nil)

	// User with multiple accounts
	accountsUser1, err := s.repo.FindByUserID(ctx, s.testUser.ID)
	require.NoError(s.T(), err)
	assert.Len(s.T(), accountsUser1, 2)

	// User with one account
	accountsUser2, err := s.repo.FindByUserID(ctx, user2.ID)
	require.NoError(s.T(), err)
	assert.Len(s.T(), accountsUser2, 1)
	assert.Equal(s.T(), "google", accountsUser2[0].Provider)

	// User with no accounts
	userNoAccounts := s.helperCreateUser("ext_acc_no_accounts")
	accountsNone, err := s.repo.FindByUserID(ctx, userNoAccounts.ID)
	require.NoError(s.T(), err)
	assert.Empty(s.T(), accountsNone)
}

func (s *ExternalAccountRepositoryTestSuite) TestFindByUserIDAndProvider_SuccessAndNotFound() {
	ctx := context.Background()
	providerGoogle := "google"
	providerFacebook := "facebook"
	s.helperCreateExternalAccount(s.testUser.ID, providerGoogle, "g_uid_prov", "", "", nil, nil)

	// Success
	fetched, err := s.repo.FindByUserIDAndProvider(ctx, s.testUser.ID, providerGoogle)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), fetched)
	assert.Equal(s.T(), "g_uid_prov", fetched.ExternalUserID)

	// Not found for provider
	_, err = s.repo.FindByUserIDAndProvider(ctx, s.testUser.ID, providerFacebook)
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrNotFound)

	// Not found for user
	_, err = s.repo.FindByUserIDAndProvider(ctx, uuid.New(), providerGoogle)
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrNotFound)
}

func (s *ExternalAccountRepositoryTestSuite) TestUpdateExternalAccount_Success() {
	ctx := context.Background()
	extAccount := s.helperCreateExternalAccount(s.testUser.ID, "linkedin", "li_123", "old_at", "old_rt", nil, nil)

	newAccessTokenHash := "new_linkedin_at_hash"
	newProfile := map[string]interface{}{"headline": "Software Engineer"}
	newProfileJSON, _ := json.Marshal(newProfile)
	newExpires := time.Now().Add(2 * time.Hour).UTC().Truncate(time.Millisecond)

	extAccount.AccessTokenHash = &newAccessTokenHash
	extAccount.ProfileData = newProfileJSON
	extAccount.TokenExpiresAt = &newExpires
	nowUpdate := time.Now().UTC().Truncate(time.Millisecond)
	extAccount.UpdatedAt = &nowUpdate


	err := s.repo.Update(ctx, extAccount)
	require.NoError(s.T(), err)

	fetched, _ := s.repo.FindByID(ctx, extAccount.ID)
	require.NotNil(s.T(), fetched)
	require.NotNil(s.T(), fetched.AccessTokenHash)
	assert.Equal(s.T(), newAccessTokenHash, *fetched.AccessTokenHash)
	assert.JSONEq(s.T(), string(newProfileJSON), string(fetched.ProfileData))
	require.NotNil(s.T(), fetched.TokenExpiresAt)
	assert.WithinDuration(s.T(), newExpires, *fetched.TokenExpiresAt, time.Second)
	require.NotNil(s.T(), fetched.UpdatedAt)
	assert.WithinDuration(s.T(), nowUpdate, *fetched.UpdatedAt, time.Second)
}

func (s *ExternalAccountRepositoryTestSuite) TestDeleteExternalAccount_SuccessAndNotFound() {
	ctx := context.Background()
	extAccount := s.helperCreateExternalAccount(s.testUser.ID, "apple", "apple_id_001", "apple_token", "", nil, nil)

	// Success
	err := s.repo.Delete(ctx, extAccount.ID)
	require.NoError(s.T(), err)
	_, errFind := s.repo.FindByID(ctx, extAccount.ID)
	assert.ErrorIs(s.T(), errFind, domainErrors.ErrNotFound)

	// Not Found
	err = s.repo.Delete(ctx, uuid.New())
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrNotFound)
}

func (s *ExternalAccountRepositoryTestSuite) TestDeleteByUserIDAndProvider_Success() {
	ctx := context.Background()
	provider := "service_del"
	s.helperCreateExternalAccount(s.testUser.ID, provider, "ext_del_1", "", "", nil, nil)
	s.helperCreateExternalAccount(s.testUser.ID, "other_provider", "ext_other_1", "", "", nil, nil)


	deletedCount, err := s.repo.DeleteByUserIDAndProvider(ctx, s.testUser.ID, provider)
	require.NoError(s.T(), err)
	assert.EqualValues(s.T(), 1, deletedCount)

	_, err = s.repo.FindByUserIDAndProvider(ctx, s.testUser.ID, provider)
	assert.ErrorIs(s.T(), err, domainErrors.ErrNotFound)

	// Ensure other provider link still exists
	otherLink, err := s.repo.FindByUserIDAndProvider(ctx, s.testUser.ID, "other_provider")
	require.NoError(s.T(), err)
	assert.NotNil(s.T(), otherLink)

	// No link for user/provider
	deletedCount, err = s.repo.DeleteByUserIDAndProvider(ctx, s.testUser.ID, "non_existent_provider_for_del")
	require.NoError(s.T(), err)
	assert.EqualValues(s.T(), 0, deletedCount)
}
