package database

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/your-org/auth-service/internal/domain/models"
	domainErrors "github.com/your-org/auth-service/internal/domain/errors"
	repoPostgres "github.com/your-org/auth-service/internal/domain/repository/postgres"
	// argon2Service and testDB are assumed to be global and initialized
)

// Helper to clear mfa_backup_codes and related tables
func clearMFABackupCodeTestTables(t *testing.T) {
	t.Helper()
	tables := []string{"mfa_backup_codes", "users"} // Order for FKs
	for _, table := range tables {
		_, err := testDB.Exec(context.Background(), fmt.Sprintf("DELETE FROM %s", table))
		require.NoError(t, err, "Failed to clear table %s", table)
	}
}

// Helper to create a user for MFA backup code tests
func createTestUserForMFABackupCodeTests(ctx context.Context, t *testing.T, suffix string) *models.User {
	userRepo := repoPostgres.NewUserRepositoryPostgres(testDB)
	hashedPassword, _ := argon2Service.HashPassword("password123") // argon2Service from user_test
	user := &models.User{
		ID:           uuid.New(),
		Username:     fmt.Sprintf("user_mfabc_%s", suffix),
		Email:        fmt.Sprintf("user_mfabc_%s@example.com", suffix),
		PasswordHash: hashedPassword,
		Status:       models.UserStatusActive,
	}
	err := userRepo.Create(ctx, user)
	require.NoError(t, err)
	return user
}

func TestMFABackupCodeRepository_CreateMultiple_And_FindByUserIDAndCodeHash(t *testing.T) {
	ctx := context.Background()
	backupRepo := repoPostgres.NewMFABackupCodeRepositoryPostgres(testDB)
	clearMFABackupCodeTestTables(t)

	user := createTestUserForMFABackupCodeTests(ctx, t, "cmfb")

	// Note: MFABackupCodeRepository.FindByUserIDAndCodeHash expects a PLAIN code,
	// and it hashes it internally using PasswordService.
	// So, for testing, we store hashed codes but search using plain codes.
	// However, the repository method `FindByUserIDAndCodeHash` was updated to take `codeHash string`
	// in a previous subtask. The service layer now does the hashing before calling the repo.
	// For this integration test, we will directly insert the hash and search by hash.
	// Let's assume PasswordService is available for hashing here, or use a simple mock hash.
	// For consistency with other tests, using argon2Service (PasswordService) from TestMain.

	plainCode1 := "plain_code_1"
	hashedCode1, err := argon2Service.HashPassword(plainCode1)
	require.NoError(t, err)

	plainCode2 := "plain_code_2"
	hashedCode2, err := argon2Service.HashPassword(plainCode2)
	require.NoError(t, err)

	codesToCreate := []*models.MFABackupCode{
		{ID: uuid.New(), UserID: user.ID, CodeHash: hashedCode1},
		{ID: uuid.New(), UserID: user.ID, CodeHash: hashedCode2},
	}

	err = backupRepo.CreateMultiple(ctx, codesToCreate)
	require.NoError(t, err)

	// Find one of them by UserID and its original (now hashed) code
	foundCode, err := backupRepo.FindByUserIDAndCodeHash(ctx, user.ID, hashedCode1)
	require.NoError(t, err)
	require.NotNil(t, foundCode)
	assert.Equal(t, codesToCreate[0].ID, foundCode.ID)
	assert.Equal(t, user.ID, foundCode.UserID)
	assert.Equal(t, hashedCode1, foundCode.CodeHash)
	assert.Nil(t, foundCode.UsedAt, "UsedAt should be nil initially")

	// Test finding a non-existent code hash
	_, err = backupRepo.FindByUserIDAndCodeHash(ctx, user.ID, "non_existent_hash")
	require.Error(t, err)
	assert.True(t, errors.Is(err, domainErrors.ErrNotFound), "Expected ErrNotFound for non-existent hash")
}

func TestMFABackupCodeRepository_Create_DuplicateCodeHashForUser(t *testing.T) {
	ctx := context.Background()
	backupRepo := repoPostgres.NewMFABackupCodeRepositoryPostgres(testDB)
	clearMFABackupCodeTestTables(t)
	user := createTestUserForMFABackupCodeTests(ctx, t, "dupbc")

	hashedCode, _ := argon2Service.HashPassword("duplicate_plain_code")

	code1 := &models.MFABackupCode{ID: uuid.New(), UserID: user.ID, CodeHash: hashedCode}
	err := backupRepo.CreateMultiple(ctx, []*models.MFABackupCode{code1}) // Use CreateMultiple as there's no single Create
	require.NoError(t, err)

	// Attempt to create another with the same UserID and CodeHash
	code2 := &models.MFABackupCode{ID: uuid.New(), UserID: user.ID, CodeHash: hashedCode}
	err = backupRepo.CreateMultiple(ctx, []*models.MFABackupCode{code2})
	require.Error(t, err, "Should have failed due to duplicate (user_id, code_hash)")

	var pgErr *pgconn.PgError
	require.True(t, errors.As(err, &pgErr), "Error should be a PgError")
	assert.Equal(t, "23505", pgErr.Code, "PostgreSQL error code for unique_violation should be 23505")
}

func TestMFABackupCodeRepository_MarkAsUsed(t *testing.T) {
	ctx := context.Background()
	backupRepo := repoPostgres.NewMFABackupCodeRepositoryPostgres(testDB)
	clearMFABackupCodeTestTables(t)
	user := createTestUserForMFABackupCodeTests(ctx, t, "markused")

	hashedCode, _ := argon2Service.HashPassword("code_to_mark_used")
	code := &models.MFABackupCode{ID: uuid.New(), UserID: user.ID, CodeHash: hashedCode}
	err := backupRepo.CreateMultiple(ctx, []*models.MFABackupCode{code})
	require.NoError(t, err)

	// Mark as used
	usedAtTime := time.Now()
	err = backupRepo.MarkAsUsed(ctx, code.ID, usedAtTime)
	require.NoError(t, err)

	// Try to find it using FindByUserIDAndCodeHash (which should filter used codes)
	foundCode, err := backupRepo.FindByUserIDAndCodeHash(ctx, user.ID, hashedCode)
	require.Error(t, err, "Finding a used code by hash and user should fail or return ErrNotFound")
	assert.True(t, errors.Is(err, domainErrors.ErrNotFound), "Expected ErrNotFound for used code")
	assert.Nil(t, foundCode)

	// Verify UsedAt directly (if a FindByID method existed or direct query)
    var dbUsedAt *time.Time // Use pointer to handle NULL
    query := "SELECT used_at FROM mfa_backup_codes WHERE id = $1"
    err = testDB.QueryRow(ctx, query, code.ID).Scan(&dbUsedAt)
    require.NoError(t, err)
    require.NotNil(t, dbUsedAt, "UsedAt should be set in DB")
    assert.WithinDuration(t, usedAtTime, *dbUsedAt, time.Second)

	// Attempt to mark as used again - should not error, but also not change anything
	err = backupRepo.MarkAsUsed(ctx, code.ID, time.Now().Add(time.Minute)) // different time
	require.NoError(t, err, "Marking an already used code as used again should not error")

	// Verify UsedAt is still the original usedAtTime
	var dbUsedAtAgain *time.Time
    err = testDB.QueryRow(ctx, query, code.ID).Scan(&dbUsedAtAgain)
    require.NoError(t, err)
    require.NotNil(t, dbUsedAtAgain)
    assert.WithinDuration(t, usedAtTime, *dbUsedAtAgain, time.Second, "UsedAt should not have changed")
}

func TestMFABackupCodeRepository_DeleteByUserID(t *testing.T) {
	ctx := context.Background()
	backupRepo := repoPostgres.NewMFABackupCodeRepositoryPostgres(testDB)
	clearMFABackupCodeTestTables(t)
	user1 := createTestUserForMFABackupCodeTests(ctx, t, "delusr1")
	user2 := createTestUserForMFABackupCodeTests(ctx, t, "delusr2")

	hashedCode1U1, _ := argon2Service.HashPassword("code1u1")
	hashedCode2U1, _ := argon2Service.HashPassword("code2u1")
	hashedCode1U2, _ := argon2Service.HashPassword("code1u2")

	codesUser1 := []*models.MFABackupCode{
		{ID: uuid.New(), UserID: user1.ID, CodeHash: hashedCode1U1},
		{ID: uuid.New(), UserID: user1.ID, CodeHash: hashedCode2U1},
	}
	err := backupRepo.CreateMultiple(ctx, codesUser1); require.NoError(t, err)

	codesUser2 := []*models.MFABackupCode{
		{ID: uuid.New(), UserID: user2.ID, CodeHash: hashedCode1U2},
	}
	err = backupRepo.CreateMultiple(ctx, codesUser2); require.NoError(t, err)

	// Delete all for user1
	deletedCount, err := backupRepo.DeleteByUserID(ctx, user1.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(2), deletedCount)

	// Verify user1's codes are gone
	_, err = backupRepo.FindByUserIDAndCodeHash(ctx, user1.ID, hashedCode1U1)
	assert.ErrorIs(t, err, domainErrors.ErrNotFound)
	_, err = backupRepo.FindByUserIDAndCodeHash(ctx, user1.ID, hashedCode2U1)
	assert.ErrorIs(t, err, domainErrors.ErrNotFound)

	// Verify user2's codes remain
	foundCodeUser2, err := backupRepo.FindByUserIDAndCodeHash(ctx, user2.ID, hashedCode1U2)
	require.NoError(t, err)
	assert.NotNil(t, foundCodeUser2)
}

func TestMFABackupCodeRepository_FindByUserID(t *testing.T) {
    ctx := context.Background()
    backupRepo := repoPostgres.NewMFABackupCodeRepositoryPostgres(testDB)
    clearMFABackupCodeTestTables(t)
    user := createTestUserForMFABackupCodeTests(ctx, t, "findbyuser")

    hashedCode1, _ := argon2Service.HashPassword("fbuid_code1")
    hashedCode2, _ := argon2Service.HashPassword("fbuid_code2")

    codesToCreate := []*models.MFABackupCode{
        {ID: uuid.New(), UserID: user.ID, CodeHash: hashedCode1},
        {ID: uuid.New(), UserID: user.ID, CodeHash: hashedCode2},
    }
    err := backupRepo.CreateMultiple(ctx, codesToCreate)
    require.NoError(t, err)

    // Mark one as used
    err = backupRepo.MarkAsUsed(ctx, codesToCreate[0].ID, time.Now())
    require.NoError(t, err)

    // FindByUserID should return only non-used codes
    foundCodes, err := backupRepo.FindByUserID(ctx, user.ID)
    require.NoError(t, err)
    require.Len(t, foundCodes, 1, "FindByUserID should only return non-used codes")
    assert.Equal(t, codesToCreate[1].ID, foundCodes[0].ID) // The second code (non-used)
}
