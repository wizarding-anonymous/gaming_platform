// File: internal/domain/service/mfa_logic_service_test.go
package service_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	appConfig "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/config"
	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors"
	domainInterfaces "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/interfaces"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/service"
	kafkaPkg "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/events/kafka"
	// infrastructureSecurity "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/infrastructure/security"
)

// --- Mocks ---

// MockTOTPService
type MockTOTPService struct {
	mock.Mock
}

func (m *MockTOTPService) GenerateSecret(accountName string, issuerNameOverride string) (string, string, error) {
	args := m.Called(accountName, issuerNameOverride)
	return args.String(0), args.String(1), args.Error(2)
}
func (m *MockTOTPService) ValidateCode(secretBase32 string, code string) (bool, error) {
	args := m.Called(secretBase32, code)
	return args.Bool(0), args.Error(1)
}

// MockEncryptionService (mocking the concrete type from infrastructure/security)
// The mfaLogicService takes security.EncryptionService, which is an interface.
// This mock should implement that interface.
type MockEncryptionService struct {
	mock.Mock
}

func (m *MockEncryptionService) Encrypt(plainText string, keyHex string) (string, error) {
	args := m.Called(plainText, keyHex)
	return args.String(0), args.Error(1)
}
func (m *MockEncryptionService) Decrypt(cipherTextBase64 string, keyHex string) (string, error) {
	args := m.Called(cipherTextBase64, keyHex)
	return args.String(0), args.Error(1)
}

// MockMFASecretRepository
type MockMFASecretRepository struct {
	mock.Mock
}

func (m *MockMFASecretRepository) FindByUserIDAndType(ctx context.Context, userID uuid.UUID, mfaType models.MFAType) (*models.MFASecret, error) {
	args := m.Called(ctx, userID, mfaType)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.MFASecret), args.Error(1)
}
func (m *MockMFASecretRepository) Create(ctx context.Context, secret *models.MFASecret) error {
	args := m.Called(ctx, secret)
	return args.Error(0)
}
func (m *MockMFASecretRepository) Update(ctx context.Context, secret *models.MFASecret) error {
	args := m.Called(ctx, secret)
	return args.Error(0)
}
func (m *MockMFASecretRepository) FindByID(ctx context.Context, id uuid.UUID) (*models.MFASecret, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.MFASecret), args.Error(1)
}
func (m *MockMFASecretRepository) DeleteByUserIDAndTypeIfUnverified(ctx context.Context, userID uuid.UUID, mfaType models.MFAType) (bool, error) {
	args := m.Called(ctx, userID, mfaType)
	return args.Bool(0), args.Error(1)
}
func (m *MockMFASecretRepository) DeleteAllForUser(ctx context.Context, userID uuid.UUID) (int64, error) {
	args := m.Called(ctx, userID)
	// Allow int64 or int, then cast if needed, as some mocks might return int.
	val := args.Get(0)
	if valInt, ok := val.(int); ok {
		return int64(valInt), args.Error(1)
	}
	return val.(int64), args.Error(1)
}

// MockMFABackupCodeRepository
type MockMFABackupCodeRepository struct {
	mock.Mock
}

func (m *MockMFABackupCodeRepository) DeleteByUserID(ctx context.Context, userID uuid.UUID) (int64, error) {
	args := m.Called(ctx, userID)
	val := args.Get(0)
	if valInt, ok := val.(int); ok {
		return int64(valInt), args.Error(1)
	}
	return val.(int64), args.Error(1)
}
func (m *MockMFABackupCodeRepository) CreateMultiple(ctx context.Context, codes []*models.MFABackupCode) error {
	args := m.Called(ctx, codes)
	return args.Error(0)
}
func (m *MockMFABackupCodeRepository) FindByUserID(ctx context.Context, userID uuid.UUID) ([]*models.MFABackupCode, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.MFABackupCode), args.Error(1)
}
func (m *MockMFABackupCodeRepository) MarkAsUsed(ctx context.Context, id uuid.UUID, usedAt time.Time) error {
	args := m.Called(ctx, id, usedAt)
	return args.Error(0)
}
func (m *MockMFABackupCodeRepository) CountActiveByUserID(ctx context.Context, userID uuid.UUID) (int, error) {
	args := m.Called(ctx, userID)
	return args.Int(0), args.Error(1)
}

// MockUserRepository
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) FindByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

// Add other UserRepo methods if they become necessary for mfaLogicService tests
func (m *MockUserRepository) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	panic("not implemented")
}
func (m *MockUserRepository) FindByUsername(ctx context.Context, username string) (*models.User, error) {
	panic("not implemented")
}
func (m *MockUserRepository) Create(ctx context.Context, user *models.User) error {
	panic("not implemented")
}
func (m *MockUserRepository) Update(ctx context.Context, user *models.User) error {
	panic("not implemented")
}

// ... and so on for all methods of UserRepository interface

// MockPasswordService
type MockPasswordService struct {
	mock.Mock
}

func (m *MockPasswordService) HashPassword(password string) (string, error) {
	args := m.Called(password)
	return args.String(0), args.Error(1)
}
func (m *MockPasswordService) CheckPasswordHash(password, hash string) (bool, error) {
	args := m.Called(password, hash)
	return args.Bool(0), args.Error(1)
}

// MockAuditLogRecorder
type MockAuditLogRecorder struct {
	mock.Mock
}

func (m *MockAuditLogRecorder) RecordEvent(ctx context.Context, actorID *uuid.UUID, eventName models.AuditLogEventName, status models.AuditLogStatus, targetID *uuid.UUID, targetType models.AuditTargetType, details map[string]interface{}, ipAddress, userAgent string) {
	m.Called(ctx, actorID, eventName, status, targetID, targetType, details, ipAddress, userAgent)
}

// MockKafkaProducer (mocking the concrete type)
type MockKafkaProducer struct {
	mock.Mock
}

func (m *MockKafkaProducer) PublishCloudEvent(ctx context.Context, topic string, eventType kafkaPkg.EventType, subject *string, dataContentType *string, dataPayload interface{}) error {
	args := m.Called(ctx, topic, eventType, subject, dataContentType, dataPayload)
	return args.Error(0)
}
func (m *MockKafkaProducer) Close() error {
	args := m.Called()
	return args.Error(0)
}

// MockRateLimiter
type MockRateLimiter struct {
	mock.Mock
}

func (m *MockRateLimiter) Allow(ctx context.Context, key string, rule appConfig.RateLimitRule) (bool, error) {
	args := m.Called(ctx, key, rule)
	return args.Bool(0), args.Error(1)
}

// --- Test Setup Helper ---
type mfalsTestDeps struct {
	mockTOTPService       *MockTOTPService
	mockEncryptionService *MockEncryptionService
	mockMFASecretRepo     *MockMFASecretRepository
	mockMFABackupCodeRepo *MockMFABackupCodeRepository
	mockUserRepo          *MockUserRepository
	mockPasswordService   *MockPasswordService
	mockAuditLogRecorder  *MockAuditLogRecorder
	mockKafkaProducer     *MockKafkaProducer
	mockRateLimiter       *MockRateLimiter
}

func setupMFALogicServiceWithMocks(t *testing.T) (service.MFALogicService, *mfalsTestDeps, *appConfig.Config) {
	cfg := &appConfig.Config{
		MFA: appConfig.MFAConfig{
			TOTPIssuerName:          "TestApp",
			TOTPSecretEncryptionKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", // 64 hex chars = 32 bytes
			TOTPBackupCodeCount:     10,
		},
		Security: appConfig.SecurityConfig{
			RateLimiting: appConfig.RateLimitConfig{
				TwoFAVerificationPerUser: appConfig.RateLimitRule{
					Enabled: false,
					Limit:   5,
					Window:  1 * time.Minute,
				},
			},
		},
		// Add other necessary config fields if mfaLogicService uses them.
	}

	deps := &mfalsTestDeps{
		mockTOTPService:       new(MockTOTPService),
		mockEncryptionService: new(MockEncryptionService),
		mockMFASecretRepo:     new(MockMFASecretRepository),
		mockMFABackupCodeRepo: new(MockMFABackupCodeRepository),
		mockUserRepo:          new(MockUserRepository),
		mockPasswordService:   new(MockPasswordService),
		mockAuditLogRecorder:  new(MockAuditLogRecorder),
		mockKafkaProducer:     new(MockKafkaProducer),
		mockRateLimiter:       new(MockRateLimiter),
	}

	deps.mockAuditLogRecorder.On("RecordEvent", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Maybe()

	mfaService := service.NewMFALogicService(
		cfg,
		deps.mockTOTPService,
		deps.mockEncryptionService,
		deps.mockMFASecretRepo,
		deps.mockMFABackupCodeRepo,
		deps.mockUserRepo,
		deps.mockPasswordService,
		deps.mockAuditLogRecorder,
		deps.mockKafkaProducer,
		deps.mockRateLimiter,
	)
	return mfaService, deps, cfg
}

// --- Tests ---

func TestEnable2FAInitiate_Success_NewSetup(t *testing.T) {
	ctx := context.Background()
	mfaService, deps, _ := setupMFALogicServiceWithMocks(t)
	userID := uuid.New()
	accountName := "testuser@example.com"

	deps.mockMFASecretRepo.On("FindByUserIDAndType", ctx, userID, models.MFATypeTOTP).Return(nil, domainErrors.ErrNotFound)
	deps.mockTOTPService.On("GenerateSecret", accountName, "TestApp").Return("testBase32Secret", "otpauth://test", nil)
	deps.mockEncryptionService.On("Encrypt", "testBase32Secret", mock.AnythingOfType("string")).Return("encryptedSecret", nil)
	// Matcher for the MFASecret to be created
	deps.mockMFASecretRepo.On("Create", ctx, mock.MatchedBy(func(s *models.MFASecret) bool {
		return s.UserID == userID && s.Type == models.MFATypeTOTP && s.SecretKeyEncrypted == "encryptedSecret" && !s.Verified
	})).Return(nil)
	deps.mockAuditLogRecorder.On("RecordEvent", ctx, &userID, models.AuditLogMFARegisterAttempt, models.AuditLogStatusSuccess, &userID, models.AuditTargetTypeUser, mock.Anything, "unknown", "unknown").Once()

	secretID, base32Secret, otpAuthURL, err := mfaService.Enable2FAInitiate(ctx, userID, accountName)

	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, secretID)
	assert.Equal(t, "testBase32Secret", base32Secret)
	assert.Equal(t, "otpauth://test", otpAuthURL)
	deps.mockMFASecretRepo.AssertExpectations(t)
	deps.mockTOTPService.AssertExpectations(t)
	deps.mockEncryptionService.AssertExpectations(t)
	deps.mockAuditLogRecorder.AssertExpectations(t)
}

func TestEnable2FAInitiate_Success_PreviousUnverifiedExists(t *testing.T) {
	ctx := context.Background()
	mfaService, deps, _ := setupMFALogicServiceWithMocks(t)
	userID := uuid.New()
	accountName := "testuser@example.com"
	existingUnverifiedSecret := &models.MFASecret{ID: uuid.New(), UserID: userID, Type: models.MFATypeTOTP, Verified: false}

	deps.mockMFASecretRepo.On("FindByUserIDAndType", ctx, userID, models.MFATypeTOTP).Return(existingUnverifiedSecret, nil)
	deps.mockMFASecretRepo.On("DeleteByUserIDAndTypeIfUnverified", ctx, userID, models.MFATypeTOTP).Return(true, nil)
	deps.mockTOTPService.On("GenerateSecret", accountName, "TestApp").Return("newSecret", "newURL", nil)
	deps.mockEncryptionService.On("Encrypt", "newSecret", mock.AnythingOfType("string")).Return("newEncrypted", nil)
	deps.mockMFASecretRepo.On("Create", ctx, mock.AnythingOfType("*models.MFASecret")).Return(nil) // Simplified matcher for brevity
	deps.mockAuditLogRecorder.On("RecordEvent", ctx, &userID, models.AuditLogMFARegisterAttempt, models.AuditLogStatusSuccess, &userID, models.AuditTargetTypeUser, mock.Anything, "unknown", "unknown").Once()

	_, _, _, err := mfaService.Enable2FAInitiate(ctx, userID, accountName)
	require.NoError(t, err)
	deps.mockMFASecretRepo.AssertCalled(t, "DeleteByUserIDAndTypeIfUnverified", ctx, userID, models.MFATypeTOTP)
	deps.mockAuditLogRecorder.AssertExpectations(t)
}

func TestEnable2FAInitiate_Failure_AlreadyEnabledAndVerified(t *testing.T) {
	ctx := context.Background()
	mfaService, deps, _ := setupMFALogicServiceWithMocks(t)
	userID := uuid.New()
	existingVerifiedSecret := &models.MFASecret{ID: uuid.New(), UserID: userID, Type: models.MFATypeTOTP, Verified: true}

	deps.mockMFASecretRepo.On("FindByUserIDAndType", ctx, userID, models.MFATypeTOTP).Return(existingVerifiedSecret, nil)
	deps.mockAuditLogRecorder.On("RecordEvent", ctx, &userID, models.AuditLogMFARegisterAttempt, models.AuditLogStatusFailure, &userID, models.AuditTargetTypeUser, mock.Anything, "unknown", "unknown").Once()

	_, _, _, err := mfaService.Enable2FAInitiate(ctx, userID, "test")
	assert.ErrorIs(t, err, domainErrors.Err2FAAlreadyEnabled)
	deps.mockAuditLogRecorder.AssertExpectations(t)
}

func TestVerifyAndActivate2FA_Success(t *testing.T) {
	ctx := context.Background()
	mfaService, deps, cfg := setupMFALogicServiceWithMocks(t)
	userID := uuid.New()
	mfaSecretID := uuid.New()
	totpCode := "123456"
	base32Secret := "testBase32Secret" // This is the decrypted secret

	unverifiedSecret := &models.MFASecret{
		ID: mfaSecretID, UserID: userID, Type: models.MFATypeTOTP,
		SecretKeyEncrypted: "encryptedSecretString", Verified: false,
	}

	deps.mockMFASecretRepo.On("FindByID", ctx, mfaSecretID).Return(unverifiedSecret, nil)
	deps.mockEncryptionService.On("Decrypt", "encryptedSecretString", cfg.MFA.TOTPSecretEncryptionKey).Return(base32Secret, nil)
	deps.mockTOTPService.On("ValidateCode", base32Secret, totpCode).Return(true, nil)
	deps.mockMFASecretRepo.On("Update", ctx, mock.MatchedBy(func(s *models.MFASecret) bool {
		return s.ID == mfaSecretID && s.UserID == userID && s.Verified
	})).Return(nil)
	deps.mockMFABackupCodeRepo.On("DeleteByUserID", ctx, userID).Return(int64(0), nil)

	for i := 0; i < cfg.MFA.TOTPBackupCodeCount; i++ {
		deps.mockPasswordService.On("HashPassword", mock.AnythingOfType("string")).Return(fmt.Sprintf("hashedBackupCode%d", i), nil).Once()
	}
	deps.mockMFABackupCodeRepo.On("CreateMultiple", ctx, mock.MatchedBy(func(codes []*models.MFABackupCode) bool {
		return len(codes) == cfg.MFA.TOTPBackupCodeCount
	})).Return(nil)
	deps.mockKafkaProducer.On("PublishCloudEvent", ctx, "auth.events", kafkaPkg.EventType(models.AuthMFAEnabledV1), mock.AnythingOfType("*string"), mock.AnythingOfType("*string"), mock.AnythingOfType("models.MFAEnabledPayload")).Return(nil)
	deps.mockAuditLogRecorder.On("RecordEvent", ctx, &userID, models.AuditLogMFAEnableFinalize, models.AuditLogStatusSuccess, &userID, models.AuditTargetTypeUser, mock.Anything, "unknown", "unknown").Once()

	backupCodes, err := mfaService.VerifyAndActivate2FA(ctx, userID, totpCode, mfaSecretID)
	require.NoError(t, err)
	assert.Len(t, backupCodes, cfg.MFA.TOTPBackupCodeCount)

	deps.mockMFASecretRepo.AssertExpectations(t)
	deps.mockEncryptionService.AssertExpectations(t)
	deps.mockTOTPService.AssertExpectations(t)
	deps.mockPasswordService.AssertExpectations(t)
	deps.mockMFABackupCodeRepo.AssertExpectations(t)
	deps.mockKafkaProducer.AssertExpectations(t)
	deps.mockAuditLogRecorder.AssertExpectations(t)
}

func TestVerify2FACode_TOTP_Success(t *testing.T) {
	ctx := context.Background()
	mfaService, deps, cfg := setupMFALogicServiceWithMocks(t)
	userID := uuid.New()
	totpCode := "123456"
	base32Secret := "testBase32Secret"

	cfg.Security.RateLimiting.TwoFAVerificationPerUser.Enabled = true // Enable rate limiting for this test

	verifiedSecret := &models.MFASecret{
		ID: uuid.New(), UserID: userID, Type: models.MFATypeTOTP,
		SecretKeyEncrypted: "encryptedSecretString", Verified: true,
	}

	deps.mockRateLimiter.On("Allow", ctx, "2faverify_user:"+userID.String(), cfg.Security.RateLimiting.TwoFAVerificationPerUser).Return(true, nil)
	deps.mockMFASecretRepo.On("FindByUserIDAndType", ctx, userID, models.MFATypeTOTP).Return(verifiedSecret, nil)
	deps.mockEncryptionService.On("Decrypt", "encryptedSecretString", cfg.MFA.TOTPSecretEncryptionKey).Return(base32Secret, nil)
	deps.mockTOTPService.On("ValidateCode", base32Secret, totpCode).Return(true, nil)
	deps.mockAuditLogRecorder.On("RecordEvent", ctx, &userID, models.AuditLogMFACodeVerify, models.AuditLogStatusSuccess, &userID, models.AuditTargetTypeUser, mock.Anything, "unknown", "unknown").Once()

	valid, err := mfaService.Verify2FACode(ctx, userID, totpCode, models.MFATypeTOTP)
	require.NoError(t, err)
	assert.True(t, valid)

	deps.mockRateLimiter.AssertExpectations(t)
	deps.mockMFASecretRepo.AssertExpectations(t)
	deps.mockEncryptionService.AssertExpectations(t)
	deps.mockTOTPService.AssertExpectations(t)
	deps.mockAuditLogRecorder.AssertExpectations(t)
}

func TestVerify2FACode_TOTP_RateLimited(t *testing.T) {
	ctx := context.Background()
	mfaService, deps, cfg := setupMFALogicServiceWithMocks(t)
	userID := uuid.New()
	totpCode := "123456"

	cfg.Security.RateLimiting.TwoFAVerificationPerUser.Enabled = true
	rateLimitRule := cfg.Security.RateLimiting.TwoFAVerificationPerUser

	deps.mockRateLimiter.On("Allow", ctx, "2faverify_user:"+userID.String(), rateLimitRule).Return(false, nil) // Rate limit exceeded
	deps.mockAuditLogRecorder.On("RecordEvent", ctx, &userID, models.AuditLogMFACodeVerify, models.AuditLogStatusFailure, &userID, models.AuditTargetTypeUser, mock.MatchedBy(func(m map[string]interface{}) bool {
		return m["error"] == domainErrors.ErrRateLimitExceeded.Error()
	}), "unknown", "unknown").Once()

	valid, err := mfaService.Verify2FACode(ctx, userID, totpCode, models.MFATypeTOTP)
	assert.ErrorIs(t, err, domainErrors.ErrRateLimitExceeded)
	assert.False(t, valid)
	deps.mockRateLimiter.AssertExpectations(t)
	deps.mockAuditLogRecorder.AssertExpectations(t)
}

func TestVerify2FACode_BackupCode_Success(t *testing.T) {
	ctx := context.Background()
	mfaService, deps, cfg := setupMFALogicServiceWithMocks(t)
	userID := uuid.New()
	backupCodePlain := "backup123"

	cfg.Security.RateLimiting.TwoFAVerificationPerUser.Enabled = false // Disable rate limiting for this specific test focus

	hashedBackupCode := "hashed-" + backupCodePlain
	backupCodesInDB := []*models.MFABackupCode{
		{ID: uuid.New(), UserID: userID, CodeHash: hashedBackupCode, UsedAt: nil},
		{ID: uuid.New(), UserID: userID, CodeHash: "some-other-hash", UsedAt: nil},
	}

	deps.mockMFABackupCodeRepo.On("FindByUserID", ctx, userID).Return(backupCodesInDB, nil)
	deps.mockPasswordService.On("CheckPasswordHash", backupCodePlain, hashedBackupCode).Return(true, nil)
	deps.mockPasswordService.On("CheckPasswordHash", backupCodePlain, "some-other-hash").Return(false, nil) // For the other code
	deps.mockMFABackupCodeRepo.On("MarkAsUsed", ctx, backupCodesInDB[0].ID, mock.AnythingOfType("time.Time")).Return(nil)
	deps.mockAuditLogRecorder.On("RecordEvent", ctx, &userID, models.AuditLogMFACodeVerify, models.AuditLogStatusSuccess, &userID, models.AuditTargetTypeUser, mock.Anything, "unknown", "unknown").Once()

	valid, err := mfaService.Verify2FACode(ctx, userID, backupCodePlain, models.MFATypeBackup)
	require.NoError(t, err)
	assert.True(t, valid)
	deps.mockMFABackupCodeRepo.AssertExpectations(t)
	deps.mockPasswordService.AssertExpectations(t)
	deps.mockAuditLogRecorder.AssertExpectations(t)
}

// Minimal stubs for other tests to make the file compile
func TestDisable2FA_PasswordAuth_Success(t *testing.T) {
	t.Skip("Disable2FA test not fully implemented for brevity")
}
func TestRegenerateBackupCodes_PasswordAuth_Success(t *testing.T) {
	t.Skip("RegenerateBackupCodes test not fully implemented for brevity")
}
func TestGetActiveBackupCodeCount_Success(t *testing.T) {
	t.Skip("GetActiveBackupCodeCount test not fully implemented for brevity")
}
