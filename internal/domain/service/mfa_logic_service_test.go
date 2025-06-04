package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/your-org/auth-service/internal/config"
	"github.com/your-org/auth-service/internal/domain/models"
	domainErrors "github.com/your-org/auth-service/internal/domain/errors"
	eventModels "github.com/your-org/auth-service/internal/events/models"
	kafkaPkg "github.com/your-org/auth-service/internal/events/kafka"
	repoInterfaces "github.com/your-org/auth-service/internal/repository/interfaces"
	"go.uber.org/zap"
)

// --- Mocks ---

type MockUserRepositoryForMFATests struct {
	mock.Mock
}
func (m *MockUserRepositoryForMFATests) FindByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

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
func (m *MockMFASecretRepository) FindByID(ctx context.Context, id uuid.UUID) (*models.MFASecret, error) {
    args := m.Called(ctx, id)
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
func (m *MockMFASecretRepository) DeleteByUserIDAndTypeIfUnverified(ctx context.Context, userID uuid.UUID, mfaType models.MFAType) (bool, error) {
    args := m.Called(ctx, userID, mfaType)
    return args.Bool(0), args.Error(1)
}
func (m *MockMFASecretRepository) DeleteAllForUser(ctx context.Context, userID uuid.UUID) (int64, error) {
    args := m.Called(ctx, userID)
    return args.Get(0).(int64), args.Error(1)
}


type MockMFABackupCodeRepository struct {
	mock.Mock
}
func (m *MockMFABackupCodeRepository) DeleteByUserID(ctx context.Context, userID uuid.UUID) (int64, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).(int64), args.Error(1)
}
func (m *MockMFABackupCodeRepository) CreateMultiple(ctx context.Context, codes []*models.MFABackupCode) error {
	args := m.Called(ctx, codes)
	return args.Error(0)
}
func (m *MockMFABackupCodeRepository) FindByUserIDAndCodeHash(ctx context.Context, userID uuid.UUID, codeHash string) (*models.MFABackupCode, error) {
	args := m.Called(ctx, userID, codeHash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.MFABackupCode), args.Error(1)
}
func (m *MockMFABackupCodeRepository) MarkAsUsed(ctx context.Context, id uuid.UUID, usedAt time.Time) error {
	args := m.Called(ctx, id, usedAt)
	return args.Error(0)
}


type MockTOTPService struct {
	mock.Mock
}
func (m *MockTOTPService) GenerateSecret(accountName string, issuerName string) (base32Secret string, otpAuthURL string, err error) {
	args := m.Called(accountName, issuerName)
	return args.String(0), args.String(1), args.Error(2)
}
func (m *MockTOTPService) ValidateCode(secretBase32 string, code string) (bool, error) {
	args := m.Called(secretBase32, code)
	return args.Bool(0), args.Error(1)
}

type MockPasswordServiceForMFA struct {
	mock.Mock
}
func (m *MockPasswordServiceForMFA) HashPassword(password string) (string, error) {
	args := m.Called(password)
	return args.String(0), args.Error(1)
}
func (m *MockPasswordServiceForMFA) CheckPasswordHash(password, hash string) (bool, error) {
	args := m.Called(password, hash)
	return args.Bool(0), args.Error(1)
}

type MockAuditLogRecorderForMFA struct {
	mock.Mock
}
func (m *MockAuditLogRecorderForMFA) RecordEvent(ctx context.Context, actorID *uuid.UUID, action string, status models.AuditLogStatus, targetID interface{}, targetType models.AuditTargetType, details map[string]interface{}, ipAddress string, userAgent string) {
	m.Called(ctx, actorID, action, status, targetID, targetType, details, ipAddress, userAgent)
}

type MockKafkaProducerForMFA struct {
	mock.Mock
}
func (m *MockKafkaProducerForMFA) PublishCloudEvent(ctx context.Context, topic string, eventType eventModels.EventType, subject string, dataPayload interface{}) error {
	args := m.Called(ctx, topic, eventType, subject, dataPayload)
	return args.Error(0)
}
func (m *MockKafkaProducerForMFA) Close() error {
	args := m.Called()
	return args.Error(0)
}

type MockEncryptionService struct {
	mock.Mock
}
func (m *MockEncryptionService) Encrypt(plaintext string, key string) (string, error) {
	args := m.Called(plaintext, key)
	return args.String(0), args.Error(1)
}
func (m *MockEncryptionService) Decrypt(ciphertext string, key string) (string, error) {
	args := m.Called(ciphertext, key)
	return args.String(0), args.Error(1)
}


// --- Test Suite Setup ---
type MFALogicServiceTestSuite struct {
	service           MFALogicService
	mockUserRepo      *MockUserRepositoryForMFATests
	mockMfaSecretRepo *MockMFASecretRepository
	mockMfaBackupRepo *MockMFABackupCodeRepository
	mockTotpSvc       *MockTOTPService
	mockPassSvc       *MockPasswordServiceForMFA
	mockAudit         *MockAuditLogRecorderForMFA
	mockKafka         *MockKafkaProducerForMFA
	mockEncryptionSvc *MockEncryptionService
	testMFAConfig     *config.MFAConfig
	testKafkaConfig   *config.KafkaConfig
}

func setupMFALogicServiceTestSuite(t *testing.T) *MFALogicServiceTestSuite {
	ts := &MFALogicServiceTestSuite{}
	ts.mockUserRepo = new(MockUserRepositoryForMFATests)
	ts.mockMfaSecretRepo = new(MockMFASecretRepository)
	ts.mockMfaBackupRepo = new(MockMFABackupCodeRepository)
	ts.mockTotpSvc = new(MockTOTPService)
	ts.mockPassSvc = new(MockPasswordServiceForMFA)
	ts.mockAudit = new(MockAuditLogRecorderForMFA)
	ts.mockKafka = new(MockKafkaProducerForMFA)
	ts.mockEncryptionSvc = new(MockEncryptionService)

	key := "12345678901234567890123456789012"
	ts.testMFAConfig = &config.MFAConfig{
		TOTPIssuerName:         "TestIssuer",
		TOTPSecretEncryptionKey: key,
		TOTPBackupCodeCount:    5,
	}
	ts.testKafkaConfig = &config.KafkaConfig{
		Producer: config.KafkaProducerConfig{
			Topic: "auth-events",
		},
	}

	ts.service = NewMFALogicService(
		ts.testMFAConfig,
		ts.mockTotpSvc,
		ts.mockEncryptionSvc,
		ts.mockMfaSecretRepo,
		ts.mockMfaBackupRepo,
		ts.mockUserRepo,
		ts.mockPassSvc,
		ts.mockAudit,
		ts.mockKafka,
	)
	return ts
}

// --- Test NewMFALogicService ---
func TestNewMFALogicService_Success(t *testing.T) {
	ts := setupMFALogicServiceTestSuite(t)
	assert.NotNil(t, ts.service)
}

// --- Test Enable2FAInitiate ---
// ... (Enable2FAInitiate tests) ...
func TestMFALogicService_Enable2FAInitiate_Success(t *testing.T) {
	ts := setupMFALogicServiceTestSuite(t)
	ctx := context.Background()
	userID := uuid.New()
	accountName := "test@example.com"
	expectedSecret := "TESTSECRETBASE32"
	expectedURL := "otpauth://..."
	encryptedSecret := "encrypted-secret"

	ts.mockMfaSecretRepo.On("FindByUserIDAndType", ctx, userID, models.MFATypeTOTP).Return(nil, domainErrors.ErrNotFound).Once()
	ts.mockTotpSvc.On("GenerateSecret", accountName, ts.testMFAConfig.TOTPIssuerName).Return(expectedSecret, expectedURL, nil).Once()
	ts.mockEncryptionSvc.On("Encrypt", expectedSecret, ts.testMFAConfig.TOTPSecretEncryptionKey).Return(encryptedSecret, nil).Once()
	ts.mockMfaSecretRepo.On("Create", ctx, mock.MatchedBy(func(s *models.MFASecret) bool {
		return s.UserID == userID && s.SecretKeyEncrypted == encryptedSecret && !s.Verified && s.Type == models.MFATypeTOTP
	})).Return(nil).Once()

	ts.mockAudit.On("RecordEvent", ctx, &userID, "mfa_enable_initiate", models.AuditLogStatusSuccess, &userID, models.AuditTargetTypeUser, mock.Anything, "unknown", "unknown").Once()

	mfaSecretID, secret, url, err := ts.service.Enable2FAInitiate(ctx, userID, accountName)

	assert.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, mfaSecretID)
	assert.Equal(t, expectedSecret, secret)
	assert.Equal(t, expectedURL, url)

	ts.mockMfaSecretRepo.AssertExpectations(t)
	ts.mockTotpSvc.AssertExpectations(t)
	ts.mockEncryptionSvc.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
}

func TestMFALogicService_Enable2FAInitiate_Failure_AlreadyVerified(t *testing.T) {
	ts := setupMFALogicServiceTestSuite(t)
	ctx := context.Background()
	userID := uuid.New()
	accountName := "test@example.com"

	existingVerifiedSecret := &models.MFASecret{UserID: userID, Type: models.MFATypeTOTP, Verified: true}
	ts.mockMfaSecretRepo.On("FindByUserIDAndType", ctx, userID, models.MFATypeTOTP).Return(existingVerifiedSecret, nil).Once()
	ts.mockAudit.On("RecordEvent", ctx, &userID, "mfa_enable_initiate", models.AuditLogStatusFailure, &userID, models.AuditTargetTypeUser, mock.Anything, "unknown", "unknown").Once()

	_, _, _, err := ts.service.Enable2FAInitiate(ctx, userID, accountName)
	assert.ErrorIs(t, err, domainErrors.Err2FAAlreadyEnabled)
	ts.mockMfaSecretRepo.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
}

func TestMFALogicService_Enable2FAInitiate_Success_DeletesUnverified(t *testing.T) {
	ts := setupMFALogicServiceTestSuite(t)
	ctx := context.Background()
	userID := uuid.New()
	accountName := "test@example.com"
	expectedSecret := "TESTSECRETBASE32"
	expectedURL := "otpauth://..."
	encryptedSecret := "encrypted-secret"

	existingUnverifiedSecret := &models.MFASecret{UserID: userID, Type: models.MFATypeTOTP, Verified: false}
	ts.mockMfaSecretRepo.On("FindByUserIDAndType", ctx, userID, models.MFATypeTOTP).Return(existingUnverifiedSecret, nil).Once()
	ts.mockMfaSecretRepo.On("DeleteByUserIDAndTypeIfUnverified", ctx, userID, models.MFATypeTOTP).Return(true, nil).Once()

	ts.mockTotpSvc.On("GenerateSecret", accountName, ts.testMFAConfig.TOTPIssuerName).Return(expectedSecret, expectedURL, nil).Once()
	ts.mockEncryptionSvc.On("Encrypt", expectedSecret, ts.testMFAConfig.TOTPSecretEncryptionKey).Return(encryptedSecret, nil).Once()
	ts.mockMfaSecretRepo.On("Create", ctx, mock.AnythingOfType("*models.MFASecret")).Return(nil).Once()
	ts.mockAudit.On("RecordEvent", ctx, &userID, "mfa_enable_initiate", models.AuditLogStatusSuccess, &userID, models.AuditTargetTypeUser, mock.Anything, "unknown", "unknown").Once()


	_, _, _, err := ts.service.Enable2FAInitiate(ctx, userID, accountName)
	assert.NoError(t, err)
	ts.mockMfaSecretRepo.AssertExpectations(t)
}


func TestMFALogicService_Enable2FAInitiate_Failure_GenerateSecretFails(t *testing.T) {
	ts := setupMFALogicServiceTestSuite(t)
	ctx := context.Background()
	userID := uuid.New()
	genError := errors.New("TOTP generation error")

	ts.mockMfaSecretRepo.On("FindByUserIDAndType", ctx, userID, models.MFATypeTOTP).Return(nil, domainErrors.ErrNotFound).Once()
	ts.mockTotpSvc.On("GenerateSecret", mock.AnythingOfType("string"), mock.AnythingOfType("string")).Return("", "", genError).Once()
	ts.mockAudit.On("RecordEvent", ctx, &userID, "mfa_enable_initiate", models.AuditLogStatusFailure, &userID, models.AuditTargetTypeUser, mock.Anything, "unknown", "unknown").Once()

	_, _, _, err := ts.service.Enable2FAInitiate(ctx, userID, "test")
	assert.ErrorContains(t, err, genError.Error())
	ts.mockTotpSvc.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
}

func TestMFALogicService_Enable2FAInitiate_Failure_EncryptFails(t *testing.T) {
	ts := setupMFALogicServiceTestSuite(t)
	ctx := context.Background()
	userID := uuid.New()
	encryptError := errors.New("encryption error")

	ts.mockMfaSecretRepo.On("FindByUserIDAndType", ctx, userID, models.MFATypeTOTP).Return(nil, domainErrors.ErrNotFound).Once()
	ts.mockTotpSvc.On("GenerateSecret", mock.AnythingOfType("string"), mock.AnythingOfType("string")).Return("secret", "url", nil).Once()
	ts.mockEncryptionSvc.On("Encrypt", "secret", ts.testMFAConfig.TOTPSecretEncryptionKey).Return("", encryptError).Once()
	ts.mockAudit.On("RecordEvent", ctx, &userID, "mfa_enable_initiate", models.AuditLogStatusFailure, &userID, models.AuditTargetTypeUser, mock.Anything, "unknown", "unknown").Once()

	_, _, _, err := ts.service.Enable2FAInitiate(ctx, userID, "test")
	assert.ErrorContains(t, err, encryptError.Error())
	ts.mockEncryptionSvc.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
}

func TestMFALogicService_Enable2FAInitiate_Failure_RepoCreateFails(t *testing.T) {
	ts := setupMFALogicServiceTestSuite(t)
	ctx := context.Background()
	userID := uuid.New()
	repoCreateError := errors.New("repo create error")

	ts.mockMfaSecretRepo.On("FindByUserIDAndType", ctx, userID, models.MFATypeTOTP).Return(nil, domainErrors.ErrNotFound).Once()
	ts.mockTotpSvc.On("GenerateSecret", mock.AnythingOfType("string"), mock.AnythingOfType("string")).Return("secret", "url", nil).Once()
	ts.mockEncryptionSvc.On("Encrypt", "secret", ts.testMFAConfig.TOTPSecretEncryptionKey).Return("encrypted", nil).Once()
	ts.mockMfaSecretRepo.On("Create", ctx, mock.AnythingOfType("*models.MFASecret")).Return(repoCreateError).Once()
	ts.mockAudit.On("RecordEvent", ctx, &userID, "mfa_enable_initiate", models.AuditLogStatusFailure, &userID, models.AuditTargetTypeUser, mock.Anything, "unknown", "unknown").Once()

	_, _, _, err := ts.service.Enable2FAInitiate(ctx, userID, "test")
	assert.ErrorContains(t, err, repoCreateError.Error())
	ts.mockMfaSecretRepo.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
}

// --- Test VerifyAndActivate2FA ---
func TestMFALogicService_VerifyAndActivate2FA_Success(t *testing.T) {
	ts := setupMFALogicServiceTestSuite(t)
	ctx := context.Background()
	userID := uuid.New()
	mfaSecretID := uuid.New()
	plainTOTPCode := "123456"
	decryptedSecret := "DECRYPTEDSECRET"

	unverifiedSecret := &models.MFASecret{ID: mfaSecretID, UserID: userID, Type: models.MFATypeTOTP, SecretKeyEncrypted: "encrypted", Verified: false}

	ts.mockMfaSecretRepo.On("FindByID", ctx, mfaSecretID).Return(unverifiedSecret, nil).Once()
	ts.mockEncryptionSvc.On("Decrypt", "encrypted", ts.testMFAConfig.TOTPSecretEncryptionKey).Return(decryptedSecret, nil).Once()
	ts.mockTotpSvc.On("ValidateCode", decryptedSecret, plainTOTPCode).Return(true, nil).Once()
	ts.mockMfaSecretRepo.On("Update", ctx, mock.MatchedBy(func(s *models.MFASecret) bool {
		return s.ID == mfaSecretID && s.Verified == true
	})).Return(nil).Once()
	ts.mockMfaBackupRepo.On("DeleteByUserID", ctx, userID).Return(int64(0), nil).Once()
	for i := 0; i < ts.testMFAConfig.TOTPBackupCodeCount; i++ {
		ts.mockPassSvc.On("HashPassword", mock.AnythingOfType("string")).Return(fmt.Sprintf("hashed_backup_%d", i), nil).Once()
	}
	ts.mockMfaBackupRepo.On("CreateMultiple", ctx, mock.AnythingOfType("[]*models.MFABackupCode")).Return(nil).Once()

	ts.mockAudit.On("RecordEvent", ctx, &userID, "mfa_enable_complete", models.AuditLogStatusSuccess, &userID, models.AuditTargetTypeUser, mock.Anything, "unknown", "unknown").Once()
	ts.mockKafka.On("PublishCloudEvent", ctx, ts.testKafkaConfig.Producer.Topic, eventModels.AuthMFAEnabledV1, userID.String(), mock.AnythingOfType("eventModels.MFAEnabledPayload")).Return(nil).Once()


	backupCodes, err := ts.service.VerifyAndActivate2FA(ctx, userID, plainTOTPCode, mfaSecretID)
	assert.NoError(t, err)
	assert.Len(t, backupCodes, ts.testMFAConfig.TOTPBackupCodeCount)

	ts.mockMfaSecretRepo.AssertExpectations(t)
	ts.mockEncryptionSvc.AssertExpectations(t)
	ts.mockTotpSvc.AssertExpectations(t)
	ts.mockMfaBackupRepo.AssertExpectations(t)
	ts.mockPassSvc.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
	ts.mockKafka.AssertExpectations(t)
}

func TestMFALogicService_VerifyAndActivate2FA_Failure_SecretNotFound(t *testing.T) {
	ts := setupMFALogicServiceTestSuite(t)
	ctx := context.Background()
	userID := uuid.New()
	mfaSecretID := uuid.New()
	plainTOTPCode := "123456"

	ts.mockMfaSecretRepo.On("FindByID", ctx, mfaSecretID).Return(nil, domainErrors.ErrNotFound).Once()
	ts.mockAudit.On("RecordEvent", ctx, &userID, "mfa_enable_verify_code", models.AuditLogStatusFailure, &userID, models.AuditTargetTypeMFASecret, mock.Anything, "unknown", "unknown").Once()

	_, err := ts.service.VerifyAndActivate2FA(ctx, userID, plainTOTPCode, mfaSecretID)
	assert.ErrorIs(t, err, domainErrors.ErrNotFound)
	ts.mockMfaSecretRepo.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
}

func TestMFALogicService_VerifyAndActivate2FA_Failure_AlreadyVerified(t *testing.T) {
	ts := setupMFALogicServiceTestSuite(t)
	ctx := context.Background()
	userID := uuid.New()
	mfaSecretID := uuid.New()
	plainTOTPCode := "123456"

	verifiedSecret := &models.MFASecret{ID: mfaSecretID, UserID: userID, Type: models.MFATypeTOTP, Verified: true}
	ts.mockMfaSecretRepo.On("FindByID", ctx, mfaSecretID).Return(verifiedSecret, nil).Once()
	ts.mockAudit.On("RecordEvent", ctx, &userID, "mfa_enable_verify_code", models.AuditLogStatusFailure, &userID, models.AuditTargetTypeMFASecret, mock.Anything, "unknown", "unknown").Once()

	_, err := ts.service.VerifyAndActivate2FA(ctx, userID, plainTOTPCode, mfaSecretID)
	assert.ErrorIs(t, err, domainErrors.Err2FAAlreadyEnabled)
}

func TestMFALogicService_VerifyAndActivate2FA_Failure_InvalidCode(t *testing.T) {
	ts := setupMFALogicServiceTestSuite(t)
	ctx := context.Background()
	userID := uuid.New()
	mfaSecretID := uuid.New()
	plainTOTPCode := "wrongcode"
	decryptedSecret := "DECRYPTEDSECRET"

	unverifiedSecret := &models.MFASecret{ID: mfaSecretID, UserID: userID, Type: models.MFATypeTOTP, SecretKeyEncrypted: "encrypted", Verified: false}

	ts.mockMfaSecretRepo.On("FindByID", ctx, mfaSecretID).Return(unverifiedSecret, nil).Once()
	ts.mockEncryptionSvc.On("Decrypt", "encrypted", ts.testMFAConfig.TOTPSecretEncryptionKey).Return(decryptedSecret, nil).Once()
	ts.mockTotpSvc.On("ValidateCode", decryptedSecret, plainTOTPCode).Return(false, nil).Once() // Code invalid
	ts.mockAudit.On("RecordEvent", ctx, &userID, "mfa_enable_verify_code", models.AuditLogStatusFailure, &userID, models.AuditTargetTypeMFASecret, mock.Anything, "unknown", "unknown").Once()

	_, err := ts.service.VerifyAndActivate2FA(ctx, userID, plainTOTPCode, mfaSecretID)
	assert.ErrorIs(t, err, domainErrors.ErrInvalid2FACode)
}

// --- Test Verify2FACode ---
func TestMFALogicService_Verify2FACode_TOTP_Success(t *testing.T) {
	ts := setupMFALogicServiceTestSuite(t)
	ctx := context.Background()
	userID := uuid.New()
	code := "123456"
	decryptedSecret := "totp-secret"
	mfaSecret := &models.MFASecret{UserID: userID, Type: models.MFATypeTOTP, SecretKeyEncrypted: "encrypted", Verified: true}

	ts.mockMfaSecretRepo.On("FindByUserIDAndType", ctx, userID, models.MFATypeTOTP).Return(mfaSecret, nil).Once()
	ts.mockEncryptionSvc.On("Decrypt", "encrypted", ts.testMFAConfig.TOTPSecretEncryptionKey).Return(decryptedSecret, nil).Once()
	ts.mockTotpSvc.On("ValidateCode", decryptedSecret, code).Return(true, nil).Once()
	// No audit log here directly, should be logged by calling function (e.g. Login)

	isValid, err := ts.service.Verify2FACode(ctx, userID, code, models.MFATypeTOTP)
	assert.NoError(t, err)
	assert.True(t, isValid)
	ts.mockMfaSecretRepo.AssertExpectations(t)
	ts.mockEncryptionSvc.AssertExpectations(t)
	ts.mockTotpSvc.AssertExpectations(t)
}

func TestMFALogicService_Verify2FACode_Backup_Success(t *testing.T) {
	ts := setupMFALogicServiceTestSuite(t)
	ctx := context.Background()
	userID := uuid.New()
	backupCodePlain := "backup123"
	hashedBackupCode := "hashed-backup123"
	backupCodeModel := &models.MFABackupCode{ID: uuid.New(), UserID: userID, CodeHash: hashedBackupCode, UsedAt: nil}

	ts.mockPassSvc.On("HashPassword", backupCodePlain).Return(hashedBackupCode, nil).Once()
	ts.mockMfaBackupRepo.On("FindByUserIDAndCodeHash", ctx, userID, hashedBackupCode).Return(backupCodeModel, nil).Once()
	ts.mockMfaBackupRepo.On("MarkAsUsed", ctx, backupCodeModel.ID, mock.AnythingOfType("time.Time")).Return(nil).Once()
	// TODO: Verify Kafka event for backup code used if added
	// ts.mockKafka.On("PublishCloudEvent", ... AuthMFABackupCodeUsedV1 ...).Return(nil).Once()


	isValid, err := ts.service.Verify2FACode(ctx, userID, backupCodePlain, models.MFATypeBackup) // Use models.MFATypeBackup
	assert.NoError(t, err)
	assert.True(t, isValid)
	ts.mockPassSvc.AssertExpectations(t)
	ts.mockMfaBackupRepo.AssertExpectations(t)
}

// TODO: Add more failure cases for Verify2FACode

// --- Placeholder for other tests ---
func TestMFALogicService_Disable2FA_NotImplemented(t *testing.T) {
	t.Skip("Disable2FA tests not implemented yet")
}
func TestMFALogicService_RegenerateBackupCodes_NotImplemented(t *testing.T) {
	t.Skip("RegenerateBackupCodes tests not implemented yet")
}

func init() {
	// Global test setup
}
