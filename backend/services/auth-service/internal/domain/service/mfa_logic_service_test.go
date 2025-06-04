package service

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"

	"github.com/your-org/auth-service/internal/config"
	"github.com/your-org/auth-service/internal/domain/models"
	domainErrors "github.com/your-org/auth-service/internal/domain/errors"
	repoInterfaces "github.com/your-org/auth-service/internal/repository/interfaces"
	// domainService "github.com/your-org/auth-service/internal/domain/service" // Not needed if MFALogicService is tested directly
	infraSec "github.com/your-org/auth-service/internal/infrastructure/security" // For mocks if needed
	eventMocks "github.com/your-org/auth-service/internal/events/mocks" // Assuming a kafka mock
	kafkaPkg "github.com/your-org/auth-service/internal/utils/kafka"   // Actual kafka client package for mock struct field
	"go.uber.org/zap"
)

// --- Mock RateLimiter (redefined for clarity, could be in a shared test util) ---
type MockRateLimiter struct {
	mock.Mock
}

func (m *MockRateLimiter) Allow(ctx context.Context, key string, rule config.RateLimitRule) (bool, error) {
	args := m.Called(ctx, key, rule)
	return args.Bool(0), args.Error(1)
}

// --- Mock TOTPService ---
type MockTOTPService struct {
	mock.Mock
}

func (m *MockTOTPService) GenerateSecret(accountName string, issuerName string) (string, string, error) {
	args := m.Called(accountName, issuerName)
	return args.String(0), args.String(1), args.Error(2)
}
func (m *MockTOTPService) ValidateCode(secret string, code string) (bool, error) {
	args := m.Called(secret, code)
	return args.Bool(0), args.Error(1)
}

// --- Mock EncryptionService ---
type MockEncryptionService struct {
	mock.Mock
	infraSec.EncryptionService // Embed interface
}
func (m *MockEncryptionService) Encrypt(text string, key string) (string, error) {
	args := m.Called(text, key)
	return args.String(0), args.Error(1)
}
func (m *MockEncryptionService) Decrypt(encryptedText string, key string) (string, error) {
	args := m.Called(encryptedText, key)
	return args.String(0), args.Error(1)
}

// --- Mock MFASecretRepository ---
type MockMFASecretRepository struct {
	mock.Mock
	repoInterfaces.MFASecretRepository
}
func (m *MockMFASecretRepository) Create(ctx context.Context, secret *models.MFASecret) error {
    args := m.Called(ctx, secret)
    return args.Error(0)
}
func (m *MockMFASecretRepository) FindByID(ctx context.Context, id uuid.UUID) (*models.MFASecret, error) {
    args := m.Called(ctx, id)
    if args.Get(0) == nil { return nil, args.Error(1) }
    return args.Get(0).(*models.MFASecret), args.Error(1)
}
func (m *MockMFASecretRepository) FindByUserIDAndType(ctx context.Context, userID uuid.UUID, mfaType models.MFAType) (*models.MFASecret, error) {
    args := m.Called(ctx, userID, mfaType)
     if args.Get(0) == nil { return nil, args.Error(1) }
    return args.Get(0).(*models.MFASecret), args.Error(1)
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

// --- Mock MFABackupCodeRepository ---
type MockMFABackupCodeRepository struct {
	mock.Mock
	repoInterfaces.MFABackupCodeRepository
}
func (m *MockMFABackupCodeRepository) CreateMultiple(ctx context.Context, codes []*models.MFABackupCode) error {
    args := m.Called(ctx, codes)
    return args.Error(0)
}
func (m *MockMFABackupCodeRepository) FindByUserIDAndCodeHash(ctx context.Context, userID uuid.UUID, codeHash string) (*models.MFABackupCode, error) {
    args := m.Called(ctx, userID, codeHash)
    if args.Get(0) == nil { return nil, args.Error(1) }
    return args.Get(0).(*models.MFABackupCode), args.Error(1)
}
func (m *MockMFABackupCodeRepository) MarkAsUsed(ctx context.Context, id uuid.UUID, usedAt time.Time) error {
    args := m.Called(ctx, id, usedAt)
    return args.Error(0)
}
func (m *MockMFABackupCodeRepository) DeleteByUserID(ctx context.Context, userID uuid.UUID) (int64, error) {
    args := m.Called(ctx, userID)
    return args.Get(0).(int64), args.Error(1)
}
func (m *MockMFABackupCodeRepository) FindByUserID(ctx context.Context, userID uuid.UUID) ([]*models.MFABackupCode, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.MFABackupCode), args.Error(1)
}


// --- Mock UserRepository (subset needed by MFALogicService) ---
type MockUserRepositoryForMFA struct {
	mock.Mock
	repoInterfaces.UserRepository
}
func (m *MockUserRepositoryForMFA) FindByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil { return nil, args.Error(1) }
	return args.Get(0).(*models.User), args.Error(1)
}
// Add other methods if MFALogicService calls them, e.g. Update


// --- Mock PasswordService (subset needed by MFALogicService) ---
type MockPasswordServiceForMFA struct {
	mock.Mock
}
func (m *MockPasswordServiceForMFA) HashPassword(plainPassword string) (string, error) {
	args := m.Called(plainPassword)
	return args.String(0), args.Error(1)
}
func (m *MockPasswordServiceForMFA) CheckPasswordHash(plainPassword, hashedPassword string) (bool, error) {
	args := m.Called(plainPassword, hashedPassword)
	return args.Bool(0), args.Error(1)
}

// --- Mock AuditLogRecorder ---
type MockAuditLogRecorder struct {
	mock.Mock
}
func (m *MockAuditLogRecorder) RecordEvent(ctx context.Context, actorUserID *uuid.UUID, eventName string, status models.AuditLogStatus, targetUserID *uuid.UUID, targetType models.AuditTargetType, details map[string]interface{}, ipAddress string, userAgent string) {
	m.Called(ctx, actorUserID, eventName, status, targetUserID, targetType, details, ipAddress, userAgent)
}


// --- MFALogicService Test Suite ---
type MFALogicServiceTestSuite struct {
	suite.Suite
	mfaService          MFALogicService // Interface type
	mockTotpService     *MockTOTPService
	mockEncryptionSvc   *MockEncryptionService
	mockMfaSecretRepo   *MockMFASecretRepository
	mockMfaBackupRepo   *MockMFABackupCodeRepository
	mockUserRepo        *MockUserRepositoryForMFA
	mockPasswordService *MockPasswordServiceForMFA
	mockAuditRecorder   *MockAuditLogRecorder
	mockKafkaProducer   *eventMocks.MockProducer // Use the existing mock from AuthService tests if in same package, or define here
	mockRateLimiter     *MockRateLimiter
	cfg                 *config.Config
	logger              *zap.Logger
}

func (s *MFALogicServiceTestSuite) SetupTest() {
	s.mockTotpService = new(MockTOTPService)
	s.mockEncryptionSvc = new(MockEncryptionService)
	s.mockMfaSecretRepo = new(MockMFASecretRepository)
	s.mockMfaBackupRepo = new(MockMFABackupCodeRepository)
	s.mockUserRepo = new(MockUserRepositoryForMFA)
	s.mockPasswordService = new(MockPasswordServiceForMFA)
	s.mockAuditRecorder = new(MockAuditLogRecorder)
	s.mockKafkaProducer = new(eventMocks.MockProducer) // Ensure this mock is correctly accessible/defined
	s.mockRateLimiter = new(MockRateLimiter)

	s.logger, _ = zap.NewDevelopment()
	s.cfg = &config.Config{
		MFA: config.MFAConfig{
			TOTPIssuerName:          "TestPlatform",
			TOTPSecretEncryptionKey: "test_encryption_key_32_bytes_!", // Must be 32 bytes for AES-256
			TOTPBackupCodeCount:     5,
		},
		Security: config.SecurityConfig{
			RateLimiting: config.RateLimitConfig{
				Enabled: true,
				TwoFAVerificationPerUser: config.RateLimitRule{Enabled: true, Limit: 5, Window: 15 * time.Minute},
			},
		},
		Kafka: config.KafkaConfig{Producer: config.KafkaProducerConfig{Topic: "test-events"}},
	}

	s.mfaService = NewMFALogicService(
		s.cfg, // Pass global config
		s.mockTotpService,
		s.mockEncryptionSvc,
		s.mockMfaSecretRepo,
		s.mockMfaBackupRepo,
		s.mockUserRepo,
		s.mockPasswordService,
		s.mockAuditRecorder,
		s.mockKafkaProducer, // Ensure this matches constructor
		s.mockRateLimiter,
	)
}

func TestMFALogicServiceTestSuite(t *testing.T) {
	suite.Run(t, new(MFALogicServiceTestSuite))
}

// --- Test Cases for Verify2FACode ---

func (s *MFALogicServiceTestSuite) TestVerify2FACode_RateLimitExceeded() {
	ctx := context.Background()
	userID := uuid.New()
	code := "123456"
	codeType := models.MFATypeTOTP

	metadataCtx := context.WithValue(ctx, "metadata", map[string]string{"ip-address": "127.0.0.1", "user-agent": "test-agent"})
	rateKey := "2faverify_user:" + userID.String()
	rule := s.cfg.Security.RateLimiting.TwoFAVerificationPerUser

	s.mockRateLimiter.On("Allow", metadataCtx, rateKey, rule).Return(false, nil).Once()

	expectedAuditDetails := map[string]interface{}{
		"code_type": string(codeType),
		"error":     domainErrors.ErrRateLimitExceeded.Error(),
	}
	s.mockAuditRecorder.On("RecordEvent", metadataCtx, &userID, "mfa_code_verify", models.AuditLogStatusFailure, &userID, models.AuditTargetTypeUser, expectedAuditDetails, "127.0.0.1", "test-agent").Once()

	isValid, err := s.mfaService.Verify2FACode(metadataCtx, userID, code, codeType)

	assert.False(s.T(), isValid)
	assert.ErrorIs(s.T(), err, domainErrors.ErrRateLimitExceeded)
	s.mockRateLimiter.AssertExpectations(s.T())
	s.mockAuditRecorder.AssertExpectations(s.T())
	s.mockMfaSecretRepo.AssertNotCalled(s.T(), "FindByUserIDAndType", mock.Anything, mock.Anything, mock.Anything)
}

func (s *MFALogicServiceTestSuite) TestVerify2FACode_TOTP_Success() {
	ctx := context.Background()
	userID := uuid.New()
	code := "123456"
	mfaSecretKey := "base32secretkey"
	encryptedSecret := "encryptedBase32Secret"

	metadataCtx := context.WithValue(ctx, "metadata", map[string]string{"ip-address": "127.0.0.1", "user-agent": "test-agent"})
	rateKey := "2faverify_user:" + userID.String()
	rule := s.cfg.Security.RateLimiting.TwoFAVerificationPerUser

	s.mockRateLimiter.On("Allow", metadataCtx, rateKey, rule).Return(true, nil).Once()

	mfaSecret := &models.MFASecret{UserID: userID, Type: models.MFATypeTOTP, SecretKeyEncrypted: encryptedSecret, Verified: true}
	s.mockMfaSecretRepo.On("FindByUserIDAndType", metadataCtx, userID, models.MFATypeTOTP).Return(mfaSecret, nil).Once()
	s.mockEncryptionSvc.On("Decrypt", encryptedSecret, s.cfg.MFA.TOTPSecretEncryptionKey).Return(mfaSecretKey, nil).Once()
	s.mockTotpService.On("ValidateCode", mfaSecretKey, code).Return(true, nil).Once()

	expectedAuditDetails := map[string]interface{}{"code_type": string(models.MFATypeTOTP)}
	s.mockAuditRecorder.On("RecordEvent", metadataCtx, &userID, "mfa_code_verify", models.AuditLogStatusSuccess, &userID, models.AuditTargetTypeUser, expectedAuditDetails, "127.0.0.1", "test-agent").Once()


	isValid, err := s.mfaService.Verify2FACode(metadataCtx, userID, code, models.MFATypeTOTP)

	assert.True(s.T(), isValid)
	assert.NoError(s.T(), err)
	s.mockRateLimiter.AssertExpectations(s.T())
	s.mockMfaSecretRepo.AssertExpectations(s.T())
	s.mockEncryptionSvc.AssertExpectations(s.T())
	s.mockTotpService.AssertExpectations(s.T())
	s.mockAuditRecorder.AssertExpectations(s.T())
}

func (s *MFALogicServiceTestSuite) TestVerify2FACode_Backup_Success() {
	ctx := context.Background()
	userID := uuid.New()
	backupCodePlain := "backup123"

	metadataCtx := context.WithValue(ctx, "metadata", map[string]string{"ip-address": "127.0.0.1", "user-agent": "test-agent"})
	rateKey := "2faverify_user:" + userID.String()
	rule := s.cfg.Security.RateLimiting.TwoFAVerificationPerUser

	s.mockRateLimiter.On("Allow", metadataCtx, rateKey, rule).Return(true, nil).Once()

	hashedBackupCode := "hashed-" + backupCodePlain // Simplified for test
	backupCodeModel := &models.MFABackupCode{ID: uuid.New(), UserID: userID, CodeHash: hashedBackupCode}

	// Mock FindByUserID to return a list containing the matching code
	s.mockMfaBackupRepo.On("FindByUserID", metadataCtx, userID).Return([]*models.MFABackupCode{backupCodeModel}, nil).Once()
	s.mockPasswordService.On("CheckPasswordHash", backupCodePlain, hashedBackupCode).Return(true, nil).Once()
	s.mockMfaBackupRepo.On("MarkAsUsed", metadataCtx, backupCodeModel.ID, mock.AnythingOfType("time.Time")).Return(nil).Once()

	expectedAuditDetails := map[string]interface{}{
		"code_type": string(models.MFATypeBackup),
		"backup_code_id_used": backupCodeModel.ID.String(),
	}
	s.mockAuditRecorder.On("RecordEvent", metadataCtx, &userID, "mfa_code_verify", models.AuditLogStatusSuccess, &userID, models.AuditTargetTypeUser, expectedAuditDetails, "127.0.0.1", "test-agent").Once()

	isValid, err := s.mfaService.Verify2FACode(metadataCtx, userID, backupCodePlain, models.MFATypeBackup)

	assert.True(s.T(), isValid)
	assert.NoError(s.T(), err)
	s.mockRateLimiter.AssertExpectations(s.T())
	s.mockMfaBackupRepo.AssertExpectations(s.T())
	s.mockPasswordService.AssertExpectations(s.T())
	s.mockAuditRecorder.AssertExpectations(s.T())
}

// --- Tests for Disable2FA ---

func (s *MFALogicServiceTestSuite) TestDisable2FA_Success_WithPassword() {
	ctx := context.Background()
	userID := uuid.New()
	password := "correctpassword"
	metadataCtx := context.WithValue(ctx, "metadata", map[string]string{"ip-address": "127.0.0.1", "user-agent": "test-agent"})

	user := &models.User{ID: userID, PasswordHash: "hashedcorrectpassword"}
	s.mockUserRepo.On("FindByID", metadataCtx, userID).Return(user, nil).Once()
	s.mockPasswordService.On("CheckPasswordHash", password, user.PasswordHash).Return(true, nil).Once()

	s.mockMfaSecretRepo.On("DeleteAllForUser", metadataCtx, userID).Return(int64(1), nil).Once() // Assume 1 secret deleted
	s.mockMfaBackupRepo.On("DeleteByUserID", metadataCtx, userID).Return(int64(5), nil).Once()   // Assume 5 backup codes deleted

	s.mockKafkaProducer.On("PublishCloudEvent", metadataCtx, s.cfg.Kafka.Producer.Topic, eventModels.AuthMFADisabledV1, userID.String(), mock.AnythingOfType("eventModels.MFADisabledPayload")).Return(nil).Once()
	s.mockAuditRecorder.On("RecordEvent", metadataCtx, &userID, "mfa_disable", models.AuditLogStatusSuccess, &userID, models.AuditTargetTypeUser, mock.Anything, "127.0.0.1", "test-agent").Once()

	err := s.mfaService.Disable2FA(metadataCtx, userID, password, "password")
	assert.NoError(s.T(), err)
	s.mockUserRepo.AssertExpectations(s.T())
	s.mockPasswordService.AssertExpectations(s.T())
	s.mockMfaSecretRepo.AssertExpectations(s.T())
	s.mockMfaBackupRepo.AssertExpectations(s.T())
	s.mockKafkaProducer.AssertExpectations(s.T())
	s.mockAuditRecorder.AssertExpectations(s.T())
}

func (s *MFALogicServiceTestSuite) TestDisable2FA_Success_WithTOTP() {
	ctx := context.Background()
	userID := uuid.New()
	totpCode := "valid_totp"
	metadataCtx := context.WithValue(ctx, "metadata", map[string]string{"ip-address": "127.0.0.1", "user-agent": "test-agent"})

	// Mock successful Verify2FACode call for TOTP
	rateLimitRule := s.cfg.Security.RateLimiting.TwoFAVerificationPerUser
	rateKey := "2faverify_user:" + userID.String()
	s.mockRateLimiter.On("Allow", metadataCtx, rateKey, rateLimitRule).Return(true, nil).Once() // For the Verify2FACode call inside Disable2FA

	mfaSecret := &models.MFASecret{UserID: userID, Type: models.MFATypeTOTP, SecretKeyEncrypted: "secret", Verified: true}
	s.mockMfaSecretRepo.On("FindByUserIDAndType", metadataCtx, userID, models.MFATypeTOTP).Return(mfaSecret, nil).Once()
	s.mockEncryptionSvc.On("Decrypt", "secret", s.cfg.MFA.TOTPSecretEncryptionKey).Return("decrypted_secret", nil).Once()
	s.mockTotpService.On("ValidateCode", "decrypted_secret", totpCode).Return(true, nil).Once()
	s.mockAuditRecorder.On("RecordEvent", metadataCtx, &userID, "mfa_code_verify", models.AuditLogStatusSuccess, &userID, models.AuditTargetTypeUser, mock.Anything, "127.0.0.1", "test-agent").Once()


	s.mockMfaSecretRepo.On("DeleteAllForUser", metadataCtx, userID).Return(int64(1), nil).Once()
	s.mockMfaBackupRepo.On("DeleteByUserID", metadataCtx, userID).Return(int64(5), nil).Once()
	s.mockKafkaProducer.On("PublishCloudEvent", metadataCtx, s.cfg.Kafka.Producer.Topic, eventModels.AuthMFADisabledV1, userID.String(), mock.AnythingOfType("eventModels.MFADisabledPayload")).Return(nil).Once()
	s.mockAuditRecorder.On("RecordEvent", metadataCtx, &userID, "mfa_disable", models.AuditLogStatusSuccess, &userID, models.AuditTargetTypeUser, mock.Anything, "127.0.0.1", "test-agent").Once()


	err := s.mfaService.Disable2FA(metadataCtx, userID, totpCode, "totp")
	assert.NoError(s.T(), err)
	s.mockRateLimiter.AssertExpectations(s.T())
	s.mockMfaSecretRepo.AssertExpectations(s.T()) // Called for Find and Delete
	s.mockEncryptionSvc.AssertExpectations(s.T())
	s.mockTotpService.AssertExpectations(s.T())
	s.mockMfaBackupRepo.AssertExpectations(s.T())
	s.mockKafkaProducer.AssertExpectations(s.T())
	s.mockAuditRecorder.AssertExpectations(s.T()) // Called for verify and disable
}


func (s *MFALogicServiceTestSuite) TestDisable2FA_AuthFailed_WrongPassword() {
	ctx := context.Background()
	userID := uuid.New()
	password := "wrongpassword"
	metadataCtx := context.WithValue(ctx, "metadata", map[string]string{"ip-address": "127.0.0.1", "user-agent": "test-agent"})

	user := &models.User{ID: userID, PasswordHash: "hashedcorrectpassword"}
	s.mockUserRepo.On("FindByID", metadataCtx, userID).Return(user, nil).Once()
	s.mockPasswordService.On("CheckPasswordHash", password, user.PasswordHash).Return(false, nil).Once() // Password check fails

	expectedAuditDetails := map[string]interface{}{
		"error": domainErrors.ErrForbidden.Error(), "reason": "authorization failed", "verification_method": "password",
	}
	s.mockAuditRecorder.On("RecordEvent", metadataCtx, &userID, "mfa_disable_authfail", models.AuditLogStatusFailure, &userID, models.AuditTargetTypeUser, expectedAuditDetails, "127.0.0.1", "test-agent").Once()

	err := s.mfaService.Disable2FA(metadataCtx, userID, password, "password")
	assert.ErrorIs(s.T(), err, domainErrors.ErrForbidden)
	s.mockUserRepo.AssertExpectations(s.T())
	s.mockPasswordService.AssertExpectations(s.T())
	s.mockAuditRecorder.AssertExpectations(s.T())
	s.mockMfaSecretRepo.AssertNotCalled(s.T(), "DeleteAllForUser") // Deletion should not be called
}

func (s *MFALogicServiceTestSuite) TestDisable2FA_AuthFailed_InvalidTOTP() {
    ctx := context.Background()
    userID := uuid.New()
    invalidTotpCode := "invalid_totp"
    metadataCtx := context.WithValue(ctx, "metadata", map[string]string{"ip-address": "127.0.0.1", "user-agent": "test-agent"})

    // Mock Verify2FACode to return false for TOTP
	rateLimitRule := s.cfg.Security.RateLimiting.TwoFAVerificationPerUser
	rateKey := "2faverify_user:" + userID.String()
	s.mockRateLimiter.On("Allow", metadataCtx, rateKey, rateLimitRule).Return(true, nil).Once()

	s.mockMfaSecretRepo.On("FindByUserIDAndType", metadataCtx, userID, models.MFATypeTOTP).Return(nil, domainErrors.Err2FANotEnabled).Once() // Or return invalid code error

	// Audit for mfa_code_verify (failure)
	auditDetailsVerify := map[string]interface{}{
		"code_type": string(models.MFATypeTOTP),
		"error": domainErrors.Err2FANotEnabled.Error(),
	}
	s.mockAuditRecorder.On("RecordEvent", metadataCtx, &userID, "mfa_code_verify", models.AuditLogStatusFailure, &userID, models.AuditTargetTypeUser, auditDetailsVerify, "127.0.0.1", "test-agent").Once()

	// Audit for mfa_disable_authfail
    expectedAuditDetailsDisable := map[string]interface{}{
        "error": domainErrors.ErrForbidden.Error(), "reason": "authorization failed", "verification_method": "totp",
    }
    s.mockAuditRecorder.On("RecordEvent", metadataCtx, &userID, "mfa_disable_authfail", models.AuditLogStatusFailure, &userID, models.AuditTargetTypeUser, expectedAuditDetailsDisable, "127.0.0.1", "test-agent").Once()


    err := s.mfaService.Disable2FA(metadataCtx, userID, invalidTotpCode, "totp")
    assert.ErrorIs(s.T(), err, domainErrors.ErrForbidden) // Outer error from Disable2FA
	s.mockRateLimiter.AssertExpectations(s.T())
    s.mockMfaSecretRepo.AssertExpectations(s.T()) // For FindByUserIDAndType
    s.mockAuditRecorder.AssertExpectations(s.T()) // For both mfa_code_verify and mfa_disable_authfail
}


func (s *MFALogicServiceTestSuite) TestDisable2FA_NoMFAEnabled() {
	// This scenario is tricky because isUserAuthorizedForSensitiveAction might try to verify password
	// if MFAType is password, or fail if MFAType is TOTP/Backup and no secrets exist.
	// The Disable2FA method itself doesn't explicitly check if MFA is enabled before attempting auth.
	// The auth check itself might fail (e.g., Verify2FACode returns Err2FANotEnabled).
	// Let's assume verification method is password, and it passes, but then Delete returns 0.
	ctx := context.Background()
	userID := uuid.New()
	password := "correctpassword"
	metadataCtx := context.WithValue(ctx, "metadata", map[string]string{"ip-address": "127.0.0.1", "user-agent": "test-agent"})

	user := &models.User{ID: userID, PasswordHash: "hashedcorrectpassword"}
	s.mockUserRepo.On("FindByID", metadataCtx, userID).Return(user, nil).Once()
	s.mockPasswordService.On("CheckPasswordHash", password, user.PasswordHash).Return(true, nil).Once()

	s.mockMfaSecretRepo.On("DeleteAllForUser", metadataCtx, userID).Return(int64(0), nil).Once() // No secrets deleted
	s.mockMfaBackupRepo.On("DeleteByUserID", metadataCtx, userID).Return(int64(0), nil).Once()   // No backup codes deleted

	// No Kafka event should be published if nothing was effectively disabled.
	// Audit log should indicate success but with info that nothing was enabled.
	expectedAuditDetails := map[string]interface{}{
		"info": domainErrors.Err2FANotEnabled.Error(), "secrets_deleted_count": int64(0), "backup_codes_deleted_count": int64(0),
	}
	s.mockAuditRecorder.On("RecordEvent", metadataCtx, &userID, "mfa_disable", models.AuditLogStatusSuccess, &userID, models.AuditTargetTypeUser, expectedAuditDetails, "127.0.0.1", "test-agent").Once()

	err := s.mfaService.Disable2FA(metadataCtx, userID, password, "password")
	assert.NoError(s.T(), err) // Should not error, but effectively does nothing if already disabled.
	s.mockMfaSecretRepo.AssertExpectations(s.T())
	s.mockMfaBackupRepo.AssertExpectations(s.T())
	s.mockAuditRecorder.AssertExpectations(s.T())
	s.mockKafkaProducer.AssertNotCalled(s.T(), "PublishCloudEvent")
}

func (s *MFALogicServiceTestSuite) TestDisable2FA_RepoDeleteSecretError() {
	ctx := context.Background()
	userID := uuid.New()
	password := "correctpassword"
	metadataCtx := context.WithValue(ctx, "metadata", map[string]string{"ip-address": "127.0.0.1", "user-agent": "test-agent"})

	user := &models.User{ID: userID, PasswordHash: "hashedcorrectpassword"}
	s.mockUserRepo.On("FindByID", metadataCtx, userID).Return(user, nil).Once()
	s.mockPasswordService.On("CheckPasswordHash", password, user.PasswordHash).Return(true, nil).Once()

	s.mockMfaSecretRepo.On("DeleteAllForUser", metadataCtx, userID).Return(int64(0), errors.New("db error delete secret")).Once()

	expectedAuditDetails := map[string]interface{}{
		"error": "failed to delete MFA secrets", "details": errors.New("db error delete secret").Error(),
	}
	s.mockAuditRecorder.On("RecordEvent", metadataCtx, &userID, "mfa_disable", models.AuditLogStatusFailure, &userID, models.AuditTargetTypeUser, expectedAuditDetails, "127.0.0.1", "test-agent").Once()

	err := s.mfaService.Disable2FA(metadataCtx, userID, password, "password")
	assert.ErrorContains(s.T(), err, "failed to delete MFA secrets")
	s.mockMfaSecretRepo.AssertExpectations(s.T())
	s.mockAuditRecorder.AssertExpectations(s.T())
	s.mockMfaBackupRepo.AssertNotCalled(s.T(), "DeleteByUserID") // Should not be called if secret deletion fails
	s.mockKafkaProducer.AssertNotCalled(s.T(), "PublishCloudEvent")
}

// --- Tests for RegenerateBackupCodes ---

func (s *MFALogicServiceTestSuite) TestRegenerateBackupCodes_Success_WithPassword() {
	ctx := context.Background()
	userID := uuid.New()
	password := "correctpassword"
	metadataCtx := context.WithValue(ctx, "metadata", map[string]string{"ip-address": "127.0.0.1", "user-agent": "test-agent"})

	user := &models.User{ID: userID, PasswordHash: "hashedcorrectpassword"}
	s.mockUserRepo.On("FindByID", metadataCtx, userID).Return(user, nil).Once()
	s.mockPasswordService.On("CheckPasswordHash", password, user.PasswordHash).Return(true, nil).Once()

	mfaSecret := &models.MFASecret{UserID: userID, Type: models.MFATypeTOTP, Verified: true}
	s.mockMfaSecretRepo.On("FindByUserIDAndType", metadataCtx, userID, models.MFATypeTOTP).Return(mfaSecret, nil).Once()

	s.mockMfaBackupRepo.On("DeleteByUserID", metadataCtx, userID).Return(int64(5), nil).Once() // Old codes deleted
	s.mockPasswordService.On("HashPassword", mock.AnythingOfType("string")).Return("hashedbackupcode", nil).Times(s.cfg.MFA.TOTPBackupCodeCount) // Mock hashing for new codes
	s.mockMfaBackupRepo.On("CreateMultiple", metadataCtx, mock.AnythingOfType("[]*models.MFABackupCode")).Run(func(args mock.Arguments) {
		codes := args.Get(1).([]*models.MFABackupCode)
		assert.Len(s.T(), codes, s.cfg.MFA.TOTPBackupCodeCount)
	}).Return(nil).Once()

	expectedAuditDetails := map[string]interface{}{"backup_codes_generated": s.cfg.MFA.TOTPBackupCodeCount}
	s.mockAuditRecorder.On("RecordEvent", metadataCtx, &userID, "mfa_backup_codes_regenerate", models.AuditLogStatusSuccess, &userID, models.AuditTargetTypeUser, expectedAuditDetails, "127.0.0.1", "test-agent").Once()

	backupCodes, err := s.mfaService.RegenerateBackupCodes(metadataCtx, userID, password, "password")
	assert.NoError(s.T(), err)
	assert.Len(s.T(), backupCodes, s.cfg.MFA.TOTPBackupCodeCount)
	s.mockUserRepo.AssertExpectations(s.T())
	s.mockPasswordService.AssertExpectations(s.T()) // For Check and Hash
	s.mockMfaSecretRepo.AssertExpectations(s.T())
	s.mockMfaBackupRepo.AssertExpectations(s.T()) // For Delete and CreateMultiple
	s.mockAuditRecorder.AssertExpectations(s.T())
}

func (s *MFALogicServiceTestSuite) TestRegenerateBackupCodes_AuthFailed() {
	ctx := context.Background()
	userID := uuid.New()
	password := "wrongpassword"
	metadataCtx := context.WithValue(ctx, "metadata", map[string]string{"ip-address": "127.0.0.1", "user-agent": "test-agent"})

	user := &models.User{ID: userID, PasswordHash: "hashedcorrectpassword"}
	s.mockUserRepo.On("FindByID", metadataCtx, userID).Return(user, nil).Once()
	s.mockPasswordService.On("CheckPasswordHash", password, user.PasswordHash).Return(false, nil).Once() // Auth fails

	expectedAuditDetails := map[string]interface{}{
		"error": domainErrors.ErrForbidden.Error(), "reason": "authorization failed", "verification_method": "password",
	}
	s.mockAuditRecorder.On("RecordEvent", metadataCtx, &userID, "mfa_backup_codes_regenerate", models.AuditLogStatusFailure, &userID, models.AuditTargetTypeUser, expectedAuditDetails, "127.0.0.1", "test-agent").Once()

	_, err := s.mfaService.RegenerateBackupCodes(metadataCtx, userID, password, "password")
	assert.ErrorIs(s.T(), err, domainErrors.ErrForbidden)
	s.mockAuditRecorder.AssertExpectations(s.T())
	s.mockMfaSecretRepo.AssertNotCalled(s.T(), "FindByUserIDAndType") // Should not proceed
}

func (s *MFALogicServiceTestSuite) TestRegenerateBackupCodes_MFANotActive() {
	ctx := context.Background()
	userID := uuid.New()
	password := "correctpassword"
	metadataCtx := context.WithValue(ctx, "metadata", map[string]string{"ip-address": "127.0.0.1", "user-agent": "test-agent"})

	user := &models.User{ID: userID, PasswordHash: "hashedcorrectpassword"}
	s.mockUserRepo.On("FindByID", metadataCtx, userID).Return(user, nil).Once()
	s.mockPasswordService.On("CheckPasswordHash", password, user.PasswordHash).Return(true, nil).Once() // Auth success

	// MFA not active/verified
	mfaSecret := &models.MFASecret{UserID: userID, Type: models.MFATypeTOTP, Verified: false}
	s.mockMfaSecretRepo.On("FindByUserIDAndType", metadataCtx, userID, models.MFATypeTOTP).Return(mfaSecret, nil).Once()

	expectedAuditDetails := map[string]interface{}{"error": domainErrors.ErrMFANotVerified.Error()}
	s.mockAuditRecorder.On("RecordEvent", metadataCtx, &userID, "mfa_backup_codes_regenerate", models.AuditLogStatusFailure, &userID, models.AuditTargetTypeUser, expectedAuditDetails, "127.0.0.1", "test-agent").Once()

	_, err := s.mfaService.RegenerateBackupCodes(metadataCtx, userID, password, "password")
	assert.ErrorIs(s.T(), err, domainErrors.ErrMFANotVerified)
	s.mockMfaSecretRepo.AssertExpectations(s.T())
	s.mockAuditRecorder.AssertExpectations(s.T())
}

func (s *MFALogicServiceTestSuite) TestRegenerateBackupCodes_DeleteOldFails() {
	ctx := context.Background()
	userID := uuid.New()
	password := "correctpassword"
	metadataCtx := context.WithValue(ctx, "metadata", map[string]string{"ip-address": "127.0.0.1", "user-agent": "test-agent"})

	user := &models.User{ID: userID, PasswordHash: "hashedcorrectpassword"}
	s.mockUserRepo.On("FindByID", metadataCtx, userID).Return(user, nil).Once()
	s.mockPasswordService.On("CheckPasswordHash", password, user.PasswordHash).Return(true, nil).Once()

	mfaSecret := &models.MFASecret{UserID: userID, Type: models.MFATypeTOTP, Verified: true}
	s.mockMfaSecretRepo.On("FindByUserIDAndType", metadataCtx, userID, models.MFATypeTOTP).Return(mfaSecret, nil).Once()

	s.mockMfaBackupRepo.On("DeleteByUserID", metadataCtx, userID).Return(int64(0), errors.New("db delete error")).Once()

	expectedAuditDetails := map[string]interface{}{
		"error": "could not delete old backup codes", "details": errors.New("db delete error").Error(),
	}
	s.mockAuditRecorder.On("RecordEvent", metadataCtx, &userID, "mfa_backup_codes_regenerate", models.AuditLogStatusFailure, &userID, models.AuditTargetTypeUser, expectedAuditDetails, "127.0.0.1", "test-agent").Once()

	_, err := s.mfaService.RegenerateBackupCodes(metadataCtx, userID, password, "password")
	assert.ErrorContains(s.T(), err, "could not delete old backup codes")
	s.mockMfaBackupRepo.AssertExpectations(s.T())
	s.mockAuditRecorder.AssertExpectations(s.T())
}

func (s *MFALogicServiceTestSuite) TestRegenerateBackupCodes_CreateNewFails() {
	ctx := context.Background()
	userID := uuid.New()
	password := "correctpassword"
	metadataCtx := context.WithValue(ctx, "metadata", map[string]string{"ip-address": "127.0.0.1", "user-agent": "test-agent"})

	user := &models.User{ID: userID, PasswordHash: "hashedcorrectpassword"}
	s.mockUserRepo.On("FindByID", metadataCtx, userID).Return(user, nil).Once()
	s.mockPasswordService.On("CheckPasswordHash", password, user.PasswordHash).Return(true, nil).Once()

	mfaSecret := &models.MFASecret{UserID: userID, Type: models.MFATypeTOTP, Verified: true}
	s.mockMfaSecretRepo.On("FindByUserIDAndType", metadataCtx, userID, models.MFATypeTOTP).Return(mfaSecret, nil).Once()

	s.mockMfaBackupRepo.On("DeleteByUserID", metadataCtx, userID).Return(int64(5), nil).Once()
	s.mockPasswordService.On("HashPassword", mock.AnythingOfType("string")).Return("hashedbackupcode", nil).Times(s.cfg.MFA.TOTPBackupCodeCount)
	s.mockMfaBackupRepo.On("CreateMultiple", metadataCtx, mock.AnythingOfType("[]*models.MFABackupCode")).Return(errors.New("db create error")).Once()

	expectedAuditDetails := map[string]interface{}{
		"error": "failed to store regenerated backup codes", "details": errors.New("db create error").Error(),
	}
	s.mockAuditRecorder.On("RecordEvent", metadataCtx, &userID, "mfa_backup_codes_regenerate", models.AuditLogStatusFailure, &userID, models.AuditTargetTypeUser, expectedAuditDetails, "127.0.0.1", "test-agent").Once()

	_, err := s.mfaService.RegenerateBackupCodes(metadataCtx, userID, password, "password")
	assert.ErrorContains(s.T(), err, "failed to store regenerated backup codes")
	s.mockMfaBackupRepo.AssertExpectations(s.T()) // Delete and CreateMultiple called
	s.mockAuditRecorder.AssertExpectations(s.T())
}

// Add more tests for other failure cases of Verify2FACode, ensuring RateLimiter.Allow is called and returns true.
// For example, invalid TOTP code, invalid backup code, 2FA not enabled, etc.
// Each of these should still pass the rate limiter check first.

func (s *MFALogicServiceTestSuite) TestVerify2FACode_TOTP_NotEnabled() {
	ctx := context.Background()
	userID := uuid.New()
	code := "123456"
	metadataCtx := context.WithValue(ctx, "metadata", map[string]string{"ip-address": "127.0.0.1", "user-agent": "test-agent"})
	rateKey := "2faverify_user:" + userID.String()
	rule := s.cfg.Security.RateLimiting.TwoFAVerificationPerUser

	s.mockRateLimiter.On("Allow", metadataCtx, rateKey, rule).Return(true, nil).Once()
	s.mockMfaSecretRepo.On("FindByUserIDAndType", metadataCtx, userID, models.MFATypeTOTP).Return(nil, domainErrors.ErrNotFound).Once()

	expectedAuditDetails := map[string]interface{}{
		"code_type": string(models.MFATypeTOTP),
		"error":     domainErrors.Err2FANotEnabled.Error(),
	}
	s.mockAuditRecorder.On("RecordEvent", metadataCtx, &userID, "mfa_code_verify", models.AuditLogStatusFailure, &userID, models.AuditTargetTypeUser, expectedAuditDetails, "127.0.0.1", "test-agent").Once()

	isValid, err := s.mfaService.Verify2FACode(metadataCtx, userID, code, models.MFATypeTOTP)
	assert.False(s.T(), isValid)
	assert.ErrorIs(s.T(), err, domainErrors.Err2FANotEnabled)
	s.mockRateLimiter.AssertExpectations(s.T())
	s.mockMfaSecretRepo.AssertExpectations(s.T())
	s.mockAuditRecorder.AssertExpectations(s.T())
}

func (s *MFALogicServiceTestSuite) TestVerify2FACode_TOTP_NotVerified() {
	ctx := context.Background()
	userID := uuid.New()
	code := "123456"
	metadataCtx := context.WithValue(ctx, "metadata", map[string]string{"ip-address": "127.0.0.1", "user-agent": "test-agent"})
	rateKey := "2faverify_user:" + userID.String()
	rule := s.cfg.Security.RateLimiting.TwoFAVerificationPerUser

	s.mockRateLimiter.On("Allow", metadataCtx, rateKey, rule).Return(true, nil).Once()
	mfaSecret := &models.MFASecret{UserID: userID, Type: models.MFATypeTOTP, Verified: false} // Not verified
	s.mockMfaSecretRepo.On("FindByUserIDAndType", metadataCtx, userID, models.MFATypeTOTP).Return(mfaSecret, nil).Once()

	expectedAuditDetails := map[string]interface{}{
		"code_type": string(models.MFATypeTOTP),
		"error":     domainErrors.ErrMFANotVerified.Error(),
	}
	s.mockAuditRecorder.On("RecordEvent", metadataCtx, &userID, "mfa_code_verify", models.AuditLogStatusFailure, &userID, models.AuditTargetTypeUser, expectedAuditDetails, "127.0.0.1", "test-agent").Once()

	isValid, err := s.mfaService.Verify2FACode(metadataCtx, userID, code, models.MFATypeTOTP)
	assert.False(s.T(), isValid)
	assert.ErrorIs(s.T(), err, domainErrors.ErrMFANotVerified)
	s.mockMfaSecretRepo.AssertExpectations(s.T())
	s.mockAuditRecorder.AssertExpectations(s.T())
}

func (s *MFALogicServiceTestSuite) TestVerify2FACode_TOTP_SecretDecryptionFails() {
	ctx := context.Background()
	userID := uuid.New()
	code := "123456"
	encryptedSecret := "encryptedSecret"
	metadataCtx := context.WithValue(ctx, "metadata", map[string]string{"ip-address": "127.0.0.1", "user-agent": "test-agent"})
	rateKey := "2faverify_user:" + userID.String()
	rule := s.cfg.Security.RateLimiting.TwoFAVerificationPerUser

	s.mockRateLimiter.On("Allow", metadataCtx, rateKey, rule).Return(true, nil).Once()
	mfaSecret := &models.MFASecret{UserID: userID, Type: models.MFATypeTOTP, SecretKeyEncrypted: encryptedSecret, Verified: true}
	s.mockMfaSecretRepo.On("FindByUserIDAndType", metadataCtx, userID, models.MFATypeTOTP).Return(mfaSecret, nil).Once()
	s.mockEncryptionSvc.On("Decrypt", encryptedSecret, s.cfg.MFA.TOTPSecretEncryptionKey).Return("", errors.New("decryption failed")).Once()

	expectedAuditDetails := map[string]interface{}{
		"code_type": string(models.MFATypeTOTP),
		"error":     "failed to decrypt TOTP secret", // This is the specific error message from the service
		"details":   errors.New("decryption failed").Error(),
	}
	s.mockAuditRecorder.On("RecordEvent", metadataCtx, &userID, "mfa_code_verify", models.AuditLogStatusFailure, &userID, models.AuditTargetTypeUser, expectedAuditDetails, "127.0.0.1", "test-agent").Once()

	isValid, err := s.mfaService.Verify2FACode(metadataCtx, userID, code, models.MFATypeTOTP)
	assert.False(s.T(), isValid)
	assert.ErrorContains(s.T(), err, "failed to decrypt TOTP secret")
	s.mockEncryptionSvc.AssertExpectations(s.T())
	s.mockAuditRecorder.AssertExpectations(s.T())
}

func (s *MFALogicServiceTestSuite) TestVerify2FACode_TOTP_ValidateCodeError() {
	ctx := context.Background()
	userID := uuid.New()
	code := "123456"
	mfaSecretKey := "base32secretkey"
	encryptedSecret := "encryptedBase32Secret"
	metadataCtx := context.WithValue(ctx, "metadata", map[string]string{"ip-address": "127.0.0.1", "user-agent": "test-agent"})
	rateKey := "2faverify_user:" + userID.String()
	rule := s.cfg.Security.RateLimiting.TwoFAVerificationPerUser

	s.mockRateLimiter.On("Allow", metadataCtx, rateKey, rule).Return(true, nil).Once()
	mfaSecret := &models.MFASecret{UserID: userID, Type: models.MFATypeTOTP, SecretKeyEncrypted: encryptedSecret, Verified: true}
	s.mockMfaSecretRepo.On("FindByUserIDAndType", metadataCtx, userID, models.MFATypeTOTP).Return(mfaSecret, nil).Once()
	s.mockEncryptionSvc.On("Decrypt", encryptedSecret, s.cfg.MFA.TOTPSecretEncryptionKey).Return(mfaSecretKey, nil).Once()
	s.mockTotpService.On("ValidateCode", mfaSecretKey, code).Return(false, errors.New("totp validation error")).Once()

	expectedAuditDetails := map[string]interface{}{
		"code_type": string(models.MFATypeTOTP),
		"error":     "error validating TOTP code",
		"details":   errors.New("totp validation error").Error(),
	}
	s.mockAuditRecorder.On("RecordEvent", metadataCtx, &userID, "mfa_code_verify", models.AuditLogStatusFailure, &userID, models.AuditTargetTypeUser, expectedAuditDetails, "127.0.0.1", "test-agent").Once()

	isValid, err := s.mfaService.Verify2FACode(metadataCtx, userID, code, models.MFATypeTOTP)
	assert.False(s.T(), isValid)
	assert.ErrorContains(s.T(), err, "error validating TOTP code")
	s.mockTotpService.AssertExpectations(s.T())
	s.mockAuditRecorder.AssertExpectations(s.T())
}

func (s *MFALogicServiceTestSuite) TestVerify2FACode_Backup_RepoErrorOnFindByUserID() {
	ctx := context.Background()
	userID := uuid.New()
	backupCodePlain := "backup123"
	metadataCtx := context.WithValue(ctx, "metadata", map[string]string{"ip-address": "127.0.0.1", "user-agent": "test-agent"})
	rateKey := "2faverify_user:" + userID.String()
	rule := s.cfg.Security.RateLimiting.TwoFAVerificationPerUser

	s.mockRateLimiter.On("Allow", metadataCtx, rateKey, rule).Return(true, nil).Once()
	s.mockMfaBackupRepo.On("FindByUserID", metadataCtx, userID).Return(nil, errors.New("db error findbyuserid")).Once()

	expectedAuditDetails := map[string]interface{}{
		"code_type": string(models.MFATypeBackup),
		"error":     "failed to retrieve backup codes for verification",
		"details":   errors.New("db error findbyuserid").Error(),
	}
	s.mockAuditRecorder.On("RecordEvent", metadataCtx, &userID, "mfa_code_verify", models.AuditLogStatusFailure, &userID, models.AuditTargetTypeUser, expectedAuditDetails, "127.0.0.1", "test-agent").Once()

	isValid, err := s.mfaService.Verify2FACode(metadataCtx, userID, backupCodePlain, models.MFATypeBackup)
	assert.False(s.T(), isValid)
	assert.ErrorContains(s.T(), err, "failed to retrieve backup codes")
	s.mockMfaBackupRepo.AssertExpectations(s.T())
	s.mockAuditRecorder.AssertExpectations(s.T())
}


func (s *MFALogicServiceTestSuite) TestVerify2FACode_Backup_PasswordServiceError() {
    ctx := context.Background()
    userID := uuid.New()
    backupCodePlain := "backup123"
    metadataCtx := context.WithValue(ctx, "metadata", map[string]string{"ip-address": "127.0.0.1", "user-agent": "test-agent"})
    rateKey := "2faverify_user:" + userID.String()
    rule := s.cfg.Security.RateLimiting.TwoFAVerificationPerUser

    s.mockRateLimiter.On("Allow", metadataCtx, rateKey, rule).Return(true, nil).Once()

    // Simulate at least one backup code existing
    backupCodeModel := &models.MFABackupCode{ID: uuid.New(), UserID: userID, CodeHash: "somehash"}
    s.mockMfaBackupRepo.On("FindByUserID", metadataCtx, userID).Return([]*models.MFABackupCode{backupCodeModel}, nil).Once()

    // Mock PasswordService.CheckPasswordHash to return an error
    s.mockPasswordService.On("CheckPasswordHash", backupCodePlain, "somehash").Return(false, errors.New("argon2 error")).Once()
    // Since it errors on the first check, no further calls to CheckPasswordHash or MarkAsUsed are expected for this code.
    // The loop will continue if there are more codes, but for this test, we only have one.
    // If there were more, we'd mock them to not match or also error to ensure the overall outcome.

	// The error from CheckPasswordHash is currently logged but does not directly propagate to the user.
	// The function will return ErrInvalid2FACode if no codes match.
	// So, we expect ErrInvalid2FACode, and the audit log for that.
	expectedAuditDetails := map[string]interface{}{
		"code_type": string(models.MFATypeBackup),
		"error":     domainErrors.ErrInvalid2FACode.Error(),
	}
	s.mockAuditRecorder.On("RecordEvent", metadataCtx, &userID, "mfa_code_verify", models.AuditLogStatusFailure, &userID, models.AuditTargetTypeUser, expectedAuditDetails, "127.0.0.1", "test-agent").Once()


    isValid, err := s.mfaService.Verify2FACode(metadataCtx, userID, backupCodePlain, models.MFATypeBackup)
    assert.False(s.T(), isValid)
    assert.ErrorIs(s.T(), err, domainErrors.ErrInvalid2FACode) // Because no code matched due to error
    s.mockPasswordService.AssertExpectations(s.T())
	s.mockAuditRecorder.AssertExpectations(s.T())
}


func (s *MFALogicServiceTestSuite) TestVerify2FACode_Backup_MarkAsUsedError() {
	ctx := context.Background()
	userID := uuid.New()
	backupCodePlain := "backup123"
	metadataCtx := context.WithValue(ctx, "metadata", map[string]string{"ip-address": "127.0.0.1", "user-agent": "test-agent"})
	rateKey := "2faverify_user:" + userID.String()
	rule := s.cfg.Security.RateLimiting.TwoFAVerificationPerUser

	s.mockRateLimiter.On("Allow", metadataCtx, rateKey, rule).Return(true, nil).Once()

	hashedBackupCode := "hashed-" + backupCodePlain
	backupCodeModel := &models.MFABackupCode{ID: uuid.New(), UserID: userID, CodeHash: hashedBackupCode}
	s.mockMfaBackupRepo.On("FindByUserID", metadataCtx, userID).Return([]*models.MFABackupCode{backupCodeModel}, nil).Once()
	s.mockPasswordService.On("CheckPasswordHash", backupCodePlain, hashedBackupCode).Return(true, nil).Once()
	s.mockMfaBackupRepo.On("MarkAsUsed", metadataCtx, backupCodeModel.ID, mock.AnythingOfType("time.Time")).Return(errors.New("db error markasused")).Once()

	expectedAuditDetails := map[string]interface{}{
		"code_type": string(models.MFATypeBackup),
		"error":     "failed to mark backup code as used",
		"details":   errors.New("db error markasused").Error(),
	}
	s.mockAuditRecorder.On("RecordEvent", metadataCtx, &userID, "mfa_code_verify", models.AuditLogStatusFailure, &userID, models.AuditTargetTypeUser, expectedAuditDetails, "127.0.0.1", "test-agent").Once()

	isValid, err := s.mfaService.Verify2FACode(metadataCtx, userID, backupCodePlain, models.MFATypeBackup)
	assert.False(s.T(), isValid)
	assert.ErrorContains(s.T(), err, "failed to mark backup code as used")
	s.mockMfaBackupRepo.AssertExpectations(s.T()) // Verifies FindByUserID and MarkAsUsed
	s.mockPasswordService.AssertExpectations(s.T())
	s.mockAuditRecorder.AssertExpectations(s.T())
}
