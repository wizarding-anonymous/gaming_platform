// File: backend/services/auth-service/internal/domain/service/api_key_service_test.go
package service_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/entity"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/repository"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/service"
	kafkaPkg "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/events/kafka"
)

type MockAPIKeyRepository struct{ mock.Mock }

func (m *MockAPIKeyRepository) Create(ctx context.Context, apiKey *entity.APIKey) error {
	args := m.Called(ctx, apiKey)
	return args.Error(0)
}
func (m *MockAPIKeyRepository) FindByID(ctx context.Context, id uuid.UUID) (*entity.APIKey, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.APIKey), args.Error(1)
}
func (m *MockAPIKeyRepository) FindByUserIDAndID(ctx context.Context, id uuid.UUID, userID uuid.UUID) (*entity.APIKey, error) {
	args := m.Called(ctx, id, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.APIKey), args.Error(1)
}
func (m *MockAPIKeyRepository) FindByKeyPrefix(ctx context.Context, prefix string) (*entity.APIKey, error) {
	args := m.Called(ctx, prefix)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.APIKey), args.Error(1)
}
func (m *MockAPIKeyRepository) FindByPrefixAndHash(ctx context.Context, prefix string, keyHash string) (*entity.APIKey, error) {
	args := m.Called(ctx, prefix, keyHash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.APIKey), args.Error(1)
}
func (m *MockAPIKeyRepository) ListByUserID(ctx context.Context, userID uuid.UUID) ([]*entity.APIKey, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entity.APIKey), args.Error(1)
}
func (m *MockAPIKeyRepository) UpdateLastUsedAt(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}
func (m *MockAPIKeyRepository) UpdateNameAndPermissions(ctx context.Context, id uuid.UUID, userID uuid.UUID, name string, permissions json.RawMessage) error {
	args := m.Called(ctx, id, userID, name, permissions)
	return args.Error(0)
}
func (m *MockAPIKeyRepository) Revoke(ctx context.Context, id uuid.UUID, userID uuid.UUID) error {
	args := m.Called(ctx, id, userID)
	return args.Error(0)
}
func (m *MockAPIKeyRepository) Delete(ctx context.Context, id uuid.UUID) error { return nil }
func (m *MockAPIKeyRepository) DeleteByUserID(ctx context.Context, userID uuid.UUID) (int64, error) {
	return 0, nil
}
func (m *MockAPIKeyRepository) DeleteExpiredAndRevoked(ctx context.Context, olderThanRevokedPeriod time.Duration) (int64, error) {
	return 0, nil
}

type MockPasswordService struct{ mock.Mock }

func (m *MockPasswordService) HashPassword(p string) (string, error) {
	args := m.Called(p)
	return args.String(0), args.Error(1)
}
func (m *MockPasswordService) CheckPasswordHash(p, h string) (bool, error) {
	args := m.Called(p, h)
	return args.Bool(0), args.Error(1)
}

type MockAuditLogRecorder struct{ mock.Mock }

func (m *MockAuditLogRecorder) RecordEvent(ctx context.Context, actorID *uuid.UUID, action string, status models.AuditLogStatus, targetID *uuid.UUID, targetType models.AuditTargetType, details map[string]interface{}, ipAddress string, userAgent string) {
	m.Called(ctx, actorID, action, status, targetID, targetType, details, ipAddress, userAgent)
}
func (m *MockAuditLogRecorder) ListAuditLogs(ctx context.Context, params repository.ListAuditLogParams) ([]*models.AuditLog, int, error) {
	return nil, 0, nil
}

type MockKafkaProducer struct{ mock.Mock }

func (m *MockKafkaProducer) PublishCloudEvent(ctx context.Context, topic string, eventType kafkaPkg.EventType, subject *string, dataContentType *string, payload interface{}) error {
	args := m.Called(ctx, topic, eventType, subject, dataContentType, payload)
	return args.Error(0)
}
func (m *MockKafkaProducer) Close() error { return nil }

func newServiceWithMocks() (service.APIKeyService, *MockAPIKeyRepository, *MockPasswordService, *MockAuditLogRecorder, *MockKafkaProducer) {
	repo := new(MockAPIKeyRepository)
	ps := new(MockPasswordService)
	al := new(MockAuditLogRecorder)
	kp := new(MockKafkaProducer)
	svc := service.NewAPIKeyService(service.APIKeyServiceConfig{
		APIKeyRepo:       repo,
		PasswordService:  ps,
		AuditLogRecorder: al,
		KafkaProducer:    kp,
	})
	return svc, repo, ps, al, kp
}

func TestGenerateAndStoreAPIKey_PublishesEvent(t *testing.T) {
	svc, repo, ps, al, kp := newServiceWithMocks()
	ctx := context.Background()
	ps.On("HashPassword", mock.Anything).Return("hash", nil)
	repo.On("Create", ctx, mock.AnythingOfType("*entity.APIKey")).Return(nil)
	kp.On("PublishCloudEvent", ctx, kafkaPkg.AuthEventsTopic, kafkaPkg.EventType(models.AuthAPIKeyCreatedV1), mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	al.On("RecordEvent", ctx, mock.Anything, "apikey_create", models.AuditLogStatusSuccess, mock.Anything, models.AuditTargetTypeAPIKey, mock.Anything, "unknown", "unknown").Once()

	raw, stored, err := svc.GenerateAndStoreAPIKey(ctx, uuid.NewString(), "test", []string{"r"}, nil)
	require.NoError(t, err)
	assert.NotEmpty(t, raw)
	assert.NotNil(t, stored)
	kp.AssertExpectations(t)
}

func TestRevokeUserAPIKey_PublishesEvent(t *testing.T) {
	svc, repo, _, al, kp := newServiceWithMocks()
	ctx := context.Background()
	repo.On("Revoke", ctx, mock.AnythingOfType("uuid.UUID"), mock.AnythingOfType("uuid.UUID")).Return(nil)
	kp.On("PublishCloudEvent", ctx, kafkaPkg.AuthEventsTopic, kafkaPkg.EventType(models.AuthAPIKeyRevokedV1), mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	al.On("RecordEvent", ctx, mock.Anything, "apikey_revoke", models.AuditLogStatusSuccess, mock.Anything, models.AuditTargetTypeAPIKey, mock.Anything, "unknown", "unknown").Once()

	err := svc.RevokeUserAPIKey(ctx, uuid.NewString(), uuid.NewString())
	require.NoError(t, err)
	kp.AssertExpectations(t)
}

func TestAuthenticateByAPIKey_InsufficientPermissions(t *testing.T) {
	svc, repo, ps, al, _ := newServiceWithMocks()
	ctx := context.WithValue(context.Background(), service.RequiredPermissionsCtxKey, []string{"write"})

	permsJSON, _ := json.Marshal([]string{"read"})
	entityKey := &entity.APIKey{ID: uuid.NewString(), UserID: uuid.NewString(), KeyPrefix: "pltfrm_sk_1234abcd", KeyHash: "hash", Permissions: permsJSON}
	repo.On("FindByKeyPrefix", ctx, entityKey.KeyPrefix).Return(entityKey, nil)
	ps.On("CheckPasswordHash", "secret", "hash").Return(true, nil)
	repo.On("UpdateLastUsedAt", ctx, mock.AnythingOfType("uuid.UUID")).Return(nil)
	al.On("RecordEvent", ctx, mock.Anything, "apikey_auth_failure", models.AuditLogStatusFailure, mock.Anything, models.AuditTargetTypeAPIKey, mock.Anything, "unknown", "unknown").Once()

	_, _, _, err := svc.AuthenticateByAPIKey(ctx, entityKey.KeyPrefix+"_secret")
	require.Error(t, err)
}
