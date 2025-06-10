// File: backend/services/account-service/internal/domain/repository/profile_history_repository.go
// account-service\internal\domain\repository\profile_history_repository.go

package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/domain/entity"
)

// ProfileHistoryRepository определяет интерфейс для работы с хранилищем истории изменений профиля
type ProfileHistoryRepository interface {
	// Create создает новую запись истории изменений профиля
	Create(ctx context.Context, history *entity.ProfileHistory) error

	// GetByID получает запись истории по ID
	GetByID(ctx context.Context, id uuid.UUID) (*entity.ProfileHistory, error)

	// GetByProfileID получает все записи истории для профиля
	GetByProfileID(ctx context.Context, profileID uuid.UUID, offset, limit int) ([]*entity.ProfileHistory, int64, error)

	// GetByFieldName получает записи истории по названию поля
	GetByFieldName(ctx context.Context, profileID uuid.UUID, fieldName string, offset, limit int) ([]*entity.ProfileHistory, int64, error)

	// GetByChangedByAccountID получает записи истории по ID аккаунта, внесшего изменения
	GetByChangedByAccountID(ctx context.Context, changedByAccountID uuid.UUID, offset, limit int) ([]*entity.ProfileHistory, int64, error)

	// Delete удаляет запись истории
	Delete(ctx context.Context, id uuid.UUID) error
}
