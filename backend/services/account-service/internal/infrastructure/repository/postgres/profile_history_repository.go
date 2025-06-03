// account-service\internal\infrastructure\repository\postgres\profile_history_repository.go
package postgres

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/gaiming/account-service/internal/domain/entity"
	"github.com/gaiming/account-service/internal/domain/errors"
	"github.com/gaiming/account-service/internal/domain/repository"
)

// ProfileHistoryRepository реализация репозитория для работы с историей изменений профиля в PostgreSQL
type ProfileHistoryRepository struct {
	db *sqlx.DB
}

// NewProfileHistoryRepository создает новый экземпляр ProfileHistoryRepository
func NewProfileHistoryRepository(db *sqlx.DB) repository.ProfileHistoryRepository {
	return &ProfileHistoryRepository{
		db: db,
	}
}

// Create создает новую запись истории изменений профиля
func (r *ProfileHistoryRepository) Create(ctx context.Context, history *entity.ProfileHistory) error {
	query := `
		INSERT INTO profile_history (
			id, profile_id, field_name, old_value, new_value, changed_by_account_id, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7
		)
	`

	_, err := r.db.ExecContext(
		ctx,
		query,
		history.ID,
		history.ProfileID,
		history.FieldName,
		history.OldValue,
		history.NewValue,
		history.ChangedByAccountID,
		history.CreatedAt,
	)

	if err != nil {
		return errors.NewInternalError("Ошибка при создании записи истории изменений профиля", err)
	}

	return nil
}

// GetByID получает запись истории изменений профиля по ID
func (r *ProfileHistoryRepository) GetByID(ctx context.Context, id uuid.UUID) (*entity.ProfileHistory, error) {
	query := `
		SELECT 
			id, profile_id, field_name, old_value, new_value, changed_by_account_id, created_at
		FROM 
			profile_history
		WHERE 
			id = $1
	`

	var history entity.ProfileHistory
	err := r.db.GetContext(ctx, &history, query, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.NewNotFoundError("Запись истории изменений профиля не найдена", err)
		}
		return nil, errors.NewInternalError("Ошибка при получении записи истории изменений профиля", err)
	}

	return &history, nil
}

// GetByProfileID получает все записи истории изменений для профиля
func (r *ProfileHistoryRepository) GetByProfileID(ctx context.Context, profileID uuid.UUID, offset, limit int) ([]*entity.ProfileHistory, int64, error) {
	query := `
		SELECT 
			id, profile_id, field_name, old_value, new_value, changed_by_account_id, created_at
		FROM 
			profile_history
		WHERE 
			profile_id = $1
		ORDER BY 
			created_at DESC
		LIMIT $2 OFFSET $3
	`

	countQuery := `
		SELECT COUNT(*) FROM profile_history
		WHERE profile_id = $1
	`

	var history []*entity.ProfileHistory
	err := r.db.SelectContext(ctx, &history, query, profileID, limit, offset)
	if err != nil {
		return nil, 0, errors.NewInternalError("Ошибка при получении истории изменений профиля", err)
	}

	var total int64
	err = r.db.GetContext(ctx, &total, countQuery, profileID)
	if err != nil {
		return nil, 0, errors.NewInternalError("Ошибка при получении общего количества записей истории", err)
	}

	return history, total, nil
}

// GetByProfileIDAndFieldName получает все записи истории изменений для профиля по имени поля
func (r *ProfileHistoryRepository) GetByProfileIDAndFieldName(ctx context.Context, profileID uuid.UUID, fieldName string, offset, limit int) ([]*entity.ProfileHistory, int64, error) {
	query := `
		SELECT 
			id, profile_id, field_name, old_value, new_value, changed_by_account_id, created_at
		FROM 
			profile_history
		WHERE 
			profile_id = $1 AND field_name = $2
		ORDER BY 
			created_at DESC
		LIMIT $3 OFFSET $4
	`

	countQuery := `
		SELECT COUNT(*) FROM profile_history
		WHERE profile_id = $1 AND field_name = $2
	`

	var history []*entity.ProfileHistory
	err := r.db.SelectContext(ctx, &history, query, profileID, fieldName, limit, offset)
	if err != nil {
		return nil, 0, errors.NewInternalError("Ошибка при получении истории изменений поля профиля", err)
	}

	var total int64
	err = r.db.GetContext(ctx, &total, countQuery, profileID, fieldName)
	if err != nil {
		return nil, 0, errors.NewInternalError("Ошибка при получении общего количества записей истории поля", err)
	}

	return history, total, nil
}

// GetByChangedByAccountID получает все записи истории изменений, сделанные указанным аккаунтом
func (r *ProfileHistoryRepository) GetByChangedByAccountID(ctx context.Context, accountID uuid.UUID, offset, limit int) ([]*entity.ProfileHistory, int64, error) {
	query := `
		SELECT 
			id, profile_id, field_name, old_value, new_value, changed_by_account_id, created_at
		FROM 
			profile_history
		WHERE 
			changed_by_account_id = $1
		ORDER BY 
			created_at DESC
		LIMIT $2 OFFSET $3
	`

	countQuery := `
		SELECT COUNT(*) FROM profile_history
		WHERE changed_by_account_id = $1
	`

	var history []*entity.ProfileHistory
	err := r.db.SelectContext(ctx, &history, query, accountID, limit, offset)
	if err != nil {
		return nil, 0, errors.NewInternalError("Ошибка при получении истории изменений, сделанных аккаунтом", err)
	}

	var total int64
	err = r.db.GetContext(ctx, &total, countQuery, accountID)
	if err != nil {
		return nil, 0, errors.NewInternalError("Ошибка при получении общего количества записей истории", err)
	}

	return history, total, nil
}

// Delete удаляет запись истории изменений профиля
func (r *ProfileHistoryRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `
		DELETE FROM profile_history
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return errors.NewInternalError("Ошибка при удалении записи истории изменений профиля", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return errors.NewInternalError("Ошибка при получении количества затронутых строк", err)
	}

	if rowsAffected == 0 {
		return errors.NewNotFoundError("Запись истории изменений профиля не найдена", nil)
	}

	return nil
}
