// account-service/internal/domain/repository/account_repository.go
package repository

import (
"context"

"github.com/google/uuid"
"github.com/steamru/account-service/internal/domain/entity"
)

// AccountFilter представляет фильтр для поиска аккаунтов
type AccountFilter struct {
Username  string
Email     string
Status    *entity.AccountStatus
Role      string
CreatedAt *DateRange
UpdatedAt *DateRange
Limit     int
Offset    int
SortBy    string
SortOrder string
}

// DateRange представляет диапазон дат для фильтрации
type DateRange struct {
From string
To   string
}

// AccountRepository представляет интерфейс репозитория для работы с аккаунтами
type AccountRepository interface {
// Create создает новый аккаунт
Create(ctx context.Context, account *entity.Account) error

// GetByID получает аккаунт по ID
GetByID(ctx context.Context, id uuid.UUID) (*entity.Account, error)

// GetByUsername получает аккаунт по имени пользователя
GetByUsername(ctx context.Context, username string) (*entity.Account, error)

// GetByEmail получает аккаунт по email
GetByEmail(ctx context.Context, email string) (*entity.Account, error)

// Update обновляет аккаунт
Update(ctx context.Context, account *entity.Account) error

// Delete удаляет аккаунт (soft delete)
Delete(ctx context.Context, id uuid.UUID) error

// HardDelete полностью удаляет аккаунт из базы данных
HardDelete(ctx context.Context, id uuid.UUID) error

// List получает список аккаунтов по фильтру
List(ctx context.Context, filter AccountFilter) ([]*entity.Account, int64, error)

// Exists проверяет существование аккаунта по ID
Exists(ctx context.Context, id uuid.UUID) (bool, error)

// ExistsByUsername проверяет существование аккаунта по имени пользователя
ExistsByUsername(ctx context.Context, username string) (bool, error)

// ExistsByEmail проверяет существование аккаунта по email
ExistsByEmail(ctx context.Context, email string) (bool, error)

// UpdateStatus обновляет статус аккаунта
UpdateStatus(ctx context.Context, id uuid.UUID, status entity.AccountStatus) error

// UpdateRole обновляет роль аккаунта
UpdateRole(ctx context.Context, id uuid.UUID, role string) error

// UpdateEmail обновляет email аккаунта
UpdateEmail(ctx context.Context, id uuid.UUID, email string) error

// UpdateUsername обновляет имя пользователя
UpdateUsername(ctx context.Context, id uuid.UUID, username string) error

// Anonymize анонимизирует данные аккаунта
Anonymize(ctx context.Context, id uuid.UUID) error
}
