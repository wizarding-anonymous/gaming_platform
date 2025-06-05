// File: backend/services/account-service/internal/domain/entity/account.go
// account-service/internal/domain/entity/account.go
package entity

import (
"time"

"github.com/google/uuid"
)

// AccountStatus представляет статус аккаунта
type AccountStatus string

const (
// AccountStatusActive - активный аккаунт
AccountStatusActive AccountStatus = "active"
// AccountStatusSuspended - приостановленный аккаунт
AccountStatusSuspended AccountStatus = "suspended"
// AccountStatusBanned - заблокированный аккаунт
AccountStatusBanned AccountStatus = "banned"
// AccountStatusDeleted - удаленный аккаунт
AccountStatusDeleted AccountStatus = "deleted"
)

// Account представляет сущность аккаунта пользователя
type Account struct {
ID        uuid.UUID     `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
Username  string        `json:"username" gorm:"uniqueIndex;size:50;not null"`
Email     string        `json:"email" gorm:"uniqueIndex;size:255;not null"`
Status    AccountStatus `json:"status" gorm:"size:20;not null;default:'active'"`
Role      string        `json:"role" gorm:"size:20;not null;default:'user'"`
CreatedAt time.Time     `json:"created_at" gorm:"not null;default:now()"`
UpdatedAt time.Time     `json:"updated_at" gorm:"not null;default:now()"`
DeletedAt *time.Time    `json:"deleted_at,omitempty" gorm:"index"`
}

// NewAccount создает новый аккаунт
func NewAccount(username, email string) *Account {
return &Account{
ID:        uuid.New(),
Username:  username,
Email:     email,
Status:    AccountStatusActive,
Role:      "user",
CreatedAt: time.Now(),
UpdatedAt: time.Now(),
}
}

// IsActive проверяет, активен ли аккаунт
func (a *Account) IsActive() bool {
return a.Status == AccountStatusActive
}

// IsSuspended проверяет, приостановлен ли аккаунт
func (a *Account) IsSuspended() bool {
return a.Status == AccountStatusSuspended
}

// IsBanned проверяет, заблокирован ли аккаунт
func (a *Account) IsBanned() bool {
return a.Status == AccountStatusBanned
}

// IsDeleted проверяет, удален ли аккаунт
func (a *Account) IsDeleted() bool {
return a.Status == AccountStatusDeleted || a.DeletedAt != nil
}

// Suspend приостанавливает аккаунт
func (a *Account) Suspend() {
a.Status = AccountStatusSuspended
a.UpdatedAt = time.Now()
}

// Ban блокирует аккаунт
func (a *Account) Ban() {
a.Status = AccountStatusBanned
a.UpdatedAt = time.Now()
}

// Activate активирует аккаунт
func (a *Account) Activate() {
a.Status = AccountStatusActive
a.UpdatedAt = time.Now()
}

// SoftDelete помечает аккаунт как удаленный
func (a *Account) SoftDelete() {
a.Status = AccountStatusDeleted
now := time.Now()
a.DeletedAt = &now
a.UpdatedAt = now
}

// Anonymize анонимизирует данные аккаунта
func (a *Account) Anonymize() {
anonymousID := uuid.New().String()
a.Username = "deleted_" + anonymousID[:8]
a.Email = "deleted_" + anonymousID[:8] + "@example.com"
a.Status = AccountStatusDeleted
now := time.Now()
a.DeletedAt = &now
a.UpdatedAt = now
}

// UpdateRole обновляет роль аккаунта
func (a *Account) UpdateRole(role string) {
a.Role = role
a.UpdatedAt = time.Now()
}

// UpdateEmail обновляет email аккаунта
func (a *Account) UpdateEmail(email string) {
a.Email = email
a.UpdatedAt = time.Now()
}

// UpdateUsername обновляет имя пользователя
func (a *Account) UpdateUsername(username string) {
a.Username = username
a.UpdatedAt = time.Now()
}
