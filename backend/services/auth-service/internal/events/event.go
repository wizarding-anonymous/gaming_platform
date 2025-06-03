// File: internal/events/models/event.go

package models

import (
	"time"
)

// EventType представляет тип события
type EventType string

const (
	// UserCreated - событие создания пользователя
	UserCreated EventType = "user.created"
	// UserUpdated - событие обновления пользователя
	UserUpdated EventType = "user.updated"
	// UserDeleted - событие удаления пользователя
	UserDeleted EventType = "user.deleted"
	// UserPasswordChanged - событие изменения пароля пользователя
	UserPasswordChanged EventType = "user.password_changed"
	// UserEmailVerified - событие подтверждения email пользователя
	UserEmailVerified EventType = "user.email_verified"
	// UserLoginSuccess - событие успешного входа пользователя
	UserLoginSuccess EventType = "user.login_success"
	// UserLoginFailed - событие неудачного входа пользователя
	UserLoginFailed EventType = "user.login_failed"
	// UserLogout - событие выхода пользователя
	UserLogout EventType = "user.logout"
	// UserBlocked - событие блокировки пользователя
	UserBlocked EventType = "user.blocked"
	// UserUnblocked - событие разблокировки пользователя
	UserUnblocked EventType = "user.unblocked"
	// UserRoleAssigned - событие назначения роли пользователю
	UserRoleAssigned EventType = "user.role_assigned"
	// UserRoleRevoked - событие отзыва роли у пользователя
	UserRoleRevoked EventType = "user.role_revoked"
	// UserTwoFactorEnabled - событие включения двухфакторной аутентификации
	UserTwoFactorEnabled EventType = "user.two_factor_enabled"
	// UserTwoFactorDisabled - событие отключения двухфакторной аутентификации
	UserTwoFactorDisabled EventType = "user.two_factor_disabled"
	// UserTelegramLinked - событие привязки Telegram
	UserTelegramLinked EventType = "user.telegram_linked"
	// UserTelegramUnlinked - событие отвязки Telegram
	UserTelegramUnlinked EventType = "user.telegram_unlinked"
	// SessionCreated - событие создания сессии
	SessionCreated EventType = "session.created"
	// SessionExpired - событие истечения сессии
	SessionExpired EventType = "session.expired"
	// SessionRevoked - событие отзыва сессии
	SessionRevoked EventType = "session.revoked"
	// TokenCreated - событие создания токена
	TokenCreated EventType = "token.created"
	// TokenRefreshed - событие обновления токена
	TokenRefreshed EventType = "token.refreshed"
	// TokenRevoked - событие отзыва токена
	TokenRevoked EventType = "token.revoked"
	// RoleCreated - событие создания роли
	RoleCreated EventType = "role.created"
	// RoleUpdated - событие обновления роли
	RoleUpdated EventType = "role.updated"
	// RoleDeleted - событие удаления роли
	RoleDeleted EventType = "role.deleted"
	// PermissionAssigned - событие назначения разрешения
	PermissionAssigned EventType = "permission.assigned"
	// PermissionRevoked - событие отзыва разрешения
	PermissionRevoked EventType = "permission.revoked"
	// SecurityAlert - событие оповещения о безопасности
	SecurityAlert EventType = "security.alert"
)

// Event представляет событие в системе
type Event struct {
	ID          string                 `json:"id"`
	Type        EventType              `json:"type"`
	Source      string                 `json:"source"`
	Time        time.Time              `json:"time"`
	Subject     string                 `json:"subject,omitempty"`
	SubjectType string                 `json:"subject_type,omitempty"`
	UserID      string                 `json:"user_id,omitempty"`
	SessionID   string                 `json:"session_id,omitempty"`
	IP          string                 `json:"ip,omitempty"`
	UserAgent   string                 `json:"user_agent,omitempty"`
	Data        map[string]interface{} `json:"data,omitempty"`
}

// UserCreatedEvent представляет данные события создания пользователя
type UserCreatedEvent struct {
	UserID    string `json:"user_id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	CreatedAt string `json:"created_at"`
}

// UserUpdatedEvent представляет данные события обновления пользователя
type UserUpdatedEvent struct {
	UserID    string                 `json:"user_id"`
	UpdatedAt string                 `json:"updated_at"`
	Changes   map[string]interface{} `json:"changes"`
}

// UserDeletedEvent представляет данные события удаления пользователя
type UserDeletedEvent struct {
	UserID    string `json:"user_id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	DeletedAt string `json:"deleted_at"`
}

// UserPasswordChangedEvent представляет данные события изменения пароля пользователя
type UserPasswordChangedEvent struct {
	UserID    string `json:"user_id"`
	ChangedAt string `json:"changed_at"`
	IP        string `json:"ip"`
	UserAgent string `json:"user_agent"`
}

// UserEmailVerifiedEvent представляет данные события подтверждения email пользователя
type UserEmailVerifiedEvent struct {
	UserID    string `json:"user_id"`
	Email     string `json:"email"`
	VerifiedAt string `json:"verified_at"`
}

// UserLoginSuccessEvent представляет данные события успешного входа пользователя
type UserLoginSuccessEvent struct {
	UserID    string `json:"user_id"`
	Username  string `json:"username"`
	IP        string `json:"ip"`
	UserAgent string `json:"user_agent"`
	LoginAt   string `json:"login_at"`
	Location  string `json:"location,omitempty"`
}

// UserLoginFailedEvent представляет данные события неудачного входа пользователя
type UserLoginFailedEvent struct {
	UserID    string `json:"user_id,omitempty"`
	Username  string `json:"username"`
	IP        string `json:"ip"`
	UserAgent string `json:"user_agent"`
	Reason    string `json:"reason"`
	FailedAt  string `json:"failed_at"`
	Location  string `json:"location,omitempty"`
}

// UserLogoutEvent представляет данные события выхода пользователя
type UserLogoutEvent struct {
	UserID    string `json:"user_id"`
	SessionID string `json:"session_id"`
	IP        string `json:"ip"`
	UserAgent string `json:"user_agent"`
	LogoutAt  string `json:"logout_at"`
}

// UserBlockedEvent представляет данные события блокировки пользователя
type UserBlockedEvent struct {
	UserID     string `json:"user_id"`
	BlockedBy  string `json:"blocked_by"`
	Reason     string `json:"reason"`
	BlockedAt  string `json:"blocked_at"`
	ExpiresAt  string `json:"expires_at,omitempty"`
}

// UserUnblockedEvent представляет данные события разблокировки пользователя
type UserUnblockedEvent struct {
	UserID       string `json:"user_id"`
	UnblockedBy  string `json:"unblocked_by"`
	Reason       string `json:"reason"`
	UnblockedAt  string `json:"unblocked_at"`
}

// UserRoleAssignedEvent представляет данные события назначения роли пользователю
type UserRoleAssignedEvent struct {
	UserID    string `json:"user_id"`
	RoleID    string `json:"role_id"`
	RoleName  string `json:"role_name"`
	AssignedBy string `json:"assigned_by"`
	AssignedAt string `json:"assigned_at"`
}

// UserRoleRevokedEvent представляет данные события отзыва роли у пользователя
type UserRoleRevokedEvent struct {
	UserID    string `json:"user_id"`
	RoleID    string `json:"role_id"`
	RoleName  string `json:"role_name"`
	RevokedBy string `json:"revoked_by"`
	RevokedAt string `json:"revoked_at"`
}

// UserTwoFactorEnabledEvent представляет данные события включения двухфакторной аутентификации
type UserTwoFactorEnabledEvent struct {
	UserID    string `json:"user_id"`
	Method    string `json:"method"`
	EnabledAt string `json:"enabled_at"`
	IP        string `json:"ip"`
	UserAgent string `json:"user_agent"`
}

// UserTwoFactorDisabledEvent представляет данные события отключения двухфакторной аутентификации
type UserTwoFactorDisabledEvent struct {
	UserID     string `json:"user_id"`
	Method     string `json:"method"`
	DisabledAt string `json:"disabled_at"`
	IP         string `json:"ip"`
	UserAgent  string `json:"user_agent"`
}

// UserTelegramLinkedEvent представляет данные события привязки Telegram
type UserTelegramLinkedEvent struct {
	UserID      string `json:"user_id"`
	TelegramID  string `json:"telegram_id"`
	TelegramUsername string `json:"telegram_username"`
	LinkedAt    string `json:"linked_at"`
}

// UserTelegramUnlinkedEvent представляет данные события отвязки Telegram
type UserTelegramUnlinkedEvent struct {
	UserID      string `json:"user_id"`
	TelegramID  string `json:"telegram_id"`
	TelegramUsername string `json:"telegram_username"`
	UnlinkedAt  string `json:"unlinked_at"`
}

// SessionCreatedEvent представляет данные события создания сессии
type SessionCreatedEvent struct {
	SessionID string `json:"session_id"`
	UserID    string `json:"user_id"`
	IP        string `json:"ip"`
	UserAgent string `json:"user_agent"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at"`
	Location  string `json:"location,omitempty"`
}

// SessionExpiredEvent представляет данные события истечения сессии
type SessionExpiredEvent struct {
	SessionID string `json:"session_id"`
	UserID    string `json:"user_id"`
	ExpiredAt string `json:"expired_at"`
}

// SessionRevokedEvent представляет данные события отзыва сессии
type SessionRevokedEvent struct {
	SessionID  string `json:"session_id"`
	UserID     string `json:"user_id"`
	RevokedBy  string `json:"revoked_by"`
	Reason     string `json:"reason"`
	RevokedAt  string `json:"revoked_at"`
}

// TokenCreatedEvent представляет данные события создания токена
type TokenCreatedEvent struct {
	TokenID   string `json:"token_id"`
	UserID    string `json:"user_id"`
	TokenType string `json:"token_type"`
	IP        string `json:"ip"`
	UserAgent string `json:"user_agent"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at"`
}

// TokenRefreshedEvent представляет данные события обновления токена
type TokenRefreshedEvent struct {
	OldTokenID string `json:"old_token_id"`
	NewTokenID string `json:"new_token_id"`
	UserID     string `json:"user_id"`
	IP         string `json:"ip"`
	UserAgent  string `json:"user_agent"`
	RefreshedAt string `json:"refreshed_at"`
	ExpiresAt  string `json:"expires_at"`
}

// TokenRevokedEvent представляет данные события отзыва токена
type TokenRevokedEvent struct {
	TokenID   string `json:"token_id"`
	UserID    string `json:"user_id"`
	RevokedBy string `json:"revoked_by"`
	Reason    string `json:"reason"`
	RevokedAt string `json:"revoked_at"`
}

// RoleCreatedEvent представляет данные события создания роли
type RoleCreatedEvent struct {
	RoleID    string `json:"role_id"`
	RoleName  string `json:"role_name"`
	CreatedBy string `json:"created_by"`
	CreatedAt string `json:"created_at"`
}

// RoleUpdatedEvent представляет данные события обновления роли
type RoleUpdatedEvent struct {
	RoleID    string                 `json:"role_id"`
	RoleName  string                 `json:"role_name"`
	UpdatedBy string                 `json:"updated_by"`
	UpdatedAt string                 `json:"updated_at"`
	Changes   map[string]interface{} `json:"changes"`
}

// RoleDeletedEvent представляет данные события удаления роли
type RoleDeletedEvent struct {
	RoleID    string `json:"role_id"`
	RoleName  string `json:"role_name"`
	DeletedBy string `json:"deleted_by"`
	DeletedAt string `json:"deleted_at"`
}

// PermissionAssignedEvent представляет данные события назначения разрешения
type PermissionAssignedEvent struct {
	RoleID         string `json:"role_id"`
	RoleName       string `json:"role_name"`
	PermissionID   string `json:"permission_id"`
	PermissionName string `json:"permission_name"`
	AssignedBy     string `json:"assigned_by"`
	AssignedAt     string `json:"assigned_at"`
}

// PermissionRevokedEvent представляет данные события отзыва разрешения
type PermissionRevokedEvent struct {
	RoleID         string `json:"role_id"`
	RoleName       string `json:"role_name"`
	PermissionID   string `json:"permission_id"`
	PermissionName string `json:"permission_name"`
	RevokedBy      string `json:"revoked_by"`
	RevokedAt      string `json:"revoked_at"`
}

// SecurityAlertEvent представляет данные события оповещения о безопасности
type SecurityAlertEvent struct {
	AlertType  string `json:"alert_type"`
	UserID     string `json:"user_id,omitempty"`
	IP         string `json:"ip,omitempty"`
	UserAgent  string `json:"user_agent,omitempty"`
	Severity   string `json:"severity"`
	Message    string `json:"message"`
	Details    map[string]interface{} `json:"details,omitempty"`
	DetectedAt string `json:"detected_at"`
}
