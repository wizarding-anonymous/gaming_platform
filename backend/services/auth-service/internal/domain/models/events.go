// File: backend/services/auth-service/internal/domain/models/events.go
package models

import (
	"time"
	// "github.com/google/uuid" // Not needed for these event structs if IDs are strings
)

// UserRegisteredEvent is published when a new user completes registration.
// Corresponds to event type: auth.user.registered.v1
type UserRegisteredEvent struct {
	UserID                string    `json:"user_id"`
	Username              string    `json:"username"`
	Email                 string    `json:"email"`
	DisplayName           *string   `json:"display_name,omitempty"`
	RegistrationTimestamp time.Time `json:"registration_timestamp"`
	InitialStatus         string    `json:"initial_status"`
}

// EmailVerifiedEvent is published when a user successfully verifies their email.
// Corresponds to event type: auth.user.email_verified.v1
type EmailVerifiedEvent struct {
	UserID                string    `json:"user_id"`
	Email                 string    `json:"email"`
	VerificationTimestamp time.Time `json:"verification_timestamp"`
}

// PasswordResetEvent is published when a user's password has been successfully reset.
type PasswordResetEvent struct {
	UserID  string    `json:"user_id"`
	Email   string    `json:"email"` // Included for recipient identification if needed
	ResetAt time.Time `json:"reset_at"`
}

// VerificationEmailResentEvent is published when a verification email has been resent.
type VerificationEmailResentEvent struct {
	UserID string    `json:"user_id"`
	Email  string    `json:"email"`
	Token  string    `json:"token"` // The new plain token
	SentAt time.Time `json:"sent_at"`
}

// PasswordResetRequestedEvent is published when a user requests a password reset.
// Corresponds to event type: auth.user.password_reset_requested.v1
type PasswordResetRequestedEvent struct {
	UserID                string    `json:"user_id"`
	Email                 string    `json:"email"`
	RequestTimestamp      time.Time `json:"request_timestamp"`
	ResetTokenIdentifier *string   `json:"reset_token_identifier,omitempty"`
}

// DeviceInfoPayload for login success event (as per spec example)
type DeviceInfoPayload struct {
	Type        string `json:"type,omitempty"`
	OS          string `json:"os,omitempty"`
	AppVersion  string `json:"app_version,omitempty"`
	DeviceName  string `json:"device_name,omitempty"`
}

// UserLoginSuccessPayload is published upon successful user login.
// Corresponds to event type: auth.user.login_success.v1
type UserLoginSuccessPayload struct {
	UserID          string             `json:"user_id"`
	SessionID       string             `json:"session_id"`
	LoginTimestamp  time.Time          `json:"login_timestamp"`
	IPAddress       string             `json:"ip_address"`
	UserAgent       string             `json:"user_agent"`
	DeviceInfo      *DeviceInfoPayload `json:"device_info,omitempty"`
}

// UserLogoutEvent is published upon user logout from a single session.
type UserLogoutEvent struct {
	UserID    string    `json:"user_id"`
	SessionID string    `json:"session_id"`
	LogoutAt  time.Time `json:"logout_at"`
}

// UserLogoutAllEvent is published upon user logout from all sessions.
type UserLogoutAllEvent struct {
	UserID   string    `json:"user_id"`
	LogoutAt time.Time `json:"logout_at"`
}

// TokenRefreshedEvent is published when a token pair is refreshed.
type TokenRefreshedEvent struct {
	UserID    string    `json:"user_id"`
	SessionID string    `json:"session_id"`
	RefreshedAt time.Time `json:"refreshed_at"`
}

// PasswordChangedEvent is published when a user successfully changes their password while authenticated.
// Corresponds to event type: auth.user.password_changed.v1
type PasswordChangedEvent struct {
	UserID           string    `json:"user_id"`
	ChangeTimestamp  time.Time `json:"change_timestamp"`
	ChangeType       string    `json:"change_type"`
}

// --- RBAC Event Structs ---

// RoleCreatedEvent is published when a new role is created.
type RoleCreatedEvent struct {
	RoleID      string    `json:"role_id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// RoleUpdatedEvent is published when a role's details are updated.
type RoleUpdatedEvent struct {
	RoleID      string    `json:"role_id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// RoleDeletedEvent is published when a role is deleted.
type RoleDeletedEvent struct {
	RoleID    string    `json:"role_id"`
	DeletedAt time.Time `json:"deleted_at"`
}

// RoleAssignedEvent is published when a role is assigned to a user.
type RoleAssignedEvent struct {
	UserID          string    `json:"user_id"`
	RoleID          string    `json:"role_id"`
	RoleName        string    `json:"role_name"` // For context
	AssignedAt      time.Time `json:"assigned_at"`
	ChangedByUserID string    `json:"changed_by_user_id,omitempty"` // Admin/system that made the change
}

// RoleRemovedEvent is published when a role is removed from a user.
// This specific event might be deprecated in favor of UserRolesChangedEvent.
type RoleRemovedEvent struct {
	UserID          string    `json:"user_id"`
	RoleID          string    `json:"role_id"` // The specific role that was removed
	RoleName        string    `json:"role_name"` // For context
	RemovedAt       time.Time `json:"removed_at"`
	ChangedByUserID string    `json:"changed_by_user_id,omitempty"`
}

// UserRolesChangedEvent is a more general event for when a user's role assignments change.
// This can cover both assignment and removal.
// Corresponds to event type: auth.user.roles_changed.v1
type UserRolesChangedEvent struct {
	UserID          string    `json:"user_id"`
	OldRoleIDs      []string  `json:"old_role_ids"`
	NewRoleIDs      []string  `json:"new_role_ids"`
	ChangedByUserID string    `json:"changed_by_user_id"` // Changed to string, removed omitempty
	ChangeTimestamp time.Time `json:"change_timestamp"`
}


// Add other event structs as needed for Kafka integration,
// ensuring they align with `auth_event_streaming.md`.

// SessionCreatedEvent is published when a new session is created.
// Corresponds to event type: auth.session.created.v1
type SessionCreatedEvent struct {
	SessionID             string             `json:"session_id"`
	UserID                string             `json:"user_id"`
	IPAddress             string             `json:"ip_address"`
	UserAgent             string             `json:"user_agent"`
	CreationTimestamp     time.Time          `json:"creation_timestamp"`
	DeviceInfo            *DeviceInfoPayload `json:"device_info,omitempty"`
	RefreshTokenExpiresAt time.Time          `json:"refresh_token_expires_at"`
}

// SessionRevokedEvent is published when a session is revoked.
// Corresponds to event type: auth.session.revoked.v1
type SessionRevokedEvent struct { // Renamed struct
	SessionID            string    `json:"session_id"`
	UserID               string    `json:"user_id"`
	RevocationTimestamp  time.Time `json:"revocation_timestamp"`
	Reason               string    `json:"reason"`
}

// --- User Security Event Payloads ---

// UserLoginFailedPayload is published when a user login attempt fails.
// Corresponds to event type: auth.user.login_failed.v1
type UserLoginFailedPayload struct {
	AttemptedLoginIdentifier string    `json:"attempted_login_identifier"`
	FailureReason            string    `json:"failure_reason"`
	FailureTimestamp         time.Time `json:"failure_timestamp"`
	IPAddress                string    `json:"ip_address"`
	UserAgent                string    `json:"user_agent"`
}

// UserAccountLockedPayload is published when a user account is locked due to excessive failed login attempts.
// Corresponds to event type: auth.user.account_locked.v1
type UserAccountLockedPayload struct {
	UserID                  string    `json:"user_id"`
	LockTimestamp           time.Time `json:"lock_timestamp"`
	Reason                  string    `json:"reason"`
	LockoutDurationSeconds *int64    `json:"lockout_duration_seconds,omitempty"`
}

// User2FAEnabledEvent is published when a user successfully enables a 2FA method.
// Corresponds to event type: auth.2fa.enabled.v1
type User2FAEnabledEvent struct {
	UserID           string    `json:"user_id"`
	Method           string    `json:"method"` // e.g., "totp", "sms"
	EnabledTimestamp time.Time `json:"enabled_timestamp"`
}

// User2FADisabledEvent is published when a user successfully disables a 2FA method.
// Corresponds to event type: auth.2fa.disabled.v1
type User2FADisabledEvent struct {
	UserID            string    `json:"user_id"`
	Method            string    `json:"method"` // e.g., "totp", "sms"
	DisabledTimestamp time.Time `json:"disabled_timestamp"`
}


// --- CloudEvent Types ---
// These constants define the `type` attribute for CloudEvents.
// Format: {service_name}.{aggregate_type}.{event_name}.{version}
// Example: auth.user.registered.v1

// User Lifecycle Events
const (
	AuthUserRegisteredV1   = "auth.user.registered.v1"
	AuthUserEmailVerifiedV1 = "auth.user.email_verified.v1"
	// AuthUserDeletedV1 is usually an event from Account service, not published by Auth.
	// Auth service might consume account.user.deleted.v1
)

// Security Events
const (
	AuthUserLoginSuccessV1             = "auth.user.login_success.v1"
	AuthUserLoginFailedV1              = "auth.user.login_failed.v1" // New
	AuthUserAccountLockedV1            = "auth.user.account_locked.v1" // New
	AuthUserLogoutSuccessV1            = "auth.user.logout_success.v1"
	AuthUserAllSessionsRevokedV1       = "auth.user.all_sessions_revoked.v1"
	AuthUserPasswordChangedV1          = "auth.user.password_changed.v1"
	AuthUserPasswordResetV1            = "auth.user.password_reset.v1"
	AuthSecurityEmailVerificationRequestedV1 = "auth.security.email_verification_requested.v1"
	AuthSecurityPasswordResetRequestedV1 = "auth.security.password_reset_requested.v1"
	// MFA Events
	AuthUser2FAEnabledV1  = "auth.user.2fa_enabled.v1"
	AuthUser2FADisabledV1 = "auth.user.2fa_disabled.v1"
	AuthUser2FABackupCodesGeneratedV1 = "auth.user.2fa_backup_codes_generated.v1"
	// API Key Events
	AuthUserAPIKeyCreatedV1 = "auth.user.api_key_created.v1"
	AuthUserAPIKeyDeletedV1 = "auth.user.api_key_deleted.v1"
)

// Session Events
const (
	AuthSessionCreatedV1 = "auth.session.created.v1"
	AuthSessionRefreshedV1 = "auth.session.refreshed.v1" // If refresh token rotation creates a new session logical record or for audit
	AuthSessionRevokedV1 = "auth.session.revoked.v1"
)

// Role & Permission Events (can be expanded)
const (
	AuthRoleCreatedV1 = "auth.rbac.role_created.v1"
	AuthRoleUpdatedV1 = "auth.rbac.role_updated.v1"
	AuthRoleDeletedV1 = "auth.rbac.role_deleted.v1"
	AuthUserRoleAssignedV1 = "auth.rbac.user_role_assigned.v1"
	AuthUserRoleRevokedV1  = "auth.rbac.user_role_revoked.v1"
	// AuthPermissionAssignedToRoleV1 = "auth.rbac.permission_assigned_to_role.v1"
	// AuthPermissionRevokedFromRoleV1 = "auth.rbac.permission_revoked_from_role.v1"
)

// External Account Events
const (
	AuthExternalAccountLinkedV1   = "auth.external_account.linked.v1"
	AuthExternalAccountUnlinkedV1 = "auth.external_account.unlinked.v1"
)

// AllSessionsDeactivatedEvent is published when all sessions for a user are deactivated (deleted).
type AllSessionsDeactivatedEvent struct {
	UserID        string    `json:"user_id"`
	DeactivatedAt time.Time `json:"deactivated_at"`
}
