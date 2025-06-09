// File: internal/events/models/event.go
package models

import "time"

// EventType is a string type for defining specific event types.
type EventType string

// Cloud Event Types for AuthService
// Based on auth_event_streaming.md
const (
	// User Events
	AuthUserRegisteredV1         EventType = "com.yourplatform.auth.user.registered.v1"
	AuthUserEmailVerifiedV1      EventType = "com.yourplatform.auth.user.email_verified.v1"
	AuthUserPasswordChangedV1    EventType = "com.yourplatform.auth.user.password_changed.v1"
	AuthUserPasswordResetV1      EventType = "com.yourplatform.auth.user.password_reset.v1"
	AuthUserLoginSuccessV1       EventType = "com.yourplatform.auth.user.login_success.v1"
	AuthUserLogoutSuccessV1      EventType = "com.yourplatform.auth.user.logout_success.v1"
	AuthUserAccountBlockedV1     EventType = "com.yourplatform.auth.user.account.blocked.v1"
	AuthUserAccountUnblockedV1   EventType = "com.yourplatform.auth.user.account.unblocked.v1"
	AuthUserProfileUpdatedV1     EventType = "com.yourplatform.auth.user.profile_updated.v1"
	AuthUserAccountDeactivatedV1 EventType = "com.yourplatform.auth.user.account.deactivated.v1"
	AuthUserEmailVerificationRequiredV1 EventType = "com.yourplatform.auth.user.emailverification.required.v1" // Added new


	// Session Events
	AuthSessionCreatedV1 EventType = "com.yourplatform.auth.session.created.v1"
	AuthSessionRevokedV1 EventType = "com.yourplatform.auth.session.revoked.v1"
	AuthUserAllSessionsRevokedV1 EventType = "com.yourplatform.auth.user.all_sessions_revoked.v1"


	// MFA Events
	AuthMFAEnabledV1      EventType = "com.yourplatform.auth.user.2fa.enabled.v1"
	AuthMFADisabledV1     EventType = "com.yourplatform.auth.user.2fa.disabled.v1"
	AuthMFABackupCodesGeneratedV1 EventType = "com.yourplatform.auth.user.2fa.backup_codes_generated.v1"
	AuthMFABackupCodeUsedV1 EventType = "com.yourplatform.auth.user.2fa.backup_code_used.v1"


	// API Key Events
	AuthAPIKeyCreatedV1 EventType = "com.yourplatform.auth.user.apikey.created.v1"
	AuthAPIKeyRevokedV1 EventType = "com.yourplatform.auth.user.apikey.revoked.v1"

	// Role and Permission Events (Admin actions)
	AuthRoleCreatedV1 EventType = "com.yourplatform.auth.rbac.role.created.v1"
	AuthRoleUpdatedV1 EventType = "com.yourplatform.auth.rbac.role.updated.v1"
	AuthRoleDeletedV1 EventType = "com.yourplatform.auth.rbac.role.deleted.v1"
	AuthPermissionCreatedV1 EventType = "com.yourplatform.auth.rbac.permission.created.v1"
	AuthPermissionUpdatedV1 EventType = "com.yourplatform.auth.rbac.permission.updated.v1"
	AuthPermissionDeletedV1 EventType = "com.yourplatform.auth.rbac.permission.deleted.v1"
	AuthUserRoleAssignedV1 EventType = "com.yourplatform.auth.rbac.user_role.assigned.v1"
	AuthUserRoleRevokedV1 EventType = "com.yourplatform.auth.rbac.user_role.revoked.v1"
	AuthRolePermissionAssignedV1 EventType = "com.yourplatform.auth.rbac.role_permission.assigned.v1"
	AuthRolePermissionRevokedV1 EventType = "com.yourplatform.auth.rbac.role_permission.revoked.v1"

	// Security Events
	AuthSecurityPasswordResetRequestedV1 EventType = "com.yourplatform.auth.security.password_reset_requested.v1"
	AuthSecurityEmailVerificationRequestedV1 EventType = "com.yourplatform.auth.security.email_verification_requested.v1"
	AuthSecuritySuspiciousActivityDetectedV1 EventType = "com.yourplatform.auth.security.suspicious_activity.detected.v1"
	AuthSecurityTokenRevokedV1 EventType = "com.yourplatform.auth.security.token.revoked.v1"
)

// --- Event Payloads ---

// UserRegisteredPayload is the data for AuthUserRegisteredV1.
type UserRegisteredPayload struct {
	UserID                 string    `json:"user_id"`
	Username               string    `json:"username"`
	Email                  string    `json:"email"`
	DisplayName            *string   `json:"display_name,omitempty"`
	RegistrationTimestamp  time.Time `json:"registration_timestamp"`
	InitialStatus          string    `json:"initial_status"`
}

// UserEmailVerifiedPayload is the data for AuthUserEmailVerifiedV1.
type UserEmailVerifiedPayload struct {
	UserID         string    `json:"user_id"`
	Email          string    `json:"email"`
	VerifiedAt     time.Time `json:"verified_at"`
}

// UserPasswordChangedPayload is the data for AuthUserPasswordChangedV1.
type UserPasswordChangedPayload struct {
	UserID        string    `json:"user_id"`
	ChangedAt     time.Time `json:"changed_at"`
	Source        string    `json:"source"`
}

// UserPasswordResetPayload is the data for AuthUserPasswordResetV1.
type UserPasswordResetPayload struct {
	UserID    string    `json:"user_id"`
	ResetAt   time.Time `json:"reset_at"`
}

// UserLoginSuccessPayload is the data for AuthUserLoginSuccessV1.
type UserLoginSuccessPayload struct {
	UserID     string    `json:"user_id"`
	SessionID  string    `json:"session_id"`
	LoginAt    time.Time `json:"login_at"`
	IPAddress  string    `json:"ip_address,omitempty"`
	UserAgent  string    `json:"user_agent,omitempty"`
	LoginType  string    `json:"login_type"`
}

// UserLogoutSuccessPayload is the data for AuthUserLogoutSuccessV1.
type UserLogoutSuccessPayload struct {
	UserID    string    `json:"user_id"`
	SessionID string    `json:"session_id"`
	LogoutAt  time.Time `json:"logout_at"`
}

// UserAccountBlockedPayload is the data for AuthUserAccountBlockedV1.
type UserAccountBlockedPayload struct {
	UserID    string    `json:"user_id"`
	BlockedAt time.Time `json:"blocked_at"`
	Reason    *string   `json:"reason,omitempty"`
	ActorID   *string   `json:"actor_id,omitempty"`
}

// UserAccountUnblockedPayload is the data for AuthUserAccountUnblockedV1.
type UserAccountUnblockedPayload struct {
	UserID      string    `json:"user_id"`
	UnblockedAt time.Time `json:"unblocked_at"`
	ActorID     *string   `json:"actor_id,omitempty"`
}

// UserProfileUpdatedPayload is the data for AuthUserProfileUpdatedV1.
type UserProfileUpdatedPayload struct {
	UserID        string    `json:"user_id"`
	UpdatedAt     time.Time `json:"updated_at"`
	ChangedFields []string  `json:"changed_fields,omitempty"`
	ActorID       *string   `json:"actor_id,omitempty"`
}

// UserAccountDeactivatedPayload is the data for AuthUserAccountDeactivatedV1.
type UserAccountDeactivatedPayload struct {
	UserID        string    `json:"user_id"`
	DeactivatedAt time.Time `json:"deactivated_at"`
	ActorID       *string   `json:"actor_id,omitempty"`
}

// UserEmailVerificationRequiredPayload is the data for AuthUserEmailVerificationRequiredV1.
type UserEmailVerificationRequiredPayload struct {
	UserID             string    `json:"user_id"`
	Email              string    `json:"email"` // The new email that requires verification
	VerificationToken  string    `json:"verification_token"` // Plain token to be sent to user
	RequestTimestamp   time.Time `json:"request_timestamp"`
}


// SessionCreatedPayload is the data for AuthSessionCreatedV1.
type SessionCreatedPayload struct {
	SessionID  string    `json:"session_id"`
	UserID     string    `json:"user_id"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	IPAddress  string    `json:"ip_address,omitempty"`
	UserAgent  string    `json:"user_agent,omitempty"`
}

// SessionRevokedPayload is the data for AuthSessionRevokedV1.
type SessionRevokedPayload struct {
	SessionID string    `json:"session_id"`
	UserID    string    `json:"user_id"`
	RevokedAt time.Time `json:"revoked_at"`
	ActorID   *string   `json:"actor_id,omitempty"`
}

// UserAllSessionsRevokedPayload is the data for AuthUserAllSessionsRevokedV1.
type UserAllSessionsRevokedPayload struct {
	UserID    string    `json:"user_id"`
	RevokedAt time.Time `json:"revoked_at"`
	ActorID   *string   `json:"actor_id,omitempty"`
}

// MFAEnabledPayload is the data for AuthMFAEnabledV1.
type MFAEnabledPayload struct {
	UserID    string    `json:"user_id"`
	MFAType   string    `json:"mfa_type"`
	EnabledAt time.Time `json:"enabled_at"`
}

// MFADisabledPayload is the data for AuthMFADisabledV1.
type MFADisabledPayload struct {
	UserID     string    `json:"user_id"`
	MFAType    string    `json:"mfa_type"`
	DisabledAt time.Time `json:"disabled_at"`
}

// MFABackupCodesGeneratedPayload is the data for AuthMFABackupCodesGeneratedV1.
type MFABackupCodesGeneratedPayload struct {
	UserID      string    `json:"user_id"`
	GeneratedAt time.Time `json:"generated_at"`
	CodeCount   int       `json:"code_count"`
}

// MFABackupCodeUsedPayload is the data for AuthMFABackupCodeUsedV1.
type MFABackupCodeUsedPayload struct {
	UserID       string    `json:"user_id"`
	BackupCodeID string    `json:"backup_code_id"`
	UsedAt       time.Time `json:"used_at"`
}

// APIKeyCreatedPayload is the data for AuthAPIKeyCreatedV1.
type APIKeyCreatedPayload struct {
	APIKeyID    string    `json:"api_key_id"`
	UserID      string    `json:"user_id"`
	Name        string    `json:"name,omitempty"`
	KeyPrefix   string    `json:"key_prefix"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	Permissions []string  `json:"permissions,omitempty"`
}

// APIKeyRevokedPayload is the data for AuthAPIKeyRevokedV1.
type APIKeyRevokedPayload struct {
	APIKeyID  string    `json:"api_key_id"`
	UserID    string    `json:"user_id"`
	RevokedAt time.Time `json:"revoked_at"`
}

// RoleCreatedPayload is the data for AuthRoleCreatedV1.
type RoleCreatedPayload struct {
	RoleID      string    `json:"role_id"`
	Name        string    `json:"name"`
	Description *string   `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	ActorID     *string   `json:"actor_id,omitempty"`
}

// RoleUpdatedPayload is the data for AuthRoleUpdatedV1.
type RoleUpdatedPayload struct {
	RoleID         string    `json:"role_id"`
	Name           *string   `json:"name,omitempty"`
	Description    *string   `json:"description,omitempty"`
	UpdatedAt      time.Time `json:"updated_at"`
	ActorID        *string   `json:"actor_id,omitempty"`
	ChangedFields  []string  `json:"changed_fields,omitempty"`
}

// RoleDeletedPayload is the data for AuthRoleDeletedV1.
type RoleDeletedPayload struct {
	RoleID    string    `json:"role_id"`
	DeletedAt time.Time `json:"deleted_at"`
	ActorID   *string   `json:"actor_id,omitempty"`
}

// UserRoleChangePayload is for both assign and revoke user-role events.
type UserRoleChangePayload struct {
	UserID          string    `json:"user_id"`
	RoleID          string    `json:"role_id"`
	ChangedAt       time.Time `json:"changed_at"`
	ActorID         *string   `json:"actor_id,omitempty"`
}

// RolePermissionChangePayload is for both assign and revoke role-permission events.
type RolePermissionChangePayload struct {
	RoleID       string    `json:"role_id"`
	PermissionID string    `json:"permission_id"`
	ChangedAt    time.Time `json:"changed_at"`
	ActorID      *string   `json:"actor_id,omitempty"`
}


// PasswordResetRequestedPayload is the data for AuthSecurityPasswordResetRequestedV1.
type PasswordResetRequestedPayload struct {
	UserID      string    `json:"user_id"`
	Email       string    `json:"email"`
	RequestedAt time.Time `json:"requested_at"`
}

// EmailVerificationRequestedPayload is the data for AuthSecurityEmailVerificationRequestedV1.
type EmailVerificationRequestedPayload struct {
	UserID      string    `json:"user_id"`
	Email       string    `json:"email"`
	RequestedAt time.Time `json:"requested_at"`
}

// SuspiciousActivityPayload is a placeholder for AuthSecuritySuspiciousActivityDetectedV1.
type SuspiciousActivityPayload struct {
	ActivityType string      `json:"activity_type"`
	UserID       *string     `json:"user_id,omitempty"`
	Timestamp    time.Time   `json:"timestamp"`
	Details      interface{} `json:"details,omitempty"`
	Severity     string      `json:"severity,omitempty"`
}
