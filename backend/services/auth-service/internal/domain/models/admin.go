// File: backend/services/auth-service/internal/domain/models/admin.go
package models

import "github.com/google/uuid"

// PaginationMeta holds metadata for paginated responses.
type PaginationMeta struct {
	CurrentPage int   `json:"current_page"`
	PageSize    int   `json:"page_size"`
	TotalItems  int   `json:"total_items"`
	TotalPages  int   `json:"total_pages"`
}

// BlockUserRequest DTO for blocking a user.
type BlockUserRequest struct {
	Reason string `json:"reason" binding:"required,max=255"`
}

// UpdateUserRolesRequest DTO for updating a user's roles.
type UpdateUserRolesRequest struct {
	RoleIDs []string `json:"role_ids" binding:"required,dive,alphanum,max=50"` // List of role IDs (strings)
}

// AdminUserResponse could be more detailed than the standard UserResponse if needed.
// For now, we can assume UserResponse is sufficient, or define AdminUserResponse here.
// type AdminUserResponse struct {
// 	ID                  uuid.UUID  `json:"id"`
// 	Username            string     `json:"username"`
// 	Email               string     `json:"email"`
// 	Status              UserStatus `json:"status"`
// 	Roles               []string   `json:"roles"` // Role names
// 	EmailVerifiedAt     *time.Time `json:"email_verified_at,omitempty"`
// 	LastLoginAt         *time.Time `json:"last_login_at,omitempty"`
// 	FailedLoginAttempts int        `json:"failed_login_attempts"`
// 	LockoutUntil        *time.Time `json:"lockout_until,omitempty"`
// 	CreatedAt           time.Time  `json:"created_at"`
// 	UpdatedAt           time.Time  `json:"updated_at"`
// 	DeletedAt           *time.Time `json:"deleted_at,omitempty"`
// }


// AuditLogResponse DTO for audit log entries.
// Assuming models.AuditLog is the primary model and can be used directly or mapped.
// For now, we can use models.AuditLog directly in responses if its fields are suitable.
// type AuditLogResponse models.AuditLog

// ListAuditLogsParams was defined in repository.audit_log_repository.go.
// If it needs to be a shared DTO for handlers, it could be moved to models.
// For now, keeping it in repository as it's closely tied to repo filtering.

// Helper to convert []models.User to []models.UserResponse
// This might be better placed in user.go or a shared DTO helper if used elsewhere.
// func ToUserResponses(users []*User) []UserResponse {
// 	responses := make([]UserResponse, len(users))
// 	for i, u := range users {
// 		responses[i] = u.ToResponse()
// 	}
// 	return responses
// }
