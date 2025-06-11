// File: backend/services/auth-service/internal/domain/models/api_permissions.go
package models

// ValidAPIPermissions defines allowed permission IDs for API keys.
var ValidAPIPermissions = map[string]struct{}{
	"auth.users.read.self":           {},
	"auth.users.edit.self":           {},
	"auth.admin.users.list":          {},
	"auth.admin.users.edit":          {},
	"auth.admin.roles.manage":        {},
	"auth.2fa.manage":                {},
	"auth.sessions.view":             {},
	"auth.sessions.manage":           {},
	"auth.api_keys.view":             {},
	"auth.api_keys.manage":           {},
	"auth.admin.users.block":         {},
	"auth.admin.permissions.manage":  {},
	"auth.audit.view":                {},
	"auth.admin.sessions.manage_all": {},
}

// IsValidAPIPermission checks if p is in the predefined set of permissions.
func IsValidAPIPermission(p string) bool {
	_, ok := ValidAPIPermissions[p]
	return ok
}
