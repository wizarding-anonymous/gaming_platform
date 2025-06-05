// File: backend/services/auth-service/internal/domain/service/rbac_service.go
package service

import (
	"context"
	"errors"
	"fmt"
	"sort" // For de-duplicating permissions

	"github.com/gameplatform/auth-service/internal/domain/entity"
	"github.com/gameplatform/auth-service/internal/domain/repository"
)

// RBACService defines the interface for Role-Based Access Control operations.
type RBACService interface {
	AssignRoleToUser(ctx context.Context, userID string, roleID string, assignedByUserID *string) error
	RevokeRoleFromUser(ctx context.Context, userID string, roleID string) error
	GetUserRoles(ctx context.Context, userID string) ([]*entity.Role, error)
	GetRolePermissions(ctx context.Context, roleID string) ([]*entity.Permission, error)
	GetAllUserPermissions(ctx context.Context, userID string) ([]*entity.Permission, error)
	CheckUserPermission(ctx context.Context, userID string, permissionID string) (bool, error) // permissionID is the string ID like "games.publish"
}

type rbacServiceImpl struct {
	userRepo       repository.UserRepository
	roleRepo       repository.RoleRepository
	permissionRepo repository.PermissionRepository
	// No direct need for user_roles or role_permissions repos if RoleRepository handles those relationships.
}

// RBACServiceConfig holds dependencies for RBACService.
type RBACServiceConfig struct {
	UserRepo       repository.UserRepository
	RoleRepo       repository.RoleRepository
	PermissionRepo repository.PermissionRepository
}

// NewRBACService creates a new rbacServiceImpl.
func NewRBACService(cfg RBACServiceConfig) RBACService {
	return &rbacServiceImpl{
		userRepo:       cfg.UserRepo,
		roleRepo:       cfg.RoleRepo,
		permissionRepo: cfg.PermissionRepo,
	}
}

func (s *rbacServiceImpl) AssignRoleToUser(ctx context.Context, userID string, roleID string, assignedByUserID *string) error {
	// 1. Check if user exists
	_, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		// Assuming FindByID returns a specific error like entity.ErrUserNotFound
		if errors.Is(err, errors.New("user not found")) { // Placeholder for actual error
			return errors.New("user not found for role assignment") // Placeholder
		}
		return fmt.Errorf("failed to find user for role assignment: %w", err)
	}

	// 2. Check if role exists
	_, err = s.roleRepo.FindByID(ctx, roleID)
	if err != nil {
		if errors.Is(err, errors.New("role not found")) { // Placeholder for actual error
			return errors.New("role not found for assignment") // Placeholder
		}
		return fmt.Errorf("failed to find role for assignment: %w", err)
	}

	// 3. Create entry in user_roles (handled by RoleRepository)
	if err := s.roleRepo.AssignToUser(ctx, userID, roleID, assignedByUserID); err != nil {
		// Handle potential duplicate assignment errors if the repo method doesn't UPSERT/ignore
		return fmt.Errorf("failed to assign role to user: %w", err)
	}

	// TODO: Publish auth.user.roles_changed event
	fmt.Printf("Event: auth.user.roles_changed for user %s (role %s assigned)\n", userID, roleID)
	return nil
}

func (s *rbacServiceImpl) RevokeRoleFromUser(ctx context.Context, userID string, roleID string) error {
	// 1. Check if user exists (optional, depends on desired strictness)
	// 2. Check if role exists (optional)

	if err := s.roleRepo.RemoveFromUser(ctx, userID, roleID); err != nil {
		// Handle cases where the user didn't have the role (repo might not error)
		return fmt.Errorf("failed to revoke role from user: %w", err)
	}

	// TODO: Publish auth.user.roles_changed event
	fmt.Printf("Event: auth.user.roles_changed for user %s (role %s revoked)\n", userID, roleID)
	return nil
}

func (s *rbacServiceImpl) GetUserRoles(ctx context.Context, userID string) ([]*entity.Role, error) {
	roles, err := s.roleRepo.GetRolesForUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}
	return roles, nil
}

func (s *rbacServiceImpl) GetRolePermissions(ctx context.Context, roleID string) ([]*entity.Permission, error) {
	permissions, err := s.roleRepo.GetPermissionsForRole(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("failed to get role permissions: %w", err)
	}
	return permissions, nil
}

func (s *rbacServiceImpl) GetAllUserPermissions(ctx context.Context, userID string) ([]*entity.Permission, error) {
	roles, err := s.GetUserRoles(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles for permissions lookup: %w", err)
	}

	allPermissionsMap := make(map[string]*entity.Permission) // To de-duplicate

	for _, role := range roles {
		rolePermissions, err := s.GetRolePermissions(ctx, role.ID)
		if err != nil {
			// Log error and continue, or return error depending on desired behavior
			// For now, return error to indicate partial permission set might be an issue
			return nil, fmt.Errorf("failed to get permissions for role %s: %w", role.ID, err)
		}
		for _, p := range rolePermissions {
			allPermissionsMap[p.ID] = p
		}
	}

	finalPermissions := make([]*entity.Permission, 0, len(allPermissionsMap))
	for _, p := range allPermissionsMap {
		finalPermissions = append(finalPermissions, p)
	}
	// Optional: Sort permissions by ID or Name
	sort.Slice(finalPermissions, func(i, j int) bool {
		return finalPermissions[i].ID < finalPermissions[j].ID
	})

	return finalPermissions, nil
}

func (s *rbacServiceImpl) CheckUserPermission(ctx context.Context, userID string, permissionID string) (bool, error) {
	userPermissions, err := s.GetAllUserPermissions(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("failed to get user permissions for check: %w", err)
	}

	for _, p := range userPermissions {
		if p.ID == permissionID { // Assuming permissionID is the string ID like "games.publish"
			return true, nil
		}
		// Also could check by p.Name if permissionID is meant to be the human-readable name
	}

	return false, nil
}

var _ RBACService = (*rbacServiceImpl)(nil)
