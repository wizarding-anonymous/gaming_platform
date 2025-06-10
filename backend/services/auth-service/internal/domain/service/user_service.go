// File: backend/services/auth-service/internal/domain/service/user_service.go
package service

import (
	"context"

	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/entity"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/repository"
)

// UserService defines the interface for user-related operations.
type UserService interface {
	// GetUserFullInfo retrieves detailed information about a user, including their MFA status.
	GetUserFullInfo(ctx context.Context, userID string) (*entity.User, bool, error) // Returns User, mfaEnabled, error
}

type userServiceImpl struct {
	userRepo      repository.UserRepository
	mfaSecretRepo repository.MFASecretRepository
}

// UserServiceConfig holds dependencies for UserService.
type UserServiceConfig struct {
	UserRepo      repository.UserRepository
	MFASecretRepo repository.MFASecretRepository
}

// NewUserService creates a new userServiceImpl.
func NewUserService(cfg UserServiceConfig) UserService {
	return &userServiceImpl{
		userRepo:      cfg.UserRepo,
		mfaSecretRepo: cfg.MFASecretRepo,
	}
}

// GetUserFullInfo retrieves user details and their MFA status.
func (s *userServiceImpl) GetUserFullInfo(ctx context.Context, userID string) (*entity.User, bool, error) {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return nil, false, err // Propagate error (e.g., user not found)
	}

	mfaEnabled := false
	mfaSecret, err := s.mfaSecretRepo.FindByUserIDAndType(ctx, userID, entity.MFATypeTOTP)
	if err == nil && mfaSecret != nil && mfaSecret.Verified {
		mfaEnabled = true
	}
	// If err is not "not found", it might be a DB issue, log it.
	// For now, if secret not found or not verified, mfaEnabled remains false.

	return user, mfaEnabled, nil
}

var _ UserService = (*userServiceImpl)(nil)
