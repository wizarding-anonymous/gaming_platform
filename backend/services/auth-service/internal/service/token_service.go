// File: backend/services/auth-service/internal/service/token_service.go
package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/config"
	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/repository/redis"
	"go.uber.org/zap"
)

	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/repository/redis"
	repoInterfaces "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/repository/interfaces" // For new repo dependencies
	domainService "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/service"     // For TokenManagementService
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/infrastructure/security"      // For HashToken
	"go.uber.org/zap"
)

// TokenService представляет сервис для работы с токенами
type TokenService struct {
	redisClient          *redis.RedisClient
	logger               *zap.Logger
	tokenMgmtService     domainService.TokenManagementService
	refreshTokenRepo     repoInterfaces.RefreshTokenRepository
	userRepo             repoInterfaces.UserRepository     // For fetching user details if needed during refresh
	sessionRepo          repoInterfaces.SessionRepository  // For validating session during refresh
	userRolesRepo        repoInterfaces.UserRolesRepository  // Added for JWT enrichment
	roleRepo             repoInterfaces.RoleRepository     // Added for JWT enrichment (permissions per role)
}

// NewTokenService создает новый экземпляр TokenService
func NewTokenService(
	redisClient *redis.RedisClient,
	logger *zap.Logger,
	tokenMgmtService domainService.TokenManagementService,
	refreshTokenRepo repoInterfaces.RefreshTokenRepository,
	userRepo repoInterfaces.UserRepository,
	sessionRepo repoInterfaces.SessionRepository,
	userRolesRepo repoInterfaces.UserRolesRepository, // Added
	roleRepo repoInterfaces.RoleRepository,       // Added
) *TokenService {
	return &TokenService{
		redisClient:          redisClient,
		logger:               logger,
		tokenMgmtService:     tokenMgmtService,
		refreshTokenRepo:     refreshTokenRepo,
		userRepo:             userRepo,
		sessionRepo:          sessionRepo,
		userRolesRepo:        userRolesRepo, // Added
		roleRepo:             roleRepo,       // Added
	}
}

// CreateTokenPairWithSession генерирует пару токенов (access и refresh) для сессии.
// user: The user for whom the token is generated.
// sessionID: The ID of the session this token pair is associated with.
func (s *TokenService) CreateTokenPairWithSession(ctx context.Context, user *models.User, sessionID uuid.UUID) (models.TokenPair, error) {
	// Generate access token using TokenManagementService
	// Assuming user.Roles and user.Permissions are populated. If not, fetch them.
	var roleNames []string
	// var permissionNames []string // Assuming permissions are not directly in access token for now or fetched separately
	// for _, r := range user.Roles { // This was if user.Roles was []models.Role
	// roleNames = append(roleNames, r.Name)
	// }
	// If user.Roles is already []string from a simplified User model in some contexts:
	// roleNames = user.Roles

	// For now, let's assume roles need to be fetched if not on user model directly
	// This part highlights a dependency: need fully populated user or fetch roles here.
	// For simplicity, if user.Roles is not directly available as []string, pass empty.
	// This should be refined based on how user details are propagated.
	// Fetch roles and permissions for the user for JWT claims
	roleIDs, err := s.userRolesRepo.GetRoleIDsForUser(ctx, user.ID)
	if err != nil {
		s.logger.Error("Failed to get role IDs for user for token generation", zap.Error(err), zap.String("userID", user.ID.String()))
		// Decide if this is a fatal error for token generation or proceed with no roles/permissions
		// For now, proceed with empty, but log it.
		roleIDs = []string{}
	}

	roleNames := make([]string, 0, len(roleIDs))
	permissionNames := make([]string, 0)
	permissionSet := make(map[string]struct{}) // To store unique permission names

	for _, roleID := range roleIDs {
		role, errRole := s.roleRepo.GetByID(ctx, roleID)
		if errRole != nil {
			s.logger.Warn("Failed to get role details for token generation", zap.Error(errRole), zap.String("roleID", roleID))
			continue // Skip this role if details can't be fetched
		}
		roleNames = append(roleNames, role.Name)

		perms, errPerms := s.roleRepo.GetPermissionsForRole(ctx, roleID)
		if errPerms != nil {
			s.logger.Warn("Failed to get permissions for role for token generation", zap.Error(errPerms), zap.String("roleID", roleID))
			continue // Skip permissions for this role if error
		}
		for _, p := range perms {
			if _, exists := permissionSet[p.ID]; !exists { // Using p.ID as permission name/key
				permissionNames = append(permissionNames, p.ID)
				permissionSet[p.ID] = struct{}{}
			}
		}
	}

	accessTokenString, claims, err := s.tokenMgmtService.GenerateAccessToken(user.ID.String(), user.Username, roleNames, permissionNames, sessionID.String())
	if err != nil {
		return models.TokenPair{}, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Генерация refresh токена
	opaqueRefreshTokenValue, err := s.tokenMgmtService.GenerateRefreshTokenValue()
	if err != nil {
		return models.TokenPair{}, fmt.Errorf("failed to generate opaque refresh token: %w", err)
	}

	hashedRefreshToken := security.HashToken(opaqueRefreshTokenValue)
	refreshTokenExpiry := time.Now().Add(s.tokenMgmtService.GetRefreshTokenExpiry())

	refreshToken := &models.RefreshToken{
		ID:        uuid.New(), // Generate new ID for the refresh token entry
		SessionID: sessionID,
		UserID:    user.ID,
		TokenHash: hashedRefreshToken,
		ExpiresAt: refreshTokenExpiry,
	}

	if err := s.refreshTokenRepo.Create(ctx, refreshToken); err != nil {
		return models.TokenPair{}, fmt.Errorf("failed to store refresh token: %w", err)
	}

	return models.TokenPair{
		AccessToken:  accessTokenString,
		RefreshToken: opaqueRefreshTokenValue, // Return plain opaque token to client
		ExpiresIn:    int(s.tokenMgmtService.cfg.AccessTokenTTL.Seconds()), // Access token TTL from new service
		TokenType:    "Bearer",
	}, nil
}

// RefreshTokens обновляет пару токенов по refresh токену
func (s *TokenService) RefreshTokens(ctx context.Context, plainOpaqueRefreshToken string) (models.TokenPair, error) {
	hashedIncomingRefreshToken := security.HashToken(plainOpaqueRefreshToken)

	storedRefreshToken, err := s.refreshTokenRepo.FindByTokenHash(ctx, hashedIncomingRefreshToken)
	if err != nil {
		if errors.Is(err, domainErrors.ErrNotFound) {
			return models.TokenPair{}, domainErrors.ErrInvalidRefreshToken
		}
		s.logger.Error("Error finding refresh token by hash", zap.Error(err))
		return models.TokenPair{}, err
	}

	// FindByTokenHash in repo already checks if active (not revoked, not expired)

	// Fetch associated user
	user, err := s.userRepo.FindByID(ctx, storedRefreshToken.UserID)
	if err != nil {
		s.logger.Error("User not found for refresh token", zap.String("user_id", storedRefreshToken.UserID.String()), zap.Error(err))
		return models.TokenPair{}, domainErrors.ErrUserNotFound
	}
	if user.Status == models.UserStatusBlocked || user.Status == models.UserStatusDeleted {
		return models.TokenPair{}, domainErrors.ErrUserBlocked
	}

	// Fetch associated session (optional, but good for validation if session can be independently invalidated)
	_, err = s.sessionRepo.FindByID(ctx, storedRefreshToken.SessionID)
	if err != nil {
		s.logger.Error("Session not found for refresh token", zap.String("session_id", storedRefreshToken.SessionID.String()), zap.Error(err))
		return models.TokenPair{}, domainErrors.ErrSessionNotFound // Or ErrInvalidRefreshToken
	}
	// TODO: Add check here if session.IsActive or similar if sessions can be revoked separately.

	// Rotation: Revoke the old refresh token
	revokeReason := "rotated"
	if err := s.refreshTokenRepo.Revoke(ctx, storedRefreshToken.ID, &revokeReason); err != nil {
		s.logger.Error("Failed to revoke old refresh token during rotation", zap.Error(err), zap.String("token_id", storedRefreshToken.ID.String()))
		// Continue with generating new tokens, but log this issue.
	}

	// Generate new token pair (linked to the same session)
	// Need to get roles for the user for the new access token
	// This part requires a way to get roles, assuming user.Roles is not populated by FindByID directly
	// or UserRolesRepository needs to be used. For now, passing empty roles.
	// This needs to be addressed for proper claims.
	var rolesForToken []string
	// roles, _ := s.userRepo.GetRolesForUser(ctx, user.ID) // Example if userRepo had this method
	// for _, r := range roles { rolesForToken = append(rolesForToken, r.Name) }


	newAccessTokenString, newClaims, err := s.tokenMgmtService.GenerateAccessToken(user.ID.String(), user.Username, rolesForToken, nil, storedRefreshToken.SessionID.String())
	if err != nil {
		return models.TokenPair{}, fmt.Errorf("failed to generate new access token: %w", err)
	}

	newOpaqueRefreshTokenValue, err := s.tokenMgmtService.GenerateRefreshTokenValue()
	if err != nil {
		return models.TokenPair{}, fmt.Errorf("failed to generate new opaque refresh token: %w", err)
	}

	hashedNewRefreshToken := security.HashToken(newOpaqueRefreshTokenValue)
	newRefreshTokenExpiry := time.Now().Add(s.tokenMgmtService.GetRefreshTokenExpiry())

	newRefreshToken := &models.RefreshToken{
		ID:        uuid.New(),
		SessionID: storedRefreshToken.SessionID,
		UserID:    user.ID,
		TokenHash: hashedNewRefreshToken,
		ExpiresAt: newRefreshTokenExpiry,
	}
	if err := s.refreshTokenRepo.Create(ctx, newRefreshToken); err != nil {
		return models.TokenPair{}, fmt.Errorf("failed to store new refresh token: %w", err)
	}

	return models.TokenPair{
		AccessToken:  newAccessTokenString,
		RefreshToken: newOpaqueRefreshTokenValue,
		ExpiresIn:    int(s.tokenMgmtService.cfg.AccessTokenTTL.Seconds()),
		TokenType:    "Bearer",
	}, nil
}


// ValidateAccessToken проверяет валидность access токена
func (s *TokenService) ValidateAccessToken(ctx context.Context, tokenString string) (*service.Claims, error) {
	// Проверка, находится ли токен в черном списке
	isBlacklisted, err := s.redisClient.IsBlacklisted(ctx, tokenString)
	if err != nil {
		return nil, fmt.Errorf("failed to check token blacklist: %w", err)
	}
	if isBlacklisted {
		return nil, domainErrors.ErrRevokedToken
	}

	// Delegate to TokenManagementService for actual JWT validation
	claims, err := s.tokenMgmtService.ValidateAccessToken(tokenString)
	if err != nil {
		// Map errors from tokenMgmtService to domainErrors if necessary, or let them pass through
		// Example: if errors.Is(err, jwt.ErrTokenExpired) { return nil, domainErrors.ErrExpiredToken }
		return nil, err // Propagate error (e.g., expired, invalid signature, etc.)
	}
	return claims, nil
}


// RevokeToken отзывает access токен (adds to blacklist)
func (s *TokenService) RevokeToken(ctx context.Context, tokenString string) error {
	claims, err := s.tokenMgmtService.ValidateAccessToken(tokenString) // Validate first to get expiry
	if err != nil {
		// If token is already invalid (e.g. expired, malformed), no need to blacklist.
		// However, if it's just an unknown signature but parsable, we might still want to blacklist its JTI if available.
		// For simplicity, if ValidateAccessToken fails, assume it's not a candidate for blacklisting or already handled.
		// Check specific errors if needed: e.g. don't blacklist if ErrTokenExpired.
		if !errors.Is(err, jwt.ErrTokenExpired) {
			s.logger.Debug("Attempted to revoke token that failed validation", zap.Error(err))
		}
		return nil // Or return error if strict revocation of any provided string is needed
	}

	// Use JTI (ID from claims) for blacklisting if possible, or the full token string.
	// Using full token string is simpler for Redis but less standard than JTI.
	// The current redisClient.AddToBlacklist likely uses the token string.

	expiresAt := claims.ExpiresAt.Time
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		// Токен уже истек
		return nil
	}

	// Добавление токена в черный список
	err = s.redisClient.AddToBlacklist(ctx, tokenString, ttl)
	if err != nil {
		return fmt.Errorf("failed to add token to blacklist: %w", err)
	}
	return nil
}


// RevokeRefreshToken отзывает refresh токен (from PostgreSQL)
func (s *TokenService) RevokeRefreshToken(ctx context.Context, plainOpaqueRefreshToken string) error {
	hashedToken := security.HashToken(plainOpaqueRefreshToken)
	storedToken, err := s.refreshTokenRepo.FindByTokenHash(ctx, hashedToken)
	if err != nil {
		if errors.Is(err, domainErrors.ErrNotFound) {
			return domainErrors.ErrInvalidRefreshToken // Not found or already invalidated
		}
		return fmt.Errorf("error finding refresh token to revoke: %w", err)
	}

	revokeReason := "user_revoked"
	return s.refreshTokenRepo.Revoke(ctx, storedToken.ID, &revokeReason)
}


// --- Removed HMAC specific token generation methods ---
// generateAccessToken(user models.User) (string, error)
// generateRefreshToken(userID uuid.UUID) (string, error)

// --- Removed JWT-based Email/Password Reset methods (now handled by VerificationCodeRepository) ---
// GenerateEmailVerificationToken(userID uuid.UUID) (string, error)
// ValidateEmailVerificationToken(tokenString string) (uuid.UUID, error)
// GeneratePasswordResetToken(userID uuid.UUID) (string, error)
// ValidatePasswordResetToken(tokenString string) (uuid.UUID, error)

// RevokeAllRefreshTokensForUser revokes all refresh tokens for a given user from PostgreSQL.
func (s *TokenService) RevokeAllRefreshTokensForUser(ctx context.Context, userID uuid.UUID) (int64, error) {
	s.logger.Info("Revoking all refresh tokens for user", zap.String("user_id", userID.String()))
	deletedCount, err := s.refreshTokenRepo.DeleteByUserID(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to revoke/delete all refresh tokens for user",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		return 0, fmt.Errorf("failed to delete refresh tokens for user %s: %w", userID, err)
	}
	return deletedCount, nil
}
