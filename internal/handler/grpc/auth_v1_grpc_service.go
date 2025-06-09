// File: internal/handler/grpc/auth_v1_grpc_service.go
package grpc

import (
	"context"
	"encoding/base64"
	"errors" // Standard errors
	"math/big" // For JWKS e and n

	"github.com/google/uuid"
	authv1 "github.com/your-org/auth-service/gen/go/auth/v1"
	"github.com/your-org/auth-service/internal/domain/models" // For User model if UserService returns it
	domainErrors "github.com/your-org/auth-service/internal/domain/errors"
	domainService "github.com/your-org/auth-service/internal/domain/service"
	"github.com/your-org/auth-service/internal/service" // For concrete AuthService, UserService
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// AuthV1Service implements the gRPC AuthService server (using the workaround interface).
type AuthV1Service struct {
	AuthServiceServer_Workaround // Embed the workaround

	logger                 *zap.Logger
	tokenManagementService domainService.TokenManagementService
	authService            *service.AuthService            // For CheckPermission, GetUserInfo (if it has roles/mfa status)
	userService            *service.UserService            // For GetUserInfo if specific user details are there
	// rbacService            domainService.RBACService // If a separate RBAC service exists
}

// NewAuthV1Service creates a new AuthV1Service.
func NewAuthV1Service(
	logger *zap.Logger,
	tokenManagementService domainService.TokenManagementService,
	authService *service.AuthService,
	userService *service.UserService,
	// rbacService domainService.RBACService,
) *AuthV1Service {
	return &AuthV1Service{
		logger:                 logger.Named("grpc_auth_v1_service"),
		tokenManagementService: tokenManagementService,
		authService:            authService,
		userService:            userService,
		// rbacService:            rbacService,
	}
}

// ValidateToken implements AuthServiceServer_Workaround.
func (s *AuthV1Service) ValidateToken(ctx context.Context, req *authv1.ValidateTokenRequest) (*authv1.ValidateTokenResponse, error) {
	if req.GetToken() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "token is required")
	}

	claims, err := s.tokenManagementService.ValidateAccessToken(req.GetToken())
	if err != nil {
		s.logger.Debug("ValidateToken: token validation failed", zap.Error(err))
		resp := &authv1.ValidateTokenResponse{Valid: false}
		// Attempt to map domain errors to gRPC status codes and error messages
		if errors.Is(err, domainErrors.ErrExpiredToken) { // Assuming TokenManagementService wraps jwt.ErrTokenExpired
			resp.ErrorCode = "token_expired"
			resp.ErrorMessage = "Token has expired"
			// Typically, for ValidateToken, even if token is expired/invalid, we might return OK with valid:false
			// rather than a gRPC error code like Unauthenticated. The caller checks the 'valid' field.
		} else if errors.Is(err, domainErrors.ErrInvalidToken) { // Catch-all for other validation issues
			resp.ErrorCode = "token_invalid_signature_or_format"
			resp.ErrorMessage = "Token signature or format is invalid"
		} else { // Other errors (e.g. internal from ValidateAccessToken)
			resp.ErrorCode = "validation_internal_error"
			resp.ErrorMessage = "Internal error during token validation"
			// For internal errors, we might choose to return a gRPC error instead of OK valid:false
			// return nil, status.Errorf(codes.Internal, "Internal error validating token: %v", err)
		}
		return resp, nil // Return OK with valid:false and error details
	}

	// Token is valid
	return &authv1.ValidateTokenResponse{
		Valid:       true,
		UserId:      claims.UserID,
		Username:    claims.Username,
		Roles:       claims.Roles,
		Permissions: claims.Permissions,
		ExpiresAt:   timestamppb.New(claims.ExpiresAt.Time),
		SessionId:   claims.SessionID,
	}, nil
}

// CheckPermission implements AuthServiceServer_Workaround.
func (s *AuthV1Service) CheckPermission(ctx context.Context, req *authv1.CheckPermissionRequest) (*authv1.CheckPermissionResponse, error) {
	if req.GetUserId() == "" || req.GetPermission() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "user_id and permission are required")
	}
	userID, err := uuid.Parse(req.GetUserId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user_id format: %v", err)
	}

	// Use AuthService.CheckUserPermission (which is currently a placeholder)
	hasPerm, err := s.authService.CheckUserPermission(ctx, userID, req.GetPermission(), &req.ResourceId)
	if err != nil {
		s.logger.Error("CheckPermission: error from authService.CheckUserPermission", zap.Error(err))
		// Map domain errors if any specific ones are expected
		return nil, status.Errorf(codes.Internal, "failed to check permission: %v", err)
	}

	return &authv1.CheckPermissionResponse{HasPermission: hasPerm}, nil
}

// GetUserInfo implements AuthServiceServer_Workaround.
func (s *AuthV1Service) GetUserInfo(ctx context.Context, req *authv1.GetUserInfoRequest) (*authv1.UserInfoResponse, error) {
	if req.GetUserId() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "user_id is required")
	}
	userID, err := uuid.Parse(req.GetUserId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user_id format: %v", err)
	}

	// Assuming UserService.GetUserByID returns the necessary *models.User details
	// This service method might need enhancement if it doesn't include all required fields like roles, mfa status.
	user, err := s.userService.GetUserByID(ctx, userID) // This is a placeholder method in current UserService
	if err != nil {
		if errors.Is(err, domainErrors.ErrUserNotFound) {
			return nil, status.Errorf(codes.NotFound, "user not found")
		}
		s.logger.Error("GetUserInfo: error from userService.GetUserByID", zap.Error(err))
		return nil, status.Errorf(codes.Internal, "failed to get user info: %v", err)
	}

	// Check MFA status (example, assuming mfaSecretRepo is available or this logic is in UserService)
	// This is a simplified check. A dedicated method in MFALogicService or UserService would be better.
	mfaEnabled := false
	// mfaSecret, mfaErr := s.mfaSecretRepo.FindByUserIDAndType(ctx, userID, models.MFATypeTOTP)
	// if mfaErr == nil && mfaSecret != nil && mfaSecret.Verified {
	// 	mfaEnabled = true
	// } else if mfaErr != nil && !errors.Is(mfaErr, domainErrors.ErrNotFound) {
	// 	s.logger.Error("GetUserInfo: error checking MFA status", zap.Error(mfaErr))
	// 	// Decide if this should be a partial error or halt
	// }
	// For now, this part is complex as AuthService has mfaSecretRepo, not UserService directly.
	// This should be encapsulated in UserService.GetUserFullDetails or similar.

	// Get roles (user.Roles might already be populated by UserService.GetUserByID if it's comprehensive)
	// If not, we'd need to call RoleService or UserRolesRepository.
	// For now, assume user.Roles on models.User is populated with role names (strings).
	var userRoles []string
	if user.Roles != nil { // Assuming user.Roles is []models.Role
		for _, r := range user.Roles {
			userRoles = append(userRoles, r.Name)
		}
	}


	userInfo := &authv1.UserInfo{
		Id:        user.ID.String(),
		Username:  user.Username,
		Email:     user.Email,
		Status:    string(user.Status),
		CreatedAt: timestamppb.New(user.CreatedAt),
		Roles:     userRoles,
		MfaEnabled: mfaEnabled, // Placeholder
	}
	if user.EmailVerifiedAt != nil {
		userInfo.EmailVerifiedAt = timestamppb.New(*user.EmailVerifiedAt)
	}
	if user.LastLoginAt != nil {
		userInfo.LastLoginAt = timestamppb.New(*user.LastLoginAt)
	}

	return &authv1.UserInfoResponse{User: userInfo}, nil
}

// GetJWKS implements AuthServiceServer_Workaround.
func (s *AuthV1Service) GetJWKS(ctx context.Context, req *authv1.GetJWKSRequest) (*authv1.GetJWKSResponse, error) {
	jwksMap, err := s.tokenManagementService.GetJWKS()
	if err != nil {
		s.logger.Error("GetJWKS: failed to get JWKS from token manager", zap.Error(err))
		return nil, status.Errorf(codes.Internal, "failed to retrieve JWKS: %v", err)
	}

	keysInterface, ok := jwksMap["keys"]
	if !ok {
		return nil, status.Errorf(codes.Internal, "JWKS map does not contain 'keys' field")
	}

	jwkMaps, ok := keysInterface.([]map[string]interface{})
	if !ok {
		return nil, status.Errorf(codes.Internal, "'keys' field in JWKS is not a list of key maps")
	}

	responseKeys := make([]*authv1.GetJWKSResponse_JSONWebKey, 0, len(jwkMaps))
	for _, keyMap := range jwkMaps {
		jwk := &authv1.GetJWKSResponse_JSONWebKey{}
		if kty, ok := keyMap["kty"].(string); ok { jwk.Kty = kty }
		if kid, ok := keyMap["kid"].(string); ok { jwk.Kid = kid }
		if use, ok := keyMap["use"].(string); ok { jwk.Use = use }
		if alg, ok := keyMap["alg"].(string); ok { jwk.Alg = alg }
		if n, ok := keyMap["n"].(string); ok { jwk.N = n }
		if e, ok := keyMap["e"].(string); ok { jwk.E = e }
		responseKeys = append(responseKeys, jwk)
	}

	return &authv1.GetJWKSResponse{Keys: responseKeys}, nil
}

// HealthCheck implements AuthServiceServer_Workaround.
// This reuses the existing HealthCheck logic if it's compatible or reimplements.
// The previous HealthCheck handler was in health_handler.go.
// For now, a simple implementation.
func (s *AuthV1Service) HealthCheck(ctx context.Context, req *emptypb.Empty) (*authv1.HealthCheckResponse, error) {
	// TODO: Add actual health checks (e.g., DB connectivity)
	return &authv1.HealthCheckResponse{Status: authv1.HealthCheckResponse_SERVING}, nil
}
