package grpc

import (
	"context"

	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	// Import the generated Go code for the auth/v1 proto
	// The module path used during protoc generation was "github.com/gameplatform/auth-service"
	// and the go_package option was "github.com/gameplatform/auth-service/gen/go/auth/v1;authv1"
	authv1 "github.com/gameplatform/auth-service/gen/go/auth/v1" 
)

// AuthV1Service is the gRPC service for auth.v1 operations like HealthCheck and CheckPermission.
// It implements the AuthServiceServer interface generated from api/proto/v1/auth.proto.
type AuthV1Service struct {
	authv1.UnimplementedAuthServiceServer // Recommended for forward compatibility
	logger                                *zap.Logger
	authLogic                             service.AuthLogicService // For ValidateToken (which uses TokenService)
	userService                           service.UserService      // For GetUserInfo
	tokenService                          service.TokenService     // For GetJWKS directly and ValidateToken via AuthLogic
	rbacService                           service.RBACService      // For CheckPermission
}

// NewAuthV1Service creates a new AuthV1Service.
func NewAuthV1Service(
	logger *zap.Logger,
	authLogic service.AuthLogicService,
	userService service.UserService,
	tokenService service.TokenService,
	rbacService service.RBACService,
) *AuthV1Service {
	return &AuthV1Service{
		logger:       logger.Named("grpc_auth_v1_service"),
		authLogic:    authLogic,
		userService:  userService,
		tokenService: tokenService,
		rbacService:  rbacService,
	}
}

// HealthCheck implements the HealthCheck RPC method.
// It returns the serving status of the service.
func (s *AuthV1Service) HealthCheck(ctx context.Context, req *authv1.GoogleProtobufEmpty) (*authv1.HealthCheckResponse, error) {
	s.logger.Info("gRPC HealthCheck called")
	return &authv1.HealthCheckResponse{
		Status: authv1.HealthCheckResponse_SERVING,
	}, nil
}

// ValidateToken implements the ValidateToken RPC method.
func (s *AuthV1Service) ValidateToken(ctx context.Context, req *authv1.ValidateTokenRequest) (*authv1.ValidateTokenResponse, error) {
	if req == nil || req.Token == "" {
		s.logger.Warn("ValidateToken called with empty token")
		return nil, status.Errorf(codes.InvalidArgument, "token is required")
	}

	s.logger.Debug("gRPC ValidateToken called")
	claims, err := s.authLogic.ValidateAndParseToken(ctx, req.Token) // AuthLogicService wraps TokenService.ValidateAccessToken

	if err != nil {
		s.logger.Info("Token validation failed", zap.String("token", req.Token), zap.Error(err))
		// Map specific errors from service layer to gRPC status/response details
		// This is a simplified mapping.
		var errorCode string
		var errorMsg string
		// Placeholder errors, these should be defined custom errors in domain/entity or common error package
		if strings.Contains(err.Error(), "expired") {
			errorCode = "token_expired"
			errorMsg = "Token has expired."
		} else if strings.Contains(err.Error(), "invalid") { // Catch-all for other validation issues
			errorCode = "token_invalid"
			errorMsg = "Token is invalid."
		} else { // Internal errors
			s.logger.Error("Internal error validating token", zap.Error(err))
			return nil, status.Errorf(codes.Internal, "failed to validate token due to server error")
		}
		
		// For some errors like expired, we might still return some claims if they were parsed.
		// The service.Claims struct from ValidateAndParseToken might contain these.
		// For now, just returning valid=false and error details.
		return &authv1.ValidateTokenResponse{
			Valid:         false,
			ErrorCode:     errorCode,
			ErrorMessage:  errorMsg,
			// UserId, Username etc could be populated if claims were partially parsed before error.
		}, nil // Return OK status with error details in response, or codes.Unauthenticated
	}

	// Token is valid
	return &authv1.ValidateTokenResponse{
		Valid:         true,
		UserId:        claims.UserID,
		Username:      claims.Username,
		Roles:         claims.Roles,
		Permissions:   claims.Permissions,
		SessionId:     claims.SessionID,
		ExpiresAt:     timestamppb.New(claims.ExpiresAt.Time),
		// ErrorCode and ErrorMessage are empty for valid tokens
	}, nil
}

// GetUserInfo implements the GetUserInfo RPC method.
func (s *AuthV1Service) GetUserInfo(ctx context.Context, req *authv1.GetUserInfoRequest) (*authv1.UserInfoResponse, error) {
	if req == nil || req.UserId == "" {
		s.logger.Warn("GetUserInfo called with empty user_id")
		return nil, status.Errorf(codes.InvalidArgument, "user_id is required")
	}

	s.logger.Debug("gRPC GetUserInfo called", zap.String("user_id", req.UserId))

	user, mfaEnabled, err := s.userService.GetUserFullInfo(ctx, req.UserId)
	if err != nil {
		// Assuming userService.GetUserFullInfo returns a well-defined error like entity.ErrUserNotFound
		if strings.Contains(err.Error(), "not found") { // Placeholder for proper error checking
			s.logger.Info("User not found for GetUserInfo", zap.String("user_id", req.UserId), zap.Error(err))
			return nil, status.Errorf(codes.NotFound, "user not found")
		}
		s.logger.Error("Failed to get user info from UserService", zap.Error(err), zap.String("user_id", req.UserId))
		return nil, status.Errorf(codes.Internal, "failed to get user information")
	}

	var roles []string
	userRoles, errRoles := s.rbacService.GetUserRoles(ctx, user.ID)
	if errRoles != nil {
		s.logger.Warn("Failed to get roles for user in GetUserInfo", zap.String("user_id", user.ID), zap.Error(errRoles))
		// Proceed with empty roles, or return error based on policy
	} else {
		for _, r := range userRoles {
			roles = append(roles, r.ID) // Or r.Name
		}
	}
	
	// Convert entity.User and other info to authv1.UserInfo
	userInfo := &authv1.UserInfo{
		Id:        user.ID,
		Username:  user.Username,
		Email:     user.Email,
		Status:    user.Status,
		CreatedAt: timestamppb.New(user.CreatedAt),
		MfaEnabled: mfaEnabled,
		Roles:     roles,
	}
	if user.EmailVerifiedAt != nil {
		userInfo.EmailVerifiedAt = timestamppb.New(*user.EmailVerifiedAt)
	}
	if user.LastLoginAt != nil {
		userInfo.LastLoginAt = timestamppb.New(*user.LastLoginAt)
	}

	return &authv1.UserInfoResponse{User: userInfo}, nil
}

// GetJWKS implements the GetJWKS RPC method.
func (s *AuthV1Service) GetJWKS(ctx context.Context, req *authv1.GetJWKSRequest) (*authv1.GetJWKSResponse, error) {
	s.logger.Info("gRPC GetJWKS called")
	
	jwksMap, err := s.tokenService.GetJWKS()
	if err != nil {
		s.logger.Error("Failed to get JWKS from TokenService", zap.Error(err))
		return nil, status.Errorf(codes.Internal, "failed to retrieve JWKS")
	}

	// Convert map[string]interface{} to []*authv1.JSONWebKey
	// This is a bit manual; a more robust solution might involve marshalling/unmarshalling
	// through JSON if the structures are complex or using struct tags for direct conversion.
	var keys []*authv1.JSONWebKey
	if keyList, ok := jwksMap["keys"].([]map[string]interface{}); ok {
		for _, kMap := range keyList {
			jwk := &authv1.JSONWebKey{}
			if kty, ok := kMap["kty"].(string); ok { jwk.Kty = kty }
			if kid, ok := kMap["kid"].(string); ok { jwk.Kid = kid }
			if use, ok := kMap["use"].(string); ok { jwk.Use = use }
			if alg, ok := kMap["alg"].(string); ok { jwk.Alg = alg }
			if n, ok := kMap["n"].(string); ok { jwk.N = n }
			if e, ok := kMap["e"].(string); ok { jwk.E = e }
			keys = append(keys, jwk)
		}
	} else {
		s.logger.Error("JWKS map from TokenService has unexpected structure", zap.Any("jwks_map", jwksMap))
		return nil, status.Errorf(codes.Internal, "failed to process JWKS structure")
	}
	
	return &authv1.GetJWKSResponse{Keys: keys}, nil
}


// CheckPermission implements the CheckPermission RPC method.
// It uses RBACService to determine if the user has the specified permission.
func (s *AuthV1Service) CheckPermission(ctx context.Context, req *authv1.CheckPermissionRequest) (*authv1.CheckPermissionResponse, error) {
	if req == nil || req.UserId == "" || req.PermissionId == "" {
		s.logger.Warn("CheckPermission called with invalid arguments", zap.Any("request", req))
		return nil, status.Errorf(codes.InvalidArgument, "user_id and permission_id are required")
	}

	s.logger.Debug("gRPC CheckPermission called", zap.String("user_id", req.UserId), zap.String("permission_id", req.PermissionId))

	hasPerm, err := s.rbacService.CheckUserPermission(ctx, req.UserId, req.PermissionId)
	if err != nil {
		// Log the internal error from rbacService
		s.logger.Error("RBACService.CheckUserPermission failed", zap.Error(err), zap.String("user_id", req.UserId), zap.String("permission_id", req.PermissionId))
		// Return a generic error to the client
		return nil, status.Errorf(codes.Internal, "failed to check permission")
	}

	return &authv1.CheckPermissionResponse{
		HasPermission: hasPerm,
	}, nil
}


// Ensure AuthV1Service implements the interface.
var _ authv1.AuthServiceServer = (*AuthV1Service)(nil)

// Need to import "github.com/gameplatform/auth-service/internal/domain/service"
// and "google.golang.org/grpc/status"
// and "google.golang.org/grpc/codes"

// GetAuthServiceDesc returns the gRPC service description for AuthService.
// This might be useful if the main application needs to register services dynamically
// or if there are multiple services to register.
// However, direct registration using authv1.RegisterAuthServiceServer is more common.
// func GetAuthServiceDesc() grpc.ServiceDesc {
// 	return authv1.AuthService_ServiceDesc
// }
// This function is commented out as it's not strictly necessary for basic setup.
// The primary deliverable is the HealthService struct and its HealthCheck method.