// File: internal/handler/grpc/auth_server.go

package grpc

import (
	"context"

	"github.com/google/uuid"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/service"
	pb "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/pkg/api/proto"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// AuthServer представляет gRPC-сервер аутентификации
type AuthServer struct {
	pb.UnimplementedAuthServiceServer
	authService  *service.AuthService
	tokenService *service.TokenService
	logger       *zap.Logger
}

// NewAuthServer создает новый экземпляр AuthServer
func NewAuthServer(authService *service.AuthService, tokenService *service.TokenService, logger *zap.Logger) *AuthServer {
	return &AuthServer{
		authService:  authService,
		tokenService: tokenService,
		logger:       logger,
	}
}

// Login аутентифицирует пользователя
func (s *AuthServer) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	// Проверка входных данных
	if req.Email == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}
	if req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "password is required")
	}

	// Аутентификация пользователя
	loginReq := models.LoginRequest{
		Email:    req.Email,
		Password: req.Password,
	}

	tokenPair, user, err := s.authService.Login(ctx, loginReq)
	if err != nil {
		s.logger.Error("Failed to login", zap.Error(err))
		return nil, status.Error(codes.Unauthenticated, "invalid credentials")
	}

	// Проверка, требуется ли двухфакторная аутентификация
	if user.TwoFactorEnabled {
		return &pb.LoginResponse{
			Requires2fa: true,
			UserId:      user.ID.String(),
		}, nil
	}

	// Формирование ответа
	return &pb.LoginResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresIn:    int32(tokenPair.ExpiresIn),
		TokenType:    tokenPair.TokenType,
		UserId:       user.ID.String(),
	}, nil
}

// RefreshToken обновляет токены
func (s *AuthServer) RefreshToken(ctx context.Context, req *pb.RefreshTokenRequest) (*pb.RefreshTokenResponse, error) {
	// Проверка входных данных
	if req.RefreshToken == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh_token is required")
	}

	// Обновление токенов
	tokenPair, err := s.authService.RefreshToken(ctx, req.RefreshToken)
	if err != nil {
		s.logger.Error("Failed to refresh token", zap.Error(err))
		return nil, status.Error(codes.Unauthenticated, "invalid refresh token")
	}

	// Формирование ответа
	return &pb.RefreshTokenResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresIn:    int32(tokenPair.ExpiresIn),
		TokenType:    tokenPair.TokenType,
	}, nil
}

// Logout выполняет выход из системы
func (s *AuthServer) Logout(ctx context.Context, req *pb.LogoutRequest) (*pb.LogoutResponse, error) {
	// Проверка входных данных
	if req.RefreshToken == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh_token is required")
	}

	// Выход из системы
	err := s.authService.Logout(ctx, req.AccessToken, req.RefreshToken)
	if err != nil {
		s.logger.Error("Failed to logout", zap.Error(err))
		return nil, status.Error(codes.Internal, "failed to logout")
	}

	// Формирование ответа
	return &pb.LogoutResponse{
		Success: true,
	}, nil
}

// ValidateToken проверяет валидность токена
func (s *AuthServer) ValidateToken(ctx context.Context, req *pb.ValidateTokenRequest) (*pb.ValidateTokenResponse, error) {
	// Проверка входных данных
	if req.Token == "" {
		return nil, status.Error(codes.InvalidArgument, "token is required")
	}

	// Валидация токена
	result, err := s.tokenService.ValidateToken(ctx, req.Token)
	if err != nil {
		s.logger.Error("Failed to validate token", zap.Error(err))
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}

	// Формирование ответа
	return &pb.ValidateTokenResponse{
		Valid:  result.Valid,
		UserId: result.UserID.String(),
		Roles:  result.Roles,
	}, nil
}

// CheckPermission проверяет наличие разрешения у пользователя
func (s *AuthServer) CheckPermission(ctx context.Context, req *pb.CheckPermissionRequest) (*pb.CheckPermissionResponse, error) {
	// Проверка входных данных
	if req.UserId == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}
	if req.Permission == "" {
		return nil, status.Error(codes.InvalidArgument, "permission is required")
	}

	// Преобразование ID пользователя
	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid user_id")
	}

	// Проверка разрешения
	hasPermission, err := s.tokenService.CheckPermission(ctx, userID, req.Permission)
	if err != nil {
		s.logger.Error("Failed to check permission", zap.Error(err))
		return nil, status.Error(codes.Internal, "failed to check permission")
	}

	// Формирование ответа
	return &pb.CheckPermissionResponse{
		HasPermission: hasPermission,
	}, nil
}

// Register регистрирует нового пользователя
func (s *AuthServer) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	// Проверка входных данных
	if req.Email == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}
	if req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "password is required")
	}
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}

	// Регистрация пользователя
	createReq := models.CreateUserRequest{
		Email:    req.Email,
		Password: req.Password,
		Username: req.Username,
	}

	user, err := s.authService.Register(ctx, createReq)
	if err != nil {
		s.logger.Error("Failed to register user", zap.Error(err))
		
		// Обработка специфических ошибок
		if err == models.ErrEmailExists {
			return nil, status.Error(codes.AlreadyExists, "email already exists")
		}
		if err == models.ErrUsernameExists {
			return nil, status.Error(codes.AlreadyExists, "username already exists")
		}
		
		return nil, status.Error(codes.Internal, "failed to register user")
	}

	// Формирование ответа
	return &pb.RegisterResponse{
		UserId:   user.ID.String(),
		Email:    user.Email,
		Username: user.Username,
	}, nil
}
