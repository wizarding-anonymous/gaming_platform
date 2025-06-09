// File: internal/handler/grpc/user_server.go

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

// UserServer представляет gRPC-сервер для работы с пользователями
type UserServer struct {
	pb.UnimplementedUserServiceServer
	userService *service.UserService
	logger      *zap.Logger
}

// NewUserServer создает новый экземпляр UserServer
func NewUserServer(userService *service.UserService, logger *zap.Logger) *UserServer {
	return &UserServer{
		userService: userService,
		logger:      logger,
	}
}

// GetUser получает информацию о пользователе по ID
func (s *UserServer) GetUser(ctx context.Context, req *pb.GetUserRequest) (*pb.UserResponse, error) {
	// Проверка входных данных
	if req.UserId == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}

	// Преобразование ID пользователя
	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid user_id")
	}

	// Получение пользователя
	user, err := s.userService.GetUserByID(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to get user", zap.Error(err))
		
		if err == models.ErrUserNotFound {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		
		return nil, status.Error(codes.Internal, "failed to get user")
	}

	// Формирование ответа
	return &pb.UserResponse{
		Id:        user.ID.String(),
		Email:     user.Email,
		Username:  user.Username,
		CreatedAt: user.CreatedAt.Unix(),
		UpdatedAt: user.UpdatedAt.Unix(),
	}, nil
}

// UpdateUser обновляет информацию о пользователе
func (s *UserServer) UpdateUser(ctx context.Context, req *pb.UpdateUserRequest) (*pb.UserResponse, error) {
	// Проверка входных данных
	if req.UserId == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}

	// Преобразование ID пользователя
	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid user_id")
	}

	// Подготовка запроса на обновление
	updateReq := models.UpdateUserRequest{}
	
	if req.Username != "" {
		updateReq.Username = &req.Username
	}
	
	if req.Email != "" {
		updateReq.Email = &req.Email
	}

	// Обновление пользователя
	user, err := s.userService.UpdateUser(ctx, userID, updateReq)
	if err != nil {
		s.logger.Error("Failed to update user", zap.Error(err))
		
		if err == models.ErrUserNotFound {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		if err == models.ErrEmailExists {
			return nil, status.Error(codes.AlreadyExists, "email already exists")
		}
		if err == models.ErrUsernameExists {
			return nil, status.Error(codes.AlreadyExists, "username already exists")
		}
		
		return nil, status.Error(codes.Internal, "failed to update user")
	}

	// Формирование ответа
	return &pb.UserResponse{
		Id:        user.ID.String(),
		Email:     user.Email,
		Username:  user.Username,
		CreatedAt: user.CreatedAt.Unix(),
		UpdatedAt: user.UpdatedAt.Unix(),
	}, nil
}

// DeleteUser удаляет пользователя
func (s *UserServer) DeleteUser(ctx context.Context, req *pb.DeleteUserRequest) (*pb.DeleteUserResponse, error) {
	// Проверка входных данных
	if req.UserId == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}

	// Преобразование ID пользователя
	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid user_id")
	}

	// Удаление пользователя
	err = s.userService.DeleteUser(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to delete user", zap.Error(err))
		
		if err == models.ErrUserNotFound {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		
		return nil, status.Error(codes.Internal, "failed to delete user")
	}

	// Формирование ответа
	return &pb.DeleteUserResponse{
		Success: true,
	}, nil
}

// GetUserByEmail получает информацию о пользователе по email
func (s *UserServer) GetUserByEmail(ctx context.Context, req *pb.GetUserByEmailRequest) (*pb.UserResponse, error) {
	// Проверка входных данных
	if req.Email == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}

	// Получение пользователя
	user, err := s.userService.GetUserByEmail(ctx, req.Email)
	if err != nil {
		s.logger.Error("Failed to get user by email", zap.Error(err))
		
		if err == models.ErrUserNotFound {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		
		return nil, status.Error(codes.Internal, "failed to get user")
	}

	// Формирование ответа
	return &pb.UserResponse{
		Id:        user.ID.String(),
		Email:     user.Email,
		Username:  user.Username,
		CreatedAt: user.CreatedAt.Unix(),
		UpdatedAt: user.UpdatedAt.Unix(),
	}, nil
}

// GetUserByUsername получает информацию о пользователе по имени пользователя
func (s *UserServer) GetUserByUsername(ctx context.Context, req *pb.GetUserByUsernameRequest) (*pb.UserResponse, error) {
	// Проверка входных данных
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}

	// Получение пользователя
	user, err := s.userService.GetUserByUsername(ctx, req.Username)
	if err != nil {
		s.logger.Error("Failed to get user by username", zap.Error(err))
		
		if err == models.ErrUserNotFound {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		
		return nil, status.Error(codes.Internal, "failed to get user")
	}

	// Формирование ответа
	return &pb.UserResponse{
		Id:        user.ID.String(),
		Email:     user.Email,
		Username:  user.Username,
		CreatedAt: user.CreatedAt.Unix(),
		UpdatedAt: user.UpdatedAt.Unix(),
	}, nil
}
