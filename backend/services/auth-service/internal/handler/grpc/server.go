// File: internal/handler/grpc/server.go

package grpc

import (
	"context"
	"fmt"
	"net"

	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/config"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/handler/grpc/interceptors"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/service"
	pb "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/gen/auth/v1"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

// Server представляет gRPC-сервер
type Server struct {
	server        *grpc.Server
	authService   *service.AuthService
	userService   *service.UserService
	roleService   *service.RoleService
	tokenService  *service.TokenService
	healthService *health.Server
	logger        *zap.Logger
	config        *config.GRPCConfig
}

// NewServer создает новый экземпляр gRPC-сервера
func NewServer(
	authService *service.AuthService,
	userService *service.UserService,
	roleService *service.RoleService,
	tokenService *service.TokenService,
	logger *zap.Logger,
	config *config.GRPCConfig,
) *Server {
	// Создание перехватчиков
	authInterceptor := interceptors.NewAuthInterceptor(tokenService, logger)
	loggingInterceptor := interceptors.NewLoggingInterceptor(logger)
	metricsInterceptor := interceptors.NewMetricsInterceptor(logger)
	recoveryInterceptor := interceptors.NewRecoveryInterceptor(logger)
	tracingInterceptor := interceptors.NewTracingInterceptor(logger)

	// Создание gRPC-сервера с перехватчиками
	server := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			recoveryInterceptor.Unary(),
			loggingInterceptor.Unary(),
			metricsInterceptor.Unary(),
			tracingInterceptor.Unary(),
			authInterceptor.Unary(),
		),
		grpc.ChainStreamInterceptor(
			recoveryInterceptor.Stream(),
			loggingInterceptor.Stream(),
			metricsInterceptor.Stream(),
			tracingInterceptor.Stream(),
			authInterceptor.Stream(),
		),
	)

	// Создание сервиса проверки работоспособности
	healthService := health.NewServer()
	healthService.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)

	return &Server{
		server:        server,
		authService:   authService,
		userService:   userService,
		roleService:   roleService,
		tokenService:  tokenService,
		healthService: healthService,
		logger:        logger,
		config:        config,
	}
}

// Start запускает gRPC-сервер
func (s *Server) Start(ctx context.Context) error {
	// Регистрация сервисов
	s.registerServices()

	// Создание слушателя
	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	// Логирование запуска сервера
	s.logger.Info("Starting gRPC server", zap.String("address", addr))

	// Запуск сервера
	go func() {
		if err := s.server.Serve(listener); err != nil {
			s.logger.Error("Failed to serve gRPC", zap.Error(err))
		}
	}()

	// Ожидание завершения контекста
	<-ctx.Done()

	// Остановка сервера
	s.Stop()

	return nil
}

// Stop останавливает gRPC-сервер
func (s *Server) Stop() {
	s.logger.Info("Stopping gRPC server")
	s.server.GracefulStop()
}

// registerServices регистрирует gRPC-сервисы
func (s *Server) registerServices() {
	// Регистрация сервиса аутентификации
	authServer := NewAuthServer(s.authService, s.tokenService, s.logger)
	pb.RegisterAuthServiceServer(s.server, authServer)

	// Регистрация сервиса пользователей
	userServer := NewUserServer(s.userService, s.logger)
	pb.RegisterUserServiceServer(s.server, userServer)

	// Регистрация сервиса проверки работоспособности
	healthpb.RegisterHealthServer(s.server, s.healthService)

	// Включение рефлексии для инструментов отладки
	reflection.Register(s.server)
}
