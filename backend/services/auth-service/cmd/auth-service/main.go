package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/your-org/auth-service/internal/config"
	"github.com/your-org/auth-service/internal/events/kafka"
	grpcHandler "github.com/your-org/auth-service/internal/handler/grpc"
	httpHandler "github.com/your-org/auth-service/internal/handler/http"
	infraDbPostgres "github.com/your-org/auth-service/internal/infrastructure/database/postgres" // For NewDBPool
	repoPostgres "github.com/your-org/auth-service/internal/domain/repository/postgres"      // For specific repo constructors
	"github.com/your-org/auth-service/internal/repository/redis"
	domainService "github.com/your-org/auth-service/internal/domain/service" // For PasswordService interface
	"github.com/your-org/auth-service/internal/infrastructure/security"   // For NewArgon2idPasswordService
	"github.com/your-org/auth-service/internal/service"
	"github.com/your-org/auth-service/internal/utils/telemetry"
	"google.golang.org/grpc/health/grpc_health_v1"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func main() {
	// Инициализация конфигурации
	cfg, err := config.LoadConfig()
	if err != nil {
		panic(fmt.Sprintf("Failed to load config: %v", err))
	}

	// Инициализация логгера
	logger, err := telemetry.NewLogger(cfg.Logging.Level, cfg.Logging.Format)
	if err != nil {
		panic(fmt.Sprintf("Failed to initialize logger: %v", err))
	}
	defer logger.Sync()

	// Инициализация трассировки
	if cfg.Telemetry.Tracing.Enabled {
		tp, err := telemetry.InitTracer(cfg.Telemetry.Tracing.Jaeger.AgentHost, cfg.Telemetry.Tracing.Jaeger.AgentPort)
		if err != nil {
			logger.Error("Failed to initialize tracer", zap.Error(err))
		} else {
			defer func() {
				if err := tp.Shutdown(context.Background()); err != nil {
					logger.Error("Error shutting down tracer provider", zap.Error(err))
				}
			}()
		}
	}

	// Применение миграций
	if cfg.Database.AutoMigrate {
		logger.Info("Running database migrations")
		migrationURL := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
			cfg.Database.User, cfg.Database.Password, cfg.Database.Host, cfg.Database.Port, cfg.Database.DBName, cfg.Database.SSLMode)
		m, err := migrate.New("file://migrations", migrationURL)
		if err != nil {
			logger.Fatal("Failed to create migration instance", zap.Error(err))
		}
		if err := m.Up(); err != nil && err != migrate.ErrNoChange {
			logger.Fatal("Failed to apply migrations", zap.Error(err))
		}
		logger.Info("Migrations applied successfully")
	}

	// Инициализация подключения к PostgreSQL
	dbPool, err := infraDbPostgres.NewDBPool(cfg.Database) // Use new package
	if err != nil {
		logger.Fatal("Failed to initialize PostgreSQL connection pool", zap.Error(err))
	}
	defer dbPool.Close()

	// Инициализация репозиториев
	userRepo := repoPostgres.NewUserRepositoryPostgres(dbPool)
	refreshTokenRepo := repoPostgres.NewRefreshTokenRepositoryPostgres(dbPool)
	sessionRepo := repoPostgres.NewSessionRepositoryPostgres(dbPool)
	verificationCodeRepo := repoPostgres.NewVerificationCodeRepositoryPostgres(dbPool)
	mfaSecretRepo := repoPostgres.NewMFASecretRepositoryPostgres(dbPool)
	mfaBackupCodeRepo := repoPostgres.NewMFABackupCodeRepositoryPostgres(dbPool)
	apiKeyRepo := repoPostgres.NewAPIKeyRepositoryPostgres(dbPool)
	auditLogRepo := repoPostgres.NewAuditLogRepositoryPostgres(dbPool) // Added
	// TODO: Initialize RoleRepository, PermissionRepository for RoleService
	// TODO: Initialize UserRolesRepository for UserService/RoleService (admin part)

	// Инициализация подключения к Redis
	redisClient, err := redis.NewRedisClient(cfg.Redis)
	if err != nil {
		logger.Fatal("Failed to initialize Redis client", zap.Error(err))
	}
	defer redisClient.Close()

	// Инициализация Kafka Producer
	kafkaProducer, err := kafka.NewProducer(cfg.Kafka.Brokers, cfg.Kafka.Producer.Topic)
	if err != nil {
		logger.Fatal("Failed to initialize Kafka producer", zap.Error(err))
	}
	defer kafkaProducer.Close()

	// Инициализация Kafka Consumer
	kafkaConsumer, err := kafka.NewConsumer(cfg.Kafka.Brokers, cfg.Kafka.Consumer.Topics, cfg.Kafka.Consumer.GroupID)
	if err != nil {
		logger.Fatal("Failed to initialize Kafka consumer", zap.Error(err))
	}
	defer kafkaConsumer.Close()

	// Инициализация PasswordService
	argon2Params := security.Argon2idParams{
		Memory:      cfg.Security.PasswordHash.Memory,
		Iterations:  cfg.Security.PasswordHash.Iterations,
		Parallelism: cfg.Security.PasswordHash.Parallelism,
		SaltLength:  cfg.Security.PasswordHash.SaltLength,
		KeyLength:   cfg.Security.PasswordHash.KeyLength,
	}
	passwordService, err := security.NewArgon2idPasswordService(argon2Params)
	if err != nil {
		logger.Fatal("Failed to initialize password service", zap.Error(err))
	}

	// Инициализация нового TokenManagementService (RS256)
	tokenManagementService, err := security.NewRSATokenManagementService(cfg.JWT)
	if err != nil {
		logger.Fatal("Failed to initialize RSA Token Management Service", zap.Error(err))
	}

	// Инициализация TOTPService
	totpService := security.NewPquernaTOTPService(cfg.MFA.TOTPIssuerName)

	// Инициализация EncryptionService
	encryptionService := security.NewAESGCMEncryptionService()

	// Инициализация MFALogicService
	mfaLogicService := service.NewMFALogicService(
		&cfg.MFA,
		totpService,
		encryptionService,
		mfaSecretRepo,
		mfaBackupCodeRepo,
		userRepo,
		passwordService,
	)

	// Инициализация APIKeyService
	apiKeyService := service.NewAPIKeyService(apiKeyRepo, passwordService)

	// Инициализация AuditLogService
	auditLogService := service.NewAuditLogService(auditLogRepo, logger) // Added

	// Инициализация сервисов
	// Old TokenService is being refactored. NewTokenService will take new dependencies.
	tokenService := service.NewTokenService(
		redisClient,
		logger,
		tokenManagementService,
		refreshTokenRepo,
		userRepo,
		sessionRepo,
	)

	sessionService := service.NewSessionService(
		sessionRepo,
		userRepo,
		kafkaProducer,
		logger,
		tokenManagementService, // Inject new dependency
	)

	authService := service.NewAuthService(
		userRepo,
		verificationCodeRepo,
		tokenService,
		sessionService,
		kafkaProducer,
		cfg,
		logger,
		passwordService,
		tokenManagementService, // Now directly injecting into AuthService
		mfaSecretRepo,        // Injecting MFASecretRepository
		mfaLogicService,      // Injecting MFALogicService
	)

	// Assuming UserService and RoleService need specific repositories now, not the generic pgRepo
	// This part is still placeholder as full DI for these services is out of scope for current MFA focus
	// For them to work, they'd need their respective repositories created above and passed here.
	// Example: roleRepo := repoPostgres.NewRoleRepositoryPostgres(dbPool)
	// roleService := service.NewRoleService(roleRepo, logger)
	var userService *service.UserService // Placeholder - needs proper initialization with specific repos
	var roleService *service.RoleService // Placeholder - needs proper initialization with specific repos

	telegramService := service.NewTelegramService(cfg.Telegram, logger)
	// twoFactorService from previous setup is now replaced by mfaLogicService via AuthService
	// var twoFactorService *service.TwoFactorService // This would be the old one


	// Инициализация обработчиков событий
	eventHandlers := kafka.NewEventHandlers(authService, userService, logger)
	go kafkaConsumer.StartConsuming(eventHandlers.HandleEvent)

	// Инициализация HTTP сервера
	// SetupRouter now takes mfaLogicService directly for AuthHandler
	// It no longer takes the old tokenService or twoFactorService if AuthHandler is updated
	router := httpHandler.SetupRouter(
		authService,
		userService,          // Placeholder
		roleService,          // Placeholder
		tokenService,         // Old TokenService, still passed as some handlers might use it directly
		sessionService,
		telegramService,
		mfaLogicService,
		apiKeyService,
		auditLogService,      // Pass auditLogService to SetupRouter
		tokenManagementService,
		cfg,
		logger,
	)

	httpServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// Инициализация gRPC сервера
	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			grpcHandler.LoggingInterceptor(logger),
			grpcHandler.MetricsInterceptor(),
			grpcHandler.TracingInterceptor(),
		),
	)

	// TODO: Update NewAuthServer if its dependencies (authService, userService, roleService, tokenService) change structure
	// The old authGRPCServer is replaced by the new AuthV1Service
	// authGRPCServer := grpcHandler.NewAuthServer(authService, userService, roleService, tokenService, logger)
	// authGRPCServer.RegisterServer(grpcServer)

	// Инициализация и регистрация нового AuthV1Service (gRPC)
	authV1GrpcService := grpcHandler.NewAuthV1Service(
		logger,
		tokenManagementService,
		authService, // AuthService provides CheckPermission, GetUserInfo (via UserService)
		userService, // UserService provides GetUserByID for GetUserInfo
		// rbacService, // If a separate RBACService was created and used by CheckPermission
	)
	// Registering with the generated function. This will only expose methods present in the
	// currently (potentially incompletely) generated authv1.AuthServiceServer interface.
	authv1.RegisterAuthServiceServer(grpcServer, authV1GrpcService)
	logger.Info("AuthV1 gRPC service registered")


	// Инициализация и регистрация gRPC Health Check сервера (standard health check)
	// The custom HealthCheck RPC within AuthService is separate from this standard one.
	// However, our new AuthV1Service implements HealthCheck itself.
	// So, we might not need the separate standard healthServer if our AuthService.HealthCheck is sufficient.
	// For now, let's keep the standard one too, unless it conflicts or is redundant.
	// The AuthServiceServer_Workaround includes HealthCheck, so authV1GrpcService has it.
	// The standard grpc_health_v1 is often used for Kubernetes health probes.
	// If our custom HealthCheck serves the same purpose, we can remove the standard one.
	// Let's assume for now our custom one is primary. The generated code might still register only
	// the methods it knows about.
	// The line below registers the standard health service. If our proto defines HealthCheck,
	// and it's correctly generated, our authV1GrpcService.HealthCheck will be called.
	// If protoc is an issue, then only the standard one might work fully.

	standardHealthServer := grpc_health.NewServer() // Using standard health server
	grpc_health_v1.RegisterHealthServer(grpcServer, standardHealthServer)
	standardHealthServer.SetServingStatus("auth.v1.AuthService", grpc_health_v1.HealthCheckResponse_SERVING) // Mark main service as serving
	logger.Info("Standard gRPC Health Check service registered")


	// Включение reflection для gRPC (полезно для отладки)
	if cfg.GRPC.EnableReflection {
		reflection.Register(grpcServer)
	}

	// Запуск HTTP сервера в отдельной горутине
	go func() {
		logger.Info("Starting HTTP server", zap.Int("port", cfg.Server.Port))
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Failed to start HTTP server", zap.Error(err))
		}
	}()

	// Запуск gRPC сервера в отдельной горутине
	go func() {
		lis, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.GRPC.Port))
		if err != nil {
			logger.Fatal("Failed to listen for gRPC", zap.Error(err))
		}
		logger.Info("Starting gRPC server", zap.Int("port", cfg.GRPC.Port))
		if err := grpcServer.Serve(lis); err != nil {
			logger.Fatal("Failed to start gRPC server", zap.Error(err))
		}
	}()

	// Запуск сервера метрик Prometheus в отдельной горутине
	if cfg.Telemetry.Metrics.Enabled {
		go func() {
			metricsServer := telemetry.NewMetricsServer(cfg.Telemetry.Metrics.Port)
			logger.Info("Starting metrics server", zap.Int("port", cfg.Telemetry.Metrics.Port))
			if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Error("Metrics server failed", zap.Error(err))
			}
		}()
	}

	// Ожидание сигнала для graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logger.Info("Shutting down servers...")

	// Создание контекста с таймаутом для graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancel()

	// Graceful shutdown HTTP сервера
	if err := httpServer.Shutdown(ctx); err != nil {
		logger.Error("HTTP server forced to shutdown", zap.Error(err))
	}

	// Graceful shutdown gRPC сервера
	grpcServer.GracefulStop()

	logger.Info("Servers exited properly")
}
