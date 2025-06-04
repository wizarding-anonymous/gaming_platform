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
	// TODO: Initialize other repositories (Role, Permission, APIKey, AuditLog etc.) here as needed.

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
	// Note: The encryption key itself (cfg.MFA.TOTPSecretEncryptionKey) will be passed to methods
	// of encryptionService when they are called, not necessarily at instantiation unless
	// the service is designed to be instantiated with a specific key. Current design has key per call.

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
		verificationCodeRepo, // Inject new dependency
		tokenService,         // Refactored TokenService
		sessionService,
		kafkaProducer,
		cfg,
		logger,
		passwordService,
		// tokenManagementService, // AuthService might use TokenService which uses TokenManagementService
	)
	// TODO: userService and roleService might need to be updated if they depended on the old pgRepo structure directly.
	// For now, assuming they can be adapted or their pgRepo dependency was for specific sub-repos.
	// This might require creating specific RoleRepository etc. and passing them.
	// For the scope of this subtask, focusing on TokenService and SessionService DI.
	// The pgRepo was a generic repo, now we have specific ones.
	// userService := service.NewUserService(pgRepo, kafkaProducer, logger)
	// roleService := service.NewRoleService(pgRepo, logger)
	// For now, these will cause errors if pgRepo was expected to implement all interfaces.
	// Placeholder: these services might need individual repositories.
	var userService *service.UserService // Placeholder - needs proper initialization
	var roleService *service.RoleService // Placeholder

	telegramService := service.NewTelegramService(cfg.Telegram, logger)
	// twoFactorService := service.NewTwoFactorService(pgRepo, redisClient, logger) // Placeholder
	var twoFactorService *service.TwoFactorService // Placeholder


	// Инициализация обработчиков событий
	// TODO: Ensure eventHandlers are updated if constructor for authService/userService changes significantly for it
	eventHandlers := kafka.NewEventHandlers(authService, userService, logger)
	go kafkaConsumer.StartConsuming(eventHandlers.HandleEvent)

	// Инициализация HTTP сервера
	router := httpHandler.SetupRouter( // Renamed NewRouter to SetupRouter based on router.go content
		authService,
		userService,
		roleService,
		tokenService,         // Old TokenService
		tokenManagementService, // New TokenManagementService for JWKS
		sessionService,       // sessionService was not in original SetupRouter params, adding it
		telegramService,
		twoFactorService,
		cfg, // cfg was not in original SetupRouter params, but httpHandler.NewRouter took it
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
	authGRPCServer := grpcHandler.NewAuthServer(authService, userService, roleService, tokenService, logger)
	authGRPCServer.RegisterServer(grpcServer)

	// Инициализация и регистрация gRPC Health Check сервера
	healthServer := grpcHandler.NewHealthServer(logger)
	grpc_health_v1.RegisterHealthServer(grpcServer, healthServer)
	logger.Info("gRPC Health Check service registered")

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
