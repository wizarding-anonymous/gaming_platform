// File: backend/services/auth-service/cmd/auth-service/main.go
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

	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/config"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/events/handlers" // For event handlers
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/events/kafka"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models" // For EventType constants and CloudEventSource
	grpcHandler "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/handler/grpc"
	httpHandler "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/handler/http"
	infraDbPostgres "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/infrastructure/database/postgres" // For NewDBPool
	repoPostgres "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/repository/postgres"      // For specific repo constructors
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/repository/redis"
	domainService "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/service" // For PasswordService interface
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/infrastructure/security"   // For NewArgon2idPasswordService
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/service"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/utils/telemetry"
	"google.golang.org/grpc/health/grpc_health_v1"
	authv1 "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/gen/auth/v1" // For gRPC server registration

	"github.com/Shopify/sarama" // Added for Sarama config
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	// Import healthcheck interfaces (assuming checkers.go is in internal/utils/healthcheck)
	// healthcheckUtils "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/utils/healthcheck"
	// No, the interfaces are used by the grpc service, not directly by main. Main provides concrete types.
	kafkaEvents "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/events/kafka" // Path to your kafka producer/consumer wrappers
	infraCaptcha "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/infrastructure/captcha" // Added for StubCaptchaService
)

// KafkaProducerHealthChecker adapts kafka.Producer for health checks.
type KafkaProducerHealthChecker struct {
	Producer *kafkaEvents.Producer // Your wrapper around sarama.SyncProducer
}

func (kphc *KafkaProducerHealthChecker) Healthy(ctx context.Context) error {
	if kphc.Producer == nil {
		return fmt.Errorf("Kafka producer client is nil")
	}
	// TODO: A more thorough check might try to get metadata or ensure topic exists.
	// For now, simply checking if the Producer object itself (wrapper) is not nil is a basic check.
	// If the Producer wrapper has internal status or a way to check underlying client, that would be better.
	return nil // Basic check: producer object exists
}

// KafkaConsumerHealthChecker adapts kafka.ConsumerGroup for health checks.
type KafkaConsumerHealthChecker struct {
	ConsumerGroup *kafkaEvents.ConsumerGroup // Your wrapper around sarama.ConsumerGroup
}

func (kchc *KafkaConsumerHealthChecker) Healthy(ctx context.Context) error {
	if kchc.ConsumerGroup == nil {
		return fmt.Errorf("Kafka consumer group client is nil")
	}
	// TODO: Actual health of a consumer group is complex.
	// A simple check is that the object exists.
	// If ConsumerGroup wrapper has an IsHealthy() or similar, use it.
	return nil // Basic check: consumer group object exists
}

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
	auditLogRepo := repoPostgres.NewAuditLogRepositoryPostgres(dbPool)
	userRolesRepo := repoPostgres.NewUserRolesRepositoryPostgres(dbPool) // Added
	roleRepo := repoPostgres.NewRoleRepositoryPostgres(dbPool) // Added (needed for RoleService)
	// TODO: Initialize PermissionRepository for RoleService if RoleService needs it directly for more complex ops

	// Инициализация подключения к Redis
	redisClient, err := redis.NewRedisClient(cfg.Redis)
	if err != nil {
		logger.Fatal("Failed to initialize Redis client", zap.Error(err))
	}
	defer redisClient.Close()

	// Инициализация RateLimiter
	rateLimiter := redis.NewRedisRateLimiter(redisClient, cfg.RateLimit, logger)
	logger.Info("Redis Rate Limiter initialized")

	// Инициализация Kafka Producer
	// Note: NewProducer signature changed: NewProducer(brokers []string, logger logger.Logger, cloudEventSource string)
	// Assuming the logger (*zap.Logger) from telemetry.NewLogger satisfies the logger.Logger interface expected by NewProducer.
	// The CloudEventSource constant is from internal/events/models/cloudevent.go
	kafkaProducer, err := kafka.NewProducer(cfg.Kafka.Brokers, logger, "urn:service:auth")
	if err != nil {
		logger.Fatal("Failed to initialize Kafka producer", zap.Error(err))
	}
	defer kafkaProducer.Close()

	// Инициализация Kafka Consumer (Sarama-based ConsumerGroup)
	saramaCfg := sarama.NewConfig()
	saramaCfg.Version = sarama.V2_8_0_0 // Example: Use your Kafka version
	saramaCfg.Consumer.Group.Rebalance.Strategy = sarama.BalanceStrategyRange
	saramaCfg.Consumer.Offsets.Initial = sarama.OffsetOldest // Or from config
	saramaCfg.Consumer.Return.Errors = true                  // Important for logging consumer errors

	consumerGroupCfg := kafka.NewConsumerGroupConfig{
		Brokers:       cfg.Kafka.Brokers,
		Topics:        cfg.Kafka.Consumer.Topics,
		GroupID:       cfg.Kafka.Consumer.GroupID,
		SaramaConfig:  saramaCfg,
		Logger:        logger, // Pass the main application logger
		InitialOffset: sarama.OffsetOldest, // Or from cfg.Kafka.Consumer.InitialOffset if defined
	}
	kafkaConsumer, err := kafka.NewConsumerGroup(consumerGroupCfg)
	if err != nil {
		logger.Fatal("Failed to initialize Kafka consumer group", zap.Error(err))
	}
	defer kafkaConsumer.Close() // This will call the new ConsumerGroup.Close()

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

	// Инициализация HIBPClient (using existing 'security' alias for infrastructure/security)
	hibpClient := security.NewHIBPClient(cfg.HIBP, logger)

	// Инициализация StubCaptchaService
	stubCaptchaService := infraCaptcha.NewStubCaptchaService(cfg.Captcha, logger)

	// Инициализация AuditLogService (needs to be initialized before services that depend on it)
	auditLogService := service.NewAuditLogService(auditLogRepo, logger)

	// Инициализация TwoFactorService (refactored service)
	// This will serve as the MFALogicService implementation for AuthService
	twoFactorServiceImpl, err := service.NewTwoFactorService(
		userRepo,
		mfaSecretRepo,
		kafkaProducer, // Assuming this is the correct kafka client type expected
		logger,
		cfg.MFA.TOTPIssuerName,
		&cfg.MFA,
	)
	if err != nil {
		logger.Fatal("Failed to initialize TwoFactorService (MFALogicService impl)", zap.Error(err))
	}

	// Инициализация APIKeyService
	apiKeyServiceConfig := domainService.APIKeyServiceConfig{ // Changed: Use domainService.APIKeyServiceConfig
		APIKeyRepo:      apiKeyRepo,
		PasswordService: passwordService,
		AuditLogRecorder: auditLogService, // Added
		KafkaProducer:   kafkaProducer,    // Added Sarama-based kafkaProducer
	}
	apiKeyService := domainService.NewAPIKeyService(apiKeyServiceConfig) // Changed: Use domainService.NewAPIKeyService


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
		tokenManagementService,
		mfaSecretRepo,
		twoFactorServiceImpl, // Pass the refactored TwoFactorService as the MFALogicService
		userRolesRepo,
		roleService,
		externalAccountRepo, // This was missing from the original NewAuthService call structure in my view, ensure it's defined
		telegramService,   // Ensure telegramService is defined
		auditLogService,
		rateLimiter,
		hibpClient,           // Added HIBPService
		stubCaptchaService,   // Added CaptchaService
	)

	// Assuming UserService and RoleService need specific repositories now
	roleService := service.NewRoleService(
		roleRepo,
		userRepo,
		userRolesRepo,
		kafkaProducer,
		logger,
		auditLogService, // Added
	)
	// var userService *service.UserService // Placeholder - needs proper initialization with specific repos
	userService := service.NewUserService(
		userRepo,
		// roleRepo, // user_service.go's NewUserService takes roleRepo
		userRolesRepo, // Corrected: user_service.go's NewUserService takes userRolesRepo instead of just roleRepo based on recent file reads. Let me double check.
		              // Reading user_service.go again: NewUserService(userRepo, roleRepo, kafkaClient, logger, auditLogRecorder) -> it does take roleRepo.
		roleRepo,     // Correcting based on actual signature from user_service.go
		kafkaProducer,
		logger,
		auditLogService, // Added
	)

	telegramService := service.NewTelegramService(
		userRepo,       // Added missing userRepo
		tokenService,   // Added missing tokenService
		kafkaProducer,  // Pass Sarama-based kafkaProducer
		logger,
		cfg.Telegram.BotToken, // Pass BotToken from config
	)
	// twoFactorService from previous setup is now replaced by mfaLogicService via AuthService
	// var twoFactorService *service.TwoFactorService // This line is now definitely for the old one, or can be removed.
	// The refactored twoFactorServiceImpl is now used as the mfaLogicService.


	// Инициализация обработчиков событий
	// Instantiate new event handlers
	accountHandler := handlers.NewAccountEventsHandler( // Changed alias from eventHandlers to handlers
		logger,
		cfg,
		userRepo,
		verificationCodeRepo,
		authService, // authService itself is AuthLogicService
		// kafkaProducer, // AccountEventsHandler does not take kafkaProducer
		sessionRepo,
		refreshTokenRepo,
		mfaSecretRepo,
		mfaBackupCodeRepo,
		apiKeyRepo,
		externalAccountRepo,
		auditLogService,
	)
	adminHandler := handlers.NewAdminEventsHandler( // Changed alias from eventHandlers to handlers
		logger,
		cfg,
		userRepo,
		authService, // authService itself is AuthLogicService
		// kafkaProducer, // AdminEventsHandler does not take kafkaProducer
		auditLogService,
	)

	// Register handlers with the consumer
	// Assuming event type constants are defined in models package e.g. models.AccountUserProfileUpdatedV1Type
	kafkaConsumer.RegisterHandler(string(models.AccountUserProfileUpdatedV1), accountHandler.HandleAccountUserProfileUpdated)
	kafkaConsumer.RegisterHandler(string(models.AccountUserDeletedV1), accountHandler.HandleAccountUserDeleted)
	kafkaConsumer.RegisterHandler(string(models.AdminUserForceLogoutV1), adminHandler.HandleAdminUserForceLogout)
	kafkaConsumer.RegisterHandler(string(models.AdminUserBlockV1), adminHandler.HandleAdminUserBlock)
	kafkaConsumer.RegisterHandler(string(models.AdminUserUnblockV1), adminHandler.HandleAdminUserUnblock)

	// Start the consumer
	consumerCtx, consumerCancel := context.WithCancel(context.Background())
	// Ensure consumerCancel is called to stop the consumer when main exits
	// This defer should be after other defers that might panic or exit early,
	// or more robustly, called explicitly before other cleanup.
	// For now, simple defer is okay.
	defer consumerCancel()

	go func() {
		logger.Info("Starting Kafka consumer group consuming...")
		kafkaConsumer.StartConsuming(consumerCtx)
		logger.Info("Kafka consumer group has stopped consuming.")
	}()

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
		twoFactorServiceImpl, // Pass the refactored TwoFactorService here as well if httpHandler expects it directly
		apiKeyService,
		auditLogService,
		tokenManagementService,
		cfg,
		logger,
		rateLimiter, // Added rateLimiter
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

	// Health Checkers
	// dbPool (*pgxpool.Pool) directly implements healthcheck.DBPinger via its Ping method.
	// redisClient (*redis.Client) directly implements healthcheck.RedisPinger via its Ping method.
	kafkaProducerChecker := &KafkaProducerHealthChecker{Producer: kafkaProducer}
	kafkaConsumerChecker := &KafkaConsumerHealthChecker{ConsumerGroup: kafkaConsumer}

	authV1GrpcService := grpcHandler.NewAuthV1Service(
		logger,
		authService,  // This is AuthLogicService
		userService,
		tokenService, // This is service.TokenService
		roleService,  // This is service.RoleService acting as RBACService
		dbPool,       // pgxpool.Pool directly usable as healthcheck.DBPinger
		redisClient,  // redis.Client directly usable as healthcheck.RedisPinger
		kafkaProducerChecker,
		kafkaConsumerChecker,
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
