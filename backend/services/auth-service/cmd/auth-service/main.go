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
	"github.com/your-org/auth-service/internal/repository/postgres"
	"github.com/your-org/auth-service/internal/repository/redis"
	"github.com/your-org/auth-service/internal/service"
	"github.com/your-org/auth-service/internal/utils/telemetry"

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
	pgRepo, err := postgres.NewPostgresRepository(cfg.Database)
	if err != nil {
		logger.Fatal("Failed to initialize PostgreSQL repository", zap.Error(err))
	}
	defer pgRepo.Close()

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

	// Инициализация сервисов
	tokenService := service.NewTokenService(redisClient, cfg.JWT, logger)
	authService := service.NewAuthService(pgRepo, redisClient, tokenService, kafkaProducer, cfg, logger)
	userService := service.NewUserService(pgRepo, kafkaProducer, logger)
	roleService := service.NewRoleService(pgRepo, logger)
	sessionService := service.NewSessionService(pgRepo, redisClient, logger)
	telegramService := service.NewTelegramService(cfg.Telegram, logger)
	twoFactorService := service.NewTwoFactorService(pgRepo, redisClient, logger)

	// Инициализация обработчиков событий
	eventHandlers := kafka.NewEventHandlers(authService, userService, logger)
	go kafkaConsumer.StartConsuming(eventHandlers.HandleEvent)

	// Инициализация HTTP сервера
	router := httpHandler.NewRouter(
		authService,
		userService,
		roleService,
		tokenService,
		sessionService,
		telegramService,
		twoFactorService,
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

	authGRPCServer := grpcHandler.NewAuthServer(authService, userService, roleService, tokenService, logger)
	authGRPCServer.RegisterServer(grpcServer)

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
