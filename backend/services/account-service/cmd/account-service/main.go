// File: backend/services/account-service/cmd/account-service/main.go
// account-service\cmd\account-service\main.go
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/sdk/resource"
	tracesdk "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.7.0"
	"go.uber.org/zap"
	"google.golang.org/grpc"

	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/config"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/api/grpc/server"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/api/rest"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/app/usecase"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/infrastructure/kafka"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/infrastructure/repository/postgres"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/infrastructure/repository/redis"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/utils/logger"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/pkg/metrics"
)

func loadConfig() (*config.Config, error) {
	return config.Load()
}

func initDB(cfg *config.Config) (*postgres.DB, *redis.Client, error) {
	db, err := postgres.NewPostgresDB(cfg.Database)
	if err != nil {
		return nil, nil, err
	}

	redisClient, err := redis.NewRedisClient(cfg.Redis)
	if err != nil {
		db.Close()
		return nil, nil, err
	}

	return db, redisClient, nil
}

type services struct {
	accountUseCase     usecase.AccountUseCase
	profileUseCase     usecase.ProfileUseCase
	contactInfoUseCase usecase.ContactInfoUseCase
	settingUseCase     usecase.SettingUseCase
}

func initServices(db *postgres.DB, redisClient *redis.Client, producer kafka.Producer, sugar *zap.SugaredLogger) services {
	accountRepo := postgres.NewAccountRepository(db)
	profileRepo := postgres.NewProfileRepository(db)
	authMethodRepo := postgres.NewAuthMethodRepository(db)
	contactInfoRepo := postgres.NewContactInfoRepository(db)
	settingRepo := postgres.NewSettingRepository(db)
	avatarRepo := postgres.NewAvatarRepository(db)
	profileHistoryRepo := postgres.NewProfileHistoryRepository(db)

	accountCache := redis.NewAccountCache(redisClient)
	profileCache := redis.NewProfileCache(redisClient)

	return services{
		accountUseCase: usecase.NewAccountUseCase(
			accountRepo,
			authMethodRepo,
			profileRepo,
			accountCache,
			producer,
			sugar,
		),
		profileUseCase: usecase.NewProfileUseCase(
			profileRepo,
			accountRepo,
			avatarRepo,
			profileHistoryRepo,
			profileCache,
			producer,
			sugar,
		),
		contactInfoUseCase: usecase.NewContactInfoUseCase(
			contactInfoRepo,
			accountRepo,
			producer,
			sugar,
		),
		settingUseCase: usecase.NewSettingUseCase(
			settingRepo,
			accountRepo,
			producer,
			sugar,
		),
	}
}

func startHTTPServer(cfg *config.Config, router http.Handler) *http.Server {
	return &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.HTTPPort),
		Handler: router,
	}
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Инициализация логгера
	zapLogger, err := logger.NewLogger(cfg.LogLevel, cfg.Environment)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer zapLogger.Sync()

	sugar := zapLogger.Sugar()
	sugar.Infow("Starting Account Service",
		"version", cfg.Version,
		"environment", cfg.Environment,
	)

	// Инициализация трассировки
	tp, err := initTracer(cfg)
	if err != nil {
		sugar.Fatalw("Failed to initialize tracer", "error", err)
	}
	defer func() {
		if err := tp.Shutdown(context.Background()); err != nil {
			sugar.Errorw("Error shutting down tracer provider", "error", err)
		}
	}()

	// Инициализация метрик
	metricsRegistry := metrics.NewRegistry()

	db, redisClient, err := initDB(cfg)
	if err != nil {
		sugar.Fatalw("Failed to initialize databases", "error", err)
	}
	defer db.Close()
	defer redisClient.Close()

	kafkaProducer, err := kafka.NewProducer(cfg.Kafka)
	if err != nil {
		sugar.Fatalw("Failed to create Kafka producer", "error", err)
	}
	defer kafkaProducer.Close()

	svcs := initServices(db, redisClient, kafkaProducer, sugar)

	// Инициализация HTTP сервера
	gin.SetMode(gin.ReleaseMode)
	if cfg.Environment == "development" {
		gin.SetMode(gin.DebugMode)
	}

	router := gin.New()
	router.Use(gin.Recovery())

	// Middleware для логирования, метрик, трассировки
	router.Use(logger.GinMiddleware(zapLogger))
	router.Use(metrics.GinMiddleware(metricsRegistry))

	// Эндпоинты для мониторинга
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	router.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// Регистрация API маршрутов
	apiV1 := router.Group("/api/v1")
	rest.RegisterAccountRoutes(apiV1, svcs.accountUseCase, sugar)
	rest.RegisterProfileRoutes(apiV1, svcs.profileUseCase, sugar)
	rest.RegisterContactInfoRoutes(apiV1, svcs.contactInfoUseCase, sugar)
	rest.RegisterSettingRoutes(apiV1, svcs.settingUseCase, sugar)

	// Запуск HTTP сервера
	httpServer := startHTTPServer(cfg, router)

	// Запуск gRPC сервера
	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			logger.GrpcUnaryServerInterceptor(zapLogger),
			metrics.GrpcUnaryServerInterceptor(metricsRegistry),
		),
	)

	// Регистрация gRPC сервисов
	server.RegisterAccountServiceServer(grpcServer, svcs.accountUseCase)
	server.RegisterProfileServiceServer(grpcServer, svcs.profileUseCase)
	server.RegisterSettingsServiceServer(grpcServer, svcs.settingUseCase)

	grpcListener, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.GRPCPort))
	if err != nil {
		sugar.Fatalw("Failed to listen for gRPC", "error", err)
	}

	// Запуск серверов в горутинах
	go func() {
		sugar.Infow("Starting HTTP server", "port", cfg.HTTPPort)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			sugar.Fatalw("Failed to start HTTP server", "error", err)
		}
	}()

	go func() {
		sugar.Infow("Starting gRPC server", "port", cfg.GRPCPort)
		if err := grpcServer.Serve(grpcListener); err != nil {
			sugar.Fatalw("Failed to start gRPC server", "error", err)
		}
	}()

	// Обработка сигналов для graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	sugar.Info("Shutting down servers...")

	// Graceful shutdown для HTTP сервера
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		sugar.Fatalw("HTTP server forced to shutdown", "error", err)
	}

	// Graceful shutdown для gRPC сервера
	grpcServer.GracefulStop()

	sugar.Info("Servers exited properly")
}

func initTracer(cfg *config.Config) (*tracesdk.TracerProvider, error) {
	exporter, err := jaeger.New(jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(cfg.Jaeger.Endpoint)))
	if err != nil {
		return nil, err
	}

	tp := tracesdk.NewTracerProvider(
		tracesdk.WithSampler(tracesdk.AlwaysSample()),
		tracesdk.WithBatcher(exporter),
		tracesdk.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String("account-service"),
			semconv.ServiceVersionKey.String(cfg.Version),
			semconv.DeploymentEnvironmentKey.String(cfg.Environment),
		)),
	)

	otel.SetTracerProvider(tp)
	return tp, nil
}
