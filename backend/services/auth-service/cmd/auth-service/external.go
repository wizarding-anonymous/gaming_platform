// File: backend/services/auth-service/cmd/auth-service/external.go
package main

import (
	"fmt"

	"github.com/Shopify/sarama"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/config"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/events/kafka"
	infraDbPostgres "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/infrastructure/database/postgres"
	repoRedis "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/repository/redis"
)

func initDatabase(cfg *config.Config, logger *zap.Logger) (*pgxpool.Pool, error) {
	if cfg.Database.AutoMigrate {
		logger.Info("Running database migrations")
		migrationURL := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
			cfg.Database.User, cfg.Database.Password, cfg.Database.Host, cfg.Database.Port, cfg.Database.DBName, cfg.Database.SSLMode)
		m, err := migrate.New("file://migrations", migrationURL)
		if err != nil {
			return nil, fmt.Errorf("create migration instance: %w", err)
		}
		if err := m.Up(); err != nil && err != migrate.ErrNoChange {
			return nil, fmt.Errorf("apply migrations: %w", err)
		}
		logger.Info("Migrations applied successfully")
	}

	return infraDbPostgres.NewDBPool(cfg.Database)
}

func initRedis(cfg *config.Config) (*repoRedis.RedisClient, error) {
	return repoRedis.NewRedisClient(cfg.Redis)
}

func initKafkaProducer(cfg *config.Config, logger *zap.Logger) (*kafka.Producer, error) {
	return kafka.NewProducer(cfg.Kafka.Brokers, logger, "urn:service:auth")
}

func initKafkaConsumer(cfg *config.Config, logger *zap.Logger) (*kafka.ConsumerGroup, error) {
	saramaCfg := sarama.NewConfig()
	saramaCfg.Version = sarama.V2_8_0_0
	saramaCfg.Consumer.Group.Rebalance.Strategy = sarama.BalanceStrategyRange
	saramaCfg.Consumer.Offsets.Initial = sarama.OffsetOldest
	saramaCfg.Consumer.Return.Errors = true

	consumerGroupCfg := kafka.NewConsumerGroupConfig{
		Brokers:       cfg.Kafka.Brokers,
		Topics:        cfg.Kafka.Consumer.Topics,
		GroupID:       cfg.Kafka.Consumer.GroupID,
		SaramaConfig:  saramaCfg,
		Logger:        logger,
		InitialOffset: sarama.OffsetOldest,
	}

	return kafka.NewConsumerGroup(consumerGroupCfg)
}
