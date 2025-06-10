// File: internal/utils/healthcheck/checkers.go
package healthcheck

import (
	"context"
	"database/sql"                 // For DB Pinger
	"github.com/Shopify/sarama"    // For Kafka
	"github.com/go-redis/redis/v8" // For Redis Pinger
)

// GeneralPinger defines a simple Ping method.
type GeneralPinger interface {
	Ping(ctx context.Context) error
}

// KafkaProducerChecker defines an interface for checking Kafka producer health.
type KafkaProducerChecker interface {
	Healthy(ctx context.Context) error
}

// KafkaConsumerChecker defines an interface for checking Kafka consumer health.
type KafkaConsumerChecker interface {
	Healthy(ctx context.Context) error
}

// For direct use if pgxpool.Pool and redis.Client are passed
type DBPinger interface {
	Ping(ctx context.Context) error
}

type RedisPinger interface {
	Ping(ctx context.Context) error
}
