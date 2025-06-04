package postgres

import (
	"context"
	"fmt"
	// "time" // Not strictly needed here, but often used for pool settings

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/your-org/auth-service/internal/config" // Assuming this is the correct config path
)

// NewDBPool creates a new PostgreSQL connection pool.
func NewDBPool(cfg config.DatabaseConfig) (*pgxpool.Pool, error) {
	connString := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		cfg.User, cfg.Password, cfg.Host, cfg.Port, cfg.DBName, cfg.SSLMode)

	poolConfig, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("unable to parse connection string: %w", err)
	}

	// Apply connection pool settings from config
	if cfg.MaxOpenConns > 0 {
		poolConfig.MaxConns = int32(cfg.MaxOpenConns)
	}
	if cfg.MaxIdleConns > 0 { // pgxpool uses MinConns for a similar concept
		poolConfig.MinConns = int32(cfg.MaxIdleConns)
	}
	if cfg.ConnMaxLife > 0 {
		poolConfig.MaxConnLifetime = cfg.ConnMaxLife
	}
	// poolConfig.MaxConnIdleTime = cfg.ConnMaxIdleTime // If you add ConnMaxIdleTime to config

	pool, err := pgxpool.NewWithConfig(context.Background(), poolConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to create connection pool: %w", err)
	}

	// Ping the database to verify connection
	if err := pool.Ping(context.Background()); err != nil {
		pool.Close() // Close the pool if ping fails
		return nil, fmt.Errorf("unable to ping database: %w", err)
	}

	return pool, nil
}
