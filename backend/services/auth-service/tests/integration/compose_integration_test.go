// File: backend/services/auth-service/tests/integration/compose_integration_test.go
package integration

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	repoPostgres "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/repository/postgres"
	repoRedis "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/repository/redis"
	"go.uber.org/zap"
)

var (
	db          *pgxpool.Pool
	redisClient *redis.Client
)

func TestMain(m *testing.M) {
	ctx := context.Background()

	pgHost := getEnv("TEST_DB_HOST", "localhost")
	pgPort := getEnv("TEST_DB_PORT", "5433")
	dsn := fmt.Sprintf("postgres://postgres:postgres@%s:%s/auth_test?sslmode=disable", pgHost, pgPort)
	var err error
	db, err = pgxpool.New(ctx, dsn)
	if err != nil {
		fmt.Printf("db connect error: %v\n", err)
		os.Exit(1)
	}

	mig, err := migrate.New("file://../../migrations", dsn)
	if err == nil {
		_ = mig.Up()
	}

	redisHost := getEnv("TEST_REDIS_HOST", "localhost")
	redisPort := getEnv("TEST_REDIS_PORT", "6379")
	redisClient = redis.NewClient(&redis.Options{Addr: fmt.Sprintf("%s:%s", redisHost, redisPort)})
	if err = redisClient.Ping(ctx).Err(); err != nil {
		fmt.Printf("redis ping error: %v\n", err)
		os.Exit(1)
	}

	code := m.Run()
	db.Close()
	os.Exit(code)
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func TestUserRepositoryAndTokenCache(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()

	userRepo := repoPostgres.NewUserRepositoryPostgres(db)
	tokenCache := repoRedis.NewTokenCache(redisClient, logger, time.Hour)

	user := &models.User{ID: uuid.New(), Username: "docker_user", Email: "docker@example.com", PasswordHash: "hash", Status: models.UserStatusActive}
	err := userRepo.Create(ctx, user)
	require.NoError(t, err)

	fetched, err := userRepo.FindByID(ctx, user.ID)
	require.NoError(t, err)
	assert.Equal(t, user.Email, fetched.Email)

	token := &models.Token{ID: uuid.New(), UserID: user.ID, TokenType: string(models.TokenTypeAccess), TokenValue: "tval", ExpiresAt: time.Now().Add(time.Minute)}
	require.NoError(t, tokenCache.Set(ctx, token))
	fromVal, err := tokenCache.GetByValue(ctx, token.TokenValue)
	require.NoError(t, err)
	assert.Equal(t, token.ID, fromVal.ID)

	require.NoError(t, tokenCache.RevokeToken(ctx, token.TokenValue))
	revoked, err := tokenCache.IsRevoked(ctx, token.TokenValue)
	require.NoError(t, err)
	assert.True(t, revoked)
}
