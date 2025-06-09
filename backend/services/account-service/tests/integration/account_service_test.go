// File: backend/services/account-service/tests/integration/account_service_test.go
// account-service\tests\integration\account_service_test.go
package integration

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"github.com/gaiming/account-service/internal/app/usecase"
	"github.com/gaiming/account-service/internal/domain/entity"
	"github.com/gaiming/account-service/internal/infrastructure/repository/postgres"
	redisRepo "github.com/gaiming/account-service/internal/infrastructure/repository/redis"
	"github.com/gaiming/account-service/pkg/metrics"
)

var (
	db          *sqlx.DB
	redisClient *redis.Client
	pool        *dockertest.Pool
	pgResource  *dockertest.Resource
	redisResource *dockertest.Resource
)

func TestMain(m *testing.M) {
	// Создание пула Docker
	var err error
	pool, err = dockertest.NewPool("")
	if err != nil {
		fmt.Printf("Could not connect to docker: %s\n", err)
		os.Exit(1)
	}

	// Запуск контейнера PostgreSQL
	pgResource, err = pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "postgres",
		Tag:        "13",
		Env: []string{
			"POSTGRES_PASSWORD=postgres",
			"POSTGRES_USER=postgres",
			"POSTGRES_DB=testdb",
		},
	}, func(config *docker.HostConfig) {
		// Установка AutoRemove для автоматической очистки
		config.AutoRemove = true
		config.RestartPolicy = docker.RestartPolicy{
			Name: "no",
		}
	})
	if err != nil {
		fmt.Printf("Could not start PostgreSQL container: %s\n", err)
		os.Exit(1)
	}

	// Запуск контейнера Redis
	redisResource, err = pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "redis",
		Tag:        "6",
	}, func(config *docker.HostConfig) {
		// Установка AutoRemove для автоматической очистки
		config.AutoRemove = true
		config.RestartPolicy = docker.RestartPolicy{
			Name: "no",
		}
	})
	if err != nil {
		fmt.Printf("Could not start Redis container: %s\n", err)
		os.Exit(1)
	}

	// Экспонирование порта PostgreSQL
	pgPort := pgResource.GetPort("5432/tcp")
	// Экспонирование порта Redis
	redisPort := redisResource.GetPort("6379/tcp")

	// Ожидание готовности PostgreSQL
	if err = pool.Retry(func() error {
		var err error
		db, err = sqlx.Connect("postgres", fmt.Sprintf("postgres://postgres:postgres@localhost:%s/testdb?sslmode=disable", pgPort))
		if err != nil {
			return err
		}
		return db.Ping()
	}); err != nil {
		fmt.Printf("Could not connect to PostgreSQL: %s\n", err)
		os.Exit(1)
	}

	// Ожидание готовности Redis
	if err = pool.Retry(func() error {
		redisClient = redis.NewClient(&redis.Options{
			Addr: fmt.Sprintf("localhost:%s", redisPort),
		})
		return redisClient.Ping(context.Background()).Err()
	}); err != nil {
		fmt.Printf("Could not connect to Redis: %s\n", err)
		os.Exit(1)
	}

	// Создание схемы базы данных
	createSchema()

	// Запуск тестов
	code := m.Run()

	// Очистка ресурсов
	if err = pool.Purge(pgResource); err != nil {
		fmt.Printf("Could not purge PostgreSQL container: %s\n", err)
	}
	if err = pool.Purge(redisResource); err != nil {
		fmt.Printf("Could not purge Redis container: %s\n", err)
	}

	os.Exit(code)
}

func createSchema() {
	schema := `
	CREATE TABLE IF NOT EXISTS accounts (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		username VARCHAR(255) NOT NULL UNIQUE,
		email VARCHAR(255) NOT NULL UNIQUE,
		status VARCHAR(50) NOT NULL DEFAULT 'active',
		created_at TIMESTAMP NOT NULL DEFAULT NOW(),
		updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
		deleted_at TIMESTAMP
	);
	
	CREATE INDEX IF NOT EXISTS idx_accounts_username ON accounts(username);
	CREATE INDEX IF NOT EXISTS idx_accounts_email ON accounts(email);
	CREATE INDEX IF NOT EXISTS idx_accounts_status ON accounts(status);
	`

	_, err := db.Exec(schema)
	if err != nil {
		fmt.Printf("Could not create schema: %s\n", err)
		os.Exit(1)
	}
}

func TestAccountUseCase_Integration(t *testing.T) {
	// Создание логгера для тестов
	logger := zaptest.NewLogger(t).Sugar()

	// Создание метрик
	metricsRegistry := metrics.NewRegistry()

	// Создание репозитория аккаунтов
	accountRepo := postgres.NewAccountRepository(db, metricsRegistry, logger)

	// Создание кэша аккаунтов
	accountCache := redisRepo.NewAccountCache(redisClient, metricsRegistry, logger)

	// Создание usecase
	accountUseCase := usecase.NewAccountUseCase(accountRepo, accountCache, nil, logger)

	// Тест создания аккаунта
	t.Run("CreateAccount", func(t *testing.T) {
		// Создание тестового аккаунта
		account := &entity.Account{
			Username: "testuser",
			Email:    "test@example.com",
			Status:   entity.AccountStatusActive,
		}

		// Создание аккаунта
		createdAccount, err := accountUseCase.CreateAccount(context.Background(), account)
		require.NoError(t, err)
		assert.NotEmpty(t, createdAccount.ID)
		assert.Equal(t, account.Username, createdAccount.Username)
		assert.Equal(t, account.Email, createdAccount.Email)
		assert.Equal(t, account.Status, createdAccount.Status)
		assert.False(t, createdAccount.CreatedAt.IsZero())
		assert.False(t, createdAccount.UpdatedAt.IsZero())

		// Получение аккаунта по ID
		retrievedAccount, err := accountUseCase.GetAccount(context.Background(), createdAccount.ID)
		require.NoError(t, err)
		assert.Equal(t, createdAccount.ID, retrievedAccount.ID)
		assert.Equal(t, createdAccount.Username, retrievedAccount.Username)
		assert.Equal(t, createdAccount.Email, retrievedAccount.Email)
		assert.Equal(t, createdAccount.Status, retrievedAccount.Status)

		// Получение аккаунта по имени пользователя
		retrievedByUsername, err := accountUseCase.GetAccountByUsername(context.Background(), account.Username)
		require.NoError(t, err)
		assert.Equal(t, createdAccount.ID, retrievedByUsername.ID)

		// Обновление аккаунта
		updatedAccount := &entity.Account{
			ID:       createdAccount.ID,
			Username: "updateduser",
			Email:    "updated@example.com",
			Status:   entity.AccountStatusSuspended,
		}

		updated, err := accountUseCase.UpdateAccount(context.Background(), updatedAccount)
		require.NoError(t, err)
		assert.Equal(t, updatedAccount.Username, updated.Username)
		assert.Equal(t, updatedAccount.Email, updated.Email)
		assert.Equal(t, updatedAccount.Status, updated.Status)

		// Получение обновленного аккаунта
		retrievedUpdated, err := accountUseCase.GetAccount(context.Background(), createdAccount.ID)
		require.NoError(t, err)
		assert.Equal(t, updatedAccount.Username, retrievedUpdated.Username)
		assert.Equal(t, updatedAccount.Email, retrievedUpdated.Email)
		assert.Equal(t, updatedAccount.Status, retrievedUpdated.Status)

		// Удаление аккаунта
		err = accountUseCase.DeleteAccount(context.Background(), createdAccount.ID)
		require.NoError(t, err)

		// Проверка, что аккаунт удален
		_, err = accountUseCase.GetAccount(context.Background(), createdAccount.ID)
		assert.Error(t, err)
	})

	// Тест получения списка аккаунтов
	t.Run("ListAccounts", func(t *testing.T) {
		// Очистка таблицы перед тестом
		_, err := db.Exec("DELETE FROM accounts")
		require.NoError(t, err)

		// Создание нескольких тестовых аккаунтов
		for i := 0; i < 5; i++ {
			account := &entity.Account{
				Username: fmt.Sprintf("user%d", i),
				Email:    fmt.Sprintf("user%d@example.com", i),
				Status:   entity.AccountStatusActive,
			}
			_, err := accountUseCase.CreateAccount(context.Background(), account)
			require.NoError(t, err)
		}

		// Получение списка аккаунтов
		accounts, total, err := accountUseCase.ListAccounts(context.Background(), 1, 10, "")
		require.NoError(t, err)
		assert.Equal(t, 5, total)
		assert.Len(t, accounts, 5)

		// Получение списка с пагинацией
		accounts, total, err = accountUseCase.ListAccounts(context.Background(), 1, 2, "")
		require.NoError(t, err)
		assert.Equal(t, 5, total)
		assert.Len(t, accounts, 2)

		// Получение списка с фильтром по статусу
		accounts, total, err = accountUseCase.ListAccounts(context.Background(), 1, 10, "active")
		require.NoError(t, err)
		assert.Equal(t, 5, total)
		assert.Len(t, accounts, 5)

		// Получение списка с фильтром по несуществующему статусу
		accounts, total, err = accountUseCase.ListAccounts(context.Background(), 1, 10, "nonexistent")
		require.NoError(t, err)
		assert.Equal(t, 0, total)
		assert.Len(t, accounts, 0)
	})

	// Тест кэширования
	t.Run("Caching", func(t *testing.T) {
		// Очистка таблицы и кэша перед тестом
		_, err := db.Exec("DELETE FROM accounts")
		require.NoError(t, err)
		err = redisClient.FlushAll(context.Background()).Err()
		require.NoError(t, err)

		// Создание тестового аккаунта
		account := &entity.Account{
			Username: "cacheuser",
			Email:    "cache@example.com",
			Status:   entity.AccountStatusActive,
		}
		createdAccount, err := accountUseCase.CreateAccount(context.Background(), account)
		require.NoError(t, err)

		// Первый запрос должен получить данные из БД и закэшировать их
		retrievedAccount, err := accountUseCase.GetAccount(context.Background(), createdAccount.ID)
		require.NoError(t, err)
		assert.Equal(t, createdAccount.ID, retrievedAccount.ID)

		// Изменение данных напрямую в БД, минуя кэш
		_, err = db.Exec("UPDATE accounts SET username = 'directupdate' WHERE id = $1", createdAccount.ID)
		require.NoError(t, err)

		// Второй запрос должен получить данные из кэша (старые данные)
		cachedAccount, err := accountUseCase.GetAccount(context.Background(), createdAccount.ID)
		require.NoError(t, err)
		assert.Equal(t, createdAccount.Username, cachedAccount.Username) // Должно быть старое значение из кэша

		// Очистка кэша
		err = accountCache.Delete(context.Background(), createdAccount.ID)
		require.NoError(t, err)

		// Третий запрос должен получить обновленные данные из БД
		updatedAccount, err := accountUseCase.GetAccount(context.Background(), createdAccount.ID)
		require.NoError(t, err)
		assert.Equal(t, "directupdate", updatedAccount.Username) // Должно быть новое значение из БД
	})
}
