// File: internal/migrations/migrations.go

package migrations

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/config"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/utils/logger"
)

// Manager представляет менеджер миграций базы данных
type Manager struct {
	db     *sql.DB
	config *config.DatabaseConfig
	logger logger.Logger
}

// NewManager создает новый экземпляр менеджера миграций
func NewManager(db *sql.DB, config *config.DatabaseConfig, logger logger.Logger) *Manager {
	return &Manager{
		db:     db,
		config: config,
		logger: logger,
	}
}

// MigrateUp выполняет миграции вверх
func (m *Manager) MigrateUp() error {
	// Создаем драйвер для миграций
	driver, err := postgres.WithInstance(m.db, &postgres.Config{})
	if err != nil {
		m.logger.Error("Failed to create migration driver", "error", err)
		return fmt.Errorf("failed to create migration driver: %w", err)
	}

	// Создаем экземпляр мигратора
	migrator, err := migrate.NewWithDatabaseInstance(
		fmt.Sprintf("file://%s", m.config.MigrationsPath),
		"postgres", driver)
	if err != nil {
		m.logger.Error("Failed to create migrator", "error", err)
		return fmt.Errorf("failed to create migrator: %w", err)
	}

	// Выполняем миграции вверх
	err = migrator.Up()
	if err != nil && !errors.Is(err, migrate.ErrNoChange) {
		m.logger.Error("Failed to run migrations", "error", err)
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	if errors.Is(err, migrate.ErrNoChange) {
		m.logger.Info("No migrations to apply")
	} else {
		m.logger.Info("Migrations applied successfully")
	}

	return nil
}

// MigrateDown выполняет миграции вниз
func (m *Manager) MigrateDown() error {
	// Создаем драйвер для миграций
	driver, err := postgres.WithInstance(m.db, &postgres.Config{})
	if err != nil {
		m.logger.Error("Failed to create migration driver", "error", err)
		return fmt.Errorf("failed to create migration driver: %w", err)
	}

	// Создаем экземпляр мигратора
	migrator, err := migrate.NewWithDatabaseInstance(
		fmt.Sprintf("file://%s", m.config.MigrationsPath),
		"postgres", driver)
	if err != nil {
		m.logger.Error("Failed to create migrator", "error", err)
		return fmt.Errorf("failed to create migrator: %w", err)
	}

	// Выполняем миграции вниз
	err = migrator.Down()
	if err != nil && !errors.Is(err, migrate.ErrNoChange) {
		m.logger.Error("Failed to rollback migrations", "error", err)
		return fmt.Errorf("failed to rollback migrations: %w", err)
	}

	if errors.Is(err, migrate.ErrNoChange) {
		m.logger.Info("No migrations to rollback")
	} else {
		m.logger.Info("Migrations rolled back successfully")
	}

	return nil
}

// MigrateTo выполняет миграции до указанной версии
func (m *Manager) MigrateTo(version uint) error {
	// Создаем драйвер для миграций
	driver, err := postgres.WithInstance(m.db, &postgres.Config{})
	if err != nil {
		m.logger.Error("Failed to create migration driver", "error", err)
		return fmt.Errorf("failed to create migration driver: %w", err)
	}

	// Создаем экземпляр мигратора
	migrator, err := migrate.NewWithDatabaseInstance(
		fmt.Sprintf("file://%s", m.config.MigrationsPath),
		"postgres", driver)
	if err != nil {
		m.logger.Error("Failed to create migrator", "error", err)
		return fmt.Errorf("failed to create migrator: %w", err)
	}

	// Выполняем миграции до указанной версии
	err = migrator.Migrate(version)
	if err != nil && !errors.Is(err, migrate.ErrNoChange) {
		m.logger.Error("Failed to migrate to version", "error", err, "version", version)
		return fmt.Errorf("failed to migrate to version %d: %w", version, err)
	}

	if errors.Is(err, migrate.ErrNoChange) {
		m.logger.Info("No migrations to apply", "version", version)
	} else {
		m.logger.Info("Migrations applied successfully", "version", version)
	}

	return nil
}

// GetCurrentVersion возвращает текущую версию миграций
func (m *Manager) GetCurrentVersion() (uint, bool, error) {
	// Создаем драйвер для миграций
	driver, err := postgres.WithInstance(m.db, &postgres.Config{})
	if err != nil {
		m.logger.Error("Failed to create migration driver", "error", err)
		return 0, false, fmt.Errorf("failed to create migration driver: %w", err)
	}

	// Создаем экземпляр мигратора
	migrator, err := migrate.NewWithDatabaseInstance(
		fmt.Sprintf("file://%s", m.config.MigrationsPath),
		"postgres", driver)
	if err != nil {
		m.logger.Error("Failed to create migrator", "error", err)
		return 0, false, fmt.Errorf("failed to create migrator: %w", err)
	}

	// Получаем текущую версию
	version, dirty, err := migrator.Version()
	if err != nil {
		if errors.Is(err, migrate.ErrNilVersion) {
			return 0, false, nil
		}
		m.logger.Error("Failed to get current version", "error", err)
		return 0, false, fmt.Errorf("failed to get current version: %w", err)
	}

	return version, dirty, nil
}

// CreateMigration создает новые файлы миграции
func (m *Manager) CreateMigration(name string) error {
	// Проверяем, что имя миграции не пустое
	if name == "" {
		return errors.New("migration name cannot be empty")
	}

	// Проверяем, что имя миграции содержит только допустимые символы
	if !isValidMigrationName(name) {
		return errors.New("migration name can only contain letters, numbers, and underscores")
	}

	// Получаем текущее время для формирования версии миграции
	timestamp := time.Now().Unix()

	// Формируем имя файлов миграции
	upFilename := fmt.Sprintf("%d_%s.up.sql", timestamp, name)
	downFilename := fmt.Sprintf("%d_%s.down.sql", timestamp, name)

	// Формируем полные пути к файлам миграции
	upPath := filepath.Join(m.config.MigrationsPath, upFilename)
	downPath := filepath.Join(m.config.MigrationsPath, downFilename)

	// Создаем файл миграции вверх
	upFile, err := os.Create(upPath)
	if err != nil {
		m.logger.Error("Failed to create up migration file", "error", err, "path", upPath)
		return fmt.Errorf("failed to create up migration file: %w", err)
	}
	defer upFile.Close()

	// Создаем файл миграции вниз
	downFile, err := os.Create(downPath)
	if err != nil {
		m.logger.Error("Failed to create down migration file", "error", err, "path", downPath)
		return fmt.Errorf("failed to create down migration file: %w", err)
	}
	defer downFile.Close()

	m.logger.Info("Migration files created", "up", upPath, "down", downPath)
	return nil
}

// ListMigrations возвращает список доступных миграций
func (m *Manager) ListMigrations() ([]string, error) {
	// Проверяем, что директория с миграциями существует
	if _, err := os.Stat(m.config.MigrationsPath); os.IsNotExist(err) {
		m.logger.Error("Migrations directory does not exist", "path", m.config.MigrationsPath)
		return nil, fmt.Errorf("migrations directory does not exist: %w", err)
	}

	// Получаем список файлов в директории с миграциями
	files, err := os.ReadDir(m.config.MigrationsPath)
	if err != nil {
		m.logger.Error("Failed to read migrations directory", "error", err, "path", m.config.MigrationsPath)
		return nil, fmt.Errorf("failed to read migrations directory: %w", err)
	}

	// Фильтруем файлы, оставляя только файлы миграций вверх
	var migrations []string
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		filename := file.Name()
		if strings.HasSuffix(filename, ".up.sql") {
			// Извлекаем имя миграции без суффикса
			name := strings.TrimSuffix(filename, ".up.sql")
			migrations = append(migrations, name)
		}
	}

	// Сортируем миграции по версии
	sort.Strings(migrations)

	return migrations, nil
}

// isValidMigrationName проверяет, что имя миграции содержит только допустимые символы
func isValidMigrationName(name string) bool {
	for _, char := range name {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '_') {
			return false
		}
	}
	return true
}

// ForceSetVersion принудительно устанавливает версию миграций
func (m *Manager) ForceSetVersion(version uint, dirty bool) error {
	// Создаем драйвер для миграций
	driver, err := postgres.WithInstance(m.db, &postgres.Config{})
	if err != nil {
		m.logger.Error("Failed to create migration driver", "error", err)
		return fmt.Errorf("failed to create migration driver: %w", err)
	}

	// Создаем экземпляр мигратора
	migrator, err := migrate.NewWithDatabaseInstance(
		fmt.Sprintf("file://%s", m.config.MigrationsPath),
		"postgres", driver)
	if err != nil {
		m.logger.Error("Failed to create migrator", "error", err)
		return fmt.Errorf("failed to create migrator: %w", err)
	}

	// Принудительно устанавливаем версию
	err = migrator.Force(int(version))
	if err != nil {
		m.logger.Error("Failed to force version", "error", err, "version", version)
		return fmt.Errorf("failed to force version %d: %w", version, err)
	}

	m.logger.Info("Version forced successfully", "version", version, "dirty", dirty)
	return nil
}

// FixDirtyState исправляет грязное состояние миграций
func (m *Manager) FixDirtyState() error {
	// Получаем текущую версию
	version, dirty, err := m.GetCurrentVersion()
	if err != nil {
		return err
	}

	// Если состояние не грязное, ничего не делаем
	if !dirty {
		m.logger.Info("Migration state is not dirty, nothing to fix")
		return nil
	}

	// Принудительно устанавливаем версию как не грязную
	err = m.ForceSetVersion(version, false)
	if err != nil {
		return err
	}

	m.logger.Info("Dirty state fixed", "version", version)
	return nil
}

// RunMigrations запускает миграции при старте приложения
func RunMigrations(db *sql.DB, config *config.DatabaseConfig) error {
	// Создаем драйвер для миграций
	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		log.Printf("Failed to create migration driver: %v", err)
		return fmt.Errorf("failed to create migration driver: %w", err)
	}

	// Создаем экземпляр мигратора
	migrator, err := migrate.NewWithDatabaseInstance(
		fmt.Sprintf("file://%s", config.MigrationsPath),
		"postgres", driver)
	if err != nil {
		log.Printf("Failed to create migrator: %v", err)
		return fmt.Errorf("failed to create migrator: %w", err)
	}

	// Выполняем миграции вверх
	err = migrator.Up()
	if err != nil && !errors.Is(err, migrate.ErrNoChange) {
		log.Printf("Failed to run migrations: %v", err)
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	if errors.Is(err, migrate.ErrNoChange) {
		log.Println("No migrations to apply")
	} else {
		log.Println("Migrations applied successfully")
	}

	return nil
}
