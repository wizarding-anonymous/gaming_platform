package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/your-org/auth-service/internal/config"
	domainErrors "github.com/your-org/auth-service/internal/domain/errors"
	"github.com/your-org/auth-service/internal/domain/models"
	"github.com/your-org/auth-service/internal/repository/interfaces"
)

// PostgresRepository реализует все репозитории для работы с PostgreSQL
type PostgresRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresRepository создает новый экземпляр PostgresRepository
func NewPostgresRepository(cfg config.DatabaseConfig) (*PostgresRepository, error) {
	connString := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		cfg.User, cfg.Password, cfg.Host, cfg.Port, cfg.DBName, cfg.SSLMode)

	poolConfig, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("unable to parse connection string: %w", err)
	}

	// Настройка пула соединений
	poolConfig.MaxConns = int32(cfg.MaxOpenConns)
	poolConfig.MinConns = int32(cfg.MaxIdleConns)
	poolConfig.MaxConnLifetime = cfg.ConnMaxLife
	poolConfig.MaxConnIdleTime = cfg.ConnMaxLife / 2

	// Создание пула соединений
	pool, err := pgxpool.NewWithConfig(context.Background(), poolConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to create connection pool: %w", err)
	}

	// Проверка соединения
	if err := pool.Ping(context.Background()); err != nil {
		pool.Close()
		return nil, fmt.Errorf("unable to ping database: %w", err)
	}

	return &PostgresRepository{
		pool: pool,
	}, nil
}

// Close закрывает соединение с базой данных
func (r *PostgresRepository) Close() {
	if r.pool != nil {
		r.pool.Close()
	}
}

// GetPool возвращает пул соединений
func (r *PostgresRepository) GetPool() *pgxpool.Pool {
	return r.pool
}

// BeginTx начинает новую транзакцию
func (r *PostgresRepository) BeginTx(ctx context.Context) (pgx.Tx, error) {
	return r.pool.Begin(ctx)
}

// Реализация UserRepository

// Create создает нового пользователя
func (r *PostgresRepository) Create(ctx context.Context, user models.User) (models.User, error) {
	query := `
		INSERT INTO users (id, email, username, password_hash, email_verified, two_factor_secret, 
		                  two_factor_enabled, telegram_id, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id, email, username, password_hash, email_verified, two_factor_secret, 
		         two_factor_enabled, telegram_id, status, last_login_at, created_at, updated_at
	`

	var result models.User
	err := r.pool.QueryRow(ctx, query,
		user.ID, user.Email, user.Username, user.PasswordHash, user.EmailVerified,
		user.TwoFactorSecret, user.TwoFactorEnabled, user.TelegramID, user.Status,
		user.CreatedAt, user.UpdatedAt,
	).Scan(
		&result.ID, &result.Email, &result.Username, &result.PasswordHash, &result.EmailVerified,
		&result.TwoFactorSecret, &result.TwoFactorEnabled, &result.TelegramID, &result.Status,
		&result.LastLoginAt, &result.CreatedAt, &result.UpdatedAt,
	)

	if err != nil {
		// Проверка на дубликат email
		if err.Error() == "ERROR: duplicate key value violates unique constraint \"users_email_key\" (SQLSTATE 23505)" {
			return models.User{}, domainErrors.ErrEmailExists
		}
		// Проверка на дубликат username
		if err.Error() == "ERROR: duplicate key value violates unique constraint \"users_username_key\" (SQLSTATE 23505)" {
			return models.User{}, domainErrors.ErrUsernameExists
		}
		return models.User{}, fmt.Errorf("failed to create user: %w", err)
	}

	return result, nil
}

// GetByID получает пользователя по ID
func (r *PostgresRepository) GetByID(ctx context.Context, id uuid.UUID) (models.User, error) {
	query := `
		SELECT id, email, username, password_hash, email_verified, two_factor_secret, 
		       two_factor_enabled, telegram_id, status, last_login_at, created_at, updated_at
		FROM users
		WHERE id = $1 AND status != 'deleted'
	`

	var user models.User
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&user.ID, &user.Email, &user.Username, &user.PasswordHash, &user.EmailVerified,
		&user.TwoFactorSecret, &user.TwoFactorEnabled, &user.TelegramID, &user.Status,
		&user.LastLoginAt, &user.CreatedAt, &user.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.User{}, domainErrors.ErrUserNotFound
		}
		return models.User{}, fmt.Errorf("failed to get user by ID: %w", err)
	}

	// Получение ролей пользователя
	roles, err := r.GetUserRoles(ctx, id)
	if err != nil {
		return models.User{}, fmt.Errorf("failed to get user roles: %w", err)
	}
	user.Roles = roles

	return user, nil
}

// GetByEmail получает пользователя по email
func (r *PostgresRepository) GetByEmail(ctx context.Context, email string) (models.User, error) {
	query := `
		SELECT id, email, username, password_hash, email_verified, two_factor_secret, 
		       two_factor_enabled, telegram_id, status, last_login_at, created_at, updated_at
		FROM users
		WHERE email = $1 AND status != 'deleted'
	`

	var user models.User
	err := r.pool.QueryRow(ctx, query, email).Scan(
		&user.ID, &user.Email, &user.Username, &user.PasswordHash, &user.EmailVerified,
		&user.TwoFactorSecret, &user.TwoFactorEnabled, &user.TelegramID, &user.Status,
		&user.LastLoginAt, &user.CreatedAt, &user.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.User{}, domainErrors.ErrUserNotFound
		}
		return models.User{}, fmt.Errorf("failed to get user by email: %w", err)
	}

	// Получение ролей пользователя
	roles, err := r.GetUserRoles(ctx, user.ID)
	if err != nil {
		return models.User{}, fmt.Errorf("failed to get user roles: %w", err)
	}
	user.Roles = roles

	return user, nil
}

// GetByUsername получает пользователя по имени пользователя
func (r *PostgresRepository) GetByUsername(ctx context.Context, username string) (models.User, error) {
	query := `
		SELECT id, email, username, password_hash, email_verified, two_factor_secret, 
		       two_factor_enabled, telegram_id, status, last_login_at, created_at, updated_at
		FROM users
		WHERE username = $1 AND status != 'deleted'
	`

	var user models.User
	err := r.pool.QueryRow(ctx, query, username).Scan(
		&user.ID, &user.Email, &user.Username, &user.PasswordHash, &user.EmailVerified,
		&user.TwoFactorSecret, &user.TwoFactorEnabled, &user.TelegramID, &user.Status,
		&user.LastLoginAt, &user.CreatedAt, &user.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.User{}, domainErrors.ErrUserNotFound
		}
		return models.User{}, fmt.Errorf("failed to get user by username: %w", err)
	}

	// Получение ролей пользователя
	roles, err := r.GetUserRoles(ctx, user.ID)
	if err != nil {
		return models.User{}, fmt.Errorf("failed to get user roles: %w", err)
	}
	user.Roles = roles

	return user, nil
}

// GetByTelegramID получает пользователя по Telegram ID
func (r *PostgresRepository) GetByTelegramID(ctx context.Context, telegramID string) (models.User, error) {
	query := `
		SELECT id, email, username, password_hash, email_verified, two_factor_secret, 
		       two_factor_enabled, telegram_id, status, last_login_at, created_at, updated_at
		FROM users
		WHERE telegram_id = $1 AND status != 'deleted'
	`

	var user models.User
	err := r.pool.QueryRow(ctx, query, telegramID).Scan(
		&user.ID, &user.Email, &user.Username, &user.PasswordHash, &user.EmailVerified,
		&user.TwoFactorSecret, &user.TwoFactorEnabled, &user.TelegramID, &user.Status,
		&user.LastLoginAt, &user.CreatedAt, &user.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.User{}, domainErrors.ErrUserNotFound
		}
		return models.User{}, fmt.Errorf("failed to get user by Telegram ID: %w", err)
	}

	// Получение ролей пользователя
	roles, err := r.GetUserRoles(ctx, user.ID)
	if err != nil {
		return models.User{}, fmt.Errorf("failed to get user roles: %w", err)
	}
	user.Roles = roles

	return user, nil
}

// Update обновляет информацию о пользователе
func (r *PostgresRepository) Update(ctx context.Context, user models.User) error {
	query := `
		UPDATE users
		SET username = $1, status = $2, updated_at = $3
		WHERE id = $4
	`

	_, err := r.pool.Exec(ctx, query,
		user.Username, user.Status, time.Now(), user.ID,
	)

	if err != nil {
		// Проверка на дубликат username
		if err.Error() == "ERROR: duplicate key value violates unique constraint \"users_username_key\" (SQLSTATE 23505)" {
			return domainErrors.ErrUsernameExists
		}
		return fmt.Errorf("failed to update user: %w", err)
	}

	return nil
}

// Delete удаляет пользователя (мягкое удаление)
func (r *PostgresRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE users
		SET status = 'deleted', updated_at = $1
		WHERE id = $2
	`

	_, err := r.pool.Exec(ctx, query, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	return nil
}

// List получает список пользователей с пагинацией
func (r *PostgresRepository) List(ctx context.Context, offset, limit int) ([]models.User, int64, error) {
	// Получение общего количества пользователей
	var totalCount int64
	countQuery := `
		SELECT COUNT(*)
		FROM users
		WHERE status != 'deleted'
	`
	err := r.pool.QueryRow(ctx, countQuery).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count users: %w", err)
	}

	// Получение списка пользователей
	query := `
		SELECT id, email, username, email_verified, two_factor_enabled, 
		       telegram_id, status, last_login_at, created_at, updated_at
		FROM users
		WHERE status != 'deleted'
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`

	rows, err := r.pool.Query(ctx, query, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list users: %w", err)
	}
	defer rows.Close()

	users := make([]models.User, 0)
	for rows.Next() {
		var user models.User
		err := rows.Scan(
			&user.ID, &user.Email, &user.Username, &user.EmailVerified,
			&user.TwoFactorEnabled, &user.TelegramID, &user.Status,
			&user.LastLoginAt, &user.CreatedAt, &user.UpdatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan user: %w", err)
		}

		// Получение ролей пользователя
		roles, err := r.GetUserRoles(ctx, user.ID)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to get user roles: %w", err)
		}
		user.Roles = roles

		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating user rows: %w", err)
	}

	return users, totalCount, nil
}

// UpdatePassword обновляет пароль пользователя
func (r *PostgresRepository) UpdatePassword(ctx context.Context, id uuid.UUID, passwordHash string) error {
	query := `
		UPDATE users
		SET password_hash = $1, updated_at = $2
		WHERE id = $3
	`

	_, err := r.pool.Exec(ctx, query, passwordHash, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	return nil
}

// UpdateEmailVerificationStatus обновляет статус верификации email
func (r *PostgresRepository) UpdateEmailVerificationStatus(ctx context.Context, id uuid.UUID, verified bool) error {
	query := `
		UPDATE users
		SET email_verified = $1, updated_at = $2
		WHERE id = $3
	`

	_, err := r.pool.Exec(ctx, query, verified, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to update email verification status: %w", err)
	}

	return nil
}

// UpdateTwoFactorStatus обновляет статус двухфакторной аутентификации
func (r *PostgresRepository) UpdateTwoFactorStatus(ctx context.Context, id uuid.UUID, secret string, enabled bool) error {
	query := `
		UPDATE users
		SET two_factor_secret = $1, two_factor_enabled = $2, updated_at = $3
		WHERE id = $4
	`

	_, err := r.pool.Exec(ctx, query, secret, enabled, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to update two-factor status: %w", err)
	}

	return nil
}

// UpdateTelegramID обновляет Telegram ID пользователя
func (r *PostgresRepository) UpdateTelegramID(ctx context.Context, id uuid.UUID, telegramID string) error {
	// Проверка, не привязан ли уже этот Telegram ID к другому аккаунту
	var existingUserID uuid.UUID
	checkQuery := `
		SELECT id
		FROM users
		WHERE telegram_id = $1 AND id != $2
	`
	err := r.pool.QueryRow(ctx, checkQuery, telegramID, id).Scan(&existingUserID)
	if err == nil {
		// Найден другой пользователь с таким Telegram ID
		return domainErrors.ErrTelegramIDExists
	} else if !errors.Is(err, pgx.ErrNoRows) {
		// Произошла ошибка при выполнении запроса
		return fmt.Errorf("failed to check Telegram ID: %w", err)
	}

	// Обновление Telegram ID
	query := `
		UPDATE users
		SET telegram_id = $1, updated_at = $2
		WHERE id = $3
	`

	_, err = r.pool.Exec(ctx, query, telegramID, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to update Telegram ID: %w", err)
	}

	return nil
}

// UpdateLastLogin обновляет время последнего входа
func (r *PostgresRepository) UpdateLastLogin(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE users
		SET last_login_at = $1, updated_at = $1
		WHERE id = $2
	`

	now := time.Now()
	_, err := r.pool.Exec(ctx, query, now, id)
	if err != nil {
		return fmt.Errorf("failed to update last login time: %w", err)
	}

	return nil
}

// GetUserRoles получает роли пользователя
func (r *PostgresRepository) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]models.Role, error) {
	query := `
		SELECT r.id, r.name, r.description, r.created_at, r.updated_at
		FROM roles r
		JOIN user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = $1
	`

	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}
	defer rows.Close()

	roles := make([]models.Role, 0)
	for rows.Next() {
		var role models.Role
		err := rows.Scan(
			&role.ID, &role.Name, &role.Description, &role.CreatedAt, &role.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan role: %w", err)
		}

		// Получение разрешений роли
		permissions, err := r.GetRolePermissions(ctx, role.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to get role permissions: %w", err)
		}
		role.Permissions = permissions

		roles = append(roles, role)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating role rows: %w", err)
	}

	return roles, nil
}

// AssignRole назначает роль пользователю
func (r *PostgresRepository) AssignRole(ctx context.Context, userID, roleID uuid.UUID) error {
	// Проверка существования пользователя
	_, err := r.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	// Проверка существования роли
	_, err = r.GetRoleByID(ctx, roleID)
	if err != nil {
		return err
	}

	// Проверка, не назначена ли уже эта роль пользователю
	checkQuery := `
		SELECT 1
		FROM user_roles
		WHERE user_id = $1 AND role_id = $2
	`
	var exists int
	err = r.pool.QueryRow(ctx, checkQuery, userID, roleID).Scan(&exists)
	if err == nil {
		// Роль уже назначена
		return nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		// Произошла ошибка при выполнении запроса
		return fmt.Errorf("failed to check user role: %w", err)
	}

	// Назначение роли
	query := `
		INSERT INTO user_roles (user_id, role_id, created_at)
		VALUES ($1, $2, $3)
	`

	_, err = r.pool.Exec(ctx, query, userID, roleID, time.Now())
	if err != nil {
		return fmt.Errorf("failed to assign role: %w", err)
	}

	return nil
}

// RemoveRole удаляет роль у пользователя
func (r *PostgresRepository) RemoveRole(ctx context.Context, userID, roleID uuid.UUID) error {
	query := `
		DELETE FROM user_roles
		WHERE user_id = $1 AND role_id = $2
	`

	_, err := r.pool.Exec(ctx, query, userID, roleID)
	if err != nil {
		return fmt.Errorf("failed to remove role: %w", err)
	}

	return nil
}

// HasRole проверяет, имеет ли пользователь указанную роль
func (r *PostgresRepository) HasRole(ctx context.Context, userID uuid.UUID, roleName string) (bool, error) {
	query := `
		SELECT 1
		FROM user_roles ur
		JOIN roles r ON ur.role_id = r.id
		WHERE ur.user_id = $1 AND r.name = $2
	`

	var exists int
	err := r.pool.QueryRow(ctx, query, userID, roleName).Scan(&exists)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("failed to check user role: %w", err)
	}

	return true, nil
}

// HasPermission проверяет, имеет ли пользователь указанное разрешение
func (r *PostgresRepository) HasPermission(ctx context.Context, userID uuid.UUID, permissionName string) (bool, error) {
	query := `
		SELECT 1
		FROM user_roles ur
		JOIN role_permissions rp ON ur.role_id = rp.role_id
		JOIN permissions p ON rp.permission_id = p.id
		WHERE ur.user_id = $1 AND p.name = $2
		LIMIT 1
	`

	var exists int
	err := r.pool.QueryRow(ctx, query, userID, permissionName).Scan(&exists)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("failed to check user permission: %w", err)
	}

	return true, nil
}

// Реализация RoleRepository

// GetRoleByID получает роль по ID
func (r *PostgresRepository) GetByID(ctx context.Context, id uuid.UUID) (models.Role, error) {
	return r.GetRoleByID(ctx, id)
}

// GetRoleByID получает роль по ID (внутренний метод)
func (r *PostgresRepository) GetRoleByID(ctx context.Context, id uuid.UUID) (models.Role, error) {
	query := `
		SELECT id, name, description, created_at, updated_at
		FROM roles
		WHERE id = $1
	`

	var role models.Role
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&role.ID, &role.Name, &role.Description, &role.CreatedAt, &role.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.Role{}, domainErrors.ErrRoleNotFound
		}
		return models.Role{}, fmt.Errorf("failed to get role by ID: %w", err)
	}

	// Получение разрешений роли
	permissions, err := r.GetRolePermissions(ctx, id)
	if err != nil {
		return models.Role{}, fmt.Errorf("failed to get role permissions: %w", err)
	}
	role.Permissions = permissions

	return role, nil
}

// GetByName получает роль по имени
func (r *PostgresRepository) GetByName(ctx context.Context, name string) (models.Role, error) {
	query := `
		SELECT id, name, description, created_at, updated_at
		FROM roles
		WHERE name = $1
	`

	var role models.Role
	err := r.pool.QueryRow(ctx, query, name).Scan(
		&role.ID, &role.Name, &role.Description, &role.CreatedAt, &role.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.Role{}, domainErrors.ErrRoleNotFound
		}
		return models.Role{}, fmt.Errorf("failed to get role by name: %w", err)
	}

	// Получение разрешений роли
	permissions, err := r.GetRolePermissions(ctx, role.ID)
	if err != nil {
		return models.Role{}, fmt.Errorf("failed to get role permissions: %w", err)
	}
	role.Permissions = permissions

	return role, nil
}

// Create создает новую роль
func (r *PostgresRepository) Create(ctx context.Context, role models.Role) (models.Role, error) {
	query := `
		INSERT INTO roles (id, name, description, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, name, description, created_at, updated_at
	`

	var result models.Role
	err := r.pool.QueryRow(ctx, query,
		role.ID, role.Name, role.Description, role.CreatedAt, role.UpdatedAt,
	).Scan(
		&result.ID, &result.Name, &result.Description, &result.CreatedAt, &result.UpdatedAt,
	)

	if err != nil {
		// Проверка на дубликат имени роли
		if err.Error() == "ERROR: duplicate key value violates unique constraint \"roles_name_key\" (SQLSTATE 23505)" {
			return models.Role{}, fmt.Errorf("role with name '%s' already exists", role.Name)
		}
		return models.Role{}, fmt.Errorf("failed to create role: %w", err)
	}

	return result, nil
}

// Update обновляет информацию о роли
func (r *PostgresRepository) Update(ctx context.Context, role models.Role) error {
	query := `
		UPDATE roles
		SET description = $1, updated_at = $2
		WHERE id = $3
	`

	_, err := r.pool.Exec(ctx, query,
		role.Description, time.Now(), role.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update role: %w", err)
	}

	return nil
}

// Delete удаляет роль
func (r *PostgresRepository) Delete(ctx context.Context, id uuid.UUID) error {
	// Начало транзакции
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Удаление связей с пользователями
	_, err = tx.Exec(ctx, "DELETE FROM user_roles WHERE role_id = $1", id)
	if err != nil {
		return fmt.Errorf("failed to delete user role associations: %w", err)
	}

	// Удаление связей с разрешениями
	_, err = tx.Exec(ctx, "DELETE FROM role_permissions WHERE role_id = $1", id)
	if err != nil {
		return fmt.Errorf("failed to delete role permission associations: %w", err)
	}

	// Удаление роли
	_, err = tx.Exec(ctx, "DELETE FROM roles WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}

	// Фиксация транзакции
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// List получает список ролей
func (r *PostgresRepository) List(ctx context.Context) ([]models.Role, error) {
	query := `
		SELECT id, name, description, created_at, updated_at
		FROM roles
		ORDER BY name
	`

	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list roles: %w", err)
	}
	defer rows.Close()

	roles := make([]models.Role, 0)
	for rows.Next() {
		var role models.Role
		err := rows.Scan(
			&role.ID, &role.Name, &role.Description, &role.CreatedAt, &role.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan role: %w", err)
		}

		// Получение разрешений роли
		permissions, err := r.GetRolePermissions(ctx, role.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to get role permissions: %w", err)
		}
		role.Permissions = permissions

		roles = append(roles, role)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating role rows: %w", err)
	}

	return roles, nil
}

// GetRolePermissions получает разрешения роли
func (r *PostgresRepository) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]models.Permission, error) {
	query := `
		SELECT p.id, p.name, p.description, p.created_at, p.updated_at
		FROM permissions p
		JOIN role_permissions rp ON p.id = rp.permission_id
		WHERE rp.role_id = $1
	`

	rows, err := r.pool.Query(ctx, query, roleID)
	if err != nil {
		return nil, fmt.Errorf("failed to get role permissions: %w", err)
	}
	defer rows.Close()

	permissions := make([]models.Permission, 0)
	for rows.Next() {
		var permission models.Permission
		err := rows.Scan(
			&permission.ID, &permission.Name, &permission.Description,
			&permission.CreatedAt, &permission.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan permission: %w", err)
		}

		permissions = append(permissions, permission)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating permission rows: %w", err)
	}

	return permissions, nil
}

// AssignPermission назначает разрешение роли
func (r *PostgresRepository) AssignPermission(ctx context.Context, roleID, permissionID uuid.UUID) error {
	// Проверка существования роли
	_, err := r.GetRoleByID(ctx, roleID)
	if err != nil {
		return err
	}

	// Проверка существования разрешения
	_, err = r.GetPermissionByID(ctx, permissionID)
	if err != nil {
		return err
	}

	// Проверка, не назначено ли уже это разрешение роли
	checkQuery := `
		SELECT 1
		FROM role_permissions
		WHERE role_id = $1 AND permission_id = $2
	`
	var exists int
	err = r.pool.QueryRow(ctx, checkQuery, roleID, permissionID).Scan(&exists)
	if err == nil {
		// Разрешение уже назначено
		return nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		// Произошла ошибка при выполнении запроса
		return fmt.Errorf("failed to check role permission: %w", err)
	}

	// Назначение разрешения
	query := `
		INSERT INTO role_permissions (role_id, permission_id, created_at)
		VALUES ($1, $2, $3)
	`

	_, err = r.pool.Exec(ctx, query, roleID, permissionID, time.Now())
	if err != nil {
		return fmt.Errorf("failed to assign permission: %w", err)
	}

	return nil
}

// RemovePermission удаляет разрешение у роли
func (r *PostgresRepository) RemovePermission(ctx context.Context, roleID, permissionID uuid.UUID) error {
	query := `
		DELETE FROM role_permissions
		WHERE role_id = $1 AND permission_id = $2
	`

	_, err := r.pool.Exec(ctx, query, roleID, permissionID)
	if err != nil {
		return fmt.Errorf("failed to remove permission: %w", err)
	}

	return nil
}

// HasPermission проверяет, имеет ли роль указанное разрешение
func (r *PostgresRepository) HasPermission(ctx context.Context, roleID uuid.UUID, permissionName string) (bool, error) {
	query := `
		SELECT 1
		FROM role_permissions rp
		JOIN permissions p ON rp.permission_id = p.id
		WHERE rp.role_id = $1 AND p.name = $2
	`

	var exists int
	err := r.pool.QueryRow(ctx, query, roleID, permissionName).Scan(&exists)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("failed to check role permission: %w", err)
	}

	return true, nil
}

// GetPermissionByID получает разрешение по ID (внутренний метод)
func (r *PostgresRepository) GetPermissionByID(ctx context.Context, id uuid.UUID) (models.Permission, error) {
	query := `
		SELECT id, name, description, created_at, updated_at
		FROM permissions
		WHERE id = $1
	`

	var permission models.Permission
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&permission.ID, &permission.Name, &permission.Description,
		&permission.CreatedAt, &permission.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.Permission{}, domainErrors.ErrPermissionNotFound
		}
		return models.Permission{}, fmt.Errorf("failed to get permission by ID: %w", err)
	}

	return permission, nil
}

// Ensure PostgresRepository implements all required interfaces
var (
	_ interfaces.UserRepository = (*PostgresRepository)(nil)
	_ interfaces.RoleRepository = (*PostgresRepository)(nil)
)
