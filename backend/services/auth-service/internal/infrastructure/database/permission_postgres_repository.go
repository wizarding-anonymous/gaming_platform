package database

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/gameplatform/auth-service/internal/domain/entity"
	"github.com/gameplatform/auth-service/internal/domain/repository"
)

type pgxPermissionRepository struct {
	db *pgxpool.Pool
}

// NewPgxPermissionRepository creates a new instance of pgxPermissionRepository.
func NewPgxPermissionRepository(db *pgxpool.Pool) repository.PermissionRepository {
	return &pgxPermissionRepository{db: db}
}

func (r *pgxPermissionRepository) Create(ctx context.Context, p *entity.Permission) error {
	query := `
		INSERT INTO permissions (id, name, description, resource, action, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err := r.db.Exec(ctx, query,
		p.ID, p.Name, p.Description, p.Resource, p.Action, p.CreatedAt, p.UpdatedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" { // Unique violation for id or name
			return errors.New("permission with given id or name already exists: " + pgErr.Detail) // Placeholder for entity.ErrPermissionAlreadyExists
		}
		return fmt.Errorf("failed to create permission: %w", err)
	}
	return nil
}

func (r *pgxPermissionRepository) FindByID(ctx context.Context, id string) (*entity.Permission, error) {
	query := `SELECT id, name, description, resource, action, created_at, updated_at FROM permissions WHERE id = $1`
	p := &entity.Permission{}
	err := r.db.QueryRow(ctx, query, id).Scan(
		&p.ID, &p.Name, &p.Description, &p.Resource, &p.Action, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("permission not found") // Placeholder for entity.ErrPermissionNotFound
		}
		return nil, fmt.Errorf("failed to find permission by ID: %w", err)
	}
	return p, nil
}

func (r *pgxPermissionRepository) FindByName(ctx context.Context, name string) (*entity.Permission, error) {
	query := `SELECT id, name, description, resource, action, created_at, updated_at FROM permissions WHERE name = $1`
	p := &entity.Permission{}
	err := r.db.QueryRow(ctx, query, name).Scan(
		&p.ID, &p.Name, &p.Description, &p.Resource, &p.Action, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("permission not found") // Placeholder for entity.ErrPermissionNotFound
		}
		return nil, fmt.Errorf("failed to find permission by name: %w", err)
	}
	return p, nil
}

func (r *pgxPermissionRepository) Update(ctx context.Context, p *entity.Permission) error {
	// Assumes trigger handles updated_at
	query := `UPDATE permissions SET name = $2, description = $3, resource = $4, action = $5, updated_at = $6 WHERE id = $1`
	commandTag, err := r.db.Exec(ctx, query, p.ID, p.Name, p.Description, p.Resource, p.Action, time.Now())
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" { // Unique violation for name
			return errors.New("permission name conflict: " + pgErr.Detail)
		}
		return fmt.Errorf("failed to update permission: %w", err)
	}
	if commandTag.RowsAffected() == 0 {
		return errors.New("permission not found or no changes made") // Placeholder for entity.ErrPermissionNotFound
	}
	return nil
}

func (r *pgxPermissionRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM permissions WHERE id = $1`
	commandTag, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete permission: %w", err)
	}
	if commandTag.RowsAffected() == 0 {
		return errors.New("permission not found") // Placeholder for entity.ErrPermissionNotFound
	}
	return nil
}

func (r *pgxPermissionRepository) List(ctx context.Context) ([]*entity.Permission, error) {
	query := `SELECT id, name, description, resource, action, created_at, updated_at FROM permissions ORDER BY name`
	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list permissions: %w", err)
	}
	defer rows.Close()

	var permissions []*entity.Permission
	for rows.Next() {
		p := &entity.Permission{}
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Resource, &p.Action, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan permission during list: %w", err)
		}
		permissions = append(permissions, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error after iterating permissions list: %w", err)
	}
	return permissions, nil
}

var _ repository.PermissionRepository = (*pgxPermissionRepository)(nil)
