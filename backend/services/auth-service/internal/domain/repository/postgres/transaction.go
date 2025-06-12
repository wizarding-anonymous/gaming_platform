// File: backend/services/auth-service/internal/domain/repository/postgres/transaction.go

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jmoiron/sqlx"
)

// TxKey является ключом контекста для транзакции
type TxKey struct{}

// TransactionManager управляет транзакциями базы данных
type TransactionManager struct {
	db *sqlx.DB
}

// NewTransactionManager создает новый менеджер транзакций
func NewTransactionManager(db *sqlx.DB) *TransactionManager {
	return &TransactionManager{
		db: db,
	}
}

// GetTx извлекает транзакцию из контекста, если она существует
func (tm *TransactionManager) GetTx(ctx context.Context) (*sqlx.Tx, bool) {
	tx, ok := ctx.Value(TxKey{}).(*sqlx.Tx)
	return tx, ok
}

// WithinTransaction выполняет функцию fn в рамках транзакции
// Если fn возвращает ошибку, транзакция откатывается
// Если fn выполняется успешно, транзакция фиксируется
func (tm *TransactionManager) WithinTransaction(ctx context.Context, fn func(ctx context.Context) error) error {
	// Проверяем, есть ли уже транзакция в контексте
	if tx, ok := tm.GetTx(ctx); ok {
		// Если транзакция уже существует, используем её
		return fn(ctx)
	}

	// Начинаем новую транзакцию
	tx, err := tm.db.BeginTxx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
		ReadOnly:  false,
	})
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	// Создаем новый контекст с транзакцией
	txCtx := context.WithValue(ctx, TxKey{}, tx)

	// Выполняем функцию в рамках транзакции
	err = fn(txCtx)
	if err != nil {
		// Если произошла ошибка, откатываем транзакцию
		if rbErr := tx.Rollback(); rbErr != nil {
			// Если откат не удался, возвращаем обе ошибки
			return fmt.Errorf("error: %v, rollback error: %v", err, rbErr)
		}
		return err
	}

	// Если всё прошло успешно, фиксируем транзакцию
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// ExecuteInTransaction выполняет SQL-запрос в рамках транзакции
func (tm *TransactionManager) ExecuteInTransaction(ctx context.Context, query string, args ...interface{}) error {
	tx, ok := tm.GetTx(ctx)
	if !ok {
		return errors.New("no transaction in context")
	}

	_, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to execute query in transaction: %w", err)
	}

	return nil
}

// QueryInTransaction выполняет SQL-запрос в рамках транзакции и возвращает результаты
func (tm *TransactionManager) QueryInTransaction(ctx context.Context, query string, args ...interface{}) (*sqlx.Rows, error) {
	tx, ok := tm.GetTx(ctx)
	if !ok {
		return nil, errors.New("no transaction in context")
	}

	rows, err := tx.QueryxContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query in transaction: %w", err)
	}

	return rows, nil
}

// QueryRowInTransaction выполняет SQL-запрос в рамках транзакции и возвращает одну строку
func (tm *TransactionManager) QueryRowInTransaction(ctx context.Context, query string, args ...interface{}) *sqlx.Row {
	tx, ok := tm.GetTx(ctx)
	if !ok {
		return nil
	}

	return tx.QueryRowxContext(ctx, query, args...)
}
