// File: backend/services/auth-service/internal/domain/errors/types.go
package errors

import "fmt"

// Base application error with code.
type AppError struct {
	Err  error
	Msg  string
	Code string
}

func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Msg, e.Err)
	}
	return e.Msg
}

func (e *AppError) Unwrap() error { return e.Err }

const (
	CodeValidation   = "VALIDATION_ERROR"
	CodeUnauthorized = "UNAUTHORIZED"
	CodeForbidden    = "FORBIDDEN"
	CodeNotFound     = "NOT_FOUND"
	CodeConflict     = "CONFLICT"
	CodeInternal     = "INTERNAL_ERROR"
)

type ValidationError struct{ AppError }
type UnauthorizedError struct{ AppError }
type ForbiddenError struct{ AppError }
type NotFoundError struct{ AppError }
type ConflictError struct{ AppError }
type InternalError struct{ AppError }

func NewValidationError(msg string, err error) *ValidationError {
	return &ValidationError{AppError{Err: err, Msg: msg, Code: CodeValidation}}
}
func NewUnauthorizedError(msg string) *UnauthorizedError {
	return &UnauthorizedError{AppError{Msg: msg, Code: CodeUnauthorized}}
}
func NewForbiddenError(msg string) *ForbiddenError {
	return &ForbiddenError{AppError{Msg: msg, Code: CodeForbidden}}
}
func NewNotFoundError(msg string, err error) *NotFoundError {
	return &NotFoundError{AppError{Err: err, Msg: msg, Code: CodeNotFound}}
}
func NewConflictError(msg string) *ConflictError {
	return &ConflictError{AppError{Msg: msg, Code: CodeConflict}}
}
func NewInternalError(msg string, err error) *InternalError {
	return &InternalError{AppError{Err: err, Msg: msg, Code: CodeInternal}}
}
