// File: backend/services/auth-service/internal/domain/errors/errors.go
package errors

import (
	"errors"
	"fmt"
)

// Определение типов ошибок
var (
	// Общие ошибки
	ErrInternal          = errors.New("внутренняя ошибка сервера")
	ErrInvalidRequest    = errors.New("некорректный запрос")
	ErrNotFound          = errors.New("ресурс не найден")
	ErrAlreadyExists     = errors.New("ресурс уже существует")
	ErrForbidden         = errors.New("доступ запрещен")
	ErrUnauthorized      = errors.New("не авторизован")
	
	// Ошибки аутентификации
	ErrInvalidCredentials = errors.New("неверные учетные данные")
	ErrInvalidToken       = errors.New("недействительный токен")
	ErrExpiredToken       = errors.New("истекший токен")
	ErrRevokedToken       = errors.New("отозванный токен")
	ErrInvalidRefreshToken = errors.New("недействительный refresh токен")
	ErrPasswordPwned     = errors.New("пароль скомпрометирован и не может быть использован")
	
	// Ошибки пользователей
	ErrUserNotFound      = errors.New("пользователь не найден")
	ErrEmailExists       = errors.New("email уже используется")
	ErrUsernameExists    = errors.New("имя пользователя уже используется")
	ErrInvalidPassword   = errors.New("неверный пароль")
	ErrUserBlocked       = errors.New("пользователь заблокирован")
	ErrUserLockedOut     = errors.New("пользователь временно заблокирован") // Added
	ErrEmailNotVerified  = errors.New("email не подтвержден")
	
	// Ошибки ролей и разрешений
	ErrRoleNotFound      = errors.New("роль не найдена")
	ErrPermissionNotFound = errors.New("разрешение не найдено")
	ErrPermissionDenied  = errors.New("отказано в доступе")
	
	// Ошибки двухфакторной аутентификации
	ErrInvalid2FACode    = errors.New("неверный код 2FA")
	Err2FARequired       = errors.New("требуется двухфакторная аутентификация")
	Err2FAAlreadyEnabled = errors.New("двухфакторная аутентификация уже включена")
	Err2FANotEnabled     = errors.New("двухфакторная аутентификация не включена")
	
	// Ошибки сессий
	ErrSessionNotFound   = errors.New("сессия не найдена")
	ErrSessionExpired    = errors.New("сессия истекла")
	ErrSessionRevoked    = errors.New("сессия отозвана")
	
	// Ошибки Telegram
	ErrTelegramAuth      = errors.New("ошибка аутентификации через Telegram")
	ErrTelegramIDExists  = errors.New("Telegram ID уже привязан к другому аккаунту")
)

// AppError представляет ошибку приложения с дополнительной информацией
type AppError struct {
	Err        error  // Оригинальная ошибка
	Message    string // Сообщение для пользователя
	StatusCode int    // HTTP статус-код
	Code       string // Код ошибки для API
}

// Error возвращает строковое представление ошибки
func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

// Unwrap возвращает оригинальную ошибку
func (e *AppError) Unwrap() error {
	return e.Err
}

// NewAppError создает новую ошибку приложения
func NewAppError(err error, message string, statusCode int, code string) *AppError {
	return &AppError{
		Err:        err,
		Message:    message,
		StatusCode: statusCode,
		Code:       code,
	}
}

// IsNotFound проверяет, является ли ошибка ошибкой "не найдено"
func IsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound) ||
		errors.Is(err, ErrUserNotFound) ||
		errors.Is(err, ErrRoleNotFound) ||
		errors.Is(err, ErrPermissionNotFound) ||
		errors.Is(err, ErrSessionNotFound)
}

// IsForbidden проверяет, является ли ошибка ошибкой "доступ запрещен"
func IsForbidden(err error) bool {
	return errors.Is(err, ErrForbidden) ||
		errors.Is(err, ErrPermissionDenied)
}

// IsUnauthorized проверяет, является ли ошибка ошибкой "не авторизован"
func IsUnauthorized(err error) bool {
	return errors.Is(err, ErrUnauthorized) ||
		errors.Is(err, ErrInvalidCredentials) ||
		errors.Is(err, ErrInvalidToken) ||
		errors.Is(err, ErrExpiredToken) ||
		errors.Is(err, ErrRevokedToken) ||
		errors.Is(err, ErrInvalidRefreshToken)
}

// IsConflict проверяет, является ли ошибка ошибкой конфликта
func IsConflict(err error) bool {
	return errors.Is(err, ErrAlreadyExists) ||
		errors.Is(err, ErrEmailExists) ||
		errors.Is(err, ErrUsernameExists) ||
		errors.Is(err, ErrTelegramIDExists)
}

// IsBadRequest проверяет, является ли ошибка ошибкой некорректного запроса
func IsBadRequest(err error) bool {
	return errors.Is(err, ErrInvalidRequest) ||
		errors.Is(err, ErrInvalid2FACode) ||
		errors.Is(err, ErrInvalidPassword)
}
