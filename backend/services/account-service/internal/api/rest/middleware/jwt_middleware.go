// File: backend/services/account-service/internal/api/rest/middleware/jwt_middleware.go
// account-service/internal/api/rest/middleware/jwt_middleware.go

package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/domain/errors"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/infrastructure/client/auth"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/pkg/logger"
)

type contextKey string

const (
	// UserIDKey ключ для ID пользователя в контексте
	UserIDKey contextKey = "user_id"
	// UserRolesKey ключ для ролей пользователя в контексте
	UserRolesKey contextKey = "user_roles"
)

// JWTAuth middleware для проверки JWT токена
func JWTAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Получаем токен из заголовка Authorization
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			respondWithError(w, errors.NewUnauthorizedError("Отсутствует заголовок Authorization"))
			return
		}

		// Проверяем формат токена (Bearer <token>)
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			respondWithError(w, errors.NewUnauthorizedError("Неверный формат токена"))
			return
		}

		token := parts[1]

		// Валидируем токен через Auth Service
		authClient := auth.GetAuthClient()
		claims, err := authClient.ValidateToken(r.Context(), token)
		if err != nil {
			respondWithError(w, errors.NewUnauthorizedError("Недействительный токен: "+err.Error()))
			return
		}

		// Парсим ID пользователя из claims
		userID, err := uuid.Parse(claims.Subject)
		if err != nil {
			respondWithError(w, errors.NewUnauthorizedError("Некорректный ID пользователя в токене"))
			return
		}

		// Добавляем ID пользователя и роли в контекст запроса
		ctx := context.WithValue(r.Context(), UserIDKey, userID)
		ctx = context.WithValue(ctx, UserRolesKey, claims.Roles)

		// Передаем управление следующему обработчику с обновленным контекстом
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// AdminOnly middleware для проверки роли администратора
func AdminOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Проверяем, есть ли у пользователя роль admin
		if !IsAdmin(r.Context()) {
			respondWithError(w, errors.NewForbiddenError("Требуются права администратора"))
			return
		}

		// Передаем управление следующему обработчику
		next.ServeHTTP(w, r)
	})
}

// RoleRequired middleware для проверки наличия определенной роли
func RoleRequired(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Проверяем, есть ли у пользователя требуемая роль
			if !HasRole(r.Context(), role) {
				respondWithError(w, errors.NewForbiddenError("Недостаточно прав"))
				return
			}

			// Передаем управление следующему обработчику
			next.ServeHTTP(w, r)
		})
	}
}

// PermissionRequired middleware для проверки наличия определенного разрешения
func PermissionRequired(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Получаем роли пользователя из контекста
			roles, ok := r.Context().Value(UserRolesKey).([]string)
			if !ok {
				respondWithError(w, errors.NewUnauthorizedError("Не удалось получить роли пользователя"))
				return
			}

			// Проверяем разрешение через Auth Service
			authClient := auth.GetAuthClient()
			hasPermission, err := authClient.CheckPermission(r.Context(), roles, permission)
			if err != nil {
				logger.Error("Ошибка при проверке разрешения", "error", err)
				respondWithError(w, errors.NewInternalError("Ошибка при проверке разрешения"))
				return
			}

			if !hasPermission {
				respondWithError(w, errors.NewForbiddenError("Недостаточно прав"))
				return
			}

			// Передаем управление следующему обработчику
			next.ServeHTTP(w, r)
		})
	}
}

// GetUserIDFromContext получает ID пользователя из контекста
func GetUserIDFromContext(ctx context.Context) uuid.UUID {
	userID, ok := ctx.Value(UserIDKey).(uuid.UUID)
	if !ok {
		return uuid.Nil
	}
	return userID
}

// GetUserRolesFromContext получает роли пользователя из контекста
func GetUserRolesFromContext(ctx context.Context) []string {
	roles, ok := ctx.Value(UserRolesKey).([]string)
	if !ok {
		return []string{}
	}
	return roles
}

// IsAdmin проверяет, является ли пользователь администратором
func IsAdmin(ctx context.Context) bool {
	return HasRole(ctx, "admin")
}

// HasRole проверяет, имеет ли пользователь определенную роль
func HasRole(ctx context.Context, role string) bool {
	roles := GetUserRolesFromContext(ctx)
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}

// GetUserIDFromRequest получает ID пользователя из запроса
func GetUserIDFromRequest(r *http.Request) (uuid.UUID, error) {
	userID := GetUserIDFromContext(r.Context())
	if userID == uuid.Nil {
		return uuid.Nil, errors.NewUnauthorizedError("Пользователь не аутентифицирован")
	}
	return userID, nil
}

// GetUserRolesFromRequest получает роли пользователя из запроса
func GetUserRolesFromRequest(r *http.Request) []string {
	return GetUserRolesFromContext(r.Context())
}

// respondWithError отправляет ошибку в ответе
func respondWithError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")

	var statusCode int
	switch err.(type) {
	case *errors.ValidationError:
		statusCode = http.StatusBadRequest
	case *errors.UnauthorizedError:
		statusCode = http.StatusUnauthorized
	case *errors.ForbiddenError:
		statusCode = http.StatusForbidden
	case *errors.NotFoundError:
		statusCode = http.StatusNotFound
	case *errors.ConflictError:
		statusCode = http.StatusConflict
	default:
		statusCode = http.StatusInternalServerError
	}

	w.WriteHeader(statusCode)
	w.Write([]byte(`{"status":"error","error":{"message":"` + err.Error() + `"}}`))
}
