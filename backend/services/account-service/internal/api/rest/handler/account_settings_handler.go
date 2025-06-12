// File: backend/services/account-service/internal/api/rest/handler/account_settings_handler.go

package handler

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/api/presenter"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/api/rest/middleware"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/domain/errors"
)

// GetAllSettings получает все настройки пользователя
func (h *AccountHandler) GetAllSettings(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := uuid.Parse(vars["id"])
	if err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный ID аккаунта", err))
		return
	}

	// Проверка прав доступа
	userID := middleware.GetUserIDFromContext(r.Context())
	if userID != id && !middleware.IsAdmin(r.Context()) {
		presenter.RespondWithError(w, errors.NewForbiddenError("Недостаточно прав для просмотра настроек"))
		return
	}

	ctx := r.Context()
	settings, err := h.accountUseCase.GetAllSettings(ctx, id)
	if err != nil {
		presenter.RespondWithError(w, err)
		return
	}

	presenter.RespondWithJSON(w, http.StatusOK, presenter.ToSettingsMapResponse(settings))
}

// GetSettings получает настройки определенной категории
func (h *AccountHandler) GetSettings(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := uuid.Parse(vars["id"])
	if err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный ID аккаунта", err))
		return
	}

	category := vars["category"]
	if category == "" {
		presenter.RespondWithError(w, errors.NewValidationError("Категория настроек не указана", nil))
		return
	}

	// Проверка прав доступа
	userID := middleware.GetUserIDFromContext(r.Context())
	if userID != id && !middleware.IsAdmin(r.Context()) {
		presenter.RespondWithError(w, errors.NewForbiddenError("Недостаточно прав для просмотра настроек"))
		return
	}

	ctx := r.Context()
	setting, err := h.accountUseCase.GetSettings(ctx, id, category)
	if err != nil {
		presenter.RespondWithError(w, err)
		return
	}

	presenter.RespondWithJSON(w, http.StatusOK, presenter.ToSettingResponse(setting))
}

// UpdateSettings обновляет настройки определенной категории
func (h *AccountHandler) UpdateSettings(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := uuid.Parse(vars["id"])
	if err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный ID аккаунта", err))
		return
	}

	category := vars["category"]
	if category == "" {
		presenter.RespondWithError(w, errors.NewValidationError("Категория настроек не указана", nil))
		return
	}

	// Проверка прав доступа
	userID := middleware.GetUserIDFromContext(r.Context())
	if userID != id && !middleware.IsAdmin(r.Context()) {
		presenter.RespondWithError(w, errors.NewForbiddenError("Недостаточно прав для обновления настроек"))
		return
	}

	var req presenter.UpdateSettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный формат запроса", err))
		return
	}

	ctx := r.Context()
	setting, err := h.accountUseCase.UpdateSettings(ctx, id, category, req.Settings)
	if err != nil {
		presenter.RespondWithError(w, err)
		return
	}

	presenter.RespondWithJSON(w, http.StatusOK, presenter.ToSettingResponse(setting))
}
