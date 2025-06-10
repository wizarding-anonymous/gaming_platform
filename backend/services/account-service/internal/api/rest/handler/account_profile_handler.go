// File: backend/services/account-service/internal/api/rest/handler/account_profile_handler.go

package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/api/rest/middleware"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/api/rest/presenter"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/domain/errors"
)

// GetCurrentProfile получает профиль текущего пользователя
func (h *AccountHandler) GetCurrentProfile(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserIDFromContext(r.Context())
	if userID == uuid.Nil {
		presenter.RespondWithError(w, errors.NewUnauthorizedError("Пользователь не аутентифицирован"))
		return
	}

	ctx := r.Context()
	profile, err := h.accountUseCase.GetProfileByAccountID(ctx, userID)
	if err != nil {
		presenter.RespondWithError(w, err)
		return
	}

	presenter.RespondWithJSON(w, http.StatusOK, presenter.ToProfileResponse(profile))
}
func (h *AccountHandler) GetProfile(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := uuid.Parse(vars["id"])
	if err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный ID аккаунта", err))
		return
	}

	ctx := r.Context()
	profile, err := h.accountUseCase.GetProfileByAccountID(ctx, id)
	if err != nil {
		presenter.RespondWithError(w, err)
		return
	}

	// Проверка прав доступа и видимости профиля
	userID := middleware.GetUserIDFromContext(r.Context())
	isOwner := userID == id
	isAdmin := middleware.IsAdmin(r.Context())

	if !isOwner && !isAdmin && profile.Visibility == "private" {
		presenter.RespondWithError(w, errors.NewForbiddenError("Профиль пользователя приватный"))
		return
	}

	presenter.RespondWithJSON(w, http.StatusOK, presenter.ToProfileResponse(profile))
}

// UpdateProfile обновляет профиль пользователя
func (h *AccountHandler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := uuid.Parse(vars["id"])
	if err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный ID аккаунта", err))
		return
	}

	// Проверка прав доступа
	userID := middleware.GetUserIDFromContext(r.Context())
	if userID != id && !middleware.IsAdmin(r.Context()) {
		presenter.RespondWithError(w, errors.NewForbiddenError("Недостаточно прав для обновления профиля"))
		return
	}

	var req presenter.UpdateProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный формат запроса", err))
		return
	}

	ctx := r.Context()
	profile, err := h.accountUseCase.UpdateProfile(ctx, id, req.Nickname, req.Bio, req.Country, req.City, req.BirthDate, req.Gender, req.Visibility)
	if err != nil {
		presenter.RespondWithError(w, err)
		return
	}

	presenter.RespondWithJSON(w, http.StatusOK, presenter.ToProfileResponse(profile))
}

// GetProfileHistory получает историю изменений профиля
func (h *AccountHandler) GetProfileHistory(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := uuid.Parse(vars["id"])
	if err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный ID аккаунта", err))
		return
	}

	// Проверка прав доступа
	userID := middleware.GetUserIDFromContext(r.Context())
	if userID != id && !middleware.IsAdmin(r.Context()) {
		presenter.RespondWithError(w, errors.NewForbiddenError("Недостаточно прав для просмотра истории профиля"))
		return
	}

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page <= 0 {
		page = 1
	}

	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if perPage <= 0 || perPage > 100 {
		perPage = 20
	}

	offset := (page - 1) * perPage

	ctx := r.Context()
	history, total, err := h.accountUseCase.GetProfileHistory(ctx, id, offset, perPage)
	if err != nil {
		presenter.RespondWithError(w, err)
		return
	}

	response := presenter.ToProfileHistoryListResponse(history, total, page, perPage)
	presenter.RespondWithJSON(w, http.StatusOK, response)
}

// GetAvatars получает список аватаров пользователя
func (h *AccountHandler) GetAvatars(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := uuid.Parse(vars["id"])
	if err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный ID аккаунта", err))
		return
	}

	// Проверка прав доступа
	userID := middleware.GetUserIDFromContext(r.Context())
	if userID != id && !middleware.IsAdmin(r.Context()) {
		presenter.RespondWithError(w, errors.NewForbiddenError("Недостаточно прав для просмотра аватаров"))
		return
	}

	ctx := r.Context()
	avatars, err := h.accountUseCase.GetAvatars(ctx, id)
	if err != nil {
		presenter.RespondWithError(w, err)
		return
	}

	presenter.RespondWithJSON(w, http.StatusOK, presenter.ToAvatarListResponse(avatars))
}

// UploadAvatar загружает новый аватар
func (h *AccountHandler) UploadAvatar(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := uuid.Parse(vars["id"])
	if err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный ID аккаунта", err))
		return
	}

	// Проверка прав доступа
	userID := middleware.GetUserIDFromContext(r.Context())
	if userID != id && !middleware.IsAdmin(r.Context()) {
		presenter.RespondWithError(w, errors.NewForbiddenError("Недостаточно прав для загрузки аватара"))
		return
	}

	// Максимальный размер файла - 5 МБ
	r.ParseMultipartForm(5 << 20)
	file, handler, err := r.FormFile("avatar")
	if err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Ошибка при получении файла", err))
		return
	}
	defer file.Close()

	ctx := r.Context()
	avatar, err := h.accountUseCase.UploadAvatar(ctx, id, file, handler.Filename, handler.Header.Get("Content-Type"))
	if err != nil {
		presenter.RespondWithError(w, err)
		return
	}

	presenter.RespondWithJSON(w, http.StatusCreated, presenter.ToAvatarResponse(avatar))
}

// SetCurrentAvatar устанавливает текущий аватар
func (h *AccountHandler) SetCurrentAvatar(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := uuid.Parse(vars["id"])
	if err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный ID аккаунта", err))
		return
	}

	avatarID, err := uuid.Parse(vars["avatar_id"])
	if err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный ID аватара", err))
		return
	}

	// Проверка прав доступа
	userID := middleware.GetUserIDFromContext(r.Context())
	if userID != id && !middleware.IsAdmin(r.Context()) {
		presenter.RespondWithError(w, errors.NewForbiddenError("Недостаточно прав для установки аватара"))
		return
	}

	ctx := r.Context()
	avatar, err := h.accountUseCase.SetCurrentAvatar(ctx, id, avatarID)
	if err != nil {
		presenter.RespondWithError(w, err)
		return
	}

	presenter.RespondWithJSON(w, http.StatusOK, presenter.ToAvatarResponse(avatar))
}

// DeleteAvatar удаляет аватар
func (h *AccountHandler) DeleteAvatar(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := uuid.Parse(vars["id"])
	if err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный ID аккаунта", err))
		return
	}

	avatarID, err := uuid.Parse(vars["avatar_id"])
	if err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный ID аватара", err))
		return
	}

	// Проверка прав доступа
	userID := middleware.GetUserIDFromContext(r.Context())
	if userID != id && !middleware.IsAdmin(r.Context()) {
		presenter.RespondWithError(w, errors.NewForbiddenError("Недостаточно прав для удаления аватара"))
		return
	}

	ctx := r.Context()
	err = h.accountUseCase.DeleteAvatar(ctx, id, avatarID)
	if err != nil {
		presenter.RespondWithError(w, err)
		return
	}

	presenter.RespondWithJSON(w, http.StatusOK, presenter.SuccessResponse{Success: true})
}
