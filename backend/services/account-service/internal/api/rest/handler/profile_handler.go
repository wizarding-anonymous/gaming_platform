// File: backend/services/account-service/internal/api/rest/handler/profile_handler.go
// account-service\internal\api\rest\handler\profile_handler.go

package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/api/presenter"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/api/rest/middleware"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/app/usecase"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/domain/entity"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/domain/errors"
)

// ProfileHandler обработчик HTTP-запросов для работы с профилями
type ProfileHandler struct {
	profileUseCase usecase.ProfileUseCase
}

// NewProfileHandler создает новый экземпляр ProfileHandler
func NewProfileHandler(profileUseCase usecase.ProfileUseCase) *ProfileHandler {
	return &ProfileHandler{
		profileUseCase: profileUseCase,
	}
}

// Register регистрирует обработчики маршрутов
func (h *ProfileHandler) Register(router *mux.Router) {
	router.HandleFunc("/profiles/{id}", h.GetProfile).Methods(http.MethodGet)
	router.HandleFunc("/profiles/by-account/{accountId}", h.GetProfileByAccountID).Methods(http.MethodGet)
	router.HandleFunc("/profiles/by-nickname/{nickname}", h.GetProfileByNickname).Methods(http.MethodGet)
	router.HandleFunc("/profiles/{id}", h.UpdateProfile).Methods(http.MethodPut)
	router.HandleFunc("/profiles", h.ListProfiles).Methods(http.MethodGet)
	router.HandleFunc("/profiles/search", h.SearchProfiles).Methods(http.MethodGet)
	router.HandleFunc("/profiles/{id}/visibility", h.UpdateProfileVisibility).Methods(http.MethodPut)
	router.HandleFunc("/profiles/{id}/avatar", h.UpdateAvatar).Methods(http.MethodPut)
	router.HandleFunc("/profiles/{id}/banner", h.UpdateBanner).Methods(http.MethodPut)
	router.HandleFunc("/profiles/{id}/history", h.GetProfileHistory).Methods(http.MethodGet)
	router.HandleFunc("/profiles/{id}/avatars", h.GetAvatars).Methods(http.MethodGet)
	router.HandleFunc("/profiles/{id}/avatars/{avatarId}", h.SetCurrentAvatar).Methods(http.MethodPut)
	router.HandleFunc("/profiles/{id}/avatars/{avatarId}", h.DeleteAvatar).Methods(http.MethodDelete)
}

// GetProfile получает профиль по ID
func (h *ProfileHandler) GetProfile(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := uuid.Parse(vars["id"])
	if err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный ID профиля", err))
		return
	}

	ctx := r.Context()
	profile, err := h.profileUseCase.GetByID(ctx, id)
	if err != nil {
		presenter.RespondWithError(w, err)
		return
	}

	presenter.RespondWithJSON(w, http.StatusOK, presenter.ToProfileResponse(profile))
}

// GetProfileByAccountID получает профиль по ID аккаунта
func (h *ProfileHandler) GetProfileByAccountID(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	accountID, err := uuid.Parse(vars["accountId"])
	if err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный ID аккаунта", err))
		return
	}

	ctx := r.Context()
	profile, err := h.profileUseCase.GetByAccountID(ctx, accountID)
	if err != nil {
		presenter.RespondWithError(w, err)
		return
	}

	presenter.RespondWithJSON(w, http.StatusOK, presenter.ToProfileResponse(profile))
}

// GetProfileByNickname получает профиль по никнейму
func (h *ProfileHandler) GetProfileByNickname(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	nickname := vars["nickname"]
	if nickname == "" {
		presenter.RespondWithError(w, errors.NewValidationError("Никнейм не может быть пустым", nil))
		return
	}

	ctx := r.Context()
	profile, err := h.profileUseCase.GetByNickname(ctx, nickname)
	if err != nil {
		presenter.RespondWithError(w, err)
		return
	}

	presenter.RespondWithJSON(w, http.StatusOK, presenter.ToProfileResponse(profile))
}

// UpdateProfile обновляет профиль
func (h *ProfileHandler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := uuid.Parse(vars["id"])
	if err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный ID профиля", err))
		return
	}

	var req presenter.UpdateProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный формат запроса", err))
		return
	}

	ctx := r.Context()
	profile, err := h.profileUseCase.GetByID(ctx, id)
	if err != nil {
		presenter.RespondWithError(w, err)
		return
	}

	// Получаем ID текущего пользователя из контекста (установлен middleware аутентификации)
	currentUserID, ok := middleware.GetUserIDFromContext(ctx)
	if !ok {
		presenter.RespondWithError(w, errors.NewAuthorizationError("Не удалось определить текущего пользователя", nil))
		return
	}

	// Обновляем поля профиля
	if req.Nickname != "" {
		profile.Nickname = req.Nickname
	}
	if req.Bio != "" {
		profile.Bio = req.Bio
	}
	if req.Country != "" {
		profile.Country = req.Country
	}
	if req.City != "" {
		profile.City = req.City
	}
	if req.BirthDate != nil {
		profile.BirthDate = req.BirthDate
	}
	if req.Gender != "" {
		profile.Gender = entity.Gender(req.Gender)
	}

	err = h.profileUseCase.Update(ctx, profile, currentUserID)
	if err != nil {
		presenter.RespondWithError(w, err)
		return
	}

	presenter.RespondWithJSON(w, http.StatusOK, presenter.ToProfileResponse(profile))
}

// ListProfiles получает список профилей с пагинацией
func (h *ProfileHandler) ListProfiles(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page <= 0 {
		page = 1
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 20
	}

	offset := (page - 1) * limit

	ctx := r.Context()
	profiles, total, err := h.profileUseCase.List(ctx, offset, limit)
	if err != nil {
		presenter.RespondWithError(w, err)
		return
	}

	response := presenter.ToProfileListResponse(profiles, total, page, limit)
	presenter.RespondWithJSON(w, http.StatusOK, response)
}

// SearchProfiles ищет профили по критериям
func (h *ProfileHandler) SearchProfiles(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		presenter.RespondWithError(w, errors.NewValidationError("Параметр поиска не может быть пустым", nil))
		return
	}

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page <= 0 {
		page = 1
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 20
	}

	offset := (page - 1) * limit

	ctx := r.Context()
	profiles, total, err := h.profileUseCase.Search(ctx, query, offset, limit)
	if err != nil {
		presenter.RespondWithError(w, err)
		return
	}

	response := presenter.ToProfileListResponse(profiles, total, page, limit)
	presenter.RespondWithJSON(w, http.StatusOK, response)
}

// UpdateProfileVisibility обновляет настройки видимости профиля
func (h *ProfileHandler) UpdateProfileVisibility(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := uuid.Parse(vars["id"])
	if err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный ID профиля", err))
		return
	}

	var req presenter.UpdateProfileVisibilityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный формат запроса", err))
		return
	}

	ctx := r.Context()
	err = h.profileUseCase.UpdateVisibility(ctx, id, entity.ProfileVisibility(req.Visibility))
	if err != nil {
		presenter.RespondWithError(w, err)
		return
	}

	presenter.RespondWithJSON(w, http.StatusOK, presenter.SuccessResponse{Success: true})
}

// UpdateAvatar обновляет аватар профиля
func (h *ProfileHandler) UpdateAvatar(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := uuid.Parse(vars["id"])
	if err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный ID профиля", err))
		return
	}

	var req presenter.UpdateAvatarRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный формат запроса", err))
		return
	}

	ctx := r.Context()
	err = h.profileUseCase.UpdateAvatar(ctx, id, req.AvatarURL)
	if err != nil {
		presenter.RespondWithError(w, err)
		return
	}

	presenter.RespondWithJSON(w, http.StatusOK, presenter.SuccessResponse{Success: true})
}

// UpdateBanner обновляет баннер профиля
func (h *ProfileHandler) UpdateBanner(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := uuid.Parse(vars["id"])
	if err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный ID профиля", err))
		return
	}

	var req presenter.UpdateBannerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный формат запроса", err))
		return
	}

	ctx := r.Context()
	err = h.profileUseCase.UpdateBanner(ctx, id, req.BannerURL)
	if err != nil {
		presenter.RespondWithError(w, err)
		return
	}

	presenter.RespondWithJSON(w, http.StatusOK, presenter.SuccessResponse{Success: true})
}

// GetProfileHistory получает историю изменений профиля
func (h *ProfileHandler) GetProfileHistory(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := uuid.Parse(vars["id"])
	if err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный ID профиля", err))
		return
	}

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page <= 0 {
		page = 1
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 20
	}

	offset := (page - 1) * limit

	fieldName := r.URL.Query().Get("field")

	ctx := r.Context()
	var history []*entity.ProfileHistory
	var total int64

	if fieldName != "" {
		history, total, err = h.profileUseCase.GetHistoryByField(ctx, id, fieldName, offset, limit)
	} else {
		history, total, err = h.profileUseCase.GetHistory(ctx, id, offset, limit)
	}

	if err != nil {
		presenter.RespondWithError(w, err)
		return
	}

	response := presenter.ToProfileHistoryListResponse(history, total, page, limit)
	presenter.RespondWithJSON(w, http.StatusOK, response)
}

// GetAvatars получает все аватары пользователя
func (h *ProfileHandler) GetAvatars(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := uuid.Parse(vars["id"])
	if err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный ID профиля", err))
		return
	}

	ctx := r.Context()
	profile, err := h.profileUseCase.GetByID(ctx, id)
	if err != nil {
		presenter.RespondWithError(w, err)
		return
	}

	avatars, err := h.profileUseCase.GetAvatars(ctx, profile.AccountID)
	if err != nil {
		presenter.RespondWithError(w, err)
		return
	}

	presenter.RespondWithJSON(w, http.StatusOK, presenter.ToAvatarListResponse(avatars))
}

// SetCurrentAvatar устанавливает аватар как текущий
func (h *ProfileHandler) SetCurrentAvatar(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := uuid.Parse(vars["id"])
	if err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный ID профиля", err))
		return
	}

	avatarID, err := uuid.Parse(vars["avatarId"])
	if err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный ID аватара", err))
		return
	}

	ctx := r.Context()
	profile, err := h.profileUseCase.GetByID(ctx, id)
	if err != nil {
		presenter.RespondWithError(w, err)
		return
	}

	err = h.profileUseCase.SetCurrentAvatar(ctx, profile.AccountID, avatarID)
	if err != nil {
		presenter.RespondWithError(w, err)
		return
	}

	presenter.RespondWithJSON(w, http.StatusOK, presenter.SuccessResponse{Success: true})
}

// DeleteAvatar удаляет аватар
func (h *ProfileHandler) DeleteAvatar(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := uuid.Parse(vars["id"])
	if err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный ID профиля", err))
		return
	}

	avatarID, err := uuid.Parse(vars["avatarId"])
	if err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный ID аватара", err))
		return
	}

	ctx := r.Context()
	profile, err := h.profileUseCase.GetByID(ctx, id)
	if err != nil {
		presenter.RespondWithError(w, err)
		return
	}

	err = h.profileUseCase.DeleteAvatar(ctx, profile.AccountID, avatarID)
	if err != nil {
		presenter.RespondWithError(w, err)
		return
	}

	presenter.RespondWithJSON(w, http.StatusOK, presenter.SuccessResponse{Success: true})
}
