// File: backend/services/account-service/internal/api/rest/handler/account_handler.go
// account-service/internal/api/rest/handler/account_handler.go

package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/api/rest/middleware"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/api/rest/presenter"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/app/usecase"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/domain/entity"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/domain/errors"
)

// AccountHandler обработчик HTTP-запросов для работы с аккаунтами
type AccountHandler struct {
	accountUseCase usecase.AccountUseCase
}

// NewAccountHandler создает новый экземпляр AccountHandler
func NewAccountHandler(accountUseCase usecase.AccountUseCase) *AccountHandler {
	return &AccountHandler{
		accountUseCase: accountUseCase,
	}
}

// Register регистрирует обработчики маршрутов
func (h *AccountHandler) Register(router *mux.Router) {
	// Публичные эндпоинты
	router.HandleFunc("/accounts", h.CreateAccount).Methods(http.MethodPost)

	// Защищенные эндпоинты (требуют аутентификации)
	protected := router.PathPrefix("").Subrouter()
	protected.Use(middleware.JWTAuth)

	// Эндпоинты для всех аутентифицированных пользователей
	protected.HandleFunc("/accounts/{id}", h.GetAccount).Methods(http.MethodGet)
	protected.HandleFunc("/accounts/me", h.GetCurrentAccount).Methods(http.MethodGet)
	protected.HandleFunc("/accounts/me/profile", h.GetCurrentProfile).Methods(http.MethodGet)

	// Эндпоинты для владельцев аккаунтов или администраторов
	protected.HandleFunc("/accounts/{id}", h.UpdateAccount).Methods(http.MethodPut)
	protected.HandleFunc("/accounts/{id}", h.DeleteAccount).Methods(http.MethodDelete)
	protected.HandleFunc("/accounts/{id}/status", h.UpdateAccountStatus).Methods(http.MethodPut)

	// Эндпоинты для работы с контактной информацией
	protected.HandleFunc("/accounts/{id}/contact-info", h.GetContactInfo).Methods(http.MethodGet)
	protected.HandleFunc("/accounts/{id}/contact-info", h.AddContactInfo).Methods(http.MethodPost)
	protected.HandleFunc("/accounts/{id}/contact-info/{contact_id}", h.UpdateContactInfo).Methods(http.MethodPut)
	protected.HandleFunc("/accounts/{id}/contact-info/{contact_id}", h.DeleteContactInfo).Methods(http.MethodDelete)
	protected.HandleFunc("/accounts/{id}/contact-info/{type}/verification-request", h.RequestContactVerification).Methods(http.MethodPost)
	protected.HandleFunc("/accounts/{id}/contact-info/{type}/verify", h.VerifyContact).Methods(http.MethodPost)

	// Эндпоинты для работы с профилем
	protected.HandleFunc("/accounts/{id}/profile", h.GetProfile).Methods(http.MethodGet)
	protected.HandleFunc("/accounts/{id}/profile", h.UpdateProfile).Methods(http.MethodPut)
	protected.HandleFunc("/accounts/{id}/profile/history", h.GetProfileHistory).Methods(http.MethodGet)

	// Эндпоинты для работы с аватарами
	protected.HandleFunc("/accounts/{id}/avatar", h.GetAvatars).Methods(http.MethodGet)
	protected.HandleFunc("/accounts/{id}/avatar", h.UploadAvatar).Methods(http.MethodPost)
	protected.HandleFunc("/accounts/{id}/avatar/{avatar_id}", h.SetCurrentAvatar).Methods(http.MethodPut)
	protected.HandleFunc("/accounts/{id}/avatar/{avatar_id}", h.DeleteAvatar).Methods(http.MethodDelete)

	// Эндпоинты для работы с настройками
	protected.HandleFunc("/accounts/{id}/settings", h.GetAllSettings).Methods(http.MethodGet)
	protected.HandleFunc("/accounts/{id}/settings/{category}", h.GetSettings).Methods(http.MethodGet)
	protected.HandleFunc("/accounts/{id}/settings/{category}", h.UpdateSettings).Methods(http.MethodPut)

	// Эндпоинты только для администраторов
	admin := router.PathPrefix("").Subrouter()
	admin.Use(middleware.JWTAuth, middleware.AdminOnly)
	admin.HandleFunc("/accounts", h.ListAccounts).Methods(http.MethodGet)
}

// CreateAccount создает новый аккаунт
func (h *AccountHandler) CreateAccount(w http.ResponseWriter, r *http.Request) {
	var req presenter.CreateAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный формат запроса", err))
		return
	}

	ctx := r.Context()
	account, err := h.accountUseCase.Create(ctx, req.Username, req.Email, req.Password)
	if err != nil {
		presenter.RespondWithError(w, err)
		return
	}

	presenter.RespondWithJSON(w, http.StatusCreated, presenter.ToAccountResponse(account))
}

// GetAccount получает аккаунт по ID
func (h *AccountHandler) GetAccount(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := uuid.Parse(vars["id"])
	if err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный ID аккаунта", err))
		return
	}

	// Проверка прав доступа
	userID := middleware.GetUserIDFromContext(r.Context())
	if userID != id && !middleware.IsAdmin(r.Context()) {
		presenter.RespondWithError(w, errors.NewForbiddenError("Недостаточно прав для просмотра этого аккаунта"))
		return
	}

	ctx := r.Context()
	account, err := h.accountUseCase.GetByID(ctx, id)
	if err != nil {
		presenter.RespondWithError(w, err)
		return
	}

	presenter.RespondWithJSON(w, http.StatusOK, presenter.ToAccountResponse(account))
}

// GetCurrentAccount получает текущий аккаунт пользователя
func (h *AccountHandler) GetCurrentAccount(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserIDFromContext(r.Context())
	if userID == uuid.Nil {
		presenter.RespondWithError(w, errors.NewUnauthorizedError("Пользователь не аутентифицирован"))
		return
	}

	ctx := r.Context()
	account, err := h.accountUseCase.GetByID(ctx, userID)
	if err != nil {
		presenter.RespondWithError(w, err)
		return
	}

	presenter.RespondWithJSON(w, http.StatusOK, presenter.ToAccountResponse(account))
}

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

// UpdateAccount обновляет аккаунт
func (h *AccountHandler) UpdateAccount(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := uuid.Parse(vars["id"])
	if err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный ID аккаунта", err))
		return
	}

	// Проверка прав доступа
	userID := middleware.GetUserIDFromContext(r.Context())
	if userID != id && !middleware.IsAdmin(r.Context()) {
		presenter.RespondWithError(w, errors.NewForbiddenError("Недостаточно прав для обновления этого аккаунта"))
		return
	}

	var req presenter.UpdateAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный формат запроса", err))
		return
	}

	ctx := r.Context()
	account, err := h.accountUseCase.GetByID(ctx, id)
	if err != nil {
		presenter.RespondWithError(w, err)
		return
	}

	if req.Username != "" {
		account.Username = req.Username
	}

	err = h.accountUseCase.Update(ctx, account)
	if err != nil {
		presenter.RespondWithError(w, err)
		return
	}

	presenter.RespondWithJSON(w, http.StatusOK, presenter.ToAccountResponse(account))
}

// UpdateAccountStatus обновляет статус аккаунта (блокировка/разблокировка)
func (h *AccountHandler) UpdateAccountStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := uuid.Parse(vars["id"])
	if err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный ID аккаунта", err))
		return
	}

	// Проверка прав доступа (только админ)
	if !middleware.IsAdmin(r.Context()) {
		presenter.RespondWithError(w, errors.NewForbiddenError("Недостаточно прав для изменения статуса аккаунта"))
		return
	}

	var req presenter.UpdateAccountStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный формат запроса", err))
		return
	}

	ctx := r.Context()
	var updateErr error

	switch entity.AccountStatus(req.Status) {
	case entity.AccountStatusActive:
		updateErr = h.accountUseCase.Activate(ctx, id)
	case entity.AccountStatusBlocked:
		updateErr = h.accountUseCase.Block(ctx, id, req.Reason)
	default:
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный статус аккаунта", nil))
		return
	}

	if updateErr != nil {
		presenter.RespondWithError(w, updateErr)
		return
	}

	account, err := h.accountUseCase.GetByID(ctx, id)
	if err != nil {
		presenter.RespondWithError(w, err)
		return
	}

	presenter.RespondWithJSON(w, http.StatusOK, presenter.ToAccountResponse(account))
}

// DeleteAccount удаляет аккаунт (soft delete)
func (h *AccountHandler) DeleteAccount(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := uuid.Parse(vars["id"])
	if err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный ID аккаунта", err))
		return
	}

	// Проверка прав доступа
	userID := middleware.GetUserIDFromContext(r.Context())
	if userID != id && !middleware.IsAdmin(r.Context()) {
		presenter.RespondWithError(w, errors.NewForbiddenError("Недостаточно прав для удаления этого аккаунта"))
		return
	}

	ctx := r.Context()
	err = h.accountUseCase.Delete(ctx, id)
	if err != nil {
		presenter.RespondWithError(w, err)
		return
	}

	presenter.RespondWithJSON(w, http.StatusOK, presenter.SuccessResponse{Success: true})
}

// ListAccounts получает список аккаунтов с пагинацией (только для админов)
func (h *AccountHandler) ListAccounts(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page <= 0 {
		page = 1
	}

	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if perPage <= 0 || perPage > 100 {
		perPage = 20
	}

	offset := (page - 1) * perPage

	// Фильтры
	username := r.URL.Query().Get("username")
	email := r.URL.Query().Get("email")
	status := r.URL.Query().Get("status")

	ctx := r.Context()
	accounts, total, err := h.accountUseCase.Search(ctx, username, email, status, offset, perPage)
	if err != nil {
		presenter.RespondWithError(w, err)
		return
	}

	response := presenter.ToAccountListResponse(accounts, total, page, perPage)
	presenter.RespondWithJSON(w, http.StatusOK, response)
}

// GetContactInfo получает контактную информацию аккаунта
func (h *AccountHandler) GetContactInfo(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := uuid.Parse(vars["id"])
	if err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный ID аккаунта", err))
		return
	}

	// Проверка прав доступа
	userID := middleware.GetUserIDFromContext(r.Context())
	if userID != id && !middleware.IsAdmin(r.Context()) {
		presenter.RespondWithError(w, errors.NewForbiddenError("Недостаточно прав для просмотра контактной информации"))
		return
	}

	ctx := r.Context()
	contacts, err := h.accountUseCase.GetContactInfo(ctx, id)
	if err != nil {
		presenter.RespondWithError(w, err)
		return
	}

	presenter.RespondWithJSON(w, http.StatusOK, presenter.ToContactInfoListResponse(contacts))
}

// AddContactInfo добавляет новую контактную информацию
func (h *AccountHandler) AddContactInfo(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := uuid.Parse(vars["id"])
	if err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный ID аккаунта", err))
		return
	}

	// Проверка прав доступа
	userID := middleware.GetUserIDFromContext(r.Context())
	if userID != id && !middleware.IsAdmin(r.Context()) {
		presenter.RespondWithError(w, errors.NewForbiddenError("Недостаточно прав для добавления контактной информации"))
		return
	}

	var req presenter.AddContactInfoRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный формат запроса", err))
		return
	}

	ctx := r.Context()
	contact, err := h.accountUseCase.AddContactInfo(ctx, id, req.Type, req.Value, req.Visibility)
	if err != nil {
		presenter.RespondWithError(w, err)
		return
	}

	presenter.RespondWithJSON(w, http.StatusCreated, presenter.ToContactInfoResponse(contact))
}

// UpdateContactInfo обновляет контактную информацию
func (h *AccountHandler) UpdateContactInfo(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := uuid.Parse(vars["id"])
	if err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный ID аккаунта", err))
		return
	}

	contactID, err := uuid.Parse(vars["contact_id"])
	if err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный ID контактной информации", err))
		return
	}

	// Проверка прав доступа
	userID := middleware.GetUserIDFromContext(r.Context())
	if userID != id && !middleware.IsAdmin(r.Context()) {
		presenter.RespondWithError(w, errors.NewForbiddenError("Недостаточно прав для обновления контактной информации"))
		return
	}

	var req presenter.UpdateContactInfoRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный формат запроса", err))
		return
	}

	ctx := r.Context()
	contact, err := h.accountUseCase.UpdateContactInfo(ctx, id, contactID, req.Value, req.Visibility, req.IsPrimary)
	if err != nil {
		presenter.RespondWithError(w, err)
		return
	}

	presenter.RespondWithJSON(w, http.StatusOK, presenter.ToContactInfoResponse(contact))
}

// DeleteContactInfo удаляет контактную информацию
func (h *AccountHandler) DeleteContactInfo(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := uuid.Parse(vars["id"])
	if err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный ID аккаунта", err))
		return
	}

	contactID, err := uuid.Parse(vars["contact_id"])
	if err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный ID контактной информации", err))
		return
	}

	// Проверка прав доступа
	userID := middleware.GetUserIDFromContext(r.Context())
	if userID != id && !middleware.IsAdmin(r.Context()) {
		presenter.RespondWithError(w, errors.NewForbiddenError("Недостаточно прав для удаления контактной информации"))
		return
	}

	ctx := r.Context()
	err = h.accountUseCase.DeleteContactInfo(ctx, id, contactID)
	if err != nil {
		presenter.RespondWithError(w, err)
		return
	}

	presenter.RespondWithJSON(w, http.StatusOK, presenter.SuccessResponse{Success: true})
}

// RequestContactVerification запрашивает верификацию контактной информации
func (h *AccountHandler) RequestContactVerification(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := uuid.Parse(vars["id"])
	if err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный ID аккаунта", err))
		return
	}

	contactType := vars["type"]
	if contactType != "email" && contactType != "phone" {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный тип контактной информации", nil))
		return
	}

	// Проверка прав доступа
	userID := middleware.GetUserIDFromContext(r.Context())
	if userID != id && !middleware.IsAdmin(r.Context()) {
		presenter.RespondWithError(w, errors.NewForbiddenError("Недостаточно прав для запроса верификации"))
		return
	}

	ctx := r.Context()
	expiresAt, err := h.accountUseCase.RequestContactVerification(ctx, id, contactType)
	if err != nil {
		presenter.RespondWithError(w, err)
		return
	}

	presenter.RespondWithJSON(w, http.StatusOK, presenter.VerificationRequestResponse{
		Message:   "Код верификации отправлен",
		ExpiresAt: expiresAt,
	})
}

// VerifyContact подтверждает контактную информацию
func (h *AccountHandler) VerifyContact(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := uuid.Parse(vars["id"])
	if err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный ID аккаунта", err))
		return
	}

	contactType := vars["type"]
	if contactType != "email" && contactType != "phone" {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный тип контактной информации", nil))
		return
	}

	// Проверка прав доступа
	userID := middleware.GetUserIDFromContext(r.Context())
	if userID != id && !middleware.IsAdmin(r.Context()) {
		presenter.RespondWithError(w, errors.NewForbiddenError("Недостаточно прав для подтверждения верификации"))
		return
	}

	var req presenter.VerifyContactRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		presenter.RespondWithError(w, errors.NewValidationError("Некорректный формат запроса", err))
		return
	}

	ctx := r.Context()
	err = h.accountUseCase.VerifyContact(ctx, id, contactType, req.Code)
	if err != nil {
		presenter.RespondWithError(w, err)
		return
	}

	presenter.RespondWithJSON(w, http.StatusOK, presenter.SuccessResponse{
		Success: true,
		Message: "Контактная информация успешно подтверждена",
	})
}

// GetProfile получает профиль пользователя
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
