// File: backend/services/account-service/internal/api/rest/handler/account_handler.go
// account-service/internal/api/rest/handler/account_handler.go

package handler

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/api/rest/middleware"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/api/rest/presenter"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/app/usecase"
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
