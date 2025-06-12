// File: backend/services/account-service/internal/api/rest/handler/account_create_handler.go

package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/api/presenter"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/api/rest/middleware"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/domain/entity"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/domain/errors"
)

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
