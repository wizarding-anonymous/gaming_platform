// File: backend/services/account-service/tests/unit/account_usecase_test.go
// account-service\tests\unit\account_usecase_test.go

package usecase_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"github.com/gaiming/account-service/internal/app/usecase"
	"github.com/gaiming/account-service/internal/domain/entity"
	"github.com/gaiming/account-service/internal/domain/repository"
)

// Мок для репозитория аккаунтов
type MockAccountRepository struct {
	mock.Mock
}

func (m *MockAccountRepository) GetByID(ctx context.Context, id string) (*entity.Account, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.Account), args.Error(1)
}

func (m *MockAccountRepository) GetByUsername(ctx context.Context, username string) (*entity.Account, error) {
	args := m.Called(ctx, username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.Account), args.Error(1)
}

func (m *MockAccountRepository) GetByEmail(ctx context.Context, email string) (*entity.Account, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.Account), args.Error(1)
}

func (m *MockAccountRepository) List(ctx context.Context, page, limit int, status string) ([]*entity.Account, int, error) {
	args := m.Called(ctx, page, limit, status)
	return args.Get(0).([]*entity.Account), args.Int(1), args.Error(2)
}

func (m *MockAccountRepository) Create(ctx context.Context, account *entity.Account) (*entity.Account, error) {
	args := m.Called(ctx, account)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.Account), args.Error(1)
}

func (m *MockAccountRepository) Update(ctx context.Context, account *entity.Account) (*entity.Account, error) {
	args := m.Called(ctx, account)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.Account), args.Error(1)
}

func (m *MockAccountRepository) Delete(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

// Мок для репозитория методов аутентификации
type MockAuthMethodRepository struct {
	mock.Mock
}

func (m *MockAuthMethodRepository) GetByAccountID(ctx context.Context, accountID string) ([]*entity.AuthMethod, error) {
	args := m.Called(ctx, accountID)
	return args.Get(0).([]*entity.AuthMethod), args.Error(1)
}

func (m *MockAuthMethodRepository) Create(ctx context.Context, authMethod *entity.AuthMethod) (*entity.AuthMethod, error) {
	args := m.Called(ctx, authMethod)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.AuthMethod), args.Error(1)
}

func (m *MockAuthMethodRepository) Update(ctx context.Context, authMethod *entity.AuthMethod) (*entity.AuthMethod, error) {
	args := m.Called(ctx, authMethod)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.AuthMethod), args.Error(1)
}

func (m *MockAuthMethodRepository) Delete(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

// Мок для репозитория профилей
type MockProfileRepository struct {
	mock.Mock
}

func (m *MockProfileRepository) GetByID(ctx context.Context, id string) (*entity.Profile, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.Profile), args.Error(1)
}

func (m *MockProfileRepository) GetByAccountID(ctx context.Context, accountID string) (*entity.Profile, error) {
	args := m.Called(ctx, accountID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.Profile), args.Error(1)
}

func (m *MockProfileRepository) Create(ctx context.Context, profile *entity.Profile) (*entity.Profile, error) {
	args := m.Called(ctx, profile)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.Profile), args.Error(1)
}

func (m *MockProfileRepository) Update(ctx context.Context, profile *entity.Profile) (*entity.Profile, error) {
	args := m.Called(ctx, profile)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.Profile), args.Error(1)
}

// Мок для кэша аккаунтов
type MockAccountCache struct {
	mock.Mock
}

func (m *MockAccountCache) Get(ctx context.Context, id string) (*entity.Account, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.Account), args.Error(1)
}

func (m *MockAccountCache) Set(ctx context.Context, account *entity.Account) error {
	args := m.Called(ctx, account)
	return args.Error(0)
}

func (m *MockAccountCache) Delete(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

// Мок для Kafka продюсера
type MockKafkaProducer struct {
	mock.Mock
}

func (m *MockKafkaProducer) Produce(topic string, key string, value interface{}) error {
	args := m.Called(topic, key, value)
	return args.Error(0)
}

func (m *MockKafkaProducer) Close() error {
	args := m.Called()
	return args.Error(0)
}

// Тесты для AccountUseCase
func TestAccountUseCase_GetAccount(t *testing.T) {
	// Arrange
	mockAccountRepo := new(MockAccountRepository)
	mockAuthMethodRepo := new(MockAuthMethodRepository)
	mockProfileRepo := new(MockProfileRepository)
	mockAccountCache := new(MockAccountCache)
	mockKafkaProducer := new(MockKafkaProducer)
	logger := zaptest.NewLogger(t).Sugar()

	useCase := usecase.NewAccountUseCase(
		mockAccountRepo,
		mockAuthMethodRepo,
		mockProfileRepo,
		mockAccountCache,
		mockKafkaProducer,
		logger,
	)

	ctx := context.Background()
	accountID := "test-account-id"
	expectedAccount := &entity.Account{
		ID:        accountID,
		Username:  "testuser",
		Email:     "test@example.com",
		Status:    entity.AccountStatusActive,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Настройка мока кэша - кэш пуст
	mockAccountCache.On("Get", ctx, accountID).Return(nil, errors.New("not found in cache"))
	
	// Настройка мока репозитория
	mockAccountRepo.On("GetByID", ctx, accountID).Return(expectedAccount, nil)
	
	// Настройка мока кэша - сохранение в кэш
	mockAccountCache.On("Set", ctx, expectedAccount).Return(nil)

	// Act
	account, err := useCase.GetAccount(ctx, accountID)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, account)
	assert.Equal(t, expectedAccount.ID, account.ID)
	assert.Equal(t, expectedAccount.Username, account.Username)
	assert.Equal(t, expectedAccount.Email, account.Email)
	assert.Equal(t, expectedAccount.Status, account.Status)

	// Verify
	mockAccountCache.AssertExpectations(t)
	mockAccountRepo.AssertExpectations(t)
}

func TestAccountUseCase_GetAccount_FromCache(t *testing.T) {
	// Arrange
	mockAccountRepo := new(MockAccountRepository)
	mockAuthMethodRepo := new(MockAuthMethodRepository)
	mockProfileRepo := new(MockProfileRepository)
	mockAccountCache := new(MockAccountCache)
	mockKafkaProducer := new(MockKafkaProducer)
	logger := zaptest.NewLogger(t).Sugar()

	useCase := usecase.NewAccountUseCase(
		mockAccountRepo,
		mockAuthMethodRepo,
		mockProfileRepo,
		mockAccountCache,
		mockKafkaProducer,
		logger,
	)

	ctx := context.Background()
	accountID := "test-account-id"
	expectedAccount := &entity.Account{
		ID:        accountID,
		Username:  "testuser",
		Email:     "test@example.com",
		Status:    entity.AccountStatusActive,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Настройка мока кэша - кэш содержит аккаунт
	mockAccountCache.On("Get", ctx, accountID).Return(expectedAccount, nil)

	// Act
	account, err := useCase.GetAccount(ctx, accountID)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, account)
	assert.Equal(t, expectedAccount.ID, account.ID)
	assert.Equal(t, expectedAccount.Username, account.Username)
	assert.Equal(t, expectedAccount.Email, account.Email)
	assert.Equal(t, expectedAccount.Status, account.Status)

	// Verify
	mockAccountCache.AssertExpectations(t)
	// Репозиторий не должен вызываться, если данные есть в кэше
	mockAccountRepo.AssertNotCalled(t, "GetByID")
}

func TestAccountUseCase_GetAccount_NotFound(t *testing.T) {
	// Arrange
	mockAccountRepo := new(MockAccountRepository)
	mockAuthMethodRepo := new(MockAuthMethodRepository)
	mockProfileRepo := new(MockProfileRepository)
	mockAccountCache := new(MockAccountCache)
	mockKafkaProducer := new(MockKafkaProducer)
	logger := zaptest.NewLogger(t).Sugar()

	useCase := usecase.NewAccountUseCase(
		mockAccountRepo,
		mockAuthMethodRepo,
		mockProfileRepo,
		mockAccountCache,
		mockKafkaProducer,
		logger,
	)

	ctx := context.Background()
	accountID := "non-existent-id"

	// Настройка мока кэша - кэш пуст
	mockAccountCache.On("Get", ctx, accountID).Return(nil, errors.New("not found in cache"))
	
	// Настройка мока репозитория - аккаунт не найден
	mockAccountRepo.On("GetByID", ctx, accountID).Return(nil, repository.ErrNotFound)

	// Act
	account, err := useCase.GetAccount(ctx, accountID)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, account)
	assert.Equal(t, repository.ErrNotFound, err)

	// Verify
	mockAccountCache.AssertExpectations(t)
	mockAccountRepo.AssertExpectations(t)
}

func TestAccountUseCase_CreateAccount(t *testing.T) {
	// Arrange
	mockAccountRepo := new(MockAccountRepository)
	mockAuthMethodRepo := new(MockAuthMethodRepository)
	mockProfileRepo := new(MockProfileRepository)
	mockAccountCache := new(MockAccountCache)
	mockKafkaProducer := new(MockKafkaProducer)
	logger := zaptest.NewLogger(t).Sugar()

	useCase := usecase.NewAccountUseCase(
		mockAccountRepo,
		mockAuthMethodRepo,
		mockProfileRepo,
		mockAccountCache,
		mockKafkaProducer,
		logger,
	)

	ctx := context.Background()
	newAccount := &entity.Account{
		Username: "newuser",
		Email:    "new@example.com",
		Status:   entity.AccountStatusActive,
	}

	createdAccount := &entity.Account{
		ID:        "new-account-id",
		Username:  newAccount.Username,
		Email:     newAccount.Email,
		Status:    newAccount.Status,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Настройка мока репозитория - проверка существования username
	mockAccountRepo.On("GetByUsername", ctx, newAccount.Username).Return(nil, repository.ErrNotFound)
	
	// Настройка мока репозитория - проверка существования email
	mockAccountRepo.On("GetByEmail", ctx, newAccount.Email).Return(nil, repository.ErrNotFound)
	
	// Настройка мока репозитория - создание аккаунта
	mockAccountRepo.On("Create", ctx, mock.AnythingOfType("*entity.Account")).Return(createdAccount, nil)
	
	// Настройка мока кэша - сохранение в кэш
	mockAccountCache.On("Set", ctx, createdAccount).Return(nil)
	
	// Настройка мока Kafka продюсера
	mockKafkaProducer.On("Produce", "account-events", createdAccount.ID, mock.AnythingOfType("map[string]interface {}")).Return(nil)

	// Act
	account, err := useCase.CreateAccount(ctx, newAccount)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, account)
	assert.Equal(t, createdAccount.ID, account.ID)
	assert.Equal(t, createdAccount.Username, account.Username)
	assert.Equal(t, createdAccount.Email, account.Email)
	assert.Equal(t, createdAccount.Status, account.Status)

	// Verify
	mockAccountRepo.AssertExpectations(t)
	mockAccountCache.AssertExpectations(t)
	mockKafkaProducer.AssertExpectations(t)
}

func TestAccountUseCase_CreateAccount_UsernameExists(t *testing.T) {
	// Arrange
	mockAccountRepo := new(MockAccountRepository)
	mockAuthMethodRepo := new(MockAuthMethodRepository)
	mockProfileRepo := new(MockProfileRepository)
	mockAccountCache := new(MockAccountCache)
	mockKafkaProducer := new(MockKafkaProducer)
	logger := zaptest.NewLogger(t).Sugar()

	useCase := usecase.NewAccountUseCase(
		mockAccountRepo,
		mockAuthMethodRepo,
		mockProfileRepo,
		mockAccountCache,
		mockKafkaProducer,
		logger,
	)

	ctx := context.Background()
	newAccount := &entity.Account{
		Username: "existinguser",
		Email:    "new@example.com",
		Status:   entity.AccountStatusActive,
	}

	existingAccount := &entity.Account{
		ID:        "existing-account-id",
		Username:  newAccount.Username,
		Email:     "existing@example.com",
		Status:    entity.AccountStatusActive,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Настройка мока репозитория - username уже существует
	mockAccountRepo.On("GetByUsername", ctx, newAccount.Username).Return(existingAccount, nil)

	// Act
	account, err := useCase.CreateAccount(ctx, newAccount)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, account)
	assert.Contains(t, err.Error(), "username already exists")

	// Verify
	mockAccountRepo.AssertExpectations(t)
}

func TestAccountUseCase_UpdateAccount(t *testing.T) {
	// Arrange
	mockAccountRepo := new(MockAccountRepository)
	mockAuthMethodRepo := new(MockAuthMethodRepository)
	mockProfileRepo := new(MockProfileRepository)
	mockAccountCache := new(MockAccountCache)
	mockKafkaProducer := new(MockKafkaProducer)
	logger := zaptest.NewLogger(t).Sugar()

	useCase := usecase.NewAccountUseCase(
		mockAccountRepo,
		mockAuthMethodRepo,
		mockProfileRepo,
		mockAccountCache,
		mockKafkaProducer,
		logger,
	)

	ctx := context.Background()
	accountID := "test-account-id"
	
	existingAccount := &entity.Account{
		ID:        accountID,
		Username:  "oldusername",
		Email:     "old@example.com",
		Status:    entity.AccountStatusActive,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	
	updateAccount := &entity.Account{
		ID:       accountID,
		Username: "newusername",
		Email:    "new@example.com",
	}
	
	updatedAccount := &entity.Account{
		ID:        accountID,
		Username:  updateAccount.Username,
		Email:     updateAccount.Email,
		Status:    existingAccount.Status,
		CreatedAt: existingAccount.CreatedAt,
		UpdatedAt: time.Now(),
	}

	// Настройка мока репозитория - получение существующего аккаунта
	mockAccountRepo.On("GetByID", ctx, accountID).Return(existingAccount, nil)
	
	// Настройка мока репозитория - проверка существования username
	mockAccountRepo.On("GetByUsername", ctx, updateAccount.Username).Return(nil, repository.ErrNotFound)
	
	// Настройка мока репозитория - проверка существования email
	mockAccountRepo.On("GetByEmail", ctx, updateAccount.Email).Return(nil, repository.ErrNotFound)
	
	// Настройка мока репозитория - обновление аккаунта
	mockAccountRepo.On("Update", ctx, mock.AnythingOfType("*entity.Account")).Return(updatedAccount, nil)
	
	// Настройка мока кэша - удаление из кэша
	mockAccountCache.On("Delete", ctx, accountID).Return(nil)
	
	// Настройка мока Kafka продюсера
	mockKafkaProducer.On("Produce", "account-events", accountID, mock.AnythingOfType("map[string]interface {}")).Return(nil)

	// Act
	account, err := useCase.UpdateAccount(ctx, updateAccount)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, account)
	assert.Equal(t, updatedAccount.ID, account.ID)
	assert.Equal(t, updatedAccount.Username, account.Username)
	assert.Equal(t, updatedAccount.Email, account.Email)
	assert.Equal(t, updatedAccount.Status, account.Status)

	// Verify
	mockAccountRepo.AssertExpectations(t)
	mockAccountCache.AssertExpectations(t)
	mockKafkaProducer.AssertExpectations(t)
}

func TestAccountUseCase_DeleteAccount(t *testing.T) {
	// Arrange
	mockAccountRepo := new(MockAccountRepository)
	mockAuthMethodRepo := new(MockAuthMethodRepository)
	mockProfileRepo := new(MockProfileRepository)
	mockAccountCache := new(MockAccountCache)
	mockKafkaProducer := new(MockKafkaProducer)
	logger := zaptest.NewLogger(t).Sugar()

	useCase := usecase.NewAccountUseCase(
		mockAccountRepo,
		mockAuthMethodRepo,
		mockProfileRepo,
		mockAccountCache,
		mockKafkaProducer,
		logger,
	)

	ctx := context.Background()
	accountID := "test-account-id"
	
	existingAccount := &entity.Account{
		ID:        accountID,
		Username:  "testuser",
		Email:     "test@example.com",
		Status:    entity.AccountStatusActive,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Настройка мока репозитория - получение существующего аккаунта
	mockAccountRepo.On("GetByID", ctx, accountID).Return(existingAccount, nil)
	
	// Настройка мока репозитория - удаление аккаунта
	mockAccountRepo.On("Delete", ctx, accountID).Return(nil)
	
	// Настройка мока кэша - удаление из кэша
	mockAccountCache.On("Delete", ctx, accountID).Return(nil)
	
	// Настройка мока Kafka продюсера
	mockKafkaProducer.On("Produce", "account-events", accountID, mock.AnythingOfType("map[string]interface {}")).Return(nil)

	// Act
	err := useCase.DeleteAccount(ctx, accountID)

	// Assert
	assert.NoError(t, err)

	// Verify
	mockAccountRepo.AssertExpectations(t)
	mockAccountCache.AssertExpectations(t)
	mockKafkaProducer.AssertExpectations(t)
}
