// account-service\internal\domain\errors\errors.go

package errors

import (
	"errors"
)

// Определение ошибок для домена Account
var (
	// ErrAccountNotFound возникает, когда аккаунт не найден
	ErrAccountNotFound = errors.New("account not found")
	
	// ErrUsernameAlreadyExists возникает, когда имя пользователя уже занято
	ErrUsernameAlreadyExists = errors.New("username already exists")
	
	// ErrEmailAlreadyExists возникает, когда email уже занят
	ErrEmailAlreadyExists = errors.New("email already exists")
	
	// ErrInvalidAccountStatus возникает при попытке установить недопустимый статус аккаунта
	ErrInvalidAccountStatus = errors.New("invalid account status")
)

// Определение ошибок для домена Profile
var (
	// ErrProfileNotFound возникает, когда профиль не найден
	ErrProfileNotFound = errors.New("profile not found")
	
	// ErrInvalidProfileData возникает при попытке установить недопустимые данные профиля
	ErrInvalidProfileData = errors.New("invalid profile data")
	
	// ErrInvalidImageFormat возникает при загрузке изображения в неподдерживаемом формате
	ErrInvalidImageFormat = errors.New("invalid image format")
	
	// ErrImageTooLarge возникает при загрузке слишком большого изображения
	ErrImageTooLarge = errors.New("image is too large")
)

// Определение ошибок для домена ContactInfo
var (
	// ErrContactInfoNotFound возникает, когда контактная информация не найдена
	ErrContactInfoNotFound = errors.New("contact information not found")
	
	// ErrContactInfoAlreadyExists возникает, когда контактная информация уже существует
	ErrContactInfoAlreadyExists = errors.New("contact information already exists")
	
	// ErrInvalidContactInfoType возникает при попытке установить недопустимый тип контактной информации
	ErrInvalidContactInfoType = errors.New("invalid contact information type")
	
	// ErrInvalidContactInfoValue возникает при попытке установить недопустимое значение контактной информации
	ErrInvalidContactInfoValue = errors.New("invalid contact information value")
	
	// ErrVerificationCodeExpired возникает, когда срок действия кода верификации истек
	ErrVerificationCodeExpired = errors.New("verification code expired")
	
	// ErrInvalidVerificationCode возникает при попытке использовать неверный код верификации
	ErrInvalidVerificationCode = errors.New("invalid verification code")
)

// Определение ошибок для домена Setting
var (
	// ErrSettingNotFound возникает, когда настройка не найдена
	ErrSettingNotFound = errors.New("setting not found")
	
	// ErrInvalidSettingCategory возникает при попытке установить недопустимую категорию настроек
	ErrInvalidSettingCategory = errors.New("invalid setting category")
	
	// ErrInvalidSettingData возникает при попытке установить недопустимые данные настроек
	ErrInvalidSettingData = errors.New("invalid setting data")
)

// Определение общих ошибок
var (
	// ErrInternalServerError возникает при внутренней ошибке сервера
	ErrInternalServerError = errors.New("internal server error")
	
	// ErrUnauthorized возникает при попытке выполнить действие без авторизации
	ErrUnauthorized = errors.New("unauthorized")
	
	// ErrForbidden возникает при попытке выполнить действие без необходимых прав
	ErrForbidden = errors.New("forbidden")
	
	// ErrInvalidRequest возникает при получении некорректного запроса
	ErrInvalidRequest = errors.New("invalid request")
	
	// ErrDatabaseError возникает при ошибке базы данных
	ErrDatabaseError = errors.New("database error")
	
	// ErrCacheError возникает при ошибке кэша
	ErrCacheError = errors.New("cache error")
)
