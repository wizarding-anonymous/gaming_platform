// File: internal/utils/validation/validation.go

package validation

import (
	"fmt"
	"net"
	"net/mail"
	"regexp"
	"strings"
	"unicode"

	"github.com/go-playground/validator/v10"
)

// Validator представляет валидатор для проверки данных
type Validator struct {
	validate *validator.Validate
}

// NewValidator создает новый экземпляр валидатора
func NewValidator() *Validator {
	validate := validator.New()

	// Регистрируем пользовательские валидаторы
	_ = validate.RegisterValidation("password", validatePassword)
	_ = validate.RegisterValidation("username", validateUsername)
	_ = validate.RegisterValidation("phone", validatePhone)
	_ = validate.RegisterValidation("email", validateEmail)
	_ = validate.RegisterValidation("ip", validateIP)

	return &Validator{
		validate: validate,
	}
}

// Validate проверяет структуру на соответствие правилам валидации
func (v *Validator) Validate(s interface{}) error {
	return v.validate.Struct(s)
}

// ValidateVar проверяет переменную на соответствие правилам валидации
func (v *Validator) ValidateVar(field interface{}, tag string) error {
	return v.validate.Var(field, tag)
}

// validatePassword проверяет, что пароль соответствует требованиям безопасности
func validatePassword(fl validator.FieldLevel) bool {
	password := fl.Field().String()

	// Проверяем минимальную длину
	if len(password) < 8 {
		return false
	}

	var (
		hasUpper   bool
		hasLower   bool
		hasNumber  bool
		hasSpecial bool
	)

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	// Пароль должен содержать хотя бы одну заглавную букву, одну строчную букву,
	// одну цифру и один специальный символ
	return hasUpper && hasLower && hasNumber && hasSpecial
}

// validateUsername проверяет, что имя пользователя соответствует требованиям
func validateUsername(fl validator.FieldLevel) bool {
	username := fl.Field().String()

	// Проверяем минимальную и максимальную длину
	if len(username) < 3 || len(username) > 30 {
		return false
	}

	// Имя пользователя должно содержать только буквы, цифры, точки, подчеркивания и дефисы
	// и не должно начинаться или заканчиваться точкой, подчеркиванием или дефисом
	match, _ := regexp.MatchString(`^[a-zA-Z0-9][a-zA-Z0-9._-]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$`, username)
	return match
}

// validatePhone проверяет, что номер телефона соответствует требованиям
func validatePhone(fl validator.FieldLevel) bool {
	phone := fl.Field().String()

	// Удаляем все нецифровые символы
	digits := strings.Map(func(r rune) rune {
		if unicode.IsDigit(r) {
			return r
		}
		return -1
	}, phone)

	// Проверяем, что номер телефона содержит от 10 до 15 цифр
	return len(digits) >= 10 && len(digits) <= 15
}

// validateEmail проверяет, что email соответствует требованиям
func validateEmail(fl validator.FieldLevel) bool {
	email := fl.Field().String()

	// Проверяем, что email соответствует формату
	_, err := mail.ParseAddress(email)
	if err != nil {
		return false
	}

	// Проверяем, что домен содержит точку
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}
	domain := parts[1]
	return strings.Contains(domain, ".")
}

// validateIP проверяет, что строка является корректным IP-адресом
func validateIP(fl validator.FieldLevel) bool {
	ip := fl.Field().String()
	return net.ParseIP(ip) != nil
}

// FormatValidationErrors форматирует ошибки валидации в удобочитаемый вид
func FormatValidationErrors(err error) []string {
	if err == nil {
		return nil
	}

	var errors []string
	for _, err := range err.(validator.ValidationErrors) {
		field := err.Field()
		tag := err.Tag()
		param := err.Param()

		var message string
		switch tag {
		case "required":
			message = fmt.Sprintf("Поле '%s' обязательно для заполнения", field)
		case "email":
			message = fmt.Sprintf("Поле '%s' должно содержать корректный email", field)
		case "min":
			message = fmt.Sprintf("Поле '%s' должно содержать не менее %s символов", field, param)
		case "max":
			message = fmt.Sprintf("Поле '%s' должно содержать не более %s символов", field, param)
		case "password":
			message = fmt.Sprintf("Поле '%s' должно содержать не менее 8 символов, включая заглавные и строчные буквы, цифры и специальные символы", field)
		case "username":
			message = fmt.Sprintf("Поле '%s' должно содержать от 3 до 30 символов и может включать буквы, цифры, точки, подчеркивания и дефисы", field)
		case "phone":
			message = fmt.Sprintf("Поле '%s' должно содержать корректный номер телефона", field)
		case "ip":
			message = fmt.Sprintf("Поле '%s' должно содержать корректный IP-адрес", field)
		default:
			message = fmt.Sprintf("Поле '%s' не соответствует правилу '%s'", field, tag)
		}
		errors = append(errors, message)
	}

	return errors
}

// ValidatePassword проверяет, что пароль соответствует требованиям безопасности
func ValidatePassword(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("пароль должен содержать не менее 8 символов")
	}

	var (
		hasUpper   bool
		hasLower   bool
		hasNumber  bool
		hasSpecial bool
	)

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if !hasUpper {
		return fmt.Errorf("пароль должен содержать хотя бы одну заглавную букву")
	}
	if !hasLower {
		return fmt.Errorf("пароль должен содержать хотя бы одну строчную букву")
	}
	if !hasNumber {
		return fmt.Errorf("пароль должен содержать хотя бы одну цифру")
	}
	if !hasSpecial {
		return fmt.Errorf("пароль должен содержать хотя бы один специальный символ")
	}

	return nil
}

// ValidateEmail проверяет, что email соответствует требованиям
func ValidateEmail(email string) error {
	// Проверяем, что email соответствует формату
	_, err := mail.ParseAddress(email)
	if err != nil {
		return fmt.Errorf("некорректный формат email")
	}

	// Проверяем, что домен содержит точку
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return fmt.Errorf("некорректный формат email")
	}
	domain := parts[1]
	if !strings.Contains(domain, ".") {
		return fmt.Errorf("некорректный домен email")
	}

	return nil
}

// ValidateUsername проверяет, что имя пользователя соответствует требованиям
func ValidateUsername(username string) error {
	// Проверяем минимальную и максимальную длину
	if len(username) < 3 {
		return fmt.Errorf("имя пользователя должно содержать не менее 3 символов")
	}
	if len(username) > 30 {
		return fmt.Errorf("имя пользователя должно содержать не более 30 символов")
	}

	// Имя пользователя должно содержать только буквы, цифры, точки, подчеркивания и дефисы
	// и не должно начинаться или заканчиваться точкой, подчеркиванием или дефисом
	match, _ := regexp.MatchString(`^[a-zA-Z0-9][a-zA-Z0-9._-]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$`, username)
	if !match {
		return fmt.Errorf("имя пользователя может содержать только буквы, цифры, точки, подчеркивания и дефисы, и не должно начинаться или заканчиваться точкой, подчеркиванием или дефисом")
	}

	return nil
}

// ValidatePhone проверяет, что номер телефона соответствует требованиям
func ValidatePhone(phone string) error {
	// Удаляем все нецифровые символы
	digits := strings.Map(func(r rune) rune {
		if unicode.IsDigit(r) {
			return r
		}
		return -1
	}, phone)

	// Проверяем, что номер телефона содержит от 10 до 15 цифр
	if len(digits) < 10 {
		return fmt.Errorf("номер телефона должен содержать не менее 10 цифр")
	}
	if len(digits) > 15 {
		return fmt.Errorf("номер телефона должен содержать не более 15 цифр")
	}

	return nil
}
