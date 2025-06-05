// File: backend/services/auth-service/internal/utils/validator/validator.go
package validator

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/go-playground/validator/v10"
)

var validate *validator.Validate

func init() {
	validate = validator.New()

	// Регистрация функции для получения имен полей из тегов json
	validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
		if name == "-" {
			return ""
		}
		return name
	})
}

// Validate проверяет структуру на соответствие правилам валидации
func Validate(s interface{}) error {
	err := validate.Struct(s)
	if err != nil {
		// Обработка ошибок валидации
		if _, ok := err.(*validator.InvalidValidationError); ok {
			return fmt.Errorf("invalid validation error: %w", err)
		}

		validationErrors := err.(validator.ValidationErrors)
		if len(validationErrors) > 0 {
			firstErr := validationErrors[0]
			fieldName := firstErr.Field()
			tag := firstErr.Tag()
			param := firstErr.Param()

			switch tag {
			case "required":
				return fmt.Errorf("field '%s' is required", fieldName)
			case "email":
				return fmt.Errorf("field '%s' must be a valid email address", fieldName)
			case "min":
				return fmt.Errorf("field '%s' must be at least %s characters long", fieldName, param)
			case "max":
				return fmt.Errorf("field '%s' must be at most %s characters long", fieldName, param)
			case "uuid":
				return fmt.Errorf("field '%s' must be a valid UUID", fieldName)
			default:
				return fmt.Errorf("field '%s' validation failed on tag '%s'", fieldName, tag)
			}
		}
	}

	return nil
}

// ValidateVar проверяет переменную на соответствие правилам валидации
func ValidateVar(field interface{}, tag string) error {
	err := validate.Var(field, tag)
	if err != nil {
		// Обработка ошибок валидации
		if _, ok := err.(*validator.InvalidValidationError); ok {
			return fmt.Errorf("invalid validation error: %w", err)
		}

		validationErrors := err.(validator.ValidationErrors)
		if len(validationErrors) > 0 {
			firstErr := validationErrors[0]
			tag := firstErr.Tag()
			param := firstErr.Param()

			switch tag {
			case "required":
				return fmt.Errorf("value is required")
			case "email":
				return fmt.Errorf("value must be a valid email address")
			case "min":
				return fmt.Errorf("value must be at least %s characters long", param)
			case "max":
				return fmt.Errorf("value must be at most %s characters long", param)
			case "uuid":
				return fmt.Errorf("value must be a valid UUID")
			default:
				return fmt.Errorf("validation failed on tag '%s'", tag)
			}
		}
	}

	return nil
}

// GetValidator возвращает экземпляр валидатора
func GetValidator() *validator.Validate {
	return validate
}
