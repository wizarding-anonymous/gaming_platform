// File: backend/services/auth-service/internal/handler/http/response.go

package http

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// ResponseError представляет структуру ошибки в ответе API
type ResponseError struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

// ResponseSuccess представляет структуру успешного ответа API
type ResponseSuccess struct {
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

// RespondWithError отправляет ответ с ошибкой
func RespondWithError(c *gin.Context, statusCode int, message string, errorCode string, logger *zap.Logger) {
	logger.Error("API error response",
		zap.Int("status_code", statusCode),
		zap.String("error_message", message),
		zap.String("error_code", errorCode),
		zap.String("path", c.Request.URL.Path),
		zap.String("method", c.Request.Method),
	)

	c.JSON(statusCode, ResponseError{
		Error: message,
		Code:  errorCode,
	})
}

// RespondWithSuccess отправляет успешный ответ
func RespondWithSuccess(c *gin.Context, statusCode int, message string, data interface{}) {
	response := ResponseSuccess{
		Message: message,
		Data:    data,
	}

	c.JSON(statusCode, response)
}

// RespondWithData отправляет успешный ответ только с данными
func RespondWithData(c *gin.Context, statusCode int, data interface{}) {
	c.JSON(statusCode, data)
}

// RespondWithMessage отправляет успешный ответ только с сообщением
func RespondWithMessage(c *gin.Context, statusCode int, message string) {
	c.JSON(statusCode, gin.H{
		"message": message,
	})
}

// RespondWithCreated отправляет ответ о успешном создании ресурса
func RespondWithCreated(c *gin.Context, data interface{}) {
	c.JSON(http.StatusCreated, data)
}

// RespondWithNoContent отправляет ответ без содержимого
func RespondWithNoContent(c *gin.Context) {
	c.Status(http.StatusNoContent)
}
