# Используем минимальный базовый образ для Go
FROM golang:1.21-alpine AS builder

# Установка необходимых зависимостей
RUN apk add --no-cache git ca-certificates tzdata && \
    update-ca-certificates

# Установка рабочей директории
WORKDIR /app

# Копирование файлов go.mod и go.sum
COPY go.mod go.sum ./

# Загрузка зависимостей
RUN go mod download

# Копирование исходного кода
COPY . .

# Сборка приложения
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -ldflags="-w -s" -o auth-service ./cmd/auth-service

# Используем минимальный образ для запуска
FROM alpine:3.18

# Установка необходимых пакетов
RUN apk --no-cache add ca-certificates tzdata && \
    update-ca-certificates

# Создание непривилегированного пользователя
RUN adduser -D -H -h /app appuser

# Установка рабочей директории
WORKDIR /app

# Copy configuration files
COPY configs ./configs

# Копирование бинарного файла из предыдущего этапа
COPY --from=builder /app/auth-service .

# Установка прав на исполнение
RUN chmod +x /app/auth-service # Keep this for the executable itself

# Copy migration files
COPY ./migrations /app/migrations

# Set ownership for the entire /app directory, including migrations and executable
RUN chown -R appuser:appuser /app

# Переключение на непривилегированного пользователя
USER appuser

# Открытие портов
EXPOSE 8080 9090 9100

# Установка переменных окружения
ENV APP_ENV=production \
    APP_PORT=8080 \
    APP_GRPC_PORT=9090 \
    METRICS_PORT=9100 \
    APP_HOST=0.0.0.0

# Запуск приложения
CMD ["/app/auth-service"]

# Метаданные образа
LABEL maintainer="Gaiming Team <team@gaiming.ru>" \
      description="Auth Service for Gaiming Platform" \
      version="1.0.0"
