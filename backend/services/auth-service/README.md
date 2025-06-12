<!-- File: backend/services/auth-service/README.md -->
# Auth Service

Микросервис аутентификации и авторизации для российского аналога платформы Steam.

## Содержание

- [Обзор](#обзор)
- [Функциональность](#функциональность)
- [Технологический стек](#технологический-стек)
- [Структура проекта](#структура-проекта)
- [Начало работы](#начало-работы)
  - [Предварительные требования](#предварительные-требования)
  - [Установка и запуск](#установка-и-запуск)
- [API](#api)
- [Конфигурация](#конфигурация)
- [Развертывание](#развертывание)
- [Мониторинг и логирование](#мониторинг-и-логирование)
- [Безопасность](#безопасность)
- [Интеграции](#интеграции)
- [Лицензия](#лицензия)

## Обзор

Auth Service является центральным компонентом платформы, отвечающим за аутентификацию и авторизацию пользователей, управление сессиями и ролями. Он обеспечивает безопасный доступ ко всем ресурсам и функциям платформы, взаимодействуя с другими микросервисами для проверки прав доступа и предоставления информации о пользователе.

## Функциональность

- Регистрация и аутентификация пользователей
- JWT-аутентификация с Access и Refresh токенами
- Интеграция с Telegram для аутентификации
- Двухфакторная аутентификация (2FA)
- Ролевая модель контроля доступа (RBAC)
- Управление сессиями пользователей
- Аудит безопасности
- REST и gRPC API для интеграции с другими сервисами
- Асинхронное взаимодействие через Kafka Events

## Технологический стек

- **Язык программирования**: Go (версия 1.21+)
- **Веб-фреймворк (REST)**: Gin (gin-gonic/gin)
- **gRPC фреймворк**: google.golang.org/grpc
- **База данных**: PostgreSQL (версия 15+)
- **ORM/Драйвер БД**: pgx
- **Кэш**: Redis (версия 7+)
- **Клиент кэша**: go-redis
- **Очередь сообщений**: Apache Kafka
- **Клиент Kafka**: confluent-kafka-go
- **Работа с JWT**: golang-jwt/jwt/v5
- **Хеширование паролей**: Argon2id (golang.org/x/crypto/argon2)
- **Логирование**: Zap
- **Мониторинг (метрики)**: Prometheus
- **Трассировка**: OpenTelemetry (OTel)
- **Миграции БД**: golang-migrate
- **Контейнеризация**: Docker
- **Оркестрация**: Kubernetes (K8s)
- **Управление релизами**: Helm
- **Управление секретами**: HashiCorp Vault, Kubernetes Secrets
- **Service Mesh**: Istio

## Структура проекта

```
auth-service/
├── .github/workflows/        # CI/CD пайплайны
├── api/                      # API-определения
│   ├── proto/                # gRPC протофайлы
│   └── swagger/              # Swagger-документация
├── cmd/                      # Точки входа
│   └── auth-service/         # Основной сервис
├── configs/                  # Конфигурационные файлы
├── deployments/              # Файлы для развертывания
│   ├── helm/                 # Helm-чарты
│   ├── prometheus/           # Конфигурации Prometheus
│   ├── grafana/              # Дашборды Grafana
│   ├── opentelemetry/        # Конфигурации OpenTelemetry
│   ├── elk/                  # Конфигурации ELK Stack
│   └── istio/                # Конфигурации Istio
├── docs/                     # Документация
├── internal/                 # Внутренний код
│   ├── domain/               # Доменные модели и репозитории
│   ├── events/               # Обработка событий
│   ├── handler/              # Обработчики запросов
│   ├── service/              # Бизнес-логика
│   └── utils/                # Утилиты
├── migrations/               # Миграции БД
├── scripts/                  # Скрипты для автоматизации
└── security/                 # Файлы безопасности
```

## Начало работы

### Предварительные требования

- Go 1.21+
- Docker и Docker Compose
- PostgreSQL 15+
- Redis 7+
- Apache Kafka

### Установка и запуск

1. Клонировать репозиторий:
   ```bash
   git clone https://github.com/wizarding-anonymous/gaming_platform.git
   cd gaming_platform/backend/services/auth-service
   ```

2. При возникновении ошибок 403 при скачивании зависимостей настройте GOPROXY:
   ```bash
   ../../setup-go-proxy.sh
   ```

3. Установить зависимости:
   ```bash
   go mod download
   ```

4. Запустить сервисы зависимостей:
   ```bash
   docker-compose up -d postgres redis kafka
   ```

5. Применить миграции (можно пропустить, если `auto_migrate: true`):
   ```bash
   make db-migrate-up
   ```

6. Запустить сервис:
   ```bash
   make run
   ```

Альтернативно, можно запустить весь сервис через Docker Compose:
```bash
docker-compose up -d
```

Более подробная инструкция по локальному запуску и тестированию расположена в [docs/local_setup_and_testing.md](docs/local_setup_and_testing.md).

## API

### REST API

Основные эндпоинты:

- `POST /api/v1/auth/register` - Регистрация нового пользователя
- `POST /api/v1/auth/login` - Аутентификация по логину/паролю
- `POST /api/v1/auth/telegram-login` - Аутентификация через Telegram
- `POST /api/v1/auth/refresh-token` - Обновление токена доступа
- `POST /api/v1/auth/logout` - Выход из системы
- `POST /api/v1/auth/2fa/enable` - Включение 2FA
- `GET /api/v1/auth/users` - Получение списка пользователей (для админов)
- `POST /api/v1/auth/validate-token` - Проверка валидности токена

Полная документация API доступна через Swagger по адресу `/swagger/index.html`.

### gRPC API

Сервис предоставляет следующие gRPC-методы:

- `ValidateToken` - Валидация токена
- `CheckPermission` - Проверка разрешения
- `GetUser` - Получение информации о пользователе
- `GetUserRoles` - Получение ролей пользователя

Протофайлы находятся в директории `api/proto/`.

## Конфигурация

Конфигурация сервиса осуществляется через файлы в директории `configs/` и переменные окружения.

Основные параметры конфигурации:

- `HTTP_PORT` - Порт для HTTP-сервера
- `GRPC_PORT` - Порт для gRPC-сервера
- `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME` - Параметры подключения к PostgreSQL
- `REDIS_HOST`, `REDIS_PORT`, `REDIS_PASSWORD` - Параметры подключения к Redis
- `KAFKA_BROKERS` - Список брокеров Kafka
- `JWT_PRIVATE_KEY_PATH`: Путь к приватному ключу RSA для подписи JWT-токенов.
- `JWT_PUBLIC_KEY_PATH`: Путь к публичному ключу RSA для проверки JWT-токенов.
- `TOTP_ENCRYPTION_KEY`: 32-байтный ключ в hex-формате для шифрования TOTP секрета.
- `ACCESS_TOKEN_TTL` - Время жизни Access Token (в секундах)
- `REFRESH_TOKEN_TTL` - Время жизни Refresh Token (в секундах)
- `TELEGRAM_BOT_TOKEN` - Токен Telegram Bot API

Секретные ключи (RSA и TOTP) рекомендуется хранить во внешних секрет-хранилищах
(Vault, Kubernetes Secrets) и передавать сервису через переменные окружения или
смонтированные файлы.

## Развертывание

### Docker

Сборка Docker-образа:
```bash
docker build -t auth-service:latest .
```

### Kubernetes

Развертывание в Kubernetes с помощью Helm:
```bash
helm upgrade --install auth-service ./deployments/helm/auth-service \
  --namespace gaiming \
  --set image.tag=latest \
  --values ./deployments/helm/auth-service/values.yaml
```

## Мониторинг и логирование

Сервис предоставляет метрики в формате Prometheus по эндпоинту `/metrics`.

Основные метрики:
- `http_requests_total` - Общее количество HTTP-запросов
- `http_request_duration_seconds` - Длительность HTTP-запросов
- `grpc_server_handled_total` - Общее количество gRPC-запросов
- `auth_login_attempts_total` - Количество попыток входа
- `auth_login_failures_total` - Количество неудачных попыток входа

Логи в формате JSON отправляются в stdout/stderr и могут быть собраны с помощью Fluentd/Fluent Bit для дальнейшей обработки в ELK Stack.

## Безопасность

- Пароли хранятся в виде хешей Argon2id.
- Все API-эндпоинты защищены JWT-аутентификацией (RS256) (кроме публичных).
- Поддерживается двухфакторная аутентификация (2FA)
- Реализована защита от брутфорс-атак через ограничение количества попыток входа
- Все действия пользователей логируются для аудита безопасности
- Секреты управляются через HashiCorp Vault и Kubernetes Secrets

## Интеграции

Auth Service интегрируется со следующими микросервисами:

- **API Gateway** - Проксирование запросов и валидация токенов
- **Account Service** - Управление профилями пользователей
- **Payment Service** - Проверка аутентификации для платежных операций
- **Developer Service** - Управление ролями разработчиков
- **Admin Service** - Расширенное управление пользователями и ролями
- **Notification Service** - Отправка уведомлений о событиях безопасности

## Лицензия

Проприетарное программное обеспечение. Все права защищены.
