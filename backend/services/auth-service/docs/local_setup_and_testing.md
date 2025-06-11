<!-- File: backend/services/auth-service/docs/local_setup_and_testing.md -->
# Локальный запуск и тестирование Auth Service

Инструкция описывает полный процесс подготовки окружения, запуска микросервиса **Auth Service** и выполнения тестов.

## Предварительные требования

- **Go 1.21+**
- **Docker** и **Docker Compose**
- **git**

## Шаг 1. Клонировать репозиторий

```bash
git clone https://github.com/wizarding-anonymous/gaming_platform.git
cd gaming_platform/backend/services/auth-service
```

## Шаг 2. Настроить переменные окружения

Скопируйте пример файла окружения и при необходимости измените значения:

```bash
cp env.example .env
# Отредактируйте .env, указав параметры подключения к Postgres, Redis и Kafka
```

## Шаг 3. Установить зависимости Go

```bash
go mod download
```

(или `make deps` для выполнения той же команды из Makefile.)

## Шаг 4. Запустить сервисы зависимостей

```bash
docker-compose up -d postgres redis kafka
```

Эта команда поднимет PostgreSQL, Redis и Kafka (с Zookeeper). Дождитесь, пока контейнеры станут `healthy`.

## Шаг 5. Применить миграции базы данных

Можно полагаться на автоматическое применение миграций при старте сервиса (`auto_migrate: true` в конфигурации) либо выполнить их вручную:

```bash
make db-migrate-up
```

## Шаг 6. Запустить Auth Service

```bash
make run
```

Сервис будет доступен на `http://localhost:8080`. Документацию API можно открыть по адресу `http://localhost:8080/swagger/index.html`.

## Шаг 7. Выполнить тесты

Убедитесь, что контейнеры с БД и Redis продолжают работать, затем запустите:

```bash
make test
```

Команда выполнит все unit и integration тесты (`go test ./...`).

## Шаг 8. Завершение работы

Чтобы остановить все запущенные контейнеры, выполните:

```bash
docker-compose down
```

На этом локальный запуск и тестирование завершены.
