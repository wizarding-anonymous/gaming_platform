# File: backend/Makefile
# Makefile для корневого уровня монорепозитория

.PHONY: all build test clean up down migrate lint help

# Переменные
SERVICES := auth-service account-service

# Цели по умолчанию
all: build

# Сборка всех сервисов
build:
	@echo "Building all services..."
	@for service in $(SERVICES); do \
		echo "Building $$service..."; \
		$(MAKE) -C backend/services/$$service build || exit 1; \
	done

# Запуск тестов для всех сервисов
test:
	@echo "Testing all services..."
	@for service in $(SERVICES); do \
		echo "Testing $$service..."; \
		$(MAKE) -C backend/services/$$service test || exit 1; \
	done

# Очистка всех сервисов
clean:
	@echo "Cleaning all services..."
	@for service in $(SERVICES); do \
		echo "Cleaning $$service..."; \
		$(MAKE) -C backend/services/$$service clean || exit 1; \
	done

# Запуск всех сервисов через docker-compose
up:
	@echo "Starting all services..."
	docker-compose up -d

# Остановка всех сервисов
down:
	@echo "Stopping all services..."
	docker-compose down

# Запуск миграций для всех сервисов
migrate:
	@echo "Running migrations for all services..."
	@for service in $(SERVICES); do \
		echo "Migrating $$service..."; \
		$(MAKE) -C backend/services/$$service migrate || exit 1; \
	done

# Проверка кода линтером для всех сервисов
lint:
	@echo "Linting all services..."
	@for service in $(SERVICES); do \
		echo "Linting $$service..."; \
		$(MAKE) -C backend/services/$$service lint || exit 1; \
	done

# Справка
help:
	@echo "Available commands:"
	@echo "  make build    - Build all services"
	@echo "  make test     - Run tests for all services"
	@echo "  make clean    - Clean build artifacts"
	@echo "  make up       - Start all services with Docker Compose"
	@echo "  make down     - Stop all services"
	@echo "  make migrate  - Run database migrations"
	@echo "  make lint     - Run linters"
	@echo "  make help     - Show this help message"
