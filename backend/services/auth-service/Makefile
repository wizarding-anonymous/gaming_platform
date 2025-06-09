# Makefile для Auth Service

# Переменные
APP_NAME = auth-service
MAIN_PATH = ./cmd/auth-service
BUILD_DIR = ./build
DOCKER_REGISTRY = registry.gaiming.ru
DOCKER_IMAGE = $(DOCKER_REGISTRY)/gaiming/$(APP_NAME)
DOCKER_TAG ?= latest
HELM_CHART_PATH = ./deployments/helm/auth-service
NAMESPACE = gaiming

# Цвета для вывода
GREEN = \033[0;32m
NC = \033[0m # No Color

# Команды для разработки
.PHONY: run
run:
	@echo "$(GREEN)Запуск сервиса...$(NC)"
	go run $(MAIN_PATH)

.PHONY: build
build:
	@echo "$(GREEN)Сборка бинарного файла...$(NC)"
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -ldflags="-w -s" -o $(BUILD_DIR)/$(APP_NAME) $(MAIN_PATH)

.PHONY: clean
clean:
	@echo "$(GREEN)Очистка...$(NC)"
	rm -rf $(BUILD_DIR)
	go clean

.PHONY: deps
deps:
	@echo "$(GREEN)Установка зависимостей...$(NC)"
	go mod download
	go mod tidy

.PHONY: lint
lint:
	@echo "$(GREEN)Запуск линтера...$(NC)"
	golangci-lint run ./...

.PHONY: fmt
fmt:
	@echo "$(GREEN)Форматирование кода...$(NC)"
	go fmt ./...

.PHONY: vet
vet:
	@echo "$(GREEN)Статический анализ кода...$(NC)"
	go vet ./...

# Команды для Docker
.PHONY: docker-build
docker-build:
	@echo "$(GREEN)Сборка Docker образа...$(NC)"
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

.PHONY: docker-push
docker-push:
	@echo "$(GREEN)Отправка Docker образа в реестр...$(NC)"
	docker push $(DOCKER_IMAGE):$(DOCKER_TAG)

.PHONY: docker-run
docker-run:
	@echo "$(GREEN)Запуск Docker контейнера...$(NC)"
	docker run -p 8080:8080 -p 9090:9090 -p 9100:9100 --env-file .env $(DOCKER_IMAGE):$(DOCKER_TAG)

# Команды для Kubernetes
.PHONY: k8s-deploy
k8s-deploy:
	@echo "$(GREEN)Развертывание в Kubernetes...$(NC)"
	helm upgrade --install $(APP_NAME) $(HELM_CHART_PATH) \
		--namespace $(NAMESPACE) \
		--set image.repository=$(DOCKER_IMAGE) \
		--set image.tag=$(DOCKER_TAG) \
		--values $(HELM_CHART_PATH)/values.yaml

.PHONY: k8s-delete
k8s-delete:
	@echo "$(GREEN)Удаление из Kubernetes...$(NC)"
	helm uninstall $(APP_NAME) --namespace $(NAMESPACE)

.PHONY: k8s-status
k8s-status:
	@echo "$(GREEN)Статус в Kubernetes...$(NC)"
	kubectl get all -l app=$(APP_NAME) -n $(NAMESPACE)

# Команды для базы данных
.PHONY: db-migrate-up
db-migrate-up:
	@echo "$(GREEN)Применение миграций...$(NC)"
	migrate -path ./migrations -database "postgres://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}?sslmode=${DB_SSL_MODE}" up

.PHONY: db-migrate-down
db-migrate-down:
	@echo "$(GREEN)Откат миграций...$(NC)"
	migrate -path ./migrations -database "postgres://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}?sslmode=${DB_SSL_MODE}" down

.PHONY: db-migrate-create
db-migrate-create:
	@echo "$(GREEN)Создание новой миграции...$(NC)"
	migrate create -ext sql -dir ./migrations -seq $(name)

# Команды для генерации кода
.PHONY: gen-proto
gen-proto:
	@echo "$(GREEN)Генерация кода из Proto файлов...$(NC)"
	# Удаляем старые сгенерированные файлы в новой директории, если есть
	rm -f internal/gen/auth/v1/*.pb.go
	# Создаем директорию, если она не существует
	mkdir -p internal/gen/auth/v1
	# Генерируем новые
	protoc --proto_path=api/proto/v1 \
		--go_out=internal/gen/auth/v1 --go_opt=paths=source_relative \
		--go-grpc_out=internal/gen/auth/v1 --go-grpc_opt=paths=source_relative \
		auth.proto

.PHONY: gen-swagger
gen-swagger:
	@echo "$(GREEN)Генерация Swagger документации...$(NC)"
	swag init -g cmd/auth-service/main.go -o api/swagger

# Команды для мониторинга
.PHONY: prometheus-config
prometheus-config:
	@echo "$(GREEN)Применение конфигурации Prometheus...$(NC)"
	kubectl create configmap prometheus-config --from-file=./deployments/prometheus/prometheus.yaml -n monitoring --dry-run=client -o yaml | kubectl apply -f -

.PHONY: prometheus-rules
prometheus-rules:
	@echo "$(GREEN)Применение правил Prometheus...$(NC)"
	kubectl create configmap prometheus-rules --from-file=./deployments/prometheus/rules.yaml -n monitoring --dry-run=client -o yaml | kubectl apply -f -

.PHONY: grafana-dashboards
grafana-dashboards:
	@echo "$(GREEN)Применение дашбордов Grafana...$(NC)"
	kubectl create configmap grafana-dashboards --from-file=./deployments/grafana/dashboards/ -n monitoring --dry-run=client -o yaml | kubectl apply -f -

# Команды для логирования
.PHONY: logstash-config
logstash-config:
	@echo "$(GREEN)Применение конфигурации Logstash...$(NC)"
	kubectl create configmap logstash-config --from-file=./deployments/elk/logstash.conf -n monitoring --dry-run=client -o yaml | kubectl apply -f -

# Команды для OpenTelemetry
.PHONY: otel-config
otel-config:
	@echo "$(GREEN)Применение конфигурации OpenTelemetry...$(NC)"
	kubectl create configmap otel-collector-config --from-file=./deployments/opentelemetry/otel-collector-config.yaml -n monitoring --dry-run=client -o yaml | kubectl apply -f -

# Команда для запуска всех проверок
.PHONY: check
check: fmt vet lint

# Команда для полной сборки и отправки
.PHONY: release
release: check build docker-build docker-push k8s-deploy

# Команда для локальной разработки
.PHONY: dev
dev: deps fmt vet run

# Помощь
.PHONY: help
help:
	@echo "$(GREEN)Доступные команды:$(NC)"
	@echo "  make run              - Запуск сервиса локально"
	@echo "  make build            - Сборка бинарного файла"
	@echo "  make clean            - Очистка артефактов сборки"
	@echo "  make deps             - Установка зависимостей"
	@echo "  make lint             - Запуск линтера"
	@echo "  make fmt              - Форматирование кода"
	@echo "  make vet              - Статический анализ кода"
	@echo "  make docker-build     - Сборка Docker образа"
	@echo "  make docker-push      - Отправка Docker образа в реестр"
	@echo "  make docker-run       - Запуск Docker контейнера"
	@echo "  make k8s-deploy       - Развертывание в Kubernetes"
	@echo "  make k8s-delete       - Удаление из Kubernetes"
	@echo "  make k8s-status       - Статус в Kubernetes"
	@echo "  make db-migrate-up    - Применение миграций"
	@echo "  make db-migrate-down  - Откат миграций"
	@echo "  make db-migrate-create name=migration_name - Создание новой миграции"
	@echo "  make gen-proto        - Генерация кода из Proto файлов"
	@echo "  make gen-swagger      - Генерация Swagger документации"
	@echo "  make prometheus-config - Применение конфигурации Prometheus"
	@echo "  make prometheus-rules  - Применение правил Prometheus"
	@echo "  make grafana-dashboards - Применение дашбордов Grafana"
	@echo "  make logstash-config   - Применение конфигурации Logstash"
	@echo "  make otel-config       - Применение конфигурации OpenTelemetry"
	@echo "  make check            - Запуск всех проверок"
	@echo "  make release          - Полная сборка и отправка"
	@echo "  make dev              - Локальная разработка"
	@echo "  make help             - Показать эту справку"

# По умолчанию
.DEFAULT_GOAL := help
