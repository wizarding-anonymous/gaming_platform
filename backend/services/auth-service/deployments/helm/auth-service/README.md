# Auth Service Helm Chart

## Введение

Этот Helm Chart используется для развертывания Auth Service в Kubernetes кластере. Auth Service отвечает за аутентификацию и авторизацию пользователей в платформе Gaiming.

## Предварительные требования

- Kubernetes 1.19+
- Helm 3.2.0+
- Namespace `gaiming` должен существовать
- Доступ к реестру контейнеров (registry.gaiming.ru)

## Установка

### Добавление репозитория Helm

```bash
helm repo add gaiming https://charts.gaiming.ru
helm repo update
```

### Установка чарта

```bash
# Установка с значениями по умолчанию
helm install auth-service gaiming/auth-service --namespace gaiming

# Установка с переопределением значений
helm install auth-service gaiming/auth-service --namespace gaiming \
  --set image.tag=v1.0.0 \
  --values custom-values.yaml
```

### Установка из локального чарта

```bash
# Клонирование репозитория
git clone https://github.com/gaiming/auth-service.git
cd auth-service

# Установка чарта
helm install auth-service ./deployments/helm/auth-service --namespace gaiming
```

## Конфигурация

### Параметры

| Параметр | Описание | Значение по умолчанию |
|----------|----------|------------------------|
| `replicaCount` | Количество реплик | `2` |
| `image.repository` | Репозиторий образа | `registry.gaiming.ru/gaiming/auth-service` |
| `image.tag` | Тег образа | `latest` |
| `image.pullPolicy` | Политика загрузки образа | `Always` |
| `service.type` | Тип сервиса | `ClusterIP` |
| `service.httpPort` | HTTP порт | `8080` |
| `service.grpcPort` | gRPC порт | `9090` |
| `service.metricsPort` | Порт метрик | `9100` |
| `ingress.enabled` | Включить Ingress | `true` |
| `ingress.hosts[0].host` | Хост для Ingress | `auth.gaiming.ru` |
| `resources.limits.cpu` | Лимит CPU | `500m` |
| `resources.limits.memory` | Лимит памяти | `512Mi` |
| `resources.requests.cpu` | Запрос CPU | `100m` |
| `resources.requests.memory` | Запрос памяти | `128Mi` |
| `autoscaling.enabled` | Включить автомасштабирование | `true` |
| `autoscaling.minReplicas` | Минимальное количество реплик | `2` |
| `autoscaling.maxReplicas` | Максимальное количество реплик | `10` |
| `secrets.dbPassword` | Пароль базы данных | `""` |
| `secrets.redisPassword` | Пароль Redis | `""` |
| `secrets.jwtSecret` | Секрет для JWT | `""` |

Полный список параметров можно найти в файле [values.yaml](values.yaml).

### Секреты

Для безопасного хранения секретов рекомендуется использовать отдельный файл значений, который не должен храниться в системе контроля версий:

```bash
# Создание файла с секретами
cat > secrets.yaml << EOF
secrets:
  dbPassword: "your-db-password"
  redisPassword: "your-redis-password"
  jwtSecret: "your-jwt-secret"
  kafkaUsername: "your-kafka-username"
  kafkaPassword: "your-kafka-password"
  telegramBotToken: "your-telegram-bot-token"
  vaultToken: "your-vault-token"
  serviceApiKey: "your-service-api-key"
EOF

# Установка с секретами
helm install auth-service ./deployments/helm/auth-service --namespace gaiming \
  -f secrets.yaml
```

Альтернативно, можно использовать HashiCorp Vault для управления секретами.

## Зависимости

Чарт может опционально устанавливать следующие зависимости:

- PostgreSQL (если `postgresql.enabled=true`)
- Redis (если `redis.enabled=true`)
- Kafka (если `kafka.enabled=true`)

По умолчанию эти зависимости отключены, так как предполагается использование внешних сервисов.

## Мониторинг

Чарт настроен для интеграции с Prometheus и Grafana:

- ServiceMonitor для сбора метрик (если `serviceMonitor.enabled=true`)
- PrometheusRules для алертов (если `prometheusRules.enabled=true`)

## Обновление

```bash
# Обновление чарта
helm upgrade auth-service gaiming/auth-service --namespace gaiming \
  --set image.tag=v1.1.0
```

## Удаление

```bash
# Удаление чарта
helm uninstall auth-service --namespace gaiming
```

## Устранение неполадок

### Проверка статуса

```bash
# Проверка статуса развертывания
kubectl get all -l app.kubernetes.io/name=auth-service -n gaiming

# Просмотр логов
kubectl logs -l app.kubernetes.io/name=auth-service -n gaiming
```

### Частые проблемы

1. **Ошибка подключения к базе данных**
   - Проверьте секреты для подключения к базе данных
   - Убедитесь, что база данных доступна

2. **Ошибка подключения к Redis**
   - Проверьте секреты для подключения к Redis
   - Убедитесь, что Redis доступен

3. **Ошибка при запуске**
   - Проверьте логи контейнера
   - Убедитесь, что все необходимые переменные окружения установлены

## Поддержка

Для получения поддержки обратитесь к команде Gaiming:
- Email: team@gaiming.ru
- Slack: #auth-service-support
