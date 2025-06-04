# Консолидированная Спецификация API Платформы

## Введение

Этот документ объединяет спецификации API из различных микросервисов российского аналога платформы Steam.

## 1. API Gateway

Из документа "Спецификация микросервиса API Gateway.txt":

### 4. Функциональные возможности и логика работы

#### 4.1 Жизненный цикл запроса
1.  **Прием запроса**: Внешний балансировщик нагрузки (или Ingress Controller) принимает HTTP/HTTPS запрос от клиента и направляет его на один из доступных экземпляров API Gateway.
2.  **Начальное логирование и метрики**: Запись информации о входящем запросе и инициализация таймера.
3.  **Трассировка**: Инициализация или продолжение распределенного трейса.
4.  **Обработка CORS**: Обработка preflight-запросов и добавление CORS-заголовков.
5.  **Аутентификация**: Валидация JWT-токенов или API-ключей. Извлечение user_id и ролей. Взаимодействие с Auth Service.
6.  **Авторизация (базовая)**: Опциональная проверка прав на уровне шлюза.
7.  **Ограничение скорости (Rate Limiting)**: Применение лимитов.
8.  **Маршрутизация**: Определение внутреннего микросервиса на основе правил.
9.  **Трансформация запроса**: Добавление заголовков (`X-User-Id`, `X-User-Roles`), перезапись пути.
10. **Обнаружение сервиса и балансировка нагрузки**: Выбор экземпляра целевого микросервиса.
11. **Проксирование**: Отправка запроса внутреннему сервису, ожидание ответа.
12. **Обработка ответа от бэкенда**.
13. **Трансформация ответа**: Модификация ответа.
14. **Завершающее логирование и метрики**.
15. **Отправка ответа клиенту**.

#### 4.3 Аутентификация и передача контекста пользователя
- **JWT**: Проверка в заголовке `Authorization: Bearer <token>`.
  - Валидация подписи (с использованием публичного ключа от Auth Service, ключи кэшируются).
  - Проверка срока действия (`exp`).
  - Проверка `iss`, `aud`.
  - Извлечение `sub` (user ID), ролей.
- **API-ключи**: Проверка наличия и валидности.
- **Передача контекста**: Добавление заголовков `X-User-Id`, `X-User-Roles`, `X-Authenticated-By`.

### 5. Конфигурация маршрутизации и API

#### 5.1 Структура внешнего API
- **Аутентификация и управление пользователями**:
  - `/api/v1/auth/*` → Auth Service
  - `/api/v1/users/*` → Account Service
- **Каталог и библиотека игр**:
  - `/api/v1/games/*` → Catalog Service
  - `/api/v1/library/*` → Library Service
- **Платежи и транзакции**:
  - `/api/v1/payments/*` → Payment Service
- **Социальные функции**:
  - `/api/v1/social/*` → Social Service
- **Загрузки и обновления**:
  - `/api/v1/downloads/*` → Download Service
- **Уведомления**:
  - `/api/v1/notifications/*` → Notification Service
  - `/api/v1/notifications/ws` → Notification Service (WebSocket)
- **Аналитика**:
  - `/api/v1/analytics/*` → Analytics Service (для авторизованных пользователей)
- **Разработчики**:
  - `/api/v1/developers/*` → Developer Service
- **Административные функции**:
  - `/api/v1/admin/*` → Admin Service (для администраторов)

#### 5.1.2 Версионирование API
- Через префикс пути (`/api/v1/`, `/api/v2/`).

#### 5.1.3 Специальные эндпоинты API Gateway
- `/api/health` - проверка работоспособности шлюза.
- `/api/status` - расширенная информация о статусе системы (требует прав администратора).
- `/api/docs` - документация API (Swagger/OpenAPI).

#### 5.2.1 Пример конфигурации маршрутов (в формате Kong Gateway)
- **auth-login**: `POST /api/v1/auth/login` → `auth-service`
  - Plugins: `cors`, `rate-limiting` (minute: 10, policy: local)
- **users-profile**: `GET, PUT /api/v1/users/profile` → `account-service`
  - Plugins: `jwt` (verify exp), `cors`, `request-transformer` (add X-User-Id:$(jwt_claims.sub))
- **games-list**: `GET /api/v1/games` → `catalog-service`
  - Plugins: `cors`, `rate-limiting` (minute: 60, policy: local)
- **library-games**: `GET /api/v1/library/games` → `library-service`
  - Plugins: `jwt`, `cors`, `request-transformer` (add X-User-Id)
- **payments-transactions**: `GET, POST /api/v1/payments/transactions` → `payment-service`
  - Plugins: `jwt`, `cors`, `request-transformer` (add X-User-Id), `rate-limiting` (minute: 30)
- **social-friends**: `GET, POST, DELETE /api/v1/social/friends` → `social-service`
  - Plugins: `jwt`, `cors`, `request-transformer` (add X-User-Id)
- **downloads-list**: `GET /api/v1/downloads` → `download-service`
  - Plugins: `jwt`, `cors`, `request-transformer` (add X-User-Id)
- **notifications-list**: `GET /api/v1/notifications` → `notification-service`
  - Plugins: `jwt`, `cors`, `request-transformer` (add X-User-Id)
- **notifications-ws**: `/api/v1/notifications/ws` (protocols: http, https, ws, wss) → `notification-service-ws`
  - Plugins: `jwt`
- **developers-dashboard**: `GET /api/v1/developers` → `developer-service`
  - Plugins: `jwt`, `cors`, `request-transformer` (add X-User-Id), `acl` (allow: developer, admin)
- **admin-dashboard**: `GET, POST, PUT, DELETE /api/v1/admin` → `admin-service`
  - Plugins: `jwt`, `cors`, `request-transformer` (add X-User-Id, X-User-Roles), `acl` (allow: admin), `ip-restriction` (allow: 192.168.0.0/16, 10.0.0.0/8)
---

## 2. Account Service

Из документа "Спецификация микросервиса Account Service.md":

### 5.1 REST API

**Базовый URL**: `/api/v1` (предполагается, что API Gateway маппит `/api/v1/users/*` на Account Service, но в документе Account Service указан префикс `/accounts`)
**Формат данных**: JSON
**Аутентификация**: JWT Bearer Token

**Стандарт ответа (Успех)**:
```json
{
  "status": "success",
  "data": { ... },
  "meta": {
    "pagination": { ... }
  }
}
```

**Стандарт ответа (Ошибка)**:
```json
{
  "status": "error",
  "error": {
    "code": "ERROR_CODE",
    "message": "Описание ошибки.",
    "details": { ... }
  }
}
```

#### 5.1.1 Ресурс: Аккаунты (`/accounts`)
*(Примечание: API Gateway маппит `/api/v1/users/*` на Account Service, но внутренняя маршрутизация Account Service может использовать `/accounts`)*

*   **`POST /accounts`**: Регистрация нового Аккаунта.
    *   Запрос: `{ "username": "...", "email": "...", "password": "..." }` (пароль передается в Auth Service) или `{ "provider": "google", "token": "..." }`.
    *   Ответ: `201 Created`, `data: { "id": "...", "username": "...", "status": "pending" }`.
*   **`GET /accounts/{id}`**: Получение информации об Аккаунте.
    *   Ответ: `200 OK`, `data: { Account object }`.
*   **`GET /accounts/me`**: Получение информации о текущем Аккаунте (на основе JWT).
    *   Ответ: `200 OK`, `data: { Account object }`.
*   **`PUT /accounts/{id}/status`**: Обновление статуса Аккаунта (только Admin).
    *   Запрос: `{ "status": "blocked", "reason": "..." }`.
    *   Ответ: `200 OK`, `data: { Account object }`.
*   **`DELETE /accounts/{id}`**: Удаление Аккаунта (мягкое).
    *   Ответ: `204 No Content`.
*   **`GET /accounts`**: Поиск Аккаунтов (только Admin).
    *   Параметры: `username`, `email`, `status`, `page`, `per_page`, `sort`.
    *   Ответ: `200 OK`, `data: [ { Account object } ], meta: { pagination }`.

#### 5.1.2 Ресурс: Профили (`/accounts/{id}/profile`)

*   **`GET /accounts/{id}/profile`**: Получение Профиля Пользователя.
    *   Ответ: `200 OK`, `data: { Profile object }`.
*   **`GET /accounts/me/profile`**: Получение Профиля текущего Пользователя.
    *   Ответ: `200 OK`, `data: { Profile object }`.
*   **`PUT /accounts/{id}/profile`**: Обновление Профиля.
    *   Запрос: `{ "nickname": "...", "bio": "...", ... }`.
    *   Ответ: `200 OK`, `data: { Profile object }`.
*   **`POST /accounts/{id}/avatar`**: Загрузка Аватара.
    *   Запрос: `multipart/form-data` с файлом.
    *   Ответ: `200 OK`, `data: { "url": "..." }`.
*   **`GET /accounts/{id}/profile/history`**: Получение истории изменений Профиля.
    *   Параметры: `page`, `per_page`.
    *   Ответ: `200 OK`, `data: [ { ProfileHistory object } ], meta: { pagination }`.

#### 5.1.3 Ресурс: Контактная информация (`/accounts/{id}/contact-info`)

*   **`GET /accounts/{id}/contact-info`**: Получение списка контактной информации.
    *   Ответ: `200 OK`, `data: [ { ContactInfo object } ]`.
*   **`POST /accounts/{id}/contact-info`**: Добавление новой контактной информации (email/phone).
    *   Запрос: `{ "type": "email", "value": "...", "visibility": "private" }`.
    *   Ответ: `201 Created`, `data: { ContactInfo object }`.
*   **`PUT /accounts/{id}/contact-info/{contact_id}`**: Обновление контактной информации.
    *   Запрос: `{ "is_primary": true }`.
    *   Ответ: `200 OK`, `data: { ContactInfo object }`.
*   **`DELETE /accounts/{id}/contact-info/{contact_id}`**: Удаление контактной информации.
    *   Ответ: `204 No Content`.
*   **`POST /accounts/{id}/contact-info/{type}/verification-request`**: Запрос кода верификации (`type` = `email` или `phone`).
    *   Ответ: `200 OK`, `data: { "message": "Code sent", "expires_at": "..." }`.
*   **`POST /accounts/{id}/contact-info/{type}/verify`**: Подтверждение кода верификации.
    *   Запрос: `{ "code": "..." }`.
    *   Ответ: `200 OK`, `data: { "message": "Verified successfully" }`.

#### 5.1.4 Ресурс: Настройки (`/accounts/{id}/settings`)

*   **`GET /accounts/{id}/settings`**: Получение всех категорий настроек.
    *   Ответ: `200 OK`, `data: { "privacy": { ... }, "notifications": { ... } }`.
*   **`GET /accounts/{id}/settings/{category}`**: Получение настроек конкретной категории.
    *   Ответ: `200 OK`, `data: { Setting object }`.
*   **`PUT /accounts/{id}/settings/{category}`**: Обновление настроек категории.
    *   Запрос: `{ "settings": { ... } }`.
    *   Ответ: `200 OK`, `data: { Setting object }`.

### 5.2 gRPC API

**Пример `.proto` файла (`account.proto`)**:
```protobuf
syntax = "proto3";

package account.v1;

import "google/protobuf/timestamp.proto";
import "google/protobuf/empty.proto";
import "google/protobuf/struct.proto"; // Для JSON настроек

option go_package = "gen/go/account/v1;accountv1";

service AccountService {
  rpc GetAccount(GetAccountRequest) returns (AccountResponse);
  rpc GetAccounts(GetAccountsRequest) returns (GetAccountsResponse);
  rpc GetProfile(GetProfileRequest) returns (ProfileResponse);
  rpc GetSettings(GetSettingsRequest) returns (SettingsResponse);
  rpc CheckUsernameExists(CheckUsernameExistsRequest) returns (CheckExistsResponse);
  rpc CheckEmailExists(CheckEmailExistsRequest) returns (CheckExistsResponse);
}

message Account {
  string id = 1;
  string username = 2;
  string status = 3;
  google.protobuf.Timestamp created_at = 4;
}

message Profile {
  string id = 1;
  string account_id = 2;
  string nickname = 3;
  string avatar_url = 4;
  string visibility = 5;
}

message Settings {
    string account_id = 1;
    string category = 2;
    google.protobuf.Struct settings = 3;
}

message GetAccountRequest { string id = 1; }
message AccountResponse { Account account = 1; }

message GetAccountsRequest { repeated string ids = 1; }
message GetAccountsResponse { repeated Account accounts = 1; }

message GetProfileRequest { string account_id = 1; }
message ProfileResponse { Profile profile = 1; }

message GetSettingsRequest { string account_id = 1; string category = 2; }
message SettingsResponse { Settings settings = 1; }

message CheckUsernameExistsRequest { string username = 1; }
message CheckEmailExistsRequest { string email = 1; }
message CheckExistsResponse { bool exists = 1; }
```

### 5.4 События (Events)

**Топики Kafka**: `account-events`, `profile-events`

**Пример события `account.created`**:
```json
{
  "specversion": "1.0",
  "type": "com.platform.account.created",
  "source": "/service/account",
  "subject": "urn:account:550e8400-e29b-41d4-a716-446655440000",
  "id": "unique-event-id-uuid",
  "time": "2025-05-24T07:50:00Z",
  "datacontenttype": "application/json",
  "data": {
    "accountId": "550e8400-e29b-41d4-a716-446655440000",
    "username": "user123",
    "email": "user@example.com",
    "status": "pending",
    "registeredAt": "2025-05-24T07:50:00Z"
  }
}
```
**Основные типы событий**:
*   `account.created`
*   `account.status.updated` (включая blocked, deleted, activated)
*   `account.contact.added`
*   `account.contact.updated`
*   `account.contact.verified`
*   `account.contact.verification.requested`
*   `profile.updated`
*   `profile.avatar.updated`
*   `account.settings.updated`
---

## 3. Auth Service

Из документа "Спецификация микросервиса Auth Service.md":

### 5.1 REST API

**Базовый URL**: `/api/v1/auth`

#### 5.1.2 Эндпоинты аутентификации
*(Примечание: В документе Auth Service некоторые эндпоинты дублируют те, что указаны в API Gateway для `/api/v1/auth/*`. Здесь приводятся эндпоинты, как они описаны в спецификации Auth Service, предполагая, что API Gateway их соответствующим образом маршрутизирует.)*

| Метод | Путь | Описание | Аутентификация |
|-------|------|----------|----------------|
| POST | /register | Регистрация нового пользователя | Нет |
| POST | /login | Вход в систему | Нет |
| POST | /logout | Выход из системы | Да (Bearer Token) |
| POST | /refresh-token | Обновление токена доступа | Нет (только refresh token в теле) |
| POST | /verify-email | Подтверждение email | Нет (токен верификации в запросе) |
| POST | /resend-verification | Повторная отправка кода подтверждения | Нет |
| POST | /forgot-password | Запрос на сброс пароля | Нет |
| POST | /reset-password | Сброс пароля | Нет (токен сброса в запросе) |
| POST | /2fa/enable | Включение 2FA | Да |
| POST | /2fa/verify | Проверка кода 2FA | Да (с временным токеном или основным + код) |
| POST | /2fa/disable | Отключение 2FA | Да |

#### 5.1.3 Эндпоинты управления пользователями (через Auth Service)
*(Примечание: Основное управление пользователями должно быть в Account Service. Auth Service может предоставлять некоторые эндпоинты, тесно связанные с аутентификацией или безопасностью аккаунта)*

| Метод | Путь | Описание | Аутентификация |
|-------|------|----------|----------------|
| GET | /me | Получение информации о текущем пользователе (из токена) | Да |
| PUT | /me/password | Изменение пароля текущего пользователя | Да |
| GET | /me/sessions | Получение списка активных сессий текущего пользователя | Да |
| POST | /logout-all | Выход из всех устройств (отзыв всех refresh токенов) | Да |

#### 5.1.5 Эндпоинты для внешней аутентификации (Telegram)
| Метод | Путь | Описание | Аутентификация |
|-------|------|----------|----------------|
| POST | /telegram-login | Аутентификация через Telegram | Нет (данные от Telegram Login Widget в теле) |

#### 5.1.6 Эндпоинты для разработчиков (API ключи)
*(Примечание: Управление API ключами может быть вынесено в Developer Service, Auth Service отвечает за их валидацию)*
| Метод | Путь | Описание | Аутентификация |
|-------|------|----------|----------------|
| POST | /api-keys/validate | Проверка API ключа (внутренний эндпоинт для API Gateway) | API Key |


#### 5.1.7 Административные эндпоинты (через Auth Service)
*(Примечание: Основные административные функции по пользователям в Account/Admin Service. Auth Service может отвечать за управление ролями/разрешениями и аудит безопасности.)*

| Метод | Путь | Описание | Аутентификация |
|-------|------|----------|----------------|
| GET | /admin/users | Получение списка пользователей (для админов) | Да (Admin role) |
| GET | /admin/users/{id} | Получение информации о пользователе | Да (Admin role) |
| PUT | /admin/users/{id}/status | Обновление статуса пользователя (например, block/unblock) | Да (Admin role) |
| GET | /admin/roles | Получение списка ролей | Да (Admin role) |
| POST | /admin/roles | Создание новой роли | Да (Admin role) |
| PUT | /admin/roles/{id} | Обновление роли | Да (Admin role) |
| DELETE | /admin/roles/{id} | Удаление роли | Да (Admin role) |
| POST | /admin/users/{id}/roles | Назначение роли пользователю | Да (Admin role) |
| DELETE | /admin/users/{id}/roles/{role_id} | Удаление роли у пользователя | Да (Admin role) |
| GET | /admin/audit-logs | Получение журнала аудита безопасности | Да (Admin role) |

#### Валидация и проверка прав (внутренние эндпоинты для API Gateway)
| Метод | Путь | Описание | Параметры запроса | Ответ |
|-------|------|----------|------------------|-------|
| POST | /validate-token | Проверка валидности токена | `token` (в заголовке Authorization) | `200 OK` с данными пользователя (user_id, roles, permissions, expires_at) или `401 Unauthorized` |
| POST | /check-permission | Проверка наличия разрешения | `user_id`, `permission`, `resource_id` (опционально) | `200 OK` с `{"has_permission": true/false}` или `401/403` |

### 5.2 gRPC API

**Файл**: `auth.proto`
```protobuf
syntax = "proto3";

package auth;

option go_package = "github.com/gameplatform/auth-service/proto/auth";

import "google/protobuf/timestamp.proto";
import "google/protobuf/empty.proto";

service AuthService {
  rpc ValidateToken(ValidateTokenRequest) returns (ValidateTokenResponse);
  rpc CheckPermission(CheckPermissionRequest) returns (CheckPermissionResponse);
  rpc GetUserInfo(GetUserInfoRequest) returns (UserInfo);
  // ... другие методы, как в спецификации ...
  rpc HealthCheck(google.protobuf.Empty) returns (HealthCheckResponse);
}

message ValidateTokenRequest {
  string token = 1;
}

message ValidateTokenResponse {
  bool valid = 1;
  UserInfo user = 2;
  repeated string roles = 3;
  repeated string permissions = 4;
  google.protobuf.Timestamp expires_at = 5;
}

message CheckPermissionRequest {
  string user_id = 1;
  string permission = 2;
  string resource_id = 3;
}

message CheckPermissionResponse {
  bool has_permission = 1;
}

message GetUserInfoRequest {
  string user_id = 1;
}

message UserInfo {
  string id = 1;
  string username = 2;
  string email = 3;
  string status = 4; // "active", "blocked", "pending_verification"
  google.protobuf.Timestamp created_at = 5;
  google.protobuf.Timestamp email_verified_at = 6;
  google.protobuf.Timestamp last_login_at = 7;
  repeated string roles = 8;
}

message HealthCheckResponse {
  enum Status {
    UNKNOWN = 0;
    SERVING = 1;
    NOT_SERVING = 2;
  }
  Status status = 1;
}

// ... определения для GetUsers, BlockUser, AssignRole и т.д. ...
```

### 5.3 События (Events)

**Топик Kafka**: `auth-events`
**Формат**: CloudEvents JSON

**Публикуемые события**:
*   `auth.user.registered`: `{"user_id": "uuid", "email": "string", "username": "string", "created_at": "timestamp"}`
*   `auth.user.email_verified`: `{"user_id": "uuid", "email": "string", "verified_at": "timestamp"}`
*   `auth.user.role_changed`: `{"user_id": "uuid", "old_roles": ["role1"], "new_roles": ["role1", "role2"], "changed_by": "uuid", "changed_at": "timestamp"}`
*   `auth.user.password_reset_requested`: `{"user_id": "uuid", "email": "string", "requested_at": "timestamp"}`
*   `auth.user.password_changed`: `{"user_id": "uuid", "changed_at": "timestamp"}`
*   `auth.user.account_locked`: `{"user_id": "uuid", "reason": "string", "locked_at": "timestamp", "unlock_at": "timestamp"}`
*   `auth.user.account_unlocked`: `{"user_id": "uuid", "unlocked_by": "uuid", "unlocked_at": "timestamp"}`
*   `auth.user.suspicious_login_detected`: `{"user_id": "uuid", "ip_address": "string", "user_agent": "string", "timestamp": "timestamp"}`
*   `auth.user.login_success`: `{"user_id": "uuid", "ip_address": "string", "user_agent": "string", "timestamp": "timestamp"}`
*   `auth.user.login_failed`: `{"login_attempt": "string", "ip_address": "string", "user_agent": "string", "timestamp": "timestamp"}`
*   `auth.session.created`: `{"session_id": "uuid", "user_id": "uuid", "ip_address": "string", "user_agent": "string", "created_at": "timestamp"}`
*   `auth.session.revoked`: `{"session_id": "uuid", "user_id": "uuid", "revoked_at": "timestamp"}`

**Потребляемые события**:
*   `account.user.profile_updated` (из Account Service): для обновления кэшированных данных пользователя, если такие есть.
*   `admin.user.force_logout` (из Admin Service): для принудительного завершения сессий пользователя.
*   `admin.user.block` (из Admin Service): для блокировки пользователя.
*   `admin.user.unblock` (из Admin Service): для разблокировки пользователя.

### 5.4 Форматы данных

#### JWT Payload
```json
{
  "sub": "f47ac10b-58cc-4372-a567-0e02b2c3d479", // User ID
  "iss": "auth-service",
  "aud": ["api-gateway"],
  "exp": 1716561600, // Expiration Time (Unix timestamp)
  "iat": 1716558000, // Issued At (Unix timestamp)
  "jti": "a1b2c3d4-e5f6-4a5b-9c8d-0e1f2a3b4c5d", // JWT ID
  "username": "ivan_petrov",
  "roles": ["user", "developer"],
  "permissions": ["library.read", "catalog.read", "developer.games.write"],
  "session_id": "b2c3d4e5-f6a7-8b9c-0d1e-2f3a4b5c6d7e"
}
```
---

## 4. Catalog Service

Из документа "Спецификация микросервиса Catalog Service.txt":

### 6. Структура данных и API

#### 6.3 Спецификация REST API

**Основные принципы:**
- **Base URL**: `/api/v1/catalog` (предполагается, что API Gateway маппит на этот сервис)
- **Формат**: JSON
- **Аутентификация**: JWT (передается API Gateway)
- **Авторизация**: RBAC (роли из `X-User-Roles`)
- **Пагинация**: `page`, `limit`.
- **Фильтрация/Сортировка**: Query-параметры.
- **Именование**: snake_case.
- **Даты**: ISO 8601 UTC.
- **Локализация**: Заголовок `Accept-Language`.

**Эндпоинты (Примеры):**

*   **`GET /products`**: Получение списка продуктов.
    *   Query Params: `page`, `limit`, `query` (поиск), `genre_slug`, `tag_slug`, `category_slug`, `developer_id`, `publisher_id`, `platform`, `min_price`, `max_price`, `has_discount`, `release_date_from`, `release_date_to`, `age_rating`, `sort_by` (release_date, price, rating, popularity, name), `sort_order` (asc, desc).
    *   Ответ: `200 OK` (Список `ProductListItemDTO`, метаданные пагинации), `400 Bad Request`.
*   **`GET /products/{product_id}`**: Получение деталей продукта.
    *   Ответ: `200 OK` (`ProductDetailsDTO`), `404 Not Found`.
*   **`GET /genres`**: Получение списка жанров.
*   **`GET /tags`**: Получение списка тегов.
*   **`GET /categories`**: Получение списка категорий.
*   **`GET /products/{product_id}/achievements`**: Получение метаданных достижений.
*   **`GET /recommendations`**: Получение рекомендаций.
    *   Query Params: `type` (popular, new, personalized, similar_to={product_id}), `limit`.

*   **`POST /manage/products`**: Создание продукта (Права: `admin`, `developer`, `publisher`).
*   **`PUT /manage/products/{product_id}`**: Обновление продукта (Права: `admin`, `developer`¹, `publisher`¹).
*   **`PATCH /manage/products/{product_id}/status`**: Изменение статуса продукта (Права: `admin`, `moderator`).
*   **`POST /manage/products/{product_id}/prices`**: Добавление/обновление цены (Права: `admin`, `developer`¹, `publisher`¹).
*   **`POST /manage/products/{product_id}/media`**: Добавление медиа (Права: `admin`, `developer`¹, `publisher`¹).
*   **`POST /manage/products/{product_id}/achievements`**: Добавление/обновление достижений (Права: `admin`, `developer`¹, `publisher`¹).
*   **`POST /manage/genres`**, **`PUT /manage/genres/{id}`**: Управление жанрами (Права: `admin`).
*   **`POST /manage/tags`**, **`PUT /manage/tags/{id}`**: Управление тегами (Права: `admin`).

*(¹ - только для своих продуктов)*

#### 6.4 Спецификация gRPC API

**Основные принципы:**
- **Пакет**: `catalog.v1`
- **Аутентификация/Авторизация**: Через метаданные gRPC.
- **Ошибки**: Стандартные коды ошибок gRPC.
- **Именование**: CamelCase для полей Protobuf.

**Пример Protobuf (`catalog/v1/catalog.proto`):**
```protobuf
syntax = "proto3";

package catalog.v1;

import "google/protobuf/timestamp.proto";
import "google/protobuf/wrappers.proto";
// import "google/rpc/status.proto"; // Не указан в документе, но обычно используется

option go_package = "github.com/yourorg/yourproject/gen/go/catalog/v1;catalogv1";

service CatalogInternalService {
  rpc GetProductInternal(GetProductInternalRequest) returns (GetProductInternalResponse);
  rpc GetProductsInternal(GetProductsInternalRequest) returns (GetProductsInternalResponse);
  rpc GetProductPrice(GetProductPriceRequest) returns (GetProductPriceResponse);
  rpc CreateProduct(CreateProductRequest) returns (CreateProductResponse);
  rpc UpdateProduct(UpdateProductRequest) returns (UpdateProductResponse);
  rpc GetAchievementMetadata(GetAchievementMetadataRequest) returns (GetAchievementMetadataResponse);
  // ... другие методы для управления ценами, медиа, таксономией ...
}

message LocalizedString {
  map<string, string> values = 1; // {"ru": "Текст", "en": "Text"}
}

message ProductInternal {
  string id = 1; // UUID
  string type = 2; // "game", "dlc", etc.
  LocalizedString titles = 3;
  // ... другие поля, необходимые для внутреннего использования
  google.protobuf.Timestamp created_at = 50;
  google.protobuf.Timestamp updated_at = 51;
}

message GetProductInternalRequest {
  string product_id = 1; // UUID
  repeated string fields = 2;
}

message GetProductInternalResponse {
  ProductInternal product = 1;
}

message GetProductsInternalRequest {
  repeated string product_ids = 1; // UUIDs
  repeated string fields = 2;
}

message GetProductsInternalResponse {
  repeated ProductInternal products = 1;
}

message Price {
  string currency_code = 1; // "RUB", "USD"
  string amount = 2; // Используем строку для точности decimal
}

message GetProductPriceRequest {
  string product_id = 1; // UUID
  string region_code = 2; // "RU", "US", "DEFAULT"
  google.protobuf.StringValue user_id = 3;
}

message GetProductPriceResponse {
  string product_id = 1;
  Price base_price = 2;
  Price final_price = 3;
  google.protobuf.Int32Value discount_percent = 4;
  bool is_discounted = 5;
}

message CreateProductRequest {
  // ... поля для создания продукта ...
  string request_id = 100; // Для идемпотентности
}

message CreateProductResponse {
  string product_id = 1; // UUID созданного продукта
}

message UpdateProductRequest {
  // ... поля для обновления продукта ...
  string product_id = 1;
}

message UpdateProductResponse {
  ProductInternal product = 1;
}

message GetAchievementMetadataRequest {
  string product_id = 1;
}

message AchievementMetadata {
    string id = 1;
    string product_id = 2;
    string api_name = 3;
    LocalizedString names = 4;
    LocalizedString descriptions = 5;
    string icon_url = 6;
    string icon_gray_url = 7;
    bool is_hidden = 8;
    int32 display_order = 9;
    double global_progress = 10;
}

message GetAchievementMetadataResponse {
    repeated AchievementMetadata achievements = 1;
}
```

#### 6.5 Форматы событий (Kafka/CloudEvents)

**Топики**: `catalog.product.created`, `catalog.price.updated`, etc.
**Формат**: CloudEvents v1.0 JSON

**Пример события `product.created`:**
```json
{
  "specversion": "1.0",
  "type": "com.yourplatform.catalog.product.created",
  "source": "/service/catalog",
  "subject": "product/a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "id": "unique-event-id-123",
  "time": "2025-05-25T16:48:00Z",
  "datacontenttype": "application/json",
  "data": {
    "product_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "type": "game",
    "status": "in_review",
    "titles": {"ru": "Новая Игра", "en": "New Game"},
    "developer_ids": ["dev-uuid-1"],
    "publisher_id": "pub-uuid-1",
    "created_at": "2025-05-25T16:48:00Z"
  }
}
```
**Основные события**:
- `catalog.product.created`
- `catalog.product.updated`
- `catalog.product.status.changed`
- `catalog.product.visibility.changed`
- `catalog.product.deleted`
- `catalog.price.updated`
- `catalog.discount.started`
- `catalog.discount.ended`
- `catalog.genre.created` / `updated` / `deleted`
- `catalog.tag.created` / `updated` / `deleted`
- `catalog.achievement.metadata.updated`
---

## 5. Developer Service

Из документа "Спецификация микросервиса Developer Service.txt":

### 5.2 API Endpoints (REST)

**Префикс**: `/api/v1/developer`
**Аутентификация**: JWT (валидируется Auth Service)
**Авторизация**: `developer_id` и роль пользователя в команде.

**Аккаунты разработчиков:**

*   `POST /accounts` - Регистрация новой компании-разработчика.
*   `GET /accounts/me` - Получение информации о своей компании.
*   `PUT /accounts/me` - Обновление информации о своей компании.
*   `GET /accounts/me/team` - Получение списка членов команды.
*   `POST /accounts/me/team` - Приглашение нового члена команды.
*   `PUT /accounts/me/team/{user_id}` - Изменение роли члена команды.
*   `DELETE /accounts/me/team/{user_id}` - Удаление члена команды.

**Игры:**

*   `POST /games` - Создание нового проекта игры.
*   `GET /games` - Получение списка игр разработчика.
*   `GET /games/{game_id}` - Получение детальной информации об игре.
*   `PUT /games/{game_id}` - Обновление базовой информации об игре (например, статус).
*   `DELETE /games/{game_id}` - Удаление проекта игры (если возможно).

**Версии игр (Билды):**

*   `POST /games/{game_id}/versions` - Инициирование загрузки новой версии (возвращает URL для загрузки в S3).
*   `PUT /games/{game_id}/versions/{version_id}` - Обновление статуса версии (например, после завершения загрузки), добавление changelog.
*   `GET /games/{game_id}/versions` - Получение списка версий игры.
*   `GET /games/{game_id}/versions/{version_id}` - Получение информации о конкретной версии.

**Метаданные игр:**

*   `GET /games/{game_id}/metadata` - Получение метаданных игры.
*   `PUT /games/{game_id}/metadata` - Обновление метаданных игры.
*   `POST /games/{game_id}/media` - Загрузка медиа-файла (скриншот, видео) (возвращает URL).

**Ценообразование:**

*   `GET /games/{game_id}/pricing` - Получение информации о ценах и скидках.
*   `PUT /games/{game_id}/pricing` - Обновление цен и настройка скидок.

**Публикация:**

*   `POST /games/{game_id}/versions/{version_id}/submit` - Отправка версии на модерацию.
*   `POST /games/{game_id}/publish` - Публикация утвержденной игры/версии.
*   `POST /games/{game_id}/unpublish` - Снятие игры с публикации.

**Аналитика:**

*   `GET /analytics/summary` - Получение сводной аналитики по всем играм.
*   `GET /analytics/games/{game_id}` - Получение детальной аналитики по конкретной игре (параметры: период, метрики).
*   `GET /analytics/reports` - Запрос на генерацию отчетов.

**Финансы:**

*   `GET /finance/balance` - Получение текущего баланса.
*   `GET /finance/transactions` - Получение истории транзакций (начислений).
*   `GET /finance/payouts` - Получение истории выплат.
*   `POST /finance/payouts` - Запрос на новую выплату.
*   `GET /finance/settings` - Получение платежных реквизитов.
*   `PUT /finance/settings` - Обновление платежных реквизитов.

**API Ключи:**

*   `POST /apikeys` - Создание нового API ключа.
*   `GET /apikeys` - Получение списка API ключей (без самих ключей, только информация).
*   `DELETE /apikeys/{key_id}` - Отзыв (деактивация) API ключа.
---

## 6. Download Service

Из документа "Спецификация микросервиса Download Service.txt":

### 5. Структура данных и API

#### 5.1 Модели данных

##### Download (Загрузка)
```go
type Download struct {
    ID            string       `json:"id" db:"id"`
    UserID        string       `json:"user_id" db:"user_id"`
    GameID        string       `json:"game_id" db:"game_id"`
    Status        DownloadStatus `json:"status" db:"status"` // queued, preparing, downloading, paused, completed, failed, cancelled, verifying
    Progress      float64      `json:"progress" db:"progress"`
    CurrentSpeed  int64        `json:"current_speed" db:"current_speed"` // bytes/sec
    AverageSpeed  int64        `json:"average_speed" db:"average_speed"` // bytes/sec
    TotalSize     int64        `json:"total_size" db:"total_size"`       // bytes
    DownloadedSize int64       `json:"downloaded_size" db:"downloaded_size"` // bytes
    Priority      int          `json:"priority" db:"priority"`
    CreatedAt     time.Time    `json:"created_at" db:"created_at"`
    UpdatedAt     time.Time    `json:"updated_at" db:"updated_at"`
    CompletedAt   *time.Time   `json:"completed_at,omitempty" db:"completed_at"`
    EstimatedTimeLeft int64    `json:"estimated_time_left" db:"estimated_time_left"` // seconds
    Items         []DownloadItem `json:"items,omitempty" db:"-"`
}
```

##### DownloadItem (Элемент загрузки)
```go
type DownloadItem struct {
    ID            string       `json:"id" db:"id"`
    DownloadID    string       `json:"download_id" db:"download_id"`
    FileID        string       `json:"file_id" db:"file_id"` // ID из FileMetadata
    FileName      string       `json:"file_name" db:"file_name"`
    FilePath      string       `json:"file_path" db:"file_path"` // Относительный путь установки
    FileSize      int64        `json:"file_size" db:"file_size"`
    FileHash      string       `json:"file_hash" db:"file_hash"` // SHA-256
    Status        string       `json:"status" db:"status"` // queued, downloading, completed, failed
    Progress      float64      `json:"progress" db:"progress"`
    Priority      int          `json:"priority" db:"priority"`
    DownloadedSize int64       `json:"downloaded_size" db:"downloaded_size"`
    RetryCount    int          `json:"retry_count" db:"retry_count"`
    CDNSource     string       `json:"cdn_source,omitempty" db:"cdn_source"`
}
```

##### Update (Обновление) - метаданные, получаемые от Catalog Service
```go
type Update struct {
    ID            string       `json:"id" db:"id"` // ID обновления
    GameID        string       `json:"game_id" db:"game_id"`
    FromVersion   string       `json:"from_version" db:"from_version"`
    ToVersion     string       `json:"to_version" db:"to_version"`
    UpdateType    string       `json:"update_type" db:"update_type"` // "full", "delta"
    IsCritical    bool         `json:"is_critical" db:"is_critical"`
    TotalSize     int64        `json:"total_size" db:"total_size"` // Размер полного обновления
    DeltaSize     int64        `json:"delta_size,omitempty" db:"delta_size"` // Размер дельта-патча
    ReleaseNotes  string       `json:"release_notes,omitempty" db:"release_notes"`
}
```

##### FileMetadata (Метаданные файла) - получаемые от Catalog Service
```go
type FileMetadata struct {
    ID            string       `json:"id" db:"id"` // Уникальный ID файла в системе
    GameID        string       `json:"game_id" db:"game_id"`
    FileName      string       `json:"file_name" db:"file_name"`
    FilePath      string       `json:"file_path" db:"file_path"` // Относительный путь в структуре игры
    FileSize      int64        `json:"file_size" db:"file_size"`
    FileHash      string       `json:"file_hash" db:"file_hash"` // SHA-256
    Version       string       `json:"version" db:"version"`
    IsExecutable  bool         `json:"is_executable" db:"is_executable"`
    IsOptional    bool         `json:"is_optional" db:"is_optional"`
    CDNLocations  []string     `json:"cdn_locations,omitempty" db:"-"` // Список URL на CDN
}
```

#### 5.3 REST API (для клиентского приложения)

**Префикс**: `/api/v1/downloads` (через API Gateway)

##### 5.3.1 Управление загрузками
*   `POST /` - Инициирование загрузки игры или обновления.
    *   Тело запроса: `{ "game_id": "uuid", "version_id": "uuid", "type": "game|update", "install_path": "string" }`
    *   Ответ: `202 Accepted` с объектом `Download`.
*   `GET /` - Получение списка текущих и недавних загрузок пользователя.
    *   Ответ: `200 OK` с `{ "items": [Download], "total": int }`.
*   `GET /{download_id}` - Получение информации о конкретной загрузке.
    *   Ответ: `200 OK` с объектом `Download`.
*   `PATCH /{download_id}` - Управление статусом загрузки (pause, resume, cancel).
    *   Тело запроса: `{ "action": "pause|resume|cancel" }`
    *   Ответ: `200 OK` с обновленным объектом `Download`.
*   `PATCH /{download_id}/priority` - Изменение приоритета загрузки.
    *   Тело запроса: `{ "priority": int }` (например, 1 - высокий, 5 - низкий)
    *   Ответ: `200 OK`.

##### 5.3.2 Управление обновлениями
*   `GET /updates/check` - Проверка наличия обновлений для установленных игр.
    *   Query Params: `game_ids` (список ID игр, опционально).
    *   Ответ: `200 OK` с `{ "updates_available": [Update] }`.
*   `POST /updates/apply` - Инициирование установки обновления.
    *   Тело запроса: `{ "update_id": "uuid", "game_id": "uuid" }`
    *   Ответ: `202 Accepted` с объектом `Download` (для загрузки обновления).

##### 5.3.3 Проверка целостности
*   `POST /verification` - Инициирование проверки целостности файлов установленной игры.
    *   Тело запроса: `{ "game_id": "uuid", "install_path": "string" }`
    *   Ответ: `202 Accepted` с `{ "verification_id": "uuid" }`.
*   `GET /verification/{verification_id}` - Получение результатов проверки.
    *   Ответ: `200 OK` с объектом `VerificationResult`.
*   `POST /verification/{verification_id}/fix` - Инициирование исправления проблем целостности (загрузка поврежденных/отсутствующих файлов).
    *   Ответ: `202 Accepted` с объектом `Download`.

##### 5.3.4 Настройки загрузки
*   `GET /settings` - Получение текущих настроек загрузки пользователя (лимиты скорости, расписание).
    *   Ответ: `200 OK`.
*   `PATCH /settings` - Обновление настроек загрузки.
    *   Тело запроса: `{ "max_download_speed_bps": int64, "bandwidth_schedule_enabled": bool, "schedule_rules": [...] }`
    *   Ответ: `200 OK`.

##### 5.3.5 WebSocket API для отслеживания прогресса
*   `WebSocket /ws/downloads` - Подписка на обновления о прогрессе загрузок в реальном времени.
    *   Сообщения от сервера: `{ "download_id": "uuid", "progress": float64, "status": "string", "current_speed_bps": int64, "eta_seconds": int64 }`

#### 5.4 gRPC API (для межсервисного взаимодействия)

**Сервисы**:
*   `DownloadServiceInternal`
*   `UpdateServiceInternal`
*   `VerificationServiceInternal`

**Примерные методы**:
*   `rpc RequestDownload(RequestDownloadArgs) returns (DownloadStatusResponse)`: Для Catalog/Library Service, чтобы инициировать загрузку от имени пользователя.
*   `rpc GetFileInfo(FileInfoArgs) returns (FileMetadataResponse)`: Для получения информации о файлах игры.
*   `rpc ReportCDNPerformance(CDNPerformanceArgs) returns (Empty)`: Для сбора данных о производительности CDN.
*   `rpc NotifyInstallStatus(InstallStatusArgs) returns (Empty)`: Уведомление Library Service о статусе установки.
---

## 7. Library Service

Из документа "Спецификация микросервиса Library Service.md":

### 5. Структура данных и API

#### 5.1 Модели данных (Основные сущности)

##### UserLibraryItem
```json
{
  "id": "uuid",
  "user_id": "uuid",
  "game_id": "uuid",
  "acquisition_date": "string($date-time)", // ISO 8601
  "acquisition_type": "string", // enum: purchase, gift, subscription, free
  "is_hidden": "boolean",
  "is_favorite": "boolean",
  "last_played_at": "string($date-time)", // ISO 8601
  "total_playtime_seconds": "integer",
  "installation_status": "string", // enum: not_installed, installing, installed, updating, failed
  "platform": "string", // enum: windows, macos, linux, android, ios
  "categories": ["string"], // Пользовательские категории
  "notes": "string",
  "created_at": "string($date-time)",
  "updated_at": "string($date-time)"
}
```

##### PlaytimeSession
```json
{
  "id": "uuid",
  "user_id": "uuid",
  "game_id": "uuid",
  "start_time": "string($date-time)",
  "end_time": "string($date-time)", // null для активных
  "duration_seconds": "integer", // null для активных
  "device_id": "string",
  "platform": "string",
  "is_active": "boolean",
  "created_at": "string($date-time)",
  "updated_at": "string($date-time)"
}
```

##### UserAchievement
```json
{
  "id": "uuid",
  "user_id": "uuid",
  "achievement_id": "uuid", // Ссылка на достижение в Catalog Service
  "game_id": "uuid",
  "unlocked_at": "string($date-time)",
  "progress": "integer", // Для достижений с прогрессом
  "is_unlocked": "boolean",
  "created_at": "string($date-time)",
  "updated_at": "string($date-time)"
}
```

##### WishlistItem
```json
{
  "id": "uuid",
  "user_id": "uuid",
  "game_id": "uuid",
  "added_at": "string($date-time)",
  "priority": "integer",
  "notes": "string",
  "created_at": "string($date-time)",
  "updated_at": "string($date-time)"
}
```

##### SavegameMetadata
```json
{
  "id": "uuid",
  "user_id": "uuid",
  "game_id": "uuid",
  "save_name": "string",
  "timestamp": "string($date-time)",
  "version": "integer",
  "file_key": "string", // Ключ файла в S3
  "file_size_bytes": "integer",
  "device_id": "string",
  "platform": "string",
  "is_latest": "boolean",
  "created_at": "string($date-time)",
  "updated_at": "string($date-time)"
}
```

#### 5.2 REST API (v1)

**Базовый URL**: `/api/v1/library`
**Аутентификация**: JWT Bearer Token

*   **Библиотека**
    *   `GET /` - Получить библиотеку текущего пользователя (с фильтрацией, сортировкой, пагинацией)
    *   `GET /{game_id}` - Получить информацию о конкретной игре в библиотеке
    *   `PATCH /{game_id}` - Обновить метаданные игры в библиотеке (скрыть, добавить в избранное, категории)
*   **Игровое время**
    *   `POST /playtime/start` - Начать игровую сессию
    *   `POST /playtime/heartbeat` - Отправить пульсацию активной сессии
    *   `POST /playtime/end` - Завершить игровую сессию
    *   `GET /playtime/stats` - Получить статистику игрового времени
*   **Достижения**
    *   `GET /achievements` - Получить достижения пользователя (с фильтрацией по игре)
    *   `POST /achievements/unlock` - Зарегистрировать получение достижения
*   **Список желаемого**
    *   `GET /wishlist` - Получить список желаемого
    *   `POST /wishlist` - Добавить игру в список желаемого
    *   `DELETE /wishlist/{game_id}` - Удалить игру из списка желаемого
    *   `PATCH /wishlist/{game_id}` - Обновить элемент списка
*   **Сохранения**
    *   `GET /savegames` - Получить метаданные сохранений (с фильтрацией по игре)
    *   `POST /savegames/upload-url` - Получить URL для загрузки сохранения
    *   `POST /savegames/confirm-upload` - Подтвердить загрузку сохранения
    *   `POST /savegames/download-url` - Получить URL для скачивания сохранения
    *   `DELETE /savegames/{save_id}` - Удалить сохранение
*   **Настройки игр**
    *   `GET /settings/{game_id}` - Получить настройки для игры
    *   `PUT /settings/{game_id}` - Сохранить настройки для игры

#### 5.3 gRPC API (v1)

**Файл**: `/api/proto/v1/library.proto` (и аналогичные для playtime, achievement, savegame, wishlist)

*   **LibraryQueryService**
    *   `GetLibrary(GetUserLibraryRequest) returns (GetUserLibraryResponse)`
    *   `CheckGameAccess(CheckGameAccessRequest) returns (CheckGameAccessResponse)`
    *   `GetPlaytimeStats(GetUserPlaytimeRequest) returns (GetUserPlaytimeResponse)`
    *   `GetUserAchievements(GetUserAchievementsRequest) returns (GetUserAchievementsResponse)`

#### 5.4 WebSocket API

**Эндпоинт**: `/ws/v1/notifications` (через API Gateway)
**Формат сообщений**: JSON (`event_type`, `payload`)
**События для клиента**:
*   `library.updated`
*   `playtime.updated`
*   `achievement.unlocked`
*   `wishlist.updated`
*   `savegame.sync.status`
*   `notification.new`

### 11. Обработка событий (Kafka)

**Формат**: CloudEvents JSON

**Публикуемые события**:
*   `library.game.added`: `{ "user_id", "game_id", "acquisition_type" }`
*   `library.game.hidden`: `{ "user_id", "game_id", "is_hidden" }`
*   `library.achievement.unlocked`: `{ "user_id", "achievement_id", "game_id", "unlocked_at" }`
*   `library.playtime.updated`: `{ "user_id", "game_id", "total_playtime_seconds", "last_played_at" }`
*   `library.wishlist.item.added`: `{ "user_id", "game_id" }`
*   `library.wishlist.item.removed`: `{ "user_id", "game_id" }`
*   `library.savegame.synchronized`: `{ "user_id", "game_id", "save_id", "timestamp" }`

**Потребляемые события**:
*   `payment.purchase.completed` (от Payment Service) → Добавить игру в библиотеку.
*   `catalog.game.updated` (от Catalog Service) → Обновить кэш метаданных.
*   `catalog.achievement.updated` (от Catalog Service) → Обновить кэш метаданных.
*   `download.game.installed` (от Download Service) → Обновить `installation_status`.
*   `download.game.uninstalled` (от Download Service) → Обновить `installation_status`.
*   `account.user.deleted` (от Account Service) → Анонимизировать/удалить данные.

---

## 8. Notification Service

Из документа "Спецификация микросервиса Notification Service.txt":

### 5. Структура данных и API

#### 5.1 API Endpoints (REST пример)

**Префикс**: `/api/v1/notifications`
**Аутентификация**: JWT (для большинства эндпоинтов)
**Авторизация**: Роли (user, admin, marketer, service)

##### 5.1.1 Управление шаблонами (Роли: admin, service)
*   `POST /templates`: Создать новый шаблон.
    *   Тело: `{ "name": "welcome_email", "channel_type": "email", "language_code": "ru", "subject": "Добро пожаловать", "body": "Здравствуйте, {{.UserName}}!", "variables": {"UserName": "string"} }`
*   `GET /templates`: Получить список шаблонов.
*   `GET /templates/{id}`: Получить шаблон по ID.
*   `PUT /templates/{id}`: Обновить шаблон.
*   `DELETE /templates/{id}`: Удалить шаблон.

##### 5.1.2 Управление пользовательскими предпочтениями (Роли: user, admin, service)
*   `GET /preferences/{user_id}`: Получить предпочтения пользователя.
*   `PUT /preferences/{user_id}`: Обновить предпочтения пользователя.
    *   Тело: `{ "notification_type": "marketing_promo", "allowed_channels": ["email", "push"], "is_enabled": true }`
*   `GET /preferences/{user_id}/types`: Получить все типы уведомлений с настройками пользователя.
*   `POST /preferences/{user_id}/unsubscribe`: Глобальная отписка.
    *   Тело: `{ "channel_type": "all_marketing", "reason": "Not interested" }`

##### 5.1.3 Управление маркетинговыми кампаниями (Роли: admin, marketer)
*   `POST /campaigns`: Создать новую кампанию.
    *   Тело: `{ "name": "Summer Sale 2025", "target_segment": {...}, "template_ids": ["uuid1"], "schedule": {"type": "one_time", "scheduled_at": "2025-06-01T10:00:00Z"} }`
*   `GET /campaigns`: Получить список кампаний.
*   `GET /campaigns/{id}`: Получить кампанию по ID.
*   `PUT /campaigns/{id}`: Обновить кампанию.
*   `POST /campaigns/{id}/start`: Запустить кампанию.
*   `POST /campaigns/{id}/stop`: Остановить кампанию.
*   `GET /campaigns/{id}/stats`: Получить статистику по кампании.

##### 5.1.4 Управление устройствами (Роли: user, service)
*   `POST /devices`: Зарегистрировать новый device token.
    *   Тело: `{ "user_id": "uuid", "platform": "android", "token": "fcm_token_string" }`
*   `PUT /devices/{id}`: Обновить статус device token.
    *   Тело: `{ "is_active": false }`
*   `GET /devices/user/{user_id}`: Получить все устройства пользователя.

##### 5.1.5 Отправка уведомлений (Роли: service, admin)
*   `POST /send`: Отправить одиночное уведомление.
    *   Тело: `{ "user_id": "uuid", "notification_type": "order_confirmation", "data": {"order_id": "123"}, "priority": "high" }`
*   `POST /send/batch`: Отправить пакет уведомлений.
    *   Тело: `{ "notifications": [{"user_id": "uuid1", ...}, {"user_id": "uuid2", ...}] }`

##### 5.1.6 Статистика и мониторинг (Роли: admin, marketer, service)
*   `GET /stats/delivery`: Получить статистику доставки.
*   `GET /stats/messages/{message_id}`: Получить статус конкретного сообщения.
*   `GET /health`: Проверить состояние сервиса.

#### 5.2 Kafka Topics и События

##### 5.2.1 Потребляемые топики
*   `notification.send.request`: Запросы на отправку уведомлений.
    *   Сообщение: `{ "user_id", "notification_type", "data", "priority", "idempotency_key" }`
*   `user.events`, `payment.events`, `social.events`, `library.events`, etc.: События от других сервисов.

##### 5.2.2 Публикуемые топики
*   `notification.events`: События о статусах уведомлений (отправлено, доставлено, открыто, ошибка).
    *   Сообщение: `{ "event_type": "notification.delivered", "message_id", "user_id", "channel_type", "timestamp", "data" }`
*   `notification.stats`: Агрегированная статистика для Analytics Service.

#### 5.3 gRPC API (опционально)
```protobuf
service NotificationService {
  rpc SendNotification(SendNotificationRequest) returns (SendNotificationResponse);
  rpc SendBatchNotifications(SendBatchNotificationsRequest) returns (SendBatchNotificationsResponse);
  rpc GetNotificationStatus(GetNotificationStatusRequest) returns (GetNotificationStatusResponse);
}

message SendNotificationRequest {
  string user_id = 1;
  string notification_type = 2;
  map<string, string> data = 3;
  string priority = 4;
  string idempotency_key = 5;
}

message SendNotificationResponse {
  string message_id = 1;
  string status = 2;
}
// ... Другие сообщения ...
```
---

## 9. Payment Service

Из документа "Спецификация микросервиса Payment Service.txt":

### 5. Структура данных и API

#### 5.2 API Endpoints (REST)

**Префикс**: `/api/v1/payments`
**Аутентификация и Авторизация**: Требуется для всех эндпоинтов.

##### 5.2.1 API транзакций
*   `POST /transactions` - Создание новой транзакции.
    *   Тело: `{ "user_id", "type", "amount", "currency", "payment_method_id", "description", "metadata", "items": [] }`
*   `GET /transactions` - Получение списка транзакций (фильтры: `user_id`, `type`, `status`, `start_date`, `end_date`, `page`, `limit`).
*   `GET /transactions/{transaction_id}` - Получение информации о транзакции.
*   `PATCH /transactions/{transaction_id}` - Обновление статуса транзакции.
    *   Тело: `{ "status", "metadata" }`
*   `GET /transactions/{transaction_id}/events` - Получение истории событий транзакции.
*   `GET /transactions/{transaction_id}/receipt` - Получение фискального чека транзакции.

##### 5.2.2 API платежных методов
*   `POST /payment-methods` - Создание нового платежного метода.
    *   Тело: `{ "user_id", "type", "provider", "token", "masked_number", "expiry_date", "cardholder_name", "is_default", "metadata" }`
*   `GET /payment-methods` - Получение списка платежных методов пользователя (фильтры: `user_id`, `type`, `is_default`).
*   `GET /payment-methods/{payment_method_id}` - Получение информации о платежном методе.
*   `PATCH /payment-methods/{payment_method_id}` - Обновление платежного метода.
    *   Тело: `{ "is_default", "metadata" }`
*   `DELETE /payment-methods/{payment_method_id}` - Удаление платежного метода.

##### 5.2.3 API возвратов
*   `POST /refunds` - Создание нового возврата.
    *   Тело: `{ "transaction_id", "amount", "reason", "metadata" }`
*   `GET /refunds` - Получение списка возвратов (фильтры: `user_id`, `transaction_id`, `status`, `start_date`, `end_date`, `page`, `limit`).
*   `GET /refunds/{refund_id}` - Получение информации о возврате.
*   `PATCH /refunds/{refund_id}` - Обновление статуса возврата.
    *   Тело: `{ "status", "metadata" }`

##### 5.2.4 API промокодов и подарочных сертификатов
*   `POST /promo-codes` - Создание промокода.
    *   Тело: `{ "code", "type", "value", "currency", "game_id", "start_date", "end_date", "max_uses", "is_active" }`
*   `GET /promo-codes` - Получение списка промокодов (фильтры: `code`, `type`, `is_active`, `start_date`, `end_date`, `page`, `limit`).
*   `GET /promo-codes/{promo_code_id}` - Получение информации о промокоде.
*   `PATCH /promo-codes/{promo_code_id}` - Обновление промокода.
    *   Тело: `{ "end_date", "max_uses", "is_active" }`
*   `DELETE /promo-codes/{promo_code_id}` - Удаление промокода.
*   `POST /promo-codes/validate` - Валидация промокода.
    *   Тело: `{ "code", "user_id", "game_id", "amount" }`
*   `POST /gift-cards` - Создание подарочного сертификата.
    *   Тело: `{ "amount", "currency", "purchaser_id", "recipient_email", "expiry_date" }`
*   `GET /gift-cards` - Получение списка подарочных сертификатов (фильтры: `code`, `purchaser_id`, `is_activated`, `is_active`, `page`, `limit`).
*   `GET /gift-cards/{gift_card_id}` - Получение информации о подарочном сертификате.
*   `POST /gift-cards/activate` - Активация подарочного сертификата.
    *   Тело: `{ "code", "user_id" }`
*   `POST /gift-cards/apply` - Применение подарочного сертификата к заказу.
    *   Тело: `{ "code", "user_id", "amount" }`

##### 5.2.5 API балансов разработчиков
*   `GET /developer-balances` - Получение списка балансов разработчиков (фильтры: `developer_id`, `min_balance`, `max_balance`, `page`, `limit`).
*   `GET /developer-balances/{developer_id}` - Получение баланса разработчика.
*   `GET /developer-balances/{developer_id}/history` - Получение истории операций по балансу (фильтры: `type`, `start_date`, `end_date`, `page`, `limit`).
*   `POST /developer-balances/{developer_id}/adjust` - Ручная корректировка баланса (только для администраторов).
    *   Тело: `{ "amount", "description", "metadata" }`

##### 5.2.6 API выплат разработчикам
*   `POST /developer-payout-methods` - Создание метода выплаты для разработчика.
    *   Тело: `{ "developer_id", "type", "bank_name", "account_number", "account_holder", "swift_code", "is_default", "metadata" }`
*   `GET /developer-payout-methods` - Получение списка методов выплаты (фильтры: `developer_id`, `type`, `is_default`).
*   `GET /developer-payout-methods/{payout_method_id}` - Получение информации о методе выплаты.
*   `PATCH /developer-payout-methods/{payout_method_id}` - Обновление метода выплаты.
    *   Тело: `{ "is_default", "metadata" }`
*   `DELETE /developer-payout-methods/{payout_method_id}` - Удаление метода выплаты.
*   `POST /developer-payouts` - Создание выплаты разработчику.
    *   Тело: `{ "developer_id", "payout_method_id", "amount", "currency", "metadata" }`
*   `GET /developer-payouts` - Получение списка выплат (фильтры: `developer_id`, `status`, `start_date`, `end_date`, `page`, `limit`).
*   `GET /developer-payouts/{payout_id}` - Получение информации о выплате.
*   `PATCH /developer-payouts/{payout_id}` - Обновление статуса выплаты.
    *   Тело: `{ "status", "reference_number", "metadata" }`

##### 5.2.7 API фискальных данных
*   `GET /fiscal-receipts` - Получение списка фискальных чеков (фильтры: `transaction_id`, `type`, `start_date`, `end_date`, `page`, `limit`).
*   `GET /fiscal-receipts/{receipt_id}` - Получение информации о фискальном чеке.
*   `GET /fiscal-receipts/{receipt_id}/download` - Скачивание фискального чека (PDF).
*   `POST /fiscal-receipts/{receipt_id}/send` - Отправка фискального чека на email.
    *   Тело: `{ "email" }`

#### 5.3 Webhook API

**Префикс**: `/api/v1/payments/webhooks`
*   `POST /webhooks/{provider}` - Эндпоинт для получения уведомлений от платежных систем.
    *   Path params: `provider` (sbp, mir, yoomoney).
    *   Тело: Зависит от провайдера.

#### 5.4 Интеграционные API

**Префикс**: `/api/v1/payments/integration`
*   `POST /integration/purchase-complete` - Уведомление о завершении покупки.
    *   Тело: `{ "transaction_id", "user_id", "game_id", "status", "metadata" }`
*   `POST /integration/refund-complete` - Уведомление о завершении возврата.
    *   Тело: `{ "transaction_id", "original_transaction_id", "user_id", "game_id", "status", "metadata" }`
---

## 10. Social Service

Из документа "Спецификация микросервиса Social Service.txt":

### 5. Структура данных и API

#### 5.2 REST API
*(Предполагаемый префикс `/api/v1/social` или аналогичный, устанавливаемый API Gateway)*

*   **Профили пользователей (расширенные, социальные данные)**
    *   `GET /users/{userId}/profile` - Получение расширенного социального профиля.
    *   `PUT /users/me/profile` - Обновление своего социального профиля (никнейм, аватар, фон, описание, статус, ссылки на соцсети, настройки приватности).
*   **Друзья**
    *   `GET /users/me/friends` - Получение списка друзей текущего пользователя.
    *   `POST /users/me/friends/requests` - Отправка запроса в друзья пользователю.
        *   Тело: `{ "target_user_id": "uuid" }`
    *   `GET /users/me/friends/requests/incoming` - Получение входящих запросов в друзья.
    *   `GET /users/me/friends/requests/outgoing` - Получение исходящих запросов в друзья.
    *   `PUT /users/me/friends/requests/{requestId}` - Принять/отклонить запрос в друзья.
        *   Тело: `{ "action": "accept|reject" }`
    *   `DELETE /users/me/friends/{friendId}` - Удаление из списка друзей.
    *   `GET /users/search` - Поиск пользователей.
        *   Query Params: `query`, `limit`, `offset`.
*   **Группы**
    *   `GET /groups` - Получение списка групп (с фильтрами: публичные, мои, по интересам).
    *   `POST /groups` - Создание новой группы.
        *   Тело: `{ "name", "description", "privacy_level": "public|private|invite_only" }`
    *   `GET /groups/{groupId}` - Получение информации о группе.
    *   `PUT /groups/{groupId}` - Обновление информации о группе (владельцем/админом).
    *   `DELETE /groups/{groupId}` - Удаление группы (владельцем).
    *   `POST /groups/{groupId}/members` - Вступить в группу / Пригласить пользователя.
        *   Тело: `{ "user_id": "uuid" }` (для приглашения)
    *   `PUT /groups/{groupId}/members/{userId}` - Изменить роль участника (владельцем/админом).
        *   Тело: `{ "role": "admin|moderator|member" }`
    *   `DELETE /groups/{groupId}/members/{userId}` - Покинуть группу / Исключить участника.
    *   `GET /groups/{groupId}/feed` - Получение ленты активности группы.
    *   `POST /groups/{groupId}/feed` - Создание поста в группе.
*   **Лента активности (Персональная)**
    *   `GET /feed` - Получение персональной ленты активности.
        *   Query Params: `limit`, `offset`, `filter_types`: [string]
    *   `POST /feed/{itemId}/like` - Лайкнуть элемент ленты.
    *   `DELETE /feed/{itemId}/like` - Убрать лайк.
    *   `POST /feed/{itemId}/comments` - Добавить комментарий к элементу ленты.
        *   Тело: `{ "text": "string" }`
    *   `GET /feed/{itemId}/comments` - Получить комментарии к элементу ленты.
*   **Отзывы и комментарии (к играм)**
    *   `GET /games/{gameId}/reviews` - Получение отзывов к игре.
        *   Query Params: `limit`, `offset`, `sort_by` (date, helpfulness, rating), `filter_rating` (positive, negative).
    *   `POST /games/{gameId}/reviews` - Создание/обновление отзыва к игре.
        *   Тело: `{ "rating": "positive|negative", "text": "string" }`
    *   `DELETE /reviews/{reviewId}` - Удаление своего отзыва (или админом).
    *   `POST /reviews/{reviewId}/vote` - Оценить отзыв ("полезный"/"не полезный").
        *   Тело: `{ "vote_type": "helpful|unhelpful" }`
    *   `POST /reviews/{reviewId}/comments` - Добавить комментарий к отзыву.
    *   `GET /reviews/{reviewId}/comments` - Получить комментарии к отзыву.
*   **Общие комментарии (к новостям, постам и т.д.)**
    *   `GET /comments?entity_type={type}&entity_id={id}` - Получение комментариев для сущности.
    *   `POST /comments` - Добавление комментария к сущности.
        *   Тело: `{ "entity_type": "string", "entity_id": "string", "text": "string", "parent_comment_id": "uuid_optional" }`
    *   `PUT /comments/{commentId}` - Редактирование своего комментария.
    *   `DELETE /comments/{commentId}` - Удаление своего комментария (или админом).
*   **Форумы**
    *   `GET /forums` - Список общих форумов.
    *   `GET /forums/{forumId}/topics` - Список тем на форуме.
    *   `POST /forums/{forumId}/topics` - Создание новой темы.
    *   `GET /topics/{topicId}/posts` - Список сообщений в теме.
    *   `POST /topics/{topicId}/posts` - Добавление сообщения в тему.

#### 5.3 gRPC API
*   `rpc CheckFriendship(userId1, userId2) returns (status)`
*   `rpc GetUserProfileSummary(userId) returns (ProfileSummary)`
*   `rpc BatchGetUsersProfileSummary(userIds) returns (stream ProfileSummary)`
*   `rpc SubmitModerationTask(entityType, entityId, content)` - для отправки контента на модерацию в Admin Service или внутренний модуль модерации.

#### 5.4 WebSocket API
*   **События от сервера**: `new_message`, `message_read`, `user_status_update`, `notification` (общие социальные уведомления), `feed_update`.
*   **Сообщения от клиента**: `send_message`, `mark_message_read`, `subscribe_chat`, `unsubscribe_chat`.

#### 5.5 События (Kafka)
**Публикуемые события**:
*   `user.profile.updated`
*   `friend.request.sent`
*   `friend.request.accepted`
*   `friend.removed`
*   `group.created`
*   `group.member.joined`
*   `chat.message.sent` (для аналитики/архивации)
*   `review.submitted`
*   `review.approved`
*   `comment.posted`
*   `moderation.required` (для Admin Service)
*   `user.reported` (для Admin Service)

**Потребляемые события**:
*   `account.user.created` (от Account Service) - для создания базового профиля.
*   `library.achievement.unlocked` (от Library Service) - для ленты активности.
*   `catalog.game.released` (от Catalog Service) - для ленты активности.
---

## 11. Admin Service

Из документа "Спецификация микросервиса Admin Service.txt":

### 5. Структура данных и API

#### 5.2 API Endpoints (REST)

**Префикс**: `/api/v1/admin`
**Аутентификация**: JWT (валидируется Auth Service)
**Авторизация**: Роль `admin` или другие специфичные административные роли.

**Административные пользователи:**

*   `GET /users` - Получение списка административных пользователей.
*   `GET /users/{admin_id}` - Получение информации о конкретном административном пользователе.
*   `POST /users` - Создание нового административного пользователя.
*   `PUT /users/{admin_id}` - Обновление информации об административном пользователе.
*   `DELETE /users/{admin_id}` - Удаление административного пользователя.
*   `PUT /users/{admin_id}/permissions` - Обновление прав доступа административного пользователя.

**Модерация:**

*   `GET /moderation/queues` - Получение списка очередей модерации.
*   `GET /moderation/queues/{queue_id}/items` - Получение элементов в очереди модерации.
*   `GET /moderation/items/{item_id}` - Получение информации о конкретном элементе модерации.
*   `PUT /moderation/items/{item_id}/assign` - Назначение элемента модерации на конкретного модератора.
*   `PUT /moderation/items/{item_id}/decision` - Принятие решения по элементу модерации.
    *   Тело: `{ "decision": "approve|reject|request_changes", "reason": "string_optional", "comment": "string_optional" }`
*   `GET /moderation/decisions` - Получение истории решений модерации.

**Управление пользователями платформы:**

*   `GET /platform-users` - Поиск пользователей платформы (фильтры: `email`, `username`, `status`).
*   `GET /platform-users/{user_id}` - Получение детальной информации о пользователе платформы.
*   `PUT /platform-users/{user_id}/status` - Изменение статуса пользователя (блокировка/разблокировка).
    *   Тело: `{ "status": "active|blocked|suspended", "reason": "string_optional" }`
*   `PUT /platform-users/{user_id}/role` - Изменение роли пользователя.
    *   Тело: `{ "role_name": "string" }`
*   `GET /platform-users/{user_id}/history` - Получение истории действий пользователя.

**Техническая поддержка:**

*   `GET /support/tickets` - Получение списка тикетов поддержки (фильтры: `status`, `priority`, `category`, `assignee_id`).
*   `GET /support/tickets/{ticket_id}` - Получение информации о конкретном тикете.
*   `PUT /support/tickets/{ticket_id}/assign` - Назначение тикета на агента поддержки.
    *   Тело: `{ "assignee_id": "uuid" }`
*   `PUT /support/tickets/{ticket_id}/status` - Изменение статуса тикета.
    *   Тело: `{ "status": "open|in_progress|resolved|closed" }`
*   `POST /support/tickets/{ticket_id}/messages` - Добавление сообщения в тикет.
    *   Тело: `{ "sender_id": "uuid", "sender_type": "admin|user", "message": "string", "is_internal_note": boolean }`
*   `GET /support/tickets/{ticket_id}/messages` - Получение сообщений тикета.
*   `GET /support/knowledge` - Получение статей базы знаний.
*   `POST /support/knowledge` - Создание новой статьи в базе знаний.
*   `PUT /support/knowledge/{article_id}` - Обновление статьи в базе знаний.
*   `DELETE /support/knowledge/{article_id}` - Удаление статьи из базы знаний.

**Безопасность:**

*   `GET /security/incidents` - Получение списка инцидентов безопасности.
*   `POST /security/incidents` - Создание нового инцидента безопасности.
*   `PUT /security/incidents/{incident_id}` - Обновление информации об инциденте.
*   `GET /security/blocked-ips` - Получение списка заблокированных IP-адресов.
*   `POST /security/blocked-ips` - Блокировка нового IP-адреса.
    *   Тело: `{ "ip_address": "string", "reason": "string", "expires_at": "datetime_optional" }`
*   `DELETE /security/blocked-ips/{block_id}` - Разблокировка IP-адреса.
*   `GET /security/audit-log` - Получение журнала аудита административных действий (фильтры: `admin_id`, `action_type`, `entity_type`, `entity_id`, `start_date`, `end_date`).

**Настройки платформы:**

*   `GET /settings` - Получение системных настроек (фильтры: `category`).
*   `PUT /settings/{setting_id}` - Обновление системной настройки.
*   `POST /settings` - Создание новой системной настройки.
*   `DELETE /settings/{setting_id}` - Удаление системной настройки.
*   `POST /maintenance` - Планирование технических работ.
    *   Тело: `{ "start_time", "end_time", "description", "affected_services": [] }`
*   `GET /maintenance` - Получение информации о запланированных технических работах.
*   `PUT /maintenance/{maintenance_id}` - Обновление информации о технических работах.

**Аналитика (Административная):**
*(Примечание: Основной сервис аналитики - Analytics Service, Admin Service может предоставлять к нему интерфейс или запрашивать специфичные административные отчеты)*
*   `GET /analytics/dashboard` - Получение данных для административного дашборда.
*   `GET /analytics/reports` - Получение списка доступных административных отчетов.
*   `POST /analytics/reports/{report_type}` - Генерация административного отчета определенного типа.
*   `GET /analytics/reports/status/{report_id}` - Проверка статуса генерации отчета.
*   `GET /analytics/reports/download/{report_id}` - Скачивание сгенерированного отчета.

**Маркетинг (Глобальные кампании):**

*   `GET /marketing/campaigns` - Получение списка глобальных маркетинговых кампаний.
*   `POST /marketing/campaigns` - Создание новой глобальной маркетинговой кампании.
*   `GET /marketing/campaigns/{campaign_id}` - Получение информации о кампании.
*   `PUT /marketing/campaigns/{campaign_id}` - Обновление кампании.
*   `DELETE /marketing/campaigns/{campaign_id}` - Удаление кампании.
*   `GET /marketing/banners` - Получение списка глобальных баннеров.
*   `POST /marketing/banners` - Создание нового баннера.
*   `PUT /marketing/banners/{banner_id}` - Обновление баннера.
*   `DELETE /marketing/banners/{banner_id}` - Удаление баннера.
*   `GET /marketing/promo-codes` - Получение списка глобальных промокодов.
*   `POST /marketing/promo-codes` - Создание нового промокода.
*   `PUT /marketing/promo-codes/{code_id}` - Обновление промокода.
*   `DELETE /marketing/promo-codes/{code_id}` - Удаление промокода.
---

## 12. Analytics Service

Из документа "Спецификация микросервиса Analytics Service.txt":

### 5. Структура данных и API

#### 5.2 API Endpoints (REST)

**Префикс**: `/api/v1/analytics`
**Аутентификация и Авторизация**: Требуется.

##### 5.2.1 API метрик
*   `GET /metrics` - Получение списка доступных метрик.
*   `GET /metrics/{metric_name}` - Получение значений метрики (Query Params: `start_date`, `end_date`, `dimensions`, `filters`, `granularity`).
*   `GET /metrics/realtime` - Получение метрик реального времени.
*   `GET /metrics/dashboard/{dashboard_id}` - Получение набора метрик для дашборда.

##### 5.2.2 API отчетов
*   `GET /reports` - Получение списка отчетов.
*   `GET /reports/{report_id}` - Получение информации об отчете.
*   `POST /reports` - Создание нового отчета.
*   `PUT /reports/{report_id}` - Обновление отчета.
*   `DELETE /reports/{report_id}` - Удаление отчета.
*   `POST /reports/{report_id}/generate` - Запуск генерации отчета (Тело: `parameters`, `format`).
*   `GET /reports/instances` - Получение списка сгенерированных отчетов.
*   `GET /reports/instances/{instance_id}` - Получение информации об экземпляре отчета.
*   `GET /reports/instances/{instance_id}/download` - Скачивание отчета.
*   `POST /reports/{report_id}/schedule` - Настройка расписания генерации отчета.

##### 5.2.3 API сегментов
*   `GET /segments` - Получение списка сегментов.
*   `GET /segments/{segment_id}` - Получение информации о сегменте.
*   `POST /segments` - Создание нового сегмента (Тело: `name`, `description`, `criteria`, `is_dynamic`, `update_schedule`).
*   `PUT /segments/{segment_id}` - Обновление сегмента.
*   `DELETE /segments/{segment_id}` - Удаление сегмента.
*   `POST /segments/{segment_id}/update` - Принудительное обновление динамического сегмента.
*   `GET /segments/{segment_id}/users` - Получение списка пользователей в сегменте.
*   `POST /segments/{segment_id}/export` - Экспорт сегмента (Тело: `format`, `fields`).

##### 5.2.4 API предиктивной аналитики
*   `GET /predictions/models` - Получение списка моделей ML.
*   `GET /predictions/models/{model_id}` - Получение информации о модели.
*   `POST /predictions/models` - Создание модели.
*   `PUT /predictions/models/{model_id}` - Обновление модели.
*   `DELETE /predictions/models/{model_id}` - Удаление модели.
*   `POST /predictions/models/{model_id}/train` - Запуск обучения модели.
*   `GET /predictions/models/{model_id}/metrics` - Получение метрик качества модели.
*   `POST /predictions/{prediction_type}` - Запрос прогноза (Тело: `entity_type`, `entity_id`, `parameters`).
*   `GET /predictions/{entity_type}/{entity_id}` - Получение прогнозов для сущности.

##### 5.2.5 API мониторинга (системного)
*   `GET /monitoring/performance` - Получение метрик производительности системы (Query Params: `start_time`, `end_time`, `services`, `metrics`).
*   `GET /monitoring/errors` - Получение информации об ошибках и инцидентах.
*   `GET /monitoring/alerts` - Получение активных оповещений.
*   `POST /monitoring/alerts` - Создание нового оповещения.
*   `PUT /monitoring/alerts/{alert_id}` - Обновление оповещения.
*   `DELETE /monitoring/alerts/{alert_id}` - Удаление оповещения.

#### 5.3 GraphQL API

**Endpoint**: `/api/v1/analytics/graphql`

**Пример схемы GraphQL**:
```graphql
type Query {
  metrics(names: [String!], startDate: String!, endDate: String!, dimensions: [String], filters: JSON, granularity: String): [Metric!]!
  report(id: ID!): Report
  reports(type: String): [Report!]!
  segment(id: ID!): Segment
  # ... и другие запросы
}

type Mutation {
  createReport(input: CreateReportInput!): Report!
  generateReport(reportId: ID!, parameters: JSON, format: String!): ReportInstance!
  # ... и другие мутации
}
# ... определения типов Metric, Report, Segment, MLModel, Prediction и т.д.
# ... определения входных типов CreateReportInput, UpdateReportInput и т.д.
```

#### 5.4 Streaming API (WebSocket)

**Endpoint**: `/api/v1/analytics/streaming`
*   Подписка на метрики реального времени:
    *   Запрос: `{ "action": "subscribe", "channel": "metrics", "parameters": { "metrics": ["active_users"], "interval": 5 } }`
    *   Ответ: `{ "channel": "metrics", "timestamp": "...", "data": { "active_users": 123 } }`
*   Подписка на оповещения:
    *   Запрос: `{ "action": "subscribe", "channel": "alerts", "parameters": { "severity": ["critical"] } }`
    *   Ответ: `{ "channel": "alerts", "timestamp": "...", "data": { "alert_id": "...", "message": "..." } }`
---

## 13. Общие Стандарты API, Форматов Данных и Событий

Из документа "(Дополнительный фаил) Стандарты API, форматов данных, событий и конфигурационных файлов.txt":

### 2. Стандарты REST API

#### Общие принципы
1.  **Версионирование**: В URL: `/api/v1/resource`
2.  **Формат URL**: Существительные во множественном числе (`/api/v1/games`), вложенные ресурсы (`/api/v1/games/{game_id}/reviews`), kebab-case (`/api/v1/payment-methods`). Специальные действия через `/action` (`/api/v1/games/{game_id}/publish`).
3.  **HTTP-методы**: GET, POST, PUT, PATCH, DELETE.
4.  **Коды ответов**: 200, 201, 204, 400, 401, 403, 404, 409, 422, 429, 500.
5.  **Пагинация**:
    *   Query Params: `page` (с 1), `per_page` (макс 100).
    *   Ответ: `data`, `meta: { pagination }`, `links`.
6.  **Фильтрация**: Query Params (`genre=strategy`) или `filter={"genre":["strategy"],"release_date":{"$gte":"2023-01-01"}}`.
7.  **Сортировка**: Query Param `sort` (`sort=price` или `sort=-price`). Множественная: `sort=genre,-price`.
8.  **Выборка полей**: Query Param `fields` (`fields=id,title,price` или `fields=id,title,developer{id,name}`).
9.  **Формат ответа (JSON)**:
    *   Одиночный ресурс: `{ "data": { "id", "type", "attributes": { ... }, "relationships": { ... } } }`
    *   Коллекция: `{ "data": [ { ... } ], "meta": { ... }, "links": { ... } }`
10. **Формат ошибок (JSON)**:
    ```json
    {
      "errors": [
        {
          "code": "validation_error",
          "title": "Ошибка валидации",
          "detail": "Поле 'price' должно быть положительным числом",
          "source": { "pointer": "/data/attributes/price" }
        }
      ]
    }
    ```
11. **Заголовки**: `Content-Type: application/json`, `Accept: application/json`, `Authorization: Bearer <token>`, `X-Request-ID: <uuid>`, `X-API-Key: <key>`.
12. **Документация**: OpenAPI (Swagger) 3.0 на `/api/v1/docs`.

#### Специфические требования для API Gateway
- API Gateway добавляет заголовки: `X-User-Id`, `X-User-Roles`, `X-Original-IP`.

### 3. Стандарты gRPC API

#### Общие принципы
1.  **Версионирование**: В имени пакета: `platform.v1.service`.
2.  **Именование**: PascalCase для сервисов (`UserService`), методов (`GetUser`), сообщений (`User`). snake_case для полей (`user_id`). Enum: `UserStatusEnum`, `PAYMENT_STATUS_PENDING`.
3.  **Структура proto-файлов**: Каждый сервис в отдельном файле. Общие сообщения в `common.proto`.
4.  **Формат сообщений**: Запросы: `{Method}Request`, Ответы: `{Method}Response`. `google.protobuf.Timestamp` для дат/времени. `google.protobuf.Empty` для пустых.
5.  **Обработка ошибок**: Стандартные коды gRPC, метаданные для деталей.
6.  **Безопасность**: TLS, токены в метаданных (`authorization: Bearer <token>`).

### 4. Стандарты WebSocket API

#### Общие принципы
1.  **Подключение**: URL: `/api/v1/ws/{service}`. Аутентификация через query param `token` или заголовок `Authorization`. Ping/Pong.
2.  **Формат сообщений (JSON)**:
    ```json
    {
      "type": "message_type",
      "id": "unique_message_id",
      "payload": { ... }
    }
    ```
    Типы: `connect`, `disconnect`, `error`, `ping`/`pong`, специфичные для сервиса.
3.  **Обработка ошибок (JSON)**:
    ```json
    {
      "type": "error",
      "id": "correlation_id",
      "payload": { "code": "error_code", "message": "Описание ошибки" }
    }
    ```
4.  **Подтверждение доставки (JSON)**:
    ```json
    {
      "type": "ack",
      "id": "original_message_id",
      "payload": { "status": "delivered" }
    }
    ```

### 5. Форматы данных

#### Общие принципы
1.  **JSON**: camelCase для REST API. UTF-8. Даты ISO 8601 (`YYYY-MM-DDTHH:mm:ss.sssZ`).
2.  **Protocol Buffers**: snake_case для полей.
3.  **Общие типы**: ID - UUID v4. Деньги - целое число (копейки/центы) для операций, строка с точкой для отображения.
4.  **Локализация**:
    ```json
    {
      "title": { "ru": "Название", "en": "Title" }
    }
    ```
    Коды языков ISO 639-1 (ru, en, uk, be, kk).

#### Стандартные объекты (JSON примеры)
*   **User**: `id`, `username`, `email`, `status`, `createdAt`, `updatedAt`, `roles`.
*   **Game**: `id`, `title` (локал.), `description` (локал.), `price`, `discountPrice`, `releaseDate`, `developer`, `publisher`, `genres`, `tags`, `rating`, `platforms`, `systemRequirements`.
*   **Transaction**: `id`, `userId`, `type`, `status`, `amount`, `currency`, `items`, `paymentMethod`, `createdAt`, `updatedAt`.
*   **Review**: `id`, `gameId`, `userId`, `rating`, `text`, `createdAt`, `updatedAt`, `helpfulCount`, `notHelpfulCount`.
*   **Error (REST)**: См. п. 2.10.

### 6. Стандарты событий (CloudEvents)

#### Общие принципы
1.  **Формат события (JSON)**:
    ```json
    {
      "id": "uuid", // ID события
      "type": "event.type", // Тип события
      "source": "service_name", // Источник
      "time": "ISO8601_timestamp", // Время
      "dataContentType": "application/json",
      "data": { ... }, // Полезная нагрузка
      "subject": "resource_id", // ID ресурса
      "correlationId": "uuid_optional" // ID корреляции
    }
    ```
2.  **Именование типов событий**: `{domain}.{resource}.{action}` (например, `user.registered`, `game.published`). Прошедшее время для действий.
3.  **Версионирование**: В типе события (`user.registered.v1`).
4.  **Обработка**: Идемпотентность, порядок (по `time`), отказоустойчивость.
5.  **Топики Kafka**: `{service}.{resource}.{action}` (например, `auth.user.registered`).

#### Стандартные события (Примеры)
*   **User Events**: `user.registered`, `user.verified`, `user.updated`, `user.deleted`, `user.blocked`, `user.logged_in`.
*   **Game Events**: `game.created`, `game.updated`, `game.published`, `game.price_changed`.
*   **Library Events**: `library.game_added`, `library.game_installed`.
*   **Payment Events**: `payment.initiated`, `payment.completed`, `payment.failed`, `payment.refunded`.
*   **Social Events**: `friend.request_sent`, `review.published`.
*   **Notification Events**: `notification.created`, `notification.delivered`.

---

## 14. Аудит Интеграций и Контракты

Из документа "(Дополнительный фаил) Аудит интеграций между микросервисами.txt":

### Матрица интеграций (Типы взаимодействия)

| Микросервис      | API Gateway | Auth        | Account     | Catalog     | Library     | Download    | Payment     | Social      | Developer   | Admin       | Analytics   | Notification |
|------------------|-------------|-------------|-------------|-------------|-------------|-------------|-------------|-------------|-------------|-------------|-------------|--------------|
| **API Gateway**  | -           | REST        | REST        | REST        | REST        | REST        | REST        | REST        | REST        | REST        | REST        | WebSocket    |
| **Auth**         | REST        | -           | REST, Events| -           | -           | -           | REST        | -           | REST        | REST        | -           | -            |
| **Account**      | REST        | REST, Events| -           | -           | REST        | -           | REST        | REST        | REST        | REST        | Events      | Events       |
| **Catalog**      | REST        | -           | -           | -           | REST        | REST        | REST        | -           | REST        | REST        | Events      | -            |
| **Library**      | REST        | -           | REST        | REST        | -           | REST        | -           | REST        | -           | REST        | Events      | Events       |
| **Download**     | REST        | -           | -           | REST        | REST        | -           | -           | -           | REST        | REST        | Events      | Events       |
| **Payment**      | REST        | REST        | REST        | REST        | -           | -           | -           | -           | REST        | REST        | Events      | Events       |
| **Social**       | REST        | -           | REST        | -           | REST        | -           | -           | -           | -           | REST        | Events      | Events       |
| **Developer**    | REST        | REST        | REST        | REST        | -           | REST        | REST        | -           | -           | REST        | Events      | Events       |
| **Admin**        | REST        | REST        | REST        | REST        | REST        | REST        | REST        | REST        | REST        | -           | REST        | REST         |
| **Analytics**    | REST        | -           | Events      | Events      | Events      | Events      | Events      | Events      | Events      | REST        | -           | -            |
| **Notification** | WebSocket   | -           | Events      | -           | Events      | Events      | Events      | Events      | Events      | REST        | -           | -            |

### Детальный анализ интеграций (Примеры)

#### API Gateway и Flutter-клиент
*   **Типы взаимодействий**: REST API, WebSocket, gRPC (опционально).
*   **Форматы данных**: JSON (REST), Protocol Buffers (gRPC), JSON (WebSocket).
*   **Аутентификация**: JWT-токены.
*   **Эндпоинты (Примеры из документа, могут пересекаться с другими спецификациями)**:
    *   API Gateway → Auth Service:
        *   `/api/v1/auth/validate-token`
        *   `/api/v1/auth/refresh-token`
        *   `/api/v1/auth/telegram-login`

#### Auth Service и Account Service
*   **Тип интеграции**: REST API, События.
*   **Событие**: `user.registered` (Auth Service -> Account Service).

#### Notification Service и Flutter-клиент (через API Gateway)
*   **Тип интеграции**: WebSocket.

### Стандартизированные контракты интеграций

#### REST API контракты

*   **Формат успешного ответа (Wrapper)**:
    ```json
    {
      "status": "success",
      "data": { /* Данные ответа */ },
      "meta": {
        "pagination": { /* ... */ }
      }
    }
    ```
*   **Формат ошибки (Wrapper)**:
    ```json
    {
      "status": "error",
      "error": {
        "code": "RESOURCE_NOT_FOUND",
        "message": "Запрашиваемый ресурс не найден",
        "details": { /* Дополнительные детали */ }
      }
    }
    ```

#### WebSocket контракты

*   **Формат сообщения (Пример для уведомлений)**:
    ```json
    {
      "type": "notification", // или другой тип сообщения
      "payload": {
        "id": "uuid",
        "type": "friend_request", // подтип уведомления
        "title": "Новый запрос в друзья",
        "message": "Пользователь example хочет добавить вас в друзья",
        "data": { "user_id": "123456", "username": "example" },
        "created_at": "2025-05-21T12:34:56Z"
      }
    }
    ```
*   **Формат подтверждения**:
    ```json
    {
      "type": "ack",
      "payload": {
        "message_id": "uuid_original_message",
        "status": "delivered" // или "read"
      }
    }
    ```

#### События (Общий формат)
```json
{
  "id": "uuid_event", // ID события
  "type": "user.registered", // Тип события (домен.сущность.действие)
  "source": "auth_service", // Источник события
  "timestamp": "2025-05-21T12:34:56Z", // Время события (UTC)
  "data": { /* Данные события */ },
  "metadata": {
    "version": "1.0", // Версия схемы события
    "correlation_id": "uuid_request" // ID корреляции
  }
}
```

## Заключение

Данный документ объединяет ключевые аспекты API спецификаций из различных микросервисных документов платформы. Он включает информацию о REST API, gRPC API, WebSocket API, форматах данных и событиях, используемых в системе. Маршрутизация запросов осуществляется через API Gateway, который также отвечает за аутентификацию, базовую авторизацию и применение общих политик. Стандартизированные форматы ответов и ошибок обеспечивают консистентность взаимодействия между клиентами и серверами. Событийная архитектура на базе Kafka используется для асинхронного взаимодействия между сервисами.

Этот документ должен служить основой для разработчиков клиентских приложений и для команд, работающих над отдельными микросервисами, обеспечивая общее понимание контрактных обязательств каждого компонента системы.
---
