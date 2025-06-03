# API документация Auth Service

## Содержание

- [REST API](#rest-api)
  - [Аутентификация и управление сессиями](#аутентификация-и-управление-сессиями)
  - [Управление пользователями и ролями](#управление-пользователями-и-ролями)
  - [Валидация и проверка прав](#валидация-и-проверка-прав)
- [gRPC API](#grpc-api)
  - [Определения сервисов](#определения-сервисов)
  - [Сообщения](#сообщения)
- [События (Events)](#события-events)
  - [Публикуемые события](#публикуемые-события)
  - [Потребляемые события](#потребляемые-события)
- [Форматы данных](#форматы-данных)
  - [Пользователь (User)](#пользователь-user)
  - [Токены (Tokens)](#токены-tokens)
  - [Роль (Role)](#роль-role)
  - [Ошибка (Error)](#ошибка-error)
- [Обработка ошибок](#обработка-ошибок)
- [Примеры запросов](#примеры-запросов)

## REST API

Базовый URL: `/api/v1/auth`

### Аутентификация и управление сессиями

#### Регистрация нового пользователя

```
POST /api/v1/auth/register
```

Запрос:
```json
{
  "email": "user@example.com",
  "password": "securePassword123",
  "username": "username"
}
```

Ответ (201 Created):
```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "username": "username",
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

#### Аутентификация по логину/паролю

```
POST /api/v1/auth/login
```

Запрос:
```json
{
  "email": "user@example.com",
  "password": "securePassword123"
}
```

Ответ (200 OK):
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

#### Аутентификация через Telegram

```
POST /api/v1/auth/telegram-login
```

Запрос:
```json
{
  "id": 123456789,
  "first_name": "John",
  "last_name": "Doe",
  "username": "johndoe",
  "photo_url": "https://t.me/i/userpic/123/photo.jpg",
  "auth_date": 1632150000,
  "hash": "hash_from_telegram"
}
```

Ответ (200 OK):
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

#### Обновление токена доступа

```
POST /api/v1/auth/refresh-token
```

Запрос:
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

Ответ (200 OK):
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

#### Выход из системы

```
POST /api/v1/auth/logout
```

Заголовки:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Ответ (204 No Content)

#### Выход из всех устройств

```
POST /api/v1/auth/logout-all
```

Заголовки:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Ответ (204 No Content)

#### Подтверждение email

```
POST /api/v1/auth/verify-email
```

Запрос:
```json
{
  "token": "verification_token"
}
```

Ответ (200 OK):
```json
{
  "message": "Email успешно подтвержден"
}
```

#### Повторная отправка подтверждения

```
POST /api/v1/auth/resend-verification
```

Запрос:
```json
{
  "email": "user@example.com"
}
```

Ответ (200 OK):
```json
{
  "message": "Письмо с подтверждением отправлено"
}
```

#### Запрос на восстановление пароля

```
POST /api/v1/auth/forgot-password
```

Запрос:
```json
{
  "email": "user@example.com"
}
```

Ответ (200 OK):
```json
{
  "message": "Инструкции по восстановлению пароля отправлены на email"
}
```

#### Сброс пароля

```
POST /api/v1/auth/reset-password
```

Запрос:
```json
{
  "token": "reset_token",
  "new_password": "newSecurePassword123"
}
```

Ответ (200 OK):
```json
{
  "message": "Пароль успешно изменен"
}
```

#### Включение 2FA

```
POST /api/v1/auth/2fa/enable
```

Заголовки:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Ответ (200 OK):
```json
{
  "secret": "JBSWY3DPEHPK3PXP",
  "qr_code": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA...",
  "recovery_codes": [
    "1234-5678-9012",
    "2345-6789-0123",
    "3456-7890-1234"
  ]
}
```

#### Проверка кода 2FA

```
POST /api/v1/auth/2fa/verify
```

Заголовки:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Запрос:
```json
{
  "code": "123456"
}
```

Ответ (200 OK):
```json
{
  "message": "Код подтвержден"
}
```

#### Отключение 2FA

```
POST /api/v1/auth/2fa/disable
```

Заголовки:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Запрос:
```json
{
  "code": "123456"
}
```

Ответ (200 OK):
```json
{
  "message": "Двухфакторная аутентификация отключена"
}
```

### Управление пользователями и ролями

#### Получение списка пользователей

```
GET /api/v1/auth/users
```

Заголовки:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Параметры запроса:
- `page` (опционально): номер страницы (по умолчанию 1)
- `per_page` (опционально): количество элементов на странице (по умолчанию 20)
- `search` (опционально): поисковый запрос
- `status` (опционально): фильтр по статусу (`active`, `inactive`, `blocked`)

Ответ (200 OK):
```json
{
  "users": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "email": "user@example.com",
      "username": "username",
      "email_verified": true,
      "two_factor_enabled": false,
      "status": "active",
      "roles": ["user"],
      "created_at": "2023-01-01T12:00:00Z",
      "updated_at": "2023-01-02T14:30:00Z"
    },
    // ...
  ],
  "pagination": {
    "total": 100,
    "per_page": 20,
    "current_page": 1,
    "last_page": 5,
    "next_page_url": "/api/v1/auth/users?page=2",
    "prev_page_url": null
  }
}
```

#### Получение информации о пользователе

```
GET /api/v1/auth/users/{id}
```

Заголовки:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Ответ (200 OK):
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "username": "username",
  "email_verified": true,
  "two_factor_enabled": false,
  "status": "active",
  "roles": ["user"],
  "created_at": "2023-01-01T12:00:00Z",
  "updated_at": "2023-01-02T14:30:00Z"
}
```

#### Обновление информации о пользователе

```
PUT /api/v1/auth/users/{id}
```

Заголовки:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Запрос:
```json
{
  "username": "new_username",
  "status": "inactive"
}
```

Ответ (200 OK):
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "username": "new_username",
  "email_verified": true,
  "two_factor_enabled": false,
  "status": "inactive",
  "roles": ["user"],
  "created_at": "2023-01-01T12:00:00Z",
  "updated_at": "2023-01-03T10:15:00Z"
}
```

#### Удаление пользователя

```
DELETE /api/v1/auth/users/{id}
```

Заголовки:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Ответ (204 No Content)

#### Получение списка ролей

```
GET /api/v1/auth/roles
```

Заголовки:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Ответ (200 OK):
```json
{
  "roles": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440001",
      "name": "admin",
      "description": "Администратор системы",
      "permissions": [
        "users.read",
        "users.write",
        "roles.read",
        "roles.write"
      ],
      "created_at": "2023-01-01T12:00:00Z",
      "updated_at": "2023-01-01T12:00:00Z"
    },
    // ...
  ]
}
```

#### Назначение роли пользователю

```
POST /api/v1/auth/users/{id}/roles
```

Заголовки:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Запрос:
```json
{
  "role_id": "550e8400-e29b-41d4-a716-446655440001"
}
```

Ответ (200 OK):
```json
{
  "message": "Роль успешно назначена",
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "roles": ["user", "admin"]
}
```

#### Удаление роли у пользователя

```
DELETE /api/v1/auth/users/{id}/roles/{role_id}
```

Заголовки:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Ответ (204 No Content)

### Валидация и проверка прав

#### Проверка валидности токена

```
POST /api/v1/auth/validate-token
```

Заголовки:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Ответ (200 OK):
```json
{
  "valid": true,
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "roles": ["user"],
  "permissions": ["users.read"],
  "expires_at": 1672531200
}
```

#### Проверка наличия разрешения

```
POST /api/v1/auth/check-permission
```

Заголовки:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Запрос:
```json
{
  "permission": "users.read"
}
```

Ответ (200 OK):
```json
{
  "has_permission": true
}
```

## gRPC API

### Определения сервисов

```protobuf
syntax = "proto3";

package auth;

service AuthService {
  // Валидация токена
  rpc ValidateToken(ValidateTokenRequest) returns (ValidateTokenResponse);
  
  // Проверка разрешения
  rpc CheckPermission(CheckPermissionRequest) returns (CheckPermissionResponse);
  
  // Получение информации о пользователе
  rpc GetUser(GetUserRequest) returns (UserResponse);
  
  // Получение ролей пользователя
  rpc GetUserRoles(GetUserRequest) returns (UserRolesResponse);
}
```

### Сообщения

```protobuf
message ValidateTokenRequest {
  string token = 1;
}

message ValidateTokenResponse {
  bool valid = 1;
  string user_id = 2;
  repeated string roles = 3;
  int64 expires_at = 4;
}

message CheckPermissionRequest {
  string token = 1;
  string permission = 2;
}

message CheckPermissionResponse {
  bool has_permission = 1;
}

message GetUserRequest {
  string user_id = 1;
}

message UserResponse {
  string id = 1;
  string email = 2;
  string username = 3;
  bool email_verified = 4;
  bool two_factor_enabled = 5;
  int64 created_at = 6;
  int64 updated_at = 7;
}

message UserRolesResponse {
  string user_id = 1;
  repeated Role roles = 2;
}

message Role {
  string id = 1;
  string name = 2;
  repeated string permissions = 3;
}
```

## События (Events)

### Публикуемые события

#### user.registered

Топик: `auth.events`

Формат:
```json
{
  "event_type": "user.registered",
  "payload": {
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "username": "username",
    "created_at": "2023-01-01T12:00:00Z"
  }
}
```

#### user.email_verified

Топик: `auth.events`

Формат:
```json
{
  "event_type": "user.email_verified",
  "payload": {
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "verified_at": "2023-01-02T14:30:00Z"
  }
}
```

#### user.role_changed

Топик: `auth.events`

Формат:
```json
{
  "event_type": "user.role_changed",
  "payload": {
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "old_roles": ["user"],
    "new_roles": ["user", "admin"],
    "changed_by": "550e8400-e29b-41d4-a716-446655440001",
    "changed_at": "2023-01-03T10:15:00Z"
  }
}
```

#### user.password_reset

Топик: `auth.events`

Формат:
```json
{
  "event_type": "user.password_reset",
  "payload": {
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "reset_at": "2023-01-04T09:45:00Z"
  }
}
```

#### user.account_locked

Топик: `auth.events`

Формат:
```json
{
  "event_type": "user.account_locked",
  "payload": {
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "reason": "too_many_failed_attempts",
    "locked_at": "2023-01-05T16:20:00Z",
    "unlock_at": "2023-01-05T17:20:00Z"
  }
}
```

### Потребляемые события

#### user.deleted

Топик: `account.events`

Формат:
```json
{
  "event_type": "user.deleted",
  "payload": {
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "deleted_at": "2023-01-06T11:30:00Z"
  }
}
```

#### user.status_changed

Топик: `account.events`

Формат:
```json
{
  "event_type": "user.status_changed",
  "payload": {
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "old_status": "active",
    "new_status": "inactive",
    "changed_at": "2023-01-07T14:45:00Z"
  }
}
```

## Форматы данных

### Пользователь (User)

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "username": "username",
  "email_verified": true,
  "two_factor_enabled": false,
  "status": "active",
  "roles": ["user"],
  "created_at": "2023-01-01T12:00:00Z",
  "updated_at": "2023-01-02T14:30:00Z"
}
```

### Токены (Tokens)

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

### Роль (Role)

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440001",
  "name": "admin",
  "description": "Администратор системы",
  "permissions": [
    "users.read",
    "users.write",
    "roles.read",
    "roles.write"
  ],
  "created_at": "2023-01-01T12:00:00Z",
  "updated_at": "2023-01-01T12:00:00Z"
}
```

### Ошибка (Error)

```json
{
  "error": {
    "code": "auth_error",
    "message": "Неверный email или пароль",
    "details": {
      "field": "password",
      "reason": "invalid"
    },
    "request_id": "550e8400-e29b-41d4-a716-446655440002"
  }
}
```

## Обработка ошибок

Auth Service использует стандартизированный формат ошибок для всех API:

| Код HTTP | Код ошибки | Описание |
|----------|------------|----------|
| 400 | `validation_error` | Ошибка валидации данных |
| 401 | `unauthorized` | Отсутствие или недействительность токена аутентификации |
| 403 | `forbidden` | Недостаточно прав для выполнения операции |
| 404 | `not_found` | Запрашиваемый ресурс не найден |
| 409 | `conflict` | Конфликт данных (например, email уже существует) |
| 422 | `unprocessable_entity` | Невозможно обработать запрос |
| 429 | `too_many_requests` | Превышен лимит запросов |
| 500 | `internal_error` | Внутренняя ошибка сервера |

Все ошибки включают уникальный `request_id` для отслеживания и отладки, а также детали ошибки, когда это применимо.

## Примеры запросов

### cURL

#### Регистрация пользователя

```bash
curl -X POST \
  http://localhost:8080/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{
    "email": "user@example.com",
    "password": "securePassword123",
    "username": "username"
  }'
```

#### Аутентификация

```bash
curl -X POST \
  http://localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{
    "email": "user@example.com",
    "password": "securePassword123"
  }'
```

#### Проверка валидности токена

```bash
curl -X POST \
  http://localhost:8080/api/v1/auth/validate-token \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
```

### Go

```go
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

func main() {
	// Регистрация пользователя
	registerUser()
}

func registerUser() {
	url := "http://localhost:8080/api/v1/auth/register"
	
	requestBody, _ := json.Marshal(map[string]string{
		"email":    "user@example.com",
		"password": "securePassword123",
		"username": "username",
	})
	
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
	
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	
	fmt.Println("Response:", result)
}
```

### Dart (Flutter)

```dart
import 'dart:convert';
import 'package:http/http.dart' as http;

Future<void> registerUser() async {
  final url = Uri.parse('http://localhost:8080/api/v1/auth/register');
  
  final response = await http.post(
    url,
    headers: {'Content-Type': 'application/json'},
    body: jsonEncode({
      'email': 'user@example.com',
      'password': 'securePassword123',
      'username': 'username',
    }),
  );
  
  if (response.statusCode == 201) {
    final result = jsonDecode(response.body);
    print('User registered: $result');
  } else {
    print('Failed to register user: ${response.body}');
  }
}
```
