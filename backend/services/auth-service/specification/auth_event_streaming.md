<!-- File: backend/services/auth-service/specification/auth_event_streaming.md -->
# Auth Service: Event Streaming Specification

**Version:** 1.0
**Date:** 2023-10-27

## 1. Introduction

This document specifies the event-driven interactions for the Auth Service. It details the events published by the Auth Service to a message broker (Kafka) and the events it consumes from other services. These events facilitate asynchronous communication and decoupling between microservices.

## 2. Eventing System

*   **Message Broker**: Apache Kafka is used as the event streaming platform.
*   **Event Format**: All events adhere to the CloudEvents v1.0 specification, using JSON for the data payload.
*   **Serialization**: JSON.
*   **Topics**:
*   Auth Service primarily publishes to a dedicated topic: `auth.events`.
    *   Auth Service consumes events from topics related to other services (e.g., `account-events`, `admin-events`).
*   **Partitions**: Kafka topics should be partitioned appropriately (e.g., by `user_id` or `subject` of the CloudEvent where relevant) to ensure ordered processing for related events and to allow for consumer scaling.
*   **Consumer Groups**: Each consuming service (or logical group of instances) should use a unique consumer group ID for Kafka.

## 3. Common CloudEvents Attributes

All events published by the Auth Service will include the following CloudEvents attributes:

*   `specversion`: "1.0"
*   `id`: A unique UUID for each event instance (e.g., `a1b2c3d4-e5f6-7890-abcd-ef1234567890`).
*   `source`: A URI identifying the Auth Service (e.g., `/auth-service` or `urn:service:auth`).
*   `type`: A string identifying the type of event (e.g., `com.yourplatform.auth.user.registered.v1`). Versioning is included in the type.
*   `time`: Timestamp of when the event occurred (ISO 8601 format, UTC).
*   `datacontenttype`: "application/json"
*   `subject`: Optional. The primary subject of the event, often the `user_id` (e.g., `urn:user:a1b2c3d4-e5f6-7890-abcd-ef1234567890`).
*   `data`: The event-specific payload.

## 4. Published Events

Auth Service publishes the following events to the `auth.events` Kafka topic.

---

### 4.1 Event: `auth.user.registered.v1`
*   **Type**: `com.yourplatform.auth.user.registered.v1`
*   **Description**: Published when a new user successfully completes the initial registration process (before email verification, if applicable).
*   **Trigger**: Successful creation of a user record in the Auth Service database.
*   **Consumers**: Account Service (to create user profile), Notification Service (to initiate welcome/verification email), Analytics Service.
*   **Payload (`data`) Schema**:
    ```json
    {
      "user_id": "uuid", // Required: The unique ID of the registered user
      "username": "string", // Required: The chosen username
      "email": "string", // Required: The user's email address
      "display_name": "string", // Optional: The user's display name, if provided during registration
      "registration_timestamp": "string(date-time)", // Required: ISO 8601 timestamp of registration
      "initial_status": "string" // Required: e.g., "pending_verification"
    }
    ```
*   **Example Payload**:
    ```json
    {
      "user_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "username": "newuser123",
      "email": "newuser@example.com",
      "display_name": "Новый Пользователь",
      "registration_timestamp": "2023-10-27T10:00:00Z",
      "initial_status": "pending_verification"
    }
    ```

---

### 4.2 Event: `auth.user.email_verified.v1`
*   **Type**: `com.yourplatform.auth.user.email_verified.v1`
*   **Description**: Published when a user successfully verifies their email address.
*   **Trigger**: Successful validation of an email verification token.
*   **Consumers**: Account Service (to update user profile status), Analytics Service.
*   **Payload (`data`) Schema**:
    ```json
    {
      "user_id": "uuid", // Required
      "email": "string", // Required: The verified email address
      "verification_timestamp": "string(date-time)" // Required: ISO 8601 timestamp
    }
    ```

---

### 4.3 Event: `auth.user.password_reset_requested.v1`
*   **Type**: `com.yourplatform.auth.user.password_reset_requested.v1`
*   **Description**: Published when a user requests a password reset.
*   **Trigger**: User initiates the "forgot password" flow.
*   **Consumers**: Notification Service (to send password reset email), Analytics Service.
*   **Payload (`data`) Schema**:
    ```json
    {
      "user_id": "uuid", // Required
      "email": "string", // Required: Email to which the reset link is sent
      "request_timestamp": "string(date-time)", // Required
      "reset_token_identifier": "string" // Optional: An identifier for the token (not the token itself) for logging/tracking
    }
    ```

---

### 4.4 Event: `auth.user.password_changed.v1`
*   **Type**: `com.yourplatform.auth.user.password_changed.v1`
*   **Description**: Published when a user successfully changes their password (either through reset or normal change).
*   **Trigger**: Successful password update in the database.
*   **Consumers**: Notification Service (to inform user of password change), Analytics Service, potentially other services to invalidate sessions.
*   **Payload (`data`) Schema**:
    ```json
    {
      "user_id": "uuid", // Required
      "change_timestamp": "string(date-time)", // Required
      "change_type": "string" // Required: e.g., "user_initiated", "admin_reset", "forgot_password_flow"
    }
    ```

---

### 4.5 Event: `auth.user.login_success.v1`
*   **Type**: `com.yourplatform.auth.user.login_success.v1`
*   **Description**: Published upon a successful user login.
*   **Trigger**: Successful credential validation and (if applicable) 2FA.
*   **Consumers**: Analytics Service, Account Service (to update last login time), potentially services for real-time user status.
*   **Payload (`data`) Schema**:
    ```json
    {
      "user_id": "uuid", // Required
      "session_id": "uuid", // Required: The new session ID created
      "login_timestamp": "string(date-time)", // Required
      "ip_address": "string", // Required
      "user_agent": "string", // Required
      "device_info": { // Optional: As provided during login
        "type": "string",
        "os": "string",
        "app_version": "string",
        "device_name": "string"
      }
    }
    ```

---

### 4.6 Event: `auth.user.login_failed.v1`
*   **Type**: `com.yourplatform.auth.user.login_failed.v1`
*   **Description**: Published upon a failed login attempt.
*   **Trigger**: Invalid credentials, failed 2FA, or other login impediment.
*   **Consumers**: Analytics Service, Security/Fraud Detection Service.
*   **Payload (`data`) Schema**:
    ```json
    {
      "attempted_login_identifier": "string", // Required: The username or email used for the attempt
      "failure_reason": "string", // Required: e.g., "invalid_credentials", "invalid_2fa_code", "account_locked", "email_not_verified"
      "failure_timestamp": "string(date-time)", // Required
      "ip_address": "string", // Required
      "user_agent": "string" // Required
    }
    ```

---

### 4.7 Event: `auth.user.account_locked.v1`
*   **Type**: `com.yourplatform.auth.user.account_locked.v1`
*   **Description**: Published when a user account is locked due to suspicious activity or too many failed attempts.
*   **Trigger**: Logic within Auth Service detecting conditions for account lockout.
*   **Consumers**: Notification Service (to inform user), Admin Service, Analytics Service.
*   **Payload (`data`) Schema**:
    ```json
    {
      "user_id": "uuid", // Required
      "lock_timestamp": "string(date-time)", // Required
      "reason": "string", // Required: e.g., "too_many_failed_login_attempts", "suspicious_activity_detected"
      "lockout_duration_seconds": "integer" // Optional: Duration of lockout in seconds, if temporary
    }
    ```

---

### 4.8 Event: `auth.user.roles_changed.v1`
*   **Type**: `com.yourplatform.auth.user.roles_changed.v1`
*   **Description**: Published when a user's roles are modified by an administrator.
*   **Trigger**: Administrative action via Admin Service resulting in role change.
*   **Consumers**: Services that cache or depend on user roles, Analytics Service.
*   **Payload (`data`) Schema**:
    ```json
    {
      "user_id": "uuid", // Required
      "old_roles": ["string"], // Required: List of roles before change
      "new_roles": ["string"], // Required: List of roles after change
      "changed_by_user_id": "uuid", // Required: ID of the admin who made the change
      "change_timestamp": "string(date-time)" // Required
    }
    ```

---

### 4.9 Event: `auth.session.created.v1`
*   **Type**: `com.yourplatform.auth.session.created.v1`
*   **Description**: Published when a new user session is successfully created (typically after login or 2FA).
*   **Trigger**: Successful session establishment.
*   **Consumers**: Analytics Service, services interested in active user sessions.
*   **Payload (`data`) Schema**:
    ```json
    {
      "session_id": "uuid", // Required
      "user_id": "uuid", // Required
      "ip_address": "string", // Required
      "user_agent": "string", // Required
      "device_info": { /* ... */ }, // Optional
      "creation_timestamp": "string(date-time)", // Required
      "refresh_token_expires_at": "string(date-time)" // Required
    }
    ```

---

### 4.10 Event: `auth.session.revoked.v1`
*   **Type**: `com.yourplatform.auth.session.revoked.v1`
*   **Description**: Published when a user session (identified by its refresh token or session ID) is revoked.
*   **Trigger**: User logout, "logout all" action, password change, admin action.
*   **Consumers**: Analytics Service, services that might need to invalidate local caches based on sessions.
*   **Payload (`data`) Schema**:
    ```json
    {
      "session_id": "uuid", // Required
      "user_id": "uuid", // Required
      "revocation_timestamp": "string(date-time)", // Required
      "reason": "string" // Required: e.g., "user_logout", "password_change", "admin_action", "token_compromised"
    }
    ```

---

### 4.11 Event: `auth.2fa.enabled.v1`
*   **Type**: `com.yourplatform.auth.2fa.enabled.v1`
*   **Description**: Published when a user successfully enables a 2FA method.
*   **Trigger**: Successful verification and activation of a 2FA method.
*   **Consumers**: Analytics Service, Account Service (to update user security profile).
*   **Payload (`data`) Schema**:
    ```json
    {
      "user_id": "uuid", // Required
      "method": "string", // Required: e.g., "totp", "sms"
      "enabled_timestamp": "string(date-time)" // Required
    }
    ```

---

### 4.12 Event: `auth.2fa.disabled.v1`
*   **Type**: `com.yourplatform.auth.2fa.disabled.v1`
*   **Description**: Published when a user successfully disables a 2FA method.
*   **Trigger**: User successfully confirms disabling of a 2FA method.
*   **Consumers**: Analytics Service, Account Service.
*   **Payload (`data`) Schema**:
    ```json
    {
      "user_id": "uuid", // Required
      "method": "string", // Required: e.g., "totp", "sms"
      "disabled_timestamp": "string(date-time)" // Required
    }
    ```
---

## 5. Consumed Events

Auth Service consumes the following events from other services.

---

### 5.1 Event: `account.user.profile_updated.v1`
*   **Source Topic**: `account-events`
*   **Source Service**: Account Service
*   **Description**: Consumed to be aware of changes in user profile that might affect authentication or authorization status (e.g., if an email change requires re-verification, or if a status change impacts login ability).
*   **Action in Auth Service**:
    *   Potentially update cached user information if Auth Service maintains any.
    *   If user status changed to 'blocked' or 'deleted', Auth Service might need to revoke active sessions and refresh tokens for that user.
*   **Expected Payload (`data`) Schema**:
    ```json
    {
      "user_id": "uuid", // Required
      "updated_fields": ["string"], // Required: List of fields that were updated, e.g., ["email", "status", "display_name"]
      "old_values": { // Optional: Contains previous values of updated fields, if applicable and needed by consumers
        "email": "old_email@example.com",
        "status": "pending_verification"
      },
      "new_values": { // Required: Contains new values of updated fields
        "email": "new_email@example.com",
        "status": "active",
        "display_name": "New Display Name"
      },
      "update_timestamp": "string(date-time)" // Required: Timestamp of the update
    }
    ```

---

### 5.2 Event: `admin.user.force_logout.v1`
*   **Source Topic**: `admin-events`
*   **Source Service**: Admin Service
*   **Description**: Consumed when an administrator forces a user to log out from all sessions.
*   **Action in Auth Service**:
    *   Revoke all active refresh tokens for the specified `user_id`.
    *   Add all active access tokens (or their JTIs/associated session_ids) for the user to a short-lived blacklist in Redis.
    *   Publish `auth.session.revoked` events for each revoked session.
*   **Expected Payload (`data`) Schema**:
    ```json
    {
      "user_id": "uuid", // Required: User to be logged out
      "admin_user_id": "uuid", // Required: Admin who initiated the action
      "reason": "string", // Optional: Reason for forced logout
      "action_timestamp": "string(date-time)"
    }
    ```

---

### 5.3 Event: `admin.user.block.v1`
*   **Source Topic**: `admin-events`
*   **Source Service**: Admin Service
*   **Description**: Consumed when an administrator blocks a user account.
*   **Action in Auth Service**:
    *   Update the user's status to `blocked` in the Auth Service's `users` table.
    *   Revoke all active refresh tokens for the user.
    *   Add active access tokens to a blacklist.
    *   Publish `auth.user.account_locked` (or a more specific `auth.user.account_blocked_by_admin`) event.
    *   Publish `auth.session.revoked` events.
*   **Expected Payload (`data`) Schema**:
    ```json
    {
      "user_id": "uuid", // Required: User to be blocked
      "admin_user_id": "uuid", // Required
      "reason": "string", // Required
      "action_timestamp": "string(date-time)"
    }
    ```

---

### 5.4 Event: `admin.user.unblock.v1`
*   **Source Topic**: `admin-events`
*   **Source Service**: Admin Service
*   **Description**: Consumed when an administrator unblocks a user account.
*   **Action in Auth Service**:
    *   Update the user's status to `active` (or `pending_verification` if email was never verified) in the Auth Service's `users` table.
    *   Publish an `auth.user.account_unlocked` (or similar) event.
*   **Expected Payload (`data`) Schema**:
    ```json
    {
      "user_id": "uuid", // Required: User to be unblocked
      "admin_user_id": "uuid", // Required
      "reason": "string", // Optional
      "action_timestamp": "string(date-time)"
    }
    ```

---
*This event streaming specification outlines the key asynchronous interactions. Payloads should be kept minimal, containing only necessary information to act upon or to avoid further lookups. Clear versioning of event types (e.g., `.v1`) is crucial for schema evolution.*
