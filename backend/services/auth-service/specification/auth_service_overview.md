<!-- File: backend/services/auth-service/specification_final/auth_service_overview.md -->
# Auth Service Overview

**Version:** 1.0
**Date:** 2023-10-27

## 1. Introduction

The Auth Service is a critical component of the "российского аналога платформы Steam" platform, acting as the central authority for managing user identity, authentication, and authorization. It is designed to be a secure, scalable, and reliable service that underpins the security model of the entire platform.

This document provides a high-level overview of the Auth Service, its purpose, key responsibilities, and its role within the broader microservice architecture.

## 2. Purpose and Role

The primary purpose of the Auth Service is to:

*   **Authenticate Users**: Securely verify the identity of users attempting to access the platform through various methods (credentials, 2FA, external providers).
*   **Authorize Access**: Control access to platform resources and functionalities based on user roles and permissions.
*   **Manage Sessions**: Handle user sessions, including the issuance, validation, and revocation of access and refresh tokens (JWT).
*   **Provide Identity Information**: Supply other microservices with trusted information about the authenticated user.
*   **Centralize Security Logic**: Consolidate core security functions to ensure consistency and robustness.

The Auth Service plays a pivotal role in the platform's security by:

*   Serving as the **single point of truth for user authentication status**.
*   Enforcing **authentication and authorization policies** consistently across all integrated services.
*   Managing the **lifecycle of security tokens and API keys**.
*   Facilitating **secure inter-service communication** by providing mechanisms for service identity and authorization.

## 3. Key Responsibilities and Functionalities

The Auth Service is responsible for a wide range of functionalities, including:

*   **User Registration**: Handling the creation of new user accounts (in coordination with the Account Service for profile data). This includes password hashing using Argon2id.
*   **User Login**: Authenticating users via email/username and password.
*   **Two-Factor Authentication (2FA)**:
    *   Supporting Time-based One-Time Passwords (TOTP) via authenticator apps.
    *   Supporting code delivery via SMS/Email (integrating with Notification Service).
    *   Management of backup codes.
*   **External Authentication Providers**:
    *   Integration with OAuth 2.0 / OpenID Connect compliant providers.
    *   Specific support for Telegram Login, ВКонтакте (VK), and Одноклассники.
*   **JSON Web Token (JWT) Management**:
    *   Generation of short-lived Access Tokens (signed with RS256).
    *   Generation of long-lived Refresh Tokens (with rotation and secure storage).
    *   Validation and parsing of tokens.
*   **Session Management**:
    *   Tracking active user sessions.
    *   Allowing users to view and revoke their active sessions (including "logout from all devices").
*   **Password Management**:
    *   Secure password reset mechanism (via email confirmation).
    *   Password change functionality for authenticated users.
*   **Email Confirmation**: Managing the process of verifying user email addresses.
*   **Role-Based Access Control (RBAC)**:
    *   Storing and managing user roles and permissions (based on the "Единый реестр ролей пользователей и матрица доступа").
    *   Including roles and permissions within JWT Access Tokens.
    *   Providing an API for other services to check user permissions.
*   **API Key Management**:
    *   Generation, validation, and revocation of API keys for developers and external services.
*   **Security Event Auditing**:
    *   Logging all significant security-related events (logins, logouts, password changes, 2FA events, role changes, etc.).
*   **Suspicious Activity Detection**:
    *   Basic mechanisms for detecting and reacting to suspicious login patterns (e.g., multiple failed attempts leading to temporary account or IP blocking).
*   **Administrative Functions**:
    *   Providing interfaces for administrators (via Admin Service) to manage users, roles, and view audit logs.

## 4. High-Level Architecture

The Auth Service is designed as a stateless microservice, primarily written in Go. It interacts with:

*   **Databases**:
    *   **PostgreSQL**: For persistent storage of user credentials (hashed passwords), roles, permissions, refresh tokens (hashed), API keys (hashed), MFA secrets (encrypted), and audit logs.
    *   **Redis**: For caching session information, temporary tokens (e.g., for 2FA, password reset), and potentially for rate limiting counters or token blacklisting.
*   **Message Broker**:
    *   **Kafka**: For publishing security-related events (e.g., `auth.user.registered`, `auth.user.login_success`) and consuming events from other services (e.g., `admin.user.block`).
*   **Other Microservices**:
    *   **API Gateway**: All external API calls are routed through the API Gateway, which typically delegates token validation to the Auth Service.
    *   **Account Service**: For user profile information and during the registration process.
    *   **Notification Service**: To send out emails (verification, password reset) and SMS (2FA codes).
    *   **Admin Service**: To expose administrative functionalities.
    *   **Various other microservices**: For validating tokens and checking permissions.

It exposes both RESTful and gRPC APIs for different types of consumers.

## 5. Core Technologies

*   **Programming Language**: Go
*   **API Frameworks**: Gin (for REST), standard `net/http` and `grpc-go` (for gRPC).
*   **Database Interaction**: `pgx` for PostgreSQL, `go-redis` for Redis.
*   **Messaging**: `confluent-kafka-go` for Kafka.
*   **Security**: `golang-jwt/jwt/v5` for JWTs, `golang.org/x/crypto/argon2` for password hashing.
*   **Logging**: `Zap`.
*   **Monitoring**: `Prometheus client_golang`.
*   **Tracing**: `OpenTelemetry`.

## 6. Related Documents

This overview is part of a larger set of specifications for the Auth Service. For more detailed information, please refer to:

*   `Auth_Service_Detailed_Specification.md` (Parent document)
*   `auth_api_rest.md` (Detailed REST API)
*   `auth_api_grpc.md` (Detailed gRPC API)
*   `auth_service_logic.md` (Detailed Service Logic and Workflows)
*   `auth_data_model.md` (Database Schema and Data Models)
*   `auth_event_streaming.md` (Kafka Event Specifications)
*   `auth_security_compliance.md` (Security and Compliance Details)
*   `auth_integrations.md` (Integration details with other services)
*   [Единый глоссарий терминов и определений для российского аналога Steam.txt]
*   [Единый реестр ролей пользователей и матрица доступа.txt]
*   [Стандарты API, форматов данных, событий и конфигурационных файлов.txt]

*(This file provides a starting point. It will be augmented by the subsequent, more detailed specification files.)*
