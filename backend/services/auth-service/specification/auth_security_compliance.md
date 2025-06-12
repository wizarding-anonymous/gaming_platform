<!-- File: backend/services/auth-service/specification/auth_security_compliance.md -->
# Auth Service: Security and Compliance Specification

**Version:** 1.0
**Date:** 2023-10-27

## 1. Introduction

This document details the specific security measures, compliance considerations, and non-functional security requirements for the Auth Service. As the gatekeeper for user identities and access, the Auth Service adheres to stringent security protocols to protect user data and platform resources.

## 2. Core Security Mechanisms

### 2.1 Password Management and Hashing
*   **Algorithm**: **Argon2id** is the standard for password hashing.
    *   Parameters:
        *   Memory: 64MB (`m=65536`)
        *   Iterations (Time Cost): 1 to 3 (configurable, start with `t=1` and profile)
        *   Parallelism (Threads): 4 (`p=4`)
        *   Key Length: 32 bytes
        *   Salt Length: 16 bytes (randomly generated per user)
*   **Storage**: Passwords are never stored in plaintext. Only the Argon2id hash and the unique salt are stored in the `users` table.
*   **Password Complexity**: Enforced at registration and password change via REST API validation.
    *   Minimum 8 characters.
    *   At least one uppercase letter.
    *   At least one lowercase letter.
    *   At least one digit.
    *   At least one special character (e.g., `!@#$%^&*()`).
*   **Password Reset**:
    *   Secure, time-limited, single-use tokens are generated for password reset requests.
    *   Tokens are sent via email (through Notification Service) to the user's verified email address.
    *   Upon successful password reset, all other active user sessions should be invalidated.

### 2.2 JSON Web Token (JWT) Security
*   **Algorithm**: **RS256** (RSA Signature with SHA-256). This uses a private key for signing tokens and a public key for verification.
*   **Key Management**:
    *   **Private Key**: Securely stored within the Auth Service infrastructure (e.g., HashiCorp Vault, encrypted Kubernetes Secret). Access is strictly limited to the Auth Service instances responsible for token signing.
    *   **Public Key**: Made available to other microservices and the API Gateway via a JWKS (JSON Web Key Set) endpoint (e.g., `GET /api/v1/auth/.well-known/jwks.json` or gRPC `GetJWKS`). This allows services to validate tokens locally.
    *   **Key Rotation**: Private/public key pairs should be rotated periodically (e.g., every 90-180 days). The JWKS endpoint should support multiple active public keys to allow for smooth key transition. The `kid` (Key ID) claim in the JWT header is used to identify which key signed the token.
*   **Access Token (AT)**:
    *   **Purpose**: Used to authenticate and authorize requests to protected API endpoints.
    *   **TTL**: Short-lived, typically **15 minutes**.
    *   **Claims**: Contains `iss`, `sub` (user_id), `aud`, `exp`, `nbf`, `iat`, `jti`, `username`, `roles`, `permissions`, `session_id`.
    *   **Transmission**: Sent in the `Authorization: Bearer <token>` HTTP header.
    *   **Storage**: Client-side, typically in memory (e.g., JavaScript variable in SPAs). Avoid storing in `localStorage`.
*   **Refresh Token (RT)**:
    *   **Purpose**: Used to obtain new Access Tokens without requiring the user to re-authenticate.
    *   **TTL**: Long-lived, typically **30 days**.
    *   **Format**: Opaque, cryptographically strong random string.
    *   **Storage (Server-side)**: A hash (e.g., SHA256) of the Refresh Token is stored in the `refresh_tokens` PostgreSQL table, linked to a user session.
    *   **Storage (Client-side)**: If used in web applications, stored in a secure, HttpOnly, SameSite=Strict cookie. For mobile/desktop clients, stored in secure device storage.
    *   **Rotation**: Upon use, the existing Refresh Token is invalidated, and a new Refresh Token is issued along with the new Access Token. This helps detect and mitigate theft of refresh tokens.
    *   **Revocation**: Can be revoked by deleting or marking the corresponding hash in the database (e.g., on logout, password change, "logout all devices").
*   **JTI (JWT ID)**: A unique identifier for each JWT, can be used for revocation purposes if a blacklist mechanism is implemented for access tokens (though short expiry is the primary defense).

### 2.3 Two-Factor Authentication (2FA) Security
*   **TOTP (Time-based One-Time Password)**:
    *   **Algorithm**: RFC 6238.
    *   **Secret Storage**: User-specific TOTP secrets are encrypted at the application level (e.g., using AES-256-GCM with a master key stored in Vault) before being stored in the `mfa_secrets` table.
    *   **QR Code Provisioning**: Uses `otpauth://` URI scheme.
    *   **Code Validation**: Server validates TOTP codes considering time drift (e.g., +/- 1 time window).
*   **Backup Codes**:
    *   Generated once upon 2FA setup.
    *   Displayed to the user only once.
    *   Stored as hashes (e.g., SHA256) in the `mfa_backup_codes` table.
    *   Each code is single-use.
*   **SMS/Email Codes (via Notification Service)**:
    *   Codes are short-lived (e.g., 5-10 minutes).
    *   Codes are single-use.
    *   Rate limiting is applied to requests for SMS/Email codes.
    *   Transmission security depends on the Notification Service and underlying providers.

### 2.4 API Key Security
*   **Generation**: API keys consist of a non-secret prefix (for identification) and a long, cryptographically random secret part.
*   **Storage**: Only a hash (e.g., SHA256) of the secret part is stored in the `api_keys` database table. The full key is shown to the user only once upon creation.
*   **Permissions**: API keys are scoped with a specific set of permissions.
*   **Transmission**: Keys must be transmitted securely by clients, typically in an HTTP header (e.g., `X-API-Key`).
*   **Revocation**: Keys can be revoked by administrators or users.

## 3. Protection Against Common Attacks

### 3.1 Brute-Force Attacks
*   **Login/2FA/Password Reset**: Implement rate limiting on these endpoints based on user ID/login identifier and IP address.
*   **Account Lockout**: Temporarily lock accounts or IP addresses after a configurable number of failed attempts (e.g., 5 attempts within 15 minutes). Lockout duration can increase exponentially.
*   **CAPTCHA**: Consider integrating CAPTCHA (e.g., Yandex SmartCaptcha, hCaptcha) after several failed attempts, especially for registration and password reset.

### 3.2 Credential Stuffing
*   Monitor for unusual login success/failure rates.
*   Integrate with services like "Have I Been Pwned?" to check if user passwords have appeared in known breaches (during registration or as an ongoing check).
*   Strongly encourage/enforce 2FA.

### 3.3 Session Hijacking
*   Use HttpOnly, Secure, SameSite=Strict cookies for web-based refresh tokens.
*   Short-lived access tokens minimize the impact of a stolen AT.
*   Refresh token rotation helps detect if an old RT is compromised and used.
*   Bind sessions to IP addresses or device fingerprints (configurable, with considerations for user experience on dynamic IPs).
*   Allow users to view and revoke active sessions.

### 3.4 Cross-Site Request Forgery (CSRF)
*   For state-changing operations initiated from web browsers that rely on cookie-based sessions (if any part of Auth Service directly serves web forms, though this is less common for a pure API service).
*   Use anti-CSRF tokens (e.g., synchronizer token pattern).
*   Check `Origin` / `Referer` headers.
*   *Note: JWT Bearer token authentication is generally not vulnerable to CSRF if tokens are not stored in cookies accessible by JavaScript.*

### 3.5 Cross-Site Scripting (XSS)
*   While Auth Service is primarily an API, any admin UIs or user-facing pages it might serve (e.g., for OAuth consent) must:
    *   Properly sanitize and escape all user-supplied output.
    *   Implement a strict Content Security Policy (CSP).

### 3.6 Data Exposure and Enumeration
*   Generic error messages for failed login attempts ("Invalid login or password") to prevent username/email enumeration.
*   Similar generic messages for password reset requests ("If an account with this email exists...").
*   Limit information returned in public-facing API responses.

## 4. Compliance and Data Privacy

### 4.1 ФЗ-152 "О персональных данных"
*   **Data Localization**: All personal data of Russian citizens, including authentication credentials and audit logs, must be stored and processed in databases located within the Russian Federation.
*   **Consent**: Obtain explicit user consent for processing personal data for authentication and security purposes. This is typically part of the platform's main terms of service and privacy policy.
*   **Data Minimization**: Collect and store only the personal data strictly necessary for authentication and authorization.
*   **User Rights**: Provide mechanisms for users to access, rectify, and request deletion of their authentication-related personal data (in conjunction with Account Service).
*   **Security Measures**: Implement appropriate technical and organizational measures to protect personal data from unauthorized access, alteration, disclosure, or destruction. This includes encryption, access controls, and regular security audits.

### 4.2 Audit Logging (FR-AUTH-012)
*   **Scope**: Log all security-relevant events, including:
    *   Successful and failed authentication attempts (with IP, user agent).
    *   Password changes and resets.
    *   2FA enablement, disablement, and verification attempts.
    *   Session creation and revocation.
    *   API key creation and revocation.
    *   Administrative actions related to user accounts, roles, and permissions.
    *   Changes to security configurations.
*   **Content**: Logs must include timestamp, actor (user ID or system), action, target (user ID or resource ID), status (success/failure), source IP, user agent, and relevant details.
*   **Integrity**: Audit logs must be protected from tampering.
*   **Retention**: Audit logs should be retained for a defined period (e.g., 1-3 years) according to platform policy and any legal requirements.
*   **Access**: Access to audit logs should be restricted to authorized personnel (e.g., security team, administrators).

## 5. Security of Integrations

*   **Inter-Service Communication**:
    *   Use mTLS for securing gRPC communication between Auth Service and other internal microservices.
    *   Services calling Auth Service gRPC endpoints should authenticate themselves (e.g., using service account tokens or client certificates).
*   **Notification Service**:
    *   Ensure that sensitive information (like OTPs or password reset tokens) sent via Notification Service is handled securely by Notification Service and its downstream providers (Email/SMS gateways).
    *   Minimize the amount of sensitive data passed (e.g., send only the code, not full links with tokens if possible, or use short-lived, single-use tokens in links).
*   **External OAuth Providers**:
    *   Use `state` parameter to prevent CSRF in OAuth flows.
    *   Securely store `client_id` and `client_secret` for each provider.
    *   Validate ID tokens and access tokens received from providers according to their specifications.

## 6. Regular Security Practices

*   **Dependency Scanning**: Regularly scan application dependencies (Go modules) for known vulnerabilities.
*   **Static Application Security Testing (SAST)**: Integrate SAST tools into the CI/CD pipeline.
*   **Dynamic Application Security Testing (DAST)**: Perform DAST on running instances in staging environments.
*   **Penetration Testing**: Conduct periodic penetration tests by independent security experts.
*   **Security Code Reviews**: Ensure security considerations are part of the code review process.
*   **Incident Response Plan**: Have a documented plan for responding to security incidents.

---
*This document outlines critical security aspects. It should be regularly reviewed and updated to reflect evolving threats and best practices. Adherence to global and local security standards (e.g., OWASP, ФСТЭК guidelines if applicable) is paramount.*
