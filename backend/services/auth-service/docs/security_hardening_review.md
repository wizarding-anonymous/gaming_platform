# Security Hardening Review & Recommendations

Date: (Current Date)
Version: Based on current state of conceptual implementation.

This document summarizes a review of the Auth microservice codebase (as conceptually implemented and partially coded in previous subtasks) and its specification (`auth_microservice_specification_final.md`) for security hardening and best practices.

## 1. Input Validation

*   **Findings**:
    *   REST API handlers (conceptually and in implemented examples like `auth_handler.go`, `me_handler.go`) utilize Gin's binding (`ShouldBindJSON`, `ShouldBindQuery`) with struct tags (e.g., `binding:"required,email"`). This provides a good baseline for validating presence, format, and basic constraints of incoming data.
    *   gRPC handlers (conceptually, e.g., `auth_v1_grpc_service.go`) include manual checks for required fields in request messages.
*   **Recommendations**:
    *   **Service Layer Validation**: Ensure comprehensive business rule validation is performed at the service layer for all inputs, beyond basic format checks. This includes checking for valid enum values, range constraints not covered by struct tags, and context-specific rules.
    *   **Input Sanitization**: While not explicitly reviewed, ensure that any data used in constructing responses or logged (where PII is involved and cannot be avoided) is properly sanitized or encoded if it originated from user input, to prevent XSS if these logs/responses are ever rendered in web contexts. For data used in SQL queries, the use of parameterized queries (as seen in `pgx` repository implementations) is crucial and correctly applied.
    *   **File Uploads (if any)**: If any future endpoints involve file uploads (e.g., profile pictures managed by a different service but linked here), ensure strict validation of file types, sizes, and content. (Not currently in scope for Auth service).
    *   **Rate Limiting on Validation-Heavy Endpoints**: Consider rate limiting on endpoints that might trigger complex validation logic if they are computationally expensive.

## 2. Error Handling

*   **Findings**:
    *   Handler implementations conceptually map service layer errors to HTTP status codes and return JSON error messages (e.g., `gin.H{"error": message}`).
    *   gRPC handlers conceptually map errors to gRPC status codes.
*   **Recommendations**:
    *   **No Sensitive Leakage**: Consistently ensure that no internal error details (Go error strings from non-custom errors, stack traces, database error specifics beyond "not found" or "conflict") are ever propagated to the client. Log detailed errors internally.
    *   **Standardized Error DTO**: Implement a standardized JSON error response DTO for REST APIs, including fields like `code` (internal error code or string), `message` (user-friendly), and optionally `details` (for specific field errors if safe to expose). This is partially done with `gin.H{"error": ...}` but could be more structured.
    *   **gRPC Richer Error Models**: For gRPC, consider using `google.rpc.Status` and `google.rpc.BadRequest` (or similar) for more detailed error reporting beyond standard gRPC codes, if client libraries can effectively use this.

## 3. Brute-Force Protection

*   **Findings**:
    *   The specification (Section 7.6) calls for brute-force protection (rate limiting, CAPTCHA, account lockout).
    *   `AuthLogicService.LoginUser` conceptually included incrementing failed login attempts (`UpdateFailedLoginAttempts` on `UserRepository`).
    *   A dedicated `LoginAttemptService` was not explicitly implemented.
*   **Recommendations**:
    *   **Implement Dedicated Service**: Implement a robust `LoginAttemptService` (or similar) using a fast KVS like Redis.
    *   **Track Attempts**: Track failed login attempts per user account and per IP address.
    *   **Rate Limiting**: Implement strict rate limiting on login, 2FA verification, password reset request, and email verification request endpoints.
    *   **Account Lockout**: Implement temporary account lockout after a configured number of failed login attempts. The `users.lockout_until` field and `UserRepository.UpdateFailedLoginAttempts` (which should update lockout) are good foundations.
    *   **2FA & Password Reset**: Extend brute-force protection to 2FA code verification and password reset token verification steps.
    *   **CAPTCHA**: Plan for CAPTCHA integration after several failed attempts from an IP or on a specific account, as mentioned in the spec.

## 4. Session Management

*   **Findings**:
    *   Refresh token rotation was conceptually part of `AuthLogicService.RefreshToken`.
    *   Session IDs are UUIDs.
    *   Logout (`LogoutUser`) and Logout All (`LogoutAllUserSessions`) logic aims to revoke/delete refresh tokens and sessions.
*   **Recommendations**:
    *   **Refresh Token Invalidation**: Ensure that when a refresh token is used, it is *always* invalidated or rotated, even if the access token generation fails for some reason after the refresh token has been validated. This is crucial for preventing token reuse.
    *   **Session Binding**: If sessions are bound to IP addresses or User-Agents, ensure this is clearly communicated and handled, especially for single-page applications or mobile clients where network changes can occur. (The current schema stores these but doesn't enforce binding).
    *   **HttpOnly Cookies for Refresh Tokens**: For web clients, strongly recommend storing refresh tokens in `HttpOnly`, `Secure`, `SameSite=Strict` cookies to mitigate XSS. The service layer should be agnostic to this, but API gateway or frontend BFF would handle it.

## 5. API Key Security

*   **Findings**:
    *   `APIKeyService.GenerateAndStoreAPIKey` returns the raw key only once.
    *   API key secrets are hashed using `PasswordService` (Argon2id).
    *   Authentication logic (`AuthenticateByAPIKey`) involves finding by prefix and then using `PasswordService.CheckPasswordHash`.
*   **Recommendations**:
    *   **Hashing Algorithm**: While Argon2id is very secure, it's computationally intensive. For API keys that might be validated frequently at high throughput, evaluate if a faster, still secure hash like SHA256 or SHA512 (properly salted, though salt is part of Argon2id output) would be more appropriate for the `key_hash`. The current approach is secure but might have performance implications at extreme scale. *Decision to use Argon2id was made for consistency in the subtask, but this is a review point.*
    *   **Prefix Uniqueness**: Ensure the `key_prefix` stored in the database for each key is globally unique as it's used for lookup. The current generation logic in `GenerateAndStoreAPIKey` (e.g., `sk_<ID_PART>_`) aims for this.
    *   **Permissions**: Ensure API key permissions are granular and follow the principle of least privilege.

## 6. Audit Logging Integration Plan

*   **Findings**:
    *   `audit_integration_plan.md` was created in the previous subtask (Turn 51).
    *   It lists many critical events: user registration, login success/failure, 2FA changes, role changes, API key CUD, admin actions.
*   **Recommendations**:
    *   **Completeness Check**: Cross-reference the plan with OWASP Top 10 logging recommendations and any specific compliance requirements. Ensure all sensitive operations and security mechanism interactions are logged.
    *   **Failure Details**: For failure events, ensure the logged `details` field captures sufficient non-sensitive context about the failure reason without logging overly verbose or private data.
    *   **Log Review and Alerting**: Note that having logs is step one; a plan for regular review, monitoring, and alerting on suspicious audit log patterns is crucial (outside current scope but important).

## 7. Sensitive Data Handling

*   **Findings**:
    *   Service logic and DTOs generally avoid exposing raw password hashes or secrets post-creation.
    *   Placeholder encryption for TOTP secrets.
*   **Recommendations**:
    *   **Logging**: Re-iterate: No plaintext passwords, API keys, session tokens, or TOTP secrets should ever be logged in production. If request/response bodies are logged at DEBUG level, ensure these fields are masked. The `zap.ByteString("payload", ...)` example in Kafka producer was noted for caution.
    *   **Configuration**: Ensure JWT secrets, API signing keys, database credentials, and encryption keys are loaded from secure configurations (e.g., environment variables, Kubernetes secrets, Vault) and never hardcoded. The current `config.yaml` uses placeholders, which is correct.

## 8. Dependency Review (Conceptual)

*   **Recommendations**:
    *   Use a dependency management tool (Go modules are used).
    *   Pin dependency versions (`go.mod` does this).
    *   Regularly scan dependencies for known vulnerabilities using tools like `govulncheck`.
    *   Keep dependencies updated.

## 9. Placeholder Encryption

*   **Findings**:
    *   Placeholder `EncryptSecret` and `DecryptSecret` functions were created in `internal/infrastructure/security/totp_mock.go` for TOTP secrets. These are clearly marked as placeholders and **NOT FOR PRODUCTION USE**.
*   **Recommendations**:
    *   **Prioritize Replacement**: These placeholders MUST be replaced with a strong, standard cryptographic library (e.g., AES-GCM with a securely managed key) before any production deployment. The key used for this symmetric encryption must be stored securely, e.g., in HashiCorp Vault or similar.

## 10. General Security Best Practices

*   **HTTPS**: Ensure all communication is over HTTPS (handled by ingress/load balancer typically).
*   **Secure Headers**: Implement security headers (X-Content-Type-Options, X-Frame-Options, CSP, HSTS) at the API gateway or web server level.
*   **Least Privilege**: Ensure service accounts (e.g., for database access) have only the minimum necessary permissions.
*   **Regular Security Audits**: Conduct regular security code reviews and penetration testing.

## 11. Small Security Utilities Implementation

*   No small, isolated security utility functions were identified as critically missing *and* feasible to implement in the final turn without risking further file modification issues. The focus remains on the review and documentation aspect. Existing use of `crypto/rand`, `crypto/hmac`, `crypto/sha256`, and `golang.org/x/crypto/argon2` covers many basic needs. Constant-time comparison is provided by `subtle.ConstantTimeCompare` and was used in the Argon2id implementation.

This review provides a snapshot based on the conceptual and partial implementation. A full security audit would require a complete and testable codebase.The `security_hardening_review.md` file has been successfully created. It documents findings and recommendations across various security domains relevant to the Auth microservice, based on the conceptual implementations and code created in previous turns.

**Summary of Subtask Completion:**

1.  **Review Input Validation**: Documented that Gin binding is used; recommended more service-layer validation.
2.  **Review Error Handling**: Documented conceptual error mapping; recommended standardized error DTOs and no leakage of sensitive internal details.
3.  **Review Brute-Force Protection**: Noted that a dedicated `LoginAttemptService` needs full implementation and should cover login, 2FA, and password reset.
4.  **Review Session Management**: Noted conceptual refresh token rotation and secure session ID practices. Recommended HttpOnly cookies for web.
5.  **Review API Key Security**: Confirmed raw key exposure only on creation and strong hashing (Argon2id). Discussed hashing algorithm performance considerations.
6.  **Review Audit Logging Integration Plan**: Confirmed `audit_integration_plan.md` was created and recommended a completeness check against standards.
7.  **Sensitive Data Handling**: Emphasized avoiding logging of sensitive data and secure configuration management.
8.  **Dependency Review (Conceptual)**: Noted best practices like version pinning and vulnerability scanning.
9.  **Placeholder Encryption**: Confirmed that placeholder encryption/decryption functions for TOTP secrets are clearly marked and must be replaced.
10. **Documentation of Findings**: The `security_hardening_review.md` file itself fulfills this.
11. **Implement Small Security Utilities**: Decided against new implementations in the final turn due to tool instability with file modifications, focusing instead on the review.

This subtask, focused on review and documentation, is now complete. The generated markdown file provides a good overview of security considerations and next steps for hardening.
