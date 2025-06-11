# File: README.md
<!-- README.md -->

# Overview

This monorepo contains the code for a gaming platform inspired by Steam. It is structured as a collection of backend microservices and a frontend application.

## Directory structure

- **backend/** - backend code and documentation for the microservices. Common tooling lives here.
- **backend/services/** - contains individual backend services such as `auth-service` and `account-service`.
- **frontend/** - placeholder for the web client implementation.
- **configs/** - configuration templates and environment files.

Each service under `backend/services` is managed independently with its own Makefile and configuration.

## Required Environment Variables

The configuration in `configs/config.yaml` expects the following environment variables when running in production:

- `VK_APP_ID` – OAuth application ID for VK
- `VK_APP_SECRET` – OAuth secret for VK
- `OK_APP_ID` – OAuth application ID for Odnoklassniki
- `OK_APP_SECRET_KEY` – OAuth secret key for Odnoklassniki
- `OK_APP_PUBLIC_KEY` – Public key for Odnoklassniki
- `TELEGRAM_BOT_TOKEN` – Telegram bot token
- `JWT_PRIVATE_KEY_PATH` – Path to the RSA private key
- `JWT_PUBLIC_KEY_PATH` – Path to the RSA public key
- `JWT_HMAC_SECRET_KEY` – HMAC secret used for internal tokens
- `OAUTH_STATE_SECRET` – HMAC secret used for OAuth state tokens
- `TOTP_ENCRYPTION_KEY` – 32‑byte key used to encrypt TOTP secrets

A template for Helm secret values can be found at `backend/services/auth-service/deployments/helm/auth-service/values-secrets-template.yaml`.

## Configuring Go Modules

To prevent `Forbidden` errors when fetching dependencies, configure Go to bypass the default proxy and download modules directly from GitHub:

```bash
go env -w GOPROXY=direct
```

If your organization provides its own mirror, replace `direct` with that proxy URL:

```bash
go env -w GOPROXY=https://your.corp.proxy/,direct
```

The helper script `setup-go-proxy.sh` in the repository root automates this step.

## Generating Test Keys

Use OpenSSL to create a local RSA key pair for development:

```bash
openssl genpkey -algorithm RSA -out configs/keys/dev_private_key.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in configs/keys/dev_private_key.pem -out configs/keys/dev_public_key.pem
```

These commands place the keys in `configs/keys`. The `.gitignore` file prevents
these files from being committed.
