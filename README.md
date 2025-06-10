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
