-- File: backend/services/auth-service/migrations/000010_alter_password_hash_length.down.sql
-- Purpose: Revert the length of the hashed_password column to VARCHAR(255).
-- According to the initial schema (000001_create_initial_tables.up.sql), the column is named 'password_hash'.
-- If it was 'hashed_password' in an earlier version not visible here, this would need adjustment.
-- Assuming 'password_hash' is the correct current name based on auth_microservice_specification_final.md.
ALTER TABLE users ALTER COLUMN password_hash TYPE VARCHAR(255);
