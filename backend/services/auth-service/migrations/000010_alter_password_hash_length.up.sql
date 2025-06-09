-- Purpose: Increase the length of the hashed_password column to accommodate Argon2id hashes.
-- According to the initial schema (000001_create_initial_tables.up.sql), the column is named 'password_hash'.
-- If it was 'hashed_password' in an earlier version not visible here, this would need adjustment.
-- Assuming 'password_hash' is the correct current name based on auth_microservice_specification_final.md.
ALTER TABLE users ALTER COLUMN password_hash TYPE TEXT;
