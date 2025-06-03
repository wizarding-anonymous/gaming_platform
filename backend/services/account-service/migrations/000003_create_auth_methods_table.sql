-- account-service/migrations/000003_create_auth_methods_table.sql

-- Create auth_methods table
CREATE TABLE IF NOT EXISTS auth_methods (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL,
    type VARCHAR(20) NOT NULL, -- 'password', 'google', 'telegram', etc.
    identifier VARCHAR(255) NOT NULL, -- email, social id, telegram id, etc.
    secret VARCHAR(255), -- password hash or other secret authentication data
    is_primary BOOLEAN NOT NULL DEFAULT false,
    is_verified BOOLEAN NOT NULL DEFAULT false,
    last_used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_auth_methods_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
    CONSTRAINT uq_auth_methods_type_identifier UNIQUE (type, identifier)
);

-- Create index on account_id for faster lookups and joins
CREATE INDEX IF NOT EXISTS idx_auth_methods_account_id ON auth_methods(account_id);

-- Create index on type for filtering
CREATE INDEX IF NOT EXISTS idx_auth_methods_type ON auth_methods(type);

-- Create index on is_primary for filtering
CREATE INDEX IF NOT EXISTS idx_auth_methods_is_primary ON auth_methods(is_primary);

-- Create index on is_verified for filtering
CREATE INDEX IF NOT EXISTS idx_auth_methods_is_verified ON auth_methods(is_verified);

-- Add comments for documentation
COMMENT ON TABLE auth_methods IS 'Stores authentication methods for user accounts';
COMMENT ON COLUMN auth_methods.id IS 'Unique identifier for the authentication method';
COMMENT ON COLUMN auth_methods.account_id IS 'Foreign key to the accounts table';
COMMENT ON COLUMN auth_methods.type IS 'Type of authentication method (password, google, telegram, etc.)';
COMMENT ON COLUMN auth_methods.identifier IS 'Unique identifier for this auth method (email, social id, etc.)';
COMMENT ON COLUMN auth_methods.secret IS 'Password hash or other secret authentication data';
COMMENT ON COLUMN auth_methods.is_primary IS 'Whether this is the primary authentication method for the account';
COMMENT ON COLUMN auth_methods.is_verified IS 'Whether this authentication method has been verified';
COMMENT ON COLUMN auth_methods.last_used_at IS 'Timestamp when this auth method was last used';
COMMENT ON COLUMN auth_methods.created_at IS 'Timestamp when the auth method was created';
COMMENT ON COLUMN auth_methods.updated_at IS 'Timestamp when the auth method was last updated';
