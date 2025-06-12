-- File: backend/services/account-service/migrations/000002_create_profiles_table.sql

-- Create profiles table
CREATE TABLE IF NOT EXISTS profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL,
    nickname VARCHAR(50) NOT NULL,
    bio TEXT,
    country VARCHAR(100),
    city VARCHAR(100),
    birth_date DATE,
    gender VARCHAR(20),
    visibility VARCHAR(20) NOT NULL DEFAULT 'public',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_profiles_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);

-- Create index on account_id for faster lookups and joins
CREATE INDEX IF NOT EXISTS idx_profiles_account_id ON profiles(account_id);

-- Create index on nickname for searches
CREATE INDEX IF NOT EXISTS idx_profiles_nickname ON profiles(nickname);

-- Create index on visibility for filtering
CREATE INDEX IF NOT EXISTS idx_profiles_visibility ON profiles(visibility);

-- Add comments for documentation
COMMENT ON TABLE profiles IS 'Stores user profile information';
COMMENT ON COLUMN profiles.id IS 'Unique identifier for the profile';
COMMENT ON COLUMN profiles.account_id IS 'Foreign key to the accounts table';
COMMENT ON COLUMN profiles.nickname IS 'Display name shown to other users';
COMMENT ON COLUMN profiles.bio IS 'User biography or about me text';
COMMENT ON COLUMN profiles.country IS 'User country';
COMMENT ON COLUMN profiles.city IS 'User city';
COMMENT ON COLUMN profiles.birth_date IS 'User birth date';
COMMENT ON COLUMN profiles.gender IS 'User gender';
COMMENT ON COLUMN profiles.visibility IS 'Profile visibility setting (public, friends, private)';
COMMENT ON COLUMN profiles.created_at IS 'Timestamp when the profile was created';
COMMENT ON COLUMN profiles.updated_at IS 'Timestamp when the profile was last updated';
