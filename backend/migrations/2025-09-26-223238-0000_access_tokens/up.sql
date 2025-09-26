-- Migration: Create access_tokens table for JWT token management
-- Up migration

CREATE TABLE access_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Index für schnelle Token-Suche
CREATE UNIQUE INDEX idx_access_tokens_token_hash ON access_tokens(token_hash);

-- Index für alle access-Tokens eines Users
CREATE INDEX idx_access_tokens_user_id ON access_tokens(user_id);

-- Index für abgelaufene Tokens (für Cleanup)
CREATE INDEX idx_access_tokens_expires_at ON access_tokens(expires_at);