-- Migration: Create access_tokens table for JWT token management
-- Down migration (rollback)

-- Entferne Indizes
DROP INDEX IF EXISTS idx_access_tokens_token_hash;
DROP INDEX IF EXISTS idx_access_tokens_user_id;
DROP INDEX IF EXISTS idx_access_tokens_expires_at;

-- Lösche access_tokens Tabelle
DROP TABLE IF EXISTS access_tokens;