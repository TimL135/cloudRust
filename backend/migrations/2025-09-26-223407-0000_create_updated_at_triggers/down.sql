-- Migration: Create updated_at trigger function and apply to existing tables
-- Down migration (rollback)

-- Entferne Trigger von allen Tabellen
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
DROP TRIGGER IF EXISTS update_files_updated_at ON files;
DROP TRIGGER IF EXISTS update_access_tokens_updated_at ON access_tokens;

-- Entferne die Trigger-Funktion
DROP FUNCTION IF EXISTS update_updated_at_column();