-- Migration: Create users table with authentication system
-- Down migration (rollback)

-- Entferne Trigger
DROP TRIGGER IF EXISTS update_users_updated_at ON users;

-- Entferne Funktion
DROP FUNCTION IF EXISTS update_updated_at_column();

-- Entferne Indizes
DROP INDEX IF EXISTS idx_users_email;
DROP INDEX IF EXISTS idx_users_role;

-- Lösche users Tabelle
DROP TABLE IF EXISTS users;