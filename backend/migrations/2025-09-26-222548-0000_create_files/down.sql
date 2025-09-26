-- Migration: Create files table for file management
-- Down migration (rollback)

-- Entferne Trigger
DROP TRIGGER IF EXISTS update_files_updated_at ON files;

-- Entferne Indizes
DROP INDEX IF EXISTS idx_files_user_id;
DROP INDEX IF EXISTS idx_files_hash;
DROP INDEX IF EXISTS idx_files_status;

-- Lösche files Tabelle
DROP TABLE IF EXISTS files;