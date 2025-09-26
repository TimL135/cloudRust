-- Migration: Create updated_at trigger function and apply to existing tables
-- Up migration

-- Erstelle oder ersetze die Trigger-Funktion
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Füge Trigger zu bestehenden Tabellen hinzu
CREATE TRIGGER update_users_updated_at 
    BEFORE UPDATE ON users
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_files_updated_at 
    BEFORE UPDATE ON files
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_access_tokens_updated_at 
    BEFORE UPDATE ON access_tokens
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();