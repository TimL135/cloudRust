-- Lösche alte users Tabelle falls vorhanden
DROP TABLE IF EXISTS users;

-- Erstelle neue users Tabelle mit vollständigem Auth-System
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    is_active BOOLEAN DEFAULT true
);

-- Index für bessere Performance bei Login-Queries
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role ON users(role);

-- Trigger für updated_at automatisch setzen
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at 
    BEFORE UPDATE ON users 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Standard Admin User erstellen
-- Passwort: "admin" -> bcrypt Hash mit cost 12
INSERT INTO users (name, email, password_hash, role) 
VALUES (
    'Administrator',
    'admin@localhost',
    '$2b$12$lrEreK9iCHGuyyzfthqOEuN37npEoSjbqYi72tJIgCSvkUxFa8DgS',
    'admin'
);

-- Beispiel normaler User (optional)
-- Passwort: "user123" -> bcrypt Hash
INSERT INTO users (name, email, password_hash, role) 
VALUES (
    'Demo User',
    'user@localhost',
    '$2b$12$8Ry3VQKWKxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj3bp.Test123',
    'user'
);