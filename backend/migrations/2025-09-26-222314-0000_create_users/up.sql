-- Migration: Create users table with authentication system
-- Up migration

-- Erstelle neue users Tabelle mit vollständigem Auth-System
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    public_key TEXT NOT NULL,
    encrypted_private_key TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    is_active BOOLEAN DEFAULT true
);

-- Index für bessere Performance bei Login-Queries
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role ON users(role);
