-- Migration: Create files table for file management
-- Up migration

CREATE TABLE files (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    original_filename VARCHAR(255) NOT NULL,
    stored_filename VARCHAR(255) NOT NULL,
    file_path VARCHAR(500) NOT NULL,
    file_size BIGINT NOT NULL,
    mime_type VARCHAR(100),
    file_hash VARCHAR(64), -- SHA-256 hash
    iv VARCHAR(255) NOT NULL,
    upload_status VARCHAR(20) DEFAULT 'completed' CHECK (upload_status IN ('pending', 'completed', 'failed')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indizes für bessere Performance
CREATE INDEX idx_files_user_id ON files(user_id);
CREATE INDEX idx_files_hash ON files(file_hash);
CREATE INDEX idx_files_status ON files(upload_status);