-- Add migration script here
-- 003_create_file_permissions_table.sql
CREATE TABLE file_permissions (
    id SERIAL PRIMARY KEY,
    file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permission_type VARCHAR(20) NOT NULL, -- read, write, delete
    granted_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE(file_id, user_id, permission_type)
);

CREATE INDEX idx_file_permissions_file_user ON file_permissions(file_id, user_id);