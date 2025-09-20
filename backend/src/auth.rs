use bcrypt::{hash, verify, DEFAULT_COST};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use time::PrimitiveDateTime; // <-- Hier importieren

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub id: i32,
    pub name: String,
    pub email: String,
    pub role: String,
    pub created_at: Option<PrimitiveDateTime>, // <-- NaiveDateTime verwenden
    pub updated_at: Option<PrimitiveDateTime>, // <-- Neu hinzugefügt, falls in DB vorhanden
    pub last_login: Option<PrimitiveDateTime>, // <-- NaiveDateTime verwenden
    pub is_active: Option<bool>,               // <-- Neu hinzugefügt, falls in DB vorhanden
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub name: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub success: bool,
    pub message: String,
    pub user: Option<User>,
}

pub fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
    hash(password, DEFAULT_COST)
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, bcrypt::BcryptError> {
    verify(password, hash)
}

pub async fn authenticate_user(
    pool: &PgPool,
    email: &str,
    password: &str,
) -> Result<Option<User>, sqlx::Error> {
    let user_row = sqlx::query!(
        "SELECT id, name, email, password_hash, role, created_at, updated_at, last_login, is_active FROM users WHERE email = $1",
        email
    )
    .fetch_optional(pool)
    .await?;

    if let Some(row) = user_row {
        match verify_password(password, &row.password_hash) {
            Ok(true) => {
                // Update last_login
                sqlx::query!(
                    "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1",
                    row.id
                )
                .execute(pool)
                .await?;

                Ok(Some(User {
                    id: row.id,
                    name: row.name,
                    email: row.email,
                    role: row.role,
                    created_at: row.created_at,
                    updated_at: row.updated_at,
                    last_login: row.last_login,
                    is_active: row.is_active,
                }))
            }
            _ => Ok(None),
        }
    } else {
        Ok(None)
    }
}

pub async fn create_user(
    pool: &PgPool,
    name: &str,
    email: &str,
    password: &str,
) -> Result<User, Box<dyn std::error::Error>> {
    let password_hash = hash_password(password)?;

    let user_row = sqlx::query!(
        "INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id, name, email, role, created_at, updated_at, last_login, is_active",
        name,
        email,
        password_hash
    )
    .fetch_one(pool)
    .await?;

    Ok(User {
        id: user_row.id,
        name: user_row.name,
        email: user_row.email,
        role: user_row.role,
        created_at: user_row.created_at,
        updated_at: user_row.updated_at,
        last_login: user_row.last_login,
        is_active: user_row.is_active,
    })
}
