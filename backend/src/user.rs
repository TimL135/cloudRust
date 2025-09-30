use axum::{extract::State, http::StatusCode, Json};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{NaiveDateTime, Utc};
use diesel::{prelude::*, AsChangeset, Insertable, Queryable};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::schema::users::{self, encrypted_private_key, public_key, role};
use crate::{access_token, db_error_to_status, AppState};
use tower_cookies::Cookies;

#[derive(Debug, Serialize, Deserialize, Queryable, AsChangeset)]
#[diesel(table_name = users)]
pub struct User {
    pub id: i32,
    pub name: String,
    pub email: String,
    pub password_hash: String,

    pub public_key: String,
    pub encrypted_private_key: String,
    pub role: String,
    pub created_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
    pub last_login: Option<NaiveDateTime>,
    pub is_active: Option<bool>,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = users)]
pub struct NewUser {
    pub name: String,
    pub email: String,
    pub password_hash: String,
    pub public_key: String,
    pub encrypted_private_key: String,
    pub role: String,
    pub created_at: Option<NaiveDateTime>,
    pub is_active: Option<bool>,
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

#[derive(Debug, Deserialize)]
pub struct UpdateKeysRequest {
    pub public_key: String,
    pub encrypted_private_key: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub success: bool,
    pub message: String,
    pub user: Option<UserResponse>,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: i32,
    pub name: String,
    pub email: String,
    pub role: String,
    pub public_key: String,
    pub encrypted_private_key: String,
    pub created_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
    pub last_login: Option<NaiveDateTime>,
    pub is_active: Option<bool>,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        UserResponse {
            id: user.id,
            name: user.name,
            email: user.email,
            role: user.role,
            public_key: user.public_key,
            encrypted_private_key: user.encrypted_private_key,
            created_at: user.created_at,
            updated_at: user.updated_at,
            last_login: user.last_login,
            is_active: user.is_active,
        }
    }
}

pub struct AuthenticatedUser {
    pub user_id: i32,
    pub role: String,
}

// 🔐 Authentifizierungs-Funktion für Handler
pub async fn authenticate_user_from_cookie(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
) -> Result<AuthenticatedUser, StatusCode> {
    let mut conn = state
        .db
        .get()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match access_token::check(&mut conn, cookies) {
        Ok(_user_id) => {
            let user = get_user_by_id(&mut conn, &_user_id)
                .map_err(|_| StatusCode::NOT_FOUND)?
                .ok_or(StatusCode::NOT_FOUND)?;

            if user.is_active != Some(true) {
                return Err(StatusCode::FORBIDDEN);
            }

            Ok(AuthenticatedUser {
                user_id: _user_id,
                role: user.role,
            })
        }
        Err(error) => return Err(error),
    }
}

pub fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
    hash(password, DEFAULT_COST)
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, bcrypt::BcryptError> {
    verify(password, hash)
}

pub async fn auth_check(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
) -> Result<Json<AuthResponse>, StatusCode> {
    // Prüft Cookie und gibt User-Daten zurück
    let auth_user = authenticate_user_from_cookie(State(state.clone()), cookies).await?;
    let mut conn = state
        .db
        .get()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let user = get_user_by_id(&mut conn, &auth_user.user_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    Ok(Json(AuthResponse {
        success: true,
        message: "Login erfolgreich".to_string(),
        user: Some(user.into()),
    }))
}

pub async fn login(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, StatusCode> {
    let mut conn = state
        .db
        .get()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match authenticate(&mut conn, &payload.email, &payload.password) {
        Ok(Some(user)) => match access_token::create(&mut conn, user.id, cookies) {
            Ok(_) => Ok(Json(AuthResponse {
                success: true,
                message: "Login erfolgreich".to_string(),
                user: Some(user.into()),
            })),
            Err(_) => Ok(Json(AuthResponse {
                success: false,
                message: "Unerwarteter Datenbank Fehler".to_string(),
                user: None,
            })),
        },
        Ok(None) => Ok(Json(AuthResponse {
            success: false,
            message: "Ungültige Anmeldedaten".to_string(),
            user: None,
        })),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub async fn register(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    Json(payload): Json<RegisterRequest>,
) -> Result<StatusCode, StatusCode> {
    let mut conn = state
        .db
        .get()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let auth_user = authenticate_user_from_cookie(State(state.clone()), cookies).await?;

    if auth_user.role != "admin" {
        return Err(StatusCode::UNAUTHORIZED);
    }

    match create(
        &mut conn,
        &payload.name,
        &payload.email,
        &payload.password,
        "_encrzpted_private_key",
        "_public_key",
    ) {
        Ok(_) => Ok(StatusCode::OK),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub fn authenticate(
    conn: &mut PgConnection,
    _email: &str,
    password: &str,
) -> Result<Option<User>, diesel::result::Error> {
    use self::users::dsl::*;

    let user_result = users
        .filter(email.eq(_email))
        .first::<User>(conn)
        .optional()?;

    if let Some(user) = user_result {
        match verify_password(password, &user.password_hash) {
            Ok(true) => {
                // Update last_login
                diesel::update(users.find(user.id))
                    .set(last_login.eq(Some(Utc::now().naive_utc())))
                    .execute(conn)?;

                // Fetch updated user
                let updated_user = users.find(user.id).first::<User>(conn)?;
                Ok(Some(updated_user))
            }
            _ => Ok(None),
        }
    } else {
        Ok(None)
    }
}

pub fn create(
    conn: &mut PgConnection,
    _name: &str,
    _email: &str,
    password: &str,
    _encrypted_private_key: &str,
    _public_key: &str,
) -> Result<User, Box<dyn std::error::Error>> {
    use self::users::dsl::users; // ✅ nur Tabelle, kein Namenskonflikt

    let hashed_password = hash_password(password)?; // <- Anderen Namen verwenden
    let now = Utc::now().naive_utc();

    let new_user = NewUser {
        name: _name.to_string(),
        email: _email.to_string(),
        password_hash: hashed_password,
        encrypted_private_key: _encrypted_private_key.to_string(),
        public_key: _public_key.to_string(),
        role: "user".to_string(),
        created_at: Some(now),
        is_active: Some(true),
    };

    let user = diesel::insert_into(users)
        .values(&new_user)
        .get_result::<User>(conn)?;

    Ok(user)
}

pub fn get_user_by_id(
    conn: &mut PgConnection,
    _id: &i32,
) -> Result<Option<User>, diesel::result::Error> {
    use self::users::dsl::*;
    users.filter(id.eq(_id)).first::<User>(conn).optional()
}

/// Erstellt automatisch einen Admin, falls keiner vorhanden ist.
pub fn init_admin(conn: &mut PgConnection) -> Result<(), Box<dyn std::error::Error>> {
    use self::users::dsl::users; // ✅ nur Tabelle, kein Namenskonflikt

    // Prüfen, ob ein Admin existiert
    let admin_exists = users
        .filter(role.eq("admin"))
        .first::<User>(conn)
        .optional()?
        .is_some();

    if !admin_exists {
        let password_hash = hash_password("admin")?;
        let now = Utc::now().naive_utc();

        let new_admin = NewUser {
            name: "Administrator".to_string(),
            email: "admin@localhost".to_string(),
            password_hash,
            encrypted_private_key: "_encrypted_private_key".to_string(),
            public_key: "_public_key".to_string(),
            role: "admin".to_string(),
            created_at: Some(now),
            is_active: Some(true),
        };

        diesel::insert_into(users)
            .values(&new_admin)
            .execute(conn)?;

        println!("🔐 Admin-Account 'admin@localhost' mit Passwort 'admin' erstellt!");
    }

    Ok(())
}

pub async fn update_keys(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    Json(payload): Json<UpdateKeysRequest>,
) -> Result<StatusCode, StatusCode> {
    use self::users::dsl::users; // ✅ nur Tabelle, kein Namenskonflikt

    let mut conn = state
        .db
        .get()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let auth_user = authenticate_user_from_cookie(State(state.clone()), cookies).await?;

    if auth_user.role != "admin" {
        return Err(StatusCode::UNAUTHORIZED);
    }

    diesel::update(users.find(auth_user.user_id))
        .set((
            public_key.eq(payload.public_key),
            encrypted_private_key.eq(payload.encrypted_private_key),
        ))
        .execute(&mut conn)
        .map_err(db_error_to_status)?;
    Ok(StatusCode::OK)
}
