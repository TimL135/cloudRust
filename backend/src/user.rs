use axum::{
    extract::{FromRequestParts, State},
    http::{request::Parts, StatusCode},
    Json,
};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{Duration, NaiveDateTime, Utc};
use diesel::{prelude::*, r2d2::ConnectionManager, AsChangeset, Insertable, Queryable};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::schema::users::{self, role};
use crate::{AppState, Claims};

#[derive(Debug, Serialize, Deserialize, Queryable, AsChangeset)]
#[diesel(table_name = users)]
pub struct User {
    pub id: i32,
    pub name: String,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
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

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub success: bool,
    pub message: String,
    pub token: Option<String>,
    pub user: Option<UserResponse>,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: i32,
    pub name: String,
    pub email: String,
    pub role: String,
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

impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Extract Authorization header
        let auth_header = parts
            .headers
            .get("Authorization")
            .and_then(|header| header.to_str().ok())
            .ok_or(StatusCode::UNAUTHORIZED)?;

        // Check if it starts with "Bearer "
        if !auth_header.starts_with("Bearer ") {
            return Err(StatusCode::UNAUTHORIZED);
        }

        let token = &auth_header[7..]; // Remove "Bearer " prefix

        // Decode JWT token
        let jwt_secret =
            std::env::var("JWT_SECRET").unwrap_or_else(|_| "your-secret-key".to_string());

        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(jwt_secret.as_ref()),
            &Validation::new(Algorithm::HS256),
        )
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
        let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL muss gesetzt sein");
        let manager = ConnectionManager::<PgConnection>::new(db_url);
        let pool = r2d2::Pool::builder()
            .build(manager)
            .expect("DB Pool konnte nicht erstellt werden");
        let mut conn = pool.get().expect("Keine Verbindung aus Pool");

        let user_id = token_data.claims.user_id;
        let user = get_user_by_id(&mut conn, &user_id)
            .unwrap_or_else(|e| {
                eprintln!("Error getting user: {}", e);
                None
            })
            .unwrap_or_else(|| {
                panic!("User not found");
            });
        Ok(AuthenticatedUser {
            user_id,
            role: user.role,
        })
    }
}

pub fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
    hash(password, DEFAULT_COST)
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, bcrypt::BcryptError> {
    verify(password, hash)
}

pub async fn login(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, StatusCode> {
    let mut conn = state
        .db
        .get()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match authenticate(&mut conn, &payload.email, &payload.password) {
        Ok(Some(user)) => {
            // JWT Token erstellen
            let token = create_jwt_token(user.id)?;

            Ok(Json(AuthResponse {
                success: true,
                message: "Login erfolgreich".to_string(),
                token: Some(token), // 👈 Token zurückgeben
                user: Some(user.into()),
            }))
        }
        Ok(None) => Ok(Json(AuthResponse {
            success: false,
            message: "Ungültige Anmeldedaten".to_string(),
            token: None,
            user: None,
        })),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub async fn register(
    State(state): State<Arc<AppState>>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<RegisterRequest>,
) -> Result<StatusCode, StatusCode> {
    if auth_user.role != "admin" {
        return Err(StatusCode::FORBIDDEN);
    }

    let mut conn = state
        .db
        .get()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match create(&mut conn, &payload.name, &payload.email, &payload.password) {
        Ok(_) => Ok(StatusCode::OK),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

fn create_jwt_token(user_id: i32) -> Result<String, StatusCode> {
    let jwt_secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "your-secret-key".to_string());

    let claims = Claims {
        user_id,
        exp: (Utc::now() + Duration::hours(24)).timestamp() as usize,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_ref()),
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
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
    name: &str,
    email: &str,
    password: &str,
) -> Result<User, Box<dyn std::error::Error>> {
    use self::users::dsl::users; // ✅ nur Tabelle, kein Namenskonflikt

    let hashed_password = hash_password(password)?; // <- Anderen Namen verwenden
    let now = Utc::now().naive_utc();

    let new_user = NewUser {
        name: name.to_string(),
        email: email.to_string(),
        password_hash: hashed_password,
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
