use axum::{
    async_trait,
    extract::{FromRequestParts, State},
    http::{request::Parts, StatusCode},
    response::Json,
    routing::{get, post},
    Router,
};

use chrono::{Duration, Utc};
use diesel::r2d2::{self, ConnectionManager};
use diesel::PgConnection;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};

mod auth;
mod models;
mod schema;
mod upload;

use auth::*;

#[derive(Clone)]
pub struct AppState {
    pub db: r2d2::Pool<ConnectionManager<PgConnection>>,
}

#[derive(Serialize)]
struct Message {
    msg: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub user_id: i32,
    pub exp: usize, // Expiration time
}

pub struct AuthenticatedUser {
    pub user_id: i32,
}

// 👇 AuthResponse mit token-Feld hinzufügen
#[derive(Serialize)]
struct AuthResponse {
    success: bool,
    message: String,
    token: Option<String>, // 👈 Das hat gefehlt!
    user: Option<UserResponse>,
}

#[async_trait]
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

        Ok(AuthenticatedUser {
            user_id: token_data.claims.user_id,
        })
    }
}

// 👇 Helper-Function für JWT-Token-Erstellung
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

pub async fn login(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, StatusCode> {
    let mut conn = state
        .db
        .get()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match authenticate_user(&mut conn, &payload.email, &payload.password) {
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

async fn register(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<AuthResponse>, StatusCode> {
    let mut conn = state
        .db
        .get()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match create_user(&mut conn, &payload.name, &payload.email, &payload.password) {
        Ok(user) => {
            // 👇 Auch bei Register ein JWT-Token erstellen!
            let token = create_jwt_token(user.id)?;

            Ok(Json(AuthResponse {
                success: true,
                message: "Registrierung erfolgreich".to_string(),
                token: Some(token), // 👈 Token auch hier zurückgeben
                user: Some(user.into()),
            }))
        }
        Err(_) => Ok(Json(AuthResponse {
            success: false,
            message: "Registrierung fehlgeschlagen (E-Mail bereits vergeben?)".to_string(),
            token: None,
            user: None,
        })),
    }
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL muss gesetzt sein");

    // Diesel Connection Pool erstellen
    let manager = ConnectionManager::<PgConnection>::new(db_url);
    let pool = r2d2::Pool::builder()
        .build(manager)
        .expect("DB Pool konnte nicht erstellt werden");
    let mut conn = pool.get().expect("Keine Verbindung aus Pool");
    if let Err(e) = auth::init_admin_user(&mut conn) {
        eprintln!("⚠️ Konnte Admin nicht initialisieren: {e}");
    }
    let state = Arc::new(AppState { db: pool });

    let app = Router::new()
        .route("/api/auth/login", post(login))
        .route("/api/auth/register", post(register))
        // 📁 Upload Routes hinzufügen
        .route("/api/upload", post(upload::upload_file))
        .route("/api/files", get(upload::list_files))
        .route("/api/files/:id/download", get(upload::download_file))
        .with_state(state)
        .layer(CorsLayer::new().allow_origin(Any));

    let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();

    println!("🚀 Backend läuft auf http://127.0.0.1:3000");
    println!("🔐 Standard Admin: admin@localhost / admin");
    println!("📁 Upload API: POST /api/upload");
    axum::serve(listener, app).await.unwrap();
}
