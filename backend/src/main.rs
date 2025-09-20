use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::Serialize;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};

mod auth;
use auth::*;

#[derive(Clone)]
struct AppState {
    db: PgPool,
}

#[derive(Serialize)]
struct Message {
    msg: String,
}

async fn hello(State(state): State<Arc<AppState>>) -> Json<Message> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(&state.db)
        .await
        .unwrap_or((0,));

    Json(Message {
        msg: format!("🚀 Cloud Storage – {} User registriert", row.0),
    })
}

async fn login(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, StatusCode> {
    match authenticate_user(&state.db, &payload.email, &payload.password).await {
        Ok(Some(user)) => Ok(Json(AuthResponse {
            success: true,
            message: "Login erfolgreich".to_string(),
            user: Some(user),
        })),
        Ok(None) => Ok(Json(AuthResponse {
            success: false,
            message: "Ungültige Anmeldedaten".to_string(),
            user: None,
        })),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn register(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<AuthResponse>, StatusCode> {
    match create_user(&state.db, &payload.name, &payload.email, &payload.password).await {
        Ok(user) => Ok(Json(AuthResponse {
            success: true,
            message: "Registrierung erfolgreich".to_string(),
            user: Some(user),
        })),
        Err(_) => Ok(Json(AuthResponse {
            success: false,
            message: "Registrierung fehlgeschlagen (E-Mail bereits vergeben?)".to_string(),
            user: None,
        })),
    }
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL muss gesetzt sein");
    let pool = PgPool::connect(&db_url)
        .await
        .expect("DB Verbindung fehlgeschlagen");

    let state = Arc::new(AppState { db: pool });

    let app = Router::new()
        .route("/api/hello", get(hello))
        .route("/api/auth/login", post(login))
        .route("/api/auth/register", post(register))
        .with_state(state)
        .layer(CorsLayer::new().allow_origin(Any));

    let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("🚀 Backend läuft auf http://127.0.0.1:3000");
    println!("🔐 Standard Admin: admin@localhost / admin");
    axum::serve(listener, app).await.unwrap();
}
