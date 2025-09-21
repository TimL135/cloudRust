use axum::{
    extract::{ws::WebSocket, FromRequestParts, Query, State},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};

use axum::extract::ws::{Message, WebSocketUpgrade};

use chrono::{Duration, Utc};
use diesel::r2d2::{self, ConnectionManager};
use diesel::PgConnection;
use futures_util::{SinkExt, StreamExt};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tokio::{
    net::TcpListener,
    sync::{mpsc, Mutex},
};
use tower_http::cors::{Any, CorsLayer};

mod auth;
mod models;
mod schema;
mod upload;

use auth::*;

#[derive(Clone)]
pub struct AppState {
    pub db: r2d2::Pool<ConnectionManager<PgConnection>>,
    pub clients: Clients,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub user_id: i32,
    pub exp: usize, // Expiration time
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

type UserId = i32;
type Clients = Arc<Mutex<HashMap<UserId, Vec<mpsc::UnboundedSender<Message>>>>>;

#[derive(Deserialize)]
struct WsParams {
    user_id: String,
}

// --------------------------------------
// WebSocket Handler
// --------------------------------------
async fn ws_handler(
    ws: WebSocketUpgrade,
    Query(params): Query<WsParams>,
    State(clients): State<Clients>,
) -> impl IntoResponse {
    // String zu i32 konvertieren
    let user_id: i32 = match params.user_id.parse() {
        Ok(id) => id,
        Err(_) => {
            println!("❌ Ungültige user_id: {}", params.user_id);
            return ws.on_upgrade(|_| async {}); // Leere Verbindung
        }
    };
    ws.on_upgrade(move |socket| handle_socket(socket, user_id, clients))
}

async fn handle_socket(socket: WebSocket, user_id: i32, clients: Clients) {
    // Channel für diesen einzelnen Client
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();

    // Speichere den Sender global
    let mut lock = clients.lock().await;

    lock.entry(user_id).or_insert_with(Vec::new).push(tx);

    let (mut sender, mut receiver) = socket.split();

    // Nachrichten vom Backend an den Client weiterleiten
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if sender.send(msg).await.is_err() {
                break; // Client hat geschlossen
            }
        }
    });

    // Server ← Client
    tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            println!("Got from client {user_id}: {:?}", msg);
        }
    });
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
    let clients: Clients = Arc::new(Mutex::new(HashMap::new()));
    let state = Arc::new(AppState { db: pool, clients });
    let app = Router::new()
        .route("/ws", get(ws_handler))
        .with_state(state.clients.clone())
        .route("/api/auth/login", post(login))
        .route("/api/auth/register", post(register))
        // 📁 Upload Routes hinzufügen
        .route("/api/upload", post(upload::upload_file))
        .with_state(state.clone())
        .route("/api/files", get(upload::list_files))
        .route("/api/files/{id}/download", get(upload::download_file))
        .with_state(state)
        .layer(CorsLayer::new().allow_origin(Any));

    let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();

    println!("🚀 Backend läuft auf http://127.0.0.1:3000");
    println!("🔐 Standard Admin: admin@localhost / admin");
    println!("📁 Upload API: POST /api/upload");
    axum::serve(listener, app).await.unwrap();
}
