use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use diesel::{
    r2d2::{self, ConnectionManager},
    PgConnection,
};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tokio::{
    net::TcpListener,
    sync::{mpsc, Mutex},
};
use tower_cookies::CookieManagerLayer;

use tower_http::cors::{Any, CorsLayer};

mod access_token;
mod file;
mod schema;
mod user;

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
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    // String zu i32 konvertieren
    let user_id: i32 = match params.user_id.parse() {
        Ok(id) => id,
        Err(_) => {
            println!("❌ Ungültige user_id: {}", params.user_id);
            return ws.on_upgrade(|_| async {}); // Leere Verbindung
        }
    };
    ws.on_upgrade(move |socket| handle_socket(socket, user_id, state.clients.clone()))
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
    if let Err(e) = user::init_admin(&mut conn) {
        eprintln!("⚠️ Konnte Admin nicht initialisieren: {e}");
    }
    let clients: Clients = Arc::new(Mutex::new(HashMap::new()));
    let state = Arc::new(AppState { db: pool, clients });
    let app = Router::new()
        .route("/ws", get(ws_handler))
        .route("/api/auth/login", post(user::login))
        .route("/api/auth/auth_check", get(user::auth_check))
        .route("/api/auth/register", post(user::register))
        .route("/api/upload", post(file::upload))
        .route("/api/files", get(file::list))
        .route("/api/files/{id}/download", get(file::download))
        .route("/api/files/{id}/delete", get(file::delete))
        .with_state(state)
        .layer(CookieManagerLayer::new())
        .layer(CorsLayer::new().allow_origin(Any));

    let listener = match TcpListener::bind("0.0.0.0:3000").await {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("Failed to bind to port 3000: {}", e);
            std::process::exit(1);
        }
    };

    println!("🚀 Backend läuft auf http://127.0.0.1:3000");
    println!("🔐 Standard Admin: admin@localhost / admin");
    println!("📁 Upload API: POST /api/upload");
    match axum::serve(listener, app).await {
        Ok(_) => {
            println!("Server has stopped running");
        }
        Err(e) => {
            eprintln!("Fatal server error: {}", e);
            eprintln!("Server will now exit");
            std::process::exit(1);
        }
    }
}
