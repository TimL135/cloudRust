use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use diesel::r2d2::{self, ConnectionManager};
use diesel::PgConnection;
use serde::Serialize;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};

mod auth;
use auth::*;

#[derive(Clone)]
struct AppState {
    pub db: r2d2::Pool<ConnectionManager<PgConnection>>,
}

#[derive(Serialize)]
struct Message {
    msg: String,
}

async fn hello(State(state): State<Arc<AppState>>) -> Json<Message> {
    // Diesel-Version für User-Count
    let mut conn = match state.db.get() {
        Ok(conn) => conn,
        Err(_) => {
            return Json(Message {
                msg: "🚀 Cloud Storage – DB Verbindung fehlgeschlagen".to_string(),
            })
        }
    };

    // Diesel Query für User-Count
    use auth::users::dsl::*;
    use diesel::prelude::*;

    let user_count: i64 = users.count().get_result(&mut conn).unwrap_or(0);

    Json(Message {
        msg: format!("🚀 Cloud Storage – {} User registriert", user_count),
    })
}

async fn login(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, StatusCode> {
    let mut conn = state
        .db
        .get()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match authenticate_user(&mut conn, &payload.email, &payload.password) {
        Ok(Some(user)) => Ok(Json(AuthResponse {
            success: true,
            message: "Login erfolgreich".to_string(),
            user: Some(user.into()), // UserResponse conversion
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
    let mut conn = state
        .db
        .get()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match create_user(&mut conn, &payload.name, &payload.email, &payload.password) {
        Ok(user) => Ok(Json(AuthResponse {
            success: true,
            message: "Registrierung erfolgreich".to_string(),
            user: Some(user.into()), // UserResponse conversion
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
