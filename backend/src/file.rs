use axum::{
    extract::{ws::Message, Multipart, Path, Query, State},
    http::StatusCode,
    response::Json,
};
use chrono::NaiveDateTime;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::{fs, io::AsyncWriteExt};
use uuid::Uuid;

use crate::{schema::files, user::AuthenticatedUser, AppState};
#[derive(Queryable, Serialize, Clone)]
#[diesel(table_name = files)]
#[diesel(check_for_backend(Pg))]
pub struct File {
    pub id: i32,
    pub user_id: i32,
    pub original_filename: String,
    pub stored_filename: String,
    pub file_path: String,
    pub file_size: i64,
    pub mime_type: Option<String>,
    pub file_hash: Option<String>,
    pub upload_status: Option<String>,
    pub created_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
}

#[derive(Insertable)]
#[diesel(table_name = crate::schema::files)]
pub struct NewFile {
    pub user_id: i32,
    pub original_filename: String,
    pub stored_filename: String,
    pub file_path: String,
    pub file_size: i64,
    pub mime_type: Option<String>,
    pub file_hash: Option<String>,
    pub upload_status: String,
}
#[derive(Serialize)]
pub struct UploadResponse {
    pub id: i32,
    pub filename: String,
    pub size: i64,
    pub url: String,
}

#[derive(Serialize)]
pub struct FileListResponse {
    pub files: Vec<FileInfo>,
    pub total: i64,
}

#[derive(Serialize)]
pub struct FileInfo {
    pub id: i32,
    pub original_filename: String,
    pub file_size: i64,
    pub mime_type: Option<String>,
    pub created_at: chrono::NaiveDateTime,
}

#[derive(Deserialize)]
pub struct FileQuery {
    pub page: Option<i64>,
    pub limit: Option<i64>,
}

pub async fn upload(
    State(state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> Result<Json<Vec<UploadResponse>>, StatusCode> {
    let user_id = 1; // TODO: aus Session/JWT

    let mut responses = Vec::new();

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?
    {
        let name = field.name().unwrap_or("").to_string();

        if name == "file" {
            let filename = field.file_name().unwrap_or("unknown").to_string();
            let content_type = field
                .content_type()
                .unwrap_or("application/octet-stream")
                .to_string();
            let data = field.bytes().await.map_err(|_| StatusCode::BAD_REQUEST)?;

            // unique filename generieren
            let ext = std::path::Path::new(&filename)
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("");
            let stored_filename = format!("{}.{}", Uuid::new_v4(), ext);
            let upload_dir = "uploads";
            let file_path = format!("{}/{}", upload_dir, stored_filename);

            fs::create_dir_all(upload_dir)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            let mut hasher = Sha256::new();
            hasher.update(&data);
            let file_hash = format!("{:x}", hasher.finalize());

            let mut file = fs::File::create(&file_path)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            file.write_all(&data)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            // DB Insert
            let new_file = NewFile {
                user_id,
                original_filename: filename.clone(),
                stored_filename: stored_filename.clone(),
                file_path: file_path.clone(),
                file_size: data.len() as i64,
                mime_type: Some(content_type),
                file_hash: Some(file_hash),
                upload_status: "completed".into(),
            };

            let mut conn = state
                .db
                .get()
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            let file_record: File = diesel::insert_into(files::table)
                .values(&new_file)
                .get_result(&mut conn)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            responses.push(UploadResponse {
                id: file_record.id,
                filename,
                size: file_record.file_size,
                url: format!("/api/files/{}/download", file_record.id),
            });
        }
    }

    if responses.is_empty() {
        Err(StatusCode::BAD_REQUEST)
    } else {
        let clients = state.clients.clone();
        let lock = clients.lock().await;

        if let Some(senders) = lock.get(&user_id) {
            for tx in senders {
                let _ = tx.send(Message::Text(format!("new_file").into()));
            }
        }
        Ok(Json(responses))
    }
}

pub async fn list(
    State(state): State<Arc<AppState>>,
    Query(params): Query<FileQuery>,
    auth_user: AuthenticatedUser,
) -> Result<Json<FileListResponse>, StatusCode> {
    let user_id = auth_user.user_id; // Extract from JWT token
    let page = params.page.unwrap_or(1);
    let limit = params.limit.unwrap_or(20);
    let offset = (page - 1) * limit;

    let mut conn = state
        .db
        .get()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut query = files::table.into_boxed();

    query = query.filter(files::user_id.eq(user_id));

    let files_result: Vec<File> = query
        .order(files::created_at.desc())
        .limit(limit)
        .offset(offset)
        .load(&mut conn)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let total: i64 = files::table
        .filter(files::user_id.eq(user_id))
        .count()
        .get_result(&mut conn)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let file_infos: Vec<FileInfo> = files_result
        .into_iter()
        .map(|f| FileInfo {
            id: f.id,
            original_filename: f.original_filename,
            file_size: f.file_size,
            mime_type: f.mime_type,
            created_at: f.created_at.unwrap(),
        })
        .collect();

    Ok(Json(FileListResponse {
        files: file_infos,
        total,
    }))
}

pub async fn download(
    State(state): State<Arc<AppState>>,
    Path(file_id): Path<i32>,
    auth_user: AuthenticatedUser,
) -> Result<Vec<u8>, StatusCode> {
    let mut conn = state
        .db
        .get()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let file: File = files::table
        .find(file_id)
        .first(&mut conn)
        .map_err(|_| StatusCode::NOT_FOUND)?;

    if file.user_id != auth_user.user_id {
        return Err(StatusCode::FORBIDDEN);
    }

    let file_data = fs::read(&file.file_path)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    Ok(file_data)
}

pub async fn delete(
    State(state): State<Arc<AppState>>,
    Path(file_id): Path<i32>,
    auth_user: AuthenticatedUser,
) -> Result<StatusCode, StatusCode> {
    let mut conn = state
        .db
        .get()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let file: File = files::table
        .find(file_id)
        .first(&mut conn)
        .map_err(|_| StatusCode::NOT_FOUND)?;

    if file.user_id != auth_user.user_id {
        return Err(StatusCode::FORBIDDEN);
    }

    // Datei aus dem Dateisystem löschen
    fs::remove_file(&file.file_path)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Datei aus der Datenbank löschen
    diesel::delete(files::table.find(file_id))
        .execute(&mut conn)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let clients = state.clients.clone();
    let lock = clients.lock().await;

    if let Some(senders) = lock.get(&auth_user.user_id) {
        for tx in senders {
            let _ = tx.send(Message::Text(format!("delete file").into()));
        }
    }
    Ok(StatusCode::NO_CONTENT)
}
