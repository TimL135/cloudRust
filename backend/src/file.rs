use axum::{
    extract::{ws::Message, Multipart, Path, Query, State},
    http::StatusCode,
    response::Json,
};
use base64::{engine::general_purpose, Engine as _};
use chrono::{NaiveDateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::{fs, io::AsyncWriteExt};
use tower_cookies::Cookies;
use uuid::Uuid;

use crate::schema::wrapped_keys;
use crate::{schema::files, user::authenticate_user_from_cookie, AppState};
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
    pub iv: String,
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
    pub mime_type: String,
    pub file_hash: String,
    pub iv: String,
    pub upload_status: String,
}
#[derive(Serialize)]
pub struct UploadResponse {
    pub id: i32,
    pub filename: String,
    pub size: i64,
    pub url: String,
}

#[derive(Debug, Serialize)]
pub struct DownloadResponse {
    pub file: Vec<u8>,
    pub file_iv: String,
    pub wrapped_key: WrappedKey,
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

use std::collections::HashMap;

#[derive(Debug, Deserialize, Serialize)]
struct EncryptedFile {
    #[serde(rename = "encryptedData")]
    encrypted_data: String,
    iv: String,
    #[serde(rename = "fileName")]
    file_name: String,
    #[serde(rename = "fileType")]
    file_type: String,
    #[serde(rename = "fileSize")]
    file_size: i64,
}

#[derive(Debug, Deserialize, Serialize)]
struct MultiRecipientEncryptedFile {
    #[serde(rename = "encryptedFile")]
    encrypted_file: EncryptedFile,
    #[serde(rename = "wrappedKeys")]
    wrapped_keys: HashMap<String, String>,
}

#[derive(Insertable)]
#[diesel(table_name = wrapped_keys)]
struct NewWrappedKey {
    user_id: i32,
    file_id: i32,
    wrapped_key: String,
    public_key: String,
}
#[derive(Debug, Deserialize, Queryable, Selectable, Serialize)]
#[diesel(table_name = wrapped_keys)]
pub struct WrappedKey {
    pub id: i32,
    pub user_id: i32,
    pub file_id: i32,
    pub wrapped_key: String,
    pub public_key: String,
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: chrono::NaiveDateTime,
}

pub async fn upload(
    State(state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> Result<Json<Vec<UploadResponse>>, StatusCode> {
    let user_id = 1; // TODO: aus Session/JWT

    let mut responses = Vec::new();
    let mut current_file_json: Option<String> = None;
    let mut current_sender_public_key: Option<String> = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?
    {
        let field_name = field.name().unwrap_or("").to_string();

        match field_name.as_str() {
            "file" => {
                current_file_json = Some(field.text().await.map_err(|_| StatusCode::BAD_REQUEST)?);
            }
            "sender_public_key" => {
                current_sender_public_key =
                    Some(field.text().await.map_err(|_| StatusCode::BAD_REQUEST)?);
            }
            _ => {}
        }

        // Wenn wir beide Felder haben, verarbeiten
        if let (Some(file_json), Some(sender_key)) =
            (&current_file_json, &current_sender_public_key)
        {
            // JSON parsen
            let encrypted_file: MultiRecipientEncryptedFile =
                serde_json::from_str(file_json).map_err(|_| StatusCode::BAD_REQUEST)?;

            // Base64 dekodieren für Speicherung
            let encrypted_data_bytes = general_purpose::STANDARD
                .decode(&encrypted_file.encrypted_file.encrypted_data)
                .map_err(|_| StatusCode::BAD_REQUEST)?;

            // unique filename generieren
            let ext = std::path::Path::new(&encrypted_file.encrypted_file.file_name)
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("");
            let stored_filename = format!("{}.{}", Uuid::new_v4(), ext);
            let upload_dir = "uploads";
            let file_path = format!("{}/{}", upload_dir, stored_filename);

            fs::create_dir_all(upload_dir)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            // Hash berechnen
            let mut hasher = Sha256::new();
            hasher.update(&encrypted_data_bytes);
            let file_hash = format!("{:x}", hasher.finalize());

            // Verschlüsselte Datei speichern
            let mut file = fs::File::create(&file_path)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            file.write_all(&encrypted_data_bytes)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            // DB Insert
            let new_file = NewFile {
                user_id,
                original_filename: encrypted_file.encrypted_file.file_name.clone(),
                stored_filename: stored_filename.clone(),
                file_path: file_path.clone(),
                file_size: encrypted_file.encrypted_file.file_size,
                mime_type: encrypted_file.encrypted_file.file_type.clone(),
                file_hash: file_hash,
                iv: encrypted_file.encrypted_file.iv,
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
            // Wrapped Keys speichern
            for (recipient_user_id, wrapped_key_json) in encrypted_file.wrapped_keys {
                // JSON parsen

                let new_wrapped_key = NewWrappedKey {
                    user_id: recipient_user_id.parse::<i32>().unwrap_or(user_id),
                    file_id: file_record.id,
                    wrapped_key: wrapped_key_json,
                    public_key: sender_key.clone(),
                };

                diesel::insert_into(wrapped_keys::table)
                    .values(&new_wrapped_key)
                    .execute(&mut conn)
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            }

            responses.push(UploadResponse {
                id: file_record.id,
                filename: encrypted_file.encrypted_file.file_name.clone(),
                size: file_record.file_size,
                url: format!("/api/files/{}/download", file_record.id),
            });

            // Reset für nächste Datei
            current_file_json = None;
            current_sender_public_key = None;
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
    cookies: Cookies,
    Query(params): Query<FileQuery>,
) -> Result<Json<FileListResponse>, StatusCode> {
    let auth_user = authenticate_user_from_cookie(State(state.clone()), cookies.clone()).await?;
    let user_id = auth_user.user_id;
    let page = params.page.unwrap_or(1);
    let limit = params.limit.unwrap_or(20);
    let offset = (page - 1) * limit;

    let mut conn = state
        .db
        .get()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let query = files::table.into_boxed().filter(files::user_id.eq(user_id));

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
            created_at: f.created_at.unwrap_or(Utc::now().naive_utc()),
        })
        .collect();

    Ok(Json(FileListResponse {
        files: file_infos,
        total,
    }))
}

pub async fn download(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    Path(file_id): Path<i32>,
) -> Result<Json<DownloadResponse>, StatusCode> {
    let auth_user = authenticate_user_from_cookie(State(state.clone()), cookies.clone()).await?;

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
    let wrapped_key = wrapped_keys::table
        .filter(wrapped_keys::file_id.eq(file.id))
        .filter(wrapped_keys::user_id.eq(auth_user.user_id))
        .first::<WrappedKey>(&mut conn)
        .map_err(|_| StatusCode::NOT_FOUND)?;

    Ok(Json(DownloadResponse {
        file: file_data,
        file_iv: file.iv,
        wrapped_key,
    }))
}

pub async fn delete(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    Path(file_id): Path<i32>,
) -> Result<StatusCode, StatusCode> {
    let auth_user = authenticate_user_from_cookie(State(state.clone()), cookies.clone()).await?;

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
