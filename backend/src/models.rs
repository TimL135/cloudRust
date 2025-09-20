use chrono::NaiveDateTime;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Queryable, Serialize, Clone)]
pub struct File {
    pub id: i32,
    pub user_id: i32,
    pub original_filename: String,
    pub stored_filename: String,
    pub file_path: String,
    pub file_size: i64,
    pub mime_type: Option<String>,
    pub file_hash: Option<String>,
    pub is_public: bool,
    pub upload_status: String,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
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
    pub is_public: bool,
    pub upload_status: String,
}
