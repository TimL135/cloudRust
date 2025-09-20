// src/schema.rs
// automatisch generiert von diesel print-schema

diesel::table! {
    users (id) {
        id -> Int4,
        email -> Varchar,
        password_hash -> Varchar,
        first_name -> Nullable<Varchar>,
        last_name -> Nullable<Varchar>,
        is_active -> Bool,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    files (id) {
        id -> Int4,
        user_id -> Int4,
        original_filename -> Varchar,
        stored_filename -> Varchar,
        file_path -> Varchar,
        file_size -> Int8,
        mime_type -> Nullable<Varchar>,
        file_hash -> Nullable<Varchar>,
        is_public -> Bool,
        upload_status -> Varchar,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::joinable!(files -> users (user_id));
diesel::allow_tables_to_appear_in_same_query!(users, files,);
