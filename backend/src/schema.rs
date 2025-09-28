// @generated automatically by Diesel CLI.

diesel::table! {
    access_tokens (id) {
        id -> Int4,
        user_id -> Int4,
        token_hash -> Text,
        expires_at -> Timestamp,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

diesel::table! {
    files (id) {
        id -> Int4,
        user_id -> Int4,
        #[max_length = 255]
        original_filename -> Varchar,
        #[max_length = 255]
        stored_filename -> Varchar,
        #[max_length = 500]
        file_path -> Varchar,
        file_size -> Int8,
        #[max_length = 100]
        mime_type -> Nullable<Varchar>,
        #[max_length = 64]
        file_hash -> Nullable<Varchar>,
        #[max_length = 20]
        upload_status -> Nullable<Varchar>,
        created_at -> Nullable<Timestamptz>,
        updated_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    users (id) {
        id -> Int4,
        name -> Text,
        email -> Text,
        password_hash -> Text,
        public_key -> Text,
        encrypted_private_key -> Text,
        role -> Text,
        created_at -> Nullable<Timestamp>,
        updated_at -> Nullable<Timestamp>,
        last_login -> Nullable<Timestamp>,
        is_active -> Nullable<Bool>,
    }
}

diesel::joinable!(access_tokens -> users (user_id));
diesel::joinable!(files -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(access_tokens, files, users,);
