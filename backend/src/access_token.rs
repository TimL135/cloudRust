use crate::{
    db_error_to_status,
    schema::access_tokens::{self},
};
use axum::http::StatusCode;
use chrono::{Duration as ChronoDuration, NaiveDateTime, Utc};
use diesel::{dsl::delete, prelude::*, Insertable, Queryable};
use rand::{distr::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::Duration;
use tower_cookies::{Cookie, Cookies};

#[derive(Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::access_tokens)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct AccessToken {
    pub id: i32,
    pub user_id: i32,
    pub token_hash: String,
    pub expires_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Insertable)]
#[diesel(table_name = crate::schema::access_tokens)]
pub struct NewAccessToken {
    pub user_id: i32,
    pub token_hash: String,
    pub expires_at: NaiveDateTime,
}

pub fn create(
    conn: &mut PgConnection,
    user_id: i32,
    cookies: Cookies,
) -> Result<(), Box<dyn std::error::Error>> {
    let token = generate_secure_token(64);
    let new_access_token = NewAccessToken {
        user_id,
        token_hash: hash_cookie(token.clone()),
        expires_at: (Utc::now() + ChronoDuration::milliseconds(1500)).naive_utc(),
    };
    diesel::insert_into(access_tokens::table)
        .values(&new_access_token)
        .execute(conn)?;

    cookies.add(
        Cookie::build(("access_token", token.clone()))
            .http_only(true)
            .secure(true)
            .same_site(tower_cookies::cookie::SameSite::Lax)
            .path("/")
            .max_age(Duration::milliseconds(1500))
            .build(),
    );
    Ok(())
}

pub fn check(conn: &mut PgConnection, cookies: Cookies) -> Result<i32, StatusCode> {
    use self::access_tokens::dsl::*;

    // Token aus Cookies extrahieren (bereits gut)
    let token = cookies
        .get("access_token")
        .and_then(|cookie| Some(cookie.value().to_string()))
        .ok_or(StatusCode::NOT_FOUND)?;

    // Token in DB suchen: Verwende ? für DB-Fehler und handle Option
    let access_token_opt = access_tokens
        .filter(token_hash.eq(hash_cookie(token.clone())))
        .first::<AccessToken>(conn)
        .optional()
        .map_err(db_error_to_status)?;

    let access_token = match access_token_opt {
        Some(token) => token,
        None => return Err(StatusCode::UNAUTHORIZED), // Kein Token gefunden
    };

    // Ablauf prüfen
    if access_token.expires_at < Utc::now().naive_utc() {
        // Token löschen: ? für DB-Fehler
        delete(access_tokens.filter(id.eq(access_token.id)))
            .execute(conn)
            .map_err(db_error_to_status)?;

        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(access_token.user_id)
}

fn generate_secure_token(length: usize) -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

fn hash_cookie(cookie_token: String) -> String {
    let mut hasher = Sha256::new();
    hasher.update(&cookie_token);
    format!("{:x}", hasher.finalize())
}
