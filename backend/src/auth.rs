use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{NaiveDateTime, Utc};
use diesel::prelude::*;
use diesel::{AsChangeset, Insertable, Queryable};
use serde::{Deserialize, Serialize};

use crate::auth::users::role;

// Schema definition (normalerweise in schema.rs)
table! {
    users (id) {
        id -> Int4,
        name -> Varchar,
        email -> Varchar,
        password_hash -> Varchar,
        role -> Varchar,
        created_at -> Nullable<Timestamp>,
        updated_at -> Nullable<Timestamp>,
        last_login -> Nullable<Timestamp>,
        is_active -> Nullable<Bool>,
    }
}

#[derive(Debug, Serialize, Deserialize, Queryable, AsChangeset)]
#[diesel(table_name = users)]
pub struct User {
    pub id: i32,
    pub name: String,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub role: String,
    pub created_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
    pub last_login: Option<NaiveDateTime>,
    pub is_active: Option<bool>,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = users)]
pub struct NewUser {
    pub name: String,
    pub email: String,
    pub password_hash: String,
    pub role: String,
    pub created_at: Option<NaiveDateTime>,
    pub is_active: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub name: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub success: bool,
    pub message: String,
    pub user: Option<UserResponse>,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: i32,
    pub name: String,
    pub email: String,
    pub role: String,
    pub created_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
    pub last_login: Option<NaiveDateTime>,
    pub is_active: Option<bool>,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        UserResponse {
            id: user.id,
            name: user.name,
            email: user.email,
            role: user.role,
            created_at: user.created_at,
            updated_at: user.updated_at,
            last_login: user.last_login,
            is_active: user.is_active,
        }
    }
}

pub fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
    hash(password, DEFAULT_COST)
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, bcrypt::BcryptError> {
    verify(password, hash)
}

pub fn authenticate_user(
    conn: &mut PgConnection,
    email: &str,
    password: &str,
) -> Result<Option<User>, diesel::result::Error> {
    use self::users::dsl::*;

    let user_result = users
        .filter(email.eq(email))
        .first::<User>(conn)
        .optional()?;

    if let Some(user) = user_result {
        match verify_password(password, &user.password_hash) {
            Ok(true) => {
                // Update last_login
                diesel::update(users.find(user.id))
                    .set(last_login.eq(Some(Utc::now().naive_utc())))
                    .execute(conn)?;

                // Fetch updated user
                let updated_user = users.find(user.id).first::<User>(conn)?;
                Ok(Some(updated_user))
            }
            _ => Ok(None),
        }
    } else {
        Ok(None)
    }
}

pub fn create_user(
    conn: &mut PgConnection,
    name: &str,
    email: &str,
    password: &str,
) -> Result<User, Box<dyn std::error::Error>> {
    use self::users::dsl::users; // ✅ nur Tabelle, kein Namenskonflikt

    let hashed_password = hash_password(password)?; // <- Anderen Namen verwenden
    let now = Utc::now().naive_utc();

    let new_user = NewUser {
        name: name.to_string(),
        email: email.to_string(),
        password_hash: hashed_password,
        role: "user".to_string(),
        created_at: Some(now),
        is_active: Some(true),
    };

    let user = diesel::insert_into(users)
        .values(&new_user)
        .get_result::<User>(conn)?;

    Ok(user)
}

pub fn find_user_by_id(
    conn: &mut PgConnection,
    user_id: i32,
) -> Result<Option<User>, diesel::result::Error> {
    use self::users::dsl::*;

    users.find(user_id).first::<User>(conn).optional()
}

pub fn find_user_by_email(
    conn: &mut PgConnection,
    user_email: &str,
) -> Result<Option<User>, diesel::result::Error> {
    use self::users::dsl::*;

    users
        .filter(email.eq(user_email))
        .first::<User>(conn)
        .optional()
}

pub fn update_user(
    conn: &mut PgConnection,
    user_id: i32,
    user_updates: &User,
) -> Result<User, diesel::result::Error> {
    use self::users::dsl::*;

    diesel::update(users.find(user_id))
        .set(user_updates)
        .get_result::<User>(conn)
}

pub fn delete_user(conn: &mut PgConnection, user_id: i32) -> Result<usize, diesel::result::Error> {
    use self::users::dsl::*;

    diesel::delete(users.find(user_id)).execute(conn)
}

/// Erstellt automatisch einen Admin, falls keiner vorhanden ist.
pub fn init_admin_user(conn: &mut PgConnection) -> Result<(), Box<dyn std::error::Error>> {
    use self::users::dsl::users; // ✅ nur Tabelle, kein Namenskonflikt

    // Prüfen, ob ein Admin existiert
    let admin_exists = users
        .filter(role.eq("admin"))
        .first::<User>(conn)
        .optional()?
        .is_some();

    if !admin_exists {
        let password_hash = hash_password("admin")?;
        let now = Utc::now().naive_utc();

        let new_admin = NewUser {
            name: "Administrator".to_string(),
            email: "admin@localhost".to_string(),
            password_hash,
            role: "admin".to_string(),
            created_at: Some(now),
            is_active: Some(true),
        };

        diesel::insert_into(users)
            .values(&new_admin)
            .execute(conn)?;

        println!("🔐 Admin-Account 'admin@localhost' mit Passwort 'admin' erstellt!");
    }

    Ok(())
}
