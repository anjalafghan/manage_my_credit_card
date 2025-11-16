use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

const JWT_SECRET: &[u8] = b"your-secret-key-change-this-in-production";

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

pub async fn create_user(pool: &SqlitePool, username: &str, password: &str) -> Result<(), String> {
    if username.is_empty() || password.len() < 6 {
        return Err(
            "Username cannot be empty and password must be at least 6 characters".to_string(),
        );
    }

    let password_hash =
        hash(password, DEFAULT_COST).map_err(|e| format!("Password hashing failed: {}", e))?;

    crate::db::create_user(pool, username, &password_hash)
        .await
        .map_err(|e| format!("Failed to create user: {}", e))?;

    Ok(())
}

pub async fn authenticate_user(
    pool: &SqlitePool,
    username: &str,
    password: &str,
) -> Result<String, String> {
    let user = crate::db::get_user_by_username(pool, username)
        .await
        .map_err(|e| format!("Database error: {}", e))?
        .ok_or("Invalid credentials")?;

    let valid = verify(password, &user.password_hash)
        .map_err(|e| format!("Password verification failed: {}", e))?;

    if !valid {
        return Err("Invalid credentials".to_string());
    }

    let expiration = Utc::now()
        .checked_add_signed(Duration::hours(24))
        .ok_or("Invalid timestamp")?
        .timestamp() as usize;

    let claims = Claims {
        sub: user.username,
        exp: expiration,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET),
    )
    .map_err(|e| format!("Token generation failed: {}", e))?;

    Ok(token)
}

pub fn verify_token(token: &str) -> Result<Claims, String> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET),
        &Validation::default(),
    )
    .map_err(|e| format!("Token verification failed: {}", e))?;

    Ok(token_data.claims)
}
