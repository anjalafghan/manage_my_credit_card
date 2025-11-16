use argon2::{Algorithm as ArgonAlgorithm, Argon2, Params, Version};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use once_cell::sync::Lazy;
use password_hash::rand_core::OsRng;
use password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

/// Load JWT secret from environment in production.
/// Set: JWT_SECRET="some-very-long-random-string"
static JWT_SECRET: Lazy<String> = Lazy::new(|| {
    std::env::var("JWT_SECRET").expect("JWT_SECRET env var must be set in the environment")
});

fn encoding_key() -> EncodingKey {
    EncodingKey::from_secret(JWT_SECRET.as_bytes())
}

fn decoding_key() -> DecodingKey {
    DecodingKey::from_secret(JWT_SECRET.as_bytes())
}

fn jwt_validation() -> Validation {
    let mut v = Validation::new(Algorithm::HS256);
    v.validate_exp = true;
    v
}

// Argon2id with sane defaults for interactive logins.
fn argon2id() -> Argon2<'static> {
    Argon2::new(ArgonAlgorithm::Argon2id, Version::V0x13, Params::default())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // username or user_id
    pub exp: i64,    // expiration (seconds since epoch)
    pub iat: i64,    // issued at
}

pub async fn create_user(pool: &SqlitePool, username: &str, password: &str) -> Result<(), String> {
    if username.trim().is_empty() {
        return Err("Username cannot be empty".to_string());
    }

    if password.len() < 8 {
        return Err("Password must be at least 8 characters".to_string());
    }

    // Generate a random salt and hash with Argon2id
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = argon2id();

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_e| "Internal error (hash)".to_string())?
        .to_string();

    crate::db::create_user(pool, username, &password_hash)
        .await
        .map_err(|_e| "Failed to create user".to_string())?;

    Ok(())
}

pub async fn authenticate_user(
    pool: &SqlitePool,
    username: &str,
    password: &str,
) -> Result<String, String> {
    let user = crate::db::get_user_by_username(pool, username)
        .await
        .map_err(|_e| "Internal authentication error".to_string())?
        .ok_or_else(|| "Invalid credentials".to_string())?;

    // Parse stored Argon2 hash
    let parsed_hash = PasswordHash::new(&user.password_hash)
        .map_err(|_e| "Internal authentication error".to_string())?;

    let argon2 = argon2id();

    // Verify password
    let verify_result = argon2.verify_password(password.as_bytes(), &parsed_hash);

    if verify_result.is_err() {
        // Treat any verify failure as invalid creds
        return Err("Invalid credentials".to_string());
    }

    let now = Utc::now();
    let expiration = now
        .checked_add_signed(Duration::hours(24))
        .ok_or_else(|| "Invalid timestamp".to_string())?
        .timestamp();

    let claims = Claims {
        sub: user.username,
        exp: expiration,
        iat: now.timestamp(),
    };

    let header = Header::new(Algorithm::HS256);

    let token = encode(&header, &claims, &encoding_key())
        .map_err(|_e| "Failed to generate token".to_string())?;

    Ok(token)
}

pub fn verify_token(token: &str) -> Result<Claims, String> {
    log::info!("verify_token: verifying token, len={}", token.len());

    let token_data = decode::<Claims>(token, &decoding_key(), &jwt_validation()).map_err(|e| {
        log::warn!("verify_token: JWT decode/validation error: {}", e);
        format!("Token verification failed: {}", e)
    })?;

    log::info!("verify_token: success for sub={}", token_data.claims.sub);

    Ok(token_data.claims)
}
