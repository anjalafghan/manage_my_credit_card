use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};
use std::path::Path;
use std::sync::OnceLock;

static DB_POOL: OnceLock<SqlitePool> = OnceLock::new();

pub async fn get_db_pool() -> Result<SqlitePool, sqlx::Error> {
    if let Some(pool) = DB_POOL.get() {
        return Ok(pool.clone());
    }

    // Use current directory for database file
    let db_path = std::env::current_dir()
        .map(|p| p.join("auth.db"))
        .unwrap_or_else(|_| Path::new("auth.db").to_path_buf());

    let database_url = format!("sqlite:{}", db_path.display());

    println!("Creating database at: {}", database_url);

    // Create the database file if it doesn't exist by using create_if_missing
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(
            database_url
                .parse::<sqlx::sqlite::SqliteConnectOptions>()
                .map_err(|e| sqlx::Error::Configuration(Box::new(e)))?
                .create_if_missing(true),
        )
        .await?;

    // Initialize database schema
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        "#,
    )
    .execute(&pool)
    .await?;

    let _ = DB_POOL.set(pool.clone());

    Ok(pool)
}

#[derive(Debug, sqlx::FromRow)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
}

pub async fn create_user(
    pool: &SqlitePool,
    username: &str,
    password_hash: &str,
) -> Result<i64, sqlx::Error> {
    let result = sqlx::query("INSERT INTO users (username, password_hash) VALUES (?, ?)")
        .bind(username)
        .bind(password_hash)
        .execute(pool)
        .await?;

    Ok(result.last_insert_rowid())
}

pub async fn get_user_by_username(
    pool: &SqlitePool,
    username: &str,
) -> Result<Option<User>, sqlx::Error> {
    let user = sqlx::query_as::<_, User>(
        "SELECT id, username, password_hash FROM users WHERE username = ?",
    )
    .bind(username)
    .fetch_optional(pool)
    .await?;

    Ok(user)
}
