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

    println!("Creating / opening database at: {}", database_url);

    let connect_opts = database_url
        .parse::<sqlx::sqlite::SqliteConnectOptions>()
        .map_err(|e| sqlx::Error::Configuration(Box::new(e)))?
        .create_if_missing(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(connect_opts)
        .await?;

    // Always enable foreign keys in SQLite
    sqlx::query("PRAGMA foreign_keys = ON;")
        .execute(&pool)
        .await?;

    // Initialize database schema
    init_schema(&pool).await?;

    let _ = DB_POOL.set(pool.clone());

    Ok(pool)
}

async fn init_schema(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    // Users table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        "#,
    )
    .execute(pool)
    .await?;

    // Credit cards table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS credit_cards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            brand TEXT NOT NULL,
            last4 TEXT NOT NULL,
            credit_limit INTEGER NOT NULL DEFAULT 0,
            current_balance INTEGER NOT NULL DEFAULT 0,
            nickname TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        "#,
    )
    .execute(pool)
    .await?;

    // Optional index: speed up lookups by user_id
    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_credit_cards_user_id
        ON credit_cards (user_id);
        "#,
    )
    .execute(pool)
    .await?;

    Ok(())
}

//
// ─────────────────────────── Users ───────────────────────────
//

#[derive(Debug, sqlx::FromRow)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    // created_at is present in DB but we don't need it in code right now
}

pub async fn create_user(
    pool: &SqlitePool,
    username: &str,
    password_hash: &str,
) -> Result<i64, sqlx::Error> {
    let result = sqlx::query(
        r#"
        INSERT INTO users (username, password_hash)
        VALUES (?, ?)
        "#,
    )
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
        r#"
        SELECT id, username, password_hash
        FROM users
        WHERE username = ?
        "#,
    )
    .bind(username)
    .fetch_optional(pool)
    .await?;

    Ok(user)
}

//
// ───────────────────────── Credit cards ─────────────────────────
//

#[derive(Debug, sqlx::FromRow, Clone, serde::Serialize, serde::Deserialize)]
pub struct CreditCard {
    pub id: i64,
    pub user_id: i64,
    pub brand: String,
    pub last4: String,
    pub credit_limit: i64,
    pub current_balance: i64,
    pub nickname: Option<String>,
}

/// Helper to get user_id from username
async fn get_user_id(pool: &SqlitePool, username: &str) -> Result<i64, sqlx::Error> {
    let row: (i64,) = sqlx::query_as(
        r#"
        SELECT id FROM users WHERE username = ?
        "#,
    )
    .bind(username)
    .fetch_one(pool)
    .await?;

    Ok(row.0)
}

/// List all cards belonging to a given username.
pub async fn list_cards_for_user(
    pool: &SqlitePool,
    username: &str,
) -> Result<Vec<CreditCard>, sqlx::Error> {
    // You can either:
    // 1) join users + credit_cards, or
    // 2) get user_id then filter by user_id.
    //
    // We'll go with a join to avoid two round trips.

    let cards = sqlx::query_as::<_, CreditCard>(
        r#"
        SELECT
            c.id,
            c.user_id,
            c.brand,
            c.last4,
            c.credit_limit,
            c.current_balance,
            c.nickname
        FROM credit_cards c
        JOIN users u ON c.user_id = u.id
        WHERE u.username = ?
        ORDER BY c.created_at DESC, c.id DESC
        "#,
    )
    .bind(username)
    .fetch_all(pool)
    .await?;

    Ok(cards)
}

/// Insert a new card for a user (by username).
pub async fn insert_card_for_user(
    pool: &SqlitePool,
    username: &str,
    brand: &str,
    last4: &str,
    credit_limit: i64,
    nickname: Option<String>,
) -> Result<CreditCard, sqlx::Error> {
    let user_id = get_user_id(pool, username).await?;

    let result = sqlx::query(
        r#"
        INSERT INTO credit_cards (user_id, brand, last4, credit_limit, current_balance, nickname)
        VALUES (?, ?, ?, ?, 0, ?)
        "#,
    )
    .bind(user_id)
    .bind(brand)
    .bind(last4)
    .bind(credit_limit)
    .bind(nickname)
    .execute(pool)
    .await?;

    let id = result.last_insert_rowid();

    // Return the inserted card
    let card = sqlx::query_as::<_, CreditCard>(
        r#"
        SELECT
            id,
            user_id,
            brand,
            last4,
            credit_limit,
            current_balance,
            nickname
        FROM credit_cards
        WHERE id = ?
        "#,
    )
    .bind(id)
    .fetch_one(pool)
    .await?;

    Ok(card)
}

/// Update an existing card that belongs to the given username.
pub async fn update_card_for_user(
    pool: &SqlitePool,
    username: &str,
    id: i64,
    brand: &str,
    last4: &str,
    credit_limit: i64,
    current_balance: i64,
    nickname: Option<String>,
) -> Result<CreditCard, sqlx::Error> {
    let user_id = get_user_id(pool, username).await?;

    let result = sqlx::query(
        r#"
        UPDATE credit_cards
        SET
            brand = ?,
            last4 = ?,
            credit_limit = ?,
            current_balance = ?,
            nickname = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND user_id = ?
        "#,
    )
    .bind(brand)
    .bind(last4)
    .bind(credit_limit)
    .bind(current_balance)
    .bind(nickname)
    .bind(id)
    .bind(user_id)
    .execute(pool)
    .await?;

    if result.rows_affected() == 0 {
        // No such card or doesn't belong to this user
        return Err(sqlx::Error::RowNotFound);
    }

    let card = sqlx::query_as::<_, CreditCard>(
        r#"
        SELECT
            id,
            user_id,
            brand,
            last4,
            credit_limit,
            current_balance,
            nickname
        FROM credit_cards
        WHERE id = ?
        "#,
    )
    .bind(id)
    .fetch_one(pool)
    .await?;

    Ok(card)
}

/// Delete a card for a specific user (by username).
pub async fn delete_card_for_user(
    pool: &SqlitePool,
    username: &str,
    id: i64,
) -> Result<(), sqlx::Error> {
    let user_id = get_user_id(pool, username).await?;

    let result = sqlx::query(
        r#"
        DELETE FROM credit_cards
        WHERE id = ? AND user_id = ?
        "#,
    )
    .bind(id)
    .bind(user_id)
    .execute(pool)
    .await?;

    if result.rows_affected() == 0 {
        // No such card or doesn't belong to this user
        return Err(sqlx::Error::RowNotFound);
    }

    Ok(())
}
