//! Setup helpers for encryption integration tests, built on the shipped
//! `loco_rs::testing::encryption` helpers.

use loco_rs::{app::AppContext, encryption::config::EncryptionConfig, testing};
use sea_orm::{ConnectionTrait, Database, DatabaseConnection, EntityTrait, Schema};

use super::entity;

pub use testing::encryption::{DET_KEY, KEY_A, KEY_B, SALT};

/// Build an `EncryptionConfig` with the given primary, optional previous key,
/// and the shared deterministic key and salt.
pub fn config(primary: &str, previous: Option<&str>) -> EncryptionConfig {
    testing::encryption::encryption_config(primary, previous)
}

/// Open an in-memory sqlite connection and create `entity`'s table from its
/// definition.
pub async fn make_db_for<E: EntityTrait>(entity: E) -> DatabaseConnection {
    let db = Database::connect("sqlite::memory:")
        .await
        .expect("connect sqlite in-memory");
    let backend = db.get_database_backend();
    let stmt = Schema::new(backend).create_table_from_entity(entity);
    db.execute_raw(backend.build(&stmt))
        .await
        .expect("create table");
    db
}

/// [`make_db_for`] the `secret_documents` entity.
pub async fn make_db() -> DatabaseConnection {
    make_db_for(entity::Entity).await
}

/// Build a fresh `AppContext` whose `shared_store` already has the encryption
/// provider registered, with the given primary key and optional previous key.
/// Replaces `ctx.db` with a fresh in-memory sqlite connection so each test
/// is isolated.
pub async fn ctx_with_encryption(primary: &str, previous: Option<&str>) -> AppContext {
    let mut ctx = testing::encryption::ctx_with_encryption(primary, previous).await;
    ctx.db = make_db().await;
    ctx
}

/// Fetch one string column of a `secret_documents` row exactly as stored.
pub async fn raw_string_column(db: &DatabaseConnection, id: i64, column: &str) -> String {
    testing::encryption::raw_string_column(db, "secret_documents", id, column).await
}
