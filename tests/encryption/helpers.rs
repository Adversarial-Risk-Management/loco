//! Setup helpers for encryption integration tests.

use loco_rs::{
    app::AppContext,
    encryption::{
        config::{EncryptionConfig, KeyDerivationConfig},
        registry,
    },
    tests_cfg::app::get_app_context,
};
use sea_orm::{ConnectionTrait, Database, DatabaseConnection, Schema};

use super::entity;

/// Hex-encoded 32-byte keys used across the integration suite.
pub const KEY_A: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
pub const KEY_B: &str = "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100";
pub const DET_KEY: &str = "aabbccdd00112233445566778899aabbccddeeff00112233445566778899aabb";
pub const SALT: &str = "112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00";

/// Build an `EncryptionConfig` with the given primary, optional previous key,
/// and key-derivation enabled.
pub fn config(primary: &str, previous: Option<&str>) -> EncryptionConfig {
    EncryptionConfig {
        primary_key: primary.to_string(),
        previous_keys: previous.map(|k| vec![k.to_string()]).unwrap_or_default(),
        deterministic_key: Some(DET_KEY.to_string()),
        key_derivation: Some(KeyDerivationConfig {
            enabled: true,
            salt: Some(SALT.to_string()),
        }),
    }
}

/// Open an in-memory sqlite connection and create the `secret_documents`
/// table from the entity definition.
pub async fn make_db() -> DatabaseConnection {
    let db = Database::connect("sqlite::memory:")
        .await
        .expect("connect sqlite in-memory");
    let backend = db.get_database_backend();
    let schema = Schema::new(backend);
    let stmt = schema.create_table_from_entity(entity::Entity);
    db.execute_raw(backend.build(&stmt))
        .await
        .expect("create secret_documents table");
    db
}

/// Build a fresh `AppContext` whose `shared_store` already has the encryption
/// provider registered, with the given primary key and optional previous key.
/// Replaces `ctx.db` with a fresh in-memory sqlite connection so each test
/// is isolated.
pub async fn ctx_with_encryption(primary: &str, previous: Option<&str>) -> AppContext {
    let mut ctx = get_app_context().await;
    ctx.db = make_db().await;
    let cfg = config(primary, previous);
    registry::register(&ctx, &cfg).expect("register encryption provider");
    ctx
}

/// Fetch one string column of a `secret_documents` row exactly as stored.
pub async fn raw_string_column(db: &DatabaseConnection, id: i32, column: &str) -> String {
    let backend = db.get_database_backend();
    let stmt = sea_orm::Statement::from_sql_and_values(
        backend,
        format!("SELECT {column} FROM secret_documents WHERE id = ?"),
        [id.into()],
    );
    let row = db
        .query_one_raw(stmt)
        .await
        .expect("raw query")
        .expect("row exists");
    row.try_get::<String>("", column).expect("string column")
}
