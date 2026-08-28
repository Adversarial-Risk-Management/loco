//! Helpers for testing models with encrypted fields.
//!
//! Available with the `testing` and `encryption` features. They cover the
//! setup every encryption test repeats: a config with all three keys, an
//! `AppContext` with that provider registered, and a raw read of a stored
//! column so a test can assert on the ciphertext rather than the decrypted
//! value.
//!
//! ```rust,ignore
//! use loco_rs::testing::encryption::{ctx_with_encryption, raw_string_column, KEY_A, KEY_B};
//!
//! let mut ctx = ctx_with_encryption(KEY_B, Some(KEY_A)).await;
//! ctx.db = my_sqlite_db().await;
//! let stored = raw_string_column(&ctx.db, "users", saved.id, "ssn").await;
//! ```

use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement};

use crate::{
    app::AppContext,
    encryption::{config::EncryptionConfig, registry},
};

/// Hex-encoded 32-byte primary key for tests.
pub const KEY_A: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
/// A second primary key, for rotation tests.
pub const KEY_B: &str = "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100";
/// Deterministic key used by [`encryption_config`].
pub const DET_KEY: &str = "aabbccdd00112233445566778899aabbccddeeff00112233445566778899aabb";
/// HKDF salt used by [`encryption_config`].
pub const SALT: &str = "112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00";

/// An `EncryptionConfig` with the given primary key, an optional previous
/// key, the shared [`DET_KEY`], and [`SALT`].
#[must_use]
pub fn encryption_config(primary: &str, previous: Option<&str>) -> EncryptionConfig {
    EncryptionConfig {
        primary_key: primary.to_string(),
        previous_keys: previous.map(|k| vec![k.to_string()]).unwrap_or_default(),
        deterministic_key: DET_KEY.to_string(),
        key_derivation_salt: SALT.to_string(),
    }
}

/// A test `AppContext` with the provider built by [`encryption_config`] from
/// `primary` and `previous` registered in its `shared_store`. Replace
/// `ctx.db` with your own connection afterwards.
///
/// # Panics
/// Panics if the config fails validation.
pub async fn ctx_with_encryption(primary: &str, previous: Option<&str>) -> AppContext {
    ctx_with_encryption_config(&encryption_config(primary, previous)).await
}

/// A test `AppContext` with the provider for `cfg` registered.
///
/// # Panics
/// Panics if the config fails validation.
pub async fn ctx_with_encryption_config(cfg: &EncryptionConfig) -> AppContext {
    let ctx = crate::tests_cfg::app::get_app_context().await;
    registry::register(&ctx, cfg).expect("register encryption provider");
    ctx
}

/// One string column of one row, exactly as stored — the envelope, not the
/// plaintext. `table` and `column` are interpolated into the SQL and must
/// be trusted identifiers.
///
/// # Panics
/// Panics if the query fails, the row is missing, or the column is not a
/// non-null string.
pub async fn raw_string_column(
    db: &DatabaseConnection,
    table: &str,
    id: i64,
    column: &str,
) -> String {
    raw_nullable_column(db, table, id, column)
        .await
        .expect("column is NULL")
}

/// [`raw_string_column`] for a nullable column.
///
/// # Panics
/// Panics if the query fails or the row is missing.
pub async fn raw_nullable_column(
    db: &DatabaseConnection,
    table: &str,
    id: i64,
    column: &str,
) -> Option<String> {
    let backend = db.get_database_backend();
    let placeholder = match backend {
        DbBackend::Postgres => "$1",
        _ => "?",
    };
    let stmt = Statement::from_sql_and_values(
        backend,
        format!("SELECT {column} FROM {table} WHERE id = {placeholder}"),
        [id.into()],
    );
    let row = db
        .query_one_raw(stmt)
        .await
        .expect("raw query")
        .expect("row exists");
    row.try_get::<Option<String>>("", column)
        .expect("string column")
}
