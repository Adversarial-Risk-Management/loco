//! Compression integration tests.

use loco_rs::encryption::{format::EncryptedValue, Encryptable, ModelDecryption};
use sea_orm::{
    ActiveModelTrait, ConnectionTrait, Database, DatabaseConnection, EntityTrait, Schema, Set,
    Statement,
};

use super::{
    compress_entity::{ActiveModel, Entity, Model},
    helpers::{ctx_with_encryption, KEY_A},
};

async fn make_db() -> DatabaseConnection {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    let backend = db.get_database_backend();
    let stmt = Schema::new(backend).create_table_from_entity(Entity);
    db.execute_raw(backend.build(&stmt)).await.unwrap();
    db
}

async fn ctx() -> loco_rs::app::AppContext {
    let mut c = ctx_with_encryption(KEY_A, None).await;
    c.db = make_db().await;
    c
}

async fn insert(ctx: &loco_rs::app::AppContext, bio: &str, note: &str) -> Model {
    let am = ActiveModel {
        bio: Set(bio.into()),
        note: Set(note.into()),
        ..Default::default()
    };
    am.encrypt_fields_ctx(ctx)
        .unwrap()
        .insert(&ctx.db)
        .await
        .unwrap()
}

async fn raw(db: &DatabaseConnection, id: i32, col: &str) -> String {
    let stmt = Statement::from_sql_and_values(
        db.get_database_backend(),
        format!("SELECT {col} FROM long_documents WHERE id = ?"),
        [id.into()],
    );
    let row = db.query_one_raw(stmt).await.unwrap().unwrap();
    row.try_get::<String>("", col).unwrap()
}

#[tokio::test]
async fn long_compressed_field_round_trips() {
    let ctx = ctx().await;
    let bio: String = "loco encryption story ".repeat(64);
    let note: String = "short note".into();
    let saved = insert(&ctx, &bio, &note).await;

    let mut model = Entity::find_by_id(saved.id)
        .one(&ctx.db)
        .await
        .unwrap()
        .unwrap();
    model.decrypt_fields_ctx::<Entity>(&ctx).unwrap();
    assert_eq!(model.bio, bio);
    assert_eq!(model.note, note);
}

#[tokio::test]
async fn long_bio_envelope_marks_compressed_and_shrinks_payload() {
    let ctx = ctx().await;
    // Highly redundant payload so deflate has plenty to work with.
    let bio: String = "the same line over and over and over\n".repeat(80);
    let note: String = "untouched".into();
    let saved = insert(&ctx, &bio, &note).await;

    let bio_env = raw(&ctx.db, saved.id, "bio").await;
    let parsed = EncryptedValue::from_json(&bio_env).unwrap();
    assert!(parsed.is_compressed(), "bio should be marked h.c=true");

    let payload = parsed.ciphertext().unwrap();
    assert!(
        payload.len() < bio.len() / 4,
        "compressed bio ciphertext ({}) should be << plaintext ({})",
        payload.len(),
        bio.len()
    );

    // The note field is not on the compress list, so its envelope must not
    // claim compression even though the plaintext is short.
    let note_env = raw(&ctx.db, saved.id, "note").await;
    let note_parsed = EncryptedValue::from_json(&note_env).unwrap();
    assert!(!note_parsed.is_compressed());
}

#[tokio::test]
async fn short_compressed_plaintext_is_stored_uncompressed() {
    let ctx = ctx().await;
    // Below COMPRESS_THRESHOLD (140 bytes) — encrypt path skips deflate.
    let bio = "short bio".to_string();
    let saved = insert(&ctx, &bio, "n").await;

    let env = raw(&ctx.db, saved.id, "bio").await;
    let parsed = EncryptedValue::from_json(&env).unwrap();
    assert!(
        !parsed.is_compressed(),
        "below-threshold plaintext must skip compression"
    );

    let mut model = Entity::find_by_id(saved.id)
        .one(&ctx.db)
        .await
        .unwrap()
        .unwrap();
    model.decrypt_fields_ctx::<Entity>(&ctx).unwrap();
    assert_eq!(model.bio, bio);
}
