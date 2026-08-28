//! Compression integration tests.

use loco_rs::encryption::{Encryptable, EncryptedValue, ModelDecryption};
use sea_orm::{ConnectionTrait, DatabaseConnection, EntityTrait, Set, Statement};

use super::{
    compress_entity::{ActiveModel, Entity, Model},
    helpers::{ctx_with_encryption, make_db_for, KEY_A},
};

async fn ctx() -> loco_rs::app::AppContext {
    let mut c = ctx_with_encryption(KEY_A, None).await;
    c.db = make_db_for(Entity).await;
    c
}

async fn insert(ctx: &loco_rs::app::AppContext, bio: &str, note: &str) -> Model {
    let am = ActiveModel {
        bio: Set(bio.into()),
        note: Set(note.into()),
        ..Default::default()
    };
    am.insert_encrypted(ctx).await.unwrap()
}

async fn raw(db: &DatabaseConnection, id: i64, col: &str) -> String {
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
    model.decrypt_fields_ctx(&ctx).unwrap();
    assert_eq!(model.bio, bio);
    assert_eq!(model.note, note);
}

#[tokio::test]
async fn long_bio_envelope_marks_compressed_and_shrinks_payload() {
    let ctx = ctx().await;
    // Highly redundant payloads so deflate would have plenty to work with.
    let bio: String = "the same line over and over and over\n".repeat(80);
    let note: String = "the same note over and over and over\n".repeat(80);
    let saved = insert(&ctx, &bio, &note).await;

    // `bio` is compressed by default.
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

    // `note` opts out via `(no_compress)`: even this long, redundant payload
    // must be stored uncompressed, proving the opt-out is honored rather than
    // the threshold merely being missed.
    let note_env = raw(&ctx.db, saved.id, "note").await;
    let note_parsed = EncryptedValue::from_json(&note_env).unwrap();
    assert!(
        !note_parsed.is_compressed(),
        "note opted out of compression and must not be deflated"
    );
    assert!(
        note_parsed.ciphertext().unwrap().len() >= note.len(),
        "uncompressed note ciphertext should be ~plaintext size, not shrunk"
    );
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
    model.decrypt_fields_ctx(&ctx).unwrap();
    assert_eq!(model.bio, bio);
}
