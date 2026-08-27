//! Lazy migration ("previous encryption schemes") integration tests: a `Set`
//! value that is already an envelope is kept when current, re-encrypted with
//! the current primary when a previous key wrote it, and rejected when no
//! configured key can decrypt it.

use loco_rs::encryption::{
    config::EncryptionConfig, decrypt_field, key_provider::ConfigKeyProvider, Encryptable,
};
use sea_orm::{ActiveModelTrait, Set};

use super::{
    entity::ActiveModel,
    helpers::{ctx_with_encryption, raw_string_column, DET_KEY, KEY_A, KEY_B, SALT},
};

async fn encrypted_ssn_under(ctx: &loco_rs::app::AppContext, ssn: &str) -> String {
    let saved = ActiveModel {
        ssn: Set(ssn.to_string()),
        email: Set("seed@example.com".to_string()),
        name: Set("Seed".to_string()),
        ..Default::default()
    }
    .encrypt_fields_ctx(ctx)
    .unwrap()
    .insert(&ctx.db)
    .await
    .unwrap();
    raw_string_column(&ctx.db, saved.id, "ssn").await
}

#[tokio::test]
async fn stale_envelope_is_reencrypted_with_the_current_key_on_save() {
    // A row written while KEY_A was primary.
    let ctx_a = ctx_with_encryption(KEY_A, None).await;
    let old_ssn_envelope = encrypted_ssn_under(&ctx_a, "111-22-3333").await;
    drop(ctx_a);

    // Rotated config: KEY_B primary, KEY_A demoted to previous. Saving the
    // old envelope must rewrite it under KEY_B.
    let ctx_b = ctx_with_encryption(KEY_B, Some(KEY_A)).await;
    let saved = ActiveModel {
        ssn: Set(old_ssn_envelope.clone()),
        email: Set("alice@example.com".to_string()),
        name: Set("Alice".to_string()),
        ..Default::default()
    }
    .encrypt_fields_ctx(&ctx_b)
    .unwrap()
    .insert(&ctx_b.db)
    .await
    .unwrap();

    let stored = raw_string_column(&ctx_b.db, saved.id, "ssn").await;
    assert_ne!(stored, old_ssn_envelope, "stale envelope must be rewritten");

    // Decisive: a provider knowing ONLY KEY_B (no previous keys) reads it.
    let key_b_only = ConfigKeyProvider::new(&EncryptionConfig {
        primary_key: KEY_B.to_string(),
        previous_keys: vec![],
        deterministic_key: DET_KEY.to_string(),
        key_derivation_salt: SALT.to_string(),
    })
    .unwrap();
    assert_eq!(
        decrypt_field(&stored, "ssn", &key_b_only, &ActiveModel::field_aad("ssn")).unwrap(),
        "111-22-3333"
    );
}

#[tokio::test]
async fn current_envelope_is_not_rewritten_on_save() {
    let ctx = ctx_with_encryption(KEY_A, None).await;
    let envelope = encrypted_ssn_under(&ctx, "999-88-7777").await;

    // Saving the same, already-current envelope must keep it byte-identical
    // (no IV churn, and `encrypt_fields` stays idempotent).
    let am = ActiveModel {
        ssn: Set(envelope.clone()),
        email: Set("bob@example.com".to_string()),
        name: Set("Bob".to_string()),
        ..Default::default()
    }
    .encrypt_fields_ctx(&ctx)
    .unwrap();
    assert_eq!(am.get_set_string_value("ssn").unwrap(), envelope);
}

#[tokio::test]
async fn undecryptable_envelope_is_rejected_on_save() {
    // Written under KEY_B...
    let ctx_b = ctx_with_encryption(KEY_B, None).await;
    let foreign_envelope = encrypted_ssn_under(&ctx_b, "000-00-0000").await;
    drop(ctx_b);

    // ...saved under a config that knows only KEY_A: no key decrypts it, so
    // the save must fail instead of persisting an unreadable value.
    let ctx_a = ctx_with_encryption(KEY_A, None).await;
    let err = ActiveModel {
        ssn: Set(foreign_envelope),
        email: Set("x@example.com".to_string()),
        name: Set("X".to_string()),
        ..Default::default()
    }
    .encrypt_fields_ctx(&ctx_a)
    .unwrap_err();
    assert!(
        err.to_string().to_lowercase().contains("key"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn deterministic_envelope_survives_primary_rotation_unchanged() {
    // The deterministic key does not rotate, so a deterministic envelope is
    // still current after a primary-key rotation and must stay byte-identical
    // (rewriting it would be harmless but pointless churn).
    let ctx_a = ctx_with_encryption(KEY_A, None).await;
    let saved = ActiveModel {
        ssn: Set("111-22-3333".to_string()),
        email: Set("carol@example.com".to_string()),
        name: Set("Carol".to_string()),
        ..Default::default()
    }
    .encrypt_fields_ctx(&ctx_a)
    .unwrap()
    .insert(&ctx_a.db)
    .await
    .unwrap();
    let email_envelope = raw_string_column(&ctx_a.db, saved.id, "email").await;
    drop(ctx_a);

    let ctx_b = ctx_with_encryption(KEY_B, Some(KEY_A)).await;
    let am = ActiveModel {
        ssn: Set("111-22-3333".to_string()),
        email: Set(email_envelope.clone()),
        name: Set("Carol".to_string()),
        ..Default::default()
    }
    .encrypt_fields_ctx(&ctx_b)
    .unwrap();
    assert_eq!(am.get_set_string_value("email").unwrap(), email_envelope);
}
