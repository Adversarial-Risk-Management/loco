//! End-to-end encryption tests against a real SeaORM entity backed by sqlite.

use loco_rs::encryption::{
    encrypt_query_value, is_encrypted_format, registry, Encryptable, EncryptedValue,
    ModelDecryption, RowScope,
};
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder, Set, Statement, Unchanged,
};

use super::{
    entity::{self, ActiveModel, Column, Entity, Model},
    helpers::{ctx_with_encryption, raw_string_column, KEY_A, KEY_B},
};

/// Insert a row through `insert_encrypted` and read the raw column value back
/// via a SQL query so we can assert on the persisted ciphertext.
async fn insert_with_encryption(
    ctx: &loco_rs::app::AppContext,
    ssn: &str,
    email: &str,
    name: &str,
) -> Model {
    let am = ActiveModel {
        ssn: Set(ssn.to_string()),
        email: Set(email.to_string()),
        name: Set(name.to_string()),
        ..Default::default()
    };
    am.insert_encrypted(ctx)
        .await
        .expect("insert encrypted row")
}

#[tokio::test]
async fn encrypts_at_rest_and_decrypts_on_read() {
    let ctx = ctx_with_encryption(KEY_A, None).await;

    let saved = insert_with_encryption(&ctx, "123-45-6789", "alice@example.com", "Alice").await;

    // The model returned from `insert` still holds the encrypted form (Loco's
    // model layer is *not* magically transparent — that's intentional, see
    // module docs).
    assert!(is_encrypted_format(&saved.ssn));
    assert!(is_encrypted_format(&saved.email));

    // What hits disk is the same encrypted JSON envelope.
    let raw_ssn = raw_string_column(&ctx.db, saved.id, "ssn").await;
    let raw_email = raw_string_column(&ctx.db, saved.id, "email").await;
    assert!(is_encrypted_format(&raw_ssn));
    assert!(is_encrypted_format(&raw_email));

    // Decrypt via the context-aware helper.
    let mut model = Entity::find_by_id(saved.id)
        .one(&ctx.db)
        .await
        .unwrap()
        .unwrap();
    model
        .decrypt_fields_ctx(&ctx)
        .expect("decrypt fields via context");
    assert_eq!(model.ssn, "123-45-6789");
    assert_eq!(model.email, "alice@example.com");
    assert_eq!(model.name, "Alice");
}

#[tokio::test]
async fn save_encrypted_encrypts_before_persistence() {
    let ctx = ctx_with_encryption(KEY_A, None).await;
    let active = ActiveModel {
        ssn: Set("123-45-6789".to_string()),
        email: Set("alice@example.com".to_string()),
        name: Set("Alice".to_string()),
        ..Default::default()
    }
    .save_encrypted(&ctx)
    .await
    .unwrap();

    assert!(is_encrypted_format(
        &raw_string_column(&ctx.db, active.id.unwrap(), "ssn").await
    ));
}

#[tokio::test]
async fn before_save_runs_before_encryption() {
    let ctx = ctx_with_encryption(KEY_A, None).await;
    let mut saved =
        insert_with_encryption(&ctx, "  123-45-6789  ", "alice@example.com", "Alice").await;

    saved.decrypt_fields_ctx(&ctx).unwrap();
    assert_eq!(saved.ssn, "123-45-6789");
}

#[tokio::test]
async fn deterministic_email_is_queryable_by_equality() {
    let ctx = ctx_with_encryption(KEY_A, None).await;

    let alice = insert_with_encryption(&ctx, "111", "alice@example.com", "Alice").await;
    let bob = insert_with_encryption(&ctx, "222", "bob@example.com", "Bob").await;
    let _carol = insert_with_encryption(&ctx, "333", "carol@example.com", "Carol").await;

    // Build the deterministic query value and search by it.
    let needle = encrypt_query_value::<Entity>("email", "bob@example.com", &ctx, &RowScope::new())
        .expect("query encryption");
    let found = Entity::find()
        .filter(Column::Email.eq(needle))
        .one(&ctx.db)
        .await
        .unwrap()
        .expect("bob's row");
    assert_eq!(found.id, bob.id);
    assert_ne!(found.id, alice.id);
}

#[tokio::test]
async fn ssn_is_not_queryable_by_equality_because_iv_is_random() {
    let ctx = ctx_with_encryption(KEY_A, None).await;
    let _ = insert_with_encryption(&ctx, "555-12-3456", "x@example.com", "X").await;

    // ssn is non-deterministic — `encrypt_query_value` must refuse it so users
    // don't silently produce a query that can never match any row.
    let err = encrypt_query_value::<Entity>("ssn", "555-12-3456", &ctx, &RowScope::new())
        .expect_err("non-deterministic field must error");
    assert!(
        err.to_string().contains("not declared as deterministic"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn rotation_decrypts_records_written_under_a_previous_key() {
    // Write under primary=A.
    let ctx_a = ctx_with_encryption(KEY_A, None).await;
    let original = insert_with_encryption(&ctx_a, "old", "alice@example.com", "Alice").await;

    // Snapshot the raw ciphertext from the A-keyed DB.
    let ciphertext_ssn = raw_string_column(&ctx_a.db, original.id, "ssn").await;

    drop(ctx_a);

    // Stand up a fresh ctx with primary=B + previous=A and copy the row in
    // verbatim so the simulated old data is now read under the new config.
    let ctx_b = ctx_with_encryption(KEY_B, Some(KEY_A)).await;
    let stmt = Statement::from_sql_and_values(
        ctx_b.db.get_database_backend(),
        "INSERT INTO secret_documents (ssn, email, name) VALUES (?, ?, ?)",
        [
            ciphertext_ssn.into(),
            // re-insert any encrypted email under B too; this row mirrors the
            // realistic case of a partial migration
            insert_with_encryption(&ctx_b, "tmp", "alice@example.com", "tmp")
                .await
                .email
                .into(),
            "Alice".into(),
        ],
    );
    ctx_b.db.execute_raw(stmt).await.unwrap();

    // The most-recently-inserted row has SSN written under A; reading it
    // should fall through to the previous-key entry.
    let last = Entity::find()
        .order_by_desc(Column::Id)
        .one(&ctx_b.db)
        .await
        .unwrap()
        .unwrap();
    let mut model = last.clone();
    model
        .decrypt_fields_ctx(&ctx_b)
        .expect("decrypt under rotated config");
    assert_eq!(
        model.ssn, "old",
        "rotation: previous key must decrypt old data"
    );
}

#[tokio::test]
async fn tampered_ciphertext_is_rejected() {
    let ctx = ctx_with_encryption(KEY_A, None).await;
    let saved = insert_with_encryption(&ctx, "123-45-6789", "alice@example.com", "Alice").await;

    // Pull the raw envelope, flip a byte in the base64 ciphertext, write it
    // back, then attempt decryption.
    let mut envelope =
        EncryptedValue::from_json(&raw_string_column(&ctx.db, saved.id, "ssn").await)
            .expect("envelope parses");
    let mut bytes = envelope.ciphertext().expect("ciphertext bytes");
    if bytes.is_empty() {
        bytes.push(0xFF);
    } else {
        bytes[0] ^= 0xFF;
    }
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    envelope.p = B64.encode(&bytes);
    let tampered = envelope.to_json().expect("re-serialize envelope");

    ctx.db
        .execute_raw(Statement::from_sql_and_values(
            ctx.db.get_database_backend(),
            "UPDATE secret_documents SET ssn = ? WHERE id = ?",
            [tampered.into(), saved.id.into()],
        ))
        .await
        .unwrap();

    let mut model = Entity::find_by_id(saved.id)
        .one(&ctx.db)
        .await
        .unwrap()
        .unwrap();
    let err = model
        .decrypt_fields_ctx(&ctx)
        .expect_err("tampered ciphertext must fail GCM authentication");
    assert!(
        err.to_string().to_lowercase().contains("keys"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn deterministic_envelope_carries_d_flag() {
    let ctx = ctx_with_encryption(KEY_A, None).await;
    let saved = insert_with_encryption(&ctx, "ssn-v", "alice@example.com", "Alice").await;

    let raw_email = raw_string_column(&ctx.db, saved.id, "email").await;
    let raw_ssn = raw_string_column(&ctx.db, saved.id, "ssn").await;

    let det = EncryptedValue::from_json(&raw_email).unwrap();
    let nondet = EncryptedValue::from_json(&raw_ssn).unwrap();
    let provider = registry::require(&ctx).unwrap();
    assert!(det.is_deterministic(), "email envelope must mark h.d=true");
    assert_eq!(det.key_id(), Some("deterministic"));
    assert_eq!(nondet.key_id(), provider.get_key_id().as_deref());
    assert!(
        !nondet.is_deterministic(),
        "ssn envelope must not be marked"
    );

    // The query helper must reproduce the stored deterministic envelope.
    let again = encrypt_query_value::<Entity>("email", "alice@example.com", &ctx, &RowScope::new())
        .unwrap();
    let stored = raw_email.clone();
    assert_eq!(
        again, stored,
        "deterministic ciphertext must be reproducible"
    );

    // Silence the unused-binding lint when the compiler decides nondet
    // doesn't need to live to the end.
    let _ = (nondet, entity::Entity);
}

#[tokio::test]
async fn plaintext_in_an_encrypted_column_is_an_error_on_read() {
    // The only plaintext-to-envelope transition is the save path. A stored
    // plaintext (a row written around the model layer) must not be handed
    // back as if it had been decrypted.
    let ctx = ctx_with_encryption(KEY_A, None).await;
    let saved = insert_with_encryption(&ctx, "123-45-6789", "alice@example.com", "Alice").await;
    ctx.db
        .execute_raw(Statement::from_sql_and_values(
            ctx.db.get_database_backend(),
            "UPDATE secret_documents SET ssn = ? WHERE id = ?",
            ["123-45-6789".into(), saved.id.into()],
        ))
        .await
        .unwrap();

    let mut model = Entity::find_by_id(saved.id)
        .one(&ctx.db)
        .await
        .unwrap()
        .unwrap();
    let err = model.decrypt_fields_ctx(&ctx).unwrap_err();
    assert!(
        matches!(err, loco_rs::encryption::EncryptionError::InvalidFormat(_)),
        "{err}"
    );
}

#[tokio::test]
async fn failed_decryption_leaves_the_model_unchanged() {
    let ctx = ctx_with_encryption(KEY_A, None).await;
    let saved = insert_with_encryption(&ctx, "123-45-6789", "alice@example.com", "Alice").await;
    ctx.db
        .execute_raw(Statement::from_sql_and_values(
            ctx.db.get_database_backend(),
            "UPDATE secret_documents SET email = ? WHERE id = ?",
            ["not-an-envelope".into(), saved.id.into()],
        ))
        .await
        .unwrap();

    let mut model = Entity::find_by_id(saved.id)
        .one(&ctx.db)
        .await
        .unwrap()
        .unwrap();
    let encrypted_ssn = model.ssn.clone();
    model.decrypt_fields_ctx(&ctx).unwrap_err();

    assert_eq!(model.ssn, encrypted_ssn);
    assert_eq!(model.email, "not-an-envelope");
}

#[tokio::test]
async fn unchanged_plaintext_is_encrypted_on_save() {
    // SeaORM's `insert` writes `Unchanged` columns, so a decrypted `Model`
    // turned back into an `ActiveModel` must not leak its plaintext to disk.
    let ctx = ctx_with_encryption(KEY_A, None).await;
    let saved = ActiveModel {
        ssn: Unchanged("123-45-6789".to_string()),
        email: Unchanged("alice@example.com".to_string()),
        name: Set("Alice".to_string()),
        ..Default::default()
    }
    .insert_encrypted(&ctx)
    .await
    .unwrap();

    let raw_ssn = raw_string_column(&ctx.db, saved.id, "ssn").await;
    assert!(is_encrypted_format(&raw_ssn), "stored: {raw_ssn}");
    assert!(is_encrypted_format(
        &raw_string_column(&ctx.db, saved.id, "email").await
    ));

    let mut model = Entity::find_by_id(saved.id)
        .one(&ctx.db)
        .await
        .unwrap()
        .unwrap();
    model.decrypt_fields_ctx(&ctx).unwrap();
    assert_eq!(model.ssn, "123-45-6789");
}
