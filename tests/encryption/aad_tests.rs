//! AAD binding integration tests.
//!
//! `aad_entity` binds every ciphertext to `(table, column)`. These tests
//! demonstrate that the binding defeats the ciphertext-relocation attack
//! class.

use loco_rs::encryption::{Encryptable, ModelDecryption};
use sea_orm::{ActiveModelTrait, ConnectionTrait, DatabaseConnection, EntityTrait, Set, Statement};

use super::{
    aad_entity::{ActiveModel, Entity, Model},
    helpers::{ctx_with_encryption, make_db_for, KEY_A},
};

async fn ctx() -> loco_rs::app::AppContext {
    let mut c = ctx_with_encryption(KEY_A, None).await;
    c.db = make_db_for(Entity).await;
    c
}

async fn insert(ctx: &loco_rs::app::AppContext, ssn: &str, email: &str) -> Model {
    let am = ActiveModel {
        ssn: Set(ssn.into()),
        email: Set(email.into()),
        ..Default::default()
    };
    am.encrypt_fields_ctx(ctx)
        .unwrap()
        .insert(&ctx.db)
        .await
        .unwrap()
}

async fn raw(db: &DatabaseConnection, id: i32, col: &str) -> String {
    let backend = db.get_database_backend();
    let stmt = Statement::from_sql_and_values(
        backend,
        format!("SELECT {col} FROM bound_documents WHERE id = ?"),
        [id.into()],
    );
    let row = db.query_one_raw(stmt).await.unwrap().unwrap();
    row.try_get::<String>("", col).unwrap()
}

#[tokio::test]
async fn aad_bound_field_round_trips_normally() {
    let ctx = ctx().await;
    let saved = insert(&ctx, "111-22-3333", "alice@example.com").await;

    let mut model = Entity::find_by_id(saved.id)
        .one(&ctx.db)
        .await
        .unwrap()
        .unwrap();
    model.decrypt_fields_ctx::<Entity>(&ctx).unwrap();
    assert_eq!(model.ssn, "111-22-3333");
    assert_eq!(model.email, "alice@example.com");
}

#[tokio::test]
async fn aad_defeats_cross_column_relocation() {
    // Attacker writes the email ciphertext into the ssn column. Without AAD
    // this would silently decrypt as if it were an SSN; with AAD bound to
    // `bound_documents:<column>`, decryption fails.
    let ctx = ctx().await;
    let saved = insert(&ctx, "111-22-3333", "alice@example.com").await;

    let email_ct = raw(&ctx.db, saved.id, "email").await;

    // Move email's ciphertext into the ssn column.
    ctx.db
        .execute_raw(Statement::from_sql_and_values(
            ctx.db.get_database_backend(),
            "UPDATE bound_documents SET ssn = ? WHERE id = ?",
            [email_ct.into(), saved.id.into()],
        ))
        .await
        .unwrap();

    let mut model = Entity::find_by_id(saved.id)
        .one(&ctx.db)
        .await
        .unwrap()
        .unwrap();
    let err = model
        .decrypt_fields_ctx::<Entity>(&ctx)
        .expect_err("relocated ciphertext must fail authentication");
    assert!(
        err.to_string().to_lowercase().contains("keys"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn changing_aad_invalidates_existing_ciphertexts() {
    // The macro's AAD feeds through to the cipher: the bound ciphertext does
    // not decrypt under the no-AAD primitive.
    let ctx = ctx().await;
    let saved = insert(&ctx, "111-22-3333", "alice@example.com").await;
    let ssn_ct = raw(&ctx.db, saved.id, "ssn").await;

    use loco_rs::encryption::{cipher, registry};
    let provider = registry::require(&ctx).unwrap();
    let key = provider.get_field_key("ssn").unwrap();

    // Empty AAD against a bound ciphertext: must fail.
    let err = cipher::decrypt(&ssn_ct, key.as_bytes(), b"").unwrap_err();
    assert!(matches!(
        err,
        loco_rs::encryption::EncryptionError::DecryptionFailed(_)
    ));

    // Correct AAD: succeeds.
    let aad = ActiveModel::field_aad("ssn");
    assert_eq!(
        cipher::decrypt(&ssn_ct, key.as_bytes(), &aad).unwrap(),
        "111-22-3333"
    );
}
