//! Integration tests for nullable (`Option<String>`) encrypted columns —
//! the shape `cargo loco generate model x ssn:string:encrypted` emits.

use loco_rs::encryption::{
    encrypt_query_value, is_encrypted_format, Encryptable, ModelDecryption, RowScope,
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, EntityTrait, QueryFilter,
    Set, Statement,
};

use super::{
    helpers::{ctx_with_encryption, make_db_for, KEY_A},
    nullable_entity::{ActiveModel, Column, Entity},
};

async fn ctx() -> loco_rs::app::AppContext {
    let mut c = ctx_with_encryption(KEY_A, None).await;
    c.db = make_db_for(Entity).await;
    c
}

async fn raw(db: &DatabaseConnection, id: i32, col: &str) -> Option<String> {
    let backend = db.get_database_backend();
    let stmt = Statement::from_sql_and_values(
        backend,
        format!("SELECT {col} FROM nullable_documents WHERE id = ?"),
        [id.into()],
    );
    let row = db.query_one_raw(stmt).await.unwrap().unwrap();
    row.try_get::<Option<String>>("", col).unwrap()
}

#[tokio::test]
async fn nullable_some_value_encrypts_and_round_trips() {
    let ctx = ctx().await;
    let saved = ActiveModel {
        ssn: Set(Some("111-22-3333".to_string())),
        email: Set(Some("alice@example.com".to_string())),
        name: Set("Alice".to_string()),
        ..Default::default()
    }
    .encrypt_fields_ctx(&ctx)
    .unwrap()
    .insert(&ctx.db)
    .await
    .unwrap();

    // At rest: both columns hold encryption envelopes, not plaintext.
    let stored_ssn = raw(&ctx.db, saved.id, "ssn").await.unwrap();
    let stored_email = raw(&ctx.db, saved.id, "email").await.unwrap();
    assert!(
        is_encrypted_format(&stored_ssn),
        "ssn not encrypted: {stored_ssn}"
    );
    assert!(is_encrypted_format(&stored_email));
    assert!(!stored_ssn.contains("111-22-3333"));

    // Read + decrypt restores the plaintext inside `Some`.
    let mut model = Entity::find_by_id(saved.id)
        .one(&ctx.db)
        .await
        .unwrap()
        .unwrap();
    model.decrypt_fields_ctx::<Entity>(&ctx).unwrap();
    assert_eq!(model.ssn.as_deref(), Some("111-22-3333"));
    assert_eq!(model.email.as_deref(), Some("alice@example.com"));
}

#[tokio::test]
async fn nullable_none_stays_null_and_decrypts_as_none() {
    let ctx = ctx().await;
    let saved = ActiveModel {
        ssn: Set(None),
        email: Set(None),
        name: Set("Blank".to_string()),
        ..Default::default()
    }
    .encrypt_fields_ctx(&ctx)
    .unwrap()
    .insert(&ctx.db)
    .await
    .unwrap();

    // NULL in means SQL NULL at rest — no phantom envelope.
    assert_eq!(raw(&ctx.db, saved.id, "ssn").await, None);
    assert_eq!(raw(&ctx.db, saved.id, "email").await, None);

    // And decryption leaves `None` untouched.
    let mut model = Entity::find_by_id(saved.id)
        .one(&ctx.db)
        .await
        .unwrap()
        .unwrap();
    model.decrypt_fields_ctx::<Entity>(&ctx).unwrap();
    assert_eq!(model.ssn, None);
    assert_eq!(model.email, None);
}

#[tokio::test]
async fn nullable_deterministic_field_is_queryable_by_equality() {
    let ctx = ctx().await;
    for (name, email) in [("Alice", "alice@example.com"), ("Bob", "bob@example.com")] {
        ActiveModel {
            ssn: Set(None),
            email: Set(Some(email.to_string())),
            name: Set(name.to_string()),
            ..Default::default()
        }
        .encrypt_fields_ctx(&ctx)
        .unwrap()
        .insert(&ctx.db)
        .await
        .unwrap();
    }

    let needle =
        encrypt_query_value::<Entity>("email", "bob@example.com", &ctx, &RowScope::new()).unwrap();
    let found = Entity::find()
        .filter(Column::Email.eq(needle))
        .all(&ctx.db)
        .await
        .unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].name, "Bob");
}
