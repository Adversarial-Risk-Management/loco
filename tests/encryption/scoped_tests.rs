//! `aad_fields` integration tests: ciphertexts are bound to the row's
//! `org_id`, on both the macro/ctx path and the explicit-provider path.

use loco_rs::encryption::{
    decrypt_field, encrypt_query_value, key_provider::ConfigKeyProvider, Encryptable,
    EncryptionError, ModelDecryption, RowScope,
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, EntityTrait, QueryFilter,
    Set, Statement, Unchanged,
};
use uuid::Uuid;

use super::{
    helpers::{config, ctx_with_encryption, make_db_for, KEY_A, KEY_B},
    scoped_entity::{ActiveModel, Column, Entity, Model},
};

async fn ctx() -> loco_rs::app::AppContext {
    let mut c = ctx_with_encryption(KEY_A, None).await;
    c.db = make_db_for(Entity).await;
    c
}

async fn insert(ctx: &loco_rs::app::AppContext, org: Uuid, creds: &str, ext: &str) -> Model {
    ActiveModel {
        org_id: Set(org),
        credentials: Set(creds.to_string()),
        external_id: Set(ext.to_string()),
        ..Default::default()
    }
    .insert_encrypted(ctx)
    .await
    .unwrap()
}

async fn raw(db: &DatabaseConnection, id: i64, col: &str) -> String {
    let stmt = Statement::from_sql_and_values(
        db.get_database_backend(),
        format!("SELECT {col} FROM scoped_credentials WHERE id = ?"),
        [id.into()],
    );
    let row = db.query_one_raw(stmt).await.unwrap().unwrap();
    row.try_get::<String>("", col).unwrap()
}

#[tokio::test]
async fn scoped_fields_round_trip() {
    let ctx = ctx().await;
    let org = Uuid::new_v4();
    let saved = insert(&ctx, org, r#"{"token":"abc"}"#, "ext-1").await;

    let mut model = Entity::find_by_id(saved.id)
        .one(&ctx.db)
        .await
        .unwrap()
        .unwrap();
    model.decrypt_fields_ctx(&ctx).unwrap();
    assert_eq!(model.credentials, r#"{"token":"abc"}"#);
    assert_eq!(model.external_id, "ext-1");
    assert_eq!(model.org_id, org);
}

#[tokio::test]
async fn envelope_moved_to_another_org_row_fails_to_decrypt() {
    let ctx = ctx().await;
    let org_a = Uuid::new_v4();
    let org_b = Uuid::new_v4();
    let a = insert(&ctx, org_a, "a-secret", "ext-a").await;
    let b = insert(&ctx, org_b, "b-secret", "ext-b").await;

    // Attacker copies org A's credentials envelope onto org B's row.
    let a_ct = raw(&ctx.db, a.id, "credentials").await;
    ctx.db
        .execute_raw(Statement::from_sql_and_values(
            ctx.db.get_database_backend(),
            "UPDATE scoped_credentials SET credentials = ? WHERE id = ?",
            [a_ct.into(), b.id.into()],
        ))
        .await
        .unwrap();

    let mut model = Entity::find_by_id(b.id)
        .one(&ctx.db)
        .await
        .unwrap()
        .unwrap();
    let err = model
        .decrypt_fields_ctx(&ctx)
        .expect_err("cross-org relocation must fail authentication");
    assert!(
        matches!(err, EncryptionError::AllKeysFailed { .. }),
        "{err}"
    );

    // Saving that relocated envelope is rejected too: no key decrypts it
    // under org B's scope, so it never gets re-encrypted as B's data.
    let err = ActiveModel {
        id: Set(b.id),
        org_id: Set(org_b),
        credentials: Set(raw(&ctx.db, a.id, "credentials").await),
        ..Default::default()
    }
    .encrypt_fields_ctx(&ctx)
    .expect_err("relocated envelope must not re-encrypt under the new scope");
    assert!(
        matches!(err, EncryptionError::AllKeysFailed { .. }),
        "{err}"
    );
}

#[tokio::test]
async fn aad_is_namespace_field_and_hyphenated_uuid() {
    // Pins the exact AAD layout so the manual scheme's raw-16-byte form can
    // never be accepted by accident, and so hand-rolled readers can match it.
    let ctx = ctx().await;
    let org = Uuid::parse_str("6F9619FF-8B86-D011-B42D-00C04FC964FF").unwrap();
    let saved = insert(&ctx, org, "pinned", "ext").await;
    let ct = raw(&ctx.db, saved.id, "credentials").await;

    let provider = ConfigKeyProvider::new(&config(KEY_A, None)).unwrap();
    let aad = b"scoped_credentials:credentials\0org_id=\"6f9619ff-8b86-d011-b42d-00c04fc964ff\"";
    assert_eq!(
        decrypt_field(&ct, "credentials", &provider, aad).unwrap(),
        "pinned"
    );

    let mut raw_bytes = b"scoped_credentials:credentials\0org_id=".to_vec();
    raw_bytes.extend_from_slice(org.as_bytes());
    assert!(decrypt_field(&ct, "credentials", &provider, &raw_bytes).is_err());
    // The unquoted string form is not accepted either.
    let unquoted = format!("scoped_credentials:credentials\0org_id={org}");
    assert!(decrypt_field(&ct, "credentials", &provider, unquoted.as_bytes()).is_err());

    // The trait hooks agree with each other and with the pinned bytes.
    let am = ActiveModel {
        org_id: Set(org),
        ..Default::default()
    };
    let from_active = am.row_scope().unwrap();
    let from_model = ActiveModel::row_scope_from_model(&saved).unwrap();
    assert_eq!(from_active, from_model);
    assert_eq!(
        from_active.field_aad(ActiveModel::field_aad("credentials")),
        aad.to_vec()
    );
}

#[tokio::test]
async fn not_set_scope_column_is_an_error_only_when_an_encrypted_field_is_set() {
    let ctx = ctx().await;

    // Encrypted field Set, org_id NotSet: refuse rather than bind to nothing.
    let err = ActiveModel {
        credentials: Set("x".to_string()),
        ..Default::default()
    }
    .encrypt_fields_ctx(&ctx)
    .unwrap_err();
    assert!(matches!(err, EncryptionError::Scope(_)), "{err}");

    // No encrypted field Set: a partial update needs no scope.
    ActiveModel {
        id: Set(1),
        ..Default::default()
    }
    .encrypt_fields_ctx(&ctx)
    .expect("partial update without encrypted fields must not need the scope");
}

#[tokio::test]
async fn explicit_provider_path_honours_the_scope_and_rotation() {
    // Rotation tests drive `encrypt_fields(&provider)` / `decrypt_fields`
    // directly with a ConfigKeyProvider; the scope must apply there too.
    let db = make_db_for(Entity).await;
    let org = Uuid::new_v4();
    let key_a = ConfigKeyProvider::new(&config(KEY_A, None)).unwrap();
    let saved = ActiveModel {
        org_id: Set(org),
        credentials: Set("rotate-me".to_string()),
        external_id: Set("ext".to_string()),
        ..Default::default()
    }
    .encrypt_fields(&key_a)
    .unwrap()
    .insert(&db)
    .await
    .unwrap();

    // Read under KEY_B primary with KEY_A retired: decrypts via the previous
    // key with the scoped AAD.
    let rotated = ConfigKeyProvider::new(&config(KEY_B, Some(KEY_A))).unwrap();
    let mut model = Entity::find_by_id(saved.id)
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    model.decrypt_fields(&rotated).unwrap();
    assert_eq!(model.credentials, "rotate-me");

    // Re-save the stale envelope: it is rewritten under KEY_B, still bound
    // to the org, and readable by a provider that knows only KEY_B.
    let old_ct = raw(&db, saved.id, "credentials").await;
    ActiveModel {
        id: Set(saved.id),
        org_id: Unchanged(org),
        credentials: Set(old_ct.clone()),
        ..Default::default()
    }
    .encrypt_fields(&rotated)
    .unwrap()
    .update(&db)
    .await
    .unwrap();
    let new_ct = raw(&db, saved.id, "credentials").await;
    assert_ne!(new_ct, old_ct);
    let key_b_only = ConfigKeyProvider::new(&config(KEY_B, None)).unwrap();
    let mut model = Entity::find_by_id(saved.id)
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    model.decrypt_fields(&key_b_only).unwrap();
    assert_eq!(model.credentials, "rotate-me");
}

#[tokio::test]
async fn deterministic_scoped_field_queries_within_the_org() {
    let ctx = ctx().await;
    let org_a = Uuid::new_v4();
    let org_b = Uuid::new_v4();
    let a = insert(&ctx, org_a, "a", "shared-ext").await;
    let _b = insert(&ctx, org_b, "b", "shared-ext").await;

    // Same plaintext under different orgs is a different ciphertext, so the
    // needle only matches inside org A.
    let scope = RowScope::new().with("org_id", &org_a).unwrap();
    let needle = encrypt_query_value::<Entity>("external_id", "shared-ext", &ctx, &scope).unwrap();
    let found = Entity::find()
        .filter(Column::ExternalId.eq(needle))
        .all(&ctx.db)
        .await
        .unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].id, a.id);

    // A scope missing the required column is rejected instead of producing a
    // needle that never matches.
    let err = encrypt_query_value::<Entity>("external_id", "shared-ext", &ctx, &RowScope::new())
        .unwrap_err();
    assert!(matches!(err, EncryptionError::Scope(_)), "{err}");
}

#[tokio::test]
async fn changing_a_scope_column_requires_every_encrypted_field() {
    let ctx = ctx().await;
    let org_a = Uuid::new_v4();
    let org_b = Uuid::new_v4();
    let a = insert(&ctx, org_a, "creds", "ext").await;

    // Moving the row to org B without re-supplying the encrypted fields would
    // leave ciphertexts bound to org A behind: rejected.
    let err = ActiveModel {
        id: Set(a.id),
        org_id: Set(org_b),
        ..Default::default()
    }
    .encrypt_fields_ctx(&ctx)
    .unwrap_err();
    assert!(matches!(err, EncryptionError::Scope(_)), "{err}");

    // Supplying every encrypted field re-binds them to org B.
    let moved = ActiveModel {
        id: Set(a.id),
        org_id: Set(org_b),
        credentials: Set("creds".to_string()),
        external_id: Set("ext".to_string()),
    }
    .update_encrypted(&ctx)
    .await
    .unwrap();
    let mut model = Entity::find_by_id(moved.id)
        .one(&ctx.db)
        .await
        .unwrap()
        .unwrap();
    model.decrypt_fields_ctx(&ctx).unwrap();
    assert_eq!(model.org_id, org_b);
    assert_eq!(model.credentials, "creds");

    // A partial update of an encrypted field with the scope NotSet still
    // needs the scope (the AAD depends on it).
    let err = ActiveModel {
        id: Set(a.id),
        external_id: Set("ext-2".to_string()),
        ..Default::default()
    }
    .encrypt_fields_ctx(&ctx)
    .unwrap_err();
    assert!(matches!(err, EncryptionError::Scope(_)), "{err}");
}
