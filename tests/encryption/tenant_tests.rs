//! `provider_for` integration tests: the ctx helpers pick a per-org provider
//! from the row scope, cached in `shared_store`, and never fall back to the
//! global registry for a scoped row.

use std::{collections::HashMap, sync::RwLock};

use loco_rs::{
    app::AppContext,
    encryption::{
        encrypt_query_value_scoped, key_provider::ConfigKeyProvider, Encryptable, EncryptionError,
        EncryptionResult, ModelDecryption, RowScope, SharedKeyProvider,
    },
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, Database, DatabaseConnection, EntityTrait,
    QueryFilter, Schema, Set,
};
use uuid::Uuid;

use super::{
    helpers::{config, ctx_with_encryption, KEY_A, KEY_B},
    tenant_entity::{ActiveModel, Column, Entity},
};

/// Per-org provider cache, installed in `shared_store` by the app at an
/// async point (request extractor, job start) before any save or read.
#[derive(Default)]
pub struct OrgProviders(RwLock<HashMap<Uuid, SharedKeyProvider>>);

impl OrgProviders {
    fn insert(&self, org: Uuid, provider: SharedKeyProvider) {
        self.0.write().unwrap().insert(org, provider);
    }
    fn evict(&self, org: Uuid) {
        self.0.write().unwrap().remove(&org);
    }
}

/// The function named by `provider_for = ...` in `tenant_entity`.
pub fn org_provider(
    scope: &RowScope,
    ctx: &AppContext,
) -> EncryptionResult<Option<SharedKeyProvider>> {
    let org = scope
        .get("org_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| EncryptionError::Scope("org_id missing from scope".into()))?;
    let cache = ctx
        .shared_store
        .get_ref::<OrgProviders>()
        .ok_or_else(|| EncryptionError::NotConfigured("OrgProviders not installed".into()))?;
    // Returning `None` on a miss is safe: the macro-generated hook turns it
    // into an error instead of falling back to the global provider.
    Ok(cache.0.read().unwrap().get(&org).cloned())
}

async fn make_db() -> DatabaseConnection {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    let backend = db.get_database_backend();
    let stmt = Schema::new(backend).create_table_from_entity(Entity);
    db.execute_raw(backend.build(&stmt)).await.unwrap();
    db
}

/// Global registry holds KEY_B; orgs get their own providers.
async fn ctx() -> (AppContext, Uuid, Uuid) {
    let mut c = ctx_with_encryption(KEY_B, None).await;
    c.db = make_db().await;
    let org_a = Uuid::new_v4();
    let org_b = Uuid::new_v4();
    let cache = OrgProviders::default();
    cache.insert(org_a, provider(KEY_A, None));
    cache.insert(org_b, provider(KEY_B_ORG, None));
    c.shared_store.insert(cache);
    (c, org_a, org_b)
}

/// A third key so org B's provider differs from the global KEY_B registry.
const KEY_B_ORG: &str = "5555555555555555555555555555555555555555555555555555555555555555";

fn provider(primary: &str, previous: Option<&str>) -> SharedKeyProvider {
    std::sync::Arc::new(ConfigKeyProvider::new(&config(primary, previous)).unwrap())
}

async fn insert(ctx: &AppContext, org: Uuid, secret: &str, lookup: &str) -> i32 {
    ActiveModel {
        org_id: Set(org),
        secret: Set(secret.to_string()),
        lookup: Set(lookup.to_string()),
        ..Default::default()
    }
    .encrypt_fields_ctx(ctx)
    .unwrap()
    .insert(&ctx.db)
    .await
    .unwrap()
    .id
}

#[tokio::test]
async fn rows_are_encrypted_under_their_orgs_provider_not_the_registry() {
    let (ctx, org_a, _) = ctx().await;
    let id = insert(&ctx, org_a, "a-secret", "a-lookup").await;
    let stored = Entity::find_by_id(id).one(&ctx.db).await.unwrap().unwrap();

    // Readable through the ctx path (provider_for → org A's provider).
    let mut model = stored.clone();
    model.decrypt_fields_ctx::<Entity>(&ctx).unwrap();
    assert_eq!(model.secret, "a-secret");

    // Decisive: org A's provider alone reads it; the global KEY_B one cannot.
    let mut model = stored.clone();
    model
        .decrypt_fields::<Entity, _>(&*provider(KEY_A, None))
        .unwrap();
    assert_eq!(model.secret, "a-secret");
    let mut model = stored;
    let err = model
        .decrypt_fields::<Entity, _>(&*provider(KEY_B, None))
        .unwrap_err();
    assert!(
        matches!(err, EncryptionError::AllKeysFailed { .. }),
        "{err}"
    );
}

#[tokio::test]
async fn provider_cache_miss_is_an_error_not_a_registry_fallback() {
    let (ctx, org_a, _) = ctx().await;
    let unknown_org = Uuid::new_v4();

    let err = ActiveModel {
        org_id: Set(unknown_org),
        secret: Set("x".to_string()),
        ..Default::default()
    }
    .encrypt_fields_ctx(&ctx)
    .unwrap_err();
    assert!(
        matches!(err, EncryptionError::NotConfigured(_))
            && err.to_string().contains("org_provider"),
        "unexpected error: {err}"
    );

    // Eviction (what the app does on key rotation) has the same effect
    // until the cache is refilled.
    let id = insert(&ctx, org_a, "s", "l").await;
    ctx.shared_store
        .get_ref::<OrgProviders>()
        .unwrap()
        .evict(org_a);
    let mut model = Entity::find_by_id(id).one(&ctx.db).await.unwrap().unwrap();
    let err = model.decrypt_fields_ctx::<Entity>(&ctx).unwrap_err();
    assert!(matches!(err, EncryptionError::NotConfigured(_)), "{err}");
}

#[tokio::test]
async fn org_key_rotation_reencrypts_on_save_under_the_orgs_new_key() {
    let (ctx, org_a, _) = ctx().await;
    let id = insert(&ctx, org_a, "rotate", "l").await;
    let before = Entity::find_by_id(id).one(&ctx.db).await.unwrap().unwrap();

    // Rotate org A: new active key, KEY_A retired. Evict + reinstall.
    let cache = ctx.shared_store.get_ref::<OrgProviders>().unwrap();
    cache.evict(org_a);
    cache.insert(org_a, provider(KEY_B_ORG, Some(KEY_A)));

    // Read still works (retired key), and a re-save rewrites the envelope.
    let mut model = before.clone();
    model.decrypt_fields_ctx::<Entity>(&ctx).unwrap();
    assert_eq!(model.secret, "rotate");
    ActiveModel {
        id: Set(id),
        org_id: Set(org_a),
        secret: Set(before.secret.clone()),
        ..Default::default()
    }
    .encrypt_fields_ctx(&ctx)
    .unwrap()
    .update(&ctx.db)
    .await
    .unwrap();
    let after = Entity::find_by_id(id).one(&ctx.db).await.unwrap().unwrap();
    assert_ne!(after.secret, before.secret);

    // Readable with only the new org key.
    let mut model = after;
    model
        .decrypt_fields::<Entity, _>(&*provider(KEY_B_ORG, None))
        .unwrap();
    assert_eq!(model.secret, "rotate");
}

#[tokio::test]
async fn scoped_query_uses_the_orgs_provider() {
    let (ctx, org_a, org_b) = ctx().await;
    let id_a = insert(&ctx, org_a, "a", "same").await;
    let _id_b = insert(&ctx, org_b, "b", "same").await;

    let scope = RowScope::new().with("org_id", &org_a).unwrap();
    let needle = encrypt_query_value_scoped::<Entity>("lookup", "same", &scope, &ctx).unwrap();
    let found = Entity::find()
        .filter(Column::Lookup.eq(needle))
        .all(&ctx.db)
        .await
        .unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].id, id_a);

    // The hook is what the macro wired in.
    assert!(ActiveModel::provider_for(&scope, &ctx).unwrap().is_some());
}
