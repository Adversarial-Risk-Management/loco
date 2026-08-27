//! Tenant-keyed entity: `aad_fields = [org_id]` plus `provider_for`, so each
//! organization's rows are encrypted under that organization's own keys.

use loco_rs::impl_encryptable_fields;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, serde::Serialize, serde::Deserialize)]
#[sea_orm(table_name = "tenant_secrets")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub org_id: Uuid,
    #[sea_orm(column_type = "Text")]
    pub secret: String,
    #[sea_orm(column_type = "Text")]
    pub lookup: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl_encryptable_fields!(
    ActiveModel,
    [secret, lookup(deterministic)],
    aad_namespace = "tenant_secrets",
    aad_fields = [org_id],
    provider_for = super::tenant_tests::org_provider,
);
