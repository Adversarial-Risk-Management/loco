//! Tenant-scoped entity: `aad_fields = [org_id]` binds every ciphertext to
//! the row's organization, the shape a multi-tenant credentials table uses.

use loco_rs::impl_encryptable_fields;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, serde::Serialize, serde::Deserialize)]
#[sea_orm(table_name = "scoped_credentials")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub org_id: Uuid,
    #[sea_orm(column_type = "Text")]
    pub credentials: String,
    /// Deterministic + scoped: equality queries need the org in the scope.
    #[sea_orm(column_type = "Text")]
    pub external_id: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl_encryptable_fields!(
    ActiveModel,
    [credentials(no_compress), external_id(deterministic)],
    aad_namespace = "scoped_credentials",
    aad_fields = [org_id],
);
