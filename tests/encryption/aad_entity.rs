//! Sibling entity used by the ciphertext-relocation-defense tests. The macro
//! binds every ciphertext to `bound_documents:<column>`.

use loco_rs::impl_encryptable_fields;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, serde::Serialize, serde::Deserialize)]
#[sea_orm(table_name = "bound_documents")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(column_type = "Text", nullable)]
    pub ssn: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub email: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl_encryptable_fields!(
    ActiveModel,
    [ssn, email(deterministic)],
    aad_namespace = "bound_documents",
);
