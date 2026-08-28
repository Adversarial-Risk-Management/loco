//! Sibling entity used by the compression integration tests.

use loco_rs::impl_encryptable_fields;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, serde::Serialize, serde::Deserialize)]
#[sea_orm(table_name = "long_documents")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    #[sea_orm(column_type = "Text", nullable)]
    pub bio: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub note: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

// `bio` is compressed by default; `note` opts out of compression with
// `(no_compress)`, so it is stored at plaintext size even when large.
impl_encryptable_fields!(
    ActiveModel,
    [bio, note(no_compress)],
    aad_namespace = "long_documents",
);
