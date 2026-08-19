//! Entity with **nullable** encrypted columns (`Option<String>`), matching
//! what `cargo loco generate model x ssn:string:encrypted` produces by
//! default (the bare column DSL is nullable). Exercises the
//! `EncryptableValue` impl for `Option<String>` in
//! `impl_encryptable_fields!`.

use loco_rs::impl_encryptable_fields;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, serde::Serialize, serde::Deserialize)]
#[sea_orm(table_name = "nullable_documents")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    /// Nullable, non-deterministic.
    #[sea_orm(column_type = "Text", nullable)]
    pub ssn: Option<String>,
    /// Nullable, deterministic (queryable by equality).
    #[sea_orm(column_type = "Text", nullable)]
    pub email: Option<String>,
    pub name: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl_encryptable_fields!(ActiveModel, [ssn, email(deterministic)]);
