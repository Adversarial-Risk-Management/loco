//! The `users` entity. SSN and email are encrypted at rest; email is
//! deterministic so we can do equality lookups against the ciphertext.

use loco_rs::impl_encryptable_fields;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, serde::Serialize, serde::Deserialize)]
#[sea_orm(table_name = "users")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub name: String,
    /// Stored as encrypted JSON; decrypted via `decrypt_fields_ctx`.
    #[sea_orm(column_type = "Text", nullable)]
    pub ssn: String,
    /// Same, but deterministic so `WHERE email = encrypted_query(...)` works.
    #[sea_orm(column_type = "Text", nullable)]
    pub email: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl_encryptable_fields!(ActiveModel, [ssn, email(deterministic)]);
