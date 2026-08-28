//! Minimal SeaORM entity used by the encryption integration tests.
//!
//! Schema:
//! ```sql
//! CREATE TABLE secret_documents (
//!   id INTEGER PRIMARY KEY AUTOINCREMENT,
//!   ssn TEXT,           -- non-deterministic encryption
//!   email TEXT,         -- deterministic encryption (queryable by equality)
//!   name TEXT
//! );
//! ```

use loco_rs::impl_encryptable_fields;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, serde::Serialize, serde::Deserialize)]
#[sea_orm(table_name = "secret_documents")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    #[sea_orm(column_type = "Text", nullable)]
    pub ssn: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub email: String,
    pub name: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

#[async_trait::async_trait]
impl ActiveModelBehavior for ActiveModel {
    async fn before_save<C>(mut self, _db: &C, _insert: bool) -> Result<Self, DbErr>
    where
        C: ConnectionTrait,
    {
        if let sea_orm::ActiveValue::Set(ssn) = &mut self.ssn {
            *ssn = ssn.trim().to_string();
        }
        Ok(self)
    }
}

impl_encryptable_fields!(
    ActiveModel,
    [ssn, email(deterministic)],
    aad_namespace = "secret_documents",
);
