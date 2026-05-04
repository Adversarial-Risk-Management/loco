//! Sibling entity with AAD binding enabled, used by the
//! ciphertext-relocation-defense test.

use loco_rs::encryption::Encryptable;
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

impl Encryptable for ActiveModel {
    fn encrypted_fields() -> Vec<String> {
        vec!["ssn".into(), "email".into()]
    }

    fn deterministic_fields() -> Vec<String> {
        vec!["email".into()]
    }

    /// Bind every ciphertext to its `(table, column)` location so a row-level
    /// attacker cannot copy `bound_documents.email` into `bound_documents.ssn`
    /// (or another row's column) and have it decrypt.
    fn field_aad(field_name: &str) -> Vec<u8> {
        format!("bound_documents:{field_name}").into_bytes()
    }

    fn get_set_string_value(&self, field_name: &str) -> Option<String> {
        match field_name {
            "ssn" => match &self.ssn {
                sea_orm::ActiveValue::Set(v) => Some(v.clone()),
                _ => None,
            },
            "email" => match &self.email {
                sea_orm::ActiveValue::Set(v) => Some(v.clone()),
                _ => None,
            },
            _ => None,
        }
    }

    fn set_string_value(mut self, field_name: &str, value: String) -> Self {
        match field_name {
            "ssn" => self.ssn = sea_orm::ActiveValue::Set(value),
            "email" => self.email = sea_orm::ActiveValue::Set(value),
            _ => {}
        }
        self
    }
}
