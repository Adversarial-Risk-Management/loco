//! Row scope: sibling column values that bind a ciphertext to its row.
//!
//! [`RowScope`] carries the values of the columns an `Encryptable` model
//! names in `aad_fields = [...]` (for example a tenant id). Both sides of
//! the round trip derive it — the `ActiveModel` on encrypt and the `Model` on
//! decrypt — and feed it into the AES-GCM associated data, so a
//! ciphertext copied onto a row with different scope values fails
//! authentication. The same scope is what `Encryptable::provider_for` uses
//! to pick a per-row key provider.

use serde::Serialize;
pub use serde_json::Value;

use super::errors::{EncryptionError, EncryptionResult};

/// Ordered `(column, value)` pairs that scope a row's ciphertexts.
///
/// Values are JSON scalars only (string, number, bool). The model macro
/// converts `SeaORM` values to the same JSON representation on both the encrypt
/// and decrypt paths, so a `Uuid` column is always its hyphenated lowercase
/// string form. Raw bytes, arrays, objects, and `null` are rejected because
/// they have no single canonical byte encoding.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RowScope {
    entries: Vec<(String, Value)>,
}

impl RowScope {
    /// An empty scope: no row binding.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a column value, serialized through `serde`.
    ///
    /// # Errors
    /// Returns [`EncryptionError::Scope`] if the value does not serialize
    /// to a JSON scalar.
    pub fn with<T: Serialize + ?Sized>(
        mut self,
        column: impl Into<String>,
        value: &T,
    ) -> EncryptionResult<Self> {
        self.insert(column, value)?;
        Ok(self)
    }

    /// Add a column value, serialized through `serde`.
    ///
    /// # Errors
    /// Returns [`EncryptionError::Scope`] if the value does not serialize
    /// to a JSON scalar.
    pub fn insert<T: Serialize + ?Sized>(
        &mut self,
        column: impl Into<String>,
        value: &T,
    ) -> EncryptionResult<()> {
        let column = column.into();
        let value = serde_json::to_value(value)?;
        Self::check_scalar(&column, &value)?;
        self.entries.push((column, value));
        Ok(())
    }

    /// Add a scope value read from a `SeaORM` model.
    ///
    /// This is public for macro expansion in application crates. Use
    /// [`insert`](Self::insert) when building a scope directly.
    ///
    /// # Errors
    /// Returns [`EncryptionError::Scope`] for byte and array columns, `NULL`,
    /// or any value that does not convert to a JSON scalar.
    #[doc(hidden)]
    pub fn insert_sea_value(
        &mut self,
        column: impl Into<String>,
        value: &sea_orm::Value,
    ) -> EncryptionResult<()> {
        let column = column.into();
        if matches!(
            value,
            sea_orm::Value::Bytes(_) | sea_orm::Value::Array(_, _)
        ) {
            return Err(EncryptionError::Scope(format!(
                "scope column '{column}' must be a string, number, or bool"
            )));
        }
        let value = sea_orm::sea_query::sea_value_to_json_value(value);
        Self::check_scalar(&column, &value)?;
        self.entries.push((column, value));
        Ok(())
    }

    /// Build a scope from a serialized row by picking the named columns.
    ///
    /// # Errors
    /// Returns [`EncryptionError::Scope`] when `row` is not a JSON object,
    /// a named column is missing, or its value is `null` or not a scalar.
    pub fn from_json_row(row: &Value, columns: &[&str]) -> EncryptionResult<Self> {
        let obj = row.as_object().ok_or_else(|| {
            EncryptionError::Scope("row did not serialize to a JSON object".to_string())
        })?;
        let mut scope = Self::new();
        for column in columns {
            let value = obj.get(*column).ok_or_else(|| {
                EncryptionError::Scope(format!("scope column '{column}' is missing from the row"))
            })?;
            Self::check_scalar(column, value)?;
            scope.entries.push(((*column).to_string(), value.clone()));
        }
        Ok(scope)
    }

    /// The value recorded for `column`, if any.
    #[must_use]
    pub fn get(&self, column: &str) -> Option<&Value> {
        self.entries
            .iter()
            .find(|(c, _)| c == column)
            .map(|(_, v)| v)
    }

    /// The scoped column names, in declaration order.
    #[must_use]
    pub fn columns(&self) -> Vec<&str> {
        self.entries.iter().map(|(c, _)| c.as_str()).collect()
    }

    /// Whether the scope carries no values.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Number of scoped columns.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Canonical byte encoding appended to a field's AAD.
    ///
    /// Each entry renders as `\0<column>=<json>` in entry order, where
    /// `<json>` is the value's JSON text: strings quoted and escaped
    /// (`"7"`), numbers and bools bare (`7`, `true`). Quoting keeps the
    /// encoding injective — a string cannot impersonate a number, and a
    /// string containing `\0` or `=` cannot fake a second entry, because
    /// JSON escapes control characters. Empty for an empty scope, so
    /// unscoped models keep their existing AAD.
    #[must_use]
    pub fn aad_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (column, value) in &self.entries {
            out.push(0);
            out.extend_from_slice(column.as_bytes());
            out.push(b'=');
            out.extend_from_slice(value.to_string().as_bytes());
        }
        out
    }

    /// The same scope reordered to `columns`, for callers that built a scope
    /// by hand in a different insertion order than the model declares.
    ///
    /// # Errors
    /// Returns [`EncryptionError::Scope`] when a column is missing.
    pub fn ordered_by(&self, columns: &[String]) -> EncryptionResult<Self> {
        let mut out = Self::new();
        for column in columns {
            let value = self.get(column).ok_or_else(|| {
                EncryptionError::Scope(format!(
                    "query scope is missing column '{column}' required by the model's aad_fields"
                ))
            })?;
            out.entries.push((column.clone(), value.clone()));
        }
        Ok(out)
    }

    /// Full AAD for one field: the model's static `field_aad` followed by the
    /// row scope bytes.
    #[must_use]
    pub fn field_aad(&self, mut field_aad: Vec<u8>) -> Vec<u8> {
        field_aad.extend(self.aad_bytes());
        field_aad
    }

    fn check_scalar(column: &str, value: &Value) -> EncryptionResult<()> {
        match value {
            Value::String(_) | Value::Number(_) | Value::Bool(_) => Ok(()),
            Value::Null => Err(EncryptionError::Scope(format!(
                "scope column '{column}' is null; scoped rows must carry a value"
            ))),
            Value::Array(_) | Value::Object(_) => Err(EncryptionError::Scope(format!(
                "scope column '{column}' must be a string, number, or bool (got {})",
                match value {
                    Value::Array(_) => "an array",
                    _ => "an object",
                }
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_renders_as_hyphenated_lowercase_string() {
        // Pinned: the manual per-org scheme used the raw 16 bytes; this
        // scheme must only ever accept the string form, on both sides.
        let id = uuid::Uuid::parse_str("6F9619FF-8B86-D011-B42D-00C04FC964FF").unwrap();
        let scope = RowScope::new().with("org_id", &id).unwrap();
        assert_eq!(
            scope.aad_bytes(),
            b"\0org_id=\"6f9619ff-8b86-d011-b42d-00c04fc964ff\"".to_vec()
        );

        // Decrypt side reads the same bytes out of the serialized row.
        let row = serde_json::json!({ "id": 1, "org_id": id, "credentials": "x" });
        let from_row = RowScope::from_json_row(&row, &["org_id"]).unwrap();
        assert_eq!(from_row, scope);

        // Raw bytes serialize as an array and are rejected.
        assert!(matches!(
            RowScope::new().with("org_id", id.as_bytes()),
            Err(EncryptionError::Scope(_))
        ));
    }

    #[test]
    fn scalars_render_and_compose_in_order() {
        let scope = RowScope::new()
            .with("tenant", &7_i64)
            .unwrap()
            .with("active", &true)
            .unwrap();
        assert_eq!(scope.aad_bytes(), b"\0tenant=7\0active=true".to_vec());
        assert_eq!(
            scope.field_aad(b"ns:f".to_vec()),
            b"ns:f\0tenant=7\0active=true"
        );
        assert_eq!(scope.get("tenant"), Some(&serde_json::json!(7)));
        assert_eq!(scope.columns(), vec!["tenant", "active"]);
        assert_eq!(scope.len(), 2);
    }

    #[test]
    fn empty_scope_keeps_field_aad_unchanged() {
        let scope = RowScope::new();
        assert!(scope.is_empty());
        assert!(scope.aad_bytes().is_empty());
        assert_eq!(scope.field_aad(b"users:ssn".to_vec()), b"users:ssn");
    }

    #[test]
    fn from_json_row_rejects_missing_null_and_non_scalar() {
        let row = serde_json::json!({ "a": null, "b": [1], "c": {"x": 1} });
        for col in ["missing", "a", "b", "c"] {
            let err = RowScope::from_json_row(&row, &[col]).unwrap_err();
            assert!(matches!(err, EncryptionError::Scope(_)), "{col}: {err}");
        }
        let err = RowScope::from_json_row(&serde_json::json!([1]), &["a"]).unwrap_err();
        assert!(matches!(err, EncryptionError::Scope(_)));
    }

    #[test]
    fn null_option_is_rejected_on_insert() {
        let none: Option<i32> = None;
        assert!(RowScope::new().with("org_id", &none).is_err());
        assert!(RowScope::new().with("org_id", &Some(3)).is_ok());
    }

    #[test]
    fn sea_value_bytes_are_rejected_without_utf8_conversion() {
        let bytes = sea_orm::Value::Bytes(Some(vec![0xff]));
        assert!(RowScope::new().insert_sea_value("org_id", &bytes).is_err());
    }
}
