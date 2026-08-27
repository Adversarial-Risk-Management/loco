//! Model Field Encryption
//!
//! This module provides Rails-style `ActiveRecord` encryption for Loco, using
//! AEAD (Authenticated Encryption with Associated Data) encryption for model fields
//! with AES-256-GCM.
//!
//! # Features
//!
//! - **Explicit encryption on save**: call `encrypt_fields_ctx` on the
//!   `ActiveModel` before `insert`/`update`
//! - **Explicit decryption on read**: Manual decryption call required (Rust idiom)
//! - **Rails-style envelope**: Uses the same JSON envelope *shape* as Rails
//!   `ActiveRecord` Encryption (`{"p":…,"h":{"iv":…,"at":…}}`). See the
//!   compatibility note below — the shape matches but values are not
//!   wire-compatible across the two stacks.
//! - **AEAD security**: Uses AES-256-GCM for authenticated encryption, with the
//!   envelope headers folded into the authenticated data (envelope `v >= 2`)
//! - **Flexible key management**: Trait-based key provider system
//! - **Key rotation support**: Configure previous keys for seamless rotation
//!   (non-deterministic fields only; see the deterministic-key caveat in
//!   [`config::EncryptionConfig`])
//! - **Non-deterministic encryption**: Same plaintext produces different ciphertext
//!
//! # Differences from Rails `ActiveRecord` Encryption
//!
//! - **Decryption**: **Explicit** (unlike Rails) - requires calling `decrypt_fields()`
//!   - Rails: `user.ssn` automatically decrypts
//!   - Loco: `user.ssn` returns encrypted JSON; must call `user.decrypt_fields()` first
//! - **Wire compatibility**: the envelope *shape* matches Rails, but values do
//!   not interoperate. The deterministic-IV PRF length-prefixes its input, the
//!   `i` key-id uses semantic labels (`"primary"`) rather than Rails' key
//!   fingerprint, and per-field keys are derived with HKDF-SHA256 rather than
//!   Rails' PBKDF2. Do not plan a cross-stack migration on the shared shape.
//! - **Compression**: on by default for non-deterministic fields, as in Rails.
//!   Opt a field out with the `(no_compress)` modifier (see
//!   [`Encryptable::uncompressed_fields`](encryptable::Encryptable::uncompressed_fields))
//!   when it mixes attacker-influenced and secret bytes, to avoid
//!   CRIME/BREACH-style length leakage.
//! - **Deterministic key rotation**: unsupported, as in Rails (see
//!   [`config::EncryptionConfig::deterministic_key`]).
//!
//! # Quick Start
//!
//! 1. Add configuration to your `config/*.yaml` (generate a key with
//!    `openssl rand -hex 32`):
//!
//! ```yaml
//! encryption:
//!   primary_key: {{ get_env(name="LOCO_ENCRYPTION_PRIMARY_KEY") }}
//! ```
//!
//!    When present, the key provider is registered automatically during
//!    `boot::create_context`; no user code required.
//!
//! 2. Declare the encryptable fields on your `ActiveModel`. The
//!    [`impl_encryptable_fields!`](crate::impl_encryptable_fields) macro
//!    generates the required boilerplate:
//!
//! ```rust,ignore
//! use loco_rs::impl_encryptable_fields;
//!
//! impl_encryptable_fields!(users::ActiveModel, [ssn, credit_card]);
//! ```
//!
//! 3. Use the context-aware helpers in controllers:
//!
//! ```rust,ignore
//! use loco_rs::prelude::*;
//!
//! // Encrypt on save:
//! let active = users::ActiveModel { ssn: Set(ssn), ..Default::default() };
//! let user = active.encrypt_fields_ctx(&ctx)?.insert(&ctx.db).await?;
//!
//! // Decrypt on read:
//! if let Some(mut user) = users::Entity::find_by_id(id).one(&ctx.db).await? {
//!     user.decrypt_fields_ctx::<users::Entity>(&ctx)?;
//!     println!("{}", user.ssn); // Decrypted
//! }
//! ```
//!
//! **Note**: `SeaORM`'s `ActiveModelBehavior::before_save` hook has no access
//! to the `AppContext`, so encryption is invoked explicitly via
//! `encrypt_fields_ctx` before save rather than from the hook.
//!
//! # Encrypted Value Format
//!
//! Encrypted values are stored as JSON (Rails-compatible):
//!
//! ```json
//! {
//!   "p": "base64-encoded-ciphertext",
//!   "h": {
//!     "iv": "base64-encoded-iv",
//!     "at": "base64-encoded-auth-tag",
//!     "v": 2,
//!     "i": "optional-key-id"
//!   }
//! }
//! ```
//!
//! # Security Considerations
//!
//! - **Never commit keys to version control**
//! - Use Loco's config system with env var templating
//! - Generate keys with: `openssl rand -hex 32`
//! - Enable key derivation for field-specific keys
//! - Configure `previous_keys` for zero-downtime key rotation

pub mod cipher;
pub mod config;
pub mod encryptable;
pub mod errors;
pub mod format;
pub mod key_provider;
pub mod registry;
pub mod scope;

// Re-export main types for convenience
pub use cipher::{
    decrypt, encrypt, encrypt_deterministic, parse_hex_key, KEY_SIZE, NONCE_SIZE, TAG_SIZE,
};
pub use config::{EncryptionConfig, KeyDerivationConfig};
pub use encryptable::{
    decrypt_field, decrypt_field_with_aad, encrypt_field, encrypt_field_with_aad,
    encrypt_query_value, encrypt_query_value_scoped, encrypt_query_value_with, Encryptable,
    EncryptableValue, ModelDecryption,
};
pub use errors::{EncryptionError, EncryptionResult};
pub use format::{
    debug, estimate_encrypted_size, is_encrypted_format, EncryptedHeaders, EncryptedValue,
    EncryptionMetadata,
};
pub use key_provider::{ConfigKeyProvider, KeyProvider, SecureKey, StaticKeyProvider};
pub use registry::SharedKeyProvider;
pub use scope::RowScope;

/// Convenience macro to implement [`Encryptable`](encryptable::Encryptable)
/// for an `ActiveModel`.
///
/// Each field is one of:
/// - a bare ident — non-deterministic (random IV) and **compressed by
///   default** (subject to the size threshold);
/// - `name(deterministic)` — deterministic encryption so the field can be used
///   in equality queries (never compressed);
/// - `name(no_compress)` — non-deterministic but with compression disabled (see
///   the CRIME/BREACH note on
///   [`Encryptable::uncompressed_fields`](encryptable::Encryptable::uncompressed_fields)).
///
/// # Example
///
/// ```rust,ignore
/// use loco_rs::impl_encryptable_fields;
///
/// // ssn: compressed by default. email: deterministic (and not compressed) so
/// // `WHERE email = encrypt_query_value::<users::Entity>("email", &input, &ctx)?`
/// // works. bio: opted out of compression.
/// impl_encryptable_fields!(users::ActiveModel, [ssn, email(deterministic), bio(no_compress)]);
/// ```
///
/// The generated impl produces `encrypted_fields()` containing every name,
/// `deterministic_fields()` containing only those marked `(deterministic)`,
/// and `uncompressed_fields()` containing only those marked `(no_compress)`.
/// Unknown modifiers are rejected at compile time.
///
/// # Binding ciphertexts to a `(table, column)` location (AAD)
///
/// Pass an `aad_namespace = "<label>"` argument to bind every ciphertext to
/// `<label>:<field_name>` via Additional Authenticated Data. With this
/// enabled, a ciphertext written for one field will not decrypt as another:
///
/// ```rust,ignore
/// impl_encryptable_fields!(
///     users::ActiveModel,
///     [ssn, email(deterministic)],
///     aad_namespace = "users",
/// );
/// ```
///
/// Once enabled, all reads and writes must agree on the namespace; turning it
/// on for a field that already has data invalidates existing ciphertexts the
/// same way a key rotation does.
///
/// # Binding ciphertexts to row values (`aad_fields`)
///
/// Pass `aad_fields = [col, ...]` to also authenticate the values of sibling
/// columns — typically a tenant id — so a ciphertext copied onto another
/// tenant's row fails to decrypt:
///
/// ```rust,ignore
/// impl_encryptable_fields!(
///     integration_credentials::ActiveModel,
///     [credentials(no_compress)],
///     aad_namespace = "integration_credential",
///     aad_fields = [org_id],
/// );
/// ```
///
/// The referenced columns must implement `serde::Serialize` and serialize to
/// a JSON scalar (a `Uuid` renders as its hyphenated lowercase string). On
/// save, a scope column that is `NotSet` while an encrypted field is `Set`
/// is an error; on read, a missing or null scope column is an error. The
/// scope is also what [`Encryptable::provider_for`](encryptable::Encryptable::provider_for)
/// receives to select a per-row key provider. Deterministic fields on a
/// scoped model must be queried with
/// [`encrypt_query_value_scoped`](encryptable::encrypt_query_value_scoped).
#[macro_export]
macro_rules! impl_encryptable_fields {
    ($model:ty, [$($field:ident $(($modifier:ident))?),* $(,)?]) => {
        $crate::__impl_encryptable_fields_inner!(
            $model,
            [$($field $(($modifier))?),*],
            aad_namespace = "",
            aad_fields = []
        );
    };
    (
        $model:ty,
        [$($field:ident $(($modifier:ident))?),* $(,)?],
        aad_namespace = $ns:literal $(,)?
    ) => {
        $crate::__impl_encryptable_fields_inner!(
            $model,
            [$($field $(($modifier))?),*],
            aad_namespace = $ns,
            aad_fields = []
        );
    };
    (
        $model:ty,
        [$($field:ident $(($modifier:ident))?),* $(,)?],
        aad_fields = [$($scope:ident),* $(,)?] $(,)?
    ) => {
        $crate::__impl_encryptable_fields_inner!(
            $model,
            [$($field $(($modifier))?),*],
            aad_namespace = "",
            aad_fields = [$($scope),*]
        );
    };
    (
        $model:ty,
        [$($field:ident $(($modifier:ident))?),* $(,)?],
        aad_namespace = $ns:literal,
        aad_fields = [$($scope:ident),* $(,)?] $(,)?
    ) => {
        $crate::__impl_encryptable_fields_inner!(
            $model,
            [$($field $(($modifier))?),*],
            aad_namespace = $ns,
            aad_fields = [$($scope),*]
        );
    };
}

/// Shared expansion for [`impl_encryptable_fields!`] — public-but-hidden so
/// the public macro's arms can all delegate here.
#[macro_export]
#[doc(hidden)]
macro_rules! __impl_encryptable_fields_inner {
    (
        $model:ty,
        [$($field:ident $(($modifier:ident))?),* $(,)?],
        aad_namespace = $ns:literal,
        aad_fields = [$($scope:ident),*]
    ) => {
        impl $crate::encryption::Encryptable for $model {
            fn encrypted_fields() -> Vec<String> {
                vec![$(stringify!($field).to_string()),*]
            }

            fn deterministic_fields() -> Vec<String> {
                let mut det: Vec<String> = Vec::new();
                let mut uncomp: Vec<String> = Vec::new();
                $(
                    $crate::__impl_encryptable_field_meta!(
                        det, uncomp, $field $(, $modifier)?
                    );
                )*
                let _ = uncomp;
                det
            }

            fn uncompressed_fields() -> Vec<String> {
                let mut det: Vec<String> = Vec::new();
                let mut uncomp: Vec<String> = Vec::new();
                $(
                    $crate::__impl_encryptable_field_meta!(
                        det, uncomp, $field $(, $modifier)?
                    );
                )*
                let _ = det;
                uncomp
            }

            fn field_aad(field_name: &str) -> Vec<u8> {
                if $ns.is_empty() {
                    Vec::new()
                } else {
                    format!("{}:{}", $ns, field_name).into_bytes()
                }
            }

            fn scope_columns() -> Vec<String> {
                vec![$(stringify!($scope).to_string()),*]
            }

            fn row_scope(
                &self,
            ) -> $crate::encryption::EncryptionResult<$crate::encryption::RowScope> {
                #[allow(unused_mut)]
                let mut scope = $crate::encryption::RowScope::new();
                $(
                    match &self.$scope {
                        sea_orm::ActiveValue::Set(v) | sea_orm::ActiveValue::Unchanged(v) => {
                            scope.insert(stringify!($scope), v)?;
                        }
                        sea_orm::ActiveValue::NotSet => {
                            return Err($crate::encryption::EncryptionError::Scope(format!(
                                "scope column '{}' is NotSet while an encrypted field is Set",
                                stringify!($scope)
                            )));
                        }
                    }
                )*
                Ok(scope)
            }

            fn row_scope_from_json(
                row: &$crate::encryption::scope::Value,
            ) -> $crate::encryption::EncryptionResult<$crate::encryption::RowScope> {
                $crate::encryption::RowScope::from_json_row(row, &[$(stringify!($scope)),*])
            }

            fn get_set_string_value(&self, field_name: &str) -> Option<String> {
                match field_name {
                    $(
                        stringify!($field) => {
                            match &self.$field {
                                sea_orm::ActiveValue::Set(v) => {
                                    $crate::encryption::EncryptableValue::plaintext(v)
                                        .map(str::to_string)
                                }
                                _ => None,
                            }
                        }
                    )*
                    _ => None,
                }
            }

            fn set_string_value(mut self, field_name: &str, value: String) -> Self {
                match field_name {
                    $(
                        stringify!($field) => {
                            self.$field = sea_orm::ActiveValue::Set(
                                $crate::encryption::EncryptableValue::from_string(value),
                            );
                        }
                    )*
                    _ => {}
                }
                self
            }
        }
    };
}

/// Internal helper for [`impl_encryptable_fields!`] — classifies a single
/// field's modifier into either the deterministic-list or the
/// compression-opt-out list accumulator, and rejects unknown modifiers at
/// compile time.
#[macro_export]
#[doc(hidden)]
macro_rules! __impl_encryptable_field_meta {
    ($det:ident, $uncomp:ident, $field:ident, deterministic) => {
        $det.push(stringify!($field).to_string());
        let _ = &$uncomp;
    };
    ($det:ident, $uncomp:ident, $field:ident, no_compress) => {
        $uncomp.push(stringify!($field).to_string());
        let _ = &$det;
    };
    ($det:ident, $uncomp:ident, $field:ident, $other:ident) => {
        compile_error!(concat!(
            "unknown encryption modifier `",
            stringify!($other),
            "` on field `",
            stringify!($field),
            "` (expected `deterministic` or `no_compress`)"
        ));
        let _ = (&$det, &$uncomp);
    };
    ($det:ident, $uncomp:ident, $field:ident) => {
        // bare field — non-deterministic and compressed by default
        let _ = (&$det, &$uncomp);
    };
}

/// Validate encryption configuration at startup
///
/// Call this during application boot to fail fast on misconfiguration.
/// Returns Ok(()) if encryption is not configured (optional feature).
///
/// # Errors
/// Returns an error if the configuration is invalid:
/// - Primary key is present but invalid format/length
/// - Key derivation is enabled but salt is missing or invalid
///
/// # Example
/// ```rust,ignore
/// // In your app's boot sequence
/// if let Some(config) = &app_config.encryption {
///     loco_rs::encryption::validate_config(config)?;
/// }
/// ```
pub fn validate_config(config: &config::EncryptionConfig) -> EncryptionResult<()> {
    // Validate primary key format and length
    if config.has_primary_key() {
        let _ = cipher::parse_hex_key(&config.primary_key)
            .map_err(|e| EncryptionError::InvalidKey(format!("primary_key: {e}")))?;
    }

    // Validate key derivation salt if enabled
    if let Some(ref kd) = config.key_derivation
        && kd.enabled
    {
        let salt = kd.salt.as_ref().ok_or_else(|| {
            EncryptionError::NotConfigured(
                "key_derivation.salt is required when derivation is enabled".to_string(),
            )
        })?;
        let _ = cipher::parse_hex_key(salt)
            .map_err(|e| EncryptionError::InvalidKey(format!("key_derivation.salt: {e}")))?;
    }

    // Validate deterministic key when present
    if let Some(ref det) = config.deterministic_key
        && !det.trim().is_empty()
    {
        cipher::parse_hex_key(det)
            .map_err(|e| EncryptionError::InvalidKey(format!("deterministic_key: {e}")))?;
        if det.trim() == config.primary_key.trim() {
            return Err(EncryptionError::InvalidKey(
                "deterministic_key must differ from primary_key".into(),
            ));
        }
    }

    // Warn about empty previous_keys entries (don't fail, just log)
    for (i, key) in config.previous_keys.iter().enumerate() {
        if key.trim().is_empty() {
            tracing::warn!(
                "encryption.previous_keys[{}] is empty and will be skipped",
                i
            );
        } else if cipher::parse_hex_key(key).is_err() {
            tracing::warn!(
                "encryption.previous_keys[{}] has invalid format and will be skipped",
                i
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_hex_key() -> String {
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".to_string()
    }

    #[test]
    fn test_validate_config_valid() {
        let config = config::EncryptionConfig {
            primary_key: valid_hex_key(),
            previous_keys: vec![],
            deterministic_key: None,
            key_derivation: None,
        };
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn test_validate_config_invalid_primary_key() {
        let config = config::EncryptionConfig {
            primary_key: "too_short".to_string(),
            previous_keys: vec![],
            deterministic_key: None,
            key_derivation: None,
        };
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_validate_config_key_derivation_missing_salt() {
        let config = config::EncryptionConfig {
            primary_key: valid_hex_key(),
            previous_keys: vec![],
            deterministic_key: None,
            key_derivation: Some(config::KeyDerivationConfig {
                enabled: true,
                salt: None,
            }),
        };
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_validate_config_key_derivation_invalid_salt() {
        let config = config::EncryptionConfig {
            primary_key: valid_hex_key(),
            previous_keys: vec![],
            deterministic_key: None,
            key_derivation: Some(config::KeyDerivationConfig {
                enabled: true,
                salt: Some("invalid".to_string()),
            }),
        };
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_validate_config_key_derivation_valid() {
        let config = config::EncryptionConfig {
            primary_key: valid_hex_key(),
            previous_keys: vec![],
            deterministic_key: None,
            key_derivation: Some(config::KeyDerivationConfig {
                enabled: true,
                salt: Some(valid_hex_key()),
            }),
        };
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn test_validate_config_deterministic_key_valid() {
        let other_hex = "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100";
        let config = config::EncryptionConfig {
            primary_key: valid_hex_key(),
            previous_keys: vec![],
            deterministic_key: Some(other_hex.to_string()),
            key_derivation: None,
        };
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn test_validate_config_deterministic_key_equal_to_primary() {
        let config = config::EncryptionConfig {
            primary_key: valid_hex_key(),
            previous_keys: vec![],
            deterministic_key: Some(valid_hex_key()),
            key_derivation: None,
        };
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_validate_config_deterministic_key_invalid_hex() {
        let config = config::EncryptionConfig {
            primary_key: valid_hex_key(),
            previous_keys: vec![],
            deterministic_key: Some("not-a-valid-hex-key".to_string()),
            key_derivation: None,
        };
        assert!(validate_config(&config).is_err());
    }

    /// Direct unit test of the macro's modifier classifier. The full
    /// `impl_encryptable_fields!` macro requires `ActiveModelTrait` to be
    /// implemented for the target type, which is heavyweight to mock here;
    /// the SeaORM round-trip is covered in the Phase 4 integration tests.
    #[test]
    fn impl_encryptable_field_meta_helper_classifies_modifiers() {
        let mut det: Vec<String> = Vec::new();
        let mut uncomp: Vec<String> = Vec::new();
        crate::__impl_encryptable_field_meta!(det, uncomp, ssn);
        crate::__impl_encryptable_field_meta!(det, uncomp, email, deterministic);
        crate::__impl_encryptable_field_meta!(det, uncomp, bio, no_compress);
        crate::__impl_encryptable_field_meta!(det, uncomp, phone);
        crate::__impl_encryptable_field_meta!(det, uncomp, recovery_email, deterministic);
        crate::__impl_encryptable_field_meta!(det, uncomp, journal, no_compress);

        // Deterministic and opt-out lists hold only the explicitly marked
        // fields; bare fields (ssn, phone) are compressed by default and
        // appear in neither.
        assert_eq!(det, vec!["email".to_string(), "recovery_email".to_string()]);
        assert_eq!(uncomp, vec!["bio".to_string(), "journal".to_string()]);
    }
}
