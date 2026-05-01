//! Model Field Encryption
//!
//! This module provides Rails-style `ActiveRecord` encryption for Loco, using
//! AEAD (Authenticated Encryption with Associated Data) encryption for model fields
//! with AES-256-GCM.
//!
//! # Features
//!
//! - **Automatic encryption on save**: Fields are automatically encrypted using
//!   `ActiveModelBehavior::before_save`
//! - **Explicit decryption on read**: Manual decryption call required (Rust idiom)
//! - **Rails-compatible format**: Uses the Rails `ActiveRecord` Encryption JSON format
//! - **AEAD security**: Uses AES-256-GCM for authenticated encryption
//! - **Flexible key management**: Trait-based key provider system
//! - **Key rotation support**: Configure previous keys for seamless rotation
//! - **Non-deterministic encryption**: Same plaintext produces different ciphertext
//!
//! # Differences from Rails `ActiveRecord` Encryption
//!
//! - **Encryption**: Automatic (same as Rails) - happens in `before_save` hook
//! - **Decryption**: **Explicit** (unlike Rails) - requires calling `decrypt_fields()`
//!   - Rails: `user.ssn` automatically decrypts
//!   - Loco: `user.ssn` returns encrypted JSON; must call `user.decrypt_fields()` first
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
//!     "v": 1,
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

// Re-export main types for convenience
pub use cipher::{
    decrypt, encrypt, encrypt_deterministic, parse_hex_key, KEY_SIZE, NONCE_SIZE, TAG_SIZE,
};
pub use config::{EncryptionConfig, KeyDerivationConfig};
pub use encryptable::{
    decrypt_field, encrypt_field, encrypt_query_value, Encryptable, ModelDecryption,
};
pub use errors::{EncryptionError, EncryptionResult};
pub use format::{
    debug, estimate_encrypted_size, is_encrypted_format, EncryptedHeaders, EncryptedValue,
    EncryptionMetadata,
};
pub use key_provider::{ConfigKeyProvider, KeyProvider, SecureKey, StaticKeyProvider};
pub use registry::SharedKeyProvider;

/// Convenience macro to implement [`Encryptable`](encryptable::Encryptable)
/// for an `ActiveModel`.
///
/// Each field is either a bare ident (non-deterministic, random IV) or
/// `name(deterministic)` to opt the field into deterministic encryption so
/// it can be used in equality queries.
///
/// # Example
///
/// ```rust,ignore
/// use loco_rs::impl_encryptable_fields;
///
/// // SSN is non-deterministic; email is deterministic so we can do
/// // `WHERE email = encrypt_query_value::<users::Entity>("email", &input, &ctx)?`.
/// impl_encryptable_fields!(users::ActiveModel, [ssn, email(deterministic)]);
/// ```
///
/// The generated impl produces `encrypted_fields()` containing every name,
/// and `deterministic_fields()` containing only those marked
/// `(deterministic)`. Unknown modifiers are rejected at compile time.
#[macro_export]
macro_rules! impl_encryptable_fields {
    ($model:ty, [$($field:ident $(($modifier:ident))?),* $(,)?]) => {
        impl $crate::encryption::Encryptable for $model {
            fn encrypted_fields() -> Vec<String> {
                vec![$(stringify!($field).to_string()),*]
            }

            fn deterministic_fields() -> Vec<String> {
                let mut out: Vec<String> = Vec::new();
                $(
                    $crate::__impl_encryptable_det_push!(
                        out, $field $(, $modifier)?
                    );
                )*
                out
            }

            fn get_set_string_value(&self, field_name: &str) -> Option<String> {
                match field_name {
                    $(
                        stringify!($field) => {
                            match &self.$field {
                                sea_orm::ActiveValue::Set(v) => Some(v.clone()),
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
                            self.$field = sea_orm::ActiveValue::Set(value);
                        }
                    )*
                    _ => {}
                }
                self
            }
        }
    };
}

/// Internal helper for [`impl_encryptable_fields!`] — pushes deterministic
/// field names into the accumulator and rejects unknown modifiers.
#[macro_export]
#[doc(hidden)]
macro_rules! __impl_encryptable_det_push {
    ($out:ident, $field:ident, deterministic) => {
        $out.push(stringify!($field).to_string());
    };
    ($out:ident, $field:ident, $other:ident) => {
        compile_error!(concat!(
            "unknown encryption modifier `",
            stringify!($other),
            "` on field `",
            stringify!($field),
            "` (expected `deterministic`)"
        ));
    };
    ($out:ident, $field:ident) => {
        let _ = &$out; // bare field — non-deterministic, nothing to push
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

    /// Direct unit test of the macro's deterministic-marker helper. The full
    /// `impl_encryptable_fields!` macro requires `ActiveModelTrait` to be
    /// implemented for the target type, which is heavyweight to mock here;
    /// the SeaORM round-trip is covered in the Phase 4 integration tests.
    #[test]
    fn impl_encryptable_det_push_helper_collects_marked_fields() {
        let mut out: Vec<String> = Vec::new();
        crate::__impl_encryptable_det_push!(out, ssn);
        crate::__impl_encryptable_det_push!(out, email, deterministic);
        crate::__impl_encryptable_det_push!(out, phone);
        crate::__impl_encryptable_det_push!(out, recovery_email, deterministic);
        assert_eq!(out, vec!["email".to_string(), "recovery_email".to_string()]);
    }
}
