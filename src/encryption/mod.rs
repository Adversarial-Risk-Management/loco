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
//! 1. Add configuration to your `config/*.yaml`:
//!
//! ```yaml
//! encryption:
//!   primary_key: {{ get_env(name="LOCO_ENCRYPTION_PRIMARY_KEY") }}
//! ```
//!
//! 2. Generate a key with: `openssl rand -hex 32`
//!
//! 3. Implement `Encryptable` on your `ActiveModel`:
//!
//! ```rust,ignore
//! use loco_rs::encryption::Encryptable;
//!
//! impl Encryptable for users::ActiveModel {
//!     fn encrypted_fields() -> Vec<String> {
//!         vec!["ssn".into(), "credit_card".into()]
//!     }
//! }
//! ```
//!
//! 4. Add helper methods on your Model for encrypted save/find:
//!
//! ```rust,ignore
//! impl users::Model {
//!     pub async fn save_encrypted(
//!         active_model: users::ActiveModel,
//!         db: &DatabaseConnection,
//!         ctx: &AppContext,
//!     ) -> Result<Self> {
//!         let provider = ConfigKeyProvider::new(
//!             ctx.config.encryption.clone()
//!                 .ok_or_else(|| Error::string("encryption not configured"))?
//!         )?;
//!         let encrypted = active_model.encrypt_fields(&provider)?;
//!         Ok(encrypted.insert(db).await?)
//!     }
//!
//!     pub async fn find_decrypt(
//!         db: &DatabaseConnection,
//!         id: i32,
//!         ctx: &AppContext,
//!     ) -> Result<Option<Self>> {
//!         let provider = ConfigKeyProvider::new(
//!             ctx.config.encryption.clone()
//!                 .ok_or_else(|| Error::string("encryption not configured"))?
//!         )?;
//!         if let Some(mut model) = users::Entity::find_by_id(id).one(db).await? {
//!             model.decrypt_fields::<users::Entity>(&provider)?;
//!             Ok(Some(model))
//!         } else {
//!             Ok(None)
//!         }
//!     }
//! }
//! ```
//!
//! 5. Use in your controllers:
//!
//! ```rust,ignore
//! // Creating with encryption
//! let user = users::Model::save_encrypted(active_model, &ctx.db, &ctx).await?;
//!
//! // Finding with decryption
//! let user = users::Model::find_decrypt(&ctx.db, 1, &ctx).await?
//!     .ok_or_else(|| Error::NotFound)?;
//! println!("{}", user.ssn); // Decrypted!
//! ```
//!
//! **Note**: `SeaORM`'s `ActiveModelBehavior::before_save` hook does not have access
//! to the `AppContext`, so encryption must be done explicitly before calling save.
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
//!     "kid": "optional-key-id"
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

// Re-export main types for convenience
pub use cipher::{decrypt, encrypt, parse_hex_key, KEY_SIZE, NONCE_SIZE, TAG_SIZE};
pub use config::{EncryptionConfig, KeyDerivationConfig};
pub use encryptable::{decrypt_field, encrypt_field, Encryptable, ModelDecryption};
pub use errors::{EncryptionError, EncryptionResult};
pub use format::{
    debug, estimate_encrypted_size, is_encrypted_format, EncryptedHeaders, EncryptedValue,
    EncryptionMetadata,
};
pub use key_provider::{ConfigKeyProvider, KeyProvider, SecureKey, StaticKeyProvider};

/// Convenience macro to implement `Encryptable` for an `ActiveModel`
///
/// This macro reduces boilerplate by generating the `get_set_string_value`
/// and `set_string_value` implementations automatically.
///
/// # Example
///
/// ```rust,ignore
/// use loco_rs::impl_encryptable_fields;
///
/// // Implements Encryptable for users::ActiveModel with ssn and credit_card as encrypted fields
/// impl_encryptable_fields!(users::ActiveModel, [ssn, credit_card]);
///
/// // Is equivalent to:
/// impl Encryptable for users::ActiveModel {
///     fn encrypted_fields() -> Vec<String> {
///         vec!["ssn".to_string(), "credit_card".to_string()]
///     }
///
///     fn get_set_string_value(&self, field_name: &str) -> Option<String> {
///         match field_name {
///             "ssn" => match &self.ssn {
///                 sea_orm::ActiveValue::Set(v) => Some(v.clone()),
///                 _ => None,
///             },
///             "credit_card" => match &self.credit_card {
///                 sea_orm::ActiveValue::Set(v) => Some(v.clone()),
///                 _ => None,
///             },
///             _ => None,
///         }
///     }
///
///     fn set_string_value(mut self, field_name: &str, value: String) -> Self {
///         match field_name {
///             "ssn" => self.ssn = sea_orm::ActiveValue::Set(value),
///             "credit_card" => self.credit_card = sea_orm::ActiveValue::Set(value),
///             _ => {}
///         }
///         self
///     }
/// }
/// ```
#[macro_export]
macro_rules! impl_encryptable_fields {
    ($model:ty, [$($field:ident),* $(,)?]) => {
        impl $crate::encryption::Encryptable for $model {
            fn encrypted_fields() -> Vec<String> {
                vec![$(stringify!($field).to_string()),*]
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
            key_derivation: None,
        };
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn test_validate_config_invalid_primary_key() {
        let config = config::EncryptionConfig {
            primary_key: "too_short".to_string(),
            previous_keys: vec![],
            key_derivation: None,
        };
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_validate_config_key_derivation_missing_salt() {
        let config = config::EncryptionConfig {
            primary_key: valid_hex_key(),
            previous_keys: vec![],
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
            key_derivation: Some(config::KeyDerivationConfig {
                enabled: true,
                salt: Some(valid_hex_key()),
            }),
        };
        assert!(validate_config(&config).is_ok());
    }
}
