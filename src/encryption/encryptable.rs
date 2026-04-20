//! Encryptable trait for model field encryption
//!
//! This module provides the `Encryptable` trait for marking which fields should be
//! encrypted on an `ActiveModel`, and the `ModelDecryption` trait for decrypting
//! fields on a `Model`.
//!
//! # Convenience Macro
//!
//! Use the `impl_encryptable_fields!` macro to reduce boilerplate:
//!
//! ```rust,ignore
//! use loco_rs::impl_encryptable_fields;
//!
//! // Instead of manually implementing all methods:
//! impl_encryptable_fields!(users::ActiveModel, [ssn, credit_card]);
//! ```
//!
//! # Usage
//!
//! 1. Declare encryptable fields. The [`impl_encryptable_fields!`] macro
//!    generates the trait impl:
//!
//! ```rust,ignore
//! use loco_rs::impl_encryptable_fields;
//!
//! impl_encryptable_fields!(users::ActiveModel, [ssn, credit_card]);
//! ```
//!
//! 2. Encrypt on save and decrypt on read using the context-aware helpers:
//!
//! ```rust,ignore
//! use loco_rs::prelude::*;
//!
//! // Save with encryption
//! let active = users::ActiveModel { ssn: Set(ssn), ..Default::default() };
//! let user = active.encrypt_fields_ctx(&ctx)?.insert(&ctx.db).await?;
//!
//! // Find and decrypt
//! if let Some(mut user) = users::Entity::find_by_id(id).one(&ctx.db).await? {
//!     user.decrypt_fields_ctx::<users::Entity>(&ctx)?;
//!     println!("{}", user.ssn);
//! }
//! ```
//!
//! The provider is registered automatically at boot when `config.encryption`
//! is present. For custom providers (KMS, Vault, HSM), call
//! [`crate::encryption::registry::set_global`] during your `Hooks::boot`
//! implementation.
//!
//! **Note**: `SeaORM`'s `ActiveModelBehavior::before_save` hook has no access
//! to the `AppContext`, so encryption is invoked explicitly via
//! `encrypt_fields_ctx` rather than from the hook.

use sea_orm::{ActiveModelTrait, EntityTrait};
use serde::{de::DeserializeOwned, Serialize};

use super::{
    cipher::{decrypt, encrypt},
    errors::{EncryptionError, EncryptionResult},
    format::is_encrypted_format,
    key_provider::KeyProvider,
    registry,
};
use crate::app::AppContext;

/// Trait for marking a model as having encryptable fields
///
/// Implement this on your `ActiveModel` to specify which fields should be encrypted.
pub trait Encryptable: ActiveModelTrait {
    /// Returns the list of field names that should be encrypted
    ///
    /// These field names must match the column names in the database.
    fn encrypted_fields() -> Vec<String>;

    /// Get the current value of a string field if it is Set
    ///
    /// This method must be implemented for each field that can be encrypted.
    /// Returns `None` if the field is `NotSet` or `Unchanged`.
    fn get_set_string_value(&self, field_name: &str) -> Option<String>;

    /// Set a string field value
    ///
    /// This method must be implemented to set the encrypted value back.
    #[must_use]
    fn set_string_value(self, field_name: &str, value: String) -> Self
    where
        Self: Sized;

    /// Encrypt all specified fields using the provider resolved from an
    /// [`AppContext`](crate::app::AppContext).
    ///
    /// Looks up the provider registered at boot (see
    /// [`crate::encryption::registry`]). Prefer this over
    /// [`encrypt_fields`](Self::encrypt_fields) in controllers where `ctx` is
    /// already available.
    ///
    /// # Errors
    /// Returns an error if no provider is registered or encryption fails.
    fn encrypt_fields_ctx(self, ctx: &AppContext) -> EncryptionResult<Self>
    where
        Self: Sized,
    {
        let provider = registry::require(ctx)?;
        self.encrypt_fields(&*provider)
    }

    /// Encrypt all specified fields before saving
    ///
    /// This method should be called in `ActiveModelBehavior::before_save`.
    ///
    /// # Errors
    /// Returns an error if encryption fails
    fn encrypt_fields<P: KeyProvider + ?Sized>(mut self, provider: &P) -> EncryptionResult<Self>
    where
        Self: Sized,
    {
        let fields = Self::encrypted_fields();

        for field_name in &fields {
            // Get the current value for this field
            if let Some(plaintext) = self.get_set_string_value(field_name) {
                // Skip if already encrypted
                if is_encrypted_format(&plaintext) {
                    continue;
                }

                // Get field-specific key (may be derived)
                let key = provider.get_field_key(field_name)?;
                let key_id = provider.get_key_id();

                // Encrypt
                let encrypted = encrypt(&plaintext, key.as_bytes(), key_id)?;

                // Set the encrypted value
                self = self.set_string_value(field_name, encrypted);
            }
        }

        Ok(self)
    }
}

/// Extension trait for decrypting fields on a Model
///
/// This trait provides a generic `decrypt_fields` method that works with any
/// `Model` whose corresponding `ActiveModel` implements `Encryptable`.
pub trait ModelDecryption: Sized + Serialize + DeserializeOwned {
    /// Decrypt all encrypted fields in-place
    ///
    /// This method uses `serde_json` for runtime field access, converting the
    /// model to JSON, decrypting the relevant fields, and converting back.
    ///
    /// # Type Parameters
    /// * `E` - The Entity type for this model
    /// * `P` - The `KeyProvider` type
    ///
    /// # Errors
    /// Returns an error if decryption fails
    /// Decrypt all encrypted fields using the provider resolved from an
    /// [`AppContext`](crate::app::AppContext).
    ///
    /// # Errors
    /// Returns an error if no provider is registered or decryption fails.
    fn decrypt_fields_ctx<E>(&mut self, ctx: &AppContext) -> EncryptionResult<()>
    where
        E: EntityTrait,
        <E as EntityTrait>::Model: Serialize + DeserializeOwned,
        <E as EntityTrait>::ActiveModel: Encryptable,
    {
        let provider = registry::require(ctx)?;
        self.decrypt_fields::<E, _>(&*provider)
    }

    /// Decrypt all encrypted fields in-place using an explicit provider.
    ///
    /// # Errors
    /// Returns an error if the model cannot round-trip through JSON or if a
    /// field fails to decrypt under every configured key.
    fn decrypt_fields<E, P>(&mut self, provider: &P) -> EncryptionResult<()>
    where
        E: EntityTrait,
        <E as EntityTrait>::Model: Serialize + DeserializeOwned,
        <E as EntityTrait>::ActiveModel: Encryptable,
        P: KeyProvider + ?Sized,
    {
        let encrypted_fields = <<E as EntityTrait>::ActiveModel as Encryptable>::encrypted_fields();

        // Convert model to JSON for dynamic field access
        let mut value = serde_json::to_value(&self)?;
        let obj = value.as_object_mut().ok_or_else(|| {
            EncryptionError::DecryptionFailed("failed to convert model to JSON object".into())
        })?;

        // Get all decryption keys (for key rotation support)
        let decryption_keys = provider.get_decryption_keys()?;

        // Decrypt each encrypted field
        for field_name in encrypted_fields {
            let Some(encrypted_json) = obj.get_mut(&field_name) else {
                continue;
            };
            let Some(encrypted_str) = encrypted_json.as_str() else {
                continue;
            };
            // Skip if not encrypted
            if !is_encrypted_format(encrypted_str) {
                continue;
            }

            // Try decrypting with each master key until one succeeds.
            // For each master, derive the field-specific key *from that
            // master* — otherwise records encrypted under a previous
            // master + key-derivation would never decrypt.
            let mut decrypted = None;
            let mut last_error = None;

            for (master, key_id) in &decryption_keys {
                let field_key = match provider.derive_field_key(master, &field_name) {
                    Ok(k) => k,
                    Err(e) => {
                        last_error = Some(e);
                        continue;
                    }
                };

                match decrypt(encrypted_str, field_key.as_bytes()) {
                    Ok(plaintext) => {
                        decrypted = Some(plaintext);
                        break;
                    }
                    Err(e) => {
                        tracing::debug!(
                            field = %field_name,
                            key_id = ?key_id,
                            error = %e,
                            "decryption attempt failed, trying next key"
                        );
                        last_error = Some(e);
                    }
                }
            }

            match decrypted {
                Some(plaintext) => {
                    *encrypted_json = serde_json::Value::String(plaintext);
                }
                None => {
                    return Err(EncryptionError::all_keys_failed(
                        decryption_keys.len(),
                        last_error.map_or_else(|| "unknown error".to_string(), |e| e.to_string()),
                    ));
                }
            }
        }

        // Convert back to Model
        *self = serde_json::from_value(value)?;
        Ok(())
    }
}

// Blanket implementation for all types that implement Serialize + DeserializeOwned
impl<M> ModelDecryption for M where M: Serialize + DeserializeOwned {}

/// Helper function to decrypt a single field value
///
/// Useful when you need to decrypt a field without going through the full
/// `ModelDecryption` trait.
///
/// # Errors
/// Returns an error if decryption fails
pub fn decrypt_field<P: KeyProvider + ?Sized>(
    encrypted_value: &str,
    field_name: &str,
    provider: &P,
) -> EncryptionResult<String> {
    if !is_encrypted_format(encrypted_value) {
        return Ok(encrypted_value.to_string());
    }

    let key = provider.get_field_key(field_name)?;
    decrypt(encrypted_value, key.as_bytes())
}

/// Helper function to encrypt a single field value
///
/// Useful when you need to encrypt a field without going through the full
/// `Encryptable` trait.
///
/// # Errors
/// Returns an error if encryption fails
pub fn encrypt_field<P: KeyProvider + ?Sized>(
    plaintext: &str,
    field_name: &str,
    provider: &P,
) -> EncryptionResult<String> {
    let key = provider.get_field_key(field_name)?;
    let key_id = provider.get_key_id();
    encrypt(plaintext, key.as_bytes(), key_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::key_provider::StaticKeyProvider;

    fn test_provider() -> StaticKeyProvider {
        StaticKeyProvider::from_hex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            Some("test".to_string()),
        )
        .unwrap()
    }

    #[test]
    fn test_encrypt_decrypt_field_helpers() {
        let provider = test_provider();
        let plaintext = "secret value";
        let field_name = "ssn";

        let encrypted = encrypt_field(plaintext, field_name, &provider).unwrap();
        assert!(is_encrypted_format(&encrypted));

        let decrypted = decrypt_field(&encrypted, field_name, &provider).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_field_passthrough_plaintext() {
        let provider = test_provider();
        let plaintext = "not encrypted";

        let result = decrypt_field(plaintext, "ssn", &provider).unwrap();
        assert_eq!(result, plaintext);
    }

    #[test]
    fn test_rotation_with_key_derivation_end_to_end() {
        // Regression: before the fix, decryption under a rotated primary with
        // key derivation enabled would always derive the field key from the
        // new primary, making ciphertexts produced under the old primary
        // undecryptable — even when the old master was listed as a previous
        // key. The fix derives per-master inside the decryption loop.

        use crate::encryption::{
            config::{EncryptionConfig, KeyDerivationConfig},
            key_provider::ConfigKeyProvider,
        };

        let old_master =
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".to_string();
        let new_master =
            "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100".to_string();
        let salt = "aabbccdd00112233445566778899aabbccddeeff00112233445566778899aabb".to_string();

        // Encrypt under the OLD config (old master is primary).
        let old_config = EncryptionConfig {
            primary_key: old_master.clone(),
            previous_keys: vec![],
            key_derivation: Some(KeyDerivationConfig {
                enabled: true,
                salt: Some(salt.clone()),
            }),
        };
        let old_provider = ConfigKeyProvider::new(old_config).unwrap();
        let ciphertext = encrypt_field("secret ssn", "ssn", &old_provider).unwrap();
        assert!(is_encrypted_format(&ciphertext));

        // Rotate: the OLD master becomes a previous key under a new primary.
        let new_config = EncryptionConfig {
            primary_key: new_master,
            previous_keys: vec![old_master],
            key_derivation: Some(KeyDerivationConfig {
                enabled: true,
                salt: Some(salt),
            }),
        };
        let new_provider = ConfigKeyProvider::new(new_config).unwrap();

        // Simulate the decrypt_fields loop: iterate masters, derive per
        // master, try to decrypt. With the bug, this would only ever derive
        // from the new primary and always fail.
        let masters = new_provider.get_decryption_keys().unwrap();
        assert_eq!(masters.len(), 2);

        let mut decrypted = None;
        for (master, _kid) in &masters {
            let field_key = new_provider.derive_field_key(master, "ssn").unwrap();
            if let Ok(pt) = crate::encryption::cipher::decrypt(&ciphertext, field_key.as_bytes()) {
                decrypted = Some(pt);
                break;
            }
        }

        assert_eq!(decrypted.as_deref(), Some("secret ssn"));
    }
}
