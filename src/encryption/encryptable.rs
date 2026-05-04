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
    cipher::{decrypt, encrypt, encrypt_deterministic},
    errors::{EncryptionError, EncryptionResult},
    format::{is_encrypted_format, EncryptedValue},
    key_provider::{KeyProvider, SecureKey},
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

    /// Returns the list of field names that should be encrypted
    /// **deterministically**.
    ///
    /// Deterministic fields produce the same ciphertext for identical
    /// plaintexts under a given key, enabling equality queries via
    /// [`encrypt_query_value`](crate::encryption::encrypt_query_value). Every
    /// name returned here must also appear in
    /// [`encrypted_fields`](Self::encrypted_fields). The default is an empty
    /// list — all fields are non-deterministic.
    #[must_use]
    fn deterministic_fields() -> Vec<String> {
        Vec::new()
    }

    /// Returns the Additional Authenticated Data to bind to ciphertexts of
    /// the named field.
    ///
    /// AES-GCM authenticates this byte string alongside the ciphertext: the
    /// same AAD must be supplied at decryption time, otherwise authentication
    /// fails. Override this to defeat ciphertext-relocation attacks where a
    /// row-level attacker copies a ciphertext from one column to another.
    ///
    /// A common choice is `format!("{table}:{field}").into_bytes()`. Once
    /// non-empty AAD is in use, all reads and writes of the field must
    /// agree, so changing the value invalidates existing ciphertexts.
    ///
    /// The default is empty (no AAD binding).
    #[must_use]
    fn field_aad(field_name: &str) -> Vec<u8> {
        let _ = field_name;
        Vec::new()
    }

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
        let det_fields = Self::deterministic_fields();

        for field_name in &fields {
            let Some(plaintext) = self.get_set_string_value(field_name) else {
                continue;
            };
            // Skip if already encrypted
            if is_encrypted_format(&plaintext) {
                continue;
            }

            let key_id = provider.get_key_id();
            let is_deterministic = det_fields.iter().any(|f| f == field_name);
            let aad = Self::field_aad(field_name);

            let encrypted = if is_deterministic {
                let det_master = provider.get_deterministic_key()?.ok_or_else(|| {
                    EncryptionError::NotConfigured(format!(
                        "field '{field_name}' is marked deterministic but no \
                         `deterministic_key` is configured"
                    ))
                })?;
                let field_key = provider.derive_field_key(&det_master, field_name)?;
                encrypt_deterministic(&plaintext, field_key.as_bytes(), key_id, &aad)?
            } else {
                let key = provider.get_field_key(field_name)?;
                encrypt(&plaintext, key.as_bytes(), key_id, &aad)?
            };

            self = self.set_string_value(field_name, encrypted);
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

        // Rotation: a decryption attempt iterates these masters in order.
        // Deterministic values only ever use the single deterministic key.
        let decryption_keys = provider.get_decryption_keys()?;
        let deterministic_masters: Vec<SecureKey> =
            provider.get_deterministic_key()?.into_iter().collect();

        for field_name in encrypted_fields {
            let Some(encrypted_json) = obj.get_mut(&field_name) else {
                continue;
            };
            let Some(encrypted_str) = encrypted_json.as_str() else {
                continue;
            };
            if !is_encrypted_format(encrypted_str) {
                continue;
            }

            // Inspect the envelope to decide which master-key list to try.
            let is_deterministic =
                EncryptedValue::from_json(encrypted_str).is_ok_and(|v| v.is_deterministic());

            let masters: &[SecureKey] = if is_deterministic {
                if deterministic_masters.is_empty() {
                    return Err(EncryptionError::NotConfigured(format!(
                        "field '{field_name}' was encrypted deterministically but no \
                         `deterministic_key` is configured"
                    )));
                }
                &deterministic_masters
            } else {
                // Fall through to the generic rotation path below.
                &[]
            };

            let mut decrypted = None;
            let mut last_error = None;

            let aad = <<E as EntityTrait>::ActiveModel as Encryptable>::field_aad(&field_name);

            if is_deterministic {
                for master in masters {
                    let field_key = match provider.derive_field_key(master, &field_name) {
                        Ok(k) => k,
                        Err(e) => {
                            last_error = Some(e);
                            continue;
                        }
                    };
                    match decrypt(encrypted_str, field_key.as_bytes(), &aad) {
                        Ok(plaintext) => {
                            decrypted = Some(plaintext);
                            break;
                        }
                        Err(e) => last_error = Some(e),
                    }
                }
            } else {
                for (master, key_id) in &decryption_keys {
                    let field_key = match provider.derive_field_key(master, &field_name) {
                        Ok(k) => k,
                        Err(e) => {
                            last_error = Some(e);
                            continue;
                        }
                    };
                    match decrypt(encrypted_str, field_key.as_bytes(), &aad) {
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
            }

            if let Some(plaintext) = decrypted {
                *encrypted_json = serde_json::Value::String(plaintext);
            } else {
                let tried = if is_deterministic {
                    deterministic_masters.len()
                } else {
                    decryption_keys.len()
                };
                return Err(EncryptionError::all_keys_failed(
                    tried,
                    last_error.map_or_else(|| "unknown error".to_string(), |e| e.to_string()),
                ));
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
    decrypt_field_with_aad(encrypted_value, field_name, provider, &[])
}

/// Decrypt a single field value with explicit AAD.
///
/// The same AAD bytes that were passed to encryption must be supplied here.
///
/// # Errors
/// Returns an error if decryption fails (including AAD mismatch).
pub fn decrypt_field_with_aad<P: KeyProvider + ?Sized>(
    encrypted_value: &str,
    field_name: &str,
    provider: &P,
    aad: &[u8],
) -> EncryptionResult<String> {
    if !is_encrypted_format(encrypted_value) {
        return Ok(encrypted_value.to_string());
    }

    let key = provider.get_field_key(field_name)?;
    decrypt(encrypted_value, key.as_bytes(), aad)
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
    encrypt_field_with_aad(plaintext, field_name, provider, &[])
}

/// Encrypt a single field value with explicit AAD bound to the ciphertext.
///
/// The exact AAD bytes must be supplied at decryption (see
/// [`decrypt_field_with_aad`]).
///
/// # Errors
/// Returns an error if encryption fails.
pub fn encrypt_field_with_aad<P: KeyProvider + ?Sized>(
    plaintext: &str,
    field_name: &str,
    provider: &P,
    aad: &[u8],
) -> EncryptionResult<String> {
    let key = provider.get_field_key(field_name)?;
    let key_id = provider.get_key_id();
    encrypt(plaintext, key.as_bytes(), key_id, aad)
}

/// Produce the deterministic ciphertext used for equality queries.
///
/// Call this to construct the value to match against a deterministically
/// encrypted column in a `WHERE` clause:
///
/// ```rust,ignore
/// use loco_rs::encryption::encrypt_query_value;
///
/// let ct = encrypt_query_value::<users::Entity>("email", "alice@example.com", &ctx)?;
/// users::Entity::find()
///     .filter(users::Column::Email.eq(ct))
///     .one(&ctx.db)
///     .await?;
/// ```
///
/// The requested `field_name` must be listed in
/// [`Encryptable::deterministic_fields`] for the entity's `ActiveModel`,
/// otherwise this returns an error (rather than silently producing a
/// non-deterministic ciphertext that cannot match any row).
///
/// # Errors
/// Returns an error when no provider is registered, the field is not
/// deterministic, no `deterministic_key` is configured, or encryption fails.
pub fn encrypt_query_value<E>(
    field_name: &str,
    plaintext: &str,
    ctx: &AppContext,
) -> EncryptionResult<String>
where
    E: EntityTrait,
    <E as EntityTrait>::ActiveModel: Encryptable,
{
    let det_fields = <<E as EntityTrait>::ActiveModel as Encryptable>::deterministic_fields();
    if !det_fields.iter().any(|f| f == field_name) {
        return Err(EncryptionError::NotConfigured(format!(
            "field '{field_name}' is not declared as deterministic — add it to \
             `deterministic_fields()` to enable equality queries"
        )));
    }

    let provider = registry::require(ctx)?;
    let det_master = provider.get_deterministic_key()?.ok_or_else(|| {
        EncryptionError::NotConfigured(
            "deterministic_key is required for query-value encryption".into(),
        )
    })?;
    let field_key = provider.derive_field_key(&det_master, field_name)?;
    let aad = <<E as EntityTrait>::ActiveModel as Encryptable>::field_aad(field_name);
    encrypt_deterministic(plaintext, field_key.as_bytes(), provider.get_key_id(), &aad)
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
    fn test_encrypt_field_with_aad_round_trip() {
        let provider = test_provider();
        let plaintext = "secret";
        let aad = b"users:ssn";

        let encrypted = encrypt_field_with_aad(plaintext, "ssn", &provider, aad).unwrap();
        assert!(is_encrypted_format(&encrypted));

        // Same AAD: decrypts.
        assert_eq!(
            decrypt_field_with_aad(&encrypted, "ssn", &provider, aad).unwrap(),
            plaintext
        );

        // Different AAD: authentication fails.
        assert!(
            decrypt_field_with_aad(&encrypted, "ssn", &provider, b"users:other").is_err(),
            "AAD mismatch must fail decryption"
        );
    }

    #[test]
    fn test_decrypt_field_passthrough_plaintext() {
        let provider = test_provider();
        let plaintext = "not encrypted";

        let result = decrypt_field(plaintext, "ssn", &provider).unwrap();
        assert_eq!(result, plaintext);
    }

    #[test]
    fn test_deterministic_equality_query_roundtrip() {
        // Two independent provider instances (simulating two server processes)
        // with the same config must produce identical ciphertext for the same
        // plaintext — that's what makes equality queries work.
        use crate::encryption::{
            cipher,
            config::{EncryptionConfig, KeyDerivationConfig},
            key_provider::ConfigKeyProvider,
        };

        let primary = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let det = "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100";
        let salt = "aabbccdd00112233445566778899aabbccddeeff00112233445566778899aabb";

        let cfg = EncryptionConfig {
            primary_key: primary.to_string(),
            previous_keys: vec![],
            deterministic_key: Some(det.to_string()),
            key_derivation: Some(KeyDerivationConfig {
                enabled: true,
                salt: Some(salt.to_string()),
            }),
        };
        let p1 = ConfigKeyProvider::new(cfg.clone()).unwrap();
        let p2 = ConfigKeyProvider::new(cfg).unwrap();

        let det_master_1 = p1.get_deterministic_key().unwrap().unwrap();
        let det_master_2 = p2.get_deterministic_key().unwrap().unwrap();

        let field_key_1 = p1.derive_field_key(&det_master_1, "email").unwrap();
        let field_key_2 = p2.derive_field_key(&det_master_2, "email").unwrap();

        let ct_a =
            cipher::encrypt_deterministic("alice@example.com", field_key_1.as_bytes(), None, b"")
                .unwrap();
        let ct_b =
            cipher::encrypt_deterministic("alice@example.com", field_key_2.as_bytes(), None, b"")
                .unwrap();
        assert_eq!(
            ct_a, ct_b,
            "cross-process deterministic ciphertext must match"
        );

        // Decrypts cleanly with the field key.
        let pt = cipher::decrypt(&ct_a, field_key_1.as_bytes(), b"").unwrap();
        assert_eq!(pt, "alice@example.com");

        // Different field name → different key → different ciphertext for the
        // same plaintext (HKDF per-field binding).
        let other_field_key = p1
            .derive_field_key(&det_master_1, "recovery_email")
            .unwrap();
        let ct_other = cipher::encrypt_deterministic(
            "alice@example.com",
            other_field_key.as_bytes(),
            None,
            b"",
        )
        .unwrap();
        assert_ne!(
            ct_a, ct_other,
            "same plaintext in different fields must not collide"
        );
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
            deterministic_key: None,
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
            deterministic_key: None,
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
            if let Ok(pt) =
                crate::encryption::cipher::decrypt(&ciphertext, field_key.as_bytes(), b"")
            {
                decrypted = Some(pt);
                break;
            }
        }

        assert_eq!(decrypted.as_deref(), Some("secret ssn"));
    }
}
