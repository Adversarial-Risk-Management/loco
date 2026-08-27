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
    cipher::{decrypt, encrypt, encrypt_compressed, encrypt_deterministic},
    errors::{EncryptionError, EncryptionResult},
    format::{is_encrypted_format, EncryptedValue, CURRENT_ENVELOPE_VERSION},
    key_provider::{KeyProvider, SecureKey},
    registry,
    scope::RowScope,
};
use crate::app::AppContext;

/// Column value types that can carry an encryption envelope.
///
/// [`impl_encryptable_fields!`](crate::impl_encryptable_fields) routes every
/// field read/write through this trait, so the macro works for both `String`
/// (a `NOT NULL` column) and `Option<String>` (a nullable column — what
/// `cargo loco generate model x:string:encrypted` produces by default). A
/// `None` in an `Option<String>` field means SQL `NULL`: there is no
/// plaintext, so nothing is encrypted and the value is stored as `NULL`.
pub trait EncryptableValue: Sized {
    /// The plaintext to encrypt, or `None` when the column value is NULL.
    fn plaintext(&self) -> Option<&str>;

    /// Rebuild the column value from an encrypted (or decrypted) string.
    fn from_string(value: String) -> Self;
}

impl EncryptableValue for String {
    fn plaintext(&self) -> Option<&str> {
        Some(self)
    }

    fn from_string(value: String) -> Self {
        value
    }
}

impl EncryptableValue for Option<String> {
    fn plaintext(&self) -> Option<&str> {
        self.as_deref()
    }

    fn from_string(value: String) -> Self {
        Some(value)
    }
}

/// Decide what to do with a field value that is already an encryption
/// envelope at save time — Rails' "previous encryption schemes" behavior.
///
/// Returns:
/// - `Ok(None)` when the envelope is fully current (decrypts under the
///   current primary — or deterministic — key, carries the current envelope
///   version, and its deterministic flag matches the field's current mode):
///   keep it untouched, so repeated `encrypt_fields` calls stay idempotent
///   and unchanged rows are not rewritten with fresh IVs on every save.
/// - `Ok(Some(plaintext))` when the envelope is stale (written under a
///   previous key, an older envelope version, or the field's mode changed):
///   the caller re-encrypts the plaintext with the current scheme, lazily
///   migrating the row.
/// - `Err(..)` when no configured key decrypts it — persisting a value that
///   can never be read back again hides stale-key misconfiguration (and, for
///   AAD-bound fields, a relocated ciphertext), so it fails loudly instead.
fn stale_envelope_plaintext<P: KeyProvider + ?Sized>(
    provider: &P,
    field_name: &str,
    envelope_json: &str,
    field_is_deterministic: bool,
    aad: &[u8],
) -> EncryptionResult<Option<String>> {
    let envelope = EncryptedValue::from_json(envelope_json)?;
    let version_is_current = envelope.h.v.unwrap_or(0) >= CURRENT_ENVELOPE_VERSION;
    let mode_matches = envelope.is_deterministic() == field_is_deterministic;

    // Deterministic envelopes only ever use the (non-rotatable) deterministic
    // key, so decrypt failure is terminal rather than a rotation candidate.
    if envelope.is_deterministic() {
        let det_master = provider.get_deterministic_key()?.ok_or_else(|| {
            EncryptionError::NotConfigured(format!(
                "field '{field_name}' holds a deterministic ciphertext but no \
                 `deterministic_key` is configured"
            ))
        })?;
        let field_key = provider.derive_field_key(&det_master, field_name)?;
        let plaintext = decrypt(envelope_json, field_key.as_bytes(), aad)?;
        return Ok((!(version_is_current && mode_matches)).then_some(plaintext));
    }

    // Random-IV envelope: try the current primary first — success means the
    // value is only stale if the version or mode is outdated.
    let primary_key = provider.get_field_key(field_name)?;
    if let Ok(plaintext) = decrypt(envelope_json, primary_key.as_bytes(), aad) {
        return Ok((!(version_is_current && mode_matches)).then_some(plaintext));
    }

    // Walk the full rotation chain (re-deriving the field key per master).
    // Any success here means a previous key wrote it — always stale. The
    // chain conventionally starts with the primary; retrying it costs one
    // GCM tag check and avoids assuming provider list order.
    let masters = provider.get_decryption_keys()?;
    let mut last_error = None;
    for (master, _key_id) in &masters {
        let field_key = match provider.derive_field_key(master, field_name) {
            Ok(k) => k,
            Err(e) => {
                last_error = Some(e);
                continue;
            }
        };
        match decrypt(envelope_json, field_key.as_bytes(), aad) {
            Ok(plaintext) => return Ok(Some(plaintext)),
            Err(e) => last_error = Some(e),
        }
    }
    Err(EncryptionError::all_keys_failed(
        masters.len(),
        last_error.map_or_else(|| "unknown error".to_string(), |e| e.to_string()),
    ))
}

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
    ///
    /// # Information leakage
    ///
    /// Deterministic encryption is inherently less private than the random-IV
    /// default: equal plaintexts yield equal ciphertexts, which is what makes
    /// equality queries possible but also reveals which rows share a value.
    /// This matches Rails Active Record Encryption. Note the leak is not
    /// confined to a single column: with key derivation disabled (or no
    /// `aad_namespace`), two deterministic fields holding the same plaintext
    /// produce the *same* ciphertext, revealing the cross-field equality.
    /// Enabling key derivation derives a distinct per-field key, so identical
    /// plaintexts in different fields no longer collide — prefer it whenever
    /// you have more than one deterministic field. Reserve deterministic mode
    /// for fields you must query by exact value (e.g. an email used for
    /// lookup); leave everything else non-deterministic.
    #[must_use]
    fn deterministic_fields() -> Vec<String> {
        Vec::new()
    }

    /// Returns the field names that should **not** be zlib-compressed before
    /// encryption.
    ///
    /// Compression is on by default for every non-deterministic field (as in
    /// Rails Active Record Encryption); list a field here to opt it out. It
    /// only ever kicks in when the plaintext is at least
    /// [`crate::encryption::cipher::COMPRESS_THRESHOLD`] bytes long anyway —
    /// smaller values are stored uncompressed because the zlib header overhead
    /// outweighs any savings. The envelope header `h.c` records per-value
    /// whether a given ciphertext was compressed, so moving a field on or off
    /// this list is safe: existing ciphertexts continue to decrypt without
    /// re-encryption regardless of the current setting.
    ///
    /// Deterministic fields are never compressed (deflate output is not stable
    /// across zlib versions, which would break the equal-plaintext-equal-
    /// ciphertext property), so they do not need to appear here.
    ///
    /// # When to opt out
    ///
    /// Compressing plaintext before encrypting it leaks length-correlated
    /// information: AES-GCM ciphertext is the same length as its input, so the
    /// stored length reveals how compressible the value was (the CRIME /
    /// BREACH attack class). Opt a field out when it mixes attacker-influenced
    /// bytes with secret bytes in the same value and an attacker can observe
    /// the stored ciphertext length. For values that are wholly secret or
    /// wholly non-secret, the default (compressed) is fine.
    #[must_use]
    fn uncompressed_fields() -> Vec<String> {
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

    /// Columns whose values scope this row's ciphertexts (`aad_fields`).
    ///
    /// The macro's `aad_fields = [org_id]` argument fills this list and
    /// generates [`row_scope`](Self::row_scope) /
    /// [`row_scope_from_json`](Self::row_scope_from_json). The values are
    /// appended to every field's AAD (see [`RowScope::aad_bytes`]), so a
    /// ciphertext copied onto a row with a different tenant id fails
    /// authentication. Deterministic fields on a scoped model need
    /// [`encrypt_query_value_scoped`] for equality queries.
    ///
    /// The default is empty (no row binding).
    #[must_use]
    fn scope_columns() -> Vec<String> {
        Vec::new()
    }

    /// Row scope from this `ActiveModel`'s current values.
    ///
    /// Only consulted when at least one encrypted field is `Set`, so partial
    /// updates that leave the scope columns `NotSet` are fine as long as
    /// they do not touch an encrypted column.
    ///
    /// # Errors
    /// Returns [`EncryptionError::Scope`] when a scope column is `NotSet`
    /// or its value is not a JSON scalar.
    fn row_scope(&self) -> EncryptionResult<RowScope> {
        Ok(RowScope::new())
    }

    /// Row scope from a `Model` serialized to JSON (the decrypt side).
    ///
    /// Must produce byte-identical [`RowScope::aad_bytes`] to
    /// [`row_scope`](Self::row_scope) for the same row.
    ///
    /// # Errors
    /// Returns [`EncryptionError::Scope`] when a scope column is missing,
    /// null, or not a JSON scalar.
    fn row_scope_from_json(row: &serde_json::Value) -> EncryptionResult<RowScope> {
        let _ = row;
        Ok(RowScope::new())
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

    /// Encrypt all specified fields before saving, using an explicit provider.
    ///
    /// Call this on the `ActiveModel` right before `insert`/`update`. It
    /// cannot run from `ActiveModelBehavior::before_save`: that hook has no
    /// access to the `AppContext` or a key provider. Prefer
    /// [`encrypt_fields_ctx`](Self::encrypt_fields_ctx) when a context is
    /// available.
    ///
    /// A `Set` value that is already an encryption envelope is kept as-is
    /// when it is fully current, and transparently **re-encrypted with the
    /// current scheme** when it was written under a previous key, an older
    /// envelope version, or a different deterministic mode — Rails'
    /// "previous encryption schemes" behavior. Rows therefore migrate to the
    /// newest key lazily as they are saved.
    ///
    /// # Errors
    /// Returns an error if encryption fails, or if a `Set` value is an
    /// envelope that none of the configured keys can decrypt (persisting it
    /// would hide stale-key misconfiguration or a relocated ciphertext).
    fn encrypt_fields<P: KeyProvider + ?Sized>(mut self, provider: &P) -> EncryptionResult<Self>
    where
        Self: Sized,
    {
        let fields = Self::encrypted_fields();
        let det_fields = Self::deterministic_fields();
        let uncompressed_fields = Self::uncompressed_fields();
        // The key id is constant across all fields of a model; fetch it once
        // rather than re-allocating it on every loop iteration.
        let key_id = provider.get_key_id();
        // The row scope is resolved on first use so a partial update that
        // touches no encrypted column never demands the scope columns.
        let mut scope: Option<RowScope> = None;

        for field_name in &fields {
            let Some(value) = self.get_set_string_value(field_name) else {
                continue;
            };
            if scope.is_none() {
                scope = Some(self.row_scope()?);
            }

            let is_deterministic = det_fields.iter().any(|f| f == field_name);
            // Compression is on by default; deterministic fields are never
            // compressed (deflate output is not stable across zlib versions),
            // and any field can opt out via `uncompressed_fields`.
            let is_compressed =
                !is_deterministic && !uncompressed_fields.iter().any(|f| f == field_name);
            let aad = scope
                .as_ref()
                .map_or_else(Vec::new, |s| s.field_aad(Self::field_aad(field_name)));

            let plaintext = if is_encrypted_format(&value) {
                // Already an envelope: keep it when current, or recover the
                // plaintext so it re-encrypts under the current scheme.
                match stale_envelope_plaintext(
                    provider,
                    field_name,
                    &value,
                    is_deterministic,
                    &aad,
                )? {
                    None => continue,
                    Some(plaintext) => plaintext,
                }
            } else {
                value
            };

            let encrypted = if is_deterministic {
                let det_master = provider.get_deterministic_key()?.ok_or_else(|| {
                    EncryptionError::NotConfigured(format!(
                        "field '{field_name}' is marked deterministic but no \
                         `deterministic_key` is configured"
                    ))
                })?;
                let field_key = provider.derive_field_key(&det_master, field_name)?;
                encrypt_deterministic(&plaintext, field_key.as_bytes(), key_id.clone(), &aad)?
            } else if is_compressed {
                let key = provider.get_field_key(field_name)?;
                encrypt_compressed(&plaintext, key.as_bytes(), key_id.clone(), &aad)?
            } else {
                let key = provider.get_field_key(field_name)?;
                encrypt(&plaintext, key.as_bytes(), key_id.clone(), &aad)?
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
        let scope = <<E as EntityTrait>::ActiveModel as Encryptable>::row_scope_from_json(&value)?;
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

            let aad = scope.field_aad(<<E as EntityTrait>::ActiveModel as Encryptable>::field_aad(
                &field_name,
            ));

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

    // Route on the envelope's deterministic flag and walk the same master-key
    // lists as `ModelDecryption::decrypt_fields`, so this helper handles key
    // rotation (previous_keys) and deterministic values rather than only the
    // current primary key.
    let is_deterministic =
        EncryptedValue::from_json(encrypted_value).is_ok_and(|v| v.is_deterministic());

    let masters: Vec<SecureKey> = if is_deterministic {
        provider.get_deterministic_key()?.into_iter().collect()
    } else {
        provider
            .get_decryption_keys()?
            .into_iter()
            .map(|(master, _id)| master)
            .collect()
    };

    if masters.is_empty() {
        return Err(EncryptionError::NotConfigured(format!(
            "field '{field_name}' was encrypted deterministically but no \
             `deterministic_key` is configured"
        )));
    }

    let mut last_error = None;
    for master in &masters {
        let field_key = match provider.derive_field_key(master, field_name) {
            Ok(k) => k,
            Err(e) => {
                last_error = Some(e);
                continue;
            }
        };
        match decrypt(encrypted_value, field_key.as_bytes(), aad) {
            Ok(plaintext) => return Ok(plaintext),
            Err(e) => last_error = Some(e),
        }
    }

    Err(EncryptionError::all_keys_failed(
        masters.len(),
        last_error.map_or_else(|| "unknown error".to_string(), |e| e.to_string()),
    ))
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
/// Models with `aad_fields` (a non-empty
/// [`Encryptable::scope_columns`]) bind the ciphertext to row values, so the
/// needle must be built with [`encrypt_query_value_scoped`]; calling this
/// unscoped form on such a model is an error rather than a query that can
/// never match.
///
/// # Errors
/// Returns an error when no provider is registered, the field is not
/// deterministic, the model is row-scoped, no `deterministic_key` is
/// configured, or encryption fails.
pub fn encrypt_query_value<E>(
    field_name: &str,
    plaintext: &str,
    ctx: &AppContext,
) -> EncryptionResult<String>
where
    E: EntityTrait,
    <E as EntityTrait>::ActiveModel: Encryptable,
{
    let scope_columns = <<E as EntityTrait>::ActiveModel as Encryptable>::scope_columns();
    if !scope_columns.is_empty() {
        return Err(EncryptionError::Scope(format!(
            "field '{field_name}' belongs to a row-scoped model (aad_fields = {scope_columns:?}); \
             use `encrypt_query_value_scoped` with the row's scope values"
        )));
    }
    let provider = registry::require(ctx)?;
    encrypt_query_value_with::<E, _>(field_name, plaintext, &RowScope::new(), &*provider)
}

/// [`encrypt_query_value`] for a row-scoped model (`aad_fields`).
///
/// `scope` must carry every column in [`Encryptable::scope_columns`] with the
/// values of the rows being matched — for a tenant-scoped table, the tenant
/// id the query is confined to.
///
/// # Errors
/// As [`encrypt_query_value`], plus [`EncryptionError::Scope`] when `scope`
/// lacks one of the model's scope columns.
pub fn encrypt_query_value_scoped<E>(
    field_name: &str,
    plaintext: &str,
    scope: &RowScope,
    ctx: &AppContext,
) -> EncryptionResult<String>
where
    E: EntityTrait,
    <E as EntityTrait>::ActiveModel: Encryptable,
{
    let provider = registry::require(ctx)?;
    encrypt_query_value_with::<E, _>(field_name, plaintext, scope, &*provider)
}

/// [`encrypt_query_value_scoped`] with an explicit provider and no
/// `AppContext`.
///
/// Pass an empty [`RowScope`] for models without `aad_fields`.
///
/// # Errors
/// Returns an error when the field is not deterministic, `scope` lacks one
/// of the model's scope columns, no deterministic key is available, or
/// encryption fails.
pub fn encrypt_query_value_with<E, P>(
    field_name: &str,
    plaintext: &str,
    scope: &RowScope,
    provider: &P,
) -> EncryptionResult<String>
where
    E: EntityTrait,
    <E as EntityTrait>::ActiveModel: Encryptable,
    P: KeyProvider + ?Sized,
{
    let det_fields = <<E as EntityTrait>::ActiveModel as Encryptable>::deterministic_fields();
    if !det_fields.iter().any(|f| f == field_name) {
        return Err(EncryptionError::NotConfigured(format!(
            "field '{field_name}' is not declared as deterministic — add it to \
             `deterministic_fields()` to enable equality queries"
        )));
    }
    for column in <<E as EntityTrait>::ActiveModel as Encryptable>::scope_columns() {
        if scope.get(&column).is_none() {
            return Err(EncryptionError::Scope(format!(
                "query scope is missing column '{column}' required by the model's aad_fields"
            )));
        }
    }

    let det_master = provider.get_deterministic_key()?.ok_or_else(|| {
        EncryptionError::NotConfigured(
            "deterministic_key is required for query-value encryption".into(),
        )
    })?;
    let field_key = provider.derive_field_key(&det_master, field_name)?;
    let aad = scope.field_aad(<<E as EntityTrait>::ActiveModel as Encryptable>::field_aad(
        field_name,
    ));
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
    fn test_decrypt_field_reads_value_written_under_previous_key() {
        // decrypt_field must walk the rotation key list, not just the primary.
        use crate::encryption::{
            config::{EncryptionConfig, KeyDerivationConfig},
            key_provider::ConfigKeyProvider,
        };

        let old = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".to_string();
        let new = "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100".to_string();
        let salt = "aabbccdd00112233445566778899aabbccddeeff00112233445566778899aabb".to_string();

        let kd = || {
            Some(KeyDerivationConfig {
                enabled: true,
                salt: Some(salt.clone()),
            })
        };

        // Write under old primary.
        let old_provider = ConfigKeyProvider::new(&EncryptionConfig {
            primary_key: old.clone(),
            previous_keys: vec![],
            deterministic_key: None,
            key_derivation: kd(),
        })
        .unwrap();
        let ciphertext = encrypt_field("secret ssn", "ssn", &old_provider).unwrap();

        // Rotate: new primary, old as previous.
        let new_provider = ConfigKeyProvider::new(&EncryptionConfig {
            primary_key: new,
            previous_keys: vec![old],
            deterministic_key: None,
            key_derivation: kd(),
        })
        .unwrap();

        // Before the fix this only tried the new primary and failed.
        let decrypted = decrypt_field(&ciphertext, "ssn", &new_provider).unwrap();
        assert_eq!(decrypted, "secret ssn");
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
        let p1 = ConfigKeyProvider::new(&cfg).unwrap();
        let p2 = ConfigKeyProvider::new(&cfg).unwrap();

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
        let old_provider = ConfigKeyProvider::new(&old_config).unwrap();
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
        let new_provider = ConfigKeyProvider::new(&new_config).unwrap();

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

    mod stale_envelope {
        use super::super::stale_envelope_plaintext;
        use super::test_provider;
        use crate::encryption::{
            cipher,
            config::{EncryptionConfig, KeyDerivationConfig},
            encryptable::{encrypt_field, KeyProvider},
            format::EncryptedValue,
            key_provider::ConfigKeyProvider,
        };

        const OLD: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        const NEW: &str = "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100";
        const DET: &str = "aabbccdd00112233445566778899aabbccddeeff00112233445566778899aabb";
        const SALT: &str = "112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00";

        fn provider(primary: &str, previous: Vec<&str>) -> ConfigKeyProvider {
            ConfigKeyProvider::new(&EncryptionConfig {
                primary_key: primary.to_string(),
                previous_keys: previous.into_iter().map(String::from).collect(),
                deterministic_key: Some(DET.to_string()),
                key_derivation: Some(KeyDerivationConfig {
                    enabled: true,
                    salt: Some(SALT.to_string()),
                }),
            })
            .unwrap()
        }

        #[test]
        fn previous_key_envelope_is_stale() {
            let envelope = encrypt_field("secret", "ssn", &provider(OLD, vec![])).unwrap();
            let rotated = provider(NEW, vec![OLD]);
            let plaintext = stale_envelope_plaintext(&rotated, "ssn", &envelope, false, b"")
                .unwrap()
                .expect("previous-key envelope must be marked stale");
            assert_eq!(plaintext, "secret");
        }

        #[test]
        fn current_envelope_is_kept() {
            let p = provider(NEW, vec![OLD]);
            let envelope = encrypt_field("secret", "ssn", &p).unwrap();
            assert_eq!(
                stale_envelope_plaintext(&p, "ssn", &envelope, false, b"").unwrap(),
                None
            );
        }

        #[test]
        fn undecryptable_envelope_errors() {
            let envelope = encrypt_field("secret", "ssn", &provider(OLD, vec![])).unwrap();
            // NEW only — OLD is not in the rotation chain.
            let err =
                stale_envelope_plaintext(&provider(NEW, vec![]), "ssn", &envelope, false, b"")
                    .unwrap_err();
            assert!(err.to_string().contains("keys"), "unexpected error: {err}");
        }

        #[test]
        fn legacy_v1_envelope_is_stale_even_under_current_key() {
            use aes_gcm::{
                aead::{Aead, KeyInit, OsRng},
                AeadCore, Aes256Gcm,
            };
            // StaticKeyProvider: no derivation, so the field key IS the master.
            let p = test_provider();
            let key = p.get_field_key("ssn").unwrap();
            let gcm = Aes256Gcm::new_from_slice(key.as_bytes()).unwrap();
            let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
            let ct_with_tag = gcm
                .encrypt(
                    &nonce,
                    aes_gcm::aead::Payload {
                        msg: b"legacy value",
                        aad: b"",
                    },
                )
                .unwrap();
            let (ct, tag) = ct_with_tag.split_at(ct_with_tag.len() - cipher::TAG_SIZE);
            let mut env = EncryptedValue::new(ct, &nonce, tag, None);
            env.h.v = Some(1);
            let envelope = env.to_json().unwrap();

            let plaintext = stale_envelope_plaintext(&p, "ssn", &envelope, false, b"")
                .unwrap()
                .expect("v1 envelope must be marked stale for a version upgrade");
            assert_eq!(plaintext, "legacy value");
        }

        #[test]
        fn deterministic_mode_mismatch_is_stale() {
            let p = provider(NEW, vec![]);

            // Deterministic envelope on a field now marked non-deterministic.
            let det_master = p.get_deterministic_key().unwrap().unwrap();
            let det_key = p.derive_field_key(&det_master, "email").unwrap();
            let det_env =
                cipher::encrypt_deterministic("a@b.c", det_key.as_bytes(), None, b"").unwrap();
            assert_eq!(
                stale_envelope_plaintext(&p, "email", &det_env, false, b"")
                    .unwrap()
                    .as_deref(),
                Some("a@b.c")
            );

            // Random-IV envelope on a field now marked deterministic.
            let rand_env = encrypt_field("a@b.c", "email", &p).unwrap();
            assert_eq!(
                stale_envelope_plaintext(&p, "email", &rand_env, true, b"")
                    .unwrap()
                    .as_deref(),
                Some("a@b.c")
            );
        }

        #[test]
        fn deterministic_current_envelope_is_kept() {
            let p = provider(NEW, vec![]);
            let det_master = p.get_deterministic_key().unwrap().unwrap();
            let det_key = p.derive_field_key(&det_master, "email").unwrap();
            let envelope =
                cipher::encrypt_deterministic("a@b.c", det_key.as_bytes(), None, b"").unwrap();
            assert_eq!(
                stale_envelope_plaintext(&p, "email", &envelope, true, b"").unwrap(),
                None
            );
        }
    }
}
