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
//! impl_encryptable_fields!(users::ActiveModel, [ssn, credit_card], aad_namespace = "users");
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
//! impl_encryptable_fields!(users::ActiveModel, [ssn, credit_card], aad_namespace = "users");
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
//! [`crate::encryption::registry::install`] in your `Hooks::after_context`
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
    format::EncryptedValue,
    key_provider::{KeyProvider, SecureKey},
    registry::{self, SharedKeyProvider},
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

/// Result of decrypting one envelope.
struct Decrypted {
    plaintext: String,
    /// The first master the provider offers for the envelope's mode decrypted
    /// it: the current primary, or the deterministic key.
    current_key: bool,
}

/// Decrypt one envelope, walking the provider's masters for the envelope's
/// mode and deriving the field key per master until one authenticates.
///
/// Deterministic envelopes use only the deterministic key. Random-IV
/// envelopes try [`KeyProvider::get_decryption_keys`] in order, primary first.
fn decrypt_envelope<P: KeyProvider + ?Sized>(
    provider: &P,
    field_name: &str,
    envelope: &EncryptedValue,
    envelope_json: &str,
    aad: &[u8],
) -> EncryptionResult<Decrypted> {
    let masters: Vec<SecureKey> = if envelope.is_deterministic() {
        provider.get_deterministic_key()?.into_iter().collect()
    } else {
        provider
            .get_decryption_keys()?
            .into_iter()
            .map(|(master, _key_id)| master)
            .collect()
    };
    if masters.is_empty() {
        return Err(EncryptionError::NotConfigured(format!(
            "field '{field_name}' holds a deterministic ciphertext but the provider has no \
             deterministic key"
        )));
    }

    let mut last_error = None;
    for (i, master) in masters.iter().enumerate() {
        match provider
            .derive_field_key(master, field_name)
            .and_then(|key| decrypt(envelope_json, key.as_bytes(), aad))
        {
            Ok(plaintext) => {
                return Ok(Decrypted {
                    plaintext,
                    current_key: i == 0,
                })
            }
            Err(e) => {
                tracing::debug!(field = %field_name, key_index = i, error = %e, "decryption attempt failed");
                last_error = Some(e);
            }
        }
    }
    Err(EncryptionError::all_keys_failed(
        masters.len(),
        last_error.map_or_else(|| "unknown error".to_string(), |e| e.to_string()),
    ))
}

/// Encrypt one plaintext for `field_name` under the field's current scheme.
///
/// Deterministic values are labelled `h.i = "deterministic"`: their key is
/// the deterministic key, never the primary, so the primary's id would be
/// misleading there.
fn seal_plaintext<P: KeyProvider + ?Sized>(
    provider: &P,
    field_name: &str,
    plaintext: &str,
    deterministic: bool,
    compressed: bool,
    aad: &[u8],
) -> EncryptionResult<String> {
    if deterministic {
        let det_master = provider.get_deterministic_key()?.ok_or_else(|| {
            EncryptionError::NotConfigured(format!(
                "field '{field_name}' is marked deterministic but the provider has no \
                 deterministic key"
            ))
        })?;
        let key = provider.derive_field_key(&det_master, field_name)?;
        return encrypt_deterministic(
            plaintext,
            key.as_bytes(),
            Some("deterministic".to_string()),
            aad,
        );
    }
    let key = provider.get_field_key(field_name)?;
    if compressed {
        encrypt_compressed(plaintext, key.as_bytes(), provider.get_key_id(), aad)
    } else {
        encrypt(plaintext, key.as_bytes(), provider.get_key_id(), aad)
    }
}

/// Decide what to do with a field value that is already an encryption
/// envelope at save time (Rails' "previous encryption schemes").
///
/// Returns:
/// - `Ok(None)` when the envelope is current (decrypts under the current
///   primary, or the deterministic key, and its deterministic flag matches
///   the field's mode): keep it untouched, so repeated `encrypt_fields`
///   calls stay idempotent and unchanged rows are not rewritten with fresh
///   IVs on every save.
/// - `Ok(Some(plaintext))` when the envelope is stale (a previous key wrote
///   it, or the field's mode changed): the caller re-encrypts it.
/// - `Err(..)` when no configured key decrypts it: persisting a value that
///   can never be read back hides stale-key misconfiguration (and, for
///   AAD-bound fields, a relocated ciphertext).
fn stale_envelope_plaintext<P: KeyProvider + ?Sized>(
    provider: &P,
    field_name: &str,
    envelope: &EncryptedValue,
    envelope_json: &str,
    field_is_deterministic: bool,
    aad: &[u8],
) -> EncryptionResult<Option<String>> {
    let decrypted = decrypt_envelope(provider, field_name, envelope, envelope_json, aad)?;
    let current = decrypted.current_key && envelope.is_deterministic() == field_is_deterministic;
    Ok((!current).then_some(decrypted.plaintext))
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
    /// This matches Rails Active Record Encryption. The leak is confined to a
    /// single column: the per-field HKDF key and the `aad_namespace` binding
    /// mean identical plaintexts in different fields do not collide. Reserve
    /// deterministic mode for fields you must query by exact value (e.g. an
    /// email used for lookup); leave everything else non-deterministic.
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

    /// The Additional Authenticated Data that binds ciphertexts of the named
    /// field to their column.
    ///
    /// AES-GCM authenticates this byte string alongside the ciphertext: the
    /// same AAD must be supplied at decryption time, otherwise authentication
    /// fails. This is what defeats ciphertext-relocation attacks where a
    /// row-level attacker copies a ciphertext from one column to another.
    ///
    /// The macro emits `format!("{aad_namespace}:{field_name}")`. Hand
    /// implementations should follow the same shape. All reads and writes of
    /// the field must agree, so changing the value invalidates existing
    /// ciphertexts.
    #[must_use]
    fn field_aad(field_name: &str) -> Vec<u8>;

    /// Columns whose values scope this row's ciphertexts (`aad_fields`).
    ///
    /// The macro's `aad_fields = [org_id]` argument fills this list and
    /// generates [`row_scope`](Self::row_scope) /
    /// [`row_scope_from_json`](Self::row_scope_from_json). The values are
    /// appended to every field's AAD (see [`RowScope::aad_bytes`]), so a
    /// ciphertext copied onto a row with a different tenant id fails
    /// authentication. Deterministic fields on a scoped model need the same
    /// scope values passed to [`encrypt_query_value`] for equality queries.
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

    /// Select the key provider for a row, given its scope.
    ///
    /// The `*_ctx` helpers ([`encrypt_fields_ctx`](Self::encrypt_fields_ctx),
    /// [`ModelDecryption::decrypt_fields_ctx`], [`encrypt_query_value`])
    /// call this first and fall back to the registry when it returns
    /// `Ok(None)`. Override it — or pass `provider_for = path::to::fn` to
    /// [`impl_encryptable_fields!`](crate::impl_encryptable_fields) — to
    /// encrypt each tenant's rows under that tenant's own keys.
    ///
    /// The hook is synchronous: resolve providers that need I/O (a sealed
    /// per-tenant keypair read from the database, a KMS call) earlier on the
    /// request or job path and cache them, for example in
    /// `ctx.shared_store`, then look them up here. The cache owner must evict
    /// an entry when that tenant's keys rotate. When the hook is declared
    /// through the macro's `provider_for = ...` argument, `Ok(None)` is an
    /// error: a model with its own provider never falls back to the registry,
    /// which would write a tenant's row under the wrong key.
    ///
    /// # Errors
    /// Returns an error when no provider can be resolved for the scope.
    fn provider_for(
        scope: &RowScope,
        ctx: &AppContext,
    ) -> EncryptionResult<Option<SharedKeyProvider>> {
        let _ = (scope, ctx);
        Ok(None)
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
        // Nothing to encrypt: do not demand the scope columns or a provider.
        if !Self::encrypted_fields()
            .iter()
            .any(|f| self.get_set_string_value(f).is_some())
        {
            return Ok(self);
        }
        let scope = self.row_scope()?;
        let provider = resolve_provider::<Self>(&scope, ctx)?;
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
    /// current scheme** when it was written under a previous key or a
    /// different deterministic mode — Rails'
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

            // Already an envelope: keep it when current, or recover the
            // plaintext so it re-encrypts under the current scheme. A value
            // with the envelope shape that fails to parse is an error, never
            // plaintext to be wrapped again.
            let plaintext = match EncryptedValue::parse_column(&value)? {
                Some(envelope) => match stale_envelope_plaintext(
                    provider,
                    field_name,
                    &envelope,
                    &value,
                    is_deterministic,
                    &aad,
                )? {
                    None => continue,
                    Some(plaintext) => plaintext,
                },
                None => value,
            };

            let encrypted = seal_plaintext(
                provider,
                field_name,
                &plaintext,
                is_deterministic,
                is_compressed,
                &aad,
            )?;

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
    /// Decrypt all encrypted fields in-place using the provider resolved from
    /// an [`AppContext`](crate::app::AppContext).
    ///
    /// The model round-trips through `serde_json` for runtime field access.
    /// Every declared field must be present and hold `null` or an envelope;
    /// see [`decrypt_fields`](Self::decrypt_fields).
    ///
    /// # Errors
    /// Returns an error if no provider resolves, a declared field is missing
    /// or holds a value that is not an envelope, or no key decrypts a value.
    fn decrypt_fields_ctx<E>(&mut self, ctx: &AppContext) -> EncryptionResult<()>
    where
        E: EntityTrait,
        <E as EntityTrait>::Model: Serialize + DeserializeOwned,
        <E as EntityTrait>::ActiveModel: Encryptable,
    {
        let mut value = serde_json::to_value(&self)?;
        let scope = <<E as EntityTrait>::ActiveModel as Encryptable>::row_scope_from_json(&value)?;
        let provider = resolve_provider::<<E as EntityTrait>::ActiveModel>(&scope, ctx)?;
        decrypt_row_fields::<E, _>(&mut value, &scope, &*provider)?;
        *self = serde_json::from_value(value)?;
        Ok(())
    }

    /// Decrypt all encrypted fields in-place using an explicit provider.
    ///
    /// # Errors
    /// Returns an error if the model cannot round-trip through JSON, a
    /// declared field is missing or holds a value that is not an envelope
    /// (a plaintext in an encrypted column is an error, not a passthrough),
    /// or no key decrypts a value.
    fn decrypt_fields<E, P>(&mut self, provider: &P) -> EncryptionResult<()>
    where
        E: EntityTrait,
        <E as EntityTrait>::Model: Serialize + DeserializeOwned,
        <E as EntityTrait>::ActiveModel: Encryptable,
        P: KeyProvider + ?Sized,
    {
        let mut value = serde_json::to_value(&self)?;
        let scope = <<E as EntityTrait>::ActiveModel as Encryptable>::row_scope_from_json(&value)?;
        decrypt_row_fields::<E, P>(&mut value, &scope, provider)?;
        *self = serde_json::from_value(value)?;
        Ok(())
    }
}

/// Resolve the provider for a row: the model's [`Encryptable::provider_for`]
/// first, then the registry.
fn resolve_provider<A: Encryptable>(
    scope: &RowScope,
    ctx: &AppContext,
) -> EncryptionResult<SharedKeyProvider> {
    A::provider_for(scope, ctx)?.map_or_else(|| registry::require(ctx), Ok)
}

/// Decrypt every encrypted field of a model serialized as a JSON object,
/// in place. Shared by the ctx-aware and explicit-provider entry points.
///
/// Every declared field must be present in the JSON. `null` (a nullable
/// column with no value) is left alone; any other value must be a valid
/// envelope. A plaintext string in an encrypted column is an error: the only
/// plaintext-to-envelope transition is the save path.
fn decrypt_row_fields<E, P>(
    value: &mut serde_json::Value,
    scope: &RowScope,
    provider: &P,
) -> EncryptionResult<()>
where
    E: EntityTrait,
    <E as EntityTrait>::ActiveModel: Encryptable,
    P: KeyProvider + ?Sized,
{
    let obj = value.as_object_mut().ok_or_else(|| {
        EncryptionError::DecryptionFailed("failed to convert model to JSON object".into())
    })?;

    for field_name in <<E as EntityTrait>::ActiveModel as Encryptable>::encrypted_fields() {
        let Some(stored) = obj.get_mut(&field_name) else {
            return Err(EncryptionError::InvalidFormat(format!(
                "encrypted field '{field_name}' is not present on the model (check the \
                 field list and any `#[serde(rename)]`)"
            )));
        };
        if stored.is_null() {
            continue;
        }
        let envelope_json = stored.as_str().ok_or_else(|| {
            EncryptionError::InvalidFormat(format!(
                "encrypted field '{field_name}' is not a string column"
            ))
        })?;
        let envelope = EncryptedValue::parse_column(envelope_json)?.ok_or_else(|| {
            EncryptionError::InvalidFormat(format!(
                "encrypted field '{field_name}' holds a value that is not an encryption \
                 envelope"
            ))
        })?;
        let aad = scope.field_aad(<<E as EntityTrait>::ActiveModel as Encryptable>::field_aad(
            &field_name,
        ));
        let decrypted = decrypt_envelope(provider, &field_name, &envelope, envelope_json, &aad)?;
        *stored = serde_json::Value::String(decrypted.plaintext);
    }
    Ok(())
}

// Blanket implementation for all types that implement Serialize + DeserializeOwned
impl<M> ModelDecryption for M where M: Serialize + DeserializeOwned {}

/// Decrypt one envelope outside the model layer.
///
/// `aad` must be the exact bytes bound at encryption: `&[]` for a value from
/// [`encrypt_field`] with no binding, or
/// `scope.field_aad(ActiveModel::field_aad(field_name))` for a value read
/// from a model column. Handles deterministic envelopes and `previous_keys`
/// the same way [`ModelDecryption::decrypt_fields`] does.
///
/// # Errors
/// Returns an error if `encrypted_value` is not an envelope, or no key
/// decrypts it under `aad`.
pub fn decrypt_field<P: KeyProvider + ?Sized>(
    encrypted_value: &str,
    field_name: &str,
    provider: &P,
    aad: &[u8],
) -> EncryptionResult<String> {
    let envelope = EncryptedValue::parse_column(encrypted_value)?.ok_or_else(|| {
        EncryptionError::InvalidFormat(format!(
            "field '{field_name}' value is not an encryption envelope"
        ))
    })?;
    decrypt_envelope(provider, field_name, &envelope, encrypted_value, aad).map(|d| d.plaintext)
}

/// Encrypt one value outside the model layer: random IV, no compression,
/// per-field key for `field_name`, bound to `aad` (pass `&[]` for none).
///
/// # Errors
/// Returns an error if the key is unavailable or encryption fails.
pub fn encrypt_field<P: KeyProvider + ?Sized>(
    plaintext: &str,
    field_name: &str,
    provider: &P,
    aad: &[u8],
) -> EncryptionResult<String> {
    seal_plaintext(provider, field_name, plaintext, false, false, aad)
}

/// Produce the deterministic ciphertext used for equality queries.
///
/// ```rust,ignore
/// use loco_rs::encryption::{encrypt_query_value, RowScope};
///
/// let ct = encrypt_query_value::<users::Entity>("email", "alice@example.com", &ctx, &RowScope::new())?;
/// users::Entity::find()
///     .filter(users::Column::Email.eq(ct))
///     .one(&ctx.db)
///     .await?;
/// ```
///
/// `field_name` must be listed in [`Encryptable::deterministic_fields`] for
/// the entity's `ActiveModel`; otherwise this is an error rather than a
/// ciphertext that can never match a row.
///
/// `scope` must carry every column in [`Encryptable::scope_columns`] with the
/// values of the rows being matched (for a tenant-scoped table, the tenant
/// id the query is confined to). Pass `RowScope::new()` for a model without
/// `aad_fields`. The provider comes from [`Encryptable::provider_for`], then
/// the registry.
///
/// # Errors
/// Returns an error when no provider resolves, the field is not
/// deterministic, `scope` lacks one of the model's scope columns, or
/// encryption fails.
pub fn encrypt_query_value<E>(
    field_name: &str,
    plaintext: &str,
    ctx: &AppContext,
    scope: &RowScope,
) -> EncryptionResult<String>
where
    E: EntityTrait,
    <E as EntityTrait>::ActiveModel: Encryptable,
{
    type A<E> = <E as EntityTrait>::ActiveModel;
    if !A::<E>::deterministic_fields()
        .iter()
        .any(|f| f == field_name)
    {
        return Err(EncryptionError::NotConfigured(format!(
            "field '{field_name}' is not declared as deterministic; only deterministic fields \
             support equality queries"
        )));
    }
    let scope = scope.ordered_by(&A::<E>::scope_columns())?;
    let provider = resolve_provider::<A<E>>(&scope, ctx)?;
    let aad = scope.field_aad(A::<E>::field_aad(field_name));
    seal_plaintext(&*provider, field_name, plaintext, true, false, &aad)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::{format::is_encrypted_format, key_provider::StaticKeyProvider};

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

        let encrypted = encrypt_field(plaintext, field_name, &provider, b"").unwrap();
        assert!(is_encrypted_format(&encrypted));

        let decrypted = decrypt_field(&encrypted, field_name, &provider, b"").unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_field_with_aad_round_trip() {
        let provider = test_provider();
        let plaintext = "secret";
        let aad = b"users:ssn";

        let encrypted = encrypt_field(plaintext, "ssn", &provider, aad).unwrap();
        assert!(is_encrypted_format(&encrypted));

        // Same AAD: decrypts.
        assert_eq!(
            decrypt_field(&encrypted, "ssn", &provider, aad).unwrap(),
            plaintext
        );

        // Different AAD: authentication fails.
        assert!(
            decrypt_field(&encrypted, "ssn", &provider, b"users:other").is_err(),
            "AAD mismatch must fail decryption"
        );
    }

    #[test]
    fn test_decrypt_field_rejects_plaintext() {
        let provider = test_provider();
        let err = decrypt_field("not encrypted", "ssn", &provider, b"").unwrap_err();
        assert!(matches!(err, EncryptionError::InvalidFormat(_)), "{err}");
    }

    #[test]
    fn test_decrypt_field_reads_value_written_under_previous_key() {
        // decrypt_field must walk the rotation key list, not just the primary.
        use crate::encryption::{config::EncryptionConfig, key_provider::ConfigKeyProvider};

        let old = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".to_string();
        let new = "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100".to_string();

        // Write under old primary.
        let old_provider = ConfigKeyProvider::new(&EncryptionConfig {
            primary_key: old.clone(),
            previous_keys: vec![],
            deterministic_key: "aabbccdd00112233445566778899aabbccddeeff00112233445566778899aabb"
                .to_string(),
            key_derivation_salt: "112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00"
                .to_string(),
        })
        .unwrap();
        let ciphertext = encrypt_field("secret ssn", "ssn", &old_provider, b"").unwrap();

        // Rotate: new primary, old as previous.
        let new_provider = ConfigKeyProvider::new(&EncryptionConfig {
            primary_key: new,
            previous_keys: vec![old],
            deterministic_key: "aabbccdd00112233445566778899aabbccddeeff00112233445566778899aabb"
                .to_string(),
            key_derivation_salt: "112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00"
                .to_string(),
        })
        .unwrap();

        // Before the fix this only tried the new primary and failed.
        let decrypted = decrypt_field(&ciphertext, "ssn", &new_provider, b"").unwrap();
        assert_eq!(decrypted, "secret ssn");
    }

    #[test]
    fn test_deterministic_equality_query_roundtrip() {
        // Two independent provider instances (simulating two server processes)
        // with the same config must produce identical ciphertext for the same
        // plaintext — that's what makes equality queries work.
        use crate::encryption::{
            cipher, config::EncryptionConfig, key_provider::ConfigKeyProvider,
        };

        let primary = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let det = "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100";

        let cfg = EncryptionConfig {
            primary_key: primary.to_string(),
            previous_keys: vec![],
            deterministic_key: det.to_string(),
            key_derivation_salt: "112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00"
                .to_string(),
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

        use crate::encryption::{config::EncryptionConfig, key_provider::ConfigKeyProvider};

        let old_master =
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".to_string();
        let new_master =
            "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100".to_string();

        // Encrypt under the OLD config (old master is primary).
        let old_config = EncryptionConfig {
            primary_key: old_master.clone(),
            previous_keys: vec![],
            deterministic_key: "aabbccdd00112233445566778899aabbccddeeff00112233445566778899aabb"
                .to_string(),
            key_derivation_salt: "112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00"
                .to_string(),
        };
        let old_provider = ConfigKeyProvider::new(&old_config).unwrap();
        let ciphertext = encrypt_field("secret ssn", "ssn", &old_provider, b"").unwrap();
        assert!(is_encrypted_format(&ciphertext));

        // Rotate: the OLD master becomes a previous key under a new primary.
        let new_config = EncryptionConfig {
            primary_key: new_master,
            previous_keys: vec![old_master],
            deterministic_key: "aabbccdd00112233445566778899aabbccddeeff00112233445566778899aabb"
                .to_string(),
            key_derivation_salt: "112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00"
                .to_string(),
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
        use crate::encryption::{
            cipher,
            config::EncryptionConfig,
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
                deterministic_key: DET.to_string(),
                key_derivation_salt: SALT.to_string(),
            })
            .unwrap()
        }

        #[test]
        fn previous_key_envelope_is_stale() {
            let envelope = encrypt_field("secret", "ssn", &provider(OLD, vec![]), b"").unwrap();
            let rotated = provider(NEW, vec![OLD]);
            let plaintext = stale_envelope_plaintext(
                &rotated,
                "ssn",
                &EncryptedValue::from_json(&envelope).unwrap(),
                &envelope,
                false,
                b"",
            )
            .unwrap()
            .expect("previous-key envelope must be marked stale");
            assert_eq!(plaintext, "secret");
        }

        #[test]
        fn current_envelope_is_kept() {
            let p = provider(NEW, vec![OLD]);
            let envelope = encrypt_field("secret", "ssn", &p, b"").unwrap();
            assert_eq!(
                stale_envelope_plaintext(
                    &p,
                    "ssn",
                    &EncryptedValue::from_json(&envelope).unwrap(),
                    &envelope,
                    false,
                    b""
                )
                .unwrap(),
                None
            );
        }

        #[test]
        fn undecryptable_envelope_errors() {
            let envelope = encrypt_field("secret", "ssn", &provider(OLD, vec![]), b"").unwrap();
            // NEW only — OLD is not in the rotation chain.
            let err = stale_envelope_plaintext(
                &provider(NEW, vec![]),
                "ssn",
                &EncryptedValue::from_json(&envelope).unwrap(),
                &envelope,
                false,
                b"",
            )
            .unwrap_err();
            assert!(err.to_string().contains("keys"), "unexpected error: {err}");
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
                stale_envelope_plaintext(
                    &p,
                    "email",
                    &EncryptedValue::from_json(&det_env).unwrap(),
                    &det_env,
                    false,
                    b""
                )
                .unwrap()
                .as_deref(),
                Some("a@b.c")
            );

            // Random-IV envelope on a field now marked deterministic.
            let rand_env = encrypt_field("a@b.c", "email", &p, b"").unwrap();
            assert_eq!(
                stale_envelope_plaintext(
                    &p,
                    "email",
                    &EncryptedValue::from_json(&rand_env).unwrap(),
                    &rand_env,
                    true,
                    b""
                )
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
                stale_envelope_plaintext(
                    &p,
                    "email",
                    &EncryptedValue::from_json(&envelope).unwrap(),
                    &envelope,
                    true,
                    b""
                )
                .unwrap(),
                None
            );
        }
    }
}
