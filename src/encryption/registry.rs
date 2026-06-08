//! Key provider registry
//!
//! This module wires a configured [`KeyProvider`] into the application so that
//! model-level encryption helpers can find it without every call site threading
//! one through.
//!
//! Two storage locations are used:
//!
//! - **Per-`AppContext`**: the provider is cloned into `AppContext.shared_store`
//!   under the `Arc<dyn KeyProvider + Send + Sync>` type key. This is the
//!   preferred access path — it lets tests and sub-apps use different providers
//!   by constructing fresh `AppContext`s.
//! - **Process-wide latest**: a fallback for call sites that do not have access
//!   to an `AppContext` (e.g. a custom `KeyProvider` installed at boot). Held
//!   in an `RwLock` so a later [`register`] or [`set_global`] (key rotation,
//!   config reload, a second app context in tests) refreshes it rather than
//!   being silently dropped.
//!
//! Registration happens automatically during `boot::create_context` when
//! `config.encryption` is set. User code normally does not need to call
//! [`register`] directly.

use std::sync::{Arc, RwLock};

use super::{
    config::EncryptionConfig,
    errors::{EncryptionError, EncryptionResult},
    key_provider::{ConfigKeyProvider, KeyProvider},
};
use crate::app::AppContext;

/// Type alias for the concrete dynamic provider stored in both locations.
pub type SharedKeyProvider = Arc<dyn KeyProvider + Send + Sync>;

static GLOBAL: RwLock<Option<SharedKeyProvider>> = RwLock::new(None);

/// Register a provider built from the given configuration.
///
/// Inserts the provider into `ctx.shared_store` and refreshes the process-wide
/// fallback. Calling twice (e.g. a second `AppContext`, or a config reload with
/// rotated keys) replaces both, so the global never points at a stale provider.
///
/// # Errors
/// Returns an error if the configuration fails validation or the primary key
/// cannot be parsed.
pub fn register(ctx: &AppContext, cfg: &EncryptionConfig) -> EncryptionResult<()> {
    super::validate_config(cfg)?;
    let provider: SharedKeyProvider = Arc::new(ConfigKeyProvider::new(cfg)?);
    ctx.shared_store.insert(provider.clone());
    if let Ok(mut guard) = GLOBAL.write() {
        *guard = Some(provider);
    }
    Ok(())
}

/// Install an arbitrary provider as the process-wide fallback.
///
/// Useful for custom `KeyProvider` implementations (KMS, Vault, HSM) that are
/// not driven by `EncryptionConfig`. Overwrites any previously installed
/// global provider.
pub fn set_global(provider: SharedKeyProvider) {
    if let Ok(mut guard) = GLOBAL.write() {
        *guard = Some(provider);
    }
}

/// Return the process-wide provider if one has been registered.
#[must_use]
pub fn global() -> Option<SharedKeyProvider> {
    GLOBAL.read().ok().and_then(|g| g.clone())
}

/// Resolve a provider from an `AppContext`, falling back to the global.
///
/// Prefers the per-context copy so per-test isolation works when tests build
/// their own `AppContext`.
#[must_use]
pub fn from_ctx(ctx: &AppContext) -> Option<SharedKeyProvider> {
    ctx.shared_store.get::<SharedKeyProvider>().or_else(global)
}

/// Resolve a provider or return a descriptive `NotConfigured` error.
///
/// # Errors
/// Returns [`EncryptionError::NotConfigured`] when neither `ctx.shared_store`
/// nor the global has a provider.
pub fn require(ctx: &AppContext) -> EncryptionResult<SharedKeyProvider> {
    from_ctx(ctx).ok_or_else(|| {
        EncryptionError::NotConfigured(
            "no encryption key provider is registered: add an `encryption` block to your \
             config, or call `loco_rs::encryption::registry::set_global` at boot"
                .to_string(),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::config::KeyDerivationConfig;
    use crate::tests_cfg::app::get_app_context;

    fn valid_hex_key() -> String {
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".to_string()
    }

    #[tokio::test]
    async fn register_inserts_into_shared_store() {
        let ctx = get_app_context().await;
        let cfg = EncryptionConfig {
            primary_key: valid_hex_key(),
            previous_keys: vec![],
            deterministic_key: None,
            key_derivation: None,
        };

        register(&ctx, &cfg).unwrap();

        assert!(from_ctx(&ctx).is_some());
        let resolved = require(&ctx).expect("registered provider");
        assert_eq!(resolved.get_encryption_key().unwrap().as_bytes().len(), 32);
    }

    #[tokio::test]
    async fn require_resolution_is_consistent_with_helpers() {
        // The process-wide OnceLock may or may not be set depending on the
        // order in which other tests in this binary ran. The contract under
        // test is "if `from_ctx` returns Some, `require` returns the same
        // pointer; otherwise `require` returns NotConfigured". That's
        // independent of whether the global is set.
        let ctx = get_app_context().await;
        match (from_ctx(&ctx), require(&ctx)) {
            (Some(p_lookup), Ok(p_required)) => {
                assert!(
                    Arc::ptr_eq(&p_lookup, &p_required),
                    "from_ctx and require must agree on the provider"
                );
            }
            (None, Err(EncryptionError::NotConfigured(_))) => {}
            (lookup, required) => panic!(
                "inconsistent resolution: from_ctx={:?}, require={:?}",
                lookup.is_some(),
                required.is_ok()
            ),
        }
    }

    #[tokio::test]
    async fn register_rejects_invalid_config() {
        let ctx = get_app_context().await;
        let cfg = EncryptionConfig {
            primary_key: "not-hex".to_string(),
            previous_keys: vec![],
            deterministic_key: None,
            key_derivation: Some(KeyDerivationConfig {
                enabled: true,
                salt: None,
            }),
        };
        assert!(register(&ctx, &cfg).is_err());
    }

    #[tokio::test]
    async fn app_context_encryption_provider_resolves_after_register() {
        let ctx = get_app_context().await;
        let cfg = EncryptionConfig {
            primary_key: valid_hex_key(),
            previous_keys: vec![],
            deterministic_key: None,
            key_derivation: None,
        };
        register(&ctx, &cfg).unwrap();

        let provider = ctx.encryption_provider().expect("provider should resolve");
        let encrypted = crate::encryption::encrypt_field("secret", "ssn", &*provider).unwrap();
        assert!(crate::encryption::is_encrypted_format(&encrypted));
        let decrypted = crate::encryption::decrypt_field(&encrypted, "ssn", &*provider).unwrap();
        assert_eq!(decrypted, "secret");
    }
}
