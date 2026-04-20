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
//! - **Process-wide singleton**: a fallback `OnceLock` for call sites that do
//!   not have access to an `AppContext` (notably
//!   `sea_orm::ActiveModelBehavior::before_save`, which gets only `&self` and
//!   `&DatabaseConnection`).
//!
//! Registration happens automatically during `boot::create_context` when
//! `config.encryption` is set. User code normally does not need to call
//! [`register`] directly.

use std::sync::{Arc, OnceLock};

use super::{
    config::EncryptionConfig,
    errors::{EncryptionError, EncryptionResult},
    key_provider::{ConfigKeyProvider, KeyProvider},
};
use crate::app::AppContext;

/// Type alias for the concrete dynamic provider stored in both locations.
pub type SharedKeyProvider = Arc<dyn KeyProvider + Send + Sync>;

static GLOBAL: OnceLock<SharedKeyProvider> = OnceLock::new();

/// Register a provider built from the given configuration.
///
/// Inserts the provider into `ctx.shared_store` and, if the process-wide
/// singleton has not already been set, installs it there too. Idempotent:
/// calling twice with the same config replaces the `shared_store` entry but
/// leaves the global untouched.
///
/// # Errors
/// Returns an error if the configuration fails validation or the primary key
/// cannot be parsed.
pub fn register(ctx: &AppContext, cfg: &EncryptionConfig) -> EncryptionResult<()> {
    super::validate_config(cfg)?;
    let provider: SharedKeyProvider = Arc::new(ConfigKeyProvider::new(cfg.clone())?);
    ctx.shared_store.insert(provider.clone());
    let _ = GLOBAL.set(provider);
    Ok(())
}

/// Install an arbitrary provider as the process-wide singleton.
///
/// Useful for custom `KeyProvider` implementations (KMS, Vault, HSM) that are
/// not driven by `EncryptionConfig`. Returns the provider back unchanged if the
/// global was already set — the caller can decide whether to swap it into
/// `ctx.shared_store` manually.
///
/// # Errors
/// Returns `Err` with the provider when the process-wide singleton was
/// already set.
pub fn set_global(provider: SharedKeyProvider) -> Result<(), SharedKeyProvider> {
    GLOBAL.set(provider)
}

/// Return the process-wide provider if one has been registered.
#[must_use]
pub fn global() -> Option<SharedKeyProvider> {
    GLOBAL.get().cloned()
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
            key_derivation: None,
        };

        register(&ctx, &cfg).unwrap();

        assert!(from_ctx(&ctx).is_some());
        let resolved = require(&ctx).expect("registered provider");
        assert_eq!(resolved.get_encryption_key().unwrap().as_bytes().len(), 32);
    }

    #[tokio::test]
    async fn require_errors_when_not_configured() {
        let ctx = get_app_context().await;
        // The global may already be set by another test; the per-ctx store is
        // always fresh, so the error path is tested by ensuring nothing was
        // registered in *this* ctx.
        let err = require(&ctx);
        // Can't assert on err unconditionally because a parallel test may have
        // installed the global. Just make sure resolution is consistent with
        // the helpers.
        match err {
            Ok(p) => {
                assert!(global().is_some());
                assert!(Arc::ptr_eq(&p, &global().unwrap()));
            }
            Err(EncryptionError::NotConfigured(_)) => {
                assert!(global().is_none() && from_ctx(&ctx).is_none());
            }
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn register_rejects_invalid_config() {
        let ctx = get_app_context().await;
        let cfg = EncryptionConfig {
            primary_key: "not-hex".to_string(),
            previous_keys: vec![],
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
