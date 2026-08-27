//! Key provider registry
//!
//! The configured [`KeyProvider`] lives in `AppContext.shared_store` under
//! the [`SharedKeyProvider`] type key, so model-level helpers can find it
//! without every call site threading one through. There is no process-wide
//! fallback: a context without a provider is not configured, and says so.
//!
//! Registration happens automatically during `boot::create_context` when
//! `config.encryption` is set. Custom providers (KMS, Vault, HSM) call
//! [`install`] from `Hooks::after_context`, which replaces the config-driven
//! one for that context.

use std::sync::Arc;

use super::{
    config::EncryptionConfig,
    errors::{EncryptionError, EncryptionResult},
    key_provider::{ConfigKeyProvider, KeyProvider},
};
use crate::app::AppContext;

/// Type alias for the dynamic provider stored in `shared_store`.
pub type SharedKeyProvider = Arc<dyn KeyProvider + Send + Sync>;

/// Register a provider built from the given configuration.
///
/// # Errors
/// Returns an error if the configuration fails validation or the primary key
/// cannot be parsed.
pub fn register(ctx: &AppContext, cfg: &EncryptionConfig) -> EncryptionResult<()> {
    super::validate_config(cfg)?;
    install(ctx, Arc::new(ConfigKeyProvider::new(cfg)?));
    Ok(())
}

/// Install an arbitrary provider for this context, replacing any existing
/// one. Call from `Hooks::after_context` for providers that are not driven
/// by `EncryptionConfig`.
pub fn install(ctx: &AppContext, provider: SharedKeyProvider) {
    ctx.shared_store.insert(provider);
}

/// Resolve the provider registered on this context, if any.
#[must_use]
pub fn from_ctx(ctx: &AppContext) -> Option<SharedKeyProvider> {
    ctx.shared_store.get::<SharedKeyProvider>()
}

/// Resolve a provider or return a descriptive `NotConfigured` error.
///
/// # Errors
/// Returns [`EncryptionError::NotConfigured`] when the context has no
/// provider.
pub fn require(ctx: &AppContext) -> EncryptionResult<SharedKeyProvider> {
    from_ctx(ctx).ok_or_else(|| {
        EncryptionError::NotConfigured(
            "no encryption key provider is registered: add an `encryption` block to your \
             config, or call `loco_rs::encryption::registry::install` in `Hooks::after_context`"
                .to_string(),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
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
            deterministic_key: "aabbccdd00112233445566778899aabbccddeeff00112233445566778899aabb"
                .to_string(),
            key_derivation_salt: "112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00"
                .to_string(),
        };

        register(&ctx, &cfg).unwrap();

        assert!(from_ctx(&ctx).is_some());
        let resolved = require(&ctx).expect("registered provider");
        assert_eq!(resolved.get_encryption_key().unwrap().as_bytes().len(), 32);
    }

    #[tokio::test]
    async fn unconfigured_context_is_not_configured() {
        // No fallback to any other context's provider: a fresh context with
        // no `encryption` block reports NotConfigured regardless of what
        // other tests in this binary registered.
        let ctx = get_app_context().await;
        assert!(from_ctx(&ctx).is_none());
        assert!(matches!(
            require(&ctx),
            Err(EncryptionError::NotConfigured(_))
        ));
    }

    #[tokio::test]
    async fn install_replaces_the_config_provider() {
        let ctx = get_app_context().await;
        let cfg = EncryptionConfig {
            primary_key: valid_hex_key(),
            previous_keys: vec![],
            deterministic_key: "aabbccdd00112233445566778899aabbccddeeff00112233445566778899aabb"
                .to_string(),
            key_derivation_salt: "112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00"
                .to_string(),
        };
        register(&ctx, &cfg).unwrap();
        let custom: SharedKeyProvider = Arc::new(
            crate::encryption::key_provider::StaticKeyProvider::from_hex(
                &valid_hex_key(),
                Some("custom".to_string()),
            )
            .unwrap(),
        );
        install(&ctx, custom);
        assert_eq!(
            require(&ctx).unwrap().get_key_id(),
            Some("custom".to_string())
        );
    }

    #[tokio::test]
    async fn register_rejects_invalid_config() {
        let ctx = get_app_context().await;
        let cfg = EncryptionConfig {
            primary_key: "not-hex".to_string(),
            previous_keys: vec![],
            deterministic_key: "aabbccdd00112233445566778899aabbccddeeff00112233445566778899aabb"
                .to_string(),
            key_derivation_salt: "112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00"
                .to_string(),
        };
        assert!(register(&ctx, &cfg).is_err());
    }

    #[tokio::test]
    async fn app_context_encryption_provider_resolves_after_register() {
        let ctx = get_app_context().await;
        let cfg = EncryptionConfig {
            primary_key: valid_hex_key(),
            previous_keys: vec![],
            deterministic_key: "aabbccdd00112233445566778899aabbccddeeff00112233445566778899aabb"
                .to_string(),
            key_derivation_salt: "112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00"
                .to_string(),
        };
        register(&ctx, &cfg).unwrap();

        let provider = ctx.encryption_provider().expect("provider should resolve");
        let encrypted = crate::encryption::encrypt_field("secret", "ssn", &*provider, b"").unwrap();
        assert!(crate::encryption::is_encrypted_format(&encrypted));
        let decrypted =
            crate::encryption::decrypt_field(&encrypted, "ssn", &*provider, b"").unwrap();
        assert_eq!(decrypted, "secret");
    }
}
