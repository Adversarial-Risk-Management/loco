//! Key provider trait and implementations
//!
//! This module defines the `KeyProvider` trait for abstracting encryption key management,
//! and provides a default implementation that reads keys from Loco's configuration.
//!
//! # Security
//!
//! Keys are automatically zeroed from memory when providers are dropped, using the
//! `zeroize` crate. This helps prevent keys from being leaked in memory dumps or
//! through other memory disclosure vulnerabilities.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{
    cipher::{parse_hex_key, KEY_SIZE},
    config::EncryptionConfig,
    errors::{EncryptionError, EncryptionResult},
};

/// A key that is automatically zeroed when dropped
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecureKey(Vec<u8>);

impl SecureKey {
    /// Create a new secure key from raw bytes
    #[must_use]
    pub fn new(key: Vec<u8>) -> Self {
        Self(key)
    }

    /// Get the key bytes (borrowed)
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Number of bytes in the key
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the key is empty (zero bytes)
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for SecureKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the actual key
        f.debug_struct("SecureKey")
            .field("len", &self.0.len())
            .finish()
    }
}

/// Trait for providing encryption keys
///
/// Implement this trait to create custom key providers (e.g., `HashiCorp` Vault, AWS KMS).
pub trait KeyProvider: Send + Sync {
    /// Get the primary encryption key
    ///
    /// # Errors
    /// Returns an error if the key is not available or invalid
    fn get_encryption_key(&self) -> EncryptionResult<SecureKey>;

    /// Get the key identifier for the primary key
    ///
    /// Used for key rotation support. Returns `None` if not tracking key IDs.
    fn get_key_id(&self) -> Option<String> {
        None
    }

    /// Derive a field-specific key from a given master key
    ///
    /// This is the low-level derivation primitive. Implementations that support
    /// key derivation (e.g. HKDF) should override this. The default is no
    /// derivation — the master is returned unchanged.
    ///
    /// Callers that want "the derived key for the primary master" should use
    /// [`get_field_key`](Self::get_field_key).
    ///
    /// # Errors
    /// Returns an error if key derivation fails
    fn derive_field_key(
        &self,
        master: &SecureKey,
        _field_name: &str,
    ) -> EncryptionResult<SecureKey> {
        Ok(master.clone())
    }

    /// Get the field-specific key derived from the primary master key
    ///
    /// Convenience wrapper around `derive_field_key(&primary, field_name)`.
    ///
    /// # Errors
    /// Returns an error if the primary key is unavailable or derivation fails
    fn get_field_key(&self, field_name: &str) -> EncryptionResult<SecureKey> {
        let primary = self.get_encryption_key()?;
        self.derive_field_key(&primary, field_name)
    }

    /// Get all keys for decryption (primary + previous keys for rotation)
    ///
    /// Returns a list of `(master_key, key_id)` tuples. Each master is a
    /// distinct master key that may have encrypted existing ciphertexts. For
    /// decryption with key derivation, callers must call
    /// [`derive_field_key`](Self::derive_field_key) for each master.
    ///
    /// # Errors
    /// Returns an error if keys cannot be retrieved
    fn get_decryption_keys(&self) -> EncryptionResult<Vec<(SecureKey, Option<String>)>> {
        let primary = self.get_encryption_key()?;
        let key_id = self.get_key_id();
        Ok(vec![(primary, key_id)])
    }

    /// Return the deterministic master key, if one is configured.
    ///
    /// Deterministic encryption requires a distinct master from the primary
    /// so that `HMAC(deterministic_key, plaintext)`-derived IVs never collide
    /// with random-IV ciphertexts. Providers that do not support
    /// deterministic encryption should return `None` (the default).
    ///
    /// # Errors
    /// Returns an error if the key is configured but unavailable.
    fn get_deterministic_key(&self) -> EncryptionResult<Option<SecureKey>> {
        Ok(None)
    }
}

/// Default key provider that reads from Loco configuration
///
/// This provider parses encryption keys from the application's YAML configuration,
/// which supports environment variable templating via `{{ get_env(...) }}`.
///
/// # Security
///
/// All keys stored in this provider are wrapped in [`SecureKey`], which ensures
/// they are zeroed from memory when the provider is dropped.
#[derive(Debug, Clone)]
pub struct ConfigKeyProvider {
    /// Whether per-field HKDF derivation is enabled. We store only this flag
    /// rather than the full `EncryptionConfig` so the provider does not retain
    /// a second, un-zeroized copy of the raw hex key strings for its lifetime.
    key_derivation_enabled: bool,
    primary_key: SecureKey,
    previous_keys: Vec<SecureKey>,
    deterministic_key: Option<SecureKey>,
    salt: Option<SecureKey>,
}

impl ConfigKeyProvider {
    /// Create a new config key provider
    ///
    /// # Errors
    /// Returns an error if the primary key is missing or invalid
    pub fn new(config: &EncryptionConfig) -> EncryptionResult<Self> {
        if !config.has_primary_key() {
            return Err(EncryptionError::NotConfigured(
                "primary_key is required".to_string(),
            ));
        }

        let primary_key = SecureKey::new(parse_hex_key(&config.primary_key)?);

        // Parse previous keys, skipping invalid ones with a warning
        let previous_keys: Vec<SecureKey> = config
            .valid_previous_keys()
            .iter()
            .filter_map(|k| parse_hex_key(k).ok().map(SecureKey::new))
            .collect();

        // Parse salt if key derivation is enabled
        let salt = if config.is_key_derivation_enabled() {
            config
                .key_derivation
                .as_ref()
                .and_then(|kd| kd.salt.as_ref())
                .map(|s| parse_hex_key(s).map(SecureKey::new))
                .transpose()?
        } else {
            None
        };

        // Parse deterministic key if configured. It must be distinct from the
        // primary AND from every previous (rotation) key: if it collided with
        // any master used for random-IV encryption, the same HKDF-derived
        // field key could be shared between a deterministic ciphertext and a
        // random-IV one, risking AES-GCM nonce reuse across the two modes.
        let deterministic_key = match config.deterministic_key.as_ref() {
            Some(k) if !k.trim().is_empty() => {
                let det = parse_hex_key(k)?;
                if det.as_slice() == primary_key.as_bytes() {
                    return Err(EncryptionError::InvalidKey(
                        "deterministic_key must differ from primary_key".into(),
                    ));
                }
                if previous_keys.iter().any(|p| p.as_bytes() == det.as_slice()) {
                    return Err(EncryptionError::InvalidKey(
                        "deterministic_key must differ from every previous_keys entry".into(),
                    ));
                }
                Some(SecureKey::new(det))
            }
            _ => None,
        };

        Ok(Self {
            key_derivation_enabled: config.is_key_derivation_enabled(),
            primary_key,
            previous_keys,
            deterministic_key,
            salt,
        })
    }
}

impl KeyProvider for ConfigKeyProvider {
    fn get_encryption_key(&self) -> EncryptionResult<SecureKey> {
        Ok(self.primary_key.clone())
    }

    fn get_key_id(&self) -> Option<String> {
        Some("primary".to_string())
    }

    fn derive_field_key(
        &self,
        master: &SecureKey,
        field_name: &str,
    ) -> EncryptionResult<SecureKey> {
        if !self.key_derivation_enabled {
            return Ok(master.clone());
        }

        let salt = self.salt.as_ref().ok_or_else(|| {
            EncryptionError::KeyDerivation("salt is required for key derivation".to_string())
        })?;

        let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), master.as_bytes());
        let mut derived = vec![0u8; KEY_SIZE];
        hk.expand(field_name.as_bytes(), &mut derived)
            .map_err(|e| EncryptionError::KeyDerivation(e.to_string()))?;

        Ok(SecureKey::new(derived))
    }

    fn get_decryption_keys(&self) -> EncryptionResult<Vec<(SecureKey, Option<String>)>> {
        let mut keys = Vec::with_capacity(1 + self.previous_keys.len());
        keys.push((self.primary_key.clone(), Some("primary".to_string())));
        for (i, key) in self.previous_keys.iter().enumerate() {
            keys.push((key.clone(), Some(format!("previous_{i}"))));
        }
        Ok(keys)
    }

    fn get_deterministic_key(&self) -> EncryptionResult<Option<SecureKey>> {
        Ok(self.deterministic_key.clone())
    }
}

/// A simple key provider for testing or when keys are already in memory
///
/// # Security
///
/// The key is wrapped in [`SecureKey`], which ensures it is zeroed from
/// memory when the provider is dropped.
#[derive(Debug, Clone)]
pub struct StaticKeyProvider {
    key: SecureKey,
    key_id: Option<String>,
}

impl StaticKeyProvider {
    /// Create a new static key provider from raw key bytes
    ///
    /// # Errors
    /// Returns an error if the key is not 32 bytes
    pub fn new(key: Vec<u8>, key_id: Option<String>) -> EncryptionResult<Self> {
        if key.len() != KEY_SIZE {
            return Err(EncryptionError::InvalidKey(format!(
                "key must be {KEY_SIZE} bytes, got {}",
                key.len()
            )));
        }
        Ok(Self {
            key: SecureKey::new(key),
            key_id,
        })
    }

    /// Create from a hex-encoded key string
    ///
    /// # Errors
    /// Returns an error if the hex string is invalid
    pub fn from_hex(hex: &str, key_id: Option<String>) -> EncryptionResult<Self> {
        let key = parse_hex_key(hex)?;
        Self::new(key, key_id)
    }
}

impl KeyProvider for StaticKeyProvider {
    fn get_encryption_key(&self) -> EncryptionResult<SecureKey> {
        Ok(self.key.clone())
    }

    fn get_key_id(&self) -> Option<String> {
        self.key_id.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> EncryptionConfig {
        EncryptionConfig {
            // 64 hex chars = 32 bytes
            primary_key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                .to_string(),
            previous_keys: vec![],
            deterministic_key: None,
            key_derivation: None,
        }
    }

    #[test]
    fn test_config_key_provider_basic() {
        let config = test_config();
        let provider = ConfigKeyProvider::new(&config).unwrap();

        let key = provider.get_encryption_key().unwrap();
        assert_eq!(key.len(), KEY_SIZE);
        assert_eq!(key.as_bytes()[0], 0x00);
        assert_eq!(key.as_bytes()[31], 0x1f);
    }

    #[test]
    fn test_config_key_provider_missing_key() {
        let config = EncryptionConfig {
            primary_key: "".to_string(),
            previous_keys: vec![],
            deterministic_key: None,
            key_derivation: None,
        };

        assert!(ConfigKeyProvider::new(&config).is_err());
    }

    #[test]
    fn test_config_key_provider_with_previous_keys() {
        let config = EncryptionConfig {
            primary_key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                .to_string(),
            previous_keys: vec![
                "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100".to_string(),
            ],
            deterministic_key: None,
            key_derivation: None,
        };

        let provider = ConfigKeyProvider::new(&config).unwrap();
        let decryption_keys = provider.get_decryption_keys().unwrap();

        assert_eq!(decryption_keys.len(), 2);
        assert_eq!(decryption_keys[0].1, Some("primary".to_string()));
        assert_eq!(decryption_keys[1].1, Some("previous_0".to_string()));
    }

    #[test]
    fn test_config_key_provider_key_derivation() {
        let config = EncryptionConfig {
            primary_key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                .to_string(),
            previous_keys: vec![],
            deterministic_key: None,
            key_derivation: Some(super::super::config::KeyDerivationConfig {
                enabled: true,
                salt: Some(
                    "aabbccdd00112233445566778899aabbccddeeff00112233445566778899aabb".to_string(),
                ),
            }),
        };

        let provider = ConfigKeyProvider::new(&config).unwrap();

        // Field-specific keys should be different from primary key
        let primary = provider.get_encryption_key().unwrap();
        let field_key = provider.get_field_key("ssn").unwrap();

        assert_ne!(primary.as_bytes(), field_key.as_bytes());
        assert_eq!(field_key.len(), KEY_SIZE);

        // Same field should get same derived key
        let field_key2 = provider.get_field_key("ssn").unwrap();
        assert_eq!(field_key.as_bytes(), field_key2.as_bytes());

        // Different fields should get different keys
        let other_field_key = provider.get_field_key("credit_card").unwrap();
        assert_ne!(field_key.as_bytes(), other_field_key.as_bytes());
    }

    #[test]
    fn test_config_key_provider_deterministic_key() {
        let config = EncryptionConfig {
            primary_key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                .to_string(),
            previous_keys: vec![],
            deterministic_key: Some(
                "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100".to_string(),
            ),
            key_derivation: None,
        };
        let provider = ConfigKeyProvider::new(&config).unwrap();

        let det = provider
            .get_deterministic_key()
            .unwrap()
            .expect("deterministic key should be present");
        assert_eq!(det.len(), KEY_SIZE);
        assert_ne!(
            det.as_bytes(),
            provider.get_encryption_key().unwrap().as_bytes()
        );
    }

    #[test]
    fn test_config_key_provider_rejects_det_equal_to_primary() {
        let hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let config = EncryptionConfig {
            primary_key: hex.to_string(),
            previous_keys: vec![],
            deterministic_key: Some(hex.to_string()),
            key_derivation: None,
        };
        let err = ConfigKeyProvider::new(&config).unwrap_err();
        assert!(
            matches!(err, EncryptionError::InvalidKey(_)),
            "expected InvalidKey, got {err:?}"
        );
    }

    #[test]
    fn test_config_key_provider_rejects_det_equal_to_previous_key() {
        let primary = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let previous = "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100";
        let config = EncryptionConfig {
            primary_key: primary.to_string(),
            previous_keys: vec![previous.to_string()],
            // Equal to a previous master: would risk a shared HKDF-derived
            // field key across deterministic and random-IV ciphertexts.
            deterministic_key: Some(previous.to_string()),
            key_derivation: None,
        };
        let err = ConfigKeyProvider::new(&config).unwrap_err();
        assert!(
            matches!(err, EncryptionError::InvalidKey(_)),
            "expected InvalidKey, got {err:?}"
        );
    }

    #[test]
    fn test_config_key_provider_no_deterministic_key() {
        let provider = ConfigKeyProvider::new(&test_config()).unwrap();
        assert!(provider.get_deterministic_key().unwrap().is_none());
    }

    #[test]
    fn test_derive_field_key_per_master_for_rotation() {
        // Regression for the rotation+derivation bug: derive_field_key must
        // derive from the supplied master, not always from the primary.
        let config = EncryptionConfig {
            primary_key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                .to_string(),
            previous_keys: vec![
                "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100".to_string(),
            ],
            deterministic_key: None,
            key_derivation: Some(super::super::config::KeyDerivationConfig {
                enabled: true,
                salt: Some(
                    "aabbccdd00112233445566778899aabbccddeeff00112233445566778899aabb".to_string(),
                ),
            }),
        };
        let provider = ConfigKeyProvider::new(&config).unwrap();

        let masters = provider.get_decryption_keys().unwrap();
        assert_eq!(masters.len(), 2);

        let (primary_master, _) = &masters[0];
        let (previous_master, _) = &masters[1];

        let primary_field = provider.derive_field_key(primary_master, "ssn").unwrap();
        let previous_field = provider.derive_field_key(previous_master, "ssn").unwrap();

        // Deriving from different masters MUST yield different field keys;
        // before the fix `get_field_key` always derived from primary.
        assert_ne!(primary_field.as_bytes(), previous_field.as_bytes());
        assert_eq!(primary_field.len(), KEY_SIZE);
        assert_eq!(previous_field.len(), KEY_SIZE);
    }

    #[test]
    fn test_static_key_provider() {
        let key = vec![0u8; 32];
        let provider = StaticKeyProvider::new(key.clone(), Some("test".to_string())).unwrap();

        assert_eq!(provider.get_encryption_key().unwrap().as_bytes(), &key[..]);
        assert_eq!(provider.get_key_id(), Some("test".to_string()));
    }

    #[test]
    fn test_static_key_provider_from_hex() {
        let hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let provider = StaticKeyProvider::from_hex(hex, None).unwrap();

        let key = provider.get_encryption_key().unwrap();
        assert_eq!(key.len(), KEY_SIZE);
    }

    #[test]
    fn test_static_key_provider_invalid_size() {
        let short_key = vec![0u8; 16];
        assert!(StaticKeyProvider::new(short_key, None).is_err());
    }

    #[test]
    fn test_secure_key_zeroize() {
        // Test that Zeroize trait is implemented and works
        let mut key = SecureKey::new(vec![0xAA; 32]);

        // Verify key has expected content before zeroing
        assert!(key.as_bytes().iter().all(|&b| b == 0xAA));

        // Manually call zeroize (what Drop does internally via ZeroizeOnDrop)
        key.zeroize();

        // After zeroize, all bytes should be zero
        assert!(
            key.as_bytes().iter().all(|&b| b == 0),
            "SecureKey should be zeroed after zeroize() call"
        );
    }

    #[test]
    fn test_secure_key_debug_does_not_leak() {
        let key = SecureKey::new(vec![0x42; 32]);
        let debug_output = format!("{:?}", key);

        // Debug output should NOT contain the actual key bytes
        assert!(
            !debug_output.contains("42"),
            "Debug output should not contain key bytes"
        );
        assert!(
            debug_output.contains("SecureKey"),
            "Debug output should identify the type"
        );
        assert!(
            debug_output.contains("len"),
            "Debug output should show length"
        );
    }

    #[test]
    fn test_secure_key_clone() {
        let key1 = SecureKey::new(vec![0x55; 32]);
        let key2 = key1.clone();

        // Both keys should have same content
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }
}
