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
    /// Returns a list of `(master_key, key_id)` tuples. **The first entry must
    /// be the current primary**: a value that only a later entry decrypts is
    /// treated as stale and re-encrypted on its next save. Each master is a
    /// distinct master key that may have encrypted existing ciphertexts; the
    /// caller derives the field key per master with
    /// [`derive_field_key`](Self::derive_field_key).
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
/// Parses the keys from [`EncryptionConfig`] (which supports environment
/// variable templating via `{{ get_env(...) }}`) and derives a distinct
/// AES-256 key per field with HKDF-SHA256.
///
/// # Security
///
/// All keys stored in this provider are wrapped in [`SecureKey`], which ensures
/// they are zeroed from memory when the provider is dropped. The provider
/// does not retain the raw hex strings from the config.
#[derive(Debug, Clone)]
pub struct ConfigKeyProvider {
    primary_key: SecureKey,
    previous_keys: Vec<SecureKey>,
    deterministic_key: SecureKey,
    salt: SecureKey,
}

impl ConfigKeyProvider {
    /// Parse and validate a configuration.
    ///
    /// # Errors
    /// Returns an error when any key or the salt is not 64 hex characters,
    /// when a non-empty `previous_keys` entry is invalid, or when
    /// `deterministic_key` equals `primary_key` or a previous key.
    pub fn new(config: &EncryptionConfig) -> EncryptionResult<Self> {
        let parse = |label: &str, hex: &str| {
            parse_hex_key(hex)
                .map(SecureKey::new)
                .map_err(|e| EncryptionError::InvalidKey(format!("{label}: {e}")))
        };
        let primary_key = parse("primary_key", &config.primary_key)?;
        let previous_keys = config
            .previous_keys_present()
            .iter()
            .enumerate()
            .map(|(i, k)| parse(&format!("previous_keys[{i}]"), k))
            .collect::<EncryptionResult<Vec<_>>>()?;
        let salt = parse("key_derivation_salt", &config.key_derivation_salt)?;

        // The deterministic key must be distinct from every master used for
        // random-IV encryption: if it collided with one, the same HKDF-derived
        // field key would be shared between a deterministic ciphertext and a
        // random-IV one, risking AES-GCM nonce reuse across the two modes.
        let deterministic_key = parse("deterministic_key", &config.deterministic_key)?;
        if deterministic_key.as_bytes() == primary_key.as_bytes() {
            return Err(EncryptionError::InvalidKey(
                "deterministic_key must differ from primary_key".into(),
            ));
        }
        if previous_keys
            .iter()
            .any(|p| p.as_bytes() == deterministic_key.as_bytes())
        {
            return Err(EncryptionError::InvalidKey(
                "deterministic_key must differ from every previous_keys entry".into(),
            ));
        }

        Ok(Self {
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
        let hk = Hkdf::<Sha256>::new(Some(self.salt.as_bytes()), master.as_bytes());
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
        Ok(Some(self.deterministic_key.clone()))
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

    const PRIMARY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const PREVIOUS: &str = "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100";
    const DET: &str = "aabbccdd00112233445566778899aabbccddeeff00112233445566778899aabb";
    const SALT: &str = "112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00";

    fn cfg(primary: &str, previous: &[&str], det: &str) -> EncryptionConfig {
        EncryptionConfig {
            primary_key: primary.to_string(),
            previous_keys: previous.iter().map(ToString::to_string).collect(),
            deterministic_key: det.to_string(),
            key_derivation_salt: SALT.to_string(),
        }
    }

    #[test]
    fn test_config_key_provider_basic() {
        let provider = ConfigKeyProvider::new(&cfg(PRIMARY, &[], DET)).unwrap();
        let key = provider.get_encryption_key().unwrap();
        assert_eq!(key.len(), KEY_SIZE);
        assert_eq!(key.as_bytes()[0], 0x00);
        assert_eq!(key.as_bytes()[31], 0x1f);
        assert_eq!(
            provider.get_deterministic_key().unwrap().unwrap().len(),
            KEY_SIZE
        );
    }

    #[test]
    fn test_config_key_provider_rejects_bad_keys() {
        for (label, config) in [
            ("primary", cfg("", &[], DET)),
            ("primary", cfg("too_short", &[], DET)),
            ("deterministic", cfg(PRIMARY, &[], "")),
            ("deterministic", cfg(PRIMARY, &[], "not-hex")),
            ("previous", cfg(PRIMARY, &["bad"], DET)),
            (
                "salt",
                EncryptionConfig {
                    key_derivation_salt: "short".to_string(),
                    ..cfg(PRIMARY, &[], DET)
                },
            ),
        ] {
            let err = ConfigKeyProvider::new(&config).unwrap_err();
            assert!(
                matches!(err, EncryptionError::InvalidKey(_)),
                "{label}: {err}"
            );
        }
    }

    #[test]
    fn test_config_key_provider_skips_empty_previous_entries() {
        // An unset templated env var renders as "", which is not an error.
        let provider = ConfigKeyProvider::new(&cfg(PRIMARY, &["", PREVIOUS, "  "], DET)).unwrap();
        let decryption_keys = provider.get_decryption_keys().unwrap();
        assert_eq!(decryption_keys.len(), 2);
        assert_eq!(decryption_keys[0].1, Some("primary".to_string()));
        assert_eq!(decryption_keys[1].1, Some("previous_0".to_string()));
    }

    #[test]
    fn test_config_key_provider_key_derivation() {
        let provider = ConfigKeyProvider::new(&cfg(PRIMARY, &[], DET)).unwrap();

        // Field keys are never the master.
        let primary = provider.get_encryption_key().unwrap();
        let field_key = provider.get_field_key("ssn").unwrap();
        assert_ne!(primary.as_bytes(), field_key.as_bytes());
        assert_eq!(field_key.len(), KEY_SIZE);

        // Stable per field, distinct across fields.
        assert_eq!(
            field_key.as_bytes(),
            provider.get_field_key("ssn").unwrap().as_bytes()
        );
        assert_ne!(
            field_key.as_bytes(),
            provider.get_field_key("credit_card").unwrap().as_bytes()
        );

        // Distinct across salts.
        let other_salt = EncryptionConfig {
            key_derivation_salt: DET.to_string(),
            ..cfg(PRIMARY, &[], DET)
        };
        let other = ConfigKeyProvider::new(&other_salt).unwrap();
        assert_ne!(
            field_key.as_bytes(),
            other.get_field_key("ssn").unwrap().as_bytes()
        );
    }

    #[test]
    fn test_config_key_provider_rejects_det_equal_to_primary() {
        let err = ConfigKeyProvider::new(&cfg(PRIMARY, &[], PRIMARY)).unwrap_err();
        assert!(matches!(err, EncryptionError::InvalidKey(_)), "{err:?}");
    }

    #[test]
    fn test_config_key_provider_rejects_det_equal_to_previous_key() {
        // Equal to a previous master: would risk a shared HKDF-derived field
        // key across deterministic and random-IV ciphertexts.
        let err = ConfigKeyProvider::new(&cfg(PRIMARY, &[PREVIOUS], PREVIOUS)).unwrap_err();
        assert!(matches!(err, EncryptionError::InvalidKey(_)), "{err:?}");
    }

    #[test]
    fn test_derive_field_key_per_master_for_rotation() {
        // Rotation with derivation: the field key must come from the supplied
        // master, not always from the primary.
        let provider = ConfigKeyProvider::new(&cfg(PRIMARY, &[PREVIOUS], DET)).unwrap();
        let masters = provider.get_decryption_keys().unwrap();
        assert_eq!(masters.len(), 2);

        let primary_field = provider.derive_field_key(&masters[0].0, "ssn").unwrap();
        let previous_field = provider.derive_field_key(&masters[1].0, "ssn").unwrap();
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
