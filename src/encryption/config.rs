//! Encryption configuration structures
//!
//! Configuration for field encryption, loaded from the application's YAML config.
//!
//! # Example Configuration
//!
//! ```yaml
//! encryption:
//!   primary_key: {{ get_env(name="LOCO_ENCRYPTION_PRIMARY_KEY") }}
//!   previous_keys:
//!     - {{ get_env(name="LOCO_ENCRYPTION_KEY_2024_01", default="") }}
//!   key_derivation:
//!     enabled: true
//!     salt: {{ get_env(name="LOCO_ENCRYPTION_SALT") }}
//! ```

use serde::{Deserialize, Serialize};

/// Encryption configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EncryptionConfig {
    /// Primary encryption key (32 bytes hex-encoded = 64 chars for AES-256)
    /// Generate with: `openssl rand -hex 32`
    pub primary_key: String,

    /// Previous keys for rotation support (decryption only)
    /// The system will try decrypting with primary first, then fall back to these
    #[serde(default)]
    pub previous_keys: Vec<String>,

    /// Key derivation settings
    #[serde(default)]
    pub key_derivation: Option<KeyDerivationConfig>,
}

/// Key derivation configuration for deriving field-specific keys
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct KeyDerivationConfig {
    /// Enable key derivation (derive per-field keys from master key)
    #[serde(default)]
    pub enabled: bool,

    /// Salt for HKDF (32 bytes hex-encoded)
    /// Generate with: `openssl rand -hex 32`
    pub salt: Option<String>,
}

impl EncryptionConfig {
    /// Check if the configuration has a valid primary key
    #[must_use]
    pub fn has_primary_key(&self) -> bool {
        !self.primary_key.trim().is_empty()
    }

    /// Get non-empty previous keys for rotation
    #[must_use]
    pub fn valid_previous_keys(&self) -> Vec<&str> {
        self.previous_keys
            .iter()
            .map(String::as_str)
            .filter(|k| !k.trim().is_empty())
            .collect()
    }

    /// Check if key derivation is enabled
    #[must_use]
    pub fn is_key_derivation_enabled(&self) -> bool {
        self.key_derivation
            .as_ref()
            .is_some_and(|kd| kd.enabled && kd.salt.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_primary_key() {
        let config = EncryptionConfig {
            primary_key: "abc123".to_string(),
            previous_keys: vec![],
            key_derivation: None,
        };
        assert!(config.has_primary_key());

        let empty_config = EncryptionConfig {
            primary_key: "  ".to_string(),
            previous_keys: vec![],
            key_derivation: None,
        };
        assert!(!empty_config.has_primary_key());
    }

    #[test]
    fn test_valid_previous_keys() {
        let config = EncryptionConfig {
            primary_key: "primary".to_string(),
            previous_keys: vec![
                "key1".to_string(),
                "".to_string(),   // empty, should be filtered
                "  ".to_string(), // whitespace, should be filtered
                "key2".to_string(),
            ],
            key_derivation: None,
        };

        let valid = config.valid_previous_keys();
        assert_eq!(valid, vec!["key1", "key2"]);
    }

    #[test]
    fn test_key_derivation_enabled() {
        let config_disabled = EncryptionConfig {
            primary_key: "key".to_string(),
            previous_keys: vec![],
            key_derivation: None,
        };
        assert!(!config_disabled.is_key_derivation_enabled());

        let config_no_salt = EncryptionConfig {
            primary_key: "key".to_string(),
            previous_keys: vec![],
            key_derivation: Some(KeyDerivationConfig {
                enabled: true,
                salt: None,
            }),
        };
        assert!(!config_no_salt.is_key_derivation_enabled());

        let config_enabled = EncryptionConfig {
            primary_key: "key".to_string(),
            previous_keys: vec![],
            key_derivation: Some(KeyDerivationConfig {
                enabled: true,
                salt: Some("salt".to_string()),
            }),
        };
        assert!(config_enabled.is_key_derivation_enabled());
    }

    #[test]
    fn test_deserialize_from_yaml() {
        let yaml = r#"
primary_key: "abc123def456"
previous_keys:
  - "old_key_1"
  - "old_key_2"
key_derivation:
  enabled: true
  salt: "my_salt"
"#;
        let config: EncryptionConfig = serde_yaml::from_str(yaml).unwrap();

        assert_eq!(config.primary_key, "abc123def456");
        assert_eq!(config.previous_keys.len(), 2);
        assert!(config.is_key_derivation_enabled());
    }

    #[test]
    fn test_deserialize_minimal() {
        let yaml = r#"
primary_key: "abc123def456"
"#;
        let config: EncryptionConfig = serde_yaml::from_str(yaml).unwrap();

        assert_eq!(config.primary_key, "abc123def456");
        assert!(config.previous_keys.is_empty());
        assert!(!config.is_key_derivation_enabled());
    }
}
