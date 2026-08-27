//! Encryption configuration
//!
//! Loaded from the application's YAML config. All three keys are required,
//! as in Rails Active Record Encryption:
//!
//! ```yaml
//! encryption:
//!   primary_key: {{ get_env(name="LOCO_ENCRYPTION_PRIMARY_KEY") }}
//!   deterministic_key: {{ get_env(name="LOCO_ENCRYPTION_DETERMINISTIC_KEY") }}
//!   key_derivation_salt: {{ get_env(name="LOCO_ENCRYPTION_SALT") }}
//!   previous_keys:
//!     - "{{ get_env(name="LOCO_ENCRYPTION_KEY_2024_01", default="") }}"
//! ```
//!
//! Generate each value with `openssl rand -hex 32`. Validation happens at
//! boot (see [`crate::encryption::key_provider::ConfigKeyProvider::new`]):
//! every key must be 64 hex characters, `deterministic_key` must differ from
//! `primary_key` and from every `previous_keys` entry, and a non-empty
//! `previous_keys` entry that is not a valid key is an error. Empty entries
//! (an unset templated env var) are skipped.

use serde::{Deserialize, Serialize};

/// Encryption configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EncryptionConfig {
    /// Master key for non-deterministic fields (32 bytes, hex-encoded).
    pub primary_key: String,

    /// Retired primary keys, used for decryption only. Decryption tries the
    /// primary first, then these in order; rows written under one of these
    /// are re-encrypted under the primary on their next save.
    #[serde(default)]
    pub previous_keys: Vec<String>,

    /// Master key for fields marked `deterministic` (32 bytes, hex-encoded).
    ///
    /// Deterministic encryption derives its IV from the plaintext under this
    /// key, so it must be distinct from every key used for random-IV
    /// encryption: a shared HKDF-derived field key across the two modes would
    /// risk AES-GCM nonce reuse.
    ///
    /// **Rotation is not supported for this key.** As in Rails ("Rotating
    /// keys is not supported for deterministic encryption"), changing it
    /// changes the ciphertext for the same plaintext and breaks equality
    /// queries, and there is no fallback list. Pick it once and keep it.
    pub deterministic_key: String,

    /// HKDF-SHA256 salt for per-field key derivation (32 bytes, hex-encoded).
    ///
    /// No field is ever encrypted with a master key directly: each field uses
    /// `HKDF(master, salt, info = column name)`. Changing the salt invalidates
    /// every existing ciphertext.
    pub key_derivation_salt: String,
}

impl EncryptionConfig {
    /// `previous_keys` without empty entries (an unset templated env var).
    #[must_use]
    pub fn previous_keys_present(&self) -> Vec<&str> {
        self.previous_keys
            .iter()
            .map(String::as_str)
            .filter(|k| !k.trim().is_empty())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_previous_keys_present_skips_empty_entries() {
        let config = EncryptionConfig {
            primary_key: "primary".to_string(),
            previous_keys: vec![
                "key1".to_string(),
                String::new(),
                "  ".to_string(),
                "key2".to_string(),
            ],
            deterministic_key: "det".to_string(),
            key_derivation_salt: "salt".to_string(),
        };
        assert_eq!(config.previous_keys_present(), vec!["key1", "key2"]);
    }

    #[test]
    fn test_deserialize_from_yaml() {
        let yaml = r#"
primary_key: "abc123def456"
deterministic_key: "det"
key_derivation_salt: "my_salt"
previous_keys:
  - "old_key_1"
  - ""
"#;
        let config: EncryptionConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.primary_key, "abc123def456");
        assert_eq!(config.deterministic_key, "det");
        assert_eq!(config.key_derivation_salt, "my_salt");
        assert_eq!(config.previous_keys.len(), 2);
        assert_eq!(config.previous_keys_present(), vec!["old_key_1"]);
    }

    #[test]
    fn test_all_three_keys_are_required() {
        for yaml in [
            "primary_key: a\ndeterministic_key: b\n",
            "primary_key: a\nkey_derivation_salt: c\n",
            "deterministic_key: b\nkey_derivation_salt: c\n",
        ] {
            assert!(
                serde_yaml::from_str::<EncryptionConfig>(yaml).is_err(),
                "{yaml}"
            );
        }
        let minimal = "primary_key: a\ndeterministic_key: b\nkey_derivation_salt: c\n";
        let config: EncryptionConfig = serde_yaml::from_str(minimal).unwrap();
        assert!(config.previous_keys.is_empty());
    }
}
