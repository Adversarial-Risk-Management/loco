//! Rails-compatible encrypted value format
//!
//! This module provides serialization/deserialization for encrypted values
//! in a format compatible with Rails `ActiveRecord` Encryption.
//!
//! # Format
//!
//! Encrypted values are stored as JSON:
//! ```json
//! {
//!   "p": "base64-encoded-ciphertext",
//!   "h": {
//!     "v": 1,
//!     "iv": "base64-encoded-iv",
//!     "at": "base64-encoded-auth-tag",
//!     "i": "optional-key-id",
//!     "d": true
//!   }
//! }
//! ```
//!
//! Header keys:
//! - `v` — envelope version (`1` is current). Missing means the legacy
//!   pre-versioned format; reading is supported, writing always emits `v=1`.
//! - `iv` — AES-GCM nonce (12 bytes, base64).
//! - `at` — AES-GCM authentication tag (16 bytes, base64).
//! - `i` — optional key identifier for rotation. Rails uses this for the
//!   first 4 hex of `SHA1(key)`; this implementation uses semantic labels
//!   like `"primary"` / `"previous_0"`. The names match Rails; the values
//!   differ.
//! - `d` — set when the ciphertext was produced by deterministic
//!   encryption. Elided when false.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};

use super::errors::{EncryptionError, EncryptionResult};

/// Current envelope schema version emitted by [`EncryptedValue::new`].
pub const CURRENT_ENVELOPE_VERSION: u8 = 1;

/// Headers for encrypted value metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedHeaders {
    /// Envelope schema version. Missing on legacy pre-versioned writes;
    /// new writes always emit `v = 1`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v: Option<u8>,

    /// Base64-encoded initialization vector (nonce)
    pub iv: String,

    /// Base64-encoded authentication tag
    pub at: String,

    /// Optional key identifier for key rotation support
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "kid")]
    pub i: Option<String>,

    /// Set to `true` when the value was encrypted deterministically.
    ///
    /// Deterministic ciphertexts use an HMAC-derived IV rather than a random
    /// one, so the same plaintext always produces the same ciphertext under a
    /// given key. The flag lets `decrypt_fields` route to the deterministic
    /// key path on the way back.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub d: Option<bool>,

    /// Set to `true` when the plaintext was zlib-deflated before encryption.
    /// Decryption reverses the steps in `decrypt → inflate` order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub c: Option<bool>,
}

/// Rails-compatible encrypted value structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedValue {
    /// Base64-encoded ciphertext (payload)
    pub p: String,

    /// Headers containing IV, auth tag, and optional key ID
    pub h: EncryptedHeaders,
}

impl EncryptedValue {
    /// Create a new encrypted value from raw components
    ///
    /// # Arguments
    /// * `ciphertext` - The encrypted data bytes
    /// * `iv` - The initialization vector (nonce) bytes
    /// * `auth_tag` - The authentication tag bytes
    /// * `key_id` - Optional key identifier
    #[must_use]
    pub fn new(ciphertext: &[u8], iv: &[u8], auth_tag: &[u8], key_id: Option<String>) -> Self {
        Self {
            p: BASE64.encode(ciphertext),
            h: EncryptedHeaders {
                v: Some(CURRENT_ENVELOPE_VERSION),
                iv: BASE64.encode(iv),
                at: BASE64.encode(auth_tag),
                i: key_id,
                d: None,
                c: None,
            },
        }
    }

    /// Whether the envelope marks the ciphertext as deterministically
    /// encrypted.
    #[must_use]
    pub fn is_deterministic(&self) -> bool {
        self.h.d.unwrap_or(false)
    }

    /// Whether the envelope marks the plaintext as zlib-compressed before
    /// encryption.
    #[must_use]
    pub fn is_compressed(&self) -> bool {
        self.h.c.unwrap_or(false)
    }

    /// Parse an encrypted value from a JSON string
    ///
    /// # Errors
    /// Returns an error if the JSON is invalid, missing required fields, or
    /// declares an envelope version this build does not understand. Missing
    /// `h.v` is accepted (legacy pre-versioned format).
    pub fn from_json(json: &str) -> EncryptionResult<Self> {
        let value: Self = serde_json::from_str(json).map_err(|e| {
            EncryptionError::InvalidFormat(format!("failed to parse encrypted value: {e}"))
        })?;
        if let Some(v) = value.h.v
            && v > CURRENT_ENVELOPE_VERSION
        {
            return Err(EncryptionError::InvalidFormat(format!(
                "unsupported envelope version: {v} (this build supports up to \
                 v{CURRENT_ENVELOPE_VERSION})"
            )));
        }
        Ok(value)
    }

    /// Serialize to a JSON string
    ///
    /// # Errors
    /// Returns an error if serialization fails
    pub fn to_json(&self) -> EncryptionResult<String> {
        serde_json::to_string(self).map_err(EncryptionError::from)
    }

    /// Get the raw ciphertext bytes
    ///
    /// # Errors
    /// Returns an error if base64 decoding fails
    pub fn ciphertext(&self) -> EncryptionResult<Vec<u8>> {
        BASE64.decode(&self.p).map_err(EncryptionError::from)
    }

    /// Get the initialization vector bytes
    ///
    /// # Errors
    /// Returns an error if base64 decoding fails
    pub fn iv(&self) -> EncryptionResult<Vec<u8>> {
        BASE64.decode(&self.h.iv).map_err(EncryptionError::from)
    }

    /// Get the authentication tag bytes
    ///
    /// # Errors
    /// Returns an error if base64 decoding fails
    pub fn auth_tag(&self) -> EncryptionResult<Vec<u8>> {
        BASE64.decode(&self.h.at).map_err(EncryptionError::from)
    }

    /// Get the key identifier if present
    #[must_use]
    pub fn key_id(&self) -> Option<&str> {
        self.h.i.as_deref()
    }
}

/// Check if a string looks like an encrypted value (JSON with expected fields)
#[must_use]
pub fn is_encrypted_format(value: &str) -> bool {
    // Quick check before parsing
    if !value.starts_with('{') || !value.contains("\"p\"") || !value.contains("\"h\"") {
        return false;
    }
    EncryptedValue::from_json(value).is_ok()
}

/// Metadata about an encrypted value (for debugging)
#[derive(Debug, Clone)]
pub struct EncryptionMetadata {
    /// Whether a key ID is present
    pub has_key_id: bool,
    /// The key ID if present
    pub key_id: Option<String>,
    /// Length of the base64-encoded payload
    pub payload_len: usize,
    /// Length of the base64-encoded IV
    pub iv_len: usize,
    /// Length of the base64-encoded auth tag
    pub auth_tag_len: usize,
}

/// Debug utilities for encrypted values
///
/// These functions are useful for debugging encryption issues without
/// exposing sensitive data.
pub mod debug {
    use super::{EncryptedValue, EncryptionMetadata};

    /// Inspect an encrypted value's metadata without decrypting
    ///
    /// Returns `None` if the value is not in encrypted format.
    ///
    /// # Example
    /// ```rust,ignore
    /// if let Some(meta) = loco_rs::encryption::format::debug::inspect_encrypted(&encrypted_value) {
    ///     println!("Key ID: {:?}", meta.key_id);
    ///     println!("Payload length: {} bytes (base64)", meta.payload_len);
    /// }
    /// ```
    #[must_use]
    pub fn inspect_encrypted(value: &str) -> Option<EncryptionMetadata> {
        EncryptedValue::from_json(value)
            .ok()
            .map(|v| EncryptionMetadata {
                has_key_id: v.h.i.is_some(),
                key_id: v.h.i,
                payload_len: v.p.len(),
                iv_len: v.h.iv.len(),
                auth_tag_len: v.h.at.len(),
            })
    }

    /// Get a safe preview of an encrypted value for logging
    ///
    /// Returns a string like `"[ENCRYPTED: key_id=primary, payload=64 chars]"`
    /// that can be safely logged without exposing sensitive data.
    #[must_use]
    pub fn safe_preview(value: &str) -> String {
        match inspect_encrypted(value) {
            Some(meta) => {
                let key_info = meta
                    .key_id
                    .map_or_else(|| "no key_id".to_string(), |id| format!("key_id={id}"));
                format!(
                    "[ENCRYPTED: {}, payload={} chars]",
                    key_info, meta.payload_len
                )
            }
            None => "[NOT ENCRYPTED]".to_string(),
        }
    }

    /// Estimate the decrypted size of an encrypted value
    ///
    /// Returns an approximate size in bytes. The actual decrypted size
    /// may vary slightly due to base64 padding.
    #[must_use]
    pub fn estimate_decrypted_size(value: &str) -> Option<usize> {
        inspect_encrypted(value).map(|meta| {
            // Base64 encoding increases size by ~33%, so decoded size is ~75% of encoded
            (meta.payload_len * 3) / 4
        })
    }
}

/// Estimate the encrypted size for a given plaintext length
///
/// This is useful for planning database column sizes.
/// Encrypted values include JSON overhead, base64 encoding, IV, and auth tag.
///
/// # Example
/// ```rust
/// use loco_rs::encryption::format::estimate_encrypted_size;
///
/// // A 100-byte plaintext will need approximately this many bytes when encrypted
/// let estimated = estimate_encrypted_size(100);
/// assert!(estimated > 100); // Encrypted is always larger
/// ```
#[must_use]
pub fn estimate_encrypted_size(plaintext_len: usize) -> usize {
    // AES-GCM ciphertext is the same size as plaintext (stream cipher, no
    // padding). The 16-byte auth tag is stored separately in the envelope
    // under `h.at`, and the 12-byte IV under `h.iv`.
    let ciphertext_base64 = plaintext_len.div_ceil(3) * 4;
    let iv_base64 = 16; // 12 bytes -> 16 base64 chars
    let tag_base64 = 24; // 16 bytes -> 24 base64 chars

    // JSON structure overhead: {"p":"...","h":{"iv":"...","at":"..."}}
    // ~50 bytes for the JSON structure itself
    let json_overhead = 50;

    json_overhead + ciphertext_base64 + iv_base64 + tag_base64
}

#[cfg(test)]
mod tests {
    use super::debug::*;
    use super::*;

    #[test]
    fn test_encrypted_value_creation() {
        let ciphertext = b"encrypted data";
        let iv = b"123456789012"; // 12 bytes for AES-GCM
        let auth_tag = b"0123456789abcdef"; // 16 bytes

        let encrypted = EncryptedValue::new(ciphertext, iv, auth_tag, None);

        assert_eq!(encrypted.ciphertext().unwrap(), ciphertext);
        assert_eq!(encrypted.iv().unwrap(), iv);
        assert_eq!(encrypted.auth_tag().unwrap(), auth_tag);
        assert!(encrypted.key_id().is_none());
    }

    #[test]
    fn test_encrypted_value_with_key_id() {
        let ciphertext = b"data";
        let iv = b"123456789012";
        let auth_tag = b"0123456789abcdef";

        let encrypted = EncryptedValue::new(ciphertext, iv, auth_tag, Some("primary".to_string()));

        assert_eq!(encrypted.key_id(), Some("primary"));
    }

    #[test]
    fn test_json_round_trip() {
        let ciphertext = b"test data";
        let iv = b"123456789012";
        let auth_tag = b"0123456789abcdef";

        let original = EncryptedValue::new(ciphertext, iv, auth_tag, Some("key1".to_string()));
        let json = original.to_json().unwrap();
        let parsed = EncryptedValue::from_json(&json).unwrap();

        assert_eq!(parsed.ciphertext().unwrap(), ciphertext);
        assert_eq!(parsed.iv().unwrap(), iv);
        assert_eq!(parsed.auth_tag().unwrap(), auth_tag);
        assert_eq!(parsed.key_id(), Some("key1"));
    }

    #[test]
    fn test_rails_compatible_format() {
        // Example Rails-format JSON
        let rails_json =
            r#"{"p":"dGVzdCBkYXRh","h":{"iv":"MTIzNDU2Nzg5MDEy","at":"MDEyMzQ1Njc4OWFiY2RlZg=="}}"#;

        let parsed = EncryptedValue::from_json(rails_json).unwrap();
        assert_eq!(parsed.ciphertext().unwrap(), b"test data");
        assert_eq!(parsed.iv().unwrap(), b"123456789012");
    }

    #[test]
    fn test_is_encrypted_format() {
        assert!(is_encrypted_format(
            r#"{"p":"abc","h":{"iv":"def","at":"ghi"}}"#
        ));
        assert!(!is_encrypted_format("plain text"));
        assert!(!is_encrypted_format(r#"{"other": "json"}"#));
        assert!(!is_encrypted_format(""));
    }

    #[test]
    fn test_inspect_encrypted() {
        let json = r#"{"p":"dGVzdCBkYXRh","h":{"v":1,"iv":"MTIzNDU2Nzg5MDEy","at":"MDEyMzQ1Njc4OWFiY2RlZg==","i":"primary"}}"#;
        let meta = inspect_encrypted(json).unwrap();

        assert!(meta.has_key_id);
        assert_eq!(meta.key_id, Some("primary".to_string()));
        assert_eq!(meta.payload_len, "dGVzdCBkYXRh".len());
    }

    #[test]
    fn test_inspect_encrypted_accepts_legacy_kid_alias() {
        // Pre-versioning envelopes used `kid` instead of `i`. The serde
        // alias keeps them readable so existing data isn't stranded.
        let legacy = r#"{"p":"dGVzdCBkYXRh","h":{"iv":"MTIzNDU2Nzg5MDEy","at":"MDEyMzQ1Njc4OWFiY2RlZg==","kid":"primary"}}"#;
        let meta = inspect_encrypted(legacy).unwrap();
        assert!(meta.has_key_id);
        assert_eq!(meta.key_id, Some("primary".to_string()));
    }

    #[test]
    fn test_from_json_rejects_unknown_future_version() {
        // h.v=99 is not a version this build understands.
        let future = r#"{"p":"dGVzdA==","h":{"v":99,"iv":"MTIzNDU2Nzg5MDEy","at":"MDEyMzQ1Njc4OWFiY2RlZg=="}}"#;
        let err = EncryptedValue::from_json(future).unwrap_err();
        assert!(matches!(err, EncryptionError::InvalidFormat(_)));
    }

    #[test]
    fn test_from_json_accepts_missing_version() {
        // Legacy pre-versioned envelopes (no h.v field) must continue to work.
        let legacy =
            r#"{"p":"dGVzdA==","h":{"iv":"MTIzNDU2Nzg5MDEy","at":"MDEyMzQ1Njc4OWFiY2RlZg=="}}"#;
        let parsed = EncryptedValue::from_json(legacy).unwrap();
        assert_eq!(parsed.h.v, None);
    }

    #[test]
    fn test_new_envelope_carries_current_version() {
        let v = EncryptedValue::new(b"ct", b"123456789012", b"0123456789abcdef", None);
        assert_eq!(v.h.v, Some(CURRENT_ENVELOPE_VERSION));
    }

    #[test]
    fn test_inspect_encrypted_no_key_id() {
        let json = r#"{"p":"abc","h":{"iv":"def","at":"ghi"}}"#;
        let meta = inspect_encrypted(json).unwrap();

        assert!(!meta.has_key_id);
        assert!(meta.key_id.is_none());
    }

    #[test]
    fn test_inspect_encrypted_not_encrypted() {
        assert!(inspect_encrypted("plain text").is_none());
        assert!(inspect_encrypted("").is_none());
    }

    #[test]
    fn test_safe_preview() {
        let json = r#"{"p":"dGVzdCBkYXRh","h":{"v":1,"iv":"MTIzNDU2Nzg5MDEy","at":"MDEyMzQ1Njc4OWFiY2RlZg==","i":"primary"}}"#;
        let preview = safe_preview(json);

        assert!(preview.contains("[ENCRYPTED:"));
        assert!(preview.contains("key_id=primary"));
        assert!(preview.contains("payload="));
    }

    #[test]
    fn test_safe_preview_not_encrypted() {
        let preview = safe_preview("plain text");
        assert_eq!(preview, "[NOT ENCRYPTED]");
    }

    #[test]
    fn test_estimate_encrypted_size() {
        // A 100-byte plaintext should produce an encrypted value larger than 100 bytes
        let estimated = estimate_encrypted_size(100);
        assert!(estimated > 100);

        // Empty plaintext should still have overhead for JSON structure, IV, tag
        let empty_estimated = estimate_encrypted_size(0);
        assert!(empty_estimated > 0);
    }

    #[test]
    fn test_estimate_decrypted_size() {
        let json =
            r#"{"p":"dGVzdCBkYXRh","h":{"iv":"MTIzNDU2Nzg5MDEy","at":"MDEyMzQ1Njc4OWFiY2RlZg=="}}"#;
        let estimated = estimate_decrypted_size(json);

        // "dGVzdCBkYXRh" is base64 for "test data" (9 bytes)
        // Base64 length is 12, so estimated decrypted should be around 9
        assert!(estimated.is_some());
        let size = estimated.unwrap();
        assert!(size >= 8 && size <= 12); // Allow some margin for base64 calculation
    }
}
