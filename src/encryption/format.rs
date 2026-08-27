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
//!     "v": 2,
//!     "iv": "base64-encoded-iv",
//!     "at": "base64-encoded-auth-tag",
//!     "i": "optional-key-id",
//!     "d": true
//!   }
//! }
//! ```
//!
//! Header keys:
//! - `v` — envelope version, always `1`. The version and the `d`/`c` flags
//!   are bound into the AES-GCM associated data, so a storage-layer attacker
//!   cannot change them without failing authentication. Envelopes with any
//!   other version are rejected.
//! - `iv` — AES-GCM nonce (12 bytes, base64).
//! - `at` — AES-GCM authentication tag (16 bytes, base64).
//! - `i` — optional key identifier for rotation. Rails uses this for the
//!   first 4 hex of `SHA1(key)`; this implementation uses semantic labels
//!   like `"primary"` / `"previous_0"` / `"deterministic"`. The names match
//!   Rails; the values differ.
//! - `d` — set when the ciphertext was produced by deterministic
//!   encryption. Elided when false.
//! - `c` — set when the plaintext was zlib-deflated before encryption.
//!   Elided when false.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};

use super::{
    cipher::{NONCE_SIZE, TAG_SIZE},
    errors::{EncryptionError, EncryptionResult},
};

/// The envelope schema version, emitted by [`EncryptedValue::new`] and
/// required by [`EncryptedValue::from_json`].
///
/// The version and the `d`/`c` flags are folded into the AES-GCM associated
/// data (see [`crate::encryption::cipher`]), so they cannot be altered in
/// storage. A future format change bumps this constant and adds an explicit
/// migration; there is no fallback read path for other versions.
pub const ENVELOPE_VERSION: u8 = 1;

/// Headers for encrypted value metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedHeaders {
    /// Envelope schema version; always [`ENVELOPE_VERSION`].
    pub v: u8,

    /// Base64-encoded initialization vector (nonce)
    pub iv: String,

    /// Base64-encoded authentication tag
    pub at: String,

    /// Optional key identifier for key rotation support
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
                v: ENVELOPE_VERSION,
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
    /// Returns an error if the JSON is invalid, a field is missing, the
    /// version is not [`ENVELOPE_VERSION`], or `iv`/`at`/`p` are not base64
    /// of the expected sizes.
    pub fn from_json(json: &str) -> EncryptionResult<Self> {
        let value: Self = serde_json::from_str(json).map_err(|e| {
            EncryptionError::InvalidFormat(format!("failed to parse encrypted value: {e}"))
        })?;
        if value.h.v != ENVELOPE_VERSION {
            return Err(EncryptionError::InvalidFormat(format!(
                "unsupported envelope version {} (this build reads v{ENVELOPE_VERSION} only)",
                value.h.v
            )));
        }
        if value.iv()?.len() != NONCE_SIZE {
            return Err(EncryptionError::InvalidFormat(format!(
                "invalid IV size: expected {NONCE_SIZE} bytes"
            )));
        }
        if value.auth_tag()?.len() != TAG_SIZE {
            return Err(EncryptionError::InvalidFormat(format!(
                "invalid auth tag size: expected {TAG_SIZE} bytes"
            )));
        }
        value.ciphertext()?;
        Ok(value)
    }

    /// Parse a stored column value that may or may not be an envelope.
    ///
    /// Returns `Ok(None)` for values that do not have the envelope's JSON
    /// shape at all (plaintext), `Ok(Some(..))` for a valid envelope, and
    /// `Err` for a value that has the shape but fails validation — an
    /// unsupported version or malformed fields. The error matters: treating
    /// such a value as plaintext would re-encrypt it on save or hand it to a
    /// caller as if it were the decrypted value.
    ///
    /// # Errors
    /// Returns [`EncryptionError::InvalidFormat`] for a malformed envelope.
    pub fn parse_column(value: &str) -> EncryptionResult<Option<Self>> {
        if !looks_like_envelope(value) {
            return Ok(None);
        }
        Self::from_json(value).map(Some)
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

/// Cheap shape test: a JSON object carrying `p` and `h` keys.
fn looks_like_envelope(value: &str) -> bool {
    let value = value.trim_start();
    value.starts_with('{') && value.contains("\"p\"") && value.contains("\"h\"")
}

/// Whether a string is a valid encryption envelope.
///
/// Matching the JSON *shape* is not enough: organic user data could be JSON
/// with `p` and `h` keys. This requires the value to fully parse — current
/// version, and `iv`/`at` decoding to the exact AEAD sizes — constraints
/// organic data effectively never satisfies by accident. Model code should
/// prefer [`EncryptedValue::parse_column`], which distinguishes plaintext
/// from a malformed envelope instead of collapsing both to `false`.
#[must_use]
pub fn is_encrypted_format(value: &str) -> bool {
    matches!(EncryptedValue::parse_column(value), Ok(Some(_)))
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
            // Base64 encoding increases size by ~33%, so decoded size is ~75% of encoded.
            // Saturating: payload_len comes off the wire and could be large.
            meta.payload_len.saturating_mul(3) / 4
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
    // under `h.at`, and the 12-byte IV under `h.iv`. Saturating arithmetic
    // so an absurdly large `plaintext_len` returns usize::MAX rather than
    // overflow-panicking (debug) or wrapping to a tiny value (release).
    let ciphertext_base64 = (plaintext_len.saturating_add(2) / 3).saturating_mul(4);
    let iv_base64 = 16; // 12 bytes -> 16 base64 chars
    let tag_base64 = 24; // 16 bytes -> 24 base64 chars

    // JSON structure overhead: {"p":"...","h":{"iv":"...","at":"..."}}
    // ~50 bytes for the JSON structure itself
    let json_overhead: usize = 50;

    json_overhead
        .saturating_add(ciphertext_base64)
        .saturating_add(iv_base64)
        .saturating_add(tag_base64)
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
        let rails_json = r#"{"p":"dGVzdCBkYXRh","h":{"v":1,"iv":"MTIzNDU2Nzg5MDEy","at":"MDEyMzQ1Njc4OWFiY2RlZg=="}}"#;

        let parsed = EncryptedValue::from_json(rails_json).unwrap();
        assert_eq!(parsed.ciphertext().unwrap(), b"test data");
        assert_eq!(parsed.iv().unwrap(), b"123456789012");
    }

    #[test]
    fn test_is_encrypted_format() {
        // 12-byte iv + 16-byte at, both valid base64: a well-formed envelope.
        assert!(is_encrypted_format(
            r#"{"p":"dGVzdCBkYXRh","h":{"v":1,"iv":"MTIzNDU2Nzg5MDEy","at":"MDEyMzQ1Njc4OWFiY2RlZg=="}}"#
        ));
        assert!(!is_encrypted_format("plain text"));
        assert!(!is_encrypted_format(r#"{"other": "json"}"#));
        assert!(!is_encrypted_format(""));
    }

    #[test]
    fn test_is_encrypted_format_rejects_shape_only_match() {
        // Structurally an envelope (has `p` and `h`/`iv`/`at`) but `iv` and
        // `at` decode to 3 bytes, not the AEAD sizes. Organic JSON that merely
        // resembles the envelope must not be mistaken for ciphertext.
        let fake = r#"{"p":"aGVsbG8=","h":{"v":1,"iv":"YWJj","at":"YWJj"}}"#;
        assert!(!is_encrypted_format(fake));

        // Non-base64 iv/at also rejected.
        let not_b64 = r#"{"p":"abc","h":{"v":1,"iv":"def","at":"ghi"}}"#;
        assert!(!is_encrypted_format(not_b64));
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
    fn test_from_json_rejects_other_versions_and_missing_version() {
        for bad in [
            r#"{"p":"dGVzdA==","h":{"v":99,"iv":"MTIzNDU2Nzg5MDEy","at":"MDEyMzQ1Njc4OWFiY2RlZg=="}}"#,
            r#"{"p":"dGVzdA==","h":{"v":0,"iv":"MTIzNDU2Nzg5MDEy","at":"MDEyMzQ1Njc4OWFiY2RlZg=="}}"#,
            r#"{"p":"dGVzdA==","h":{"iv":"MTIzNDU2Nzg5MDEy","at":"MDEyMzQ1Njc4OWFiY2RlZg=="}}"#,
        ] {
            let err = EncryptedValue::from_json(bad).unwrap_err();
            assert!(
                matches!(err, EncryptionError::InvalidFormat(_)),
                "{bad}: {err}"
            );
        }
        // `kid` is unknown and ignored by serde; the value is still valid.
        let with_kid = r#"{"p":"dGVzdA==","h":{"v":1,"iv":"MTIzNDU2Nzg5MDEy","at":"MDEyMzQ1Njc4OWFiY2RlZg==","kid":"x"}}"#;
        assert!(EncryptedValue::from_json(with_kid)
            .unwrap()
            .key_id()
            .is_none());
    }

    #[test]
    fn test_parse_column_distinguishes_plaintext_from_bad_envelope() {
        assert_eq!(
            EncryptedValue::parse_column("hello").unwrap().map(|_| ()),
            None
        );
        assert_eq!(
            EncryptedValue::parse_column(r#"{"name":"x"}"#)
                .unwrap()
                .map(|_| ()),
            None
        );
        let valid = r#"{"p":"dGVzdA==","h":{"v":1,"iv":"MTIzNDU2Nzg5MDEy","at":"MDEyMzQ1Njc4OWFiY2RlZg=="}}"#;
        assert!(EncryptedValue::parse_column(valid).unwrap().is_some());
        // Envelope shape with an unsupported version is an error, not plaintext.
        let future = r#"{"p":"dGVzdA==","h":{"v":7,"iv":"MTIzNDU2Nzg5MDEy","at":"MDEyMzQ1Njc4OWFiY2RlZg=="}}"#;
        assert!(EncryptedValue::parse_column(future).is_err());
    }

    #[test]
    fn test_new_envelope_carries_current_version() {
        let v = EncryptedValue::new(b"ct", b"123456789012", b"0123456789abcdef", None);
        assert_eq!(v.h.v, ENVELOPE_VERSION);
    }

    #[test]
    fn test_inspect_encrypted_no_key_id() {
        let json = r#"{"p":"dGVzdA==","h":{"v":1,"iv":"MTIzNDU2Nzg5MDEy","at":"MDEyMzQ1Njc4OWFiY2RlZg=="}}"#;
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
        let json = r#"{"p":"dGVzdCBkYXRh","h":{"v":1,"iv":"MTIzNDU2Nzg5MDEy","at":"MDEyMzQ1Njc4OWFiY2RlZg=="}}"#;
        let estimated = estimate_decrypted_size(json);

        // "dGVzdCBkYXRh" is base64 for "test data" (9 bytes)
        // Base64 length is 12, so estimated decrypted should be around 9
        assert!(estimated.is_some());
        let size = estimated.unwrap();
        assert!(size >= 8 && size <= 12); // Allow some margin for base64 calculation
    }
}
