//! Encryption error types
//!
//! This module defines error types specific to field encryption operations.

use thiserror::Error;

/// Errors that can occur during encryption/decryption operations
#[derive(Error, Debug)]
pub enum EncryptionError {
    /// Invalid encryption key format or length
    #[error("invalid encryption key: {0}")]
    InvalidKey(String),

    /// Key not found or not configured
    #[error("encryption key not found: {0}")]
    KeyNotFound(String),

    /// Error during encryption operation
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),

    /// Error during decryption operation
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),

    /// Error during decryption of a specific field
    #[error("decryption failed for field '{field}': {cause}")]
    FieldDecryptionFailed {
        /// The field name that failed to decrypt
        field: String,
        /// The underlying cause
        cause: String,
        /// The key ID that was attempted (if known)
        key_id: Option<String>,
    },

    /// Invalid encrypted value format
    #[error("invalid encrypted value format: {0}")]
    InvalidFormat(String),

    /// Invalid encrypted value format with preview
    #[error("invalid encrypted value format for field '{field}': {reason} (value preview: {preview}...)")]
    InvalidFieldFormat {
        /// The field name with invalid format
        field: String,
        /// The reason for the format error
        reason: String,
        /// A preview of the invalid value (truncated)
        preview: String,
    },

    /// Base64 encoding/decoding error
    #[error("base64 error: {0}")]
    Base64(#[from] base64::DecodeError),

    /// JSON serialization/deserialization error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Configuration error
    #[error("encryption not configured: {0}")]
    NotConfigured(String),

    /// Key derivation error
    #[error("key derivation failed: {0}")]
    KeyDerivation(String),

    /// No keys available for decryption after trying all configured keys
    #[error("no keys could decrypt the value (tried {keys_tried} keys)")]
    AllKeysFailed {
        /// Number of keys that were attempted
        keys_tried: usize,
        /// The last error encountered
        last_error: String,
    },
}

impl EncryptionError {
    /// Create a field decryption error with context
    #[must_use]
    pub fn field_decryption_failed(
        field: impl Into<String>,
        cause: impl Into<String>,
        key_id: Option<String>,
    ) -> Self {
        Self::FieldDecryptionFailed {
            field: field.into(),
            cause: cause.into(),
            key_id,
        }
    }

    /// Create an invalid format error with field context
    #[must_use]
    pub fn invalid_field_format(
        field: impl Into<String>,
        reason: impl Into<String>,
        value: &str,
    ) -> Self {
        Self::InvalidFieldFormat {
            field: field.into(),
            reason: reason.into(),
            preview: value.chars().take(50).collect(),
        }
    }

    /// Create an all-keys-failed error
    #[must_use]
    pub fn all_keys_failed(keys_tried: usize, last_error: impl Into<String>) -> Self {
        Self::AllKeysFailed {
            keys_tried,
            last_error: last_error.into(),
        }
    }
}

/// Result type for encryption operations
pub type EncryptionResult<T> = std::result::Result<T, EncryptionError>;
