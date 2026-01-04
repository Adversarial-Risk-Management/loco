//! AES-256-GCM encryption implementation
//!
//! This module provides authenticated encryption using AES-256-GCM (AEAD).
//! Each encryption operation generates a unique nonce for non-deterministic encryption.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    AeadCore, Aes256Gcm, Nonce,
};

use super::{
    errors::{EncryptionError, EncryptionResult},
    format::EncryptedValue,
};

/// AES-256-GCM key size in bytes
pub const KEY_SIZE: usize = 32;

/// AES-GCM nonce size in bytes (96 bits)
pub const NONCE_SIZE: usize = 12;

/// AES-GCM authentication tag size in bytes
pub const TAG_SIZE: usize = 16;

/// Encrypt plaintext using AES-256-GCM
///
/// # Arguments
/// * `plaintext` - The data to encrypt
/// * `key` - The 32-byte encryption key
/// * `key_id` - Optional key identifier for key rotation support
///
/// # Returns
/// The encrypted value as a JSON string in Rails-compatible format
///
/// # Errors
/// Returns an error if encryption fails or key is invalid
pub fn encrypt(plaintext: &str, key: &[u8], key_id: Option<String>) -> EncryptionResult<String> {
    validate_key(key)?;

    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| EncryptionError::InvalidKey(e.to_string()))?;

    // 96-bit nonce from OS CSPRNG. Random nonces are safe for up to ~2^32
    // encryptions per key (NIST SP 800-38D); rotate keys before that bound.
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    // Encrypt the plaintext
    let ciphertext_with_tag = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;

    // Split ciphertext and auth tag
    // AES-GCM appends the tag at the end
    let (ciphertext, auth_tag) = ciphertext_with_tag.split_at(ciphertext_with_tag.len() - TAG_SIZE);

    // Create Rails-compatible encrypted value
    let encrypted = EncryptedValue::new(ciphertext, &nonce, auth_tag, key_id);
    encrypted.to_json()
}

/// Decrypt an encrypted value using AES-256-GCM
///
/// # Arguments
/// * `encrypted_json` - The encrypted value as a JSON string
/// * `key` - The 32-byte encryption key
///
/// # Returns
/// The decrypted plaintext
///
/// # Errors
/// Returns an error if decryption fails, format is invalid, or key is wrong
pub fn decrypt(encrypted_json: &str, key: &[u8]) -> EncryptionResult<String> {
    validate_key(key)?;

    let encrypted = EncryptedValue::from_json(encrypted_json)?;

    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| EncryptionError::InvalidKey(e.to_string()))?;

    let ciphertext = encrypted.ciphertext()?;
    let iv = encrypted.iv()?;
    let auth_tag = encrypted.auth_tag()?;

    // Validate IV size
    if iv.len() != NONCE_SIZE {
        return Err(EncryptionError::InvalidFormat(format!(
            "invalid IV size: expected {NONCE_SIZE}, got {}",
            iv.len()
        )));
    }

    // Validate auth tag size
    if auth_tag.len() != TAG_SIZE {
        return Err(EncryptionError::InvalidFormat(format!(
            "invalid auth tag size: expected {TAG_SIZE}, got {}",
            auth_tag.len()
        )));
    }

    // Infallible: `iv.len()` was validated as `NONCE_SIZE` above.
    let iv_bytes: [u8; NONCE_SIZE] = iv
        .as_slice()
        .try_into()
        .map_err(|_| EncryptionError::InvalidFormat("invalid IV size".to_string()))?;
    let nonce = Nonce::from(iv_bytes);

    // Reconstruct ciphertext with tag appended (as aes-gcm expects)
    let mut ciphertext_with_tag = ciphertext;
    ciphertext_with_tag.extend_from_slice(&auth_tag);

    // Decrypt
    let plaintext = cipher
        .decrypt(&nonce, ciphertext_with_tag.as_ref())
        .map_err(|e| EncryptionError::DecryptionFailed(e.to_string()))?;

    String::from_utf8(plaintext)
        .map_err(|e| EncryptionError::DecryptionFailed(format!("invalid UTF-8: {e}")))
}

/// Validate that a key is the correct size for AES-256
fn validate_key(key: &[u8]) -> EncryptionResult<()> {
    if key.len() != KEY_SIZE {
        return Err(EncryptionError::InvalidKey(format!(
            "key must be {KEY_SIZE} bytes, got {}",
            key.len()
        )));
    }
    Ok(())
}

/// Parse a hex-encoded key string into bytes
///
/// # Arguments
/// * `hex` - A 64-character hex string (representing 32 bytes)
///
/// # Errors
/// Returns an error if the hex string is invalid or wrong length
pub fn parse_hex_key(hex: &str) -> EncryptionResult<Vec<u8>> {
    let hex = hex.trim();
    if hex.len() != KEY_SIZE * 2 {
        return Err(EncryptionError::InvalidKey(format!(
            "hex key must be {} characters (for {} bytes), got {}",
            KEY_SIZE * 2,
            KEY_SIZE,
            hex.len()
        )));
    }

    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| EncryptionError::InvalidKey(format!("invalid hex: {e}")))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> Vec<u8> {
        // 32 bytes for AES-256
        vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ]
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = test_key();
        let plaintext = "Hello, World!";

        let encrypted = encrypt(plaintext, &key, None).unwrap();
        let decrypted = decrypt(&encrypted, &key).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_is_non_deterministic() {
        let key = test_key();
        let plaintext = "Same input";

        let encrypted1 = encrypt(plaintext, &key, None).unwrap();
        let encrypted2 = encrypt(plaintext, &key, None).unwrap();

        // Different nonces should produce different ciphertexts
        assert_ne!(encrypted1, encrypted2);

        // But both should decrypt to the same plaintext
        assert_eq!(decrypt(&encrypted1, &key).unwrap(), plaintext);
        assert_eq!(decrypt(&encrypted2, &key).unwrap(), plaintext);
    }

    #[test]
    fn test_decrypt_with_wrong_key_fails() {
        let key1 = test_key();
        let mut key2 = test_key();
        key2[0] = 0xff; // Modify first byte

        let plaintext = "Secret data";
        let encrypted = encrypt(plaintext, &key1, None).unwrap();

        // Decryption with wrong key should fail
        assert!(decrypt(&encrypted, &key2).is_err());
    }

    #[test]
    fn test_invalid_key_size() {
        let short_key = vec![0u8; 16]; // 16 bytes instead of 32
        let plaintext = "test";

        assert!(encrypt(plaintext, &short_key, None).is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let key = test_key();
        let plaintext = "";

        let encrypted = encrypt(plaintext, &key, None).unwrap();
        let decrypted = decrypt(&encrypted, &key).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_unicode_plaintext() {
        let key = test_key();
        let plaintext = "Hello, \u{4e16}\u{754c}! \u{1f600}"; // "Hello, 世界! 😀"

        let encrypted = encrypt(plaintext, &key, None).unwrap();
        let decrypted = decrypt(&encrypted, &key).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_parse_hex_key() {
        let hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let key = parse_hex_key(hex).unwrap();

        assert_eq!(key.len(), KEY_SIZE);
        assert_eq!(key[0], 0x00);
        assert_eq!(key[15], 0x0f);
        assert_eq!(key[31], 0x1f);
    }

    #[test]
    fn test_parse_hex_key_invalid_length() {
        let short_hex = "00010203";
        assert!(parse_hex_key(short_hex).is_err());
    }

    #[test]
    fn test_parse_hex_key_invalid_chars() {
        let invalid = "zz0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        assert!(parse_hex_key(invalid).is_err());
    }

    #[test]
    fn test_encrypt_with_key_id() {
        let key = test_key();
        let plaintext = "test";

        let encrypted = encrypt(plaintext, &key, Some("primary".to_string())).unwrap();

        // Verify key_id is present in the encrypted value
        let parsed = EncryptedValue::from_json(&encrypted).unwrap();
        assert_eq!(parsed.key_id(), Some("primary"));

        // Should still decrypt correctly
        let decrypted = decrypt(&encrypted, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = test_key();
        let plaintext = "Secret";

        let encrypted = encrypt(plaintext, &key, None).unwrap();
        let mut parsed = EncryptedValue::from_json(&encrypted).unwrap();

        // Tamper with the ciphertext
        parsed.p = "dGFtcGVyZWQ=".to_string(); // "tampered" in base64

        let tampered_json = parsed.to_json().unwrap();
        assert!(decrypt(&tampered_json, &key).is_err());
    }
}
