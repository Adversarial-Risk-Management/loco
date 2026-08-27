//! AES-256-GCM encryption implementation
//!
//! This module provides authenticated encryption using AES-256-GCM (AEAD).
//! Each encryption operation generates a unique nonce for non-deterministic encryption.

use std::io::Read;

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    AeadCore, Aes256Gcm, Nonce,
};
use flate2::{read::ZlibDecoder, write::ZlibEncoder, Compression};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::{
    errors::{EncryptionError, EncryptionResult},
    format::{EncryptedValue, CURRENT_ENVELOPE_VERSION},
};

type HmacSha256 = Hmac<Sha256>;

/// Fixed domain separator prefixed to the header-authenticating associated
/// data. Keeps the header bytes from ever being confused with caller AAD or
/// with a future associated-data scheme.
const AAD_HEADER_DOMAIN: &[u8] = b"loco-enc-hdr\x00";

/// Lowest envelope version that folds its headers into the AEAD data.
///
/// Values written below this (legacy `v=1` and the pre-versioned format)
/// authenticate only the caller-supplied AAD and are read back the same way.
pub const HEADER_AUTH_MIN_VERSION: u8 = 2;

/// Build the associated data that authenticates the envelope's interpretation
/// flags alongside any caller-supplied AAD.
///
/// The encoding is `domain || version || deterministic || compressed ||
/// user_aad`. The domain and the three flag bytes are fixed-width, so the
/// boundary with `user_aad` is unambiguous without a length prefix. Encryption
/// and decryption must build this identically; because the flags are baked
/// into the tag, flipping `d`/`c`/`v` in storage makes authentication fail.
fn header_aad(version: u8, deterministic: bool, compressed: bool, user_aad: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(AAD_HEADER_DOMAIN.len() + 3 + user_aad.len());
    out.extend_from_slice(AAD_HEADER_DOMAIN);
    out.push(version);
    out.push(u8::from(deterministic));
    out.push(u8::from(compressed));
    out.extend_from_slice(user_aad);
    out
}

/// Plaintext byte threshold under which compression is skipped because the
/// zlib header overhead (~10 bytes) overwhelms any savings. Matches Rails'
/// `THRESHOLD_TO_JUSTIFY_COMPRESSION`.
pub const COMPRESS_THRESHOLD: usize = 140;

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
/// * `aad` - Additional Authenticated Data bound to the ciphertext. Pass `&[]`
///   for no binding (the default at the model layer). When non-empty, the
///   same AAD must be supplied to [`decrypt`] or authentication will fail —
///   this is what defeats ciphertext-relocation attacks.
///
/// # Returns
/// The encrypted value as a JSON string in Rails-compatible format
///
/// # Errors
/// Returns an error if encryption fails or key is invalid
pub fn encrypt(
    plaintext: &str,
    key: &[u8],
    key_id: Option<String>,
    aad: &[u8],
) -> EncryptionResult<String> {
    validate_key(key)?;

    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| EncryptionError::InvalidKey(e.to_string()))?;

    // 96-bit nonce from OS CSPRNG. Random nonces are safe for up to ~2^32
    // encryptions per key (NIST SP 800-38D); rotate keys before that bound.
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    // Bind the envelope's version and (here unset) flags into the auth data so
    // the headers can't be tampered with independently of the ciphertext.
    let aad = header_aad(CURRENT_ENVELOPE_VERSION, false, false, aad);
    let payload = aes_gcm::aead::Payload {
        msg: plaintext.as_bytes(),
        aad: &aad,
    };
    let ciphertext_with_tag = cipher
        .encrypt(&nonce, payload)
        .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;

    // Split ciphertext and auth tag (AES-GCM appends the tag at the end)
    let (ciphertext, auth_tag) = ciphertext_with_tag.split_at(ciphertext_with_tag.len() - TAG_SIZE);

    let encrypted = EncryptedValue::new(ciphertext, &nonce, auth_tag, key_id);
    encrypted.to_json()
}

/// Decrypt an encrypted value using AES-256-GCM
///
/// # Arguments
/// * `encrypted_json` - The encrypted value as a JSON string
/// * `key` - The 32-byte encryption key
/// * `aad` - Additional Authenticated Data that must match the value used at
///   encryption time. Pass `&[]` if no AAD was bound.
///
/// # Returns
/// The decrypted plaintext
///
/// # Errors
/// Returns an error if decryption fails, format is invalid, key is wrong, or
/// the supplied AAD does not match what was bound at encryption.
pub fn decrypt(encrypted_json: &str, key: &[u8], aad: &[u8]) -> EncryptionResult<String> {
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

    // Rebuild the associated data the same way the writer did. For v2+ that
    // means re-deriving it from the stored version and flags; if an attacker
    // flipped `d`/`c`/`v`, the reconstructed AAD no longer matches the tag and
    // authentication fails here. Legacy values (v1 / pre-versioned) bound only
    // the caller AAD, so we use it unchanged.
    let version = encrypted.h.v.unwrap_or(0);
    let auth_data = if version >= HEADER_AUTH_MIN_VERSION {
        header_aad(
            version,
            encrypted.is_deterministic(),
            encrypted.is_compressed(),
            aad,
        )
    } else {
        aad.to_vec()
    };

    let payload = aes_gcm::aead::Payload {
        msg: ciphertext_with_tag.as_ref(),
        aad: &auth_data,
    };
    let plaintext_bytes = cipher
        .decrypt(&nonce, payload)
        .map_err(|e| EncryptionError::DecryptionFailed(e.to_string()))?;

    let bytes = if encrypted.is_compressed() {
        // No pre-sized capacity: `len * 2` could overflow usize on a large
        // payload, and the decompressed size is unknown anyway. The
        // compressed bytes are AES-GCM-authenticated, so only a key holder
        // could craft a value that reaches this point.
        let mut decoder = ZlibDecoder::new(plaintext_bytes.as_slice());
        let mut out = Vec::new();
        decoder
            .read_to_end(&mut out)
            .map_err(|e| EncryptionError::DecryptionFailed(format!("decompression: {e}")))?;
        out
    } else {
        plaintext_bytes
    };

    String::from_utf8(bytes)
        .map_err(|e| EncryptionError::DecryptionFailed(format!("invalid UTF-8: {e}")))
}

/// Encrypt plaintext using AES-256-GCM, applying zlib `deflate` compression
/// when the plaintext is large enough to benefit.
///
/// Compression is skipped when the plaintext is shorter than
/// [`COMPRESS_THRESHOLD`] (140 bytes). When applied, the envelope header
/// `h.c` is set to `true` so [`decrypt`] can reverse it.
///
/// # Errors
/// Returns an error if compression, key setup, or AES-GCM encryption fails.
pub fn encrypt_compressed(
    plaintext: &str,
    key: &[u8],
    key_id: Option<String>,
    aad: &[u8],
) -> EncryptionResult<String> {
    if plaintext.len() < COMPRESS_THRESHOLD {
        return encrypt(plaintext, key, key_id, aad);
    }

    validate_key(key)?;

    // Deflate the plaintext bytes. Default compression level is a reasonable
    // tradeoff between size and CPU; matches Rails' `Zlib::Deflate.deflate`
    // default.
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    std::io::Write::write_all(&mut encoder, plaintext.as_bytes())
        .map_err(|e| EncryptionError::EncryptionFailed(format!("compression: {e}")))?;
    let compressed = encoder
        .finish()
        .map_err(|e| EncryptionError::EncryptionFailed(format!("compression finish: {e}")))?;

    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| EncryptionError::InvalidKey(e.to_string()))?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    // Authenticate the compressed flag we are about to set, so it can't be
    // cleared in storage to make `decrypt` skip inflation and return garbage.
    let aad = header_aad(CURRENT_ENVELOPE_VERSION, false, true, aad);
    let payload = aes_gcm::aead::Payload {
        msg: compressed.as_slice(),
        aad: &aad,
    };
    let ciphertext_with_tag = cipher
        .encrypt(&nonce, payload)
        .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;
    let (ciphertext, auth_tag) = ciphertext_with_tag.split_at(ciphertext_with_tag.len() - TAG_SIZE);

    let mut envelope = EncryptedValue::new(ciphertext, &nonce, auth_tag, key_id);
    envelope.h.c = Some(true);
    envelope.to_json()
}

/// Encrypt plaintext deterministically using AES-256-GCM with an
/// HMAC-SHA256-derived IV.
///
/// Produces the same ciphertext for identical `(key, aad, plaintext)` inputs,
/// enabling equality queries on encrypted columns. The IV is
/// `HMAC-SHA256(key, len(aad) || aad || plaintext)[..12]`.
///
/// # Arguments
/// * `plaintext` - The data to encrypt
/// * `key` - The 32-byte encryption key (typically derived from the
///   deterministic master)
/// * `key_id` - Optional key identifier for key rotation support
///
/// # Returns
/// The encrypted value as a JSON string with `h.d = true`.
///
/// # Errors
/// Returns an error if encryption fails or the key is invalid.
pub fn encrypt_deterministic(
    plaintext: &str,
    key: &[u8],
    key_id: Option<String>,
    aad: &[u8],
) -> EncryptionResult<String> {
    validate_key(key)?;

    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| EncryptionError::InvalidKey(e.to_string()))?;

    // Derive a stable IV from the plaintext (and any AAD, so AAD-bound
    // ciphertexts produce different IVs from non-bound ones for the same
    // plaintext). Using the encryption key as the HMAC key binds the IV to
    // this specific key — rotating the key produces a different IV even for
    // identical plaintexts.
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;
    // Length-prefix the AAD before the plaintext so that (aad, plaintext)
    // pairs whose concatenations would otherwise be equal — e.g.
    // ("users", ":x") vs ("users:", "x") — cannot derive the same IV. Without
    // the prefix the boundary is ambiguous; with it the HMAC input is an
    // unambiguous encoding of the pair.
    mac.update(&(aad.len() as u64).to_be_bytes());
    mac.update(aad);
    mac.update(plaintext.as_bytes());
    let tag = mac.finalize().into_bytes();
    // Infallible: the HMAC output (32 bytes) is longer than `NONCE_SIZE`.
    let iv_bytes: [u8; NONCE_SIZE] = tag[..NONCE_SIZE]
        .try_into()
        .map_err(|_| EncryptionError::EncryptionFailed("invalid derived IV size".to_string()))?;
    let nonce = Nonce::from(iv_bytes);

    // The IV derivation above intentionally uses the raw caller AAD so the
    // ciphertext stays stable and queryable. The GCM auth data additionally
    // binds the version and the deterministic flag; this does not affect the
    // IV, so determinism (and cross-process query matching) is preserved.
    let aad = header_aad(CURRENT_ENVELOPE_VERSION, true, false, aad);
    let payload = aes_gcm::aead::Payload {
        msg: plaintext.as_bytes(),
        aad: &aad,
    };
    let ciphertext_with_tag = cipher
        .encrypt(&nonce, payload)
        .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;

    let (ciphertext, auth_tag) = ciphertext_with_tag.split_at(ciphertext_with_tag.len() - TAG_SIZE);

    let mut encrypted = EncryptedValue::new(ciphertext, &nonce, auth_tag, key_id);
    encrypted.h.d = Some(true);
    encrypted.to_json()
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
    // Operate on bytes: a hex key is ASCII by definition, and slicing a `str`
    // on byte offsets (below) would panic on a multibyte char straddling an
    // even offset. Reject non-ASCII up front so a stray Unicode character
    // yields a clean error instead of a panic.
    let bytes = hex.as_bytes();
    if bytes.len() != KEY_SIZE * 2 {
        return Err(EncryptionError::InvalidKey(format!(
            "hex key must be {} characters (for {} bytes), got {}",
            KEY_SIZE * 2,
            KEY_SIZE,
            bytes.len()
        )));
    }

    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            // Each pair must be valid UTF-8/ASCII before it is parsed as hex.
            let s = std::str::from_utf8(pair)
                .map_err(|_| EncryptionError::InvalidKey("invalid hex: non-ASCII".to_string()))?;
            u8::from_str_radix(s, 16)
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

        let encrypted = encrypt(plaintext, &key, None, b"").unwrap();
        let decrypted = decrypt(&encrypted, &key, b"").unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_is_non_deterministic() {
        let key = test_key();
        let plaintext = "Same input";

        let encrypted1 = encrypt(plaintext, &key, None, b"").unwrap();
        let encrypted2 = encrypt(plaintext, &key, None, b"").unwrap();

        // Different nonces should produce different ciphertexts
        assert_ne!(encrypted1, encrypted2);

        // But both should decrypt to the same plaintext
        assert_eq!(decrypt(&encrypted1, &key, b"").unwrap(), plaintext);
        assert_eq!(decrypt(&encrypted2, &key, b"").unwrap(), plaintext);
    }

    #[test]
    fn test_decrypt_with_wrong_key_fails() {
        let key1 = test_key();
        let mut key2 = test_key();
        key2[0] = 0xff; // Modify first byte

        let plaintext = "Secret data";
        let encrypted = encrypt(plaintext, &key1, None, b"").unwrap();

        // Decryption with wrong key should fail
        assert!(decrypt(&encrypted, &key2, b"").is_err());
    }

    #[test]
    fn test_invalid_key_size() {
        let short_key = vec![0u8; 16]; // 16 bytes instead of 32
        let plaintext = "test";

        assert!(encrypt(plaintext, &short_key, None, b"").is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let key = test_key();
        let plaintext = "";

        let encrypted = encrypt(plaintext, &key, None, b"").unwrap();
        let decrypted = decrypt(&encrypted, &key, b"").unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_unicode_plaintext() {
        let key = test_key();
        let plaintext = "Hello, \u{4e16}\u{754c}! \u{1f600}"; // "Hello, 世界! 😀"

        let encrypted = encrypt(plaintext, &key, None, b"").unwrap();
        let decrypted = decrypt(&encrypted, &key, b"").unwrap();

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
    fn test_parse_hex_key_non_ascii_does_not_panic() {
        // 61 ASCII chars + one 3-byte char = 64 bytes, so the byte-length gate
        // passes but a naive str byte-slice would split the multibyte char.
        // Must return an error, not panic.
        let mut s = "a".repeat(61);
        s.push('\u{20AC}'); // '€' is 3 bytes -> total 64 bytes
        assert_eq!(s.len(), 64);
        assert!(parse_hex_key(&s).is_err());
    }

    #[test]
    fn test_encrypt_with_key_id() {
        let key = test_key();
        let plaintext = "test";

        let encrypted = encrypt(plaintext, &key, Some("primary".to_string()), b"").unwrap();

        // Verify key_id is present in the encrypted value
        let parsed = EncryptedValue::from_json(&encrypted).unwrap();
        assert_eq!(parsed.key_id(), Some("primary"));

        // Should still decrypt correctly
        let decrypted = decrypt(&encrypted, &key, b"").unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = test_key();
        let plaintext = "Secret";

        let encrypted = encrypt(plaintext, &key, None, b"").unwrap();
        let mut parsed = EncryptedValue::from_json(&encrypted).unwrap();

        // Tamper with the ciphertext
        parsed.p = "dGFtcGVyZWQ=".to_string(); // "tampered" in base64

        let tampered_json = parsed.to_json().unwrap();
        assert!(decrypt(&tampered_json, &key, b"").is_err());
    }

    #[test]
    fn test_encrypt_deterministic_is_stable() {
        let key = test_key();
        let plaintext = "alice@example.com";

        let a = encrypt_deterministic(plaintext, &key, None, b"").unwrap();
        let b = encrypt_deterministic(plaintext, &key, None, b"").unwrap();
        assert_eq!(a, b, "same plaintext must produce same ciphertext");

        let parsed = EncryptedValue::from_json(&a).unwrap();
        assert!(parsed.is_deterministic(), "envelope should mark h.d=true");
    }

    #[test]
    fn test_encrypt_deterministic_differs_per_plaintext() {
        let key = test_key();
        let a = encrypt_deterministic("foo@example.com", &key, None, b"").unwrap();
        let b = encrypt_deterministic("bar@example.com", &key, None, b"").unwrap();
        assert_ne!(
            a, b,
            "different plaintexts must produce different ciphertexts"
        );
    }

    #[test]
    fn test_encrypt_deterministic_roundtrips() {
        let key = test_key();
        let plaintext = "sensitive";
        let encrypted = encrypt_deterministic(plaintext, &key, None, b"").unwrap();
        assert_eq!(decrypt(&encrypted, &key, b"").unwrap(), plaintext);
    }

    #[test]
    fn test_encrypt_compressed_below_threshold_skips_compression() {
        let key = test_key();
        // Short plaintext: compression is skipped, so the envelope is
        // indistinguishable from a regular encrypt() call.
        let short = "tiny";
        let env = encrypt_compressed(short, &key, None, b"").unwrap();
        let parsed = EncryptedValue::from_json(&env).unwrap();
        assert!(
            !parsed.is_compressed(),
            "h.c should be unset below threshold"
        );
        assert_eq!(decrypt(&env, &key, b"").unwrap(), short);
    }

    #[test]
    fn test_encrypt_compressed_above_threshold_compresses() {
        let key = test_key();
        // Highly compressible payload longer than COMPRESS_THRESHOLD: zlib
        // should make the output meaningfully smaller than the plaintext.
        let plaintext: String = "a".repeat(2048);
        let env = encrypt_compressed(&plaintext, &key, None, b"").unwrap();
        let parsed = EncryptedValue::from_json(&env).unwrap();
        assert!(parsed.is_compressed(), "h.c must be set above threshold");

        // Round-trips through decrypt().
        assert_eq!(decrypt(&env, &key, b"").unwrap(), plaintext);

        // Compressed ciphertext should be substantially smaller than the
        // plaintext for a repetitive payload of this size.
        let payload_len = parsed.ciphertext().unwrap().len();
        assert!(
            payload_len < plaintext.len() / 4,
            "expected compressed payload << plaintext (got {payload_len} vs {})",
            plaintext.len()
        );
    }

    #[test]
    fn test_compressed_envelope_authenticates_aad() {
        let key = test_key();
        let plaintext: String = "loco-".repeat(50);
        let env = encrypt_compressed(&plaintext, &key, None, b"users:bio").unwrap();
        assert_eq!(decrypt(&env, &key, b"users:bio").unwrap(), plaintext);
        assert!(decrypt(&env, &key, b"other").is_err());
    }

    #[test]
    fn test_aad_must_match_on_decrypt() {
        let key = test_key();
        let plaintext = "secret";

        let with_aad = encrypt(plaintext, &key, None, b"users:ssn").unwrap();

        // Same AAD: decrypts.
        assert_eq!(decrypt(&with_aad, &key, b"users:ssn").unwrap(), plaintext);

        // Wrong AAD: GCM authentication fails.
        assert!(
            decrypt(&with_aad, &key, b"users:other").is_err(),
            "different AAD must fail authentication"
        );

        // Missing AAD: also fails.
        assert!(
            decrypt(&with_aad, &key, b"").is_err(),
            "empty AAD against bound ciphertext must fail"
        );
    }

    #[test]
    fn test_aad_unbound_ciphertext_decrypts_only_with_empty_aad() {
        let key = test_key();
        let plaintext = "secret";
        let unbound = encrypt(plaintext, &key, None, b"").unwrap();

        assert_eq!(decrypt(&unbound, &key, b"").unwrap(), plaintext);
        assert!(
            decrypt(&unbound, &key, b"users:ssn").is_err(),
            "supplying AAD against an unbound ciphertext must fail"
        );
    }

    #[test]
    fn test_deterministic_aad_changes_ciphertext() {
        let key = test_key();
        let plaintext = "alice@example.com";

        let a = encrypt_deterministic(plaintext, &key, None, b"users:email").unwrap();
        let b = encrypt_deterministic(plaintext, &key, None, b"users:other").unwrap();
        assert_ne!(
            a, b,
            "deterministic IV must absorb AAD so different AADs produce different ciphertexts"
        );

        assert_eq!(decrypt(&a, &key, b"users:email").unwrap(), plaintext);
        assert!(decrypt(&a, &key, b"users:other").is_err());
    }

    #[test]
    fn test_v2_envelope_is_current_version() {
        let key = test_key();
        let env = encrypt("hello", &key, None, b"").unwrap();
        let parsed = EncryptedValue::from_json(&env).unwrap();
        assert_eq!(parsed.h.v, Some(CURRENT_ENVELOPE_VERSION));
        assert!(CURRENT_ENVELOPE_VERSION >= HEADER_AUTH_MIN_VERSION);
    }

    #[test]
    fn test_tampered_compressed_flag_fails_authentication() {
        let key = test_key();

        // Flip `c` from set to unset on a genuinely compressed value.
        let plaintext: String = "loco-".repeat(64);
        let compressed = encrypt_compressed(&plaintext, &key, None, b"").unwrap();
        let mut parsed = EncryptedValue::from_json(&compressed).unwrap();
        assert!(parsed.is_compressed());
        parsed.h.c = None;
        assert!(
            decrypt(&parsed.to_json().unwrap(), &key, b"").is_err(),
            "clearing the compressed flag must fail authentication, not silently skip inflation"
        );

        // Flip `c` from unset to set on a non-compressed value.
        let plain = encrypt("short", &key, None, b"").unwrap();
        let mut parsed = EncryptedValue::from_json(&plain).unwrap();
        parsed.h.c = Some(true);
        assert!(
            decrypt(&parsed.to_json().unwrap(), &key, b"").is_err(),
            "setting the compressed flag must fail authentication"
        );
    }

    #[test]
    fn test_tampered_deterministic_flag_fails_authentication() {
        let key = test_key();
        let plain = encrypt("secret", &key, None, b"").unwrap();
        let mut parsed = EncryptedValue::from_json(&plain).unwrap();
        parsed.h.d = Some(true);
        assert!(
            decrypt(&parsed.to_json().unwrap(), &key, b"").is_err(),
            "flipping the deterministic flag must fail authentication"
        );
    }

    #[test]
    fn test_tampered_version_fails_authentication() {
        let key = test_key();
        let env = encrypt("secret", &key, None, b"").unwrap();
        let mut parsed = EncryptedValue::from_json(&env).unwrap();
        // Downgrade v2 -> v1: the reader would switch to the legacy
        // user-AAD-only path, which no longer matches the v2 tag.
        parsed.h.v = Some(1);
        assert!(
            decrypt(&parsed.to_json().unwrap(), &key, b"").is_err(),
            "downgrading the envelope version must fail authentication"
        );
    }

    #[test]
    fn test_legacy_v1_envelope_decrypts_with_user_aad_only() {
        // A pre-header-auth (v1) value: the tag was computed over the caller
        // AAD only. The reader must fall back to that path for v < 2 so
        // existing data written by older builds keeps decrypting.
        use aes_gcm::aead::Aead;
        let key = test_key();
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ct_with_tag = cipher
            .encrypt(
                &nonce,
                aes_gcm::aead::Payload {
                    msg: b"legacy value",
                    aad: b"",
                },
            )
            .unwrap();
        let (ct, tag) = ct_with_tag.split_at(ct_with_tag.len() - TAG_SIZE);
        let mut env = EncryptedValue::new(ct, nonce.as_slice(), tag, None);
        env.h.v = Some(1); // mark legacy; v < HEADER_AUTH_MIN_VERSION
        let json = env.to_json().unwrap();

        assert_eq!(decrypt(&json, &key, b"").unwrap(), "legacy value");
    }

    #[test]
    fn test_encrypt_deterministic_key_change_changes_iv() {
        let plaintext = "same-value";
        let mut k1 = test_key();
        let mut k2 = test_key();
        k2[0] ^= 0xff;

        let e1 = encrypt_deterministic(plaintext, &k1, None, b"").unwrap();
        let e2 = encrypt_deterministic(plaintext, &k2, None, b"").unwrap();
        assert_ne!(e1, e2, "IV must bind to the key as well as the plaintext");

        // Consume k1 so it isn't dropped as unused.
        k1[0] ^= 0;
        let _ = (k1, k2);
    }
}
