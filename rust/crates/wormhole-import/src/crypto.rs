//! mRemoteNG ConfVersion 2.7 password decrypt (AES-256-GCM, 16-byte nonce).
//!
//! Mirrors `Services/MRemoteNg/MRemoteNgCrypto.cs` / BouncyCastle `GcmBlockCipher`:
//! layout `salt(16) | nonce(16) | ciphertext | tag(16)`, AAD = salt,
//! KDF = PBKDF2-HMAC-SHA1 → 32-byte key.
//!
//! RustCrypto `aes-gcm` defaults to 12-byte nonces; we instantiate
//! `AesGcm<Aes256, U16>` so the nonce size matches mRemoteNG (same reason C#
//! cannot use `System.Security.Cryptography.AesGcm`). Fail closed on any
//! malformed / auth / UTF-8 failure — never forge plaintext.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::aes::cipher::consts::U16;
use aes_gcm::aes::Aes256;
use aes_gcm::{AesGcm, Nonce};
use base64::Engine;
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use thiserror::Error;
use zeroize::Zeroizing;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 16;
const TAG_LEN: usize = 16;
const KEY_LEN: usize = 32;
const MIN_BLOB_LEN: usize = SALT_LEN + NONCE_LEN + TAG_LEN;

/// AES-256-GCM with mRemoteNG's 16-byte nonce (not the NIST-recommended 12).
type Aes256Gcm16 = AesGcm<Aes256, U16>;

/// Opaque decrypt failure — malformed input, wrong password, bad tag, or non-UTF-8.
///
/// Deliberately single-variant so callers cannot distinguish auth failure from
/// truncation (matches C# `TryDecryptUtf8` returning `false`).
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error(
    "mRemoteNG AES-GCM password decrypt failed \
     (malformed ciphertext, wrong password, or invalid UTF-8; see docs/migration/12-import.md)"
)]
pub struct DecryptError;

/// Attempt to decrypt an mRemoteNG `Password` / `Protected` base64 blob.
///
/// Empty / whitespace-only ciphertext → `Ok(None)`. Non-empty failures →
/// [`DecryptError`] (never a forged plaintext).
pub fn decrypt_password_utf8(
    base64_cipher: &str,
    password: &str,
    kdf_iterations: i32,
) -> Result<Option<String>, DecryptError> {
    if base64_cipher.trim().is_empty() {
        return Ok(None);
    }
    if kdf_iterations <= 0 {
        return Err(DecryptError);
    }

    let blob = base64::engine::general_purpose::STANDARD
        .decode(base64_cipher.trim())
        .map_err(|_| DecryptError)?;

    if blob.len() < MIN_BLOB_LEN {
        return Err(DecryptError);
    }

    let (salt, rest) = blob.split_at(SALT_LEN);
    let (nonce_bytes, cipher_and_tag) = rest.split_at(NONCE_LEN);
    // cipher_and_tag = ciphertext || tag (tag is last TAG_LEN bytes).

    // Zeroizing: wipe on drop (incl. panic), matching C# CryptographicOperations.ZeroMemory in finally.
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    pbkdf2_hmac::<Sha1>(
        password.as_bytes(),
        salt,
        kdf_iterations as u32,
        key.as_mut(),
    );

    let cipher = Aes256Gcm16::new_from_slice(key.as_ref()).map_err(|_| DecryptError)?;
    let nonce = Nonce::<U16>::try_from(nonce_bytes).map_err(|_| DecryptError)?;
    let plain = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: cipher_and_tag,
                aad: salt,
            },
        )
        .map_err(|_| DecryptError)?;
    String::from_utf8(plain)
        .map_err(|_| DecryptError)
        .map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    const DEFAULT_PASSWORD: &str = "mR3m";
    const DEFAULT_ITERATIONS: i32 = 10_000;

    /// Deterministic encrypt matching C# `MRemoteNgCryptoTests.Encrypt` layout.
    fn encrypt_raw(
        plain: &[u8],
        password: &str,
        iterations: i32,
        salt: [u8; 16],
        nonce: [u8; 16],
    ) -> String {
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        pbkdf2_hmac::<Sha1>(password.as_bytes(), &salt, iterations as u32, key.as_mut());
        let cipher = Aes256Gcm16::new_from_slice(key.as_ref()).expect("key len");
        let nonce_arr = Nonce::<U16>::try_from(nonce.as_slice()).expect("nonce");
        let out = cipher
            .encrypt(
                &nonce_arr,
                Payload {
                    msg: plain,
                    aad: &salt,
                },
            )
            .expect("encrypt");
        let mut blob = Vec::with_capacity(SALT_LEN + NONCE_LEN + out.len());
        blob.extend_from_slice(&salt);
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&out);
        base64::engine::general_purpose::STANDARD.encode(blob)
    }

    fn encrypt(plain: &str, password: &str, iterations: i32, salt: [u8; 16], nonce: [u8; 16]) -> String {
        encrypt_raw(plain.as_bytes(), password, iterations, salt, nonce)
    }

    #[test]
    fn empty_cipher_is_none() {
        assert_eq!(decrypt_password_utf8("", "x", 1000).unwrap(), None);
        assert_eq!(decrypt_password_utf8("   ", "x", 1000).unwrap(), None);
    }

    #[test]
    fn roundtrip_recovers_plaintext() {
        let salt = [0x11; 16];
        let nonce = [0x22; 16];
        let encrypted = encrypt(
            "ThisIsProtected",
            DEFAULT_PASSWORD,
            DEFAULT_ITERATIONS,
            salt,
            nonce,
        );
        let plain =
            decrypt_password_utf8(&encrypted, DEFAULT_PASSWORD, DEFAULT_ITERATIONS).unwrap();
        assert_eq!(plain.as_deref(), Some("ThisIsProtected"));
    }

    #[test]
    fn wrong_password_fails_closed() {
        let encrypted = encrypt(
            "hunter2",
            DEFAULT_PASSWORD,
            DEFAULT_ITERATIONS,
            [0x33; 16],
            [0x44; 16],
        );
        assert!(
            decrypt_password_utf8(&encrypted, "notTheRightPassword", DEFAULT_ITERATIONS).is_err()
        );
    }

    #[test]
    fn wrong_iterations_fails_closed() {
        let encrypted = encrypt(
            "hunter2",
            DEFAULT_PASSWORD,
            DEFAULT_ITERATIONS,
            [0x55; 16],
            [0x66; 16],
        );
        assert!(decrypt_password_utf8(&encrypted, DEFAULT_PASSWORD, 1000).is_err());
    }

    #[test]
    fn malformed_base64_fails_closed() {
        assert!(
            decrypt_password_utf8("not!valid!base64!!", DEFAULT_PASSWORD, DEFAULT_ITERATIONS)
                .is_err()
        );
    }

    #[test]
    fn too_short_blob_fails_closed() {
        let bytes = [0u8; 20];
        let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
        assert!(decrypt_password_utf8(&b64, DEFAULT_PASSWORD, DEFAULT_ITERATIONS).is_err());
    }

    #[test]
    fn zero_iterations_fails_closed() {
        let encrypted = encrypt(
            "hunter2",
            DEFAULT_PASSWORD,
            DEFAULT_ITERATIONS,
            [0x77; 16],
            [0x88; 16],
        );
        assert!(decrypt_password_utf8(&encrypted, DEFAULT_PASSWORD, 0).is_err());
        assert!(decrypt_password_utf8(&encrypted, DEFAULT_PASSWORD, -1).is_err());
    }

    #[test]
    fn invalid_utf8_payload_fails_closed() {
        let encrypted = encrypt_raw(
            &[0x80, 0x80, 0x80],
            DEFAULT_PASSWORD,
            DEFAULT_ITERATIONS,
            [0x99; 16],
            [0xaa; 16],
        );
        assert!(decrypt_password_utf8(&encrypted, DEFAULT_PASSWORD, DEFAULT_ITERATIONS).is_err());
    }

    #[test]
    fn preserves_unicode() {
        let input = "P@ssw0rd—ünì©öđé 🚀";
        let encrypted = encrypt(
            input,
            DEFAULT_PASSWORD,
            DEFAULT_ITERATIONS,
            [0xbb; 16],
            [0xcc; 16],
        );
        let plain =
            decrypt_password_utf8(&encrypted, DEFAULT_PASSWORD, DEFAULT_ITERATIONS).unwrap();
        assert_eq!(plain.as_deref(), Some(input));
    }

    /// Known vector: fixed salt/nonce + password `import-pw`, 1000 iterations, plaintext `lab-secret`.
    /// Used by the sample fixture (`cipher-ssh`) so CI does not need a live encrypt step.
    #[test]
    fn known_fixture_vector_lab_secret() {
        let salt = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let nonce = [
            0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad,
            0xae, 0xaf,
        ];
        let encrypted = encrypt("lab-secret", "import-pw", 1000, salt, nonce);
        assert_eq!(
            encrypted,
            "AQIDBAUGBwgJCgsMDQ4PEKChoqOkpaanqKmqq6ytrq+KjLoePtVObXWf/NJg081njZIDGCuP33lsaA=="
        );
        let plain = decrypt_password_utf8(&encrypted, "import-pw", 1000).unwrap();
        assert_eq!(plain.as_deref(), Some("lab-secret"));
    }

    #[test]
    fn placeholder_aaaaaa_fails_closed() {
        assert!(decrypt_password_utf8("AAAAAA==", "any-password", 1000).is_err());
    }

    #[test]
    fn tampered_aad_salt_fails_closed() {
        let salt = [0x11; 16];
        let nonce = [0x22; 16];
        let encrypted = encrypt(
            "aad-secret",
            DEFAULT_PASSWORD,
            DEFAULT_ITERATIONS,
            salt,
            nonce,
        );
        let mut blob = base64::engine::general_purpose::STANDARD
            .decode(encrypted.trim())
            .unwrap();
        blob[0] ^= 0xff;
        let tampered = base64::engine::general_purpose::STANDARD.encode(&blob);
        assert!(
            decrypt_password_utf8(&tampered, DEFAULT_PASSWORD, DEFAULT_ITERATIONS).is_err()
        );
    }

    #[test]
    fn flipped_tag_byte_fails_closed() {
        let encrypted = encrypt(
            "tag-secret",
            DEFAULT_PASSWORD,
            DEFAULT_ITERATIONS,
            [0x33; 16],
            [0x44; 16],
        );
        let mut blob = base64::engine::general_purpose::STANDARD
            .decode(encrypted.trim())
            .unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xff;
        let tampered = base64::engine::general_purpose::STANDARD.encode(&blob);
        assert!(
            decrypt_password_utf8(&tampered, DEFAULT_PASSWORD, DEFAULT_ITERATIONS).is_err()
        );
    }

    #[test]
    fn truncated_tag_fails_closed() {
        let encrypted = encrypt(
            "trunc-secret",
            DEFAULT_PASSWORD,
            DEFAULT_ITERATIONS,
            [0x55; 16],
            [0x66; 16],
        );
        let mut blob = base64::engine::general_purpose::STANDARD
            .decode(encrypted.trim())
            .unwrap();
        let full_len = blob.len();
        blob.pop();
        assert_eq!(blob.len(), full_len - 1);
        assert!(blob.len() >= SALT_LEN + NONCE_LEN);
        let truncated = base64::engine::general_purpose::STANDARD.encode(&blob);
        assert!(
            decrypt_password_utf8(&truncated, DEFAULT_PASSWORD, DEFAULT_ITERATIONS).is_err()
        );
    }

    #[test]
    fn flipped_ciphertext_byte_fails_closed() {
        let encrypted = encrypt(
            "cipher-secret",
            DEFAULT_PASSWORD,
            DEFAULT_ITERATIONS,
            [0x77; 16],
            [0x88; 16],
        );
        let mut blob = base64::engine::general_purpose::STANDARD
            .decode(encrypted.trim())
            .unwrap();
        // First ciphertext byte sits after salt(16)+nonce(16).
        assert!(blob.len() > SALT_LEN + NONCE_LEN + TAG_LEN);
        blob[SALT_LEN + NONCE_LEN] ^= 0xff;
        let tampered = base64::engine::general_purpose::STANDARD.encode(&blob);
        assert!(
            decrypt_password_utf8(&tampered, DEFAULT_PASSWORD, DEFAULT_ITERATIONS).is_err()
        );
    }

    #[test]
    fn exactly_min_blob_with_empty_ciphertext_roundtrips() {
        // Empty plaintext → ciphertext empty, blob length == MIN_BLOB_LEN (salt|nonce|tag).
        let encrypted = encrypt(
            "",
            DEFAULT_PASSWORD,
            DEFAULT_ITERATIONS,
            [0xab; 16],
            [0xcd; 16],
        );
        let blob = base64::engine::general_purpose::STANDARD
            .decode(encrypted.trim())
            .unwrap();
        assert_eq!(blob.len(), MIN_BLOB_LEN);
        let plain =
            decrypt_password_utf8(&encrypted, DEFAULT_PASSWORD, DEFAULT_ITERATIONS).unwrap();
        assert_eq!(plain.as_deref(), Some(""));
    }

    #[test]
    fn decrypt_error_display_and_debug_do_not_echo_password() {
        let marker = "IMPORT_PW_LEAK_MARKER_XYZ";
        let encrypted = encrypt(
            "payload",
            DEFAULT_PASSWORD,
            DEFAULT_ITERATIONS,
            [0xde; 16],
            [0xad; 16],
        );
        let err = decrypt_password_utf8(&encrypted, marker, DEFAULT_ITERATIONS).unwrap_err();
        let display = format!("{err}");
        let debug = format!("{err:?}");
        assert!(!display.contains(marker), "{display}");
        assert!(!debug.contains(marker), "{debug}");
        assert!(!display.contains("payload"), "{display}");
        assert!(!display.contains(&encrypted), "{display}");
    }

    #[test]
    fn layout_constants_match_mremoteng_bouncy_castle() {
        assert_eq!(SALT_LEN, 16);
        assert_eq!(NONCE_LEN, 16);
        assert_eq!(TAG_LEN, 16);
        assert_eq!(KEY_LEN, 32);
        assert_eq!(MIN_BLOB_LEN, 48);
    }
}
