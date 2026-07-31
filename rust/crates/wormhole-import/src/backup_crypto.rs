//! Backup payload seal / unseal (PBKDF2-SHA256 + AES-256-GCM, 12-byte nonce).
//!
//! Mirrors C# `BackupService.SealPayload` / `UnsealPayload` — distinct from
//! mRemoteNG import crypto ([`crate::crypto`], 16-byte nonce + SHA1 PBKDF2).
//! Fail closed on malformed envelopes, iteration caps, and auth-tag mismatch.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use getrandom::fill;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::backup::BackupEncryptedPayload;

/// Default PBKDF2 iteration count written on export (C# `Pbkdf2Iterations`).
pub const PBKDF2_ITERATIONS: u32 = 600_000;

/// Max iterations accepted from untrusted files (C# `Pbkdf2MaxAcceptedIterations`).
pub const PBKDF2_MAX_ACCEPTED_ITERATIONS: u32 = 5_000_000;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;

/// Opaque decrypt failure — wrong password or tampered ciphertext (C# `BackupBadPasswordException`).
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("backup decrypt failed (wrong password or tampered ciphertext)")]
pub struct BackupDecryptError;

/// Seal UTF-8 payload bytes with a user password.
pub fn seal_payload(plaintext: &[u8], password: &str) -> BackupEncryptedPayload {
    let salt = random_bytes(SALT_LEN);
    let nonce_bytes = random_bytes(NONCE_LEN);
    let key = derive_key(password, &salt, PBKDF2_ITERATIONS);
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).expect("key length");
    let nonce = Nonce::try_from(nonce_bytes.as_slice()).expect("nonce length");
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .expect("encrypt");
    let (body, tag) = ciphertext.split_at(ciphertext.len() - TAG_LEN);
    BackupEncryptedPayload {
        kdf: "pbkdf2-sha256".into(),
        iterations: PBKDF2_ITERATIONS as i32,
        salt_b64: base64::engine::general_purpose::STANDARD.encode(salt),
        nonce_b64: base64::engine::general_purpose::STANDARD.encode(nonce_bytes),
        ciphertext_b64: base64::engine::general_purpose::STANDARD.encode(body),
        tag_b64: base64::engine::general_purpose::STANDARD.encode(tag),
    }
}

/// Unseal an encrypted backup envelope. Fail closed on any geometry / auth failure.
pub fn unseal_payload(sealed: &BackupEncryptedPayload, password: &str) -> Result<Vec<u8>, BackupDecryptError> {
    if !sealed.kdf.eq_ignore_ascii_case("pbkdf2-sha256") {
        return Err(BackupDecryptError);
    }

    let salt = decode_b64(&sealed.salt_b64)?;
    let nonce = decode_b64(&sealed.nonce_b64)?;
    let ciphertext = decode_b64(&sealed.ciphertext_b64)?;
    let tag = decode_b64(&sealed.tag_b64)?;

    let iterations = if sealed.iterations > 0 {
        sealed.iterations as u32
    } else {
        PBKDF2_ITERATIONS
    };
    if iterations > PBKDF2_MAX_ACCEPTED_ITERATIONS {
        return Err(BackupDecryptError);
    }

    if nonce.len() != NONCE_LEN
        || tag.len() < 12
        || tag.len() > 16
        || salt.is_empty()
        || ciphertext.is_empty()
    {
        return Err(BackupDecryptError);
    }

    let key = derive_key(password, &salt, iterations);
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| BackupDecryptError)?;
    let nonce_arr = Nonce::try_from(nonce.as_slice()).map_err(|_| BackupDecryptError)?;
    let mut combined = ciphertext;
    combined.extend_from_slice(&tag);
    cipher
        .decrypt(&nonce_arr, combined.as_ref())
        .map_err(|_| BackupDecryptError)
}

fn derive_key(password: &str, salt: &[u8], iterations: u32) -> Zeroizing<[u8; KEY_LEN]> {
    let normalized: String = password.nfc().collect();
    let password_bytes = normalized.as_bytes();
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    pbkdf2_hmac::<Sha256>(password_bytes, salt, iterations, key.as_mut());
    key
}

fn decode_b64(input: &str) -> Result<Vec<u8>, BackupDecryptError> {
    base64::engine::general_purpose::STANDARD
        .decode(input.trim())
        .map_err(|_| BackupDecryptError)
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    fill(&mut out).expect("OS RNG");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_seal_unseal() {
        let plain = br#"{"nodes":[]}"#;
        let sealed = seal_payload(plain, "backup-pw");
        let out = unseal_payload(&sealed, "backup-pw").unwrap();
        assert_eq!(out, plain);
    }

    #[test]
    fn wrong_password_fails_closed() {
        let sealed = seal_payload(b"secret", "right");
        assert!(unseal_payload(&sealed, "wrong").is_err());
    }

    #[test]
    fn excessive_iterations_fails_closed() {
        let mut sealed = seal_payload(b"x", "pw");
        sealed.iterations = (PBKDF2_MAX_ACCEPTED_ITERATIONS + 1) as i32;
        assert!(unseal_payload(&sealed, "pw").is_err());
    }

    #[test]
    fn truncated_tag_fails_closed() {
        let mut sealed = seal_payload(b"payload", "pw");
        let mut tag = decode_b64(&sealed.tag_b64).unwrap();
        tag.pop();
        sealed.tag_b64 = base64::engine::general_purpose::STANDARD.encode(tag);
        assert!(unseal_payload(&sealed, "pw").is_err());
    }

    #[test]
    fn decrypt_error_never_echoes_password() {
        let marker = "LEAK_MARKER_BACKUP_PW";
        let sealed = seal_payload(b"body", "correct");
        let err = unseal_payload(&sealed, marker).unwrap_err();
        let display = format!("{err}");
        let debug = format!("{err:?}");
        assert!(!display.contains(marker));
        assert!(!debug.contains(marker));
        assert!(!display.contains("body"));
    }
}
