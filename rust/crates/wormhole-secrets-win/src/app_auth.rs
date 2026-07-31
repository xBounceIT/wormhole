//! App-authentication DPAPI store helpers (`app-auth.dpapi`).
//!
//! Entropy is always [`crate::APP_AUTHENTICATION_V1`]
//! (`Wormhole.AppAuthentication.v1`), matching
//! `DpapiAppAuthenticationDataProtector`.
//!
//! This module is the **stub unlock** surface for the Rust host: it can
//! protect/unprotect/read/write the verifier blob. Full PIN/password verify
//! (PBKDF2-SHA256, 600_000 iterations, JSON document shape) stays in a higher
//! layer — see C# `AppAuthenticationService`. Interactive Windows Hello UI is
//! documented in [`crate::hello::WINRT_HELLO_GAP`].

use std::fmt;
use std::path::Path;

use crate::dpapi::{
    protect, read_protected_file, unprotect, write_protected_file_atomic,
};
use crate::entropy::APP_AUTHENTICATION_V1;
use crate::paths::app_authentication_path;
use crate::Result;

/// Protect plaintext with app-auth entropy (CurrentUser DPAPI).
pub fn protect_app_authentication(plaintext: &[u8]) -> Result<Vec<u8>> {
    protect(plaintext, Some(APP_AUTHENTICATION_V1))
}

/// Unprotect an app-auth blob. Wrong entropy / corrupt → [`crate::SecretsError::DpapiUnprotect`].
pub fn unprotect_app_authentication(blob: &[u8]) -> Result<Vec<u8>> {
    unprotect(blob, Some(APP_AUTHENTICATION_V1))
}

/// Read + unprotect `%LOCALAPPDATA%\Wormhole\app-auth.dpapi`.
///
/// Missing file → `Ok(None)`. Corrupt / wrong entropy → error.
pub fn read_app_authentication_store() -> Result<Option<Vec<u8>>> {
    read_app_authentication_store_at(&app_authentication_path())
}

/// Read + unprotect a specific app-auth path (tests / alternate roots).
pub fn read_app_authentication_store_at(path: &Path) -> Result<Option<Vec<u8>>> {
    read_protected_file(path, Some(APP_AUTHENTICATION_V1))
}

/// Protect + atomic-write the app-auth store at the default path.
pub fn write_app_authentication_store(plaintext: &[u8]) -> Result<()> {
    write_app_authentication_store_at(&app_authentication_path(), plaintext)
}

/// Protect + atomic-write at `path` (tests / alternate roots).
pub fn write_app_authentication_store_at(path: &Path, plaintext: &[u8]) -> Result<()> {
    write_protected_file_atomic(path, plaintext, Some(APP_AUTHENTICATION_V1))
}

/// Outcome of a stub unlock against the DPAPI app-auth store.
///
/// `Debug` never echoes verifier plaintext — only length — so logging the
/// unlock result cannot leak the JSON document.
#[derive(Clone, PartialEq, Eq)]
pub enum AppAuthUnlock {
    /// Store missing — app lock has no verifier configured.
    Missing,
    /// Store unprotected successfully; caller verifies PIN/password against JSON.
    Unlocked {
        /// DPAPI-plaintext verifier document bytes (C# `AppAuthenticationDocument` JSON).
        plaintext: Vec<u8>,
    },
}

impl fmt::Debug for AppAuthUnlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => write!(f, "Missing"),
            Self::Unlocked { plaintext } => f
                .debug_struct("Unlocked")
                .field("plaintext_len", &plaintext.len())
                .finish(),
        }
    }
}

/// Stub unlock: unprotect `app-auth.dpapi` with [`APP_AUTHENTICATION_V1`].
///
/// Does **not** prompt Windows Hello and does **not** run PBKDF2 verify — those
/// belong to UI + `AppAuthenticationService` parity. Use this after Hello is
/// unavailable ([`crate::hello::check_hello_availability`]) or as the fallback
/// path once the user supplies a PIN/password to a higher layer.
pub fn unlock_app_authentication_store() -> Result<AppAuthUnlock> {
    unlock_app_authentication_store_at(&app_authentication_path())
}

/// Stub unlock against an explicit path (tests).
pub fn unlock_app_authentication_store_at(path: &Path) -> Result<AppAuthUnlock> {
    match read_app_authentication_store_at(path)? {
        None => Ok(AppAuthUnlock::Missing),
        Some(plaintext) => Ok(AppAuthUnlock::Unlocked { plaintext }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{protect, unprotect, SecretsError, BITWARDEN_BROWSER_SHARED_STORAGE_V1};

    #[cfg(windows)]
    #[test]
    fn protect_roundtrip_uses_app_auth_entropy() {
        let plain = br#"{"Version":1,"Pin":null,"Password":null}"#;
        let blob = protect_app_authentication(plain).expect("protect");
        assert_eq!(unprotect_app_authentication(&blob).unwrap(), plain);
        // Wrong / null entropy must fail (byte-compatible with C# protector).
        assert!(matches!(
            unprotect(&blob, None),
            Err(SecretsError::DpapiUnprotect)
        ));
        assert!(matches!(
            unprotect(&blob, Some(BITWARDEN_BROWSER_SHARED_STORAGE_V1)),
            Err(SecretsError::DpapiUnprotect)
        ));
    }

    #[cfg(windows)]
    #[test]
    fn wrong_entropy_blob_fails_unlock_without_leaking_secret() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app-auth.dpapi");
        let secret = b"top-secret-app-auth-verifier-json";
        // Write with Bitwarden entropy — must not unlock under app-auth entropy.
        crate::write_protected_file_atomic(&path, secret, Some(BITWARDEN_BROWSER_SHARED_STORAGE_V1))
            .unwrap();

        let err = unlock_app_authentication_store_at(&path).unwrap_err();
        assert!(matches!(err, SecretsError::DpapiUnprotect));
        let text = format!("{err} / {err:?}");
        assert!(!text.contains("top-secret"));
        assert!(!text.contains("verifier-json"));

        let err = unprotect_app_authentication(
            &protect(secret, Some(BITWARDEN_BROWSER_SHARED_STORAGE_V1)).unwrap(),
        )
        .unwrap_err();
        assert!(matches!(err, SecretsError::DpapiUnprotect));
        assert!(!format!("{err:?}").contains("top-secret"));
    }

    #[cfg(windows)]
    #[test]
    fn store_roundtrip_and_unlock_under_temp() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app-auth.dpapi");
        let plain = b"verifier-json-bytes";

        assert!(matches!(
            unlock_app_authentication_store_at(&path).unwrap(),
            AppAuthUnlock::Missing
        ));

        write_app_authentication_store_at(&path, plain).unwrap();
        let got = read_app_authentication_store_at(&path).unwrap();
        assert_eq!(got.as_deref(), Some(plain.as_slice()));

        match unlock_app_authentication_store_at(&path).unwrap() {
            AppAuthUnlock::Unlocked { plaintext } => assert_eq!(plaintext, plain),
            other => panic!("expected Unlocked, got {other:?}"),
        }
    }

    #[test]
    fn default_path_under_localappdata_wormhole() {
        let p = app_authentication_path();
        assert!(
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n == "app-auth.dpapi")
        );
        let s = p.to_string_lossy();
        assert!(
            s.contains("Wormhole"),
            "app-auth path must stay under Wormhole profile: {s}"
        );
        // Prefer LOCALAPPDATA when set (production); otherwise USERPROFILE\AppData\Local.
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            assert!(
                p.starts_with(&local),
                "app-auth path {p:?} must be under LOCALAPPDATA {local}"
            );
        }
    }

    #[test]
    fn unlock_debug_redacts_plaintext() {
        let secret = b"super-secret-pin-hash-material";
        let unlock = AppAuthUnlock::Unlocked {
            plaintext: secret.to_vec(),
        };
        let dbg = format!("{unlock:?}");
        assert!(!dbg.contains("super-secret"));
        assert!(!dbg.contains("pin-hash"));
        assert!(dbg.contains("plaintext_len"));
        assert!(dbg.contains(&secret.len().to_string()));
    }
}
