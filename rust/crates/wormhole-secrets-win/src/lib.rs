//! Windows Credential Manager + DPAPI secrets for the Wormhole Rust migration.
//!
//! Mirrors the C# surface in `Services/CredentialService.cs` and related DPAPI
//! caches so a Rust host can open existing user profiles:
//!
//! - CredMgr password store CRUD: `Wormhole:<guid>` (D-format); pre-write
//!   2560 UTF-16-byte guard (`PasswordTooLarge`); [`PasswordStore`] /
//!   [`WinCredPasswordStore`] / [`FakePasswordStore`] (tests; Debug never echoes secrets)
//! - Private keys: `%LOCALAPPDATA%\Wormhole\keys\<guid:N>.dpapi` (null entropy);
//!   [`KeyMaterialStore`] CRUD stub + [`FakeKeyMaterialStore`] (metadata stays out of blobs)
//! - Tunnel secrets: `%LOCALAPPDATA%\Wormhole\tunnels\<guid:N>.dpapi` (null entropy);
//!   [`TunnelPayloadStore`] CRUD stub + [`FakeTunnelPayloadStore`] (SQLite metadata only)
//! - Azure VPN Entra refresh tokens: `%LOCALAPPDATA%\Wormhole\azurevpn-cache\<guid:N>.tokencache`
//!   ([`AzureVpnTokenCacheStore`] + DPAPI/`Fake`; tunnel-id entropy, atomic write; opaque
//!   bytes — JSON / identity live in `wormhole-tunnels::auth_glue`)
//! - Named / per-tunnel entropy constants for app-auth, Bitwarden, Azure/WatchGuard/Stormshield caches
//! - App-auth stub unlock (`app-auth.dpapi` + `APP_AUTHENTICATION_V1`) and Windows Hello
//!   `AvailabilityProbe` / `HelloPrompt` (+ `FakeHelloPrompt` for tests); interactive WinRT
//!   `UserConsentVerifier` is **not** wired yet
//! - Bitwarden CLI unlock / memory-only session stub (`BitwardenSession` +
//!   `StubBitwardenSession` / `FakeBitwardenSession`); `bw` process spawn is **not** wired yet
//! - Process-local ephemeral session passwords (`TransientSessionCredentialStore` +
//!   `MemoryTransientSessionCredentialStore` / `FakeTransientSessionCredentialStore`);
//!   never SQLite / CredMgr / DPAPI — keyed by session or connection-node id
//!
//! See `docs/migration/04-secrets.md` and `docs/migration/15-cutover.md`.
//!
//! # Platform
//!
//! Windows-only (`x86_64-pc-windows-msvc` / `aarch64-pc-windows-msvc`). Non-Windows
//! builds compile stubs that return [`SecretsError::UnsupportedPlatform`].
//!
//! # Error safety
//!
//! [`SecretsError`] never carries secret material — only operation names, Win32
//! codes, sizes, and I/O errors (paths). Prefer [`redact_secret`] /
//! [`redact_env_and_cli_secrets`] before logging any caller-held secret.
//! Key / tunnel / Azure tokencache path helpers reject `..` / absolute escapes via
//! [`ensure_confined_under`] / [`key_path_under`] / [`tunnel_path_under`] /
//! [`azure_vpn_token_cache_path_under`];
//! [`SecretsError::PathNotConfined`] never embeds the candidate path.

#![cfg_attr(not(windows), allow(dead_code))]
#![deny(missing_docs)]

mod app_auth;
mod azure_vpn_token_cache;
mod bitwarden_session;
mod cred_mgr;
mod dpapi;
mod entropy;
mod hello;
mod key_tunnel;
mod paths;
mod redact;
mod transient_session;
#[cfg(windows)]
mod win32;

pub use app_auth::{
    protect_app_authentication, read_app_authentication_store, read_app_authentication_store_at,
    unlock_app_authentication_store, unlock_app_authentication_store_at,
    unprotect_app_authentication, write_app_authentication_store,
    write_app_authentication_store_at, AppAuthUnlock,
};
pub use azure_vpn_token_cache::{
    clear_azure_vpn_token_cache, clear_azure_vpn_token_cache_under, read_azure_vpn_token_cache,
    read_azure_vpn_token_cache_under, write_azure_vpn_token_cache,
    write_azure_vpn_token_cache_under, AzureVpnTokenCacheStore, DpapiAzureVpnTokenCacheStore,
    FakeAzureVpnTokenCacheStore,
};
pub use bitwarden_session::{
    bitwarden_session_status, unlock_bitwarden_session, BitwardenSession, BitwardenSessionKey,
    BitwardenSessionStatus, BitwardenUnlockResult, FakeBitwardenSession, StubBitwardenSession,
    BITWARDEN_CLI_SESSION_GAP,
};
pub use cred_mgr::{
    credential_target, delete_password, ensure_password_fits_cred_mgr, password_utf16_byte_len,
    read_password, store_password, FakePasswordStore, PasswordStore, WinCredPasswordStore,
    CREDENTIAL_COMMENT, CREDENTIAL_PREFIX, MAX_PASSWORD_UTF16_BYTES, MCP_TOKEN_CREDENTIAL_ID,
};
pub use dpapi::{
    delete_protected_file_if_exists, protect, read_protected_file, unprotect,
    write_protected_file, write_protected_file_atomic,
};
pub use entropy::{
    app_authentication_v1, bitwarden_browser_shared_storage_v1, guid_to_dotnet_bytes,
    tunnel_id_entropy, APP_AUTHENTICATION_V1, BITWARDEN_BROWSER_SHARED_STORAGE_V1,
};
pub use hello::{
    check_hello_availability, check_hello_availability_with, is_remote_desktop_session,
    is_remote_desktop_session_with, request_hello_verification, request_hello_verification_with,
    AvailabilityProbe, FakeHelloPrompt, HelloAvailability, HelloPrompt, HelloVerification,
    StubHelloPrompt, REMOTE_DESKTOP_UNAVAILABLE_MESSAGE, SM_REMOTESESSION, WINRT_HELLO_GAP,
};
pub use key_tunnel::{
    delete_key_payload, delete_key_payload_under, delete_tunnel_payload,
    delete_tunnel_payload_under, read_key_payload, read_key_payload_under, read_tunnel_payload,
    read_tunnel_payload_under, write_key_payload, write_key_payload_under, write_tunnel_payload,
    write_tunnel_payload_under, DpapiKeyMaterialStore, DpapiTunnelPayloadStore,
    FakeKeyMaterialStore, FakeTunnelPayloadStore, KeyMaterialStore, TunnelPayloadStore,
};
pub use paths::{
    app_authentication_path, azure_vpn_cache_dir, azure_vpn_token_cache_path,
    azure_vpn_token_cache_path_under, bitwarden_browser_shared_storage_path,
    bitwarden_browser_webview2_root, bitwarden_browser_webview2_user_data,
    bitwarden_extension_download_cache_dir, bitwarden_extension_install_dir,
    bitwarden_extension_root, confined_file_under, ensure_confined_under, key_path,
    key_path_under, keys_dir, stormshield_cache_dir, stormshield_ovpn_cache_path, tunnel_path,
    tunnel_path_under, tunnels_dir, watchguard_cache_dir, watchguard_ovpn_cache_path,
    wormhole_app_data_dir,
};
pub use redact::{
    redact_env_and_cli_secrets, redact_secret, redact_truncated, REDACTED, REDACT_TRUNCATE_DEFAULT,
};
pub use transient_session::{
    FakeTransientSessionCredentialStore, MemoryTransientSessionCredentialStore,
    TransientSessionCredentialStore,
};

use std::fmt;

/// Crate-level result alias.
pub type Result<T> = std::result::Result<T, SecretsError>;

/// Errors from CredMgr / DPAPI / path helpers.
///
/// Intentionally free of secret payloads so `Display` / `Debug` are safe to log.
#[derive(Debug)]
pub enum SecretsError {
    /// Not running on Windows.
    UnsupportedPlatform,
    /// Win32 API failure (`GetLastError` / HRESULT-derived code + context).
    Win32 {
        /// API or operation name.
        op: &'static str,
        /// Windows error code.
        code: u32,
    },
    /// Password / blob exceeds CredMgr limit (2560 UTF-16 bytes).
    PasswordTooLarge {
        /// Actual UTF-16 byte length.
        bytes: usize,
    },
    /// I/O while reading/writing a DPAPI file.
    Io(std::io::Error),
    /// DPAPI unprotect failed (wrong entropy, corrupt blob, or scope mismatch).
    DpapiUnprotect,
    /// Path segment rejected (empty, `.`/`..`, separators, absolute, or multi-component).
    InvalidPathSegment {
        /// API or helper name that rejected the segment.
        op: &'static str,
    },
    /// Candidate path escaped its allowed root (`..` in root/path, or not under root).
    ///
    /// Display/Debug never embed the path string (avoids logging hostile / sensitive paths).
    PathNotConfined {
        /// API or helper name that rejected the path.
        op: &'static str,
    },
    /// Transient session credential `store` rejected an empty password (fail closed).
    ///
    /// Parity with C# `ArgumentException.ThrowIfNullOrEmpty` on
    /// `ITransientSessionCredentialStore.Store`. Display/Debug never embed the
    /// password (there is none to embed).
    EmptyPassword,
}

impl fmt::Display for SecretsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => write!(f, "wormhole-secrets-win requires Windows"),
            Self::Win32 { op, code } => write!(f, "{op} failed with Win32 error {code}"),
            Self::PasswordTooLarge { bytes } => write!(
                f,
                "credential secret is {bytes} UTF-16 bytes (max {MAX_PASSWORD_UTF16_BYTES})"
            ),
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::DpapiUnprotect => write!(f, "DPAPI CryptUnprotectData failed"),
            Self::InvalidPathSegment { op } => {
                write!(f, "{op} rejected path segment (traversal or separators)")
            }
            Self::PathNotConfined { op } => {
                write!(
                    f,
                    "{op} path is not confined under the required secrets root"
                )
            }
            Self::EmptyPassword => write!(
                f,
                "transient session credential store rejected an empty password"
            ),
        }
    }
}

impl std::error::Error for SecretsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for SecretsError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use uuid::Uuid;

    #[test]
    fn credential_target_matches_csharp_prefix_and_d_format() {
        let id = Uuid::parse_str("a7f3c1e2-9b6d-4e8a-bf21-7c0d2e5a4b91").unwrap();
        assert_eq!(
            credential_target(&id),
            "Wormhole:a7f3c1e2-9b6d-4e8a-bf21-7c0d2e5a4b91"
        );
        assert_eq!(id, MCP_TOKEN_CREDENTIAL_ID);
        // Uuid Display is lowercase D-format — never uppercase / N / B / P.
        assert!(!credential_target(&id).contains('A'));
    }

    #[test]
    fn key_and_tunnel_paths_use_n_format() {
        let id = Uuid::parse_str("a7f3c1e2-9b6d-4e8a-bf21-7c0d2e5a4b91").unwrap();
        let key = key_path(&id).unwrap();
        let tunnel = tunnel_path(&id).unwrap();
        assert!(
            key.ends_with(r"keys\a7f3c1e29b6d4e8abf217c0d2e5a4b91.dpapi")
                || key.ends_with("keys/a7f3c1e29b6d4e8abf217c0d2e5a4b91.dpapi")
        );
        assert!(
            tunnel.ends_with(r"tunnels\a7f3c1e29b6d4e8abf217c0d2e5a4b91.dpapi")
                || tunnel.ends_with("tunnels/a7f3c1e29b6d4e8abf217c0d2e5a4b91.dpapi")
        );
    }

    #[test]
    fn cache_paths_use_n_format_and_fixed_roots() {
        let id = Uuid::parse_str("a7f3c1e2-9b6d-4e8a-bf21-7c0d2e5a4b91").unwrap();
        let n = "a7f3c1e29b6d4e8abf217c0d2e5a4b91";
        assert!(stormshield_ovpn_cache_path(&id)
            .to_string_lossy()
            .contains(&format!("stormshield-cache{sep}{n}.ovpncache", sep = std::path::MAIN_SEPARATOR)));
        assert!(watchguard_ovpn_cache_path(&id)
            .to_string_lossy()
            .contains(&format!("watchguard-cache{sep}{n}.ovpncache", sep = std::path::MAIN_SEPARATOR)));
        assert!(azure_vpn_token_cache_path(&id)
            .to_string_lossy()
            .contains(&format!("azurevpn-cache{sep}{n}.tokencache", sep = std::path::MAIN_SEPARATOR)));
        assert!(app_authentication_path()
            .to_string_lossy()
            .ends_with("app-auth.dpapi"));
        assert!(bitwarden_browser_shared_storage_path()
            .to_string_lossy()
            .ends_with("bitwarden-browser-storage.dpapi"));
        assert!(bitwarden_browser_webview2_root()
            .to_string_lossy()
            .ends_with("bitwarden-browser-webview2"));
        assert!(bitwarden_browser_webview2_user_data("profile-abc")
            .unwrap()
            .to_string_lossy()
            .ends_with(&format!(
                "bitwarden-browser-webview2{sep}profile-abc",
                sep = std::path::MAIN_SEPARATOR
            )));
        assert!(bitwarden_extension_install_dir("2026.1.0")
            .unwrap()
            .to_string_lossy()
            .ends_with(&format!(
                "extensions{sep}bitwarden{sep}2026.1.0",
                sep = std::path::MAIN_SEPARATOR
            )));
        assert!(bitwarden_extension_download_cache_dir()
            .to_string_lossy()
            .ends_with(&format!(
                "cache{sep}bitwarden-browser-extension",
                sep = std::path::MAIN_SEPARATOR
            )));
    }

    #[test]
    fn path_helpers_cannot_traverse_via_uuid() {
        let id = Uuid::nil();
        let p = key_path(&id).unwrap();
        let file = p.file_name().unwrap().to_string_lossy();
        assert_eq!(file, "00000000000000000000000000000000.dpapi");
        assert!(!file.contains(".."));
        assert!(!file.contains('/') && !file.contains('\\'));
    }

    #[test]
    fn named_entropy_utf8_constants() {
        assert_eq!(APP_AUTHENTICATION_V1, b"Wormhole.AppAuthentication.v1");
        assert_eq!(
            BITWARDEN_BROWSER_SHARED_STORAGE_V1,
            b"Wormhole.BitwardenBrowser.SharedStorage.v1"
        );
        assert_eq!(app_authentication_v1(), APP_AUTHENTICATION_V1);
        assert_eq!(
            bitwarden_browser_shared_storage_v1(),
            BITWARDEN_BROWSER_SHARED_STORAGE_V1
        );
    }

    #[test]
    fn guid_to_dotnet_bytes_matches_guid_tobytearray() {
        // Verified against .NET Guid.Parse(...).ToByteArray() for this id.
        let id = Uuid::parse_str("a7f3c1e2-9b6d-4e8a-bf21-7c0d2e5a4b91").unwrap();
        assert_eq!(
            guid_to_dotnet_bytes(&id),
            [
                0xe2, 0xc1, 0xf3, 0xa7, 0x6d, 0x9b, 0x8a, 0x4e, 0xbf, 0x21, 0x7c, 0x0d, 0x2e, 0x5a,
                0x4b, 0x91
            ]
        );
        assert_eq!(tunnel_id_entropy(&id), guid_to_dotnet_bytes(&id));
        // Must not equal RFC 4122 network order.
        assert_ne!(guid_to_dotnet_bytes(&id), *id.as_bytes());
    }

    #[test]
    fn redact_never_echoes_secret() {
        assert_eq!(redact_secret("hunter2"), REDACTED);
        assert_eq!(redact_secret(""), REDACTED);
        let long = "x".repeat(400);
        assert!(redact_truncated(&long).len() <= REDACT_TRUNCATE_DEFAULT);
        let cli = "bw unlock --session SECRET123 BW_SESSION=SECRET123 --code 999999 WORMHOLE_BW_PASSWORD=pw";
        let out = redact_env_and_cli_secrets(cli);
        assert!(!out.contains("SECRET123"));
        assert!(!out.contains("999999"));
        assert!(!out.contains("=pw"));
        assert!(out.contains(REDACTED));
    }

    #[test]
    fn secrets_error_display_debug_have_no_secret_payload() {
        let secret = "super-secret-password-value";
        let err = SecretsError::PasswordTooLarge {
            bytes: password_utf16_byte_len(secret),
        };
        let display = err.to_string();
        let debug = format!("{err:?}");
        assert!(!display.contains(secret));
        assert!(!debug.contains(secret));
        assert!(display.contains("UTF-16"));

        let dpapi = SecretsError::DpapiUnprotect;
        assert!(!format!("{dpapi}").contains(secret));
        assert!(!format!("{dpapi:?}").contains(secret));

        let empty = SecretsError::EmptyPassword;
        assert!(!format!("{empty}").contains(secret));
        assert!(!format!("{empty:?}").contains(secret));
        assert!(empty.to_string().contains("empty password"));
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_null_entropy_roundtrip() {
        let plain = b"ssh-private-key-bytes";
        let blob = protect(plain, None).expect("protect");
        assert_ne!(blob, plain);
        let back = unprotect(&blob, None).expect("unprotect");
        assert_eq!(back, plain);
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_named_entropy_roundtrip_and_mismatch() {
        let plain = b"app-auth-verifier";
        let blob = protect(plain, Some(APP_AUTHENTICATION_V1)).expect("protect");
        assert_eq!(
            unprotect(&blob, Some(APP_AUTHENTICATION_V1)).unwrap(),
            plain
        );
        assert!(matches!(
            unprotect(&blob, Some(BITWARDEN_BROWSER_SHARED_STORAGE_V1)),
            Err(SecretsError::DpapiUnprotect)
        ));
        assert!(matches!(
            unprotect(&blob, None),
            Err(SecretsError::DpapiUnprotect)
        ));
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_tunnel_id_entropy_roundtrip() {
        let id = Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap();
        let entropy = tunnel_id_entropy(&id);
        let plain = br#"{"refreshToken":"rt"}"#;
        let blob = protect(plain, Some(&entropy)).unwrap();
        assert_eq!(unprotect(&blob, Some(&entropy)).unwrap(), plain);
        let other = tunnel_id_entropy(&Uuid::nil());
        assert!(matches!(
            unprotect(&blob, Some(&other)),
            Err(SecretsError::DpapiUnprotect)
        ));
    }

    #[cfg(windows)]
    #[test]
    fn wrong_entropy_error_does_not_embed_plaintext() {
        let plain = b"top-secret-refresh-token-material";
        let blob = protect(plain, Some(APP_AUTHENTICATION_V1)).unwrap();
        let err = unprotect(&blob, None).unwrap_err();
        let text = format!("{err} / {err:?}");
        assert!(!text.contains("top-secret"));
        assert!(!text.contains("refresh-token"));
    }

    #[cfg(windows)]
    #[test]
    fn protected_file_roundtrip_under_temp() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sample.dpapi");
        let id = Uuid::new_v4();
        let entropy = tunnel_id_entropy(&id);
        write_protected_file(&path, b"tunnel-secret", Some(&entropy)).unwrap();
        let got = read_protected_file(&path, Some(&entropy)).unwrap();
        assert_eq!(got.as_deref(), Some(b"tunnel-secret".as_slice()));
        assert!(read_protected_file(&dir.path().join("missing.dpapi"), None)
            .unwrap()
            .is_none());
    }

    #[cfg(windows)]
    #[test]
    fn atomic_write_overwrites_existing_without_delete_gap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.tokencache");
        write_protected_file_atomic(&path, b"v1", None).unwrap();
        assert_eq!(
            read_protected_file(&path, None).unwrap().as_deref(),
            Some(b"v1".as_slice())
        );
        write_protected_file_atomic(&path, b"v2-overwritten", None).unwrap();
        assert_eq!(
            read_protected_file(&path, None).unwrap().as_deref(),
            Some(b"v2-overwritten".as_slice())
        );
        // No orphaned *.tmp siblings after success.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .ends_with(".tmp")
            })
            .collect();
        assert!(leftovers.is_empty(), "orphaned temps: {leftovers:?}");
    }

    #[cfg(windows)]
    #[test]
    fn atomic_temp_name_matches_csharp_suffix_pattern() {
        // C#: path + "." + Guid.N + ".tmp" — exercised indirectly: write succeeds beside path.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a7f3c1e29b6d4e8abf217c0d2e5a4b91.ovpncache");
        write_protected_file_atomic(&path, b"profile", Some(&tunnel_id_entropy(&MCP_TOKEN_CREDENTIAL_ID)))
            .unwrap();
        assert!(path.is_file());
    }

    #[cfg(windows)]
    #[test]
    fn cred_mgr_roundtrip_with_test_target() {
        // Unique id so we never collide with real Wormhole credentials.
        let id = Uuid::parse_str("f00dcafe-0000-4000-8000-0000deadbeef").unwrap();
        let _ = delete_password(&id); // clean leftover from a prior failed run
        store_password(&id, "unit-test-secret").expect("store");
        let got = read_password(&id).expect("read");
        assert_eq!(got.as_deref(), Some("unit-test-secret"));
        delete_password(&id).expect("delete");
        assert_eq!(read_password(&id).unwrap(), None);
    }

    #[cfg(windows)]
    #[test]
    fn cred_mgr_empty_and_unicode_passwords() {
        let id = Uuid::parse_str("f00dcafe-0001-4000-8000-0000deadbeef").unwrap();
        let _ = delete_password(&id);

        store_password(&id, "").expect("empty store");
        assert_eq!(read_password(&id).unwrap().as_deref(), Some(""));

        let unicode = "pässwörd-🔒-Σ";
        store_password(&id, unicode).expect("unicode store");
        assert_eq!(read_password(&id).unwrap().as_deref(), Some(unicode));

        delete_password(&id).unwrap();
        assert_eq!(read_password(&id).unwrap(), None);
    }

    #[cfg(windows)]
    #[test]
    fn cred_mgr_rejects_oversize_accepts_limit() {
        let id = Uuid::parse_str("f00dcafe-0002-4000-8000-0000deadbeef").unwrap();
        let _ = delete_password(&id);

        let at_limit: String = std::iter::repeat_n('a', 1280).collect();
        assert_eq!(password_utf16_byte_len(&at_limit), MAX_PASSWORD_UTF16_BYTES);
        store_password(&id, &at_limit).expect("1280 ASCII chars fit");
        assert_eq!(read_password(&id).unwrap().as_deref(), Some(at_limit.as_str()));

        let over: String = std::iter::repeat_n('a', 1281).collect();
        let err = store_password(&id, &over).unwrap_err();
        match err {
            SecretsError::PasswordTooLarge { bytes: 2562 } => {}
            other => panic!("expected PasswordTooLarge(2562), got {other:?}"),
        }
        assert!(!err.to_string().contains(&over));
        assert!(!format!("{err:?}").contains(&over));
        // Prior at-limit value must remain — oversize never reached CredWriteW.
        assert_eq!(read_password(&id).unwrap().as_deref(), Some(at_limit.as_str()));

        // Multibyte BMP at the UTF-16 ceiling must be accepted (not len()*2).
        let accents: String = std::iter::repeat_n('é', 1280).collect();
        assert_eq!(password_utf16_byte_len(&accents), MAX_PASSWORD_UTF16_BYTES);
        store_password(&id, &accents).expect("1280 × é fits UTF-16 limit");
        assert_eq!(read_password(&id).unwrap().as_deref(), Some(accents.as_str()));

        // Astral at-limit accepted; astral oversize rejected before vault write.
        let emoji_ok: String = std::iter::repeat_n('🔒', 640).collect();
        assert_eq!(password_utf16_byte_len(&emoji_ok), MAX_PASSWORD_UTF16_BYTES);
        store_password(&id, &emoji_ok).expect("640 emoji fit");
        assert_eq!(read_password(&id).unwrap().as_deref(), Some(emoji_ok.as_str()));

        let emoji_over: String = std::iter::repeat_n('🔒', 641).collect();
        let err = store_password(&id, &emoji_over).unwrap_err();
        match err {
            SecretsError::PasswordTooLarge { bytes: 2564 } => {}
            other => panic!("expected PasswordTooLarge(2564), got {other:?}"),
        }
        assert_eq!(read_password(&id).unwrap().as_deref(), Some(emoji_ok.as_str()));
        assert!(!err.to_string().contains('🔒'));

        delete_password(&id).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn cred_mgr_concurrent_store_read_same_target() {
        let id = Uuid::parse_str("f00dcafe-0003-4000-8000-0000deadbeef").unwrap();
        let _ = delete_password(&id);
        store_password(&id, "seed").unwrap();

        let barrier = Arc::new(Barrier::new(8));
        let mut handles = Vec::new();
        for i in 0..8 {
            let b = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                b.wait();
                if i % 2 == 0 {
                    store_password(&id, &format!("pw-{i}")).expect("store");
                } else {
                    let _ = read_password(&id).expect("read");
                }
            }));
        }
        for h in handles {
            h.join().expect("thread");
        }
        // Settled state is readable; last writer wins.
        let got = read_password(&id).unwrap();
        assert!(got.is_some());
        delete_password(&id).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn cred_mgr_missing_delete_is_ok_and_trait_matches_free_helpers() {
        let id = Uuid::parse_str("f00dcafe-0004-4000-8000-0000deadbeef").unwrap();
        // Ensure absent, then delete twice — both must succeed (C# best-effort).
        let _ = delete_password(&id);
        delete_password(&id).expect("missing delete");
        delete_password(&id).expect("second missing delete");
        assert_eq!(read_password(&id).unwrap(), None);

        // WinCredPasswordStore DI path must match free helpers (contract drift pin).
        let store = WinCredPasswordStore;
        store.store(&id, "via-wincred-trait").unwrap();
        assert_eq!(
            store.read(&id).unwrap().as_deref(),
            Some("via-wincred-trait")
        );
        assert_eq!(
            read_password(&id).unwrap().as_deref(),
            Some("via-wincred-trait")
        );
        store.delete(&id).unwrap();
        assert_eq!(store.read(&id).unwrap(), None);
        // Trait delete on missing also Ok.
        store.delete(&id).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn cred_mgr_embedded_nul_roundtrip() {
        let id = Uuid::parse_str("f00dcafe-0005-4000-8000-0000deadbeef").unwrap();
        let _ = delete_password(&id);
        // Blob is length-prefixed UTF-16 — embedded NUL is one code unit, not a C-string cut.
        // "pre" (3) + NUL (1) + "post-" (5) + 🔒 (2) = 11 units → 22 bytes.
        let secret = "pre\0post-🔒";
        assert_eq!(password_utf16_byte_len(secret), 22);
        store_password(&id, secret).expect("nul store");
        assert_eq!(read_password(&id).unwrap().as_deref(), Some(secret));
        delete_password(&id).unwrap();
        assert_eq!(read_password(&id).unwrap(), None);
    }
}
