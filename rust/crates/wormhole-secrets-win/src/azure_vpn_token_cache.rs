//! Entra refresh-token DPAPI blobs under `azurevpn-cache\` (opaque bytes).
//!
//! Mirrors C# `AzureVpnTokenCache` **file I/O**: atomic DPAPI write with
//! [`crate::tunnel_id_entropy`], path-confined under an injectable
//! `azurevpn-cache` root. JSON schema / identity-hash / max-age live in
//! `wormhole-tunnels::auth_glue` — this module stores **opaque** plaintext
//! only (never logs blob contents).
//!
//! Distinct from [`crate::KeyMaterialStore`] / [`crate::TunnelPayloadStore`]
//! (`keys\` / `tunnels\`, null entropy, non-atomic). Do not reuse those roots.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use uuid::Uuid;

use crate::dpapi::{
    delete_protected_file_if_exists, read_protected_file, write_protected_file_atomic,
};
use crate::entropy::tunnel_id_entropy;
use crate::paths::{azure_vpn_cache_dir, azure_vpn_token_cache_path_under};
use crate::Result;

/// DI surface for Azure VPN Entra refresh-token DPAPI blobs under `azurevpn-cache\`.
///
/// Blobs are opaque JSON bytes owned by the tunnels auth-glue layer. Missing
/// reads return `Ok(None)`; missing clears succeed (C# best-effort delete).
pub trait AzureVpnTokenCacheStore {
    /// Protect + atomic write / overwrite the cache blob for `tunnel_config_id`.
    fn store(&self, tunnel_config_id: &Uuid, plaintext: &[u8]) -> Result<()>;

    /// Read + unprotect; `Ok(None)` when the blob is missing.
    fn read(&self, tunnel_config_id: &Uuid) -> Result<Option<Vec<u8>>>;

    /// Delete the cache blob (logout / tunnel delete). Missing files succeed.
    ///
    /// Never reads or unprotects the blob.
    fn clear(&self, tunnel_config_id: &Uuid) -> Result<()>;
}

/// Production DPAPI Azure VPN token cache under a confined `azurevpn-cache` root.
#[derive(Clone)]
pub struct DpapiAzureVpnTokenCacheStore {
    cache_root: PathBuf,
}

impl fmt::Debug for DpapiAzureVpnTokenCacheStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DpapiAzureVpnTokenCacheStore")
            .field("cache_root_len", &self.cache_root.as_os_str().len())
            .finish()
    }
}

impl Default for DpapiAzureVpnTokenCacheStore {
    fn default() -> Self {
        Self::new()
    }
}

impl DpapiAzureVpnTokenCacheStore {
    /// Default profile: `%LOCALAPPDATA%\Wormhole\azurevpn-cache`.
    pub fn new() -> Self {
        Self {
            cache_root: azure_vpn_cache_dir(),
        }
    }

    /// Injectable `azurevpn-cache` root (temp dirs in tests).
    pub fn under(cache_root: impl Into<PathBuf>) -> Self {
        Self {
            cache_root: cache_root.into(),
        }
    }

    /// Confined cache root used by this store.
    pub fn cache_root(&self) -> &Path {
        &self.cache_root
    }
}

impl AzureVpnTokenCacheStore for DpapiAzureVpnTokenCacheStore {
    fn store(&self, tunnel_config_id: &Uuid, plaintext: &[u8]) -> Result<()> {
        write_azure_vpn_token_cache_under(&self.cache_root, tunnel_config_id, plaintext)
    }

    fn read(&self, tunnel_config_id: &Uuid) -> Result<Option<Vec<u8>>> {
        read_azure_vpn_token_cache_under(&self.cache_root, tunnel_config_id)
    }

    fn clear(&self, tunnel_config_id: &Uuid) -> Result<()> {
        clear_azure_vpn_token_cache_under(&self.cache_root, tunnel_config_id)
    }
}

/// In-memory Azure VPN token-cache stand-in for unit tests (no DPAPI / no filesystem).
///
/// [`Debug`] exposes only entry counts / call counts / byte lengths — never plaintext.
#[derive(Default)]
pub struct FakeAzureVpnTokenCacheStore {
    entries: Mutex<HashMap<Uuid, Vec<u8>>>,
    store_calls: AtomicUsize,
    read_calls: AtomicUsize,
    clear_calls: AtomicUsize,
}

impl fmt::Debug for FakeAzureVpnTokenCacheStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let lengths: Vec<usize> = self
            .entries
            .lock()
            .map(|g| g.values().map(|v| v.len()).collect())
            .unwrap_or_default();
        f.debug_struct("FakeAzureVpnTokenCacheStore")
            .field("entry_count", &lengths.len())
            .field("entry_lens", &lengths)
            .field("store_calls", &self.store_calls.load(Ordering::Relaxed))
            .field("read_calls", &self.read_calls.load(Ordering::Relaxed))
            .field("clear_calls", &self.clear_calls.load(Ordering::Relaxed))
            .finish()
    }
}

impl FakeAzureVpnTokenCacheStore {
    /// Empty in-memory store.
    pub fn new() -> Self {
        Self::default()
    }

    /// How many times [`AzureVpnTokenCacheStore::store`] was invoked.
    pub fn store_calls(&self) -> usize {
        self.store_calls.load(Ordering::Relaxed)
    }

    /// How many times [`AzureVpnTokenCacheStore::read`] was invoked.
    pub fn read_calls(&self) -> usize {
        self.read_calls.load(Ordering::Relaxed)
    }

    /// How many times [`AzureVpnTokenCacheStore::clear`] was invoked.
    pub fn clear_calls(&self) -> usize {
        self.clear_calls.load(Ordering::Relaxed)
    }
}

impl AzureVpnTokenCacheStore for FakeAzureVpnTokenCacheStore {
    fn store(&self, tunnel_config_id: &Uuid, plaintext: &[u8]) -> Result<()> {
        self.store_calls.fetch_add(1, Ordering::Relaxed);
        let mut guard = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        guard.insert(*tunnel_config_id, plaintext.to_vec());
        Ok(())
    }

    fn read(&self, tunnel_config_id: &Uuid) -> Result<Option<Vec<u8>>> {
        self.read_calls.fetch_add(1, Ordering::Relaxed);
        let guard = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        Ok(guard.get(tunnel_config_id).map(|v| v.clone()))
    }

    fn clear(&self, tunnel_config_id: &Uuid) -> Result<()> {
        self.clear_calls.fetch_add(1, Ordering::Relaxed);
        let mut guard = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        guard.remove(tunnel_config_id);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Free helpers — azurevpn-cache (tunnel-id entropy, atomic write, path-confined)
// ---------------------------------------------------------------------------

/// Protect + atomic-write `azurevpn-cache\<id:N>.tokencache` under the default profile.
pub fn write_azure_vpn_token_cache(tunnel_config_id: &Uuid, plaintext: &[u8]) -> Result<()> {
    write_azure_vpn_token_cache_under(&azure_vpn_cache_dir(), tunnel_config_id, plaintext)
}

/// Read + unprotect the default-profile tokencache. Missing → `Ok(None)`.
pub fn read_azure_vpn_token_cache(tunnel_config_id: &Uuid) -> Result<Option<Vec<u8>>> {
    read_azure_vpn_token_cache_under(&azure_vpn_cache_dir(), tunnel_config_id)
}

/// Delete the default-profile tokencache. Missing → `Ok(())`.
///
/// Never reads or unprotects the blob (no plaintext in memory on clear / logout).
pub fn clear_azure_vpn_token_cache(tunnel_config_id: &Uuid) -> Result<()> {
    clear_azure_vpn_token_cache_under(&azure_vpn_cache_dir(), tunnel_config_id)
}

/// Protect + atomic write under an injectable `cache_root` (temp dirs in tests).
///
/// Resolves the path via [`azure_vpn_token_cache_path_under`] before any I/O —
/// hostile roots / escapes never reach `write_protected_file_atomic`. Entropy is
/// [`tunnel_id_entropy`] (parity with C# `AzureVpnTokenCache`).
pub fn write_azure_vpn_token_cache_under(
    cache_root: &Path,
    tunnel_config_id: &Uuid,
    plaintext: &[u8],
) -> Result<()> {
    let path = azure_vpn_token_cache_path_under(cache_root, tunnel_config_id)?;
    let entropy = tunnel_id_entropy(tunnel_config_id);
    write_protected_file_atomic(&path, plaintext, Some(&entropy))
}

/// Read + unprotect under an injectable `cache_root`. Missing → `Ok(None)`.
///
/// Path confinement runs before any filesystem read.
pub fn read_azure_vpn_token_cache_under(
    cache_root: &Path,
    tunnel_config_id: &Uuid,
) -> Result<Option<Vec<u8>>> {
    let path = azure_vpn_token_cache_path_under(cache_root, tunnel_config_id)?;
    let entropy = tunnel_id_entropy(tunnel_config_id);
    read_protected_file(&path, Some(&entropy))
}

/// Delete under an injectable `cache_root`. Missing → `Ok(())`.
///
/// Path confinement runs before any filesystem delete — hostile roots never
/// reach `remove_file`. Never reads or unprotects the blob.
pub fn clear_azure_vpn_token_cache_under(
    cache_root: &Path,
    tunnel_config_id: &Uuid,
) -> Result<()> {
    let path = azure_vpn_token_cache_path_under(cache_root, tunnel_config_id)?;
    delete_protected_file_if_exists(&path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecretsError;
    use std::fs;
    use std::path::Path;
    use uuid::Uuid;

    fn assert_path_not_confined(err: &SecretsError, expected_op: &str) {
        match err {
            SecretsError::PathNotConfined { op } => assert_eq!(*op, expected_op),
            other => panic!("expected PathNotConfined({expected_op}), got {other:?}"),
        }
        let text = format!("{err} / {err:?}");
        assert!(!text.contains("never-written"));
        assert!(!text.contains("refresh"));
        assert!(!text.contains("Windows"));
        assert!(!text.contains(r"C:\"));
        assert!(!text.contains(".tokencache"));
    }

    #[test]
    fn write_read_clear_helpers_reject_hostile_root_before_io() {
        let id = Uuid::nil();
        let secret = b"never-written-refresh-token-material";
        let dir = tempfile::tempdir().unwrap();
        let hostile = dir.path().join("azurevpn-cache").join("..").join("outside");

        let err = write_azure_vpn_token_cache_under(&hostile, &id, secret).unwrap_err();
        assert_path_not_confined(&err, "azure_vpn_token_cache_path_under");

        let err = read_azure_vpn_token_cache_under(&hostile, &id).unwrap_err();
        assert_path_not_confined(&err, "azure_vpn_token_cache_path_under");

        let err = clear_azure_vpn_token_cache_under(&hostile, &id).unwrap_err();
        assert_path_not_confined(&err, "azure_vpn_token_cache_path_under");

        assert!(!dir.path().join("outside").exists());
        let children: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert!(
            children.is_empty(),
            "hostile root must not create dirs/files: {children:?}"
        );

        let err =
            write_azure_vpn_token_cache_under(Path::new(""), &id, secret).unwrap_err();
        assert_path_not_confined(&err, "azure_vpn_token_cache_path_under");
    }

    #[test]
    fn fake_defensive_copies_and_debug_redacts() {
        let store = FakeAzureVpnTokenCacheStore::new();
        let id = Uuid::parse_str("a7f3c1e2-9b6d-4e8a-bf21-7c0d2e5a4b91").unwrap();
        let mut input = b"rt.SECRET_LEAK_MARKER".to_vec();
        store.store(&id, &input).unwrap();
        input.fill(0);

        let mut out = store.read(&id).unwrap().expect("blob");
        assert_eq!(out, b"rt.SECRET_LEAK_MARKER");
        out.fill(0);
        // Store still holds its own copy.
        assert_eq!(
            store.read(&id).unwrap().as_deref(),
            Some(b"rt.SECRET_LEAK_MARKER".as_slice())
        );

        let dbg = format!("{store:?}");
        assert!(!dbg.contains("SECRET_LEAK"), "{dbg}");
        assert!(dbg.contains("entry_lens"), "{dbg}");

        store.clear(&id).unwrap();
        assert!(store.read(&id).unwrap().is_none());
        assert_eq!(store.clear_calls(), 1);
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_roundtrip_under_temp_uses_tunnel_id_entropy() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("azurevpn-cache");
        let store = DpapiAzureVpnTokenCacheStore::under(&root);
        let id = Uuid::parse_str("f00dcafe-aaaa-4000-8000-0000cafebabe").unwrap();
        let plain = br#"{"schemaVersion":1,"identityHash":"AB","refreshToken":"rt","cachedAtUtc":"2026-07-31T12:00:00Z"}"#;

        store.store(&id, plain).unwrap();
        let got = store.read(&id).unwrap().expect("present");
        assert_eq!(got, plain);

        // Wrong tunnel id entropy cannot decrypt a copied blob path — confinement
        // uses a different file; verify wrong entropy on same bytes fails closed.
        let path = azure_vpn_token_cache_path_under(&root, &id).unwrap();
        let blob = fs::read(&path).unwrap();
        let wrong = tunnel_id_entropy(&Uuid::nil());
        let err = crate::unprotect(&blob, Some(&wrong)).unwrap_err();
        assert!(matches!(err, SecretsError::DpapiUnprotect));
        assert!(!format!("{err}").contains("refreshToken"));

        store.clear(&id).unwrap();
        assert!(store.read(&id).unwrap().is_none());
        assert!(!path.exists());
    }

    #[test]
    fn path_under_matches_guid_n_tokencache_name() {
        let dir = tempfile::tempdir().unwrap();
        let id = Uuid::parse_str("a7f3c1e2-9b6d-4e8a-bf21-7c0d2e5a4b91").unwrap();
        let path = azure_vpn_token_cache_path_under(dir.path(), &id).unwrap();
        assert_eq!(
            path.file_name().and_then(|s| s.to_str()),
            Some("a7f3c1e29b6d4e8abf217c0d2e5a4b91.tokencache")
        );
        assert_eq!(path.parent(), Some(dir.path()));
    }

    #[test]
    fn fake_clear_does_not_read_and_clear_then_read_is_none() {
        let store = FakeAzureVpnTokenCacheStore::new();
        let id = Uuid::parse_str("bbbbbbbb-cccc-4ddd-8eee-ffffffffffff").unwrap();
        store.store(&id, b"rt.CLEAR_READ_MARKER").unwrap();
        assert_eq!(store.read_calls(), 0);

        store.clear(&id).unwrap();
        assert_eq!(store.clear_calls(), 1);
        assert_eq!(
            store.read_calls(),
            0,
            "clear must not unprotect / read the blob"
        );
        assert!(store.read(&id).unwrap().is_none());
        assert_eq!(store.read_calls(), 1);

        // Missing clear stays Ok and still does not read.
        store.clear(&id).unwrap();
        assert_eq!(store.clear_calls(), 2);
        assert_eq!(store.read_calls(), 1);
    }

    #[test]
    fn clear_never_unprotects_corrupt_ciphertext() {
        // Clear must remove ciphertext without CryptUnprotectData — corrupt blobs
        // would fail if clear tried to read/unprotect first.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("azurevpn-cache");
        let id = Uuid::parse_str("33333333-4444-5555-6666-777777777777").unwrap();
        let path = azure_vpn_token_cache_path_under(&root, &id).unwrap();
        fs::create_dir_all(&root).unwrap();
        fs::write(&path, b"not-valid-dpapi-ciphertext-REFRESH_MARKER").unwrap();

        let read_err = read_azure_vpn_token_cache_under(&root, &id).unwrap_err();
        assert!(
            matches!(
                read_err,
                SecretsError::DpapiUnprotect | SecretsError::UnsupportedPlatform
            ),
            "{read_err:?}"
        );
        assert!(!format!("{read_err} / {read_err:?}").contains("REFRESH_MARKER"));

        clear_azure_vpn_token_cache_under(&root, &id).unwrap();
        assert!(!path.exists());
        assert!(read_azure_vpn_token_cache_under(&root, &id)
            .unwrap()
            .is_none());
    }

    #[cfg(windows)]
    #[test]
    fn azure_vpn_cache_never_writes_sibling_keys_or_tunnels() {
        // Same guid under sibling keys\ / tunnels\ / azurevpn-cache\ — tokencache
        // CRUD must not land in keys\ or tunnels\ (do not merge stores).
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        let tunnels = dir.path().join("tunnels");
        let cache = dir.path().join("azurevpn-cache");
        let id = Uuid::parse_str("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        let secret = br#"{"schemaVersion":1,"identityHash":"AB","refreshToken":"rt.no-keys","cachedAtUtc":"2026-07-31T12:00:00Z"}"#;

        fs::create_dir_all(&keys).unwrap();
        fs::create_dir_all(&tunnels).unwrap();
        write_azure_vpn_token_cache_under(&cache, &id, secret).unwrap();

        let cache_path = azure_vpn_token_cache_path_under(&cache, &id).unwrap();
        let key_path = crate::key_path_under(&keys, &id).unwrap();
        let tunnel_path = crate::tunnel_path_under(&tunnels, &id).unwrap();
        assert!(cache_path.is_file());
        assert!(!key_path.exists());
        assert!(!tunnel_path.exists());
        assert!(keys.read_dir().unwrap().next().is_none());
        assert!(tunnels.read_dir().unwrap().next().is_none());

        // Escape into sibling keys/tunnels via lexical .. must fail closed before I/O.
        for escape in [
            cache.join("..").join("keys"),
            cache.join("..").join("tunnels"),
        ] {
            let err = write_azure_vpn_token_cache_under(&escape, &id, secret).unwrap_err();
            assert_path_not_confined(&err, "azure_vpn_token_cache_path_under");
            let err = read_azure_vpn_token_cache_under(&escape, &id).unwrap_err();
            assert_path_not_confined(&err, "azure_vpn_token_cache_path_under");
            let err = clear_azure_vpn_token_cache_under(&escape, &id).unwrap_err();
            assert_path_not_confined(&err, "azure_vpn_token_cache_path_under");
        }
        assert!(!key_path.exists());
        assert!(!tunnel_path.exists());
        assert!(keys.read_dir().unwrap().next().is_none());
        assert!(tunnels.read_dir().unwrap().next().is_none());

        clear_azure_vpn_token_cache_under(&cache, &id).unwrap();
        assert!(read_azure_vpn_token_cache_under(&cache, &id)
            .unwrap()
            .is_none());
    }
}
