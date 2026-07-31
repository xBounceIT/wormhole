//! Private-key and tunnel-payload DPAPI files under `keys\` / `tunnels\`.
//!
//! Entropy is always **null** (matches C# `CredentialService` key/tunnel blobs).
//! Paths are resolved through [`crate::key_path_under`] / [`crate::tunnel_path_under`]
//! so reads/writes/deletes cannot escape the injected root. Writes use the same
//! non-atomic `write_protected_file` path as C# `WriteAllBytesAsync` (cache files
//! use atomic replace separately). Deletes confine then `remove_file` only —
//! **never** unprotect. **Never** log plaintext key or tunnel material — only
//! lengths / ops via [`crate::SecretsError`].
//!
//! # Private-key material store (CRUD stub)
//!
//! [`KeyMaterialStore`] mirrors C# `StorePrivateKeyAsync` / `ReadPrivateKeyAsync` /
//! `DeletePrivateKeyAsync`. Production uses [`DpapiKeyMaterialStore`] (confined
//! `keys\<guid:N>.dpapi`); tests inject [`FakeKeyMaterialStore`] (in-memory, no DPAPI).
//! Connection / credential **metadata** stays in SQLite / domain — this store holds
//! only the opaque key blob keyed by credential id.
//!
//! # Tunnel payload store (CRUD stub)
//!
//! [`TunnelPayloadStore`] mirrors C# `StoreTunnelConfigAsync` / `ReadTunnelConfigAsync` /
//! `DeleteTunnelConfigAsync`. Production uses [`DpapiTunnelPayloadStore`] (confined
//! `tunnels\<guid:N>.dpapi`); tests inject [`FakeTunnelPayloadStore`]. SQLite
//! `TunnelConfigs` stays **metadata-only** — provider secret blobs live only in these
//! DPAPI files. Distinct from [`KeyMaterialStore`] (different root, different ids).

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use uuid::Uuid;

use crate::dpapi::{
    delete_protected_file_if_exists, read_protected_file, write_protected_file,
};
use crate::paths::{key_path_under, keys_dir, tunnel_path_under, tunnels_dir};
use crate::Result;

// ---------------------------------------------------------------------------
// Key material store (CRUD)
// ---------------------------------------------------------------------------

/// DI surface for private-key DPAPI blobs under `keys\` (production or test fake).
///
/// Blobs are opaque PEM/raw key bytes only — no connection metadata. Missing
/// reads return `Ok(None)`; missing deletes succeed (C# best-effort).
pub trait KeyMaterialStore {
    /// Protect + write / overwrite the key blob for `credential_id`.
    fn store(&self, credential_id: &Uuid, key_bytes: &[u8]) -> Result<()>;

    /// Read + unprotect; `Ok(None)` when the blob is missing.
    fn read(&self, credential_id: &Uuid) -> Result<Option<Vec<u8>>>;

    /// Delete the key blob. Missing files succeed.
    fn delete(&self, credential_id: &Uuid) -> Result<()>;
}

/// Production DPAPI key store under a confined `keys` root.
///
/// Free helpers [`write_key_payload`] / [`read_key_payload`] / [`delete_key_payload`]
/// use the default profile root; construct [`DpapiKeyMaterialStore::under`] for
/// injectable roots (tests).
#[derive(Clone)]
pub struct DpapiKeyMaterialStore {
    keys_root: PathBuf,
}

impl fmt::Debug for DpapiKeyMaterialStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Root path length only — never key material or full path strings in Debug.
        f.debug_struct("DpapiKeyMaterialStore")
            .field("keys_root_len", &self.keys_root.as_os_str().len())
            .finish()
    }
}

impl Default for DpapiKeyMaterialStore {
    fn default() -> Self {
        Self::new()
    }
}

impl DpapiKeyMaterialStore {
    /// Default profile: `%LOCALAPPDATA%\Wormhole\keys`.
    pub fn new() -> Self {
        Self {
            keys_root: keys_dir(),
        }
    }

    /// Injectable `keys` root (temp dirs in tests).
    pub fn under(keys_root: impl Into<PathBuf>) -> Self {
        Self {
            keys_root: keys_root.into(),
        }
    }

    /// Confined keys root used by this store.
    pub fn keys_root(&self) -> &Path {
        &self.keys_root
    }
}

impl KeyMaterialStore for DpapiKeyMaterialStore {
    fn store(&self, credential_id: &Uuid, key_bytes: &[u8]) -> Result<()> {
        write_key_payload_under(&self.keys_root, credential_id, key_bytes)
    }

    fn read(&self, credential_id: &Uuid) -> Result<Option<Vec<u8>>> {
        read_key_payload_under(&self.keys_root, credential_id)
    }

    fn delete(&self, credential_id: &Uuid) -> Result<()> {
        delete_key_payload_under(&self.keys_root, credential_id)
    }
}

/// In-memory key-material stand-in for unit tests (no DPAPI / no filesystem).
///
/// Store/read copy buffers (C# `FakeCredentialService` lifetime contract) so
/// callers may zero inputs/outputs without corrupting the fake. [`Debug`]
/// exposes only entry counts / call counts / byte lengths — never key contents.
pub struct FakeKeyMaterialStore {
    entries: Mutex<HashMap<Uuid, Vec<u8>>>,
    store_calls: AtomicUsize,
    read_calls: AtomicUsize,
    delete_calls: AtomicUsize,
}

impl Default for FakeKeyMaterialStore {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for FakeKeyMaterialStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        let lengths: Vec<usize> = entries.values().map(|b| b.len()).collect();
        f.debug_struct("FakeKeyMaterialStore")
            .field("entry_count", &entries.len())
            .field("entry_byte_lengths", &lengths)
            .field("store_calls", &self.store_calls.load(Ordering::SeqCst))
            .field("read_calls", &self.read_calls.load(Ordering::SeqCst))
            .field("delete_calls", &self.delete_calls.load(Ordering::SeqCst))
            .finish()
    }
}

impl FakeKeyMaterialStore {
    /// Empty memory store.
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            store_calls: AtomicUsize::new(0),
            read_calls: AtomicUsize::new(0),
            delete_calls: AtomicUsize::new(0),
        }
    }

    fn entries_guard(&self) -> std::sync::MutexGuard<'_, HashMap<Uuid, Vec<u8>>> {
        self.entries.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// How many times [`KeyMaterialStore::store`] was invoked.
    pub fn store_calls(&self) -> usize {
        self.store_calls.load(Ordering::SeqCst)
    }

    /// How many times [`KeyMaterialStore::read`] was invoked.
    pub fn read_calls(&self) -> usize {
        self.read_calls.load(Ordering::SeqCst)
    }

    /// How many times [`KeyMaterialStore::delete`] was invoked.
    pub fn delete_calls(&self) -> usize {
        self.delete_calls.load(Ordering::SeqCst)
    }

    /// Number of key blobs currently held (tests).
    pub fn len(&self) -> usize {
        self.entries_guard().len()
    }

    /// Whether the memory store holds no key blobs.
    pub fn is_empty(&self) -> bool {
        self.entries_guard().is_empty()
    }
}

impl KeyMaterialStore for FakeKeyMaterialStore {
    fn store(&self, credential_id: &Uuid, key_bytes: &[u8]) -> Result<()> {
        self.store_calls.fetch_add(1, Ordering::SeqCst);
        self.entries_guard()
            .insert(*credential_id, key_bytes.to_vec());
        Ok(())
    }

    fn read(&self, credential_id: &Uuid) -> Result<Option<Vec<u8>>> {
        self.read_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.entries_guard().get(credential_id).cloned())
    }

    fn delete(&self, credential_id: &Uuid) -> Result<()> {
        self.delete_calls.fetch_add(1, Ordering::SeqCst);
        self.entries_guard().remove(credential_id);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tunnel payload store (CRUD)
// ---------------------------------------------------------------------------

/// DI surface for tunnel-config DPAPI blobs under `tunnels\` (production or test fake).
///
/// Blobs are opaque provider secret bytes only — SQLite holds metadata. Missing
/// reads return `Ok(None)`; missing deletes succeed (C# best-effort). Deletes
/// must not read or unprotect the blob.
pub trait TunnelPayloadStore {
    /// Protect + write / overwrite the tunnel blob for `tunnel_config_id`.
    fn store(&self, tunnel_config_id: &Uuid, payload: &[u8]) -> Result<()>;

    /// Read + unprotect; `Ok(None)` when the blob is missing.
    fn read(&self, tunnel_config_id: &Uuid) -> Result<Option<Vec<u8>>>;

    /// Delete the tunnel blob. Missing files succeed; never unprotects.
    fn delete(&self, tunnel_config_id: &Uuid) -> Result<()>;
}

/// Production DPAPI tunnel store under a confined `tunnels` root.
#[derive(Clone)]
pub struct DpapiTunnelPayloadStore {
    tunnels_root: PathBuf,
}

impl fmt::Debug for DpapiTunnelPayloadStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DpapiTunnelPayloadStore")
            .field("tunnels_root_len", &self.tunnels_root.as_os_str().len())
            .finish()
    }
}

impl Default for DpapiTunnelPayloadStore {
    fn default() -> Self {
        Self::new()
    }
}

impl DpapiTunnelPayloadStore {
    /// Default profile: `%LOCALAPPDATA%\Wormhole\tunnels`.
    pub fn new() -> Self {
        Self {
            tunnels_root: tunnels_dir(),
        }
    }

    /// Injectable `tunnels` root (temp dirs in tests).
    pub fn under(tunnels_root: impl Into<PathBuf>) -> Self {
        Self {
            tunnels_root: tunnels_root.into(),
        }
    }

    /// Confined tunnels root used by this store.
    pub fn tunnels_root(&self) -> &Path {
        &self.tunnels_root
    }
}

impl TunnelPayloadStore for DpapiTunnelPayloadStore {
    fn store(&self, tunnel_config_id: &Uuid, payload: &[u8]) -> Result<()> {
        write_tunnel_payload_under(&self.tunnels_root, tunnel_config_id, payload)
    }

    fn read(&self, tunnel_config_id: &Uuid) -> Result<Option<Vec<u8>>> {
        read_tunnel_payload_under(&self.tunnels_root, tunnel_config_id)
    }

    fn delete(&self, tunnel_config_id: &Uuid) -> Result<()> {
        delete_tunnel_payload_under(&self.tunnels_root, tunnel_config_id)
    }
}

/// In-memory tunnel-payload stand-in for unit tests (no DPAPI / no filesystem).
///
/// Store/read copy buffers (same lifetime contract as [`FakeKeyMaterialStore`]).
/// [`Debug`] exposes only entry counts / call counts / byte lengths — never
/// payload contents.
pub struct FakeTunnelPayloadStore {
    entries: Mutex<HashMap<Uuid, Vec<u8>>>,
    store_calls: AtomicUsize,
    read_calls: AtomicUsize,
    delete_calls: AtomicUsize,
}

impl Default for FakeTunnelPayloadStore {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for FakeTunnelPayloadStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        let lengths: Vec<usize> = entries.values().map(|b| b.len()).collect();
        f.debug_struct("FakeTunnelPayloadStore")
            .field("entry_count", &entries.len())
            .field("entry_byte_lengths", &lengths)
            .field("store_calls", &self.store_calls.load(Ordering::SeqCst))
            .field("read_calls", &self.read_calls.load(Ordering::SeqCst))
            .field("delete_calls", &self.delete_calls.load(Ordering::SeqCst))
            .finish()
    }
}

impl FakeTunnelPayloadStore {
    /// Empty memory store.
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            store_calls: AtomicUsize::new(0),
            read_calls: AtomicUsize::new(0),
            delete_calls: AtomicUsize::new(0),
        }
    }

    fn entries_guard(&self) -> std::sync::MutexGuard<'_, HashMap<Uuid, Vec<u8>>> {
        self.entries.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// How many times [`TunnelPayloadStore::store`] was invoked.
    pub fn store_calls(&self) -> usize {
        self.store_calls.load(Ordering::SeqCst)
    }

    /// How many times [`TunnelPayloadStore::read`] was invoked.
    pub fn read_calls(&self) -> usize {
        self.read_calls.load(Ordering::SeqCst)
    }

    /// How many times [`TunnelPayloadStore::delete`] was invoked.
    pub fn delete_calls(&self) -> usize {
        self.delete_calls.load(Ordering::SeqCst)
    }

    /// Number of tunnel blobs currently held (tests).
    pub fn len(&self) -> usize {
        self.entries_guard().len()
    }

    /// Whether the memory store holds no tunnel blobs.
    pub fn is_empty(&self) -> bool {
        self.entries_guard().is_empty()
    }
}

impl TunnelPayloadStore for FakeTunnelPayloadStore {
    fn store(&self, tunnel_config_id: &Uuid, payload: &[u8]) -> Result<()> {
        self.store_calls.fetch_add(1, Ordering::SeqCst);
        self.entries_guard()
            .insert(*tunnel_config_id, payload.to_vec());
        Ok(())
    }

    fn read(&self, tunnel_config_id: &Uuid) -> Result<Option<Vec<u8>>> {
        self.read_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.entries_guard().get(tunnel_config_id).cloned())
    }

    fn delete(&self, tunnel_config_id: &Uuid) -> Result<()> {
        self.delete_calls.fetch_add(1, Ordering::SeqCst);
        self.entries_guard().remove(tunnel_config_id);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Free helpers — keys (null entropy, path-confined)
// ---------------------------------------------------------------------------

/// Protect + write `keys\<id:N>.dpapi` under the default profile (null entropy).
pub fn write_key_payload(credential_id: &Uuid, plaintext: &[u8]) -> Result<()> {
    write_key_payload_under(&keys_dir(), credential_id, plaintext)
}

/// Read + unprotect the default-profile key file. Missing → `Ok(None)`.
pub fn read_key_payload(credential_id: &Uuid) -> Result<Option<Vec<u8>>> {
    read_key_payload_under(&keys_dir(), credential_id)
}

/// Delete the default-profile key file. Missing → `Ok(())`.
///
/// Never reads or unprotects the blob (no plaintext in memory on delete).
pub fn delete_key_payload(credential_id: &Uuid) -> Result<()> {
    delete_key_payload_under(&keys_dir(), credential_id)
}

/// Protect + write under an injectable `keys_root` (temp dirs in tests).
///
/// Resolves the path via [`key_path_under`] before any I/O — hostile roots /
/// escapes never reach `write_protected_file`. Same non-atomic write as C#
/// `CredentialService.StorePrivateKeyAsync` / [`write_tunnel_payload_under`]
/// (cache files use [`crate::write_protected_file_atomic`] separately).
pub fn write_key_payload_under(
    keys_root: &Path,
    credential_id: &Uuid,
    plaintext: &[u8],
) -> Result<()> {
    let path = key_path_under(keys_root, credential_id)?;
    write_protected_file(&path, plaintext, None)
}

/// Read + unprotect under an injectable `keys_root`. Missing → `Ok(None)`.
///
/// Path confinement runs before any filesystem read.
pub fn read_key_payload_under(
    keys_root: &Path,
    credential_id: &Uuid,
) -> Result<Option<Vec<u8>>> {
    let path = key_path_under(keys_root, credential_id)?;
    read_protected_file(&path, None)
}

/// Delete under an injectable `keys_root`. Missing → `Ok(())`.
///
/// Path confinement runs before any filesystem delete — hostile roots never
/// reach `remove_file`. Never reads or unprotects the blob.
pub fn delete_key_payload_under(keys_root: &Path, credential_id: &Uuid) -> Result<()> {
    let path = key_path_under(keys_root, credential_id)?;
    delete_protected_file_if_exists(&path)
}

// ---------------------------------------------------------------------------
// Free helpers — tunnels (null entropy, path-confined)
// ---------------------------------------------------------------------------

/// Protect + write `tunnels\<id:N>.dpapi` under the default profile (null entropy).
pub fn write_tunnel_payload(tunnel_config_id: &Uuid, plaintext: &[u8]) -> Result<()> {
    write_tunnel_payload_under(&tunnels_dir(), tunnel_config_id, plaintext)
}

/// Read + unprotect the default-profile tunnel file. Missing → `Ok(None)`.
pub fn read_tunnel_payload(tunnel_config_id: &Uuid) -> Result<Option<Vec<u8>>> {
    read_tunnel_payload_under(&tunnels_dir(), tunnel_config_id)
}

/// Delete the default-profile tunnel file. Missing → `Ok(())`.
///
/// Never reads or unprotects the blob (no plaintext in memory on delete).
pub fn delete_tunnel_payload(tunnel_config_id: &Uuid) -> Result<()> {
    delete_tunnel_payload_under(&tunnels_dir(), tunnel_config_id)
}

/// Protect + write under an injectable `tunnels_root` (temp dirs in tests).
///
/// Resolves the path via [`tunnel_path_under`] before any I/O — hostile roots /
/// escapes never reach `write_protected_file`. Same non-atomic write as C#
/// `CredentialService.StoreTunnelConfigAsync` / [`write_key_payload_under`]
/// (cache files use [`crate::write_protected_file_atomic`] separately).
pub fn write_tunnel_payload_under(
    tunnels_root: &Path,
    tunnel_config_id: &Uuid,
    plaintext: &[u8],
) -> Result<()> {
    let path = tunnel_path_under(tunnels_root, tunnel_config_id)?;
    write_protected_file(&path, plaintext, None)
}

/// Read + unprotect under an injectable `tunnels_root`. Missing → `Ok(None)`.
///
/// Path confinement runs before any filesystem read.
pub fn read_tunnel_payload_under(
    tunnels_root: &Path,
    tunnel_config_id: &Uuid,
) -> Result<Option<Vec<u8>>> {
    let path = tunnel_path_under(tunnels_root, tunnel_config_id)?;
    read_protected_file(&path, None)
}

/// Delete under an injectable `tunnels_root`. Missing → `Ok(())`.
///
/// Path confinement runs before any filesystem delete — hostile roots never
/// reach `remove_file`. Never reads or unprotects the blob.
pub fn delete_tunnel_payload_under(
    tunnels_root: &Path,
    tunnel_config_id: &Uuid,
) -> Result<()> {
    let path = tunnel_path_under(tunnels_root, tunnel_config_id)?;
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
        // PathNotConfined must never embed path / key material.
        assert!(!text.contains("never-written"));
        assert!(!text.contains("private-key"));
        assert!(!text.contains("Windows"));
        assert!(!text.contains("outside"));
        assert!(!text.contains(r"C:\"));
        assert!(!text.contains(".dpapi"));
    }

    #[test]
    fn write_read_delete_helpers_reject_hostile_root_before_io() {
        let id = Uuid::nil();
        let secret = b"never-written-private-key-material";
        let dir = tempfile::tempdir().unwrap();
        // Lexical `..` in the root PathBuf — confinement must fail before mkdir/write/read/delete.
        let hostile_keys = dir.path().join("keys").join("..").join("outside");
        let hostile_tunnels = dir.path().join("tunnels").join("..").join("outside");

        let err = write_key_payload_under(&hostile_keys, &id, secret).unwrap_err();
        assert_path_not_confined(&err, "key_path_under");

        let err = read_key_payload_under(&hostile_keys, &id).unwrap_err();
        assert_path_not_confined(&err, "key_path_under");

        let err = delete_key_payload_under(&hostile_keys, &id).unwrap_err();
        assert_path_not_confined(&err, "key_path_under");

        let err = write_tunnel_payload_under(&hostile_tunnels, &id, secret).unwrap_err();
        assert_path_not_confined(&err, "tunnel_path_under");

        let err = read_tunnel_payload_under(&hostile_tunnels, &id).unwrap_err();
        assert_path_not_confined(&err, "tunnel_path_under");

        let err = delete_tunnel_payload_under(&hostile_tunnels, &id).unwrap_err();
        assert_path_not_confined(&err, "tunnel_path_under");

        // Filesystem untouched: no `outside` dir, no children under the temp root.
        assert!(!dir.path().join("outside").exists());
        let children: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert!(
            children.is_empty(),
            "hostile root must not create dirs/files: {children:?}"
        );

        let err = write_key_payload_under(Path::new(r"C:\temp\..\Windows"), &id, secret).unwrap_err();
        assert_path_not_confined(&err, "key_path_under");
        let err = delete_key_payload_under(Path::new(r"C:\temp\..\Windows"), &id).unwrap_err();
        assert_path_not_confined(&err, "key_path_under");
        let err = write_key_payload_under(Path::new(""), &id, secret).unwrap_err();
        assert_path_not_confined(&err, "key_path_under");
        let err = delete_key_payload_under(Path::new(""), &id).unwrap_err();
        assert_path_not_confined(&err, "key_path_under");
        let err = write_tunnel_payload_under(Path::new(""), &id, secret).unwrap_err();
        assert_path_not_confined(&err, "tunnel_path_under");
        let err = delete_tunnel_payload_under(Path::new(""), &id).unwrap_err();
        assert_path_not_confined(&err, "tunnel_path_under");
    }

    #[test]
    fn fake_key_and_tunnel_defensive_copies_isolate_caller_buffers() {
        // Mirror C# FakeCredentialService: store/read copy so callers can zero/reuse.
        let keys = FakeKeyMaterialStore::new();
        let tunnels = FakeTunnelPayloadStore::new();
        let id = Uuid::parse_str("a7f3c1e2-9b6d-4e8a-bf21-7c0d2e5a4b91").unwrap();

        let mut key_in = b"-----BEGIN KEY-----\ncaller-owned\n-----END KEY-----".to_vec();
        let mut tun_in = br#"{"PrivateKey":"caller-owned-tun"}"#.to_vec();
        keys.store(&id, &key_in).unwrap();
        tunnels.store(&id, &tun_in).unwrap();
        key_in.fill(0);
        tun_in.fill(0);

        let mut key_out = keys.read(&id).unwrap().expect("key");
        let mut tun_out = tunnels.read(&id).unwrap().expect("tun");
        assert_eq!(
            key_out.as_slice(),
            b"-----BEGIN KEY-----\ncaller-owned\n-----END KEY-----"
        );
        assert_eq!(tun_out.as_slice(), br#"{"PrivateKey":"caller-owned-tun"}"#);
        key_out.fill(0xFF);
        tun_out.fill(0xFF);
        assert_eq!(
            keys.read(&id).unwrap().as_deref(),
            Some(b"-----BEGIN KEY-----\ncaller-owned\n-----END KEY-----".as_slice())
        );
        assert_eq!(
            tunnels.read(&id).unwrap().as_deref(),
            Some(br#"{"PrivateKey":"caller-owned-tun"}"#.as_slice())
        );
    }

    #[test]
    fn fake_key_and_tunnel_concurrent_store_read_delete_debug_safe() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let keys = Arc::new(FakeKeyMaterialStore::new());
        let tunnels = Arc::new(FakeTunnelPayloadStore::new());
        let barrier = Arc::new(Barrier::new(8));
        let mut handles = Vec::new();
        for i in 0..8 {
            let keys = Arc::clone(&keys);
            let tunnels = Arc::clone(&tunnels);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let id = Uuid::from_u128(i as u128 + 1);
                let secret = format!("concurrent-secret-{i}");
                barrier.wait();
                match i % 4 {
                    0 => {
                        keys.store(&id, secret.as_bytes()).unwrap();
                        let _ = keys.read(&id).unwrap();
                    }
                    1 => {
                        tunnels.store(&id, secret.as_bytes()).unwrap();
                        let _ = tunnels.read(&id).unwrap();
                    }
                    2 => {
                        keys.store(&id, secret.as_bytes()).unwrap();
                        keys.delete(&id).unwrap();
                    }
                    _ => {
                        tunnels.store(&id, secret.as_bytes()).unwrap();
                        tunnels.delete(&id).unwrap();
                    }
                }
            }));
        }
        for h in handles {
            h.join().expect("thread");
        }
        let key_dbg = format!("{keys:?}");
        let tun_dbg = format!("{tunnels:?}");
        assert!(!key_dbg.contains("concurrent-secret"));
        assert!(!tun_dbg.contains("concurrent-secret"));
        assert!(key_dbg.contains("entry_count"));
        assert!(tun_dbg.contains("entry_byte_lengths"));
    }

    #[test]
    fn fake_key_material_store_crud_and_debug_redacts() {
        let store = FakeKeyMaterialStore::new();
        let id = Uuid::parse_str("a7f3c1e2-9b6d-4e8a-bf21-7c0d2e5a4b91").unwrap();
        let key = b"-----BEGIN OPENSSH PRIVATE KEY-----\nfake-test-key\n-----END OPENSSH PRIVATE KEY-----";

        assert!(store.is_empty());
        assert!(store.read(&id).unwrap().is_none());

        store.store(&id, key).unwrap();
        assert_eq!(store.len(), 1);
        assert_eq!(store.read(&id).unwrap().as_deref(), Some(key.as_slice()));

        // Overwrite
        store.store(&id, b"short").unwrap();
        assert_eq!(store.read(&id).unwrap().as_deref(), Some(b"short".as_slice()));

        store.delete(&id).unwrap();
        assert!(store.is_empty());
        assert!(store.read(&id).unwrap().is_none());
        // Missing delete succeeds.
        store.delete(&id).unwrap();

        assert_eq!(store.store_calls(), 2);
        assert_eq!(store.read_calls(), 4);
        assert_eq!(store.delete_calls(), 2);

        let debug = format!("{store:?}");
        assert!(!debug.contains("OPENSSH"));
        assert!(!debug.contains("fake-test-key"));
        assert!(!debug.contains("short"));
        assert!(debug.contains("entry_byte_lengths") || debug.contains("entry_count"));
    }

    #[test]
    fn fake_tunnel_payload_store_crud_and_debug_redacts() {
        let store = FakeTunnelPayloadStore::new();
        let id = Uuid::parse_str("a7f3c1e2-9b6d-4e8a-bf21-7c0d2e5a4b91").unwrap();
        let payload = br#"{"PrivateKey":"wg-secret-never-in-debug"}"#;

        assert!(store.is_empty());
        assert!(store.read(&id).unwrap().is_none());
        store.store(&id, payload).unwrap();
        assert_eq!(store.len(), 1);
        assert_eq!(store.read(&id).unwrap().as_deref(), Some(payload.as_slice()));

        // Overwrite (Fake ↔ DPAPI contract) including empty blob.
        store.store(&id, b"").unwrap();
        assert_eq!(store.read(&id).unwrap().as_deref(), Some(b"".as_slice()));
        store.store(&id, b"short-tun").unwrap();
        assert_eq!(store.read(&id).unwrap().as_deref(), Some(b"short-tun".as_slice()));

        store.delete(&id).unwrap();
        assert!(store.is_empty());
        assert!(store.read(&id).unwrap().is_none());
        // Missing delete succeeds.
        store.delete(&id).unwrap();

        assert_eq!(store.store_calls(), 3);
        assert_eq!(store.read_calls(), 5);
        assert_eq!(store.delete_calls(), 2);

        let debug = format!("{store:?}");
        assert!(!debug.contains("wg-secret"));
        assert!(!debug.contains("PrivateKey"));
        assert!(!debug.contains("short-tun"));
        assert!(debug.contains("entry_byte_lengths") || debug.contains("entry_count"));
    }

    #[test]
    fn key_material_store_trait_object_with_fake() {
        let store: Box<dyn KeyMaterialStore> = Box::new(FakeKeyMaterialStore::new());
        let id = Uuid::nil();
        store.store(&id, b"k").unwrap();
        assert_eq!(store.read(&id).unwrap().as_deref(), Some(b"k".as_slice()));
        store.delete(&id).unwrap();
        assert!(store.read(&id).unwrap().is_none());
    }

    #[test]
    fn tunnel_payload_store_trait_object_with_fake() {
        let store: Box<dyn TunnelPayloadStore> = Box::new(FakeTunnelPayloadStore::new());
        let id = Uuid::nil();
        store.store(&id, b"tun").unwrap();
        assert_eq!(store.read(&id).unwrap().as_deref(), Some(b"tun".as_slice()));
        store.delete(&id).unwrap();
        assert!(store.read(&id).unwrap().is_none());
    }

    #[test]
    fn key_and_tunnel_stores_are_distinct_backends() {
        // Same id, different stores — must not share backends.
        let keys = FakeKeyMaterialStore::new();
        let tunnels = FakeTunnelPayloadStore::new();
        let id = Uuid::nil();
        keys.store(&id, b"ssh-key").unwrap();
        tunnels.store(&id, b"wg-tun").unwrap();
        assert_eq!(keys.read(&id).unwrap().as_deref(), Some(b"ssh-key".as_slice()));
        assert_eq!(tunnels.read(&id).unwrap().as_deref(), Some(b"wg-tun".as_slice()));
        keys.delete(&id).unwrap();
        assert!(keys.read(&id).unwrap().is_none());
        assert_eq!(tunnels.read(&id).unwrap().as_deref(), Some(b"wg-tun".as_slice()));
    }

    #[cfg(windows)]
    #[test]
    fn key_and_tunnel_payload_roundtrip_under_temp() {
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        let tunnels = dir.path().join("tunnels");
        let id = Uuid::parse_str("a7f3c1e2-9b6d-4e8a-bf21-7c0d2e5a4b91").unwrap();

        let key_plain = b"-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----";
        let tunnel_plain = br#"{"PrivateKey":"wg-secret"}"#;

        assert!(read_key_payload_under(&keys, &id).unwrap().is_none());
        assert!(read_tunnel_payload_under(&tunnels, &id).unwrap().is_none());

        write_key_payload_under(&keys, &id, key_plain).unwrap();
        write_tunnel_payload_under(&tunnels, &id, tunnel_plain).unwrap();

        let got_key = read_key_payload_under(&keys, &id).unwrap();
        assert_eq!(got_key.as_deref(), Some(key_plain.as_slice()));
        let got_tunnel = read_tunnel_payload_under(&tunnels, &id).unwrap();
        assert_eq!(got_tunnel.as_deref(), Some(tunnel_plain.as_slice()));

        // Files landed only under the injected roots.
        let key_path = key_path_under(&keys, &id).unwrap();
        let tunnel_path = tunnel_path_under(&tunnels, &id).unwrap();
        assert!(key_path.is_file());
        assert!(tunnel_path.is_file());
        assert!(key_path.starts_with(&keys));
        assert!(tunnel_path.starts_with(&tunnels));
        assert!(!key_path
            .to_string_lossy()
            .contains("BEGIN OPENSSH"));

        // CRUD delete: confined remove; missing delete is Ok.
        delete_key_payload_under(&keys, &id).unwrap();
        assert!(!key_path.exists());
        assert!(read_key_payload_under(&keys, &id).unwrap().is_none());
        delete_key_payload_under(&keys, &id).unwrap();

        delete_tunnel_payload_under(&tunnels, &id).unwrap();
        assert!(!tunnel_path.exists());
        assert!(read_tunnel_payload_under(&tunnels, &id).unwrap().is_none());
        delete_tunnel_payload_under(&tunnels, &id).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn tunnel_payload_never_writes_sibling_keys_dir() {
        // Same guid under sibling keys\ / tunnels\ — tunnel CRUD must not touch keys\.
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        let tunnels = dir.path().join("tunnels");
        let id = Uuid::parse_str("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        let secret = br#"{"PrivateKey":"tun-must-not-land-in-keys"}"#;

        fs::create_dir_all(&keys).unwrap();
        write_tunnel_payload_under(&tunnels, &id, secret).unwrap();

        let tunnel_path = tunnel_path_under(&tunnels, &id).unwrap();
        let key_path = key_path_under(&keys, &id).unwrap();
        assert!(tunnel_path.is_file());
        assert!(!key_path.exists());
        assert!(keys.read_dir().unwrap().next().is_none());

        // Escape into sibling keys via lexical .. must fail closed before I/O.
        let escape_to_keys = tunnels.join("..").join("keys");
        let err = write_tunnel_payload_under(&escape_to_keys, &id, secret).unwrap_err();
        assert_path_not_confined(&err, "tunnel_path_under");
        let err = read_tunnel_payload_under(&escape_to_keys, &id).unwrap_err();
        assert_path_not_confined(&err, "tunnel_path_under");
        let err = delete_tunnel_payload_under(&escape_to_keys, &id).unwrap_err();
        assert_path_not_confined(&err, "tunnel_path_under");
        assert!(!key_path.exists());
        assert!(keys.read_dir().unwrap().next().is_none());

        // Join-replacement forms never reach the filesystem via tunnel helpers.
        let err = write_tunnel_payload_under(Path::new(r"C:\temp\..\Windows"), &id, secret)
            .unwrap_err();
        assert_path_not_confined(&err, "tunnel_path_under");
        let err = delete_tunnel_payload_under(Path::new(r"C:\temp\..\Windows"), &id).unwrap_err();
        assert_path_not_confined(&err, "tunnel_path_under");

        delete_tunnel_payload_under(&tunnels, &id).unwrap();
        assert!(read_tunnel_payload_under(&tunnels, &id).unwrap().is_none());
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_key_material_store_crud_under_temp() {
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        let store = DpapiKeyMaterialStore::under(&keys);
        let id = Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap();
        let key = b"-----BEGIN PRIVATE KEY-----\nunit\n-----END PRIVATE KEY-----";

        assert!(store.read(&id).unwrap().is_none());
        store.store(&id, key).unwrap();
        assert_eq!(store.read(&id).unwrap().as_deref(), Some(key.as_slice()));

        // Overwrite + empty blob (C# WriteAllBytesAsync accepts empty).
        store.store(&id, b"").unwrap();
        assert_eq!(store.read(&id).unwrap().as_deref(), Some(b"".as_slice()));
        store.store(&id, key).unwrap();
        assert_eq!(store.read(&id).unwrap().as_deref(), Some(key.as_slice()));

        let path = key_path_under(store.keys_root(), &id).unwrap();
        assert!(path.is_file());
        assert!(path.starts_with(&keys));

        store.delete(&id).unwrap();
        assert!(!path.exists());
        assert!(store.read(&id).unwrap().is_none());
        store.delete(&id).unwrap();

        // Hostile root: fail closed before I/O.
        let hostile = DpapiKeyMaterialStore::under(dir.path().join("k").join("..").join("out"));
        let err = hostile.store(&id, key).unwrap_err();
        assert_path_not_confined(&err, "key_path_under");
        let err = hostile.delete(&id).unwrap_err();
        assert_path_not_confined(&err, "key_path_under");

        let dbg = format!("{store:?}");
        assert!(!dbg.contains("PRIVATE KEY"));
        assert!(!dbg.contains("unit"));
        assert!(dbg.contains("keys_root_len"));
        assert!(!dbg.contains(keys.to_string_lossy().as_ref()));
    }

    #[cfg(windows)]
    #[test]
    fn delete_key_and_tunnel_never_unprotects_corrupt_ciphertext() {
        // Delete must remove ciphertext without CryptUnprotectData — corrupt blobs
        // would fail if delete tried to read/unprotect first.
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        let tunnels = dir.path().join("tunnels");
        let id = Uuid::parse_str("33333333-4444-5555-6666-777777777777").unwrap();

        let key_path = key_path_under(&keys, &id).unwrap();
        let tunnel_path = tunnel_path_under(&tunnels, &id).unwrap();
        fs::create_dir_all(&keys).unwrap();
        fs::create_dir_all(&tunnels).unwrap();
        fs::write(&key_path, b"not-valid-dpapi-ciphertext-KEY-MARKER").unwrap();
        fs::write(&tunnel_path, b"not-valid-dpapi-ciphertext-TUN-MARKER").unwrap();

        // Reads fail closed on corrupt blobs (proves ciphertext is unreadable).
        let read_err = read_key_payload_under(&keys, &id).unwrap_err();
        assert!(matches!(read_err, SecretsError::DpapiUnprotect));
        assert!(!format!("{read_err} / {read_err:?}").contains("KEY-MARKER"));

        let tun_read_err = read_tunnel_payload_under(&tunnels, &id).unwrap_err();
        assert!(matches!(tun_read_err, SecretsError::DpapiUnprotect));
        assert!(!format!("{tun_read_err} / {tun_read_err:?}").contains("TUN-MARKER"));

        delete_key_payload_under(&keys, &id).unwrap();
        assert!(!key_path.exists());
        assert!(read_key_payload_under(&keys, &id).unwrap().is_none());

        // Delete succeeds without unprotect — corrupt blob would still be gone.
        delete_tunnel_payload_under(&tunnels, &id).unwrap();
        assert!(!tunnel_path.exists());
        assert!(read_tunnel_payload_under(&tunnels, &id).unwrap().is_none());
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_tunnel_payload_store_crud_under_temp() {
        let dir = tempfile::tempdir().unwrap();
        let tunnels = dir.path().join("tunnels");
        let store = DpapiTunnelPayloadStore::under(&tunnels);
        let id = Uuid::parse_str("22222222-3333-4444-5555-666666666666").unwrap();
        let payload = br#"{"Endpoint":"10.0.0.1","Secret":"tun-payload-marker"}"#;

        assert!(store.read(&id).unwrap().is_none());
        store.store(&id, payload).unwrap();
        assert_eq!(store.read(&id).unwrap().as_deref(), Some(payload.as_slice()));

        // Overwrite + empty blob (parity with KeyMaterialStore / C# WriteAllBytesAsync).
        store.store(&id, b"").unwrap();
        assert_eq!(store.read(&id).unwrap().as_deref(), Some(b"".as_slice()));
        store.store(&id, br#"{"Endpoint":"10.0.0.2"}"#).unwrap();
        assert_eq!(
            store.read(&id).unwrap().as_deref(),
            Some(br#"{"Endpoint":"10.0.0.2"}"#.as_slice())
        );

        let path = tunnel_path_under(store.tunnels_root(), &id).unwrap();
        assert!(path.is_file());
        assert!(path.starts_with(&tunnels));
        // Ciphertext on disk must not contain plaintext markers.
        let on_disk = fs::read(&path).unwrap();
        let marker = b"tun-payload-marker";
        let endpoint = b"10.0.0.2";
        assert!(!on_disk.windows(marker.len()).any(|w| w == marker));
        assert!(!on_disk.windows(endpoint.len()).any(|w| w == endpoint));

        store.delete(&id).unwrap();
        assert!(!path.exists());
        assert!(store.read(&id).unwrap().is_none());
        store.delete(&id).unwrap();

        // Hostile root: store / read / delete all fail closed before I/O.
        let hostile = DpapiTunnelPayloadStore::under(dir.path().join("t").join("..").join("out"));
        let err = hostile.store(&id, payload).unwrap_err();
        assert_path_not_confined(&err, "tunnel_path_under");
        let err = hostile.read(&id).unwrap_err();
        assert_path_not_confined(&err, "tunnel_path_under");
        let err = hostile.delete(&id).unwrap_err();
        assert_path_not_confined(&err, "tunnel_path_under");
        assert!(!dir.path().join("out").exists());

        let empty = DpapiTunnelPayloadStore::under(Path::new(""));
        let err = empty.store(&id, payload).unwrap_err();
        assert_path_not_confined(&err, "tunnel_path_under");
        let err = empty.delete(&id).unwrap_err();
        assert_path_not_confined(&err, "tunnel_path_under");

        let dbg = format!("{store:?}");
        assert!(dbg.contains("tunnels_root_len"));
        assert!(!dbg.contains("10.0.0"));
        assert!(!dbg.contains("tun-payload-marker"));
        assert!(!dbg.contains(tunnels.to_string_lossy().as_ref()));
    }
}
