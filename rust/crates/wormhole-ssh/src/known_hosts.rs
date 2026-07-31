//! File-backed SSH host-key store under `%LOCALAPPDATA%\Wormhole\known_hosts`.
//!
//! Fingerprint format matches C# `SshHostKeyValidator.ComputeFingerprint`:
//! `SHA256:` + Base64(SHA-256(host_key_bytes)) with padding `=` stripped.
//!
//! Corrupt or hostile lines are skipped on load (soft-fail). Mismatch never
//! overwrites a pin. Saves use a unique temp file + atomic replace.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};

use crate::error::SshError;
use crate::Result;

/// Decision from comparing a captured fingerprint to a known pin.
///
/// Mirrors C# `HostKeyDecision`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKeyDecision {
    /// Captured fingerprint equals the known pin.
    Trust,
    /// No known pin — first sighting (caller may persist under TOFU).
    TofuAccept,
    /// Known pin differs from the captured fingerprint.
    Mismatch,
}

/// How [`KnownHostsStore::accept`] treats unknown / mismatched keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HostKeyPolicy {
    /// Unknown → accept and persist; match → accept; mismatch → reject.
    #[default]
    TrustOnFirstUse,
    /// Match → accept; unknown or mismatch → reject (no auto-pin).
    RejectMismatch,
}

/// In-memory + on-disk map of `host[:port]` → `SHA256:…` fingerprint.
#[derive(Debug, Clone)]
pub struct KnownHostsStore {
    path: PathBuf,
    /// Ordered for stable file output.
    entries: BTreeMap<String, String>,
}

impl KnownHostsStore {
    /// `%LOCALAPPDATA%\Wormhole\known_hosts` (falls back like other Wormhole paths).
    pub fn default_path() -> PathBuf {
        local_app_data().join("Wormhole").join("known_hosts")
    }

    /// Empty store that will save to `path`.
    pub fn empty(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            entries: BTreeMap::new(),
        }
    }

    /// Load from disk. Missing file → empty store (not an error).
    ///
    /// Corrupt UTF-8 or invalid lines are skipped (soft-fail); valid pins still load.
    /// Environmental I/O failures (permissions, etc.) still surface as errors.
    pub fn load(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let mut store = Self::empty(path.clone());
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(store),
            Err(e) => return Err(SshError::Io(e)),
        };
        let Ok(raw) = std::str::from_utf8(&bytes) else {
            // Corrupt encoding → empty store (soft-fail).
            return Ok(store);
        };
        for line in raw.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_whitespace();
            let Some(host) = parts.next() else {
                continue;
            };
            let Some(fp) = parts.next() else {
                continue;
            };
            if parts.next().is_some() {
                continue;
            }
            if validate_host_token(host).is_err() || validate_fingerprint(fp).is_err() {
                continue;
            }
            let key = normalize_host_key(host);
            store.entries.insert(key, fp.to_string());
        }
        Ok(store)
    }

    /// Load from the default Wormhole LocalAppData path.
    pub fn load_default() -> Result<Self> {
        Self::load(Self::default_path())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Look up a pinned fingerprint for `host` (port optional; see [`host_identity`]).
    pub fn get(&self, host: &str) -> Option<&str> {
        self.entries.get(&normalize_host_key(host)).map(String::as_str)
    }

    /// Insert/replace a pin in memory (does not write disk until [`Self::save`]).
    ///
    /// Rejects whitespace / control characters in `host` and non-`SHA256:` fingerprints
    /// so a hostile pin cannot poison the on-disk format.
    pub fn pin(&mut self, host: &str, fingerprint: &str) -> Result<()> {
        validate_host_token(host)?;
        validate_fingerprint(fingerprint)?;
        self.insert_pin(host, fingerprint);
        Ok(())
    }

    /// Remove a pin from memory (does not write disk). Used by prompt-glue rollback.
    pub fn unpin(&mut self, host: &str) {
        self.entries.remove(&normalize_host_key(host));
    }

    /// Compare against the store without mutating.
    pub fn decide(&self, host: &str, captured_fingerprint: &str) -> HostKeyDecision {
        decide(self.get(host), captured_fingerprint)
    }

    /// Apply `policy` for `host`/`fingerprint`. May pin + save on TOFU.
    ///
    /// Returns `true` when the key should be accepted.
    /// Mismatch never overwrites an existing pin (in memory or on disk).
    pub fn accept(
        &mut self,
        host: &str,
        fingerprint: &str,
        policy: HostKeyPolicy,
    ) -> Result<bool> {
        validate_host_token(host)?;
        validate_fingerprint(fingerprint)?;
        match (policy, self.decide(host, fingerprint)) {
            (_, HostKeyDecision::Trust) => Ok(true),
            (HostKeyPolicy::TrustOnFirstUse, HostKeyDecision::TofuAccept) => {
                self.insert_pin(host, fingerprint);
                if let Err(e) = self.save() {
                    // Roll back the in-memory pin so a failed persist cannot leave a
                    // Trust decision that never reached disk.
                    self.entries.remove(&normalize_host_key(host));
                    return Err(e);
                }
                Ok(true)
            }
            (HostKeyPolicy::RejectMismatch, HostKeyDecision::TofuAccept) => Ok(false),
            (_, HostKeyDecision::Mismatch) => Ok(false),
        }
    }

    fn insert_pin(&mut self, host: &str, fingerprint: &str) {
        self.entries
            .insert(normalize_host_key(host), fingerprint.to_string());
    }

    /// Persist entries atomically (unique `*.tmp` then replace). Creates parent dirs.
    pub fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = temp_path_for(&self.path);
        let write = (|| -> Result<()> {
            {
                let mut f = fs::File::create(&tmp)?;
                writeln!(f, "# wormhole-ssh known_hosts v1")?;
                writeln!(f, "# <host[:port]> <SHA256:fingerprint>")?;
                for (host, fp) in &self.entries {
                    writeln!(f, "{host} {fp}")?;
                }
                f.sync_all()?;
            }
            replace_file(&tmp, &self.path)?;
            Ok(())
        })();
        if write.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        write
    }
}

/// OpenSSH-style SHA-256 fingerprint of raw host-key bytes (C# parity).
pub fn compute_fingerprint(host_key: &[u8]) -> String {
    let digest = Sha256::digest(host_key);
    format!("SHA256:{}", STANDARD_NO_PAD.encode(digest))
}

/// Compare known vs captured fingerprints (C# `SshHostKeyValidator.Decide` parity).
///
/// Empty / missing known → [`HostKeyDecision::TofuAccept`]. Comparison is ordinal.
/// Empty `captured_fingerprint` → [`HostKeyDecision::Mismatch`] (Rust soft-fail; C# throws
/// `ArgumentException` — callers that need hard failure use [`KnownHostsStore::accept`]).
pub fn decide(known_fingerprint: Option<&str>, captured_fingerprint: &str) -> HostKeyDecision {
    if captured_fingerprint.is_empty() {
        return HostKeyDecision::Mismatch;
    }
    match known_fingerprint {
        None | Some("") => HostKeyDecision::TofuAccept,
        Some(known) if known == captured_fingerprint => HostKeyDecision::Trust,
        Some(_) => HostKeyDecision::Mismatch,
    }
}

/// Build a store key: `host` or `host:port` (host lowercased; IPv6 bracket form preserved).
pub fn host_identity(host: &str, port: Option<u16>) -> String {
    let host = normalize_host_only(host);
    match port {
        Some(p) => format!("{host}:{p}"),
        None => host,
    }
}

/// Host token safe for the single-line `host fingerprint` file format.
pub(crate) fn validate_host_token(host: &str) -> Result<()> {
    let host = host.trim();
    if host.is_empty() {
        return Err(SshError::Other("known_hosts host must be non-empty".into()));
    }
    if host.bytes().any(|b| b.is_ascii_whitespace() || b.is_ascii_control()) {
        return Err(SshError::Other(
            "known_hosts host must not contain whitespace or control characters".into(),
        ));
    }
    Ok(())
}

/// Fingerprint must be `SHA256:` + non-empty unpadded Base64 (OpenSSH / C# shape).
pub(crate) fn validate_fingerprint(fp: &str) -> Result<()> {
    let Some(rest) = fp.strip_prefix("SHA256:") else {
        return Err(SshError::Other(
            "fingerprint must start with SHA256:".into(),
        ));
    };
    if rest.is_empty() {
        return Err(SshError::Other("fingerprint digest must be non-empty".into()));
    }
    if !rest
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
    {
        return Err(SshError::Other(
            "fingerprint digest must be unpadded Base64".into(),
        ));
    }
    Ok(())
}

pub(crate) fn normalize_host_key(host: &str) -> String {
    let host = host.trim();
    // Split host:port when the host is not an unbracketed IPv6 (contains ':').
    if let Some((h, port)) = split_host_port(host) {
        return format!("{}:{port}", normalize_host_only(h));
    }
    normalize_host_only(host)
}

fn normalize_host_only(host: &str) -> String {
    host.trim().to_ascii_lowercase()
}

fn split_host_port(host: &str) -> Option<(&str, &str)> {
    if host.starts_with('[') {
        let end = host.find(']')?;
        let rest = &host[end + 1..];
        let port = rest.strip_prefix(':')?;
        if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        return Some((&host[..=end], port));
    }
    // hostname:port or ipv4:port — single trailing :port
    let (h, port) = host.rsplit_once(':')?;
    if h.is_empty() || port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // Unbracketed IPv6 has multiple colons — do not treat as host:port.
    if h.contains(':') {
        return None;
    }
    Some((h, port))
}

fn local_app_data() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("USERPROFILE").map(|p| PathBuf::from(p).join("AppData").join("Local"))
        })
        .unwrap_or_else(|| PathBuf::from(r"C:\Users\Default\AppData\Local"))
}

static TMP_SEQ: AtomicU64 = AtomicU64::new(1);

fn temp_path_for(path: &Path) -> PathBuf {
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut os = path.as_os_str().to_os_string();
    os.push(".");
    os.push(format!("{}.{nanos}.{seq}.tmp", std::process::id()));
    PathBuf::from(os)
}

/// Atomic replace matching C# `File.Move(tmp, dest, overwrite: true)` on NTFS.
fn replace_file(from: &Path, to: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        replace_file_windows(from, to)
    }
    #[cfg(not(windows))]
    {
        fs::rename(from, to)
    }
}

#[cfg(windows)]
fn replace_file_windows(from: &Path, to: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
        fn GetLastError() -> u32;
    }

    fn wide(p: &Path) -> Vec<u16> {
        p.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
    }

    let from_w = wide(from);
    let to_w = wide(to);
    let ok = unsafe { MoveFileExW(from_w.as_ptr(), to_w.as_ptr(), MOVEFILE_REPLACE_EXISTING) };
    if ok == 0 {
        Err(io::Error::from_raw_os_error(unsafe { GetLastError() } as i32))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn fingerprint_matches_csharp_test_vector() {
        // Wormhole.Tests Services/SshHostKeyValidatorTests: UTF8 "test"
        assert_eq!(
            compute_fingerprint(b"test"),
            "SHA256:n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg"
        );
    }

    #[test]
    fn fingerprint_empty_bytes_matches_known_sha256() {
        // SHA-256 of empty input, unpadded Base64 (C# Convert.ToBase64String.TrimEnd('=')).
        assert_eq!(
            compute_fingerprint(b""),
            "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
        );
        assert!(!compute_fingerprint(b"").contains('='));
    }

    #[test]
    fn fingerprint_deterministic_and_distinct() {
        assert_eq!(
            compute_fingerprint(&[1, 2, 3]),
            compute_fingerprint(&[1, 2, 3])
        );
        assert_ne!(
            compute_fingerprint(&[1, 2, 3]),
            compute_fingerprint(&[1, 2, 4])
        );
        assert!(!compute_fingerprint(&[1, 2, 3, 4, 5]).contains('='));
    }

    #[test]
    fn decide_tofu_trust_mismatch() {
        assert_eq!(
            decide(None, "SHA256:abc"),
            HostKeyDecision::TofuAccept
        );
        assert_eq!(
            decide(Some(""), "SHA256:abc"),
            HostKeyDecision::TofuAccept
        );
        assert_eq!(
            decide(Some("SHA256:abc"), "SHA256:abc"),
            HostKeyDecision::Trust
        );
        assert_eq!(
            decide(Some("SHA256:abc"), "SHA256:xyz"),
            HostKeyDecision::Mismatch
        );
        // Ordinal — case sensitive like C#
        assert_eq!(
            decide(Some("SHA256:ABC"), "SHA256:abc"),
            HostKeyDecision::Mismatch
        );
    }

    #[test]
    fn tofu_pins_and_persists() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let mut store = KnownHostsStore::empty(&path);
        assert!(store
            .accept(
                "Example.COM:22",
                "SHA256:first",
                HostKeyPolicy::TrustOnFirstUse
            )
            .unwrap());
        assert_eq!(store.get("example.com:22"), Some("SHA256:first"));
        assert!(path.is_file());

        let mut reloaded = KnownHostsStore::load(&path).unwrap();
        assert_eq!(reloaded.get("example.com:22"), Some("SHA256:first"));
        assert!(reloaded
            .accept(
                "example.com:22",
                "SHA256:first",
                HostKeyPolicy::TrustOnFirstUse
            )
            .unwrap());
        assert!(!reloaded
            .accept(
                "example.com:22",
                "SHA256:other",
                HostKeyPolicy::TrustOnFirstUse
            )
            .unwrap());
        // Mismatch must not overwrite the pin.
        assert_eq!(reloaded.get("example.com:22"), Some("SHA256:first"));
        let disk = KnownHostsStore::load(&path).unwrap();
        assert_eq!(disk.get("example.com:22"), Some("SHA256:first"));
    }

    #[test]
    fn mismatch_never_overwrites_disk() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let mut store = KnownHostsStore::empty(&path);
        store
            .accept("h:22", "SHA256:good", HostKeyPolicy::TrustOnFirstUse)
            .unwrap();
        let before = fs::read_to_string(&path).unwrap();
        assert!(!store
            .accept("h:22", "SHA256:evil", HostKeyPolicy::TrustOnFirstUse)
            .unwrap());
        assert_eq!(fs::read_to_string(&path).unwrap(), before);
        assert_eq!(store.get("h:22"), Some("SHA256:good"));
    }

    #[test]
    fn reject_mismatch_rejects_unknown_and_mismatch() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let mut store = KnownHostsStore::empty(&path);
        assert!(!store
            .accept("h:22", "SHA256:new", HostKeyPolicy::RejectMismatch)
            .unwrap());
        assert!(store.is_empty());
        assert!(!path.exists());

        store.pin("h:22", "SHA256:known").unwrap();
        assert!(store
            .accept("h:22", "SHA256:known", HostKeyPolicy::RejectMismatch)
            .unwrap());
        assert!(!store
            .accept("h:22", "SHA256:evil", HostKeyPolicy::RejectMismatch)
            .unwrap());
        assert_eq!(store.get("h:22"), Some("SHA256:known"));
    }

    #[test]
    fn load_skips_comments_roundtrips() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        fs::write(
            &path,
            "# header\n\nhost-a:22 SHA256:aaa\n# mid\nhost-b SHA256:bbb\n",
        )
        .unwrap();
        let store = KnownHostsStore::load(&path).unwrap();
        assert_eq!(store.len(), 2);
        assert_eq!(store.get("host-a:22"), Some("SHA256:aaa"));
        assert_eq!(store.get("HOST-B"), Some("SHA256:bbb"));
        store.save().unwrap();
        let again = KnownHostsStore::load(&path).unwrap();
        assert_eq!(again.get("host-a:22"), Some("SHA256:aaa"));
    }

    #[test]
    fn load_soft_fails_bad_lines_keeps_valid() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        fs::write(
            &path,
            concat!(
                "good:22 SHA256:okfp\n",
                "h:22 MD5:deadbeef\n",
                "missing-fp\n",
                "too many fields SHA256:x extra\n",
                "host with spaces SHA256:abc\n",
                "also:22 SHA256:\n",
                "pad:22 SHA256:abc=\n",
                "host-b SHA256:bbb\n",
            ),
        )
        .unwrap();
        let store = KnownHostsStore::load(&path).unwrap();
        assert_eq!(store.get("good:22"), Some("SHA256:okfp"));
        assert_eq!(store.get("host-b"), Some("SHA256:bbb"));
        assert!(store.get("h:22").is_none());
        assert!(store.get("also:22").is_none());
        assert!(store.get("pad:22").is_none());
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn load_soft_fails_invalid_utf8() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        fs::write(&path, [0xff, 0xfe, 0xfd]).unwrap();
        let store = KnownHostsStore::load(&path).unwrap();
        assert!(store.is_empty());
    }

    #[test]
    fn save_overwrites_existing_atomically() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let mut store = KnownHostsStore::empty(&path);
        store
            .accept("a:22", "SHA256:one", HostKeyPolicy::TrustOnFirstUse)
            .unwrap();
        store
            .accept("b:22", "SHA256:two", HostKeyPolicy::TrustOnFirstUse)
            .unwrap();
        let reloaded = KnownHostsStore::load(&path).unwrap();
        assert_eq!(reloaded.len(), 2);
        assert_eq!(reloaded.get("a:22"), Some("SHA256:one"));
        assert_eq!(reloaded.get("b:22"), Some("SHA256:two"));
        // No stale shared *.tmp left behind for the fixed name.
        assert!(!path.with_extension("tmp").exists());
    }

    #[test]
    fn reject_hostile_host_and_fingerprint() {
        let dir = tempdir().unwrap();
        let mut store = KnownHostsStore::empty(dir.path().join("kh"));
        assert!(store
            .accept("evil host", "SHA256:abc", HostKeyPolicy::TrustOnFirstUse)
            .is_err());
        assert!(store
            .accept("h\nwicked", "SHA256:abc", HostKeyPolicy::TrustOnFirstUse)
            .is_err());
        assert!(store
            .accept("h", "MD5:abc", HostKeyPolicy::TrustOnFirstUse)
            .is_err());
        assert!(store
            .accept("h", "SHA256:abc=def", HostKeyPolicy::TrustOnFirstUse)
            .is_err());
        assert!(store
            .accept("h", "SHA256:", HostKeyPolicy::TrustOnFirstUse)
            .is_err());
        assert!(store.is_empty());
    }

    #[test]
    fn default_path_under_wormhole() {
        let p = KnownHostsStore::default_path();
        let s = p.to_string_lossy();
        assert!(s.contains("Wormhole"));
        assert!(
            s.ends_with("known_hosts")
                || s.ends_with("known_hosts\\")
                || s.ends_with("known_hosts/")
        );
        assert_eq!(
            p.file_name().and_then(|n| n.to_str()),
            Some("known_hosts")
        );
    }

    #[test]
    fn host_identity_helpers() {
        assert_eq!(host_identity("Foo", Some(22)), "foo:22");
        assert_eq!(host_identity("Foo", None), "foo");
        assert_eq!(normalize_host_key("[::1]:22"), "[::1]:22");
        assert_eq!(normalize_host_key("2001:db8::1"), "2001:db8::1");
        assert_eq!(normalize_host_key("127.0.0.1:2222"), "127.0.0.1:2222");
    }

    #[test]
    fn accept_rejects_empty_fingerprint() {
        let dir = tempdir().unwrap();
        let mut store = KnownHostsStore::empty(dir.path().join("kh"));
        assert!(store
            .accept("h", "", HostKeyPolicy::TrustOnFirstUse)
            .is_err());
    }

    #[test]
    fn tofu_save_failure_rolls_back_memory_pin() {
        let dir = tempdir().unwrap();
        // Parent path is a file → create_dir_all / create fails on save.
        let blocker = dir.path().join("not-a-dir");
        fs::write(&blocker, b"x").unwrap();
        let path = blocker.join("known_hosts");
        let mut store = KnownHostsStore::empty(&path);
        assert!(store
            .accept("h:22", "SHA256:abc", HostKeyPolicy::TrustOnFirstUse)
            .is_err());
        assert!(store.get("h:22").is_none());
        assert!(store.is_empty());
    }

    #[test]
    fn path_like_host_is_map_key_not_traversal() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let mut store = KnownHostsStore::empty(&path);
        store
            .accept(
                "../outside:22",
                "SHA256:abc",
                HostKeyPolicy::TrustOnFirstUse,
            )
            .unwrap();
        // Saved under the store path only — host string is not joined as a filesystem path.
        assert!(path.is_file());
        assert!(!dir.path().join("outside").exists());
        assert_eq!(store.get("../outside:22"), Some("SHA256:abc"));
    }
}
