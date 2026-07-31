//! Process-local ephemeral session credential store.
//!
//! Mirrors C# `ITransientSessionCredentialStore` /
//! `TransientSessionCredentialStore` (`Services/ITransientSessionCredentialStore.cs`):
//! put / get / clear passwords keyed by a session **or** connection-node
//! [`Uuid`] (Quick Connect stores under `node.Id`; shell release uses
//! `profile.NodeId`). Entries are **never** written to SQLite, CredMgr, or
//! DPAPI — memory only for the process lifetime of an ephemeral tab.
//!
//! # Empty password
//!
//! [`TransientSessionCredentialStore::store`] fails closed on an empty
//! password (`""`) — parity with C# `ArgumentException.ThrowIfNullOrEmpty`.
//! Callers that have no usable password must skip `store` (C# Quick Connect
//! gates with `!string.IsNullOrEmpty`). Whitespace-only passwords are
//! accepted (same as C# `ThrowIfNullOrEmpty`, which does **not** treat
//! whitespace as empty).
//!
//! # Redaction
//!
//! [`Debug`] on store types never echoes password strings — only entry
//! counts, UTF-8 lengths, and call counters. Prefer [`crate::redact_secret`]
//! before logging around auth. Returned passwords from [`read`] must not be
//! logged.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use uuid::Uuid;

use crate::{Result, SecretsError};

/// DI surface for process-local ephemeral passwords (session or node key).
///
/// Implementations must **never** persist entries to disk / SQLite / CredMgr /
/// DPAPI. Missing reads return `None`; missing removes are no-ops.
pub trait TransientSessionCredentialStore: Send + Sync {
    /// Insert / overwrite a password for `key` (session id or connection node id).
    ///
    /// Empty passwords fail with [`SecretsError::EmptyPassword`] and leave the
    /// map unchanged. **Never** log `password`.
    fn store(&self, key: &Uuid, password: &str) -> Result<()>;

    /// Read a password; `None` when missing.
    ///
    /// **Never** log the returned value.
    fn read(&self, key: &Uuid) -> Option<String>;

    /// Remove one entry. Missing keys succeed (no-op).
    fn remove(&self, key: &Uuid);

    /// Drop every entry (e.g. shell tab-collection reset).
    fn clear(&self);
}

fn ensure_non_empty_password(password: &str) -> Result<()> {
    if password.is_empty() {
        return Err(SecretsError::EmptyPassword);
    }
    Ok(())
}

fn entry_utf8_byte_lengths(entries: &HashMap<Uuid, String>) -> Vec<usize> {
    entries.values().map(String::len).collect()
}

/// Production in-process store (C# `TransientSessionCredentialStore`).
///
/// Mutex-backed `HashMap` — safe across connect / tab-close threads. [`Debug`]
/// exposes entry count + UTF-8 lengths only (never password contents).
pub struct MemoryTransientSessionCredentialStore {
    entries: Mutex<HashMap<Uuid, String>>,
}

impl Default for MemoryTransientSessionCredentialStore {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for MemoryTransientSessionCredentialStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let entries = self.entries_guard();
        f.debug_struct("MemoryTransientSessionCredentialStore")
            .field("entry_count", &entries.len())
            .field("entry_utf8_byte_lengths", &entry_utf8_byte_lengths(&entries))
            .finish()
    }
}

impl MemoryTransientSessionCredentialStore {
    /// Empty process-local store.
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn entries_guard(&self) -> std::sync::MutexGuard<'_, HashMap<Uuid, String>> {
        self.entries.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Number of passwords currently held (tests / diagnostics — safe to log).
    pub fn len(&self) -> usize {
        self.entries_guard().len()
    }

    /// Whether the store holds no passwords.
    pub fn is_empty(&self) -> bool {
        self.entries_guard().is_empty()
    }
}

impl TransientSessionCredentialStore for MemoryTransientSessionCredentialStore {
    fn store(&self, key: &Uuid, password: &str) -> Result<()> {
        ensure_non_empty_password(password)?;
        // Defensive copy — caller may clear its buffer after put.
        self.entries_guard().insert(*key, password.to_owned());
        Ok(())
    }

    fn read(&self, key: &Uuid) -> Option<String> {
        self.entries_guard().get(key).cloned()
    }

    fn remove(&self, key: &Uuid) {
        self.entries_guard().remove(key);
    }

    fn clear(&self) {
        self.entries_guard().clear();
    }
}

/// Instrumented in-memory store for unit tests (no persistence).
///
/// Same empty-password fail-closed contract as production. [`Debug`] exposes
/// entry UTF-8 lengths + call counts only — never password contents.
pub struct FakeTransientSessionCredentialStore {
    entries: Mutex<HashMap<Uuid, String>>,
    store_calls: AtomicUsize,
    read_calls: AtomicUsize,
    remove_calls: AtomicUsize,
    clear_calls: AtomicUsize,
    reject_calls: AtomicUsize,
}

impl Default for FakeTransientSessionCredentialStore {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for FakeTransientSessionCredentialStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let entries = self.entries_guard();
        f.debug_struct("FakeTransientSessionCredentialStore")
            .field("entry_count", &entries.len())
            .field("entry_utf8_byte_lengths", &entry_utf8_byte_lengths(&entries))
            .field("store_calls", &self.store_calls.load(Ordering::SeqCst))
            .field("read_calls", &self.read_calls.load(Ordering::SeqCst))
            .field("remove_calls", &self.remove_calls.load(Ordering::SeqCst))
            .field("clear_calls", &self.clear_calls.load(Ordering::SeqCst))
            .field("reject_calls", &self.reject_calls.load(Ordering::SeqCst))
            .finish()
    }
}

impl FakeTransientSessionCredentialStore {
    /// Empty memory store.
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            store_calls: AtomicUsize::new(0),
            read_calls: AtomicUsize::new(0),
            remove_calls: AtomicUsize::new(0),
            clear_calls: AtomicUsize::new(0),
            reject_calls: AtomicUsize::new(0),
        }
    }

    fn entries_guard(&self) -> std::sync::MutexGuard<'_, HashMap<Uuid, String>> {
        self.entries.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// How many times [`TransientSessionCredentialStore::store`] was invoked
    /// (including empty-password rejects).
    pub fn store_calls(&self) -> usize {
        self.store_calls.load(Ordering::SeqCst)
    }

    /// How many times [`TransientSessionCredentialStore::read`] was invoked.
    pub fn read_calls(&self) -> usize {
        self.read_calls.load(Ordering::SeqCst)
    }

    /// How many times [`TransientSessionCredentialStore::remove`] was invoked.
    pub fn remove_calls(&self) -> usize {
        self.remove_calls.load(Ordering::SeqCst)
    }

    /// How many times [`TransientSessionCredentialStore::clear`] was invoked.
    pub fn clear_calls(&self) -> usize {
        self.clear_calls.load(Ordering::SeqCst)
    }

    /// How many stores were rejected (empty password).
    pub fn reject_calls(&self) -> usize {
        self.reject_calls.load(Ordering::SeqCst)
    }

    /// Number of passwords currently held.
    pub fn len(&self) -> usize {
        self.entries_guard().len()
    }

    /// Whether the memory store holds no passwords.
    pub fn is_empty(&self) -> bool {
        self.entries_guard().is_empty()
    }
}

impl TransientSessionCredentialStore for FakeTransientSessionCredentialStore {
    fn store(&self, key: &Uuid, password: &str) -> Result<()> {
        self.store_calls.fetch_add(1, Ordering::SeqCst);
        if let Err(err) = ensure_non_empty_password(password) {
            self.reject_calls.fetch_add(1, Ordering::SeqCst);
            return Err(err);
        }
        self.entries_guard().insert(*key, password.to_owned());
        Ok(())
    }

    fn read(&self, key: &Uuid) -> Option<String> {
        self.read_calls.fetch_add(1, Ordering::SeqCst);
        self.entries_guard().get(key).cloned()
    }

    fn remove(&self, key: &Uuid) {
        self.remove_calls.fetch_add(1, Ordering::SeqCst);
        self.entries_guard().remove(key);
    }

    fn clear(&self) {
        self.clear_calls.fetch_add(1, Ordering::SeqCst);
        self.entries_guard().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    #[test]
    fn memory_store_put_get_remove_by_node_or_session_key() {
        let store = MemoryTransientSessionCredentialStore::new();
        let node_key = Uuid::new_v4();
        let session_key = Uuid::new_v4();

        store.store(&node_key, "qc-secret").unwrap();
        store.store(&session_key, "tab-secret").unwrap();
        assert_eq!(store.read(&node_key).as_deref(), Some("qc-secret"));
        assert_eq!(store.read(&session_key).as_deref(), Some("tab-secret"));
        assert_eq!(store.len(), 2);

        store.remove(&node_key);
        assert!(store.read(&node_key).is_none());
        assert_eq!(store.read(&session_key).as_deref(), Some("tab-secret"));

        store.clear();
        assert!(store.is_empty());
        assert!(store.read(&session_key).is_none());
    }

    #[test]
    fn empty_password_fails_closed_and_leaves_map_unchanged() {
        let store = FakeTransientSessionCredentialStore::new();
        let key = Uuid::new_v4();
        store.store(&key, "kept").unwrap();

        let err = store.store(&key, "").expect_err("empty must fail");
        assert!(matches!(err, SecretsError::EmptyPassword));
        assert_eq!(store.reject_calls(), 1);
        assert_eq!(store.read(&key).as_deref(), Some("kept"));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn memory_empty_password_fails_closed_and_leaves_map_unchanged() {
        // Production path must match Fake — empty reject before insert (C# ThrowIfNullOrEmpty).
        let store = MemoryTransientSessionCredentialStore::new();
        let key = Uuid::new_v4();
        store.store(&key, "kept").unwrap();

        let err = store.store(&key, "").expect_err("empty must fail");
        assert!(matches!(err, SecretsError::EmptyPassword));
        assert_eq!(store.read(&key).as_deref(), Some("kept"));
        assert_eq!(store.len(), 1);
        // Reject must not clobber an existing entry under the same key.
        assert!(!format!("{store:?}").contains("kept"));
    }

    #[test]
    fn whitespace_only_password_accepted_like_csharp_throw_if_null_or_empty() {
        // C# ArgumentException.ThrowIfNullOrEmpty rejects "" only — not " ".
        let store = MemoryTransientSessionCredentialStore::new();
        let key = Uuid::new_v4();
        store.store(&key, " ").unwrap();
        assert_eq!(store.read(&key).as_deref(), Some(" "));
    }

    #[test]
    fn unicode_and_embedded_nul_roundtrip_never_echoed_in_debug() {
        // Memory-only store has no CredMgr size ceiling; UTF-8 / NUL must survive intact.
        let store = MemoryTransientSessionCredentialStore::new();
        let key = Uuid::new_v4();
        let secret = "pässwörd-\0-🔒-Σ";
        store.store(&key, secret).unwrap();
        assert_eq!(store.read(&key).as_deref(), Some(secret));

        let fake = FakeTransientSessionCredentialStore::new();
        fake.store(&key, secret).unwrap();
        assert_eq!(fake.read(&key).as_deref(), Some(secret));

        let memory_dbg = format!("{store:?}");
        let fake_dbg = format!("{fake:?}");
        assert!(!memory_dbg.contains("päss"));
        assert!(!memory_dbg.contains('🔒'));
        assert!(!fake_dbg.contains("päss"));
        assert!(!fake_dbg.contains('\0'));
        assert!(
            memory_dbg.contains(&format!("entry_utf8_byte_lengths: [{}]", secret.len())),
            "expected length-only Debug, got {memory_dbg}"
        );
    }

    #[test]
    fn missing_read_is_none_missing_remove_is_noop() {
        let store = FakeTransientSessionCredentialStore::new();
        let missing = Uuid::new_v4();
        assert!(store.read(&missing).is_none());
        store.remove(&missing);
        assert_eq!(store.remove_calls(), 1);
        assert!(store.is_empty());
    }

    #[test]
    fn store_overwrites_same_key() {
        let store = MemoryTransientSessionCredentialStore::new();
        let key = Uuid::new_v4();
        store.store(&key, "first").unwrap();
        store.store(&key, "second").unwrap();
        assert_eq!(store.read(&key).as_deref(), Some("second"));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn debug_redacts_password_material() {
        let memory = MemoryTransientSessionCredentialStore::new();
        let fake = FakeTransientSessionCredentialStore::new();
        let key = Uuid::new_v4();
        memory.store(&key, "super-secret-password").unwrap();
        fake.store(&key, "super-secret-password").unwrap();

        let memory_dbg = format!("{memory:?}");
        let fake_dbg = format!("{fake:?}");
        assert!(!memory_dbg.contains("super-secret-password"));
        assert!(!fake_dbg.contains("super-secret-password"));
        assert!(memory_dbg.contains("entry_utf8_byte_lengths"));
        assert!(fake_dbg.contains("entry_utf8_byte_lengths"));
        assert!(fake_dbg.contains("store_calls"));
    }

    #[test]
    fn empty_password_error_display_never_embeds_secret() {
        let err = SecretsError::EmptyPassword;
        let text = format!("{err:?}{err}");
        assert!(!text.contains("password="));
        assert!(text.contains("EmptyPassword") || text.contains("empty"));
    }

    #[test]
    fn fake_call_counters_and_clear() {
        let store = FakeTransientSessionCredentialStore::new();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        store.store(&a, "a").unwrap();
        store.store(&b, "b").unwrap();
        let _ = store.read(&a);
        store.remove(&a);
        store.clear();
        assert_eq!(store.store_calls(), 2);
        assert_eq!(store.read_calls(), 1);
        assert_eq!(store.remove_calls(), 1);
        assert_eq!(store.clear_calls(), 1);
        assert!(store.is_empty());
    }

    #[test]
    fn concurrent_store_read_remove_is_safe() {
        let store = Arc::new(FakeTransientSessionCredentialStore::new());
        let barrier = Arc::new(Barrier::new(4));
        let mut handles = Vec::new();

        for i in 0..4 {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                let key = Uuid::from_u128(i as u128 + 1);
                let pw = format!("pw-{i}");
                store.store(&key, &pw).unwrap();
                assert_eq!(store.read(&key).as_deref(), Some(pw.as_str()));
                // Debug must not panic under contention / poison recovery.
                let _ = format!("{store:?}");
                if i % 2 == 0 {
                    store.remove(&key);
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }
        // Odd `i` keys kept (Uuid 2, 4); even `i` removed (Uuid 1, 3).
        assert_eq!(store.len(), 2);
        assert!(store.read(&Uuid::from_u128(1)).is_none());
        assert!(store.read(&Uuid::from_u128(2)).is_some());
        assert!(store.read(&Uuid::from_u128(3)).is_none());
        assert!(store.read(&Uuid::from_u128(4)).is_some());
    }

    #[test]
    fn memory_concurrent_store_read_remove_clear_is_safe() {
        // Production Mutex map — isolation + Debug-under-contention + interleaved clear
        // must not panic / poison. Exact per-key reads are not asserted while clear races.
        let store = Arc::new(MemoryTransientSessionCredentialStore::new());
        let barrier = Arc::new(Barrier::new(5));
        let mut handles = Vec::new();

        for i in 0..4 {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                let key = Uuid::from_u128(100 + i as u128);
                let pw = format!("mem-pw-{i}");
                for _ in 0..16 {
                    let _ = store.store(&key, &pw);
                    let _ = store.read(&key);
                    let _ = format!("{store:?}");
                    if i % 2 == 0 {
                        store.remove(&key);
                    }
                }
            }));
        }
        {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                for _ in 0..32 {
                    store.clear();
                    let _ = format!("{store:?}");
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }
        // Post-race settle: map usable, Debug never echoes the password.
        let settle = Uuid::from_u128(999);
        store.store(&settle, "post-race").unwrap();
        assert_eq!(store.read(&settle).as_deref(), Some("post-race"));
        assert!(!format!("{store:?}").contains("post-race"));
    }

    #[test]
    fn trait_object_usable_for_di() {
        let store: Arc<dyn TransientSessionCredentialStore> =
            Arc::new(MemoryTransientSessionCredentialStore::new());
        let key = Uuid::new_v4();
        store.store(&key, "via-trait").unwrap();
        assert_eq!(store.read(&key).as_deref(), Some("via-trait"));
        store.remove(&key);
        store.clear();
    }
}
