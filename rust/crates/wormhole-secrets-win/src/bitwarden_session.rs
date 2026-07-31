//! Bitwarden CLI unlock / session-key stub.
//!
//! C# keeps the `bw unlock` session key **memory-only** (`BW_SESSION`) and never
//! writes it to SQLite or backup — see `BitwardenCliVaultClient` /
//! `interop-inventory.md`. Interactive CLI spawn + unlock is **not** wired here
//! yet ([`BITWARDEN_CLI_SESSION_GAP`]).
//!
//! # Traits
//!
//! - [`BitwardenSession`] — status / unlock / lock / session-key peek
//!
//! Production uses [`StubBitwardenSession`] (fail-closed: never unlocks, never
//! holds a key). Unit tests inject [`FakeBitwardenSession`] (scripted outcomes,
//! no `bw` process).
//!
//! **Never** log master passwords, session keys, OTP codes, or
//! `WORMHOLE_BW_PASSWORD` / `BW_SESSION` values. Prefer
//! [`crate::redact_env_and_cli_secrets`] before logging any CLI stderr. `Debug`
//! on session types redacts keys; unlock results expose UI-safe messages only.
//!
//! Bitwarden **browser** WebView2 profiles / shared-storage paths are a separate
//! surface (`paths` + `wormhole-http::bitwarden`) — not this CLI session stub.

use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// Documented gap: `bw` process spawn + unlock/session is not wired in Rust yet.
///
/// The shipping C# app runs `bw unlock` / `bw sync` via `BitwardenProcessRunner`
/// and keeps the resulting session key in memory only (`BW_SESSION`). Until that
/// lands, vault password resolution must stay disabled / fail closed.
pub const BITWARDEN_CLI_SESSION_GAP: &str = "Bitwarden CLI unlock/session is not yet wired in Rust. Vault passwords cannot be resolved until bw process + memory-only session key handling lands.";

/// Memory-only Bitwarden CLI session key (`BW_SESSION` value).
///
/// `Debug` / `Display` never echo the key — only length — so logging a held
/// session cannot leak material. Prefer [`crate::redact_secret`] if a caller
/// must mention that a key exists. Compare or assert secrets via [`Self::expose`],
/// never via `format!("{:?}", key)`.
#[derive(Clone, PartialEq, Eq)]
pub struct BitwardenSessionKey {
    value: String,
}

impl BitwardenSessionKey {
    /// Wrap a session key string (tests / future CLI parser only).
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
        }
    }

    /// Borrow the raw key. **Never** log the return value.
    pub fn expose(&self) -> &str {
        &self.value
    }

    /// UTF-8 byte length (safe to log / assert).
    pub fn len(&self) -> usize {
        self.value.len()
    }

    /// Whether the key is blank (empty or whitespace-only).
    ///
    /// Matches C# `BitwardenSessionService.HasSessionKey` /
    /// `IsNullOrWhiteSpace` — a whitespace-only key is not a usable
    /// `BW_SESSION` value.
    pub fn is_empty(&self) -> bool {
        self.value.trim().is_empty()
    }
}

impl fmt::Debug for BitwardenSessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BitwardenSessionKey")
            .field("len", &self.value.len())
            .finish()
    }
}

impl fmt::Display for BitwardenSessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[redacted session key; len={}]", self.value.len())
    }
}

/// Whether a Bitwarden CLI session is currently unlocked in-process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitwardenSessionStatus {
    /// No memory-only session key held (locked / never unlocked / locked again).
    Locked,
    /// Session key held in memory only (Fake or future real CLI unlock).
    Unlocked,
}

/// Outcome of an unlock attempt (UI-safe message only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitwardenUnlockResult {
    /// Whether unlock succeeded and a session key is now held.
    pub unlocked: bool,
    /// Human-readable reason (safe to show in UI; never contains secrets).
    pub message: String,
}

impl BitwardenUnlockResult {
    /// Convenience constructor.
    pub fn new(unlocked: bool, message: impl Into<String>) -> Self {
        Self {
            unlocked,
            message: message.into(),
        }
    }
}

impl fmt::Display for BitwardenUnlockResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({})",
            self.message,
            if self.unlocked {
                "unlocked"
            } else {
                "locked"
            }
        )
    }
}

/// Bitwarden CLI session holder (memory-only session key).
///
/// Implementations must **never** persist the session key to disk / SQLite /
/// backup, and must not write master passwords or session keys to logs.
pub trait BitwardenSession: Send + Sync {
    /// Current in-process lock state.
    fn status(&self) -> BitwardenSessionStatus;

    /// Attempt unlock with the vault master password.
    ///
    /// `master_password` is accepted for API parity with C# and must not be
    /// retained or logged. Production stubs ignore it and fail closed.
    fn unlock(&self, master_password: &str) -> BitwardenUnlockResult;

    /// Clear any held session key (no-op when already locked).
    fn lock(&self);

    /// Peek the memory-only session key, if unlocked.
    ///
    /// **Never** log the returned value. Prefer status checks for UI.
    fn session_key(&self) -> Option<BitwardenSessionKey>;
}

/// Production stub: always locked; unlock always fails with [`BITWARDEN_CLI_SESSION_GAP`].
///
/// Does not spawn `bw`, does not read env passwords / `BW_SESSION`, and never
/// claims unlocked.
#[derive(Debug, Default, Clone, Copy)]
pub struct StubBitwardenSession;

impl BitwardenSession for StubBitwardenSession {
    fn status(&self) -> BitwardenSessionStatus {
        BitwardenSessionStatus::Locked
    }

    fn unlock(&self, master_password: &str) -> BitwardenUnlockResult {
        let _ = master_password; // never retain — may be secret
        BitwardenUnlockResult::new(false, BITWARDEN_CLI_SESSION_GAP)
    }

    fn lock(&self) {}

    fn session_key(&self) -> Option<BitwardenSessionKey> {
        None
    }
}

/// Free-function unlock stub (parity with Hello helpers).
///
/// Always fails closed with [`BITWARDEN_CLI_SESSION_GAP`]. Password is ignored.
pub fn unlock_bitwarden_session(master_password: &str) -> BitwardenUnlockResult {
    StubBitwardenSession.unlock(master_password)
}

/// Free-function status stub — always [`BitwardenSessionStatus::Locked`].
pub fn bitwarden_session_status() -> BitwardenSessionStatus {
    StubBitwardenSession.status()
}

fn non_empty_session_key(value: impl Into<String>) -> Option<BitwardenSessionKey> {
    let key = BitwardenSessionKey::new(value);
    // Parity with C# BitwardenSessionService.SetSessionKey (IsNullOrWhiteSpace).
    (!key.is_empty()).then_some(key)
}

struct FakeState {
    /// Key held only while unlocked; cleared on lock / failed unlock.
    key: Option<BitwardenSessionKey>,
    /// Non-empty key applied on a successful unlock. Empty / `None` → fail closed.
    scripted_key: Option<BitwardenSessionKey>,
    /// When false, unlock always fails with [`BITWARDEN_CLI_SESSION_GAP`].
    allow_unlock: bool,
}

/// Scripted Bitwarden session for unit tests (no `bw` process).
///
/// Configure unlock success/failure and an optional session key. Master
/// passwords passed to [`BitwardenSession::unlock`] are **not** retained
/// (avoids secret echo in `Debug` / harness state). Empty / whitespace-only
/// master passwords fail closed and clear any held key; empty / whitespace-only
/// scripted keys also fail closed. A single mutex owns mutable state so
/// Debug / unlock / lock cannot deadlock on lock order.
pub struct FakeBitwardenSession {
    state: Mutex<FakeState>,
    unlock_calls: AtomicUsize,
    lock_calls: AtomicUsize,
}

impl Default for FakeBitwardenSession {
    fn default() -> Self {
        Self::cli_gap()
    }
}

impl fmt::Debug for FakeBitwardenSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state_guard();
        f.debug_struct("FakeBitwardenSession")
            .field("unlocked", &state.key.is_some())
            .field("key_len", &state.key.as_ref().map(|k| k.len()))
            .field(
                "scripted_key_len",
                &state.scripted_key.as_ref().map(|k| k.len()),
            )
            .field("allow_unlock", &state.allow_unlock)
            .field("unlock_calls", &self.unlock_calls.load(Ordering::SeqCst))
            .field("lock_calls", &self.lock_calls.load(Ordering::SeqCst))
            .finish()
    }
}

impl FakeBitwardenSession {
    fn state_guard(&self) -> std::sync::MutexGuard<'_, FakeState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn new(scripted_key: Option<BitwardenSessionKey>, allow_unlock: bool) -> Self {
        Self {
            state: Mutex::new(FakeState {
                key: None,
                scripted_key,
                allow_unlock,
            }),
            unlock_calls: AtomicUsize::new(0),
            lock_calls: AtomicUsize::new(0),
        }
    }

    /// Fail-closed fake matching production stub (never unlocks).
    pub fn cli_gap() -> Self {
        Self::new(None, false)
    }

    /// Fake that unlocks successfully and holds `session_key` in memory.
    ///
    /// Do not put real vault session material in tests — use opaque tokens.
    /// Empty / whitespace keys are rejected at construction (fail closed →
    /// [`Self::cli_gap`]) and re-checked on unlock.
    pub fn with_session_key(session_key: impl Into<String>) -> Self {
        match non_empty_session_key(session_key) {
            Some(key) => Self::new(Some(key), true),
            None => Self::cli_gap(),
        }
    }

    /// Allow or deny unlock (tests).
    pub fn set_allow_unlock(&self, allow: bool) {
        self.state_guard().allow_unlock = allow;
    }

    /// Configure the key that will be held after a successful unlock.
    ///
    /// Empty strings are treated as `None` (fail closed on next unlock).
    pub fn set_scripted_key(&self, session_key: Option<impl Into<String>>) {
        self.state_guard().scripted_key = session_key.and_then(non_empty_session_key);
    }

    /// How many times [`BitwardenSession::unlock`] was called.
    pub fn unlock_calls(&self) -> usize {
        self.unlock_calls.load(Ordering::SeqCst)
    }

    /// How many times [`BitwardenSession::lock`] was called.
    pub fn lock_calls(&self) -> usize {
        self.lock_calls.load(Ordering::SeqCst)
    }
}

impl BitwardenSession for FakeBitwardenSession {
    fn status(&self) -> BitwardenSessionStatus {
        if self.state_guard().key.is_some() {
            BitwardenSessionStatus::Unlocked
        } else {
            BitwardenSessionStatus::Locked
        }
    }

    fn unlock(&self, master_password: &str) -> BitwardenUnlockResult {
        self.unlock_calls.fetch_add(1, Ordering::SeqCst);
        let mut state = self.state_guard();
        let fail_closed = |state: &mut FakeState| {
            state.key = None;
            BitwardenUnlockResult::new(false, BITWARDEN_CLI_SESSION_GAP)
        };
        // Fail closed on empty / whitespace-only master password — never retain it.
        if master_password.trim().is_empty() {
            return fail_closed(&mut state);
        }
        let _ = master_password; // never retain beyond the empty check
        if !state.allow_unlock {
            return fail_closed(&mut state);
        }
        // Re-check emptiness so a poisoned/hand-edited state cannot unlock empty.
        match state
            .scripted_key
            .as_ref()
            .filter(|k| !k.is_empty())
            .cloned()
        {
            Some(key) => {
                state.key = Some(key);
                BitwardenUnlockResult::new(true, "fake-unlocked")
            }
            None => fail_closed(&mut state),
        }
    }

    fn lock(&self) {
        self.lock_calls.fetch_add(1, Ordering::SeqCst);
        self.state_guard().key = None;
    }

    fn session_key(&self) -> Option<BitwardenSessionKey> {
        self.state_guard().key.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn stub_never_unlocks_or_exposes_key() {
        let stub = StubBitwardenSession;
        assert_eq!(stub.status(), BitwardenSessionStatus::Locked);
        let secret_pw = "hunter2-master-password";
        let result = stub.unlock(secret_pw);
        assert!(!result.unlocked);
        assert_eq!(result.message, BITWARDEN_CLI_SESSION_GAP);
        assert!(stub.session_key().is_none());
        assert!(!result.message.contains("hunter2"));
        assert!(!format!("{result}").contains("hunter2"));
        assert!(!format!("{result:?}").contains("hunter2"));
        assert!(!format!("{stub:?}").contains("hunter2"));
    }

    #[test]
    fn stub_never_silently_unlocks_from_password_or_env_shaped_input() {
        // Production stub is pure fail-closed: ignores master password, does not
        // read BW_SESSION / WORMHOLE_BW_PASSWORD from the process environment,
        // and never echoes password-shaped input in results / Debug.
        let stub = StubBitwardenSession;
        for pw in [
            "",
            "BW_SESSION=env-injected-session-key-MUST-NOT-LEAK",
            "WORMHOLE_BW_PASSWORD=env-injected-master-pw",
            "hunter2-master-password",
        ] {
            assert_eq!(stub.status(), BitwardenSessionStatus::Locked);
            let r = stub.unlock(pw);
            assert!(!r.unlocked);
            assert_eq!(r.message, BITWARDEN_CLI_SESSION_GAP);
            assert!(stub.session_key().is_none());
            assert!(!format!("{r:?}").contains("env-injected"));
            assert!(!format!("{r:?}").contains("hunter2"));
            assert!(!format!("{stub:?}").contains("env-injected"));
        }
        assert_eq!(bitwarden_session_status(), BitwardenSessionStatus::Locked);
        assert!(!unlock_bitwarden_session("BW_SESSION=x").unlocked);
    }

    #[test]
    fn free_helpers_fail_closed() {
        let secret = "WORMHOLE_BW_PASSWORD=should-not-echo";
        let result = unlock_bitwarden_session(secret);
        assert!(!result.unlocked);
        assert_eq!(result.message, BITWARDEN_CLI_SESSION_GAP);
        assert!(!format!("{result:?}").contains("should-not-echo"));
        assert_eq!(bitwarden_session_status(), BitwardenSessionStatus::Locked);
    }

    #[test]
    fn session_key_debug_redacts_value() {
        let secret = "BW_SESSION_SUPER_SECRET_TOKEN";
        let key = BitwardenSessionKey::new(secret);
        let dbg = format!("{key:?}");
        let display = format!("{key}");
        // Never use Debug/Display as a secret oracle — only expose().
        assert_ne!(dbg, secret);
        assert_ne!(display, secret);
        assert!(!dbg.contains("SUPER_SECRET"));
        assert!(!display.contains("SUPER_SECRET"));
        assert!(!dbg.contains(secret));
        assert!(!display.contains(secret));
        assert!(dbg.contains("len"));
        assert_eq!(key.expose(), secret);
        assert_eq!(key.len(), secret.len());
        assert!(!key.is_empty());
    }

    #[test]
    fn session_key_is_empty_treats_whitespace_as_blank() {
        // Parity with C# HasSessionKey / IsNullOrWhiteSpace — whitespace is not usable.
        assert!(BitwardenSessionKey::new("").is_empty());
        assert!(BitwardenSessionKey::new("   ").is_empty());
        assert!(BitwardenSessionKey::new("\t\n").is_empty());
        assert!(!BitwardenSessionKey::new("x").is_empty());
        // Debug still reports raw UTF-8 len (not a secret oracle).
        let blank = BitwardenSessionKey::new("  ");
        assert!(format!("{blank:?}").contains("len: 2"));
        assert!(!format!("{blank:?}").contains("  "));
    }

    #[test]
    fn fake_cli_gap_matches_production() {
        let fake = FakeBitwardenSession::cli_gap();
        assert_eq!(fake.status(), BitwardenSessionStatus::Locked);
        let r = fake.unlock("master-pw-xyz");
        assert!(!r.unlocked);
        assert_eq!(r.message, BITWARDEN_CLI_SESSION_GAP);
        assert!(fake.session_key().is_none());
        assert_eq!(fake.unlock_calls(), 1);
        assert!(!format!("{fake:?}").contains("master-pw"));
    }

    #[test]
    fn fake_unlock_lock_cycle_holds_key_without_echoing_password() {
        let fake = FakeBitwardenSession::with_session_key("opaque-test-session");
        let pw = "real-vault-password-never-store";
        let unlocked = fake.unlock(pw);
        assert!(unlocked.unlocked);
        assert_eq!(unlocked.message, "fake-unlocked");
        assert_eq!(fake.status(), BitwardenSessionStatus::Unlocked);
        let key = fake.session_key().expect("key held");
        assert_eq!(key.expose(), "opaque-test-session");
        let dbg = format!("{fake:?}");
        assert!(!dbg.contains("real-vault-password"));
        assert!(!dbg.contains("opaque-test-session"));
        assert!(dbg.contains("key_len"));
        // Debug of held key must not equal expose().
        assert_ne!(format!("{key:?}"), key.expose());

        fake.lock();
        assert_eq!(fake.status(), BitwardenSessionStatus::Locked);
        assert!(fake.session_key().is_none());
        assert_eq!(fake.lock_calls(), 1);
    }

    #[test]
    fn fake_denied_unlock_clears_prior_key() {
        let fake = FakeBitwardenSession::with_session_key("opaque-a");
        assert!(fake.unlock("pw").unlocked);
        fake.set_allow_unlock(false);
        let r = fake.unlock("pw2");
        assert!(!r.unlocked);
        assert_eq!(r.message, BITWARDEN_CLI_SESSION_GAP);
        assert!(fake.session_key().is_none());
        assert_eq!(fake.status(), BitwardenSessionStatus::Locked);
    }

    #[test]
    fn fake_set_scripted_key_none_fails_closed() {
        let fake = FakeBitwardenSession::with_session_key("opaque-b");
        fake.set_scripted_key(None::<String>);
        let r = fake.unlock("pw");
        assert!(!r.unlocked);
        assert!(fake.session_key().is_none());
    }

    #[test]
    fn fake_empty_scripted_key_fails_closed() {
        let empty = FakeBitwardenSession::with_session_key("");
        assert_eq!(empty.status(), BitwardenSessionStatus::Locked);
        let r = empty.unlock("pw");
        assert!(!r.unlocked);
        assert_eq!(r.message, BITWARDEN_CLI_SESSION_GAP);
        assert!(empty.session_key().is_none());

        let whitespace = FakeBitwardenSession::with_session_key(" \t ");
        assert!(!whitespace.unlock("pw").unlocked);
        assert!(whitespace.session_key().is_none());

        let fake = FakeBitwardenSession::with_session_key("opaque-c");
        fake.set_scripted_key(Some(""));
        let r2 = fake.unlock("pw");
        assert!(!r2.unlocked);
        assert!(fake.session_key().is_none());
    }

    #[test]
    fn fake_empty_master_password_fails_closed() {
        let fake = FakeBitwardenSession::with_session_key("opaque-empty-pw");
        for pw in ["", "   ", "\t"] {
            let r = fake.unlock(pw);
            assert!(!r.unlocked, "pw={pw:?}");
            assert_eq!(r.message, BITWARDEN_CLI_SESSION_GAP);
            assert!(fake.session_key().is_none());
            assert_eq!(fake.status(), BitwardenSessionStatus::Locked);
            assert!(!format!("{r:?}").contains("opaque"));
            assert!(!format!("{fake:?}").contains("opaque-empty-pw"));
        }
        // Non-empty password still unlocks when scripted.
        assert!(fake.unlock("not-empty").unlocked);
        assert_eq!(
            fake.session_key().expect("held").expose(),
            "opaque-empty-pw"
        );
        // Empty / whitespace unlock after a successful unlock clears the held key
        // (fail closed) — never leave a stale session after a blank password attempt.
        for pw in ["", "   "] {
            assert!(!fake.unlock(pw).unlocked, "pw={pw:?}");
            assert!(fake.session_key().is_none());
            assert_eq!(fake.status(), BitwardenSessionStatus::Locked);
            // Re-arm for the next blank attempt.
            assert!(fake.unlock("not-empty").unlocked);
        }
        fake.lock();
        assert!(fake.session_key().is_none());
    }

    #[test]
    fn stub_via_trait_object() {
        let session: &dyn BitwardenSession = &StubBitwardenSession;
        assert_eq!(session.status(), BitwardenSessionStatus::Locked);
        assert!(!session.unlock("x").unlocked);
        assert!(session.session_key().is_none());
    }

    #[test]
    fn fake_concurrent_unlock_lock_debug_no_deadlock() {
        let fake = Arc::new(FakeBitwardenSession::with_session_key("opaque-concurrent"));
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let mut handles = Vec::new();
        for i in 0..8 {
            let f = Arc::clone(&fake);
            let b = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                b.wait();
                match i % 4 {
                    0 => {
                        let _ = f.unlock("pw");
                    }
                    1 => f.lock(),
                    2 => {
                        let _ = format!("{f:?}");
                    }
                    _ => {
                        let _ = f.session_key();
                        let _ = f.status();
                    }
                }
            }));
        }
        for h in handles {
            h.join().expect("thread");
        }
        // Settled: either locked or unlocked with opaque key — never password echo.
        let dbg = format!("{fake:?}");
        assert!(!dbg.contains("pw"));
        assert!(!dbg.contains("opaque-concurrent"));
        if let Some(key) = fake.session_key() {
            assert_eq!(key.expose(), "opaque-concurrent");
            assert!(!format!("{key:?}").contains("opaque-concurrent"));
        }
    }

    #[test]
    fn fake_default_is_cli_gap() {
        let fake = FakeBitwardenSession::default();
        assert!(!fake.unlock("x").unlocked);
        assert!(fake.session_key().is_none());
    }
}
