//! Host-key prompt glue: known_hosts store ↔ accept/reject UI stub.
//!
//! Connect path: [`crate::verify_host_key_on_connect`] decides Accept / Reject /
//! Prompt; on Prompt this module hits [`HostKeyPrompt`] → **Accept** persists
//! the pin, **Reject** fails closed.
//!
//! This module does **not** dial SSH. Unit tests use [`FakeKnownHosts`] +
//! [`FakeHostKeyPrompt`] (no disk I/O required for the fake store).
//!
//! [`Debug`] may include SHA256 fingerprints (already the public pin form) but
//! never raw host-key bytes.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::sync::Mutex;

use crate::error::SshError;
use crate::host_key_verify::{
    verify_host_key_on_connect, HostKeyConnectVerdict, HostKeyMismatchPolicy,
};
use crate::known_hosts::{
    decide, normalize_host_key, validate_fingerprint, validate_host_token, HostKeyDecision,
    KnownHostsStore,
};
use crate::Result;

/// Why the connect path is prompting (not a silent Trust).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKeyPromptReason {
    /// No pin for this host yet ([`HostKeyDecision::TofuAccept`]).
    Unknown,
    /// Captured fingerprint differs from the known pin ([`HostKeyDecision::Mismatch`]).
    Changed,
}

impl HostKeyPromptReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Changed => "changed",
        }
    }
}

/// Prompt payload — fingerprints only (no raw key material).
///
/// [`Debug`] may print SHA256 fingerprints (public pin form) but never raw host-key bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostKeyPromptRequest {
    pub host: String,
    /// Captured `SHA256:…` fingerprint.
    pub fingerprint: String,
    /// Previously pinned fingerprint, when [`HostKeyPromptReason::Changed`].
    pub known_fingerprint: Option<String>,
    pub reason: HostKeyPromptReason,
}

impl HostKeyPromptRequest {
    pub fn new(
        host: impl Into<String>,
        fingerprint: impl Into<String>,
        known_fingerprint: Option<String>,
        reason: HostKeyPromptReason,
    ) -> Self {
        Self {
            host: host.into(),
            fingerprint: fingerprint.into(),
            known_fingerprint,
            reason,
        }
    }
}

/// User (or test double) decision for an unknown / changed host key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKeyPromptResponse {
    /// Persist the captured fingerprint and continue connect.
    Accept,
    /// Fail closed — do not connect and do not overwrite a pin on reject.
    Reject,
}

/// Interactive (eventually UI) accept/reject for unknown or changed host keys.
///
/// Implementations must not log raw key material. Fingerprints on
/// [`HostKeyPromptRequest`] are already the public pin form.
pub trait HostKeyPrompt: Send + Sync {
    fn prompt(&self, request: &HostKeyPromptRequest) -> HostKeyPromptResponse;
}

/// Always rejects — fail-closed default until a real dialog is wired.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullHostKeyPrompt;

impl HostKeyPrompt for NullHostKeyPrompt {
    fn prompt(&self, _request: &HostKeyPromptRequest) -> HostKeyPromptResponse {
        HostKeyPromptResponse::Reject
    }
}

/// Scripted accept/reject queue for unit tests (no UI).
pub struct FakeHostKeyPrompt {
    responses: Mutex<VecDeque<HostKeyPromptResponse>>,
    requests: Mutex<Vec<HostKeyPromptRequest>>,
}

impl Default for FakeHostKeyPrompt {
    fn default() -> Self {
        Self::reject_all()
    }
}

impl fmt::Debug for FakeHostKeyPrompt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let remaining = self
            .responses
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len();
        let seen = self
            .requests
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len();
        f.debug_struct("FakeHostKeyPrompt")
            .field("responses_remaining", &remaining)
            .field("requests_seen", &seen)
            .finish()
    }
}

impl FakeHostKeyPrompt {
    /// Empty queue → every prompt rejects (fail closed).
    pub fn reject_all() -> Self {
        Self {
            responses: Mutex::new(VecDeque::new()),
            requests: Mutex::new(Vec::new()),
        }
    }

    pub fn from_responses(responses: impl IntoIterator<Item = HostKeyPromptResponse>) -> Self {
        Self {
            responses: Mutex::new(responses.into_iter().collect()),
            requests: Mutex::new(Vec::new()),
        }
    }

    pub fn accept_once() -> Self {
        Self::from_responses([HostKeyPromptResponse::Accept])
    }

    pub fn reject_once() -> Self {
        Self::from_responses([HostKeyPromptResponse::Reject])
    }

    pub fn requests(&self) -> Vec<HostKeyPromptRequest> {
        self.requests
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}

impl HostKeyPrompt for FakeHostKeyPrompt {
    fn prompt(&self, request: &HostKeyPromptRequest) -> HostKeyPromptResponse {
        self.requests
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(request.clone());
        let mut q = self.responses.lock().unwrap_or_else(|p| p.into_inner());
        q.pop_front()
            .unwrap_or(HostKeyPromptResponse::Reject)
    }
}

/// In-memory known_hosts map for tests (no disk, no network).
///
/// Keys are normalized like [`KnownHostsStore`]. [`Debug`] shows host → fingerprint
/// only (never raw key bytes).
#[derive(Clone, Debug, Default)]
pub struct FakeKnownHosts {
    entries: BTreeMap<String, String>,
}

impl FakeKnownHosts {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_pin(mut self, host: &str, fingerprint: &str) -> Result<Self> {
        self.pin(host, fingerprint)?;
        Ok(self)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&self, host: &str) -> Option<&str> {
        self.entries
            .get(&normalize_host_key(host))
            .map(String::as_str)
    }

    pub fn decide(&self, host: &str, captured_fingerprint: &str) -> HostKeyDecision {
        decide(self.get(host), captured_fingerprint)
    }

    pub fn pin(&mut self, host: &str, fingerprint: &str) -> Result<()> {
        validate_host_token(host)?;
        validate_fingerprint(fingerprint)?;
        self.entries
            .insert(normalize_host_key(host), fingerprint.to_string());
        Ok(())
    }

    pub fn unpin(&mut self, host: &str) {
        self.entries.remove(&normalize_host_key(host));
    }
}

/// Pin store used by [`resolve_host_key_prompted`].
pub trait HostKeyPinStore {
    fn get_fingerprint(&self, host: &str) -> Option<&str>;
    fn set_pin(&mut self, host: &str, fingerprint: &str) -> Result<()>;
}

impl HostKeyPinStore for FakeKnownHosts {
    fn get_fingerprint(&self, host: &str) -> Option<&str> {
        self.get(host)
    }

    fn set_pin(&mut self, host: &str, fingerprint: &str) -> Result<()> {
        self.pin(host, fingerprint)
    }
}

impl HostKeyPinStore for KnownHostsStore {
    fn get_fingerprint(&self, host: &str) -> Option<&str> {
        self.get(host)
    }

    fn set_pin(&mut self, host: &str, fingerprint: &str) -> Result<()> {
        let prev = self.get(host).map(str::to_string);
        self.pin(host, fingerprint)?;
        if let Err(e) = self.save() {
            match prev {
                Some(p) => {
                    let _ = self.pin(host, &p);
                }
                None => self.unpin(host),
            }
            return Err(e);
        }
        Ok(())
    }
}

/// Connect-path host-key gate: verify (Prompt-on-mismatch) then prompt → accept (store) /
/// reject (fail closed).
///
/// Uses [`verify_host_key_on_connect`] with [`HostKeyMismatchPolicy::Prompt`] so unknown
/// and changed keys both surface a prompt. Empty / invalid host or fingerprint fail
/// closed **without** prompting. Reject on mismatch never overwrites the existing pin.
///
/// Reject semantics: unknown → [`SshError::HostKeyRejected`]; changed →
/// [`SshError::HostKeyMismatch`] (expected/actual preserved). `host` is trimmed before
/// prompt / pin so leading/trailing whitespace cannot diverge lookup vs request payload.
pub fn resolve_host_key_prompted(
    store: &mut dyn HostKeyPinStore,
    prompt: &dyn HostKeyPrompt,
    host: &str,
    captured_fingerprint: &str,
) -> Result<()> {
    match verify_host_key_on_connect(
        store,
        host,
        captured_fingerprint,
        HostKeyMismatchPolicy::Prompt,
    )? {
        HostKeyConnectVerdict::Accept => Ok(()),
        HostKeyConnectVerdict::Reject {
            known_fingerprint, ..
        } => {
            // Prompt policy never yields Reject; keep fail-closed if that changes.
            Err(SshError::HostKeyMismatch {
                host: host.trim().to_string(),
                expected: known_fingerprint,
                actual: captured_fingerprint.to_string(),
            })
        }
        HostKeyConnectVerdict::Prompt {
            reason,
            known_fingerprint,
        } => {
            let host = host.trim();
            let request = HostKeyPromptRequest::new(
                host,
                captured_fingerprint,
                known_fingerprint.clone(),
                reason,
            );
            match prompt.prompt(&request) {
                HostKeyPromptResponse::Accept => store.set_pin(host, captured_fingerprint),
                HostKeyPromptResponse::Reject => match reason {
                    HostKeyPromptReason::Unknown => Err(SshError::HostKeyRejected {
                        host: host.to_string(),
                        reason: HostKeyPromptReason::Unknown.as_str(),
                        fingerprint: captured_fingerprint.to_string(),
                    }),
                    HostKeyPromptReason::Changed => Err(SshError::HostKeyMismatch {
                        host: host.to_string(),
                        expected: known_fingerprint.unwrap_or_default(),
                        actual: captured_fingerprint.to_string(),
                    }),
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::known_hosts::host_identity;

    #[test]
    fn trust_skips_prompt() {
        let mut store = FakeKnownHosts::new()
            .with_pin("h:22", "SHA256:abc")
            .unwrap();
        let prompt = FakeHostKeyPrompt::reject_once();
        resolve_host_key_prompted(&mut store, &prompt, "h:22", "SHA256:abc").unwrap();
        assert!(prompt.requests().is_empty());
        assert_eq!(store.get("h:22"), Some("SHA256:abc"));
    }

    #[test]
    fn unknown_accept_pins() {
        let mut store = FakeKnownHosts::new();
        let prompt = FakeHostKeyPrompt::accept_once();
        resolve_host_key_prompted(&mut store, &prompt, "srv:22", "SHA256:newkey").unwrap();
        assert_eq!(store.get("srv:22"), Some("SHA256:newkey"));
        let reqs = prompt.requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].reason, HostKeyPromptReason::Unknown);
        assert!(reqs[0].known_fingerprint.is_none());
    }

    #[test]
    fn unknown_reject_fail_closed() {
        let mut store = FakeKnownHosts::new();
        let prompt = NullHostKeyPrompt;
        let err =
            resolve_host_key_prompted(&mut store, &prompt, "srv:22", "SHA256:newkey").unwrap_err();
        assert!(matches!(
            err,
            SshError::HostKeyRejected {
                reason: "unknown",
                ..
            }
        ));
        assert!(store.is_empty());
    }

    #[test]
    fn changed_accept_overwrites_pin() {
        let mut store = FakeKnownHosts::new()
            .with_pin("h:22", "SHA256:old")
            .unwrap();
        let prompt = FakeHostKeyPrompt::accept_once();
        resolve_host_key_prompted(&mut store, &prompt, "h:22", "SHA256:new").unwrap();
        assert_eq!(store.get("h:22"), Some("SHA256:new"));
        let reqs = prompt.requests();
        assert_eq!(reqs[0].reason, HostKeyPromptReason::Changed);
        assert_eq!(reqs[0].known_fingerprint.as_deref(), Some("SHA256:old"));
    }

    #[test]
    fn changed_reject_preserves_pin() {
        let mut store = FakeKnownHosts::new()
            .with_pin("h:22", "SHA256:old")
            .unwrap();
        let prompt = FakeHostKeyPrompt::reject_once();
        let err =
            resolve_host_key_prompted(&mut store, &prompt, "h:22", "SHA256:evil").unwrap_err();
        assert!(matches!(
            err,
            SshError::HostKeyMismatch {
                expected: ref e,
                actual: ref a,
                ..
            } if e == "SHA256:old" && a == "SHA256:evil"
        ));
        assert_eq!(store.get("h:22"), Some("SHA256:old"));
    }

    #[test]
    fn empty_fingerprint_no_prompt() {
        let mut store = FakeKnownHosts::new();
        let prompt = FakeHostKeyPrompt::accept_once();
        let err = resolve_host_key_prompted(&mut store, &prompt, "h:22", "").unwrap_err();
        assert!(matches!(err, SshError::Other(_)));
        assert!(prompt.requests().is_empty());
    }

    #[test]
    fn invalid_fingerprint_no_prompt() {
        let mut store = FakeKnownHosts::new();
        let prompt = FakeHostKeyPrompt::accept_once();
        let err =
            resolve_host_key_prompted(&mut store, &prompt, "h:22", "MD5:deadbeef").unwrap_err();
        assert!(matches!(err, SshError::Other(_)));
        assert!(prompt.requests().is_empty());
        assert!(store.is_empty());
    }

    #[test]
    fn empty_host_no_prompt() {
        let mut store = FakeKnownHosts::new();
        let prompt = FakeHostKeyPrompt::accept_once();
        let err = resolve_host_key_prompted(&mut store, &prompt, "", "SHA256:abc").unwrap_err();
        assert!(matches!(err, SshError::Other(_)));
        assert!(prompt.requests().is_empty());
        assert!(store.is_empty());
    }

    #[test]
    fn hostile_host_no_prompt() {
        let mut store = FakeKnownHosts::new();
        let prompt = FakeHostKeyPrompt::accept_once();
        let err =
            resolve_host_key_prompted(&mut store, &prompt, "bad host", "SHA256:abc").unwrap_err();
        assert!(matches!(err, SshError::Other(_)));
        assert!(prompt.requests().is_empty());
    }

    #[test]
    fn host_trimmed_before_prompt_and_pin() {
        let mut store = FakeKnownHosts::new();
        let prompt = FakeHostKeyPrompt::accept_once();
        resolve_host_key_prompted(&mut store, &prompt, "  srv:22  ", "SHA256:trim").unwrap();
        assert_eq!(store.get("srv:22"), Some("SHA256:trim"));
        assert_eq!(prompt.requests()[0].host, "srv:22");
    }

    #[test]
    fn case_insensitive_host_trust() {
        let mut store = FakeKnownHosts::new()
            .with_pin("Host.Example:22", "SHA256:same")
            .unwrap();
        let prompt = FakeHostKeyPrompt::reject_once();
        resolve_host_key_prompted(&mut store, &prompt, "host.example:22", "SHA256:same")
            .unwrap();
        assert!(prompt.requests().is_empty());
    }

    #[test]
    fn fake_prompt_exhausted_queue_rejects() {
        let mut store = FakeKnownHosts::new();
        let prompt = FakeHostKeyPrompt::reject_all();
        let err =
            resolve_host_key_prompted(&mut store, &prompt, "srv:22", "SHA256:newkey").unwrap_err();
        assert!(matches!(
            err,
            SshError::HostKeyRejected {
                reason: "unknown",
                ..
            }
        ));
        assert!(store.is_empty());
    }

    #[test]
    fn file_store_accept_save_failure_rolls_back() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("not-a-dir");
        std::fs::write(&blocker, b"x").unwrap();
        let mut store = KnownHostsStore::empty(blocker.join("known_hosts"));
        let prompt = FakeHostKeyPrompt::accept_once();
        assert!(resolve_host_key_prompted(&mut store, &prompt, "h:22", "SHA256:abc").is_err());
        assert!(store.get("h:22").is_none());
        assert!(store.is_empty());
    }

    #[test]
    fn file_store_changed_accept_save_failure_restores_pin() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("not-a-dir");
        std::fs::write(&blocker, b"x").unwrap();
        let mut store = KnownHostsStore::empty(blocker.join("known_hosts"));
        // In-memory pin only — save is broken by design for this path.
        store.pin("h:22", "SHA256:old").unwrap();
        let prompt = FakeHostKeyPrompt::accept_once();
        assert!(resolve_host_key_prompted(&mut store, &prompt, "h:22", "SHA256:new").is_err());
        assert_eq!(store.get("h:22"), Some("SHA256:old"));
    }

    #[test]
    fn request_debug_includes_fingerprint_not_raw_key() {
        let req = HostKeyPromptRequest::new(
            "h:22",
            "SHA256:abc",
            Some("SHA256:old".into()),
            HostKeyPromptReason::Changed,
        );
        let rendered = format!("{req:?}");
        assert!(rendered.contains("SHA256:abc"));
        assert!(rendered.contains("SHA256:old"));
        assert!(!rendered.contains("ssh-ed25519"));
        assert!(!rendered.contains("-----BEGIN"));
    }

    #[test]
    fn fake_store_debug_is_fingerprint_map() {
        let store = FakeKnownHosts::new()
            .with_pin("h:22", "SHA256:pin")
            .unwrap();
        let rendered = format!("{store:?}");
        assert!(rendered.contains("SHA256:pin"));
        assert!(rendered.contains("FakeKnownHosts"));
    }

    #[test]
    fn fake_prompt_debug_omits_request_payloads() {
        let prompt = FakeHostKeyPrompt::accept_once();
        let _ = prompt.prompt(&HostKeyPromptRequest::new(
            "h",
            "SHA256:x",
            None,
            HostKeyPromptReason::Unknown,
        ));
        let rendered = format!("{prompt:?}");
        assert!(rendered.contains("requests_seen"));
        assert!(!rendered.contains("SHA256:x"));
    }

    #[test]
    fn file_store_accept_via_prompt() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = KnownHostsStore::empty(dir.path().join("known_hosts"));
        let prompt = FakeHostKeyPrompt::accept_once();
        let host = host_identity("lab.example", Some(22));
        resolve_host_key_prompted(&mut store, &prompt, &host, "SHA256:filepin").unwrap();
        assert_eq!(store.get(&host), Some("SHA256:filepin"));
        let reloaded = KnownHostsStore::load(store.path()).unwrap();
        assert_eq!(reloaded.get(&host), Some("SHA256:filepin"));
    }

    #[test]
    fn session_style_host_identity_round_trip() {
        let mut store = FakeKnownHosts::new();
        let prompt = FakeHostKeyPrompt::accept_once();
        let id = host_identity("10.0.0.1", Some(22));
        resolve_host_key_prompted(&mut store, &prompt, &id, "SHA256:aabb").unwrap();
        assert_eq!(store.decide(&id, "SHA256:aabb"), HostKeyDecision::Trust);
    }
}
