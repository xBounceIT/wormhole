//! SSH known_hosts ↔ host-key verify + prompt glue for the session connect path.
//!
//! 1. [`verify_ssh_host_key`] — pure Accept / Reject / Prompt (no UI, no dial).
//! 2. [`gate_ssh_host_key`] — Prompt path via [`wormhole_ssh::resolve_host_key_prompted`]
//!    (Accept pins / Reject fail-closed).
//!
//! No live SSH — callers supply a captured fingerprint (tests use
//! [`FakeKnownHosts`] + [`FakeHostKeyPrompt`]).

use wormhole_ssh::{
    host_identity, resolve_host_key_prompted, verify_host_key_on_connect, FakeKnownHosts,
    HostKeyConnectVerdict, HostKeyMismatchPolicy, HostKeyPinStore, HostKeyPrompt, SshError,
};

use crate::error::{Result, SessionError};

fn bare_host_or_err(host: &str) -> Result<&str> {
    let host = host.trim();
    if host.is_empty() {
        return Err(SessionError::Ssh(SshError::Other(
            "known_hosts host must be non-empty".into(),
        )));
    }
    Ok(host)
}

/// Session-connect **verify** (fingerprint already captured; no network / no prompt).
///
/// `host` must be a bare hostname / address (not `host:port`); `port` is combined via
/// [`host_identity`]. Empty bare host fails closed **before** forming `host:port`.
/// Default mismatch policy is [`HostKeyMismatchPolicy::Reject`] (C# parity); pass
/// [`HostKeyMismatchPolicy::Prompt`] for changed-key UI.
pub fn verify_ssh_host_key(
    store: &dyn HostKeyPinStore,
    host: &str,
    port: u16,
    captured_fingerprint: &str,
    mismatch_policy: HostKeyMismatchPolicy,
) -> Result<HostKeyConnectVerdict> {
    let host = bare_host_or_err(host)?;
    let id = host_identity(host, Some(port));
    verify_host_key_on_connect(store, &id, captured_fingerprint, mismatch_policy)
        .map_err(SessionError::from)
}

/// Convenience for unit tests: verify against an in-memory [`FakeKnownHosts`].
pub fn verify_ssh_host_key_fake(
    store: &FakeKnownHosts,
    host: &str,
    port: u16,
    captured_fingerprint: &str,
    mismatch_policy: HostKeyMismatchPolicy,
) -> Result<HostKeyConnectVerdict> {
    verify_ssh_host_key(store, host, port, captured_fingerprint, mismatch_policy)
}

/// Session-connect host-key **gate** (fingerprint already captured; no network).
///
/// Unknown / changed → prompt → Accept pins / Reject fails closed. Uses prompt
/// mismatch policy internally (see [`resolve_host_key_prompted`]).
///
/// `host` must be a bare hostname / address (not `host:port`); `port` is combined via
/// [`host_identity`] to match the known_hosts key shape used by the SSH client spike.
pub fn gate_ssh_host_key(
    store: &mut dyn HostKeyPinStore,
    prompt: &dyn HostKeyPrompt,
    host: &str,
    port: u16,
    captured_fingerprint: &str,
) -> Result<()> {
    let host = bare_host_or_err(host)?;
    let id = host_identity(host, Some(port));
    resolve_host_key_prompted(store, prompt, &id, captured_fingerprint).map_err(SessionError::from)
}

/// Convenience for unit tests: gate against an in-memory [`FakeKnownHosts`].
pub fn gate_ssh_host_key_fake(
    store: &mut FakeKnownHosts,
    prompt: &dyn HostKeyPrompt,
    host: &str,
    port: u16,
    captured_fingerprint: &str,
) -> Result<()> {
    gate_ssh_host_key(store, prompt, host, port, captured_fingerprint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wormhole_ssh::{
        FakeHostKeyPrompt, HostKeyPromptReason, HostKeyRejectReason, NullHostKeyPrompt,
        SshError,
    };

    #[test]
    fn verify_known_match_accepts() {
        let store = FakeKnownHosts::new()
            .with_pin("lab.local:22", "SHA256:same")
            .unwrap();
        let v = verify_ssh_host_key_fake(
            &store,
            "lab.local",
            22,
            "SHA256:same",
            HostKeyMismatchPolicy::Reject,
        )
        .unwrap();
        assert_eq!(v, HostKeyConnectVerdict::Accept);
    }

    #[test]
    fn verify_unknown_prompts() {
        let store = FakeKnownHosts::new();
        let v = verify_ssh_host_key_fake(
            &store,
            "lab.local",
            22,
            "SHA256:new",
            HostKeyMismatchPolicy::Reject,
        )
        .unwrap();
        assert_eq!(
            v,
            HostKeyConnectVerdict::Prompt {
                reason: HostKeyPromptReason::Unknown,
                known_fingerprint: None,
            }
        );
    }

    #[test]
    fn verify_mismatch_rejects_by_default() {
        let store = FakeKnownHosts::new()
            .with_pin("lab.local:22", "SHA256:old")
            .unwrap();
        let v = verify_ssh_host_key_fake(
            &store,
            "lab.local",
            22,
            "SHA256:evil",
            HostKeyMismatchPolicy::default(),
        )
        .unwrap();
        assert_eq!(
            v,
            HostKeyConnectVerdict::Reject {
                reason: HostKeyRejectReason::Mismatch,
                known_fingerprint: "SHA256:old".into(),
            }
        );
    }

    #[test]
    fn verify_mismatch_prompts_when_policy_allows() {
        let store = FakeKnownHosts::new()
            .with_pin("lab.local:22", "SHA256:old")
            .unwrap();
        let v = verify_ssh_host_key_fake(
            &store,
            "lab.local",
            22,
            "SHA256:rotated",
            HostKeyMismatchPolicy::Prompt,
        )
        .unwrap();
        assert_eq!(
            v,
            HostKeyConnectVerdict::Prompt {
                reason: HostKeyPromptReason::Changed,
                known_fingerprint: Some("SHA256:old".into()),
            }
        );
    }

    #[test]
    fn verify_empty_host_fails_closed() {
        let store = FakeKnownHosts::new();
        let err = verify_ssh_host_key_fake(
            &store,
            "",
            22,
            "SHA256:abc",
            HostKeyMismatchPolicy::Prompt,
        )
        .unwrap_err();
        assert!(matches!(err, crate::SessionError::Ssh(SshError::Other(_))));
    }

    #[test]
    fn verify_whitespace_host_fails_closed_before_port() {
        let store = FakeKnownHosts::new();
        let err = verify_ssh_host_key_fake(
            &store,
            "   ",
            22,
            "SHA256:abc",
            HostKeyMismatchPolicy::Reject,
        )
        .unwrap_err();
        assert!(matches!(err, crate::SessionError::Ssh(SshError::Other(_))));
        // Must not form a ":22" identity pin lookup / Accept.
        assert!(store.is_empty());
    }

    #[test]
    fn verify_reject_does_not_pin() {
        let store = FakeKnownHosts::new()
            .with_pin("lab.local:22", "SHA256:old")
            .unwrap();
        let v = verify_ssh_host_key_fake(
            &store,
            "lab.local",
            22,
            "SHA256:evil",
            HostKeyMismatchPolicy::Reject,
        )
        .unwrap();
        assert!(matches!(v, HostKeyConnectVerdict::Reject { .. }));
        assert_eq!(store.get("lab.local:22"), Some("SHA256:old"));
    }

    #[test]
    fn accept_unknown_pins_via_session_gate() {
        let mut store = FakeKnownHosts::new();
        let prompt = FakeHostKeyPrompt::accept_once();
        gate_ssh_host_key_fake(&mut store, &prompt, "lab.local", 22, "SHA256:sessionpin")
            .unwrap();
        assert_eq!(
            store.get("lab.local:22"),
            Some("SHA256:sessionpin")
        );
        assert_eq!(prompt.requests()[0].reason, HostKeyPromptReason::Unknown);
    }

    #[test]
    fn reject_changed_fail_closed() {
        let mut store = FakeKnownHosts::new()
            .with_pin("lab.local:22", "SHA256:old")
            .unwrap();
        let prompt = NullHostKeyPrompt;
        let err =
            gate_ssh_host_key_fake(&mut store, &prompt, "lab.local", 22, "SHA256:new").unwrap_err();
        assert!(matches!(
            err,
            crate::SessionError::Ssh(SshError::HostKeyMismatch { .. })
        ));
        assert_eq!(store.get("lab.local:22"), Some("SHA256:old"));
    }

    #[test]
    fn trust_does_not_prompt() {
        let mut store = FakeKnownHosts::new()
            .with_pin("h:22", "SHA256:same")
            .unwrap();
        let prompt = FakeHostKeyPrompt::reject_once();
        gate_ssh_host_key_fake(&mut store, &prompt, "h", 22, "SHA256:same").unwrap();
        assert!(prompt.requests().is_empty());
    }

    #[test]
    fn reject_unknown_fail_closed() {
        let mut store = FakeKnownHosts::new();
        let prompt = NullHostKeyPrompt;
        let err = gate_ssh_host_key_fake(&mut store, &prompt, "lab.local", 22, "SHA256:new")
            .unwrap_err();
        assert!(matches!(
            err,
            crate::SessionError::Ssh(SshError::HostKeyRejected {
                reason: "unknown",
                ..
            })
        ));
        assert!(store.is_empty());
    }

    #[test]
    fn accept_changed_overwrites_via_session_gate() {
        let mut store = FakeKnownHosts::new()
            .with_pin("lab.local:22", "SHA256:old")
            .unwrap();
        let prompt = FakeHostKeyPrompt::accept_once();
        gate_ssh_host_key_fake(&mut store, &prompt, "lab.local", 22, "SHA256:rotated")
            .unwrap();
        assert_eq!(store.get("lab.local:22"), Some("SHA256:rotated"));
        assert_eq!(prompt.requests()[0].reason, HostKeyPromptReason::Changed);
        assert_eq!(
            prompt.requests()[0].known_fingerprint.as_deref(),
            Some("SHA256:old")
        );
    }
}
