//! Connect-path host-key **verify** glue: host + key → Accept / Reject / Prompt.
//!
//! Pure decision only — does **not** show UI, pin the store, or dial SSH. Callers
//! that receive [`HostKeyConnectVerdict::Prompt`] continue with
//! [`crate::resolve_host_key_prompted`] (or a real dialog later).
//!
//! # C# intent vs LabOnly
//!
//! | Case | C# (`SshHostKeyValidator` + session) | This stub |
//! |---|---|---|
//! | Known match | Trust → connect | [`HostKeyConnectVerdict::Accept`] |
//! | Unknown (no pin) | Silent TOFU accept, pin after connect (saved nodes) | [`HostKeyConnectVerdict::Prompt`] (`Unknown`) — UI confirm before pin |
//! | Mismatch | Reject (`SshHostKeyMismatchException` / failure overlay) | [`HostKeyMismatchPolicy::Reject`] (default, C# parity) **or** [`HostKeyMismatchPolicy::Prompt`] (lab overwrite UX) |
//! | Empty / hostile host | N/A at this layer | **Fail closed** (`Err`) — never Accept |
//!
//! **LabOnly limits:** Fake store / unit tests; no GPUI / WinUI; no live SSH; no
//! profile `SshKnownHostFingerprint` SQLite sync. Not a HardwarePass claim.

use crate::error::SshError;
use crate::host_key_prompt::{HostKeyPinStore, HostKeyPromptReason};
use crate::known_hosts::{decide, validate_fingerprint, validate_host_token, HostKeyDecision};
use crate::Result;

/// How verify treats a **changed** host key (known pin ≠ captured).
///
/// Unknown keys always [`HostKeyConnectVerdict::Prompt`] in this lab stub
/// (C# silent-TOFU is deferred until product UI / orchestrator wiring).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HostKeyMismatchPolicy {
    /// C# connect parity: mismatch fails closed without an overwrite prompt.
    #[default]
    Reject,
    /// Lab / future UI: surface a changed-key prompt (Accept may overwrite pin).
    Prompt,
}

/// Why verify chose [`HostKeyConnectVerdict::Reject`] (not a validation `Err`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKeyRejectReason {
    /// Captured fingerprint differs from the known pin.
    Mismatch,
}

impl HostKeyRejectReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mismatch => "mismatch",
        }
    }
}

/// Connect-path decision after comparing a captured fingerprint to the pin store.
///
/// Fingerprints only (public pin form) — never raw host-key bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKeyConnectVerdict {
    /// Known pin matches — continue connect without prompting.
    Accept,
    /// Fail closed without prompting (see [`HostKeyMismatchPolicy::Reject`]).
    Reject {
        reason: HostKeyRejectReason,
        /// Previously pinned fingerprint ([`HostKeyRejectReason::Mismatch`]).
        known_fingerprint: String,
    },
    /// Caller should prompt (unknown first sighting or changed key under Prompt policy).
    Prompt {
        reason: HostKeyPromptReason,
        /// Set when [`HostKeyPromptReason::Changed`].
        known_fingerprint: Option<String>,
    },
}

/// Verify host key for the connect path against a pin store (Fake or file-backed).
///
/// `host` is trimmed after validation so lookup matches prompt/pin callers.
/// Empty / whitespace / control-bearing hosts and empty / invalid fingerprints
/// return `Err` (fail closed) — never [`HostKeyConnectVerdict::Accept`].
pub fn verify_host_key_on_connect(
    store: &dyn HostKeyPinStore,
    host: &str,
    captured_fingerprint: &str,
    mismatch_policy: HostKeyMismatchPolicy,
) -> Result<HostKeyConnectVerdict> {
    validate_host_token(host)?;
    let host = host.trim();
    if captured_fingerprint.is_empty() {
        return Err(SshError::Other(
            "captured host key fingerprint must be non-empty".into(),
        ));
    }
    validate_fingerprint(captured_fingerprint)?;

    let known = store.get_fingerprint(host);
    match decide(known, captured_fingerprint) {
        HostKeyDecision::Trust => Ok(HostKeyConnectVerdict::Accept),
        HostKeyDecision::TofuAccept => Ok(HostKeyConnectVerdict::Prompt {
            reason: HostKeyPromptReason::Unknown,
            known_fingerprint: None,
        }),
        HostKeyDecision::Mismatch => {
            let expected = known
                .ok_or_else(|| {
                    SshError::Other("internal: host key mismatch without known pin".into())
                })?
                .to_string();
            match mismatch_policy {
                HostKeyMismatchPolicy::Reject => Ok(HostKeyConnectVerdict::Reject {
                    reason: HostKeyRejectReason::Mismatch,
                    known_fingerprint: expected,
                }),
                HostKeyMismatchPolicy::Prompt => Ok(HostKeyConnectVerdict::Prompt {
                    reason: HostKeyPromptReason::Changed,
                    known_fingerprint: Some(expected),
                }),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_key_prompt::FakeKnownHosts;
    use crate::known_hosts::host_identity;

    #[test]
    fn known_match_accepts() {
        let store = FakeKnownHosts::new()
            .with_pin("h:22", "SHA256:same")
            .unwrap();
        let v = verify_host_key_on_connect(
            &store,
            "h:22",
            "SHA256:same",
            HostKeyMismatchPolicy::Reject,
        )
        .unwrap();
        assert_eq!(v, HostKeyConnectVerdict::Accept);
    }

    #[test]
    fn unknown_prompts() {
        let store = FakeKnownHosts::new();
        let v = verify_host_key_on_connect(
            &store,
            "srv:22",
            "SHA256:newkey",
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
    fn mismatch_rejects_under_default_policy() {
        let store = FakeKnownHosts::new()
            .with_pin("h:22", "SHA256:old")
            .unwrap();
        let v = verify_host_key_on_connect(
            &store,
            "h:22",
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
    fn mismatch_prompts_under_prompt_policy() {
        let store = FakeKnownHosts::new()
            .with_pin("h:22", "SHA256:old")
            .unwrap();
        let v = verify_host_key_on_connect(
            &store,
            "h:22",
            "SHA256:new",
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
    fn empty_host_fails_closed() {
        let store = FakeKnownHosts::new();
        let err = verify_host_key_on_connect(
            &store,
            "",
            "SHA256:abc",
            HostKeyMismatchPolicy::Prompt,
        )
        .unwrap_err();
        assert!(matches!(err, SshError::Other(_)));
        assert!(store.is_empty());
    }

    #[test]
    fn whitespace_only_host_fails_closed() {
        let store = FakeKnownHosts::new();
        let err = verify_host_key_on_connect(
            &store,
            "   ",
            "SHA256:abc",
            HostKeyMismatchPolicy::Reject,
        )
        .unwrap_err();
        assert!(matches!(err, SshError::Other(_)));
    }

    #[test]
    fn empty_fingerprint_fails_closed() {
        let store = FakeKnownHosts::new();
        let err =
            verify_host_key_on_connect(&store, "h:22", "", HostKeyMismatchPolicy::Prompt)
                .unwrap_err();
        assert!(matches!(err, SshError::Other(_)));
    }

    #[test]
    fn empty_fingerprint_with_existing_pin_still_errs() {
        // Must not fall through to decide() → Mismatch → Ok(Reject).
        let store = FakeKnownHosts::new()
            .with_pin("h:22", "SHA256:old")
            .unwrap();
        let err =
            verify_host_key_on_connect(&store, "h:22", "", HostKeyMismatchPolicy::Reject)
                .unwrap_err();
        assert!(matches!(err, SshError::Other(_)));
        assert_eq!(store.get("h:22"), Some("SHA256:old"));
    }

    #[test]
    fn invalid_fingerprint_fails_closed() {
        let store = FakeKnownHosts::new()
            .with_pin("h:22", "SHA256:old")
            .unwrap();
        let err = verify_host_key_on_connect(
            &store,
            "h:22",
            "MD5:deadbeef",
            HostKeyMismatchPolicy::Prompt,
        )
        .unwrap_err();
        assert!(matches!(err, SshError::Other(_)));
        assert_eq!(store.get("h:22"), Some("SHA256:old"));
    }

    #[test]
    fn whitespace_fingerprint_fails_closed() {
        let store = FakeKnownHosts::new();
        let err = verify_host_key_on_connect(
            &store,
            "h:22",
            "   ",
            HostKeyMismatchPolicy::Reject,
        )
        .unwrap_err();
        assert!(matches!(err, SshError::Other(_)));
        assert!(store.is_empty());
    }

    #[test]
    fn hostile_host_fails_closed() {
        let store = FakeKnownHosts::new();
        let err = verify_host_key_on_connect(
            &store,
            "bad host",
            "SHA256:abc",
            HostKeyMismatchPolicy::Prompt,
        )
        .unwrap_err();
        assert!(matches!(err, SshError::Other(_)));
        assert!(store.is_empty());
    }

    #[test]
    fn mismatch_reject_does_not_mutate_store() {
        let store = FakeKnownHosts::new()
            .with_pin("h:22", "SHA256:old")
            .unwrap();
        let v = verify_host_key_on_connect(
            &store,
            "h:22",
            "SHA256:evil",
            HostKeyMismatchPolicy::Reject,
        )
        .unwrap();
        assert!(matches!(v, HostKeyConnectVerdict::Reject { .. }));
        assert_eq!(store.get("h:22"), Some("SHA256:old"));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn unknown_prompt_does_not_mutate_store() {
        let store = FakeKnownHosts::new();
        let v = verify_host_key_on_connect(
            &store,
            "srv:22",
            "SHA256:newkey",
            HostKeyMismatchPolicy::Reject,
        )
        .unwrap();
        assert!(matches!(
            v,
            HostKeyConnectVerdict::Prompt {
                reason: HostKeyPromptReason::Unknown,
                ..
            }
        ));
        assert!(store.is_empty());
    }

    #[test]
    fn mismatch_prompt_does_not_mutate_store() {
        let store = FakeKnownHosts::new()
            .with_pin("h:22", "SHA256:old")
            .unwrap();
        let v = verify_host_key_on_connect(
            &store,
            "h:22",
            "SHA256:new",
            HostKeyMismatchPolicy::Prompt,
        )
        .unwrap();
        assert!(matches!(
            v,
            HostKeyConnectVerdict::Prompt {
                reason: HostKeyPromptReason::Changed,
                ..
            }
        ));
        assert_eq!(store.get("h:22"), Some("SHA256:old"));
    }

    #[test]
    fn host_trimmed_and_case_folded_for_lookup() {
        let store = FakeKnownHosts::new()
            .with_pin("Srv.Example:22", "SHA256:same")
            .unwrap();
        assert_eq!(
            verify_host_key_on_connect(
                &store,
                "  SRV.EXAMPLE:22  ",
                "SHA256:same",
                HostKeyMismatchPolicy::Reject,
            )
            .unwrap(),
            HostKeyConnectVerdict::Accept
        );
    }

    #[test]
    fn host_identity_round_trip_trust() {
        let id = host_identity("10.0.0.1", Some(22));
        let store = FakeKnownHosts::new()
            .with_pin(&id, "SHA256:aabb")
            .unwrap();
        assert_eq!(
            verify_host_key_on_connect(
                &store,
                &id,
                "SHA256:aabb",
                HostKeyMismatchPolicy::Reject,
            )
            .unwrap(),
            HostKeyConnectVerdict::Accept
        );
    }

    #[test]
    fn reject_reason_label() {
        assert_eq!(HostKeyRejectReason::Mismatch.as_str(), "mismatch");
    }
}
