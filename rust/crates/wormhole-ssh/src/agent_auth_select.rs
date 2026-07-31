//! SSH agent availability probe ↔ auth method select glue stub.
//!
//! Connect prep may list [`AuthMethodKind::Agent`] among preferred methods.
//! This module wires the existing [`SshAgentProbe`] to **include** Agent when
//! the probe reports available and **exclude** it when unavailable. It does
//! **not** reimplement named-pipe / `SSH_AUTH_SOCK` probing.
//!
//! Probe **errors** fail closed ([`AgentAuthSelectError`]) — Agent is never
//! silently treated as available. Unit tests use [`FakeAgent`] /
//! [`FakeFallibleAgent`] (no live ssh-agent).
//!
//! Wire auth for Agent remains [`crate::SshError::AuthNotImplemented`] until a
//! russh agent client lands; this glue only gates whether Agent appears in the
//! prepared method list.

use std::fmt;

use crate::agent::{AgentAvailability, FakeAgent, SshAgentProbe};

/// Auth method kind for connect-prep selection (no secrets).
///
/// Mirrors [`crate::SshAuthMethod`] variants without carrying credentials so
/// this glue stays available under `--no-default-features`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthMethodKind {
    Password,
    PrivateKey,
    Agent,
    KeyboardInteractive,
}

impl AuthMethodKind {
    /// Short label for logs / errors (never includes secrets).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::PrivateKey => "private-key",
            Self::Agent => "agent",
            Self::KeyboardInteractive => "keyboard-interactive",
        }
    }
}

/// Connect-prep failed while deciding whether Agent may be offered.
///
/// Message is a static label only — never an endpoint path or secret.
#[derive(Clone, PartialEq, Eq)]
pub struct AgentAuthSelectError {
    message: &'static str,
}

impl AgentAuthSelectError {
    pub const fn new(message: &'static str) -> Self {
        Self { message }
    }

    pub const fn message(&self) -> &'static str {
        self.message
    }
}

impl fmt::Debug for AgentAuthSelectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentAuthSelectError")
            .field("message", &self.message)
            .finish()
    }
}

impl fmt::Display for AgentAuthSelectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message)
    }
}

impl std::error::Error for AgentAuthSelectError {}

/// Fallible agent probe for connect-prep glue.
///
/// [`SshAgentProbe`] is infallible; this trait adds an error channel so hostile
/// / scripted fakes can fail closed. Blanket impl maps `probe()` → `Ok`.
pub trait FallibleAgentProbe: Send + Sync {
    fn try_probe(&self) -> Result<AgentAvailability, AgentAuthSelectError>;
}

impl<P: SshAgentProbe + ?Sized> FallibleAgentProbe for P {
    fn try_probe(&self) -> Result<AgentAvailability, AgentAuthSelectError> {
        Ok(self.probe())
    }
}

/// Scripted fallible probe for unit tests (no network, no pipes).
///
/// Prefer [`FakeAgent`] when the probe should succeed; use
/// [`FakeFallibleAgent::error`] to exercise fail-closed select.
#[derive(Clone)]
pub struct FakeFallibleAgent {
    result: Result<AgentAvailability, AgentAuthSelectError>,
}

impl FakeFallibleAgent {
    pub fn from_availability(availability: AgentAvailability) -> Self {
        Self {
            result: Ok(availability),
        }
    }

    pub fn available() -> Self {
        Self::from_availability(FakeAgent::available().probe())
    }

    pub fn unavailable() -> Self {
        Self::from_availability(FakeAgent::unavailable().probe())
    }

    pub fn error(message: &'static str) -> Self {
        Self {
            result: Err(AgentAuthSelectError::new(message)),
        }
    }
}

impl Default for FakeFallibleAgent {
    fn default() -> Self {
        Self::unavailable()
    }
}

impl fmt::Debug for FakeFallibleAgent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.result {
            Ok(a) => f
                .debug_struct("FakeFallibleAgent")
                .field("ok", &true)
                .field("available", &a.available)
                .field("source", &a.source)
                .finish(),
            Err(e) => f
                .debug_struct("FakeFallibleAgent")
                .field("ok", &false)
                .field("error", &e.message())
                .finish(),
        }
    }
}

impl FallibleAgentProbe for FakeFallibleAgent {
    fn try_probe(&self) -> Result<AgentAvailability, AgentAuthSelectError> {
        self.result.clone()
    }
}

/// Whether connect prep may include Agent given a probe result / error.
///
/// - `Ok(available=true)` → include
/// - `Ok(available=false)` → exclude
/// - `Err(_)` → fail closed ([`AgentAuthSelectError`])
pub fn agent_auth_allowed(
    probe: &dyn FallibleAgentProbe,
) -> Result<bool, AgentAuthSelectError> {
    Ok(probe.try_probe()?.available)
}

/// Probe only when Agent is requested; otherwise treat as "do not include".
fn include_agent_if_requested(
    wants_agent: bool,
    probe: &dyn FallibleAgentProbe,
) -> Result<bool, AgentAuthSelectError> {
    if wants_agent {
        agent_auth_allowed(probe)
    } else {
        Ok(false)
    }
}

/// Connect-prep select: keep non-Agent kinds; include Agent only when the
/// probe reports available.
///
/// The probe runs **only** when `candidates` contains [`AuthMethodKind::Agent`].
/// A probe error fails the whole select (fail closed — Agent is never assumed
/// present). Order of remaining kinds is preserved.
pub fn select_auth_methods_for_connect(
    candidates: &[AuthMethodKind],
    probe: &dyn FallibleAgentProbe,
) -> Result<Vec<AuthMethodKind>, AgentAuthSelectError> {
    let wants_agent = candidates
        .iter()
        .any(|k| matches!(k, AuthMethodKind::Agent));
    let include_agent = include_agent_if_requested(wants_agent, probe)?;

    Ok(candidates
        .iter()
        .copied()
        .filter(|k| match k {
            AuthMethodKind::Agent => include_agent,
            _ => true,
        })
        .collect())
}

/// Filter a prepared [`crate::SshAuthMethod`] list the same way as
/// [`select_auth_methods_for_connect`] (Agent in/out by probe).
///
/// Secrets on retained methods are untouched; Agent entries are dropped when
/// unavailable. Probe errors fail closed.
#[cfg(feature = "client")]
pub fn filter_ssh_auth_methods_for_connect(
    methods: Vec<crate::SshAuthMethod>,
    probe: &dyn FallibleAgentProbe,
) -> Result<Vec<crate::SshAuthMethod>, AgentAuthSelectError> {
    let wants_agent = methods
        .iter()
        .any(|m| matches!(m, crate::SshAuthMethod::Agent { .. }));
    let include_agent = include_agent_if_requested(wants_agent, probe)?;

    Ok(methods
        .into_iter()
        .filter(|m| match m {
            crate::SshAuthMethod::Agent { .. } => include_agent,
            _ => true,
        })
        .collect())
}

#[cfg(feature = "client")]
impl AuthMethodKind {
    /// Map a live auth method to its kind (credentials discarded).
    pub fn from_ssh_auth_method(method: &crate::SshAuthMethod) -> Self {
        match method {
            crate::SshAuthMethod::Password(_) => Self::Password,
            crate::SshAuthMethod::PrivateKey { .. } => Self::PrivateKey,
            crate::SshAuthMethod::Agent { .. } => Self::Agent,
            crate::SshAuthMethod::KeyboardInteractive { .. } => Self::KeyboardInteractive,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Counts `try_probe` calls so skip / once-only contracts are hard to regress.
    struct CountingProbe {
        inner: FakeFallibleAgent,
        calls: AtomicUsize,
    }

    impl CountingProbe {
        fn new(inner: FakeFallibleAgent) -> Self {
            Self {
                inner,
                calls: AtomicUsize::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl FallibleAgentProbe for CountingProbe {
        fn try_probe(&self) -> Result<AgentAvailability, AgentAuthSelectError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.try_probe()
        }
    }

    #[test]
    fn available_includes_agent() {
        let selected = select_auth_methods_for_connect(
            &[
                AuthMethodKind::PrivateKey,
                AuthMethodKind::Agent,
                AuthMethodKind::Password,
            ],
            &FakeAgent::available(),
        )
        .unwrap();
        assert_eq!(
            selected,
            vec![
                AuthMethodKind::PrivateKey,
                AuthMethodKind::Agent,
                AuthMethodKind::Password,
            ]
        );
        assert!(agent_auth_allowed(&FakeAgent::available()).unwrap());
    }

    #[test]
    fn unavailable_excludes_agent() {
        let selected = select_auth_methods_for_connect(
            &[
                AuthMethodKind::Agent,
                AuthMethodKind::Password,
                AuthMethodKind::Agent,
            ],
            &FakeAgent::unavailable(),
        )
        .unwrap();
        assert_eq!(selected, vec![AuthMethodKind::Password]);
        assert!(!agent_auth_allowed(&FakeAgent::unavailable()).unwrap());
    }

    #[test]
    fn agent_only_unavailable_returns_empty_ok() {
        // Drop (not Err): connect-prep may yield an empty method list.
        let selected =
            select_auth_methods_for_connect(&[AuthMethodKind::Agent], &FakeAgent::unavailable())
                .unwrap();
        assert!(selected.is_empty());
    }

    #[test]
    fn probe_error_fail_closed() {
        let err = select_auth_methods_for_connect(
            &[AuthMethodKind::Password, AuthMethodKind::Agent],
            &FakeFallibleAgent::error("probe failed"),
        )
        .unwrap_err();
        assert_eq!(err.message(), "probe failed");
        assert!(agent_auth_allowed(&FakeFallibleAgent::error("probe failed")).is_err());
    }

    #[test]
    fn agent_only_probe_error_fail_closed() {
        let err = select_auth_methods_for_connect(
            &[AuthMethodKind::Agent],
            &FakeFallibleAgent::error("probe failed"),
        )
        .unwrap_err();
        assert_eq!(err.message(), "probe failed");
    }

    #[test]
    fn no_agent_candidate_skips_probe() {
        // Erroring probe must not run when Agent is not requested.
        let selected = select_auth_methods_for_connect(
            &[AuthMethodKind::Password, AuthMethodKind::PrivateKey],
            &FakeFallibleAgent::error("must-not-run"),
        )
        .unwrap();
        assert_eq!(
            selected,
            vec![AuthMethodKind::Password, AuthMethodKind::PrivateKey]
        );
    }

    #[test]
    fn probe_runs_exactly_once_when_agent_candidate() {
        let probe = CountingProbe::new(FakeFallibleAgent::available());
        let selected = select_auth_methods_for_connect(
            &[
                AuthMethodKind::Agent,
                AuthMethodKind::Password,
                AuthMethodKind::Agent,
            ],
            &probe,
        )
        .unwrap();
        assert_eq!(
            selected,
            vec![
                AuthMethodKind::Agent,
                AuthMethodKind::Password,
                AuthMethodKind::Agent,
            ]
        );
        assert_eq!(probe.calls(), 1);
    }

    #[test]
    fn probe_not_called_without_agent_candidate() {
        let probe = CountingProbe::new(FakeFallibleAgent::error("must-not-run"));
        let selected = select_auth_methods_for_connect(
            &[AuthMethodKind::Password, AuthMethodKind::KeyboardInteractive],
            &probe,
        )
        .unwrap();
        assert_eq!(
            selected,
            vec![
                AuthMethodKind::Password,
                AuthMethodKind::KeyboardInteractive,
            ]
        );
        assert_eq!(probe.calls(), 0);
    }

    #[test]
    fn empty_candidates_ok() {
        let selected =
            select_auth_methods_for_connect(&[], &FakeFallibleAgent::error("must-not-run"))
                .unwrap();
        assert!(selected.is_empty());
    }

    #[test]
    fn fake_fallible_available_matches_fake_agent() {
        let via_fake = select_auth_methods_for_connect(
            &[AuthMethodKind::Agent],
            &FakeAgent::available(),
        )
        .unwrap();
        let via_fallible = select_auth_methods_for_connect(
            &[AuthMethodKind::Agent],
            &FakeFallibleAgent::available(),
        )
        .unwrap();
        assert_eq!(via_fake, via_fallible);
        assert_eq!(via_fake, vec![AuthMethodKind::Agent]);
    }

    #[test]
    fn kind_labels_are_stable() {
        assert_eq!(AuthMethodKind::Agent.as_str(), "agent");
        assert_eq!(AuthMethodKind::Password.as_str(), "password");
        assert_eq!(AuthMethodKind::PrivateKey.as_str(), "private-key");
        assert_eq!(
            AuthMethodKind::KeyboardInteractive.as_str(),
            "keyboard-interactive"
        );
    }

    #[test]
    fn error_debug_has_no_endpoint_path() {
        let err = AgentAuthSelectError::new("probe failed");
        let rendered = format!("{err:?}{err}");
        assert!(rendered.contains("probe failed"));
        assert!(!rendered.contains(r"\\.\pipe"));
        assert!(!rendered.contains("SSH_AUTH_SOCK"));
        assert!(!rendered.to_lowercase().contains("password"));
    }

    #[test]
    fn fake_fallible_debug_has_no_secrets() {
        let ok = format!("{:?}", FakeFallibleAgent::available());
        assert!(ok.contains("FakeFallibleAgent"));
        assert!(ok.contains("available"));
        assert!(!ok.to_lowercase().contains("password"));
        let bad = format!("{:?}", FakeFallibleAgent::error("boom"));
        assert!(bad.contains("boom"));
        assert!(!bad.contains("BEGIN"));
    }

    #[cfg(feature = "client")]
    #[test]
    fn filter_ssh_auth_methods_available_keeps_agent() {
        use crate::auth::{PasswordAuth, SshAuthMethod};

        let methods = vec![
            SshAuthMethod::Password(PasswordAuth {
                username: "u".into(),
                password: "secret".into(),
            }),
            SshAuthMethod::Agent {
                username: "u".into(),
            },
        ];
        let filtered =
            filter_ssh_auth_methods_for_connect(methods, &FakeAgent::available()).unwrap();
        assert_eq!(filtered.len(), 2);
        assert!(matches!(filtered[1], SshAuthMethod::Agent { .. }));
        assert_eq!(
            AuthMethodKind::from_ssh_auth_method(&filtered[0]),
            AuthMethodKind::Password
        );
        assert_eq!(
            AuthMethodKind::from_ssh_auth_method(&filtered[1]),
            AuthMethodKind::Agent
        );
    }

    #[cfg(feature = "client")]
    #[test]
    fn filter_ssh_auth_methods_unavailable_drops_agent() {
        use crate::auth::{PasswordAuth, SshAuthMethod};

        let methods = vec![
            SshAuthMethod::Agent {
                username: "u".into(),
            },
            SshAuthMethod::Password(PasswordAuth {
                username: "u".into(),
                password: "secret".into(),
            }),
        ];
        let filtered =
            filter_ssh_auth_methods_for_connect(methods, &FakeAgent::unavailable()).unwrap();
        assert_eq!(filtered.len(), 1);
        match &filtered[0] {
            SshAuthMethod::Password(p) => {
                assert_eq!(p.username, "u");
                assert_eq!(p.password, "secret");
            }
            other => panic!("expected Password, got {other:?}"),
        }
    }

    #[cfg(feature = "client")]
    #[test]
    fn filter_agent_only_unavailable_returns_empty_ok() {
        use crate::auth::SshAuthMethod;

        let methods = vec![SshAuthMethod::Agent {
            username: "u".into(),
        }];
        let filtered =
            filter_ssh_auth_methods_for_connect(methods, &FakeAgent::unavailable()).unwrap();
        assert!(filtered.is_empty());
    }

    #[cfg(feature = "client")]
    #[test]
    fn filter_ssh_auth_methods_probe_error_fail_closed() {
        use crate::auth::SshAuthMethod;

        let methods = vec![SshAuthMethod::Agent {
            username: "u".into(),
        }];
        let err = filter_ssh_auth_methods_for_connect(
            methods,
            &FakeFallibleAgent::error("probe failed"),
        )
        .unwrap_err();
        assert_eq!(err.message(), "probe failed");
    }

    #[cfg(feature = "client")]
    #[test]
    fn filter_without_agent_skips_probe() {
        use crate::auth::{PasswordAuth, SshAuthMethod};

        let methods = vec![SshAuthMethod::Password(PasswordAuth {
            username: "u".into(),
            password: "secret".into(),
        })];
        let probe = CountingProbe::new(FakeFallibleAgent::error("must-not-run"));
        let filtered = filter_ssh_auth_methods_for_connect(methods, &probe).unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(probe.calls(), 0);
    }

    #[cfg(feature = "client")]
    #[test]
    fn filter_probe_runs_exactly_once_with_duplicate_agents() {
        use crate::auth::SshAuthMethod;

        let methods = vec![
            SshAuthMethod::Agent {
                username: "a".into(),
            },
            SshAuthMethod::Agent {
                username: "b".into(),
            },
        ];
        let probe = CountingProbe::new(FakeFallibleAgent::available());
        let filtered = filter_ssh_auth_methods_for_connect(methods, &probe).unwrap();
        assert_eq!(filtered.len(), 2);
        assert_eq!(probe.calls(), 1);
    }

    #[cfg(feature = "client")]
    #[test]
    fn auth_method_kind_labels_match_ssh_auth_method() {
        use crate::auth::{PasswordAuth, PrivateKeySource, SshAuthMethod};

        let cases: [(SshAuthMethod, AuthMethodKind); 4] = [
            (
                SshAuthMethod::Password(PasswordAuth {
                    username: "u".into(),
                    password: "x".into(),
                }),
                AuthMethodKind::Password,
            ),
            (
                SshAuthMethod::PrivateKey {
                    username: "u".into(),
                    source: PrivateKeySource::bytes(b"k"),
                    passphrase: None,
                },
                AuthMethodKind::PrivateKey,
            ),
            (
                SshAuthMethod::Agent {
                    username: "u".into(),
                },
                AuthMethodKind::Agent,
            ),
            (
                SshAuthMethod::KeyboardInteractive {
                    username: "u".into(),
                },
                AuthMethodKind::KeyboardInteractive,
            ),
        ];
        for (method, kind) in cases {
            assert_eq!(AuthMethodKind::from_ssh_auth_method(&method), kind);
            assert_eq!(kind.as_str(), method.kind_label());
        }
    }
}
