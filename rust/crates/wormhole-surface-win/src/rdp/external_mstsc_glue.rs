//! External `mstsc.exe` + tunnel reject policy Fake glue (no `Process::Command`).
//!
//! Session-shaped wrapper for C# `RdpSessionViewModel.ConnectAsync` after
//! `ShouldUseExternalClientAsync`: when effective external routing is desired,
//! `tunnel_enabled` must be false or the attempt fails closed with the C#
//! `TunnelExternalClientUnsupportedMessage` text.
//!
//! Pure policy — delegates message identity to [`super::configure`]. Does **not**
//! spawn `mstsc.exe`, resolve Azure AD auto-detect, or rewrite CredSSP /
//! display / performance Fake glues.

use std::fmt;

use super::configure::{
    validate_tunnel_rdp_policy, TunnelRdpConflict, TunnelRdpPolicy,
    TUNNEL_EXTERNAL_CLIENT_UNSUPPORTED,
};

/// External `mstsc.exe` routing decision vs per-connection VPN tunnel.
///
/// Evaluated when the caller has already decided to use external routing (C#
/// `ShouldUseExternalClientAsync`); embedded OCX paths do not invoke this glue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalMstscTunnelDecision {
    /// External hand-off is not blocked by tunnel policy (tunnel off).
    AllowExternalMstsc,
    /// Tunnel on + external client — host-network bypass; reject before launch.
    RejectWhenTunnelEnabled,
}

impl ExternalMstscTunnelDecision {
    /// True when external routing may proceed (no tunnel reject).
    pub fn is_allowed(self) -> bool {
        matches!(self, Self::AllowExternalMstsc)
    }

    /// True when tunnel + external combo is rejected.
    pub fn is_rejected(self) -> bool {
        matches!(self, Self::RejectWhenTunnelEnabled)
    }
}

/// Focused inputs for external mstsc policy (effective bools after inheritance).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalMstscPolicyInputs {
    /// Effective `TunnelEnabled` after inheritance / per-attempt route prompt.
    pub tunnel_enabled: bool,
    /// Effective external-client routing (`RdpUseExternalClient` + deferred AAD signals).
    pub use_external_client: bool,
}

/// Decide Allow vs Reject for the external mstsc branch (C# guard after
/// `ShouldUseExternalClientAsync`).
pub fn decide_external_mstsc_tunnel(
    inputs: ExternalMstscPolicyInputs,
) -> ExternalMstscTunnelDecision {
    if inputs.tunnel_enabled && inputs.use_external_client {
        ExternalMstscTunnelDecision::RejectWhenTunnelEnabled
    } else {
        ExternalMstscTunnelDecision::AllowExternalMstsc
    }
}

/// Errors from external mstsc Fake glue — never carry secrets.
#[derive(Clone, PartialEq, Eq)]
pub struct ExternalMstscGlueError {
    message: String,
}

impl ExternalMstscGlueError {
    /// Build from a diagnostic message (must not include secrets).
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// User-facing / diagnostic text (C# overlay parity).
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Tunnel + external reject with the pinned C# message text.
    pub fn tunnel_reject() -> Self {
        Self::new(TUNNEL_EXTERNAL_CLIENT_UNSUPPORTED)
    }
}

impl fmt::Debug for ExternalMstscGlueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExternalMstscGlueError")
            .field("message", &self.message)
            .finish()
    }
}

impl fmt::Display for ExternalMstscGlueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ExternalMstscGlueError {}

/// Validate external routing when `use_external_client` is effective true.
///
/// Returns `Ok(())` when external may proceed; `Err` with C# message when tunnel is on.
pub fn validate_external_mstsc_tunnel(
    inputs: ExternalMstscPolicyInputs,
) -> Result<(), ExternalMstscGlueError> {
    match decide_external_mstsc_tunnel(inputs) {
        ExternalMstscTunnelDecision::AllowExternalMstsc => Ok(()),
        ExternalMstscTunnelDecision::RejectWhenTunnelEnabled => {
            Err(ExternalMstscGlueError::tunnel_reject())
        }
    }
}

/// Stand-in for external mstsc launch — records counts only; **never** spawns a process.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FakeExternalMstscSurface {
    evaluate_count: usize,
    reject_count: usize,
    /// Recorded when external route is allowed (launch eligibility only — no spawn).
    launch_eligible_count: usize,
    last_decision: Option<ExternalMstscTunnelDecision>,
}

impl FakeExternalMstscSurface {
    /// Empty Fake (no evaluations yet).
    pub const fn new() -> Self {
        Self {
            evaluate_count: 0,
            reject_count: 0,
            launch_eligible_count: 0,
            last_decision: None,
        }
    }

    /// How many times [`RdpExternalMstscGlue::evaluate_external_route`] ran.
    pub fn evaluate_count(&self) -> usize {
        self.evaluate_count
    }

    /// Rejections recorded (`RejectWhenTunnelEnabled`).
    pub fn reject_count(&self) -> usize {
        self.reject_count
    }

    /// Allow decisions where external launch would be eligible (no spawn).
    pub fn launch_eligible_count(&self) -> usize {
        self.launch_eligible_count
    }

    /// Last decision from the most recent evaluation.
    pub fn last_decision(&self) -> Option<ExternalMstscTunnelDecision> {
        self.last_decision
    }

    pub(crate) fn record_evaluate(&mut self, decision: ExternalMstscTunnelDecision) {
        self.evaluate_count += 1;
        self.last_decision = Some(decision);
        match decision {
            ExternalMstscTunnelDecision::AllowExternalMstsc => {
                self.launch_eligible_count += 1;
            }
            ExternalMstscTunnelDecision::RejectWhenTunnelEnabled => {
                self.reject_count += 1;
            }
        }
    }
}

/// Fake glue for external mstsc + tunnel policy (session-shaped; no `mstsc.exe`).
#[derive(Debug, Default)]
pub struct RdpExternalMstscGlue {
    fake: FakeExternalMstscSurface,
}

impl RdpExternalMstscGlue {
    /// Glue backed by an in-memory Fake surface.
    pub fn with_fake() -> Self {
        Self::default()
    }

    /// Inspect Fake counters / last decision.
    pub fn fake(&self) -> &FakeExternalMstscSurface {
        &self.fake
    }

    /// C# external-client branch: decide → reject or record launch eligibility (no spawn).
    ///
    /// Call only when effective external routing is desired; embedded OCX paths skip this.
    pub fn evaluate_external_route(
        &mut self,
        inputs: ExternalMstscPolicyInputs,
    ) -> Result<(), ExternalMstscGlueError> {
        let decision = decide_external_mstsc_tunnel(inputs);
        self.fake.record_evaluate(decision);
        validate_external_mstsc_tunnel(inputs)
    }
}

/// Identity check: focused external decision matches `validate_tunnel_rdp_policy`
/// ExternalClient conflict (same message / conflict arm).
pub fn external_decision_matches_tunnel_policy(
    inputs: ExternalMstscPolicyInputs,
) -> bool {
    let decision = decide_external_mstsc_tunnel(inputs);
    let policy = validate_tunnel_rdp_policy(TunnelRdpPolicy {
        tunnel_enabled: inputs.tunnel_enabled,
        use_external_client: inputs.use_external_client,
        gateway_usage_method: 0,
        server_authentication: 0,
    });
    match (decision, policy) {
        (ExternalMstscTunnelDecision::RejectWhenTunnelEnabled, Err(TunnelRdpConflict::ExternalClient)) => {
            true
        }
        (ExternalMstscTunnelDecision::AllowExternalMstsc, Ok(())) => true,
        (ExternalMstscTunnelDecision::AllowExternalMstsc, Err(TunnelRdpConflict::Gateway))
        | (ExternalMstscTunnelDecision::AllowExternalMstsc, Err(TunnelRdpConflict::StrictServerAuth)) => {
            // External glue is external-only; gateway/strict are separate C# guards.
            !inputs.use_external_client || !inputs.tunnel_enabled
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// C# `RdpSessionViewModel.TunnelExternalClientUnsupportedMessage`.
    const CSHARP_TUNNEL_EXTERNAL_CLIENT_UNSUPPORTED: &str = "The external Remote Desktop client cannot be used with a per-connection VPN tunnel because mstsc.exe would connect from the host network. Use embedded RDP without Azure AD/external-client routing, or disable the tunnel.";

    #[test]
    fn allow_when_tunnel_off_and_external() {
        let inputs = ExternalMstscPolicyInputs {
            tunnel_enabled: false,
            use_external_client: true,
        };
        assert_eq!(
            decide_external_mstsc_tunnel(inputs),
            ExternalMstscTunnelDecision::AllowExternalMstsc
        );
        assert!(validate_external_mstsc_tunnel(inputs).is_ok());
    }

    #[test]
    fn reject_when_tunnel_on_and_external() {
        let inputs = ExternalMstscPolicyInputs {
            tunnel_enabled: true,
            use_external_client: true,
        };
        let decision = decide_external_mstsc_tunnel(inputs);
        assert_eq!(decision, ExternalMstscTunnelDecision::RejectWhenTunnelEnabled);
        let err = validate_external_mstsc_tunnel(inputs).expect_err("reject");
        assert_eq!(err.message(), TUNNEL_EXTERNAL_CLIENT_UNSUPPORTED);
        assert_eq!(err.to_string(), CSHARP_TUNNEL_EXTERNAL_CLIENT_UNSUPPORTED);
        assert!(err.message().contains("mstsc.exe"));
    }

    #[test]
    fn allow_when_not_using_external_even_with_tunnel() {
        let inputs = ExternalMstscPolicyInputs {
            tunnel_enabled: true,
            use_external_client: false,
        };
        assert_eq!(
            decide_external_mstsc_tunnel(inputs),
            ExternalMstscTunnelDecision::AllowExternalMstsc
        );
        assert!(validate_external_mstsc_tunnel(inputs).is_ok());
    }

    #[test]
    fn reject_message_matches_csharp_constant() {
        assert_eq!(
            TUNNEL_EXTERNAL_CLIENT_UNSUPPORTED,
            CSHARP_TUNNEL_EXTERNAL_CLIENT_UNSUPPORTED
        );
        assert_eq!(
            ExternalMstscGlueError::tunnel_reject().message(),
            CSHARP_TUNNEL_EXTERNAL_CLIENT_UNSUPPORTED
        );
    }

    #[test]
    fn external_decision_matches_tunnel_policy_external_arm() {
        let reject = ExternalMstscPolicyInputs {
            tunnel_enabled: true,
            use_external_client: true,
        };
        assert!(external_decision_matches_tunnel_policy(reject));

        let allow = ExternalMstscPolicyInputs {
            tunnel_enabled: false,
            use_external_client: true,
        };
        assert!(external_decision_matches_tunnel_policy(allow));
    }

    #[test]
    fn glue_fake_records_reject_without_launch_eligible() {
        let mut glue = RdpExternalMstscGlue::with_fake();
        let inputs = ExternalMstscPolicyInputs {
            tunnel_enabled: true,
            use_external_client: true,
        };
        let err = glue.evaluate_external_route(inputs).expect_err("reject");
        assert_eq!(err.message(), TUNNEL_EXTERNAL_CLIENT_UNSUPPORTED);
        assert_eq!(glue.fake().evaluate_count(), 1);
        assert_eq!(glue.fake().reject_count(), 1);
        assert_eq!(glue.fake().launch_eligible_count(), 0);
        assert_eq!(
            glue.fake().last_decision(),
            Some(ExternalMstscTunnelDecision::RejectWhenTunnelEnabled)
        );
    }

    #[test]
    fn glue_fake_records_launch_eligible_on_allow() {
        let mut glue = RdpExternalMstscGlue::with_fake();
        let inputs = ExternalMstscPolicyInputs {
            tunnel_enabled: false,
            use_external_client: true,
        };
        glue.evaluate_external_route(inputs).expect("allow");
        assert_eq!(glue.fake().evaluate_count(), 1);
        assert_eq!(glue.fake().reject_count(), 0);
        assert_eq!(glue.fake().launch_eligible_count(), 1);
        assert_eq!(
            glue.fake().last_decision(),
            Some(ExternalMstscTunnelDecision::AllowExternalMstsc)
        );
    }

    #[test]
    fn glue_does_not_spawn_process_on_allow() {
        // Contract: Fake only bumps counters — no std::process / Command in this module.
        let mut glue = RdpExternalMstscGlue::with_fake();
        glue.evaluate_external_route(ExternalMstscPolicyInputs {
            tunnel_enabled: false,
            use_external_client: true,
        })
        .expect("allow");
        assert_eq!(glue.fake().launch_eligible_count(), 1);
        // Second allow still only counter — no side effects beyond Fake.
        glue.evaluate_external_route(ExternalMstscPolicyInputs {
            tunnel_enabled: false,
            use_external_client: true,
        })
        .expect("allow again");
        assert_eq!(glue.fake().launch_eligible_count(), 2);
    }

    #[test]
    fn decision_is_copy_and_predicate_helpers() {
        let allow = ExternalMstscTunnelDecision::AllowExternalMstsc;
        assert!(allow.is_allowed());
        assert!(!allow.is_rejected());
        let reject = ExternalMstscTunnelDecision::RejectWhenTunnelEnabled;
        assert!(!reject.is_allowed());
        assert!(reject.is_rejected());
    }

    #[test]
    fn debug_glue_error_omits_credential_shaped_content() {
        let err = ExternalMstscGlueError::tunnel_reject();
        let dbg = format!("{err:?}");
        assert!(!dbg.to_lowercase().contains("password"));
        assert!(!dbg.contains("credential"));
    }
}
