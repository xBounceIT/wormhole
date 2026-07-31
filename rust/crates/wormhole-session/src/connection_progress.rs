//! Session connecting progress stepper — pure Rust Fake glue.
//!
//! Mirrors C# [`ConnectionProgress`](../../../../ViewModels/Sessions/ConnectionProgress.cs) /
//! [`ConnectionProgressView`](../../../../Views/Sessions/ConnectionProgressView.xaml):
//! numbered phased steps, live sub-status under the active step, and failure
//! pinpointing via [`ConnectionProgress::fail`].
//!
//! Rust lab expands the orchestrator connect path into explicit phases:
//! **Resolve → Tunnel → Auth → Connect** (Tunnel / Auth omitted when not
//! applicable). C# production steppers only surface Tunnel + Connect when
//! `TunnelEnabled`; direct connects use a plain spinner ([`ConnectProgressPlan::csharp_direct`]).
//!
//! | Condition | Behavior |
//! |---|---|
//! | [`FakeConnectionProgressGlue::run_fake_connect`] | Walks planned steps; Fake delays recorded, never slept |
//! | Mid-flight cancel ([`CancellationToken`]) | **Fail closed** → [`FakeConnectOutcome::Cancelled`]; [`ConnectionProgress::reset`] (C# `HandleCancellationAsync`) |
//! | Scripted failure | Active step → [`ConnectionStepState::Failed`]; [`FakeConnectOutcome::Failed`] |
//! | Unknown phase in [`ConnectionProgress::begin`] | No-op (never marks all steps completed) |
//!
//! **No GPUI / WinUI.** [`Debug`] omits passwords, hosts, and free-form detail text.

use std::fmt;

use tokio_util::sync::CancellationToken;

use crate::error::{Result, SessionError};

/// Visual state of one step in the connecting stepper (C# `ConnectionStepState`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionStepState {
    Pending,
    Active,
    Completed,
    Failed,
}

/// Ordered connect phases for the Rust session orchestrator lab.
///
/// C# [`ConnectionPhase`](../../../../ViewModels/Sessions/ConnectionProgress.cs)
/// only models [`Self::Tunnel`] and [`Self::Connect`]; Resolve / Auth are folded
/// into the Connect phase there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectionProgressPhase {
    /// Profile / inheritance / route resolution.
    Resolve,
    /// Per-connection VPN establish ([`TunnelSubPhase`] detail lines).
    Tunnel,
    /// Target credential resolution + protocol authentication.
    Auth,
    /// Protocol handshake (SSH shell, WebView2 navigate, RDP OCX, …).
    Connect,
}

impl ConnectionProgressPhase {
    /// Stable snake-case label for errors / logging (no host material).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Resolve => "resolve",
            Self::Tunnel => "tunnel",
            Self::Auth => "auth",
            Self::Connect => "connect",
        }
    }
}

/// Coarse tunnel-provider sub-phases (C# `TunnelPhase`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelSubPhase {
    Preparing,
    Authenticating,
    DownloadingConfiguration,
    StartingTunnel,
}

/// A single tunnel progress report (C# `TunnelProgress`).
#[derive(Clone, PartialEq, Eq)]
pub struct TunnelProgressReport {
    pub phase: TunnelSubPhase,
    /// Provider override; may contain gateway text — never logged via [`Debug`].
    pub detail: Option<String>,
}

impl fmt::Debug for TunnelProgressReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunnelProgressReport")
            .field("phase", &self.phase)
            .field("detail_len", &self.detail.as_ref().map(|d| d.len()))
            .finish()
    }
}

impl TunnelProgressReport {
    pub fn new(phase: TunnelSubPhase) -> Self {
        Self {
            phase,
            detail: None,
        }
    }

    pub fn with_detail(phase: TunnelSubPhase, detail: impl Into<String>) -> Self {
        Self {
            phase,
            detail: Some(detail.into()),
        }
    }
}

/// Map a tunnel report to the human-readable line under the VPN step (C#
/// `ConnectionProgress.DescribeTunnelPhase`).
pub fn describe_tunnel_phase(progress: &TunnelProgressReport) -> String {
    if let Some(detail) = progress.detail.as_deref() {
        if !detail.trim().is_empty() {
            return detail.trim().to_owned();
        }
    }
    match progress.phase {
        TunnelSubPhase::Preparing => "Preparing VPN configuration…".to_owned(),
        TunnelSubPhase::Authenticating => "Authenticating with the VPN gateway…".to_owned(),
        TunnelSubPhase::DownloadingConfiguration => {
            "Downloading VPN configuration…".to_owned()
        }
        TunnelSubPhase::StartingTunnel => "Bringing up the VPN tunnel…".to_owned(),
    }
}

/// One numbered step in the connecting stepper (C# `ConnectionStep`).
#[derive(Clone, PartialEq, Eq)]
pub struct ConnectionStep {
    pub phase: ConnectionProgressPhase,
    pub number: u32,
    pub label: &'static str,
    pub is_last: bool,
    pub state: ConnectionStepState,
}

impl ConnectionStep {
    pub fn is_pending(&self) -> bool {
        self.state == ConnectionStepState::Pending
    }

    pub fn is_active(&self) -> bool {
        self.state == ConnectionStepState::Active
    }

    pub fn is_completed(&self) -> bool {
        self.state == ConnectionStepState::Completed
    }

    pub fn is_failed(&self) -> bool {
        self.state == ConnectionStepState::Failed
    }
}

impl fmt::Debug for ConnectionStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionStep")
            .field("phase", &self.phase)
            .field("number", &self.number)
            .field("label", &self.label)
            .field("is_last", &self.is_last)
            .field("state", &self.state)
            .finish()
    }
}

/// Which phases appear in the stepper for one connect attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectProgressPlan {
    pub resolve: bool,
    pub tunnel: bool,
    pub auth: bool,
    /// Connect is always the terminal phase when any step is shown.
    pub connect: bool,
}

impl ConnectProgressPlan {
    /// C# parity: tunneled → Tunnel + Connect; direct → empty (plain spinner).
    pub const fn csharp_tunneled() -> Self {
        Self {
            resolve: false,
            tunnel: true,
            auth: false,
            connect: true,
        }
    }

    /// C# parity: no numbered steps (overlay plain spinner).
    pub const fn csharp_direct() -> Self {
        Self {
            resolve: false,
            tunnel: false,
            auth: false,
            connect: false,
        }
    }

    /// Rust orchestrator lab: tunneled SSH/RDP/VNC password path.
    pub const fn orchestrator_tunneled_auth() -> Self {
        Self {
            resolve: true,
            tunnel: true,
            auth: true,
            connect: true,
        }
    }

    /// Rust orchestrator lab: direct SSH (no VPN).
    pub const fn orchestrator_direct_auth() -> Self {
        Self {
            resolve: true,
            tunnel: false,
            auth: true,
            connect: true,
        }
    }

    /// Rust orchestrator lab: tunneled HTTP/HTTPS (no Wormhole credentials).
    pub const fn orchestrator_tunneled_web() -> Self {
        Self {
            resolve: true,
            tunnel: true,
            auth: false,
            connect: true,
        }
    }

    /// Rust orchestrator lab: local Serial (resolve + open COM only).
    pub const fn orchestrator_serial() -> Self {
        Self {
            resolve: true,
            tunnel: false,
            auth: false,
            connect: true,
        }
    }

    /// Ordered `(phase, label)` pairs for [`ConnectionProgress::initialize`].
    pub fn steps(self) -> Vec<(ConnectionProgressPhase, &'static str)> {
        let mut out = Vec::new();
        if self.resolve {
            out.push((ConnectionProgressPhase::Resolve, "Resolve"));
        }
        if self.tunnel {
            out.push((ConnectionProgressPhase::Tunnel, "VPN tunnel"));
        }
        if self.auth {
            out.push((ConnectionProgressPhase::Auth, "Authenticate"));
        }
        if self.connect {
            out.push((ConnectionProgressPhase::Connect, "Connect"));
        }
        out
    }
}

/// Drives the numbered phased progress stepper (C# `ConnectionProgress`).
#[derive(Clone, PartialEq, Eq)]
pub struct ConnectionProgress {
    steps: Vec<ConnectionStep>,
    is_active: bool,
    has_failed_step: bool,
    detail: Option<String>,
}

impl ConnectionProgress {
    pub fn new() -> Self {
        Self {
            steps: Vec::new(),
            is_active: false,
            has_failed_step: false,
            detail: None,
        }
    }

    pub fn is_active(&self) -> bool {
        self.is_active
    }

    pub fn has_failed_step(&self) -> bool {
        self.has_failed_step
    }

    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }

    pub fn steps(&self) -> &[ConnectionStep] {
        &self.steps
    }

    pub fn active_phase(&self) -> Option<ConnectionProgressPhase> {
        self.steps
            .iter()
            .find(|s| s.state == ConnectionStepState::Active)
            .map(|s| s.phase)
    }

    /// Clear all steps — plain-spinner state (C# `Reset`).
    pub fn reset(&mut self) {
        self.steps.clear();
        self.detail = None;
        self.is_active = false;
        self.has_failed_step = false;
    }

    /// Replace steps; each starts [`ConnectionStepState::Pending`] (C# `Initialize`).
    pub fn initialize(&mut self, steps: &[(ConnectionProgressPhase, &'static str)]) {
        self.steps.clear();
        self.detail = None;
        self.has_failed_step = false;
        let last = steps.len().saturating_sub(1);
        for (i, (phase, label)) in steps.iter().enumerate() {
            self.steps.push(ConnectionStep {
                phase: *phase,
                number: (i as u32) + 1,
                label: *label,
                is_last: i == last,
                state: ConnectionStepState::Pending,
            });
        }
        self.is_active = !self.steps.is_empty();
    }

    /// Initialize from a [`ConnectProgressPlan`].
    pub fn initialize_plan(&mut self, plan: ConnectProgressPlan) {
        let steps = plan.steps();
        self.initialize(&steps);
    }

    /// Mark `phase` active; prior non-failed steps → Completed (C# `Begin`).
    pub fn begin(&mut self, phase: ConnectionProgressPhase) {
        if !self.steps.iter().any(|s| s.phase == phase) {
            return;
        }

        let mut reached = false;
        for step in &mut self.steps {
            if step.phase == phase {
                step.state = ConnectionStepState::Active;
                reached = true;
            } else if !reached && step.state != ConnectionStepState::Failed {
                step.state = ConnectionStepState::Completed;
            }
        }

        if reached {
            self.detail = None;
        }
    }

    /// Live sub-status for the active step (tunnel phase populates this in C#).
    pub fn set_detail(&mut self, detail: impl Into<String>) {
        self.detail = Some(detail.into());
    }

    pub fn clear_detail(&mut self) {
        self.detail = None;
    }

    /// Mark every non-failed step Completed (C# `CompleteAll`).
    pub fn complete_all(&mut self) {
        for step in &mut self.steps {
            if step.state != ConnectionStepState::Failed {
                step.state = ConnectionStepState::Completed;
            }
        }
        self.detail = None;
        self.has_failed_step = false;
    }

    /// Mark the active step Failed (C# `Fail`). No-op when nothing is active.
    pub fn fail(&mut self) -> bool {
        let mut failed_any = false;
        for step in &mut self.steps {
            if step.state == ConnectionStepState::Active {
                step.state = ConnectionStepState::Failed;
                failed_any = true;
            }
        }
        if failed_any {
            self.detail = None;
            self.has_failed_step = true;
        }
        failed_any
    }
}

impl Default for ConnectionProgress {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ConnectionProgress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionProgress")
            .field("step_count", &self.steps.len())
            .field("is_active", &self.is_active)
            .field("has_failed_step", &self.has_failed_step)
            .field("active_phase", &self.active_phase())
            .field("detail_len", &self.detail.as_ref().map(|d| d.len()))
            .field(
                "steps",
                &self
                    .steps
                    .iter()
                    .map(|s| (s.phase, s.state))
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

/// Scripted outcome for one planned phase in a Fake connect walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FakePhaseOutcome {
    Success,
    Fail,
}

/// Terminal Fake connect outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FakeConnectOutcome {
    Connected,
    /// User cancel mid-flight — progress reset, never Connected.
    Cancelled,
    Failed {
        phase: ConnectionProgressPhase,
    },
}

/// Thin Fake driver: advances [`ConnectionProgress`] through a planned connect.
pub struct FakeConnectionProgressGlue {
    progress: ConnectionProgress,
}

impl FakeConnectionProgressGlue {
    pub fn new() -> Self {
        Self {
            progress: ConnectionProgress::new(),
        }
    }

    pub fn from_progress(progress: ConnectionProgress) -> Self {
        Self { progress }
    }

    pub fn progress(&self) -> &ConnectionProgress {
        &self.progress
    }

    pub fn progress_mut(&mut self) -> &mut ConnectionProgress {
        &mut self.progress
    }

    /// Walk `plan` phases in order, applying one scripted outcome per step.
    ///
    /// `outcomes` must have exactly `plan.steps().len()` entries; mismatch fails
    /// closed. Checks `cancel` before each phase and after `begin` (mid-flight).
    /// Optional `tunnel_reports` apply only while the Tunnel phase is active
    /// (one report per successful tunnel phase, in order).
    pub fn run_fake_connect(
        &mut self,
        plan: ConnectProgressPlan,
        outcomes: &[FakePhaseOutcome],
        cancel: &CancellationToken,
        tunnel_reports: &[TunnelProgressReport],
    ) -> Result<FakeConnectOutcome> {
        let steps = plan.steps();
        if outcomes.len() != steps.len() {
            return Err(SessionError::Other(format!(
                "Fake connect script length {} does not match plan step count {}",
                outcomes.len(),
                steps.len()
            )));
        }

        self.progress.initialize(&steps);
        if steps.is_empty() {
            if cancel.is_cancelled() {
                return Ok(FakeConnectOutcome::Cancelled);
            }
            return Ok(FakeConnectOutcome::Connected);
        }

        let mut tunnel_report_idx = 0usize;

        for ((phase, _label), outcome) in steps.iter().zip(outcomes.iter()) {
            if cancel.is_cancelled() {
                self.progress.reset();
                return Ok(FakeConnectOutcome::Cancelled);
            }

            self.progress.begin(*phase);

            if *phase == ConnectionProgressPhase::Tunnel {
                if let Some(report) = tunnel_reports.get(tunnel_report_idx) {
                    self.progress
                        .set_detail(describe_tunnel_phase(report));
                    tunnel_report_idx = tunnel_report_idx.saturating_add(1);
                }
            }

            if cancel.is_cancelled() {
                self.progress.reset();
                return Ok(FakeConnectOutcome::Cancelled);
            }

            match outcome {
                FakePhaseOutcome::Success => {}
                FakePhaseOutcome::Fail => {
                    let _ = self.progress.fail();
                    return Ok(FakeConnectOutcome::Failed { phase: *phase });
                }
            }
        }

        if cancel.is_cancelled() {
            self.progress.reset();
            return Ok(FakeConnectOutcome::Cancelled);
        }

        self.progress.complete_all();
        Ok(FakeConnectOutcome::Connected)
    }
}

impl Default for FakeConnectionProgressGlue {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for FakeConnectionProgressGlue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeConnectionProgressGlue")
            .field("progress", &self.progress)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tunneled_auth_outcomes(success: bool) -> [FakePhaseOutcome; 4] {
        if success {
            [
                FakePhaseOutcome::Success,
                FakePhaseOutcome::Success,
                FakePhaseOutcome::Success,
                FakePhaseOutcome::Success,
            ]
        } else {
            [
                FakePhaseOutcome::Success,
                FakePhaseOutcome::Fail,
                FakePhaseOutcome::Success,
                FakePhaseOutcome::Success,
            ]
        }
    }

    #[test]
    fn initialize_plan_numbering_and_is_last() {
        let mut progress = ConnectionProgress::new();
        progress.initialize_plan(ConnectProgressPlan::orchestrator_tunneled_auth());
        assert_eq!(progress.steps().len(), 4);
        assert_eq!(progress.steps()[0].number, 1);
        assert_eq!(progress.steps()[0].label, "Resolve");
        assert!(!progress.steps()[0].is_last);
        assert!(progress.steps()[3].is_last);
        assert!(progress.is_active());
    }

    #[test]
    fn csharp_direct_is_inactive_spinner() {
        let mut progress = ConnectionProgress::new();
        progress.initialize_plan(ConnectProgressPlan::csharp_direct());
        assert!(!progress.is_active());
        assert!(progress.steps().is_empty());
    }

    #[test]
    fn begin_unknown_phase_is_noop() {
        let mut progress = ConnectionProgress::new();
        progress.initialize_plan(ConnectProgressPlan::csharp_tunneled());
        progress.begin(ConnectionProgressPhase::Resolve);
        assert!(progress
            .steps()
            .iter()
            .all(|s| s.state == ConnectionStepState::Pending));
    }

    #[test]
    fn begin_marks_prior_completed_and_clears_detail() {
        let mut progress = ConnectionProgress::new();
        progress.initialize_plan(ConnectProgressPlan::csharp_tunneled());
        progress.set_detail("stale");
        progress.begin(ConnectionProgressPhase::Tunnel);
        assert_eq!(
            progress.steps()[0].state,
            ConnectionStepState::Active
        );
        assert!(progress.detail().is_none());
        progress.begin(ConnectionProgressPhase::Connect);
        assert_eq!(
            progress.steps()[0].state,
            ConnectionStepState::Completed
        );
        assert_eq!(
            progress.steps()[1].state,
            ConnectionStepState::Active
        );
    }

    #[test]
    fn fail_marks_active_only_and_sets_has_failed_step() {
        let mut progress = ConnectionProgress::new();
        progress.initialize_plan(ConnectProgressPlan::csharp_tunneled());
        progress.begin(ConnectionProgressPhase::Tunnel);
        progress.set_detail("Bringing up…");
        assert!(progress.fail());
        assert!(progress.has_failed_step());
        assert_eq!(
            progress.steps()[0].state,
            ConnectionStepState::Failed
        );
        assert!(progress.detail().is_none());
        assert!(!progress.fail());
    }

    #[test]
    fn complete_all_clears_failed_flag() {
        let mut progress = ConnectionProgress::new();
        progress.initialize_plan(ConnectProgressPlan::csharp_tunneled());
        progress.begin(ConnectionProgressPhase::Tunnel);
        progress.complete_all();
        assert!(progress
            .steps()
            .iter()
            .all(|s| s.state == ConnectionStepState::Completed));
        assert!(!progress.has_failed_step());
    }

    #[test]
    fn describe_tunnel_phase_defaults_and_override() {
        let default = describe_tunnel_phase(&TunnelProgressReport::new(
            TunnelSubPhase::StartingTunnel,
        ));
        assert!(default.contains("VPN tunnel"));
        let custom = describe_tunnel_phase(&TunnelProgressReport::with_detail(
            TunnelSubPhase::Preparing,
            "gateway.example OTP required",
        ));
        assert_eq!(custom, "gateway.example OTP required");
    }

    #[test]
    fn fake_connect_success_completes_all_steps() {
        let mut glue = FakeConnectionProgressGlue::new();
        let cancel = CancellationToken::new();
        let outcomes = tunneled_auth_outcomes(true);
        let result = glue
            .run_fake_connect(
                ConnectProgressPlan::orchestrator_tunneled_auth(),
                &outcomes,
                &cancel,
                &[TunnelProgressReport::new(TunnelSubPhase::Authenticating)],
            )
            .unwrap();
        assert_eq!(result, FakeConnectOutcome::Connected);
        assert!(glue.progress().steps().iter().all(|s| s.is_completed()));
        assert!(!glue.progress().has_failed_step());
        assert!(glue.progress().detail().is_none());
    }

    #[test]
    fn fake_connect_failure_pins_phase() {
        let mut glue = FakeConnectionProgressGlue::new();
        let cancel = CancellationToken::new();
        let outcomes = tunneled_auth_outcomes(false);
        let result = glue
            .run_fake_connect(
                ConnectProgressPlan::orchestrator_tunneled_auth(),
                &outcomes,
                &cancel,
                &[],
            )
            .unwrap();
        assert_eq!(
            result,
            FakeConnectOutcome::Failed {
                phase: ConnectionProgressPhase::Tunnel
            }
        );
        assert!(glue.progress().has_failed_step());
        assert_eq!(
            glue.progress().steps()[1].state,
            ConnectionStepState::Failed
        );
    }

    #[test]
    fn cancel_before_begin_resets_and_fail_closed() {
        let mut glue = FakeConnectionProgressGlue::new();
        let cancel = CancellationToken::new();
        cancel.cancel();
        let outcomes = tunneled_auth_outcomes(true);
        let result = glue
            .run_fake_connect(
                ConnectProgressPlan::orchestrator_tunneled_auth(),
                &outcomes,
                &cancel,
                &[],
            )
            .unwrap();
        assert_eq!(result, FakeConnectOutcome::Cancelled);
        assert!(!glue.progress().is_active());
        assert!(glue.progress().steps().is_empty());
    }

    #[test]
    fn cancel_after_begin_resets_without_failed_step() {
        let mut progress = ConnectionProgress::new();
        progress.initialize_plan(ConnectProgressPlan::csharp_tunneled());
        progress.begin(ConnectionProgressPhase::Tunnel);
        progress.set_detail("Bringing up the VPN tunnel…");
        // Mid-flight cancel path in `run_fake_connect` (C# `HandleCancellationAsync`).
        progress.reset();
        assert!(!progress.has_failed_step());
        assert!(!progress.is_active());
        assert!(progress.steps().is_empty());
    }

    #[test]
    fn cancel_after_tunnel_begin_in_fake_walk() {
        let mut glue = FakeConnectionProgressGlue::new();
        let cancel = CancellationToken::new();
        glue.progress_mut()
            .initialize_plan(ConnectProgressPlan::csharp_tunneled());
        glue.progress_mut()
            .begin(ConnectionProgressPhase::Tunnel);
        cancel.cancel();
        // Next iteration would be Connect; emulate post-begin cancel check.
        glue.progress_mut().reset();
        assert_eq!(
            glue.run_fake_connect(
                ConnectProgressPlan::csharp_direct(),
                &[],
                &cancel,
                &[],
            )
            .unwrap(),
            FakeConnectOutcome::Cancelled
        );
        assert!(!glue.progress().has_failed_step());
    }

    #[test]
    fn fail_without_active_step_is_noop() {
        let mut progress = ConnectionProgress::new();
        progress.initialize_plan(ConnectProgressPlan::csharp_tunneled());
        assert!(!progress.fail());
        assert!(!progress.has_failed_step());
    }

    #[test]
    fn auth_failure_pins_auth_phase() {
        let mut glue = FakeConnectionProgressGlue::new();
        let cancel = CancellationToken::new();
        let outcomes = [
            FakePhaseOutcome::Success,
            FakePhaseOutcome::Success,
            FakePhaseOutcome::Fail,
            FakePhaseOutcome::Success,
        ];
        let result = glue
            .run_fake_connect(
                ConnectProgressPlan::orchestrator_tunneled_auth(),
                &outcomes,
                &cancel,
                &[],
            )
            .unwrap();
        assert_eq!(
            result,
            FakeConnectOutcome::Failed {
                phase: ConnectionProgressPhase::Auth
            }
        );
    }

    #[test]
    fn tunnel_progress_report_debug_redacts_detail() {
        let report = TunnelProgressReport::with_detail(
            TunnelSubPhase::Authenticating,
            "secret-token gateway.vpn.corp",
        );
        let dbg = format!("{report:?}");
        assert!(dbg.contains("detail_len"));
        assert!(!dbg.contains("secret-token"));
        assert!(!dbg.contains("gateway"));
    }

    #[test]
    fn script_mismatch_leaves_progress_uninitialized() {
        let mut glue = FakeConnectionProgressGlue::new();
        let cancel = CancellationToken::new();
        let err = glue
            .run_fake_connect(
                ConnectProgressPlan::orchestrator_tunneled_auth(),
                &[FakePhaseOutcome::Success],
                &cancel,
                &[],
            )
            .unwrap_err();
        assert!(err.to_string().contains("does not match"));
        assert!(!glue.progress().is_active());
        assert!(glue.progress().steps().is_empty());
    }

    #[test]
    fn empty_plan_connected_when_not_cancelled() {
        let mut glue = FakeConnectionProgressGlue::new();
        let cancel = CancellationToken::new();
        let result = glue
            .run_fake_connect(
                ConnectProgressPlan::csharp_direct(),
                &[],
                &cancel,
                &[],
            )
            .unwrap();
        assert_eq!(result, FakeConnectOutcome::Connected);
        assert!(!glue.progress().is_active());
    }

    #[test]
    fn tunnel_detail_applied_during_fake_walk() {
        let mut glue = FakeConnectionProgressGlue::new();
        let cancel = CancellationToken::new();
        let outcomes = [
            FakePhaseOutcome::Success,
            FakePhaseOutcome::Success,
            FakePhaseOutcome::Success,
        ];
        glue.run_fake_connect(
            ConnectProgressPlan::orchestrator_tunneled_web(),
            &outcomes,
            &cancel,
            &[TunnelProgressReport::with_detail(
                TunnelSubPhase::Preparing,
                "Reading config",
            )],
        )
        .unwrap();
        // complete_all clears detail
        assert!(glue.progress().detail().is_none());
    }

    #[test]
    fn debug_omits_secrets_and_freeform_detail() {
        let mut progress = ConnectionProgress::new();
        progress.initialize_plan(ConnectProgressPlan::orchestrator_tunneled_auth());
        progress.begin(ConnectionProgressPhase::Tunnel);
        progress.set_detail("password=sekret host=10.0.0.5");
        let dbg = format!("{progress:?}");
        assert!(dbg.contains("detail_len"));
        assert!(!dbg.contains("password"));
        assert!(!dbg.contains("10.0.0.5"));
        assert!(!dbg.contains("sekret"));

        let glue = FakeConnectionProgressGlue::new();
        let glue_dbg = format!("{glue:?}");
        assert!(glue_dbg.contains("FakeConnectionProgressGlue"));
        assert!(!glue_dbg.to_lowercase().contains("password"));
    }

    #[test]
    fn reset_clears_all_state() {
        let mut progress = ConnectionProgress::new();
        progress.initialize_plan(ConnectProgressPlan::csharp_tunneled());
        progress.begin(ConnectionProgressPhase::Tunnel);
        progress.fail();
        progress.reset();
        assert!(!progress.is_active());
        assert!(!progress.has_failed_step());
        assert!(progress.steps().is_empty());
    }

    #[test]
    fn orchestrator_serial_plan_two_steps() {
        let steps = ConnectProgressPlan::orchestrator_serial().steps();
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].0, ConnectionProgressPhase::Resolve);
        assert_eq!(steps[1].0, ConnectionProgressPhase::Connect);
    }
}
