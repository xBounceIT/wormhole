//! Session-orchestrator SSH reconnect glue (Fake path).
//!
//! Thin Lab stub: drives [`wormhole_ssh::SshReconnectPolicy`] with a
//! [`FakeBackoffSchedule`] after an unexpected drop of a Connected Fake SSH
//! session. **No live SSH**, no GPUI, no credential fields.
//!
//! | Cause / stop | Behavior |
//! |---|---|
//! | [`SshDisconnectCause::UnexpectedDrop`] | Policy plans Retry while budget remains |
//! | [`SshDisconnectCause::UserCancel`] | Never reconnects (budget reset) |
//! | [`ReconnectStopReason::BudgetExhausted`] | [`SessionState::Failed`] + exhaustion note |
//! | Fake schedule | Delays are **recorded**, never slept |
//!
//! Reuses `wormhole_ssh::reconnect` decide / budget helpers — does not reimplement
//! backoff rules. Live UI / WebView2 rebind loop remains Pending.

use std::fmt;
use std::time::Duration;

use wormhole_ssh::{
    reconnect_exhausted_note, BackoffSchedule, FakeBackoffSchedule, ReconnectConnectOutcome,
    ReconnectPolicyError, ReconnectStopReason, ReconnectVerdict, SshDisconnectCause,
    SshReconnectPolicy, AUTO_RECONNECT_DELAY, MAX_AUTO_RECONNECT_ATTEMPTS,
};

use crate::error::{Result, SessionError};
use crate::state::SessionState;

fn policy_err(err: ReconnectPolicyError) -> SessionError {
    SessionError::Other(err.message().into())
}

/// Terminal Fake reconnect outcome (maps onto orchestrator session state).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FakeSshReconnectResult {
    /// Fake reconnect connect succeeded.
    Connected {
        /// Attempts recorded via [`FakeSshReconnectGlue::begin_fake_retry`] (0 if
        /// the initial disconnect already stopped as Connected — defensive).
        attempts: u32,
    },
    /// User cancel / mid-connect disconnect — never auto-reconnects.
    Cancelled,
    /// Terminal failure: budget exhausted, non-retryable, policy off, etc.
    Failed {
        reason: ReconnectStopReason,
        /// Set when [`ReconnectStopReason::BudgetExhausted`] (C# exhaustion note).
        note: Option<String>,
    },
}

impl FakeSshReconnectResult {
    /// Orchestrator lifecycle state implied by this outcome.
    pub fn session_state(&self) -> SessionState {
        match self {
            Self::Connected { .. } => SessionState::Connected,
            Self::Cancelled => SessionState::Closed,
            Self::Failed { .. } => SessionState::Failed,
        }
    }

    pub fn is_failed(&self) -> bool {
        matches!(self, Self::Failed { .. })
    }
}

/// Thin Fake reconnect driver for the session orchestrator.
///
/// Owns a [`SshReconnectPolicy`] + injected [`FakeBackoffSchedule`]. Delays from
/// accepted Retry verdicts are appended to [`Self::waited_delays`] (no wall clock).
pub struct FakeSshReconnectGlue {
    policy: SshReconnectPolicy,
    schedule: FakeBackoffSchedule,
    waited: Vec<Duration>,
}

impl FakeSshReconnectGlue {
    /// C# attempt budget (3) with a Fake schedule of three fixed delays
    /// ([`AUTO_RECONNECT_DELAY`] each) — unit tests may use shorter Fake delays
    /// via [`Self::new`] / [`Self::with_fake_delays`].
    pub fn csharp_defaults() -> Self {
        Self::with_fake_delays(std::iter::repeat_n(
            AUTO_RECONNECT_DELAY,
            MAX_AUTO_RECONNECT_ATTEMPTS as usize,
        ))
        .expect("csharp defaults: schedule max matches policy budget")
    }

    /// Build glue; fail closed when budget max ≠ schedule max (hostile Fake).
    pub fn new(
        policy: SshReconnectPolicy,
        schedule: FakeBackoffSchedule,
    ) -> Result<Self> {
        if policy.budget().max_attempts() != schedule.max_attempts() {
            return Err(SessionError::Other(
                "reconnect budget max_attempts does not match Fake backoff schedule".into(),
            ));
        }
        Ok(Self {
            policy,
            schedule,
            waited: Vec::new(),
        })
    }

    /// Convenience: policy max = `delays.len()` (empty → policy disabled / fail closed).
    pub fn with_fake_delays(delays: impl IntoIterator<Item = Duration>) -> Result<Self> {
        let schedule = FakeBackoffSchedule::new(delays);
        let policy = SshReconnectPolicy::new(schedule.max_attempts());
        Self::new(policy, schedule)
    }

    pub fn policy(&self) -> &SshReconnectPolicy {
        &self.policy
    }

    pub fn policy_mut(&mut self) -> &mut SshReconnectPolicy {
        &mut self.policy
    }

    pub fn schedule(&self) -> &FakeBackoffSchedule {
        &self.schedule
    }

    /// Delays accepted via [`Self::begin_fake_retry`] (order preserved; no sleep).
    pub fn waited_delays(&self) -> &[Duration] {
        &self.waited
    }

    /// Decide after a disconnect of a Connected Fake SSH session.
    ///
    /// [`SshDisconnectCause::UserCancel`] never returns Retry (and resets budget).
    pub fn handle_disconnect(
        &mut self,
        cause: SshDisconnectCause,
    ) -> Result<ReconnectVerdict> {
        self.policy
            .on_disconnect(cause, &self.schedule)
            .map_err(policy_err)
    }

    /// Accept a Retry: record the attempt on the policy and append the Fake delay
    /// (no wall-clock wait).
    pub fn begin_fake_retry(&mut self, verdict: ReconnectVerdict) -> Result<Duration> {
        let delay = self.policy.begin_retry(verdict).map_err(policy_err)?;
        self.waited.push(delay);
        Ok(delay)
    }

    /// After a Fake reconnect connect attempt, plan the next Retry or Stop.
    pub fn after_fake_connect(
        &self,
        outcome: ReconnectConnectOutcome,
    ) -> Result<ReconnectVerdict> {
        self.policy
            .on_connect_attempt(outcome, &self.schedule)
            .map_err(policy_err)
    }

    /// Stability window elapsed while still Connected — restore full retry budget.
    pub fn on_stability_elapsed(&mut self) {
        self.policy.on_stability_elapsed();
    }

    /// Run the Fake reconnect loop from `cause` through scripted connect outcomes.
    ///
    /// Each [`ReconnectVerdict::Retry`] consumes one outcome from `connect_outcomes`
    /// (in order). Running out of outcomes while a Retry is still required fails
    /// closed. Delays are recorded only — never slept.
    pub fn run_fake_loop(
        &mut self,
        cause: SshDisconnectCause,
        connect_outcomes: &[ReconnectConnectOutcome],
    ) -> Result<FakeSshReconnectResult> {
        let mut verdict = self.handle_disconnect(cause)?;
        let mut outcome_idx = 0usize;

        loop {
            match verdict {
                ReconnectVerdict::Stop { reason } => {
                    return Ok(self.stop_to_result(reason));
                }
                ReconnectVerdict::Retry { .. } => {
                    // Peek the next scripted outcome **before** mutating budget /
                    // waited delays so an exhausted script never half-applies.
                    let Some(outcome) = connect_outcomes.get(outcome_idx).copied() else {
                        return Err(SessionError::Other(
                            "Fake reconnect script exhausted before loop settled".into(),
                        ));
                    };
                    self.begin_fake_retry(verdict)?;
                    outcome_idx = outcome_idx
                        .checked_add(1)
                        .ok_or_else(|| SessionError::Other("outcome index overflow".into()))?;
                    verdict = self.after_fake_connect(outcome)?;
                }
            }
        }
    }

    fn stop_to_result(&self, reason: ReconnectStopReason) -> FakeSshReconnectResult {
        match reason {
            ReconnectStopReason::Connected => FakeSshReconnectResult::Connected {
                attempts: self.policy.budget().attempts_consumed(),
            },
            ReconnectStopReason::UserCancel | ReconnectStopReason::Disconnected => {
                FakeSshReconnectResult::Cancelled
            }
            ReconnectStopReason::BudgetExhausted => FakeSshReconnectResult::Failed {
                reason,
                note: Some(reconnect_exhausted_note(
                    self.policy.budget().max_attempts(),
                )),
            },
            other => FakeSshReconnectResult::Failed {
                reason: other,
                note: None,
            },
        }
    }
}

impl fmt::Debug for FakeSshReconnectGlue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeSshReconnectGlue")
            .field("attempts_consumed", &self.policy.budget().attempts_consumed())
            .field("max_attempts", &self.policy.budget().max_attempts())
            .field("schedule_max", &self.schedule.max_attempts())
            .field(
                "waited_ms",
                &self
                    .waited
                    .iter()
                    .map(|d| d.as_millis())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

/// Map a Fake reconnect result onto session state (Failed keeps the reason note
/// for callers that surface [`SessionError::Other`]).
pub fn apply_fake_reconnect_result(
    result: &FakeSshReconnectResult,
) -> (SessionState, Option<SessionError>) {
    match result {
        FakeSshReconnectResult::Connected { .. } => (SessionState::Connected, None),
        FakeSshReconnectResult::Cancelled => (SessionState::Closed, None),
        FakeSshReconnectResult::Failed { note, reason } => {
            let msg = note
                .clone()
                .unwrap_or_else(|| format!("ssh reconnect stopped: {}", reason.as_str()));
            (SessionState::Failed, Some(SessionError::Other(msg)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn short_three() -> FakeSshReconnectGlue {
        FakeSshReconnectGlue::with_fake_delays([
            Duration::from_millis(1),
            Duration::from_millis(2),
            Duration::from_millis(3),
        ])
        .unwrap()
    }

    #[test]
    fn unexpected_drop_plans_retry_via_policy() {
        let mut glue = short_three();
        let v = glue
            .handle_disconnect(SshDisconnectCause::UnexpectedDrop)
            .unwrap();
        assert_eq!(
            v,
            ReconnectVerdict::Retry {
                attempt: 1,
                delay: Duration::from_millis(1)
            }
        );
        let delay = glue.begin_fake_retry(v).unwrap();
        assert_eq!(delay, Duration::from_millis(1));
        assert_eq!(glue.waited_delays(), &[Duration::from_millis(1)]);
        assert_eq!(glue.policy().budget().attempts_consumed(), 1);
    }

    #[test]
    fn user_cancel_never_reconnects_and_resets_budget() {
        let mut glue = short_three();
        // Stale budget must clear on UserCancel (C# Disconnect pairing).
        let v = glue
            .handle_disconnect(SshDisconnectCause::UnexpectedDrop)
            .unwrap();
        glue.begin_fake_retry(v).unwrap();
        assert_eq!(glue.policy().budget().attempts_consumed(), 1);

        let stop = glue
            .handle_disconnect(SshDisconnectCause::UserCancel)
            .unwrap();
        assert_eq!(
            stop,
            ReconnectVerdict::Stop {
                reason: ReconnectStopReason::UserCancel
            }
        );
        assert_eq!(glue.policy().budget().attempts_consumed(), 0);
        // No additional Fake delay recorded for cancel.
        assert_eq!(glue.waited_delays().len(), 1);
    }

    #[test]
    fn user_cancel_run_loop_does_not_consume_outcomes() {
        let mut glue = short_three();
        let result = glue
            .run_fake_loop(
                SshDisconnectCause::UserCancel,
                &[ReconnectConnectOutcome::Connected],
            )
            .unwrap();
        assert_eq!(result, FakeSshReconnectResult::Cancelled);
        assert_eq!(result.session_state(), SessionState::Closed);
        assert!(glue.waited_delays().is_empty());
        assert_eq!(glue.policy().budget().attempts_consumed(), 0);
    }

    #[test]
    fn budget_exhausted_maps_to_failed_with_note() {
        let mut glue = short_three();
        let outcomes = [
            ReconnectConnectOutcome::Failed { retryable: true },
            ReconnectConnectOutcome::Failed { retryable: true },
            ReconnectConnectOutcome::Failed { retryable: true },
        ];
        let result = glue
            .run_fake_loop(SshDisconnectCause::UnexpectedDrop, &outcomes)
            .unwrap();
        match &result {
            FakeSshReconnectResult::Failed {
                reason: ReconnectStopReason::BudgetExhausted,
                note: Some(n),
            } => {
                assert!(n.contains("3 attempts"));
            }
            other => panic!("expected BudgetExhausted Failed, got {other:?}"),
        }
        assert_eq!(result.session_state(), SessionState::Failed);
        assert_eq!(
            glue.waited_delays(),
            &[
                Duration::from_millis(1),
                Duration::from_millis(2),
                Duration::from_millis(3),
            ]
        );
        assert_eq!(glue.policy().budget().attempts_consumed(), 3);

        let (state, err) = apply_fake_reconnect_result(&result);
        assert_eq!(state, SessionState::Failed);
        let err = err.expect("Failed carries SessionError");
        assert!(err.to_string().contains("3 attempts"));
    }

    #[test]
    fn unexpected_drop_then_connect_success() {
        let mut glue = short_three();
        let result = glue
            .run_fake_loop(
                SshDisconnectCause::UnexpectedDrop,
                &[ReconnectConnectOutcome::Connected],
            )
            .unwrap();
        assert_eq!(
            result,
            FakeSshReconnectResult::Connected { attempts: 1 }
        );
        assert_eq!(result.session_state(), SessionState::Connected);
        assert_eq!(glue.waited_delays(), &[Duration::from_millis(1)]);
    }

    #[test]
    fn retryable_failures_then_success_uses_fake_schedule() {
        let mut glue = short_three();
        let result = glue
            .run_fake_loop(
                SshDisconnectCause::UnexpectedDrop,
                &[
                    ReconnectConnectOutcome::Failed { retryable: true },
                    ReconnectConnectOutcome::Connected,
                ],
            )
            .unwrap();
        assert_eq!(
            result,
            FakeSshReconnectResult::Connected { attempts: 2 }
        );
        assert_eq!(
            glue.waited_delays(),
            &[Duration::from_millis(1), Duration::from_millis(2)]
        );
    }

    #[test]
    fn non_retryable_error_fails_without_retry() {
        let mut glue = short_three();
        let result = glue
            .run_fake_loop(
                SshDisconnectCause::Error { retryable: false },
                &[ReconnectConnectOutcome::Connected],
            )
            .unwrap();
        assert_eq!(
            result,
            FakeSshReconnectResult::Failed {
                reason: ReconnectStopReason::NonRetryableError,
                note: None,
            }
        );
        assert!(glue.waited_delays().is_empty());
        assert_eq!(result.session_state(), SessionState::Failed);
    }

    #[test]
    fn mid_connect_disconnect_cancels() {
        let mut glue = short_three();
        let result = glue
            .run_fake_loop(
                SshDisconnectCause::UnexpectedDrop,
                &[ReconnectConnectOutcome::Disconnected],
            )
            .unwrap();
        assert_eq!(result, FakeSshReconnectResult::Cancelled);
        assert_eq!(glue.waited_delays(), &[Duration::from_millis(1)]);
    }

    #[test]
    fn script_exhausted_fail_closed() {
        let mut glue = short_three();
        let err = glue
            .run_fake_loop(SshDisconnectCause::UnexpectedDrop, &[])
            .unwrap_err();
        assert!(err.to_string().contains("script exhausted"));
        // Must not record a delay / consume budget when the script is empty.
        assert!(glue.waited_delays().is_empty());
        assert_eq!(glue.policy().budget().attempts_consumed(), 0);
    }

    #[test]
    fn script_exhausted_mid_loop_preserves_prior_attempts_only() {
        let mut glue = short_three();
        // One retryable failure plans attempt 2; empty remaining script must not
        // begin attempt 2 (budget stays at 1, one delay only).
        let err = glue
            .run_fake_loop(
                SshDisconnectCause::UnexpectedDrop,
                &[ReconnectConnectOutcome::Failed { retryable: true }],
            )
            .unwrap_err();
        assert!(err.to_string().contains("script exhausted"));
        assert_eq!(glue.waited_delays(), &[Duration::from_millis(1)]);
        assert_eq!(glue.policy().budget().attempts_consumed(), 1);
    }

    #[test]
    fn hostile_budget_schedule_mismatch_fail_closed() {
        let policy = SshReconnectPolicy::new(3);
        let schedule = FakeBackoffSchedule::fixed(2, Duration::from_millis(1));
        let err = FakeSshReconnectGlue::new(policy, schedule).unwrap_err();
        assert!(err.to_string().contains("does not match"));
    }

    #[test]
    fn policy_disabled_fails_closed() {
        let mut glue = FakeSshReconnectGlue::with_fake_delays(std::iter::empty::<Duration>())
            .unwrap();
        let result = glue
            .run_fake_loop(SshDisconnectCause::UnexpectedDrop, &[])
            .unwrap();
        assert_eq!(
            result,
            FakeSshReconnectResult::Failed {
                reason: ReconnectStopReason::PolicyDisabled,
                note: None,
            }
        );
        assert_eq!(result.session_state(), SessionState::Failed);
    }

    #[test]
    fn stability_elapsed_resets_budget() {
        let mut glue = short_three();
        let v = glue
            .handle_disconnect(SshDisconnectCause::UnexpectedDrop)
            .unwrap();
        glue.begin_fake_retry(v).unwrap();
        assert_eq!(glue.policy().budget().attempts_consumed(), 1);
        glue.on_stability_elapsed();
        assert_eq!(glue.policy().budget().attempts_consumed(), 0);
        let again = glue
            .handle_disconnect(SshDisconnectCause::UnexpectedDrop)
            .unwrap();
        assert_eq!(
            again,
            ReconnectVerdict::Retry {
                attempt: 1,
                delay: Duration::from_millis(1)
            }
        );
    }

    #[test]
    fn csharp_defaults_use_policy_constants() {
        let glue = FakeSshReconnectGlue::csharp_defaults();
        assert_eq!(
            glue.policy().budget().max_attempts(),
            MAX_AUTO_RECONNECT_ATTEMPTS
        );
        assert_eq!(glue.schedule().max_attempts(), MAX_AUTO_RECONNECT_ATTEMPTS);
        assert_eq!(
            glue.schedule().delay_before_attempt(1),
            Some(AUTO_RECONNECT_DELAY)
        );
    }

    #[test]
    fn debug_omits_secrets_and_hosts() {
        let mut glue = short_three();
        let v = glue
            .handle_disconnect(SshDisconnectCause::UnexpectedDrop)
            .unwrap();
        glue.begin_fake_retry(v).unwrap();
        let dbg = format!("{glue:?}");
        assert!(dbg.contains("FakeSshReconnectGlue"));
        assert!(dbg.contains("attempts_consumed"));
        assert!(!dbg.to_lowercase().contains("password"));
        assert!(!dbg.contains("127.0.0.1"));
    }

    #[test]
    fn retryable_disconnect_error_retries_like_drop() {
        let mut glue = short_three();
        let result = glue
            .run_fake_loop(
                SshDisconnectCause::Error { retryable: true },
                &[ReconnectConnectOutcome::Connected],
            )
            .unwrap();
        assert_eq!(
            result,
            FakeSshReconnectResult::Connected { attempts: 1 }
        );
    }

    #[test]
    fn connecting_outcome_fails_closed_as_not_terminal() {
        let mut glue = short_three();
        let result = glue
            .run_fake_loop(
                SshDisconnectCause::UnexpectedDrop,
                &[ReconnectConnectOutcome::Connecting],
            )
            .unwrap();
        assert_eq!(
            result,
            FakeSshReconnectResult::Failed {
                reason: ReconnectStopReason::NotTerminal,
                note: None,
            }
        );
        assert_eq!(result.session_state(), SessionState::Failed);
        assert_eq!(glue.waited_delays(), &[Duration::from_millis(1)]);
    }

    #[test]
    fn apply_non_budget_failed_uses_reason_label() {
        let failed = FakeSshReconnectResult::Failed {
            reason: ReconnectStopReason::NonRetryableError,
            note: None,
        };
        let (state, err) = apply_fake_reconnect_result(&failed);
        assert_eq!(state, SessionState::Failed);
        let err = err.expect("Failed carries SessionError");
        assert!(err.to_string().contains("non-retryable-error"));
    }

    #[test]
    fn apply_connected_and_cancelled_have_no_error() {
        let connected = FakeSshReconnectResult::Connected { attempts: 1 };
        let (state, err) = apply_fake_reconnect_result(&connected);
        assert_eq!(state, SessionState::Connected);
        assert!(err.is_none());

        let cancelled = FakeSshReconnectResult::Cancelled;
        let (state, err) = apply_fake_reconnect_result(&cancelled);
        assert_eq!(state, SessionState::Closed);
        assert!(err.is_none());
    }
}
