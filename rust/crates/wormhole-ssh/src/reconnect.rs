//! SSH auto-reconnect / backoff policy stub (pure decision glue).
//!
//! Mirrors C# `SshSessionViewModel` auto-reconnect rules:
//! - **User cancel** (Disconnect / tab close / cancel) → never auto-reconnect
//! - **Unexpected drop** of an established session → bounded retries
//! - **Error** → retry only when marked retryable (auth / host-key / notice are not)
//! - Capped attempts + delay schedule (C# uses a **fixed** 10s delay; [`FakeBackoffSchedule`]
//!   scripts arbitrary delays for unit tests)
//! - Budget resets after a stability window (timer owned by the caller), on
//!   user cancel / manual Retry ([`SshReconnectPolicy::cancel_user`] /
//!   [`SshReconnectPolicy::on_disconnect`] with [`SshDisconnectCause::UserCancel`])
//!
//! No live SSH, no GPUI, no credential fields — fail closed on hostile budget /
//! schedule inputs. Session orch Fake loop glue lives in
//! `wormhole_session::ssh_reconnect`; live UI / WebView2 rebind still Pending.

use std::fmt;
use std::time::Duration;

/// C# `MaxAutoReconnectAttempts`.
pub const MAX_AUTO_RECONNECT_ATTEMPTS: u32 = 3;

/// C# `AutoReconnectDelay` (fixed, not escalating).
pub const AUTO_RECONNECT_DELAY: Duration = Duration::from_secs(10);

/// C# `AutoReconnectStabilityWindow` — caller owns the timer; this constant is
/// the documented default only.
pub const AUTO_RECONNECT_STABILITY_WINDOW: Duration = Duration::from_secs(30);

/// Why a session left Connected / a connect attempt ended (no secrets).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SshDisconnectCause {
    /// Explicit user Disconnect / tab close / cancel mid-connect.
    UserCancel,
    /// Unexpected drop of an already-established session (host reboot, network blip).
    UnexpectedDrop,
    /// Connect / session failure. `retryable` mirrors C# `_lastConnectRetryable`
    /// (network / endpoint unreachable = true; auth / host-key / notice = false).
    Error {
        retryable: bool,
    },
}

impl SshDisconnectCause {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UserCancel => "user-cancel",
            Self::UnexpectedDrop => "unexpected-drop",
            Self::Error { retryable: true } => "error-retryable",
            Self::Error { retryable: false } => "error-non-retryable",
        }
    }
}

/// Terminal outcome of one reconnect connect attempt (C# `SessionStatus` + retryable flag).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReconnectConnectOutcome {
    /// Connect succeeded — stop the loop (stability timer may later reset budget).
    Connected,
    /// Cancel-driven disconnect mid-connect — stop.
    Disconnected,
    /// Defensive: not a terminal outcome — stop (do not treat as retryable failure).
    Connecting,
    /// Failed overlay; only [`Self::Failed`] with `retryable: true` continues.
    Failed {
        retryable: bool,
    },
}

/// Why auto-reconnect will **not** schedule another attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReconnectStopReason {
    UserCancel,
    NonRetryableError,
    /// Attempts already at / past the schedule cap.
    BudgetExhausted,
    /// Connect succeeded.
    Connected,
    /// Mid-connect cancel landed as Disconnected.
    Disconnected,
    /// Non-terminal / defensive outcome.
    NotTerminal,
    /// Schedule reports zero max attempts (policy off) — fail closed, never retry.
    PolicyDisabled,
}

impl ReconnectStopReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UserCancel => "user-cancel",
            Self::NonRetryableError => "non-retryable-error",
            Self::BudgetExhausted => "budget-exhausted",
            Self::Connected => "connected",
            Self::Disconnected => "disconnected",
            Self::NotTerminal => "not-terminal",
            Self::PolicyDisabled => "policy-disabled",
        }
    }
}

/// Auto-reconnect decision after a disconnect or connect attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconnectVerdict {
    Stop {
        reason: ReconnectStopReason,
    },
    /// Schedule 1-based `attempt` after `delay` (budget not yet incremented — caller
    /// records the attempt when the wait begins, matching C# `SetAutoReconnectAttempts`).
    Retry {
        attempt: u32,
        delay: Duration,
    },
}

/// Hostile / inconsistent policy input — fail closed (never [`ReconnectVerdict::Retry`]).
#[derive(Clone, PartialEq, Eq)]
pub struct ReconnectPolicyError {
    message: &'static str,
}

impl ReconnectPolicyError {
    pub const fn new(message: &'static str) -> Self {
        Self { message }
    }

    pub const fn message(&self) -> &'static str {
        self.message
    }
}

impl fmt::Debug for ReconnectPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReconnectPolicyError")
            .field("message", &self.message)
            .finish()
    }
}

impl fmt::Display for ReconnectPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message)
    }
}

impl std::error::Error for ReconnectPolicyError {}

/// Delay schedule for reconnect attempts (1-based attempt index).
///
/// Production default is [`FixedBackoffSchedule`] (C# fixed 10s). Unit tests use
/// [`FakeBackoffSchedule`] (scripted delays; no wall clock).
pub trait BackoffSchedule {
    /// Maximum attempts this schedule will ever authorize (`0` = policy disabled).
    fn max_attempts(&self) -> u32;

    /// Delay **before** starting `attempt` (1-based), or `None` if that attempt is
    /// not authorized. Implementations must not return `Some` when
    /// `attempt == 0` or `attempt > max_attempts()`.
    fn delay_before_attempt(&self, attempt: u32) -> Option<Duration>;
}

/// C# parity: fixed delay between attempts (not exponential).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedBackoffSchedule {
    delay: Duration,
    max_attempts: u32,
}

impl FixedBackoffSchedule {
    /// C# defaults: 3 attempts, 10s apart.
    pub const fn csharp_defaults() -> Self {
        Self {
            delay: AUTO_RECONNECT_DELAY,
            max_attempts: MAX_AUTO_RECONNECT_ATTEMPTS,
        }
    }

    pub const fn new(delay: Duration, max_attempts: u32) -> Self {
        Self {
            delay,
            max_attempts,
        }
    }
}

impl BackoffSchedule for FixedBackoffSchedule {
    fn max_attempts(&self) -> u32 {
        self.max_attempts
    }

    fn delay_before_attempt(&self, attempt: u32) -> Option<Duration> {
        if attempt == 0 || attempt > self.max_attempts {
            return None;
        }
        Some(self.delay)
    }
}

/// Scripted backoff for unit tests (no live timer / no SSH).
///
/// `delays[i]` is the wait before attempt `i + 1`. An empty vec is policy-disabled
/// (`max_attempts == 0`). Missing entries beyond `len` exhaust the budget.
#[derive(Clone, PartialEq, Eq)]
pub struct FakeBackoffSchedule {
    delays: Vec<Duration>,
}

impl FakeBackoffSchedule {
    pub fn new(delays: impl IntoIterator<Item = Duration>) -> Self {
        Self {
            delays: delays.into_iter().collect(),
        }
    }

    /// Convenience: `n` attempts with the same delay (still a Fake for tests).
    pub fn fixed(n: usize, delay: Duration) -> Self {
        Self {
            delays: vec![delay; n],
        }
    }

    pub fn delays(&self) -> &[Duration] {
        &self.delays
    }
}

impl fmt::Debug for FakeBackoffSchedule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeBackoffSchedule")
            .field("max_attempts", &self.delays.len())
            .field("delays_ms", &self.delays.iter().map(|d| d.as_millis()).collect::<Vec<_>>())
            .finish()
    }
}

impl BackoffSchedule for FakeBackoffSchedule {
    fn max_attempts(&self) -> u32 {
        u32::try_from(self.delays.len()).unwrap_or(u32::MAX)
    }

    fn delay_before_attempt(&self, attempt: u32) -> Option<Duration> {
        if attempt == 0 {
            return None;
        }
        let idx = usize::try_from(attempt - 1).ok()?;
        self.delays.get(idx).copied()
    }
}

/// Consumed auto-reconnect attempt counter (C# `_autoReconnectAttempts`).
///
/// Does **not** sleep — callers apply [`ReconnectVerdict::Retry::delay`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshReconnectBudget {
    attempts_consumed: u32,
    max_attempts: u32,
}

impl SshReconnectBudget {
    /// Build a budget capped at `max_attempts`. `0` is allowed (policy off) but
    /// [`decide_after_disconnect`] / [`plan_next_attempt`] then stop closed.
    pub fn new(max_attempts: u32) -> Self {
        Self {
            attempts_consumed: 0,
            max_attempts,
        }
    }

    pub fn with_consumed(max_attempts: u32, attempts_consumed: u32) -> Result<Self, ReconnectPolicyError> {
        if attempts_consumed > max_attempts {
            return Err(ReconnectPolicyError::new(
                "attempts_consumed exceeds max_attempts",
            ));
        }
        Ok(Self {
            attempts_consumed,
            max_attempts,
        })
    }

    pub fn attempts_consumed(&self) -> u32 {
        self.attempts_consumed
    }

    pub fn max_attempts(&self) -> u32 {
        self.max_attempts
    }

    pub fn is_exhausted(&self) -> bool {
        self.attempts_consumed >= self.max_attempts
    }

    /// Record that a Retry wait/connect is starting (C# `SetAutoReconnectAttempts(+1)`).
    pub fn record_attempt(&mut self) -> Result<u32, ReconnectPolicyError> {
        if self.attempts_consumed >= self.max_attempts {
            return Err(ReconnectPolicyError::new("reconnect budget exhausted"));
        }
        self.attempts_consumed = self
            .attempts_consumed
            .checked_add(1)
            .ok_or_else(|| ReconnectPolicyError::new("attempt counter overflow"))?;
        Ok(self.attempts_consumed)
    }

    /// Clear consumed attempts (manual Retry, or stability window elapsed).
    pub fn reset(&mut self) {
        self.attempts_consumed = 0;
    }
}

fn validate_schedule(schedule: &dyn BackoffSchedule) -> Result<(), ReconnectPolicyError> {
    let max = schedule.max_attempts();
    if max == 0 {
        return Ok(()); // policy disabled — callers Stop(PolicyDisabled)
    }
    // Spot-check attempt 1 exists; hostile Fakes that lie about max fail closed here.
    match schedule.delay_before_attempt(1) {
        Some(_) => Ok(()),
        None => Err(ReconnectPolicyError::new(
            "backoff schedule max_attempts > 0 but attempt 1 has no delay",
        )),
    }
}

fn validate_budget_vs_schedule(
    budget: &SshReconnectBudget,
    schedule: &dyn BackoffSchedule,
) -> Result<(), ReconnectPolicyError> {
    validate_schedule(schedule)?;
    if budget.max_attempts() != schedule.max_attempts() {
        return Err(ReconnectPolicyError::new(
            "budget max_attempts does not match backoff schedule",
        ));
    }
    if budget.attempts_consumed() > budget.max_attempts() {
        return Err(ReconnectPolicyError::new(
            "attempts_consumed exceeds max_attempts",
        ));
    }
    Ok(())
}

/// Plan the next reconnect attempt from `attempts_consumed` (before increment).
///
/// Returns [`ReconnectVerdict::Retry`] with 1-based `attempt = consumed + 1` and the
/// schedule delay, or Stop when the budget / schedule is exhausted or disabled.
pub fn plan_next_attempt(
    budget: &SshReconnectBudget,
    schedule: &dyn BackoffSchedule,
) -> Result<ReconnectVerdict, ReconnectPolicyError> {
    validate_budget_vs_schedule(budget, schedule)?;
    let max = schedule.max_attempts();
    if max == 0 {
        return Ok(ReconnectVerdict::Stop {
            reason: ReconnectStopReason::PolicyDisabled,
        });
    }
    if budget.is_exhausted() {
        return Ok(ReconnectVerdict::Stop {
            reason: ReconnectStopReason::BudgetExhausted,
        });
    }
    let attempt = budget
        .attempts_consumed()
        .checked_add(1)
        .ok_or_else(|| ReconnectPolicyError::new("attempt counter overflow"))?;
    let Some(delay) = schedule.delay_before_attempt(attempt) else {
        return Ok(ReconnectVerdict::Stop {
            reason: ReconnectStopReason::BudgetExhausted,
        });
    };
    Ok(ReconnectVerdict::Retry { attempt, delay })
}

/// Decide whether to auto-reconnect after a disconnect / failure.
///
/// | Cause | Verdict |
/// |---|---|
/// | [`SshDisconnectCause::UserCancel`] | Stop (never retry) |
/// | [`SshDisconnectCause::Error`] `{ retryable: false }` | Stop |
/// | Unexpected drop / retryable error | [`plan_next_attempt`] |
pub fn decide_after_disconnect(
    cause: SshDisconnectCause,
    budget: &SshReconnectBudget,
    schedule: &dyn BackoffSchedule,
) -> Result<ReconnectVerdict, ReconnectPolicyError> {
    match cause {
        SshDisconnectCause::UserCancel => Ok(ReconnectVerdict::Stop {
            reason: ReconnectStopReason::UserCancel,
        }),
        SshDisconnectCause::Error { retryable: false } => Ok(ReconnectVerdict::Stop {
            reason: ReconnectStopReason::NonRetryableError,
        }),
        SshDisconnectCause::UnexpectedDrop | SshDisconnectCause::Error { retryable: true } => {
            plan_next_attempt(budget, schedule)
        }
    }
}

/// C# `ShouldContinueAutoReconnect` — pure continue/stop after a reconnect connect.
///
/// Only `Failed { retryable: true }` continues; budget exhaustion is decided by
/// [`plan_next_attempt`] / [`decide_after_connect_attempt`], not this helper.
pub fn should_continue_auto_reconnect(
    outcome: ReconnectConnectOutcome,
) -> bool {
    matches!(
        outcome,
        ReconnectConnectOutcome::Failed { retryable: true }
    )
}

/// After a reconnect connect attempt: continue with next delay, or stop.
///
/// Does **not** mutate `budget` — caller calls [`SshReconnectBudget::record_attempt`]
/// when accepting a Retry (mirrors C# loop increment-before-delay).
pub fn decide_after_connect_attempt(
    outcome: ReconnectConnectOutcome,
    budget: &SshReconnectBudget,
    schedule: &dyn BackoffSchedule,
) -> Result<ReconnectVerdict, ReconnectPolicyError> {
    match outcome {
        ReconnectConnectOutcome::Failed { retryable: true } => {
            plan_next_attempt(budget, schedule)
        }
        ReconnectConnectOutcome::Connected => Ok(ReconnectVerdict::Stop {
            reason: ReconnectStopReason::Connected,
        }),
        ReconnectConnectOutcome::Disconnected => Ok(ReconnectVerdict::Stop {
            reason: ReconnectStopReason::Disconnected,
        }),
        ReconnectConnectOutcome::Connecting => Ok(ReconnectVerdict::Stop {
            reason: ReconnectStopReason::NotTerminal,
        }),
        ReconnectConnectOutcome::Failed { retryable: false } => Ok(ReconnectVerdict::Stop {
            reason: ReconnectStopReason::NonRetryableError,
        }),
    }
}

/// Shared exhaustion note (C# `ReconnectExhaustedNote`) — no host / secrets.
pub fn reconnect_exhausted_note(max_attempts: u32) -> String {
    format!("Reconnection failed after {max_attempts} attempts.")
}

/// Thin stateful glue over [`SshReconnectBudget`] (Fake/Fixed schedule injected per call).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshReconnectPolicy {
    budget: SshReconnectBudget,
}

impl SshReconnectPolicy {
    pub fn new(max_attempts: u32) -> Self {
        Self {
            budget: SshReconnectBudget::new(max_attempts),
        }
    }

    /// C# defaults (3 attempts). Pair with [`FixedBackoffSchedule::csharp_defaults`].
    pub fn csharp_defaults() -> Self {
        Self::new(MAX_AUTO_RECONNECT_ATTEMPTS)
    }

    pub fn budget(&self) -> &SshReconnectBudget {
        &self.budget
    }

    pub fn budget_mut(&mut self) -> &mut SshReconnectBudget {
        &mut self.budget
    }

    /// User Disconnect / Retry / tab close — clear consumed attempts (C# `CancelAutoReconnect`
    /// + attempt reset on manual Retry). Prefer [`Self::on_disconnect`] with
    /// [`SshDisconnectCause::UserCancel`], which also resets; this remains for
    /// cancel-without-decide (e.g. manual Retry starting a fresh budget).
    pub fn cancel_user(&mut self) {
        self.budget.reset();
    }

    /// Stability window elapsed while still Connected — restore full retry budget.
    pub fn on_stability_elapsed(&mut self) {
        self.budget.reset();
    }

    /// Decide after disconnect. **[`SshDisconnectCause::UserCancel`] resets the
    /// budget** (C# Disconnect pairs cancel + attempt clear); other causes leave
    /// consumed attempts intact. Pure [`decide_after_disconnect`] never mutates.
    pub fn on_disconnect(
        &mut self,
        cause: SshDisconnectCause,
        schedule: &dyn BackoffSchedule,
    ) -> Result<ReconnectVerdict, ReconnectPolicyError> {
        if matches!(cause, SshDisconnectCause::UserCancel) {
            self.cancel_user();
        }
        decide_after_disconnect(cause, &self.budget, schedule)
    }

    /// Accept a Retry: record the attempt and return the same verdict's delay.
    ///
    /// Validates `attempt == attempts_consumed + 1` **before** mutating so a
    /// stale/hostile verdict never leaves a half-applied counter.
    pub fn begin_retry(
        &mut self,
        verdict: ReconnectVerdict,
    ) -> Result<Duration, ReconnectPolicyError> {
        let ReconnectVerdict::Retry { attempt, delay } = verdict else {
            return Err(ReconnectPolicyError::new(
                "begin_retry requires ReconnectVerdict::Retry",
            ));
        };
        let expected = self
            .budget
            .attempts_consumed()
            .checked_add(1)
            .ok_or_else(|| ReconnectPolicyError::new("attempt counter overflow"))?;
        if attempt != expected {
            return Err(ReconnectPolicyError::new(
                "begin_retry attempt does not match next budget slot",
            ));
        }
        // Pre-check guarantees the next slot; record_attempt either increments to
        // `attempt` or fails closed without mutating.
        let recorded = self.budget.record_attempt()?;
        debug_assert_eq!(recorded, attempt);
        Ok(delay)
    }

    pub fn on_connect_attempt(
        &self,
        outcome: ReconnectConnectOutcome,
        schedule: &dyn BackoffSchedule,
    ) -> Result<ReconnectVerdict, ReconnectPolicyError> {
        decide_after_connect_attempt(outcome, &self.budget, schedule)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_three() -> FakeBackoffSchedule {
        FakeBackoffSchedule::fixed(3, Duration::from_millis(5))
    }

    #[test]
    fn user_cancel_never_retries() {
        let mut policy = SshReconnectPolicy::csharp_defaults();
        let v = policy
            .on_disconnect(SshDisconnectCause::UserCancel, &fake_three())
            .unwrap();
        assert_eq!(
            v,
            ReconnectVerdict::Stop {
                reason: ReconnectStopReason::UserCancel
            }
        );
    }

    #[test]
    fn user_cancel_resets_stale_budget_on_policy() {
        // C# Disconnect clears attempts; calling only on_disconnect(UserCancel)
        // must not leave a stale consumed counter for a later drop.
        let mut policy = SshReconnectPolicy::csharp_defaults();
        let schedule = fake_three();
        let v = policy
            .on_disconnect(SshDisconnectCause::UnexpectedDrop, &schedule)
            .unwrap();
        policy.begin_retry(v).unwrap();
        assert_eq!(policy.budget().attempts_consumed(), 1);
        let stop = policy
            .on_disconnect(SshDisconnectCause::UserCancel, &schedule)
            .unwrap();
        assert_eq!(
            stop,
            ReconnectVerdict::Stop {
                reason: ReconnectStopReason::UserCancel
            }
        );
        assert_eq!(policy.budget().attempts_consumed(), 0);
        let again = policy
            .on_disconnect(SshDisconnectCause::UnexpectedDrop, &schedule)
            .unwrap();
        assert_eq!(
            again,
            ReconnectVerdict::Retry {
                attempt: 1,
                delay: Duration::from_millis(5)
            }
        );
    }

    #[test]
    fn pure_user_cancel_decide_does_not_mutate_budget() {
        let budget = SshReconnectBudget::with_consumed(3, 2).unwrap();
        let schedule = fake_three();
        let v = decide_after_disconnect(
            SshDisconnectCause::UserCancel,
            &budget,
            &schedule,
        )
        .unwrap();
        assert_eq!(
            v,
            ReconnectVerdict::Stop {
                reason: ReconnectStopReason::UserCancel
            }
        );
        assert_eq!(budget.attempts_consumed(), 2);
    }

    #[test]
    fn unexpected_drop_plans_first_attempt() {
        let mut policy = SshReconnectPolicy::csharp_defaults();
        let schedule = fake_three();
        let v = policy
            .on_disconnect(SshDisconnectCause::UnexpectedDrop, &schedule)
            .unwrap();
        assert_eq!(
            v,
            ReconnectVerdict::Retry {
                attempt: 1,
                delay: Duration::from_millis(5)
            }
        );
    }

    #[test]
    fn non_retryable_error_stops() {
        let mut policy = SshReconnectPolicy::csharp_defaults();
        let v = policy
            .on_disconnect(
                SshDisconnectCause::Error { retryable: false },
                &fake_three(),
            )
            .unwrap();
        assert_eq!(
            v,
            ReconnectVerdict::Stop {
                reason: ReconnectStopReason::NonRetryableError
            }
        );
    }

    #[test]
    fn non_retryable_error_preserves_consumed_budget() {
        let mut policy = SshReconnectPolicy::csharp_defaults();
        let schedule = fake_three();
        let v = policy
            .on_disconnect(SshDisconnectCause::UnexpectedDrop, &schedule)
            .unwrap();
        policy.begin_retry(v).unwrap();
        assert_eq!(policy.budget().attempts_consumed(), 1);
        let _ = policy
            .on_disconnect(
                SshDisconnectCause::Error { retryable: false },
                &schedule,
            )
            .unwrap();
        assert_eq!(policy.budget().attempts_consumed(), 1);
    }

    #[test]
    fn retryable_error_plans_retry() {
        let mut policy = SshReconnectPolicy::csharp_defaults();
        let v = policy
            .on_disconnect(
                SshDisconnectCause::Error { retryable: true },
                &fake_three(),
            )
            .unwrap();
        assert!(matches!(v, ReconnectVerdict::Retry { attempt: 1, .. }));
    }

    #[test]
    fn budget_exhaustion_after_three_attempts() {
        let mut policy = SshReconnectPolicy::csharp_defaults();
        let schedule = fake_three();

        for expected in 1..=3 {
            let v = policy
                .on_disconnect(SshDisconnectCause::UnexpectedDrop, &schedule)
                .unwrap();
            let ReconnectVerdict::Retry { attempt, delay } = v else {
                panic!("expected Retry on attempt {expected}");
            };
            assert_eq!(attempt, expected);
            assert_eq!(delay, Duration::from_millis(5));
            policy.begin_retry(v).unwrap();
            // Transient failure → loop continues
            let cont = policy
                .on_connect_attempt(
                    ReconnectConnectOutcome::Failed { retryable: true },
                    &schedule,
                )
                .unwrap();
            if expected < 3 {
                assert!(matches!(cont, ReconnectVerdict::Retry { .. }));
            } else {
                assert_eq!(
                    cont,
                    ReconnectVerdict::Stop {
                        reason: ReconnectStopReason::BudgetExhausted
                    }
                );
            }
        }

        let drop_again = policy
            .on_disconnect(SshDisconnectCause::UnexpectedDrop, &schedule)
            .unwrap();
        assert_eq!(
            drop_again,
            ReconnectVerdict::Stop {
                reason: ReconnectStopReason::BudgetExhausted
            }
        );
        assert!(reconnect_exhausted_note(3).contains("3 attempts"));
    }

    #[test]
    fn should_continue_only_on_transient_failure() {
        assert!(should_continue_auto_reconnect(
            ReconnectConnectOutcome::Failed { retryable: true }
        ));
        assert!(!should_continue_auto_reconnect(
            ReconnectConnectOutcome::Failed { retryable: false }
        ));
        assert!(!should_continue_auto_reconnect(
            ReconnectConnectOutcome::Connected
        ));
        assert!(!should_continue_auto_reconnect(
            ReconnectConnectOutcome::Disconnected
        ));
        assert!(!should_continue_auto_reconnect(
            ReconnectConnectOutcome::Connecting
        ));
    }

    #[test]
    fn connect_success_and_user_disconnect_stop_loop() {
        let policy = SshReconnectPolicy::csharp_defaults();
        let schedule = fake_three();
        assert_eq!(
            policy
                .on_connect_attempt(ReconnectConnectOutcome::Connected, &schedule)
                .unwrap(),
            ReconnectVerdict::Stop {
                reason: ReconnectStopReason::Connected
            }
        );
        assert_eq!(
            policy
                .on_connect_attempt(ReconnectConnectOutcome::Disconnected, &schedule)
                .unwrap(),
            ReconnectVerdict::Stop {
                reason: ReconnectStopReason::Disconnected
            }
        );
    }

    #[test]
    fn connect_non_retryable_and_connecting_stop_with_reasons() {
        let policy = SshReconnectPolicy::csharp_defaults();
        let schedule = fake_three();
        assert_eq!(
            policy
                .on_connect_attempt(
                    ReconnectConnectOutcome::Failed { retryable: false },
                    &schedule,
                )
                .unwrap(),
            ReconnectVerdict::Stop {
                reason: ReconnectStopReason::NonRetryableError
            }
        );
        assert_eq!(
            policy
                .on_connect_attempt(ReconnectConnectOutcome::Connecting, &schedule)
                .unwrap(),
            ReconnectVerdict::Stop {
                reason: ReconnectStopReason::NotTerminal
            }
        );
    }

    #[test]
    fn record_attempt_when_exhausted_fails_closed() {
        let mut budget = SshReconnectBudget::with_consumed(3, 3).unwrap();
        let err = budget.record_attempt().unwrap_err();
        assert_eq!(err.message(), "reconnect budget exhausted");
        assert_eq!(budget.attempts_consumed(), 3);
    }

    #[test]
    fn begin_retry_rejects_stale_attempt_mismatch() {
        let mut policy = SshReconnectPolicy::csharp_defaults();
        let stale = ReconnectVerdict::Retry {
            attempt: 2,
            delay: Duration::from_millis(5),
        };
        let err = policy.begin_retry(stale).unwrap_err();
        assert_eq!(
            err.message(),
            "begin_retry attempt does not match next budget slot"
        );
        // Must not partially consume on Err (atomic fail-closed).
        assert_eq!(policy.budget().attempts_consumed(), 0);
    }

    #[test]
    fn cancel_user_resets_budget() {
        let mut policy = SshReconnectPolicy::csharp_defaults();
        let schedule = fake_three();
        let v = policy
            .on_disconnect(SshDisconnectCause::UnexpectedDrop, &schedule)
            .unwrap();
        policy.begin_retry(v).unwrap();
        assert_eq!(policy.budget().attempts_consumed(), 1);
        policy.cancel_user();
        assert_eq!(policy.budget().attempts_consumed(), 0);
    }

    #[test]
    fn stability_elapsed_resets_budget() {
        let mut policy = SshReconnectPolicy::csharp_defaults();
        let schedule = fake_three();
        let v = policy
            .on_disconnect(SshDisconnectCause::UnexpectedDrop, &schedule)
            .unwrap();
        policy.begin_retry(v).unwrap();
        policy.on_stability_elapsed();
        assert_eq!(policy.budget().attempts_consumed(), 0);
        let again = policy
            .on_disconnect(SshDisconnectCause::UnexpectedDrop, &schedule)
            .unwrap();
        assert_eq!(
            again,
            ReconnectVerdict::Retry {
                attempt: 1,
                delay: Duration::from_millis(5)
            }
        );
    }

    #[test]
    fn fixed_csharp_defaults_match_constants() {
        let schedule = FixedBackoffSchedule::csharp_defaults();
        assert_eq!(schedule.max_attempts(), MAX_AUTO_RECONNECT_ATTEMPTS);
        assert_eq!(
            schedule.delay_before_attempt(1),
            Some(AUTO_RECONNECT_DELAY)
        );
        assert_eq!(schedule.delay_before_attempt(3), Some(AUTO_RECONNECT_DELAY));
        assert_eq!(schedule.delay_before_attempt(4), None);
        assert_eq!(schedule.delay_before_attempt(0), None);
    }

    #[test]
    fn fake_schedule_scripts_escalating_delays() {
        let schedule = FakeBackoffSchedule::new([
            Duration::from_millis(1),
            Duration::from_millis(10),
            Duration::from_millis(100),
        ]);
        let budget = SshReconnectBudget::new(3);
        let v = plan_next_attempt(&budget, &schedule).unwrap();
        assert_eq!(
            v,
            ReconnectVerdict::Retry {
                attempt: 1,
                delay: Duration::from_millis(1)
            }
        );
        let mut budget = budget;
        budget.record_attempt().unwrap();
        let v2 = plan_next_attempt(&budget, &schedule).unwrap();
        assert_eq!(
            v2,
            ReconnectVerdict::Retry {
                attempt: 2,
                delay: Duration::from_millis(10)
            }
        );
    }

    #[test]
    fn zero_max_attempts_policy_disabled() {
        let budget = SshReconnectBudget::new(0);
        let schedule = FakeBackoffSchedule::new([]);
        let v = decide_after_disconnect(
            SshDisconnectCause::UnexpectedDrop,
            &budget,
            &schedule,
        )
        .unwrap();
        assert_eq!(
            v,
            ReconnectVerdict::Stop {
                reason: ReconnectStopReason::PolicyDisabled
            }
        );
    }

    #[test]
    fn hostile_consumed_exceeds_max_fails_closed() {
        let err = SshReconnectBudget::with_consumed(3, 4).unwrap_err();
        assert_eq!(err.message(), "attempts_consumed exceeds max_attempts");
    }

    #[test]
    fn hostile_budget_schedule_mismatch_fails_closed() {
        let budget = SshReconnectBudget::new(3);
        let schedule = FakeBackoffSchedule::fixed(2, Duration::from_millis(1));
        let err = decide_after_disconnect(
            SshDisconnectCause::UnexpectedDrop,
            &budget,
            &schedule,
        )
        .unwrap_err();
        assert_eq!(
            err.message(),
            "budget max_attempts does not match backoff schedule"
        );
    }

    #[test]
    fn hostile_lying_schedule_fails_closed() {
        struct LyingSchedule;
        impl BackoffSchedule for LyingSchedule {
            fn max_attempts(&self) -> u32 {
                3
            }
            fn delay_before_attempt(&self, _attempt: u32) -> Option<Duration> {
                None
            }
        }
        let budget = SshReconnectBudget::new(3);
        let err = plan_next_attempt(&budget, &LyingSchedule).unwrap_err();
        assert_eq!(
            err.message(),
            "backoff schedule max_attempts > 0 but attempt 1 has no delay"
        );
    }

    #[test]
    fn begin_retry_rejects_stop_verdict() {
        let mut policy = SshReconnectPolicy::csharp_defaults();
        let schedule = fake_three();
        let v = policy
            .on_disconnect(SshDisconnectCause::UnexpectedDrop, &schedule)
            .unwrap();
        policy.begin_retry(v).unwrap();
        assert_eq!(policy.budget().attempts_consumed(), 1);
        let err = policy
            .begin_retry(ReconnectVerdict::Stop {
                reason: ReconnectStopReason::UserCancel,
            })
            .unwrap_err();
        assert_eq!(err.message(), "begin_retry requires ReconnectVerdict::Retry");
        assert_eq!(policy.budget().attempts_consumed(), 1);
    }

    #[test]
    fn debug_has_no_credential_shaped_fields() {
        let cause = SshDisconnectCause::Error { retryable: false };
        let dbg = format!("{cause:?}");
        assert!(!dbg.to_lowercase().contains("password"));
        assert!(!dbg.to_lowercase().contains("secret"));
        assert!(!dbg.contains("ssh-rsa"));

        let fake = FakeBackoffSchedule::fixed(2, Duration::from_secs(1));
        let dbg = format!("{fake:?}");
        assert!(dbg.contains("FakeBackoffSchedule"));
        assert!(!dbg.to_lowercase().contains("password"));

        let err = ReconnectPolicyError::new("attempts_consumed exceeds max_attempts");
        let dbg = format!("{err:?}");
        assert!(dbg.contains("ReconnectPolicyError"));
        assert!(!dbg.to_lowercase().contains("password"));
    }

    #[test]
    fn disconnect_cause_labels_are_stable() {
        assert_eq!(SshDisconnectCause::UserCancel.as_str(), "user-cancel");
        assert_eq!(
            SshDisconnectCause::UnexpectedDrop.as_str(),
            "unexpected-drop"
        );
        assert_eq!(
            SshDisconnectCause::Error { retryable: true }.as_str(),
            "error-retryable"
        );
        assert_eq!(
            SshDisconnectCause::Error { retryable: false }.as_str(),
            "error-non-retryable"
        );
    }

    #[test]
    fn stop_reason_labels_are_stable() {
        assert_eq!(ReconnectStopReason::UserCancel.as_str(), "user-cancel");
        assert_eq!(
            ReconnectStopReason::NonRetryableError.as_str(),
            "non-retryable-error"
        );
        assert_eq!(
            ReconnectStopReason::BudgetExhausted.as_str(),
            "budget-exhausted"
        );
        assert_eq!(ReconnectStopReason::Connected.as_str(), "connected");
        assert_eq!(ReconnectStopReason::Disconnected.as_str(), "disconnected");
        assert_eq!(ReconnectStopReason::NotTerminal.as_str(), "not-terminal");
        assert_eq!(
            ReconnectStopReason::PolicyDisabled.as_str(),
            "policy-disabled"
        );
    }
}
