//! Thin soak start / cancel / status / report glue.
//!
//! Drives the existing [`crate::soak`] helpers on a caller-supplied clock so
//! unit tests can complete a planned multi-hour session with a [`FakeClock`]
//! (no real sleep). Not a live GPUI/session harness.

use std::cell::Cell;
use std::rc::Rc;
use std::time::Duration;

use crate::soak::{quad_pane_layout_stress, MAX_PANES, SOAK_SESSION_HOURS};

/// Default stress cycles executed on each [`SoakRunner::poll`] while running.
const DEFAULT_STRESS_BATCH: usize = 1;

/// Monotonic instant used for soak deadlines (arbitrary origin).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MonoInstant(Duration);

impl MonoInstant {
    /// Origin / test epoch.
    pub const ZERO: Self = Self(Duration::ZERO);

    /// Construct from a duration since an arbitrary origin.
    pub const fn from_duration(d: Duration) -> Self {
        Self(d)
    }

    /// Elapsed duration since the arbitrary origin.
    pub const fn as_duration(self) -> Duration {
        self.0
    }

    /// Saturating add (deadline = started + planned).
    pub fn saturating_add(self, delay: Duration) -> Self {
        Self(self.0.saturating_add(delay))
    }
}

/// Injected monotonic clock (production: wall/`Instant`; tests: [`FakeClock`]).
pub trait SoakClock {
    /// Current monotonic time.
    fn now(&self) -> MonoInstant;
}

/// Process-relative wall clock backed by [`std::time::Instant`].
#[derive(Debug, Clone)]
pub struct SystemClock {
    epoch: std::time::Instant,
}

impl SystemClock {
    /// Capture `Instant::now()` as the soak epoch.
    pub fn new() -> Self {
        Self {
            epoch: std::time::Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl SoakClock for SystemClock {
    fn now(&self) -> MonoInstant {
        MonoInstant::from_duration(self.epoch.elapsed())
    }
}

/// Controllable clock for deterministic soak unit tests (no real multi-hour wait).
#[derive(Debug, Clone)]
pub struct FakeClock {
    now: Rc<Cell<Duration>>,
}

impl FakeClock {
    /// Start at [`MonoInstant::ZERO`].
    pub fn new() -> Self {
        Self {
            now: Rc::new(Cell::new(Duration::ZERO)),
        }
    }

    /// Advance the fake timeline (saturating).
    pub fn advance(&self, delta: Duration) {
        let next = self.now.get().saturating_add(delta);
        self.now.set(next);
    }

    /// Jump forward to an absolute duration since the fake epoch.
    ///
    /// Never rewinds: a target earlier than the current instant is ignored so
    /// the clock stays monotonic (avoids soak `elapsed` shrinking mid-run).
    pub fn set(&self, at: Duration) {
        self.now.set(self.now.get().max(at));
    }
}

impl Default for FakeClock {
    fn default() -> Self {
        Self::new()
    }
}

impl SoakClock for FakeClock {
    fn now(&self) -> MonoInstant {
        MonoInstant::from_duration(self.now.get())
    }
}

/// Lifecycle phase of a soak run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SoakPhase {
    /// No run in progress; ready to [`SoakRunner::start`].
    Idle,
    /// Started; waiting for planned duration (or cancel).
    Running,
    /// Planned duration elapsed (via [`SoakRunner::poll`]).
    Completed,
    /// Stopped early via [`SoakRunner::cancel`].
    Cancelled,
}

/// Start / cancel / state-transition errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoakError {
    /// [`SoakRunner::start`] while already [`SoakPhase::Running`].
    AlreadyRunning,
    /// [`SoakRunner::cancel`] when not [`SoakPhase::Running`].
    NotRunning,
}

impl std::fmt::Display for SoakError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyRunning => write!(f, "soak already running"),
            Self::NotRunning => write!(f, "soak is not running"),
        }
    }
}

impl std::error::Error for SoakError {}

/// Point-in-time soak status (secrets-free).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoakStatus {
    pub phase: SoakPhase,
    /// Configured planned duration for this runner.
    pub planned: Duration,
    /// Elapsed time in the current/last run (zero when idle never started).
    pub elapsed: Duration,
    /// Cumulative [`quad_pane_layout_stress`] cycles completed this run.
    pub stress_cycles: usize,
    /// Pane hard-cap exercised by the stress helper.
    pub max_panes: usize,
}

/// Secrets-free soak summary suitable for paste / logs (no hosts, creds, paths).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoakReport {
    pub phase: SoakPhase,
    pub planned_hours: u64,
    pub elapsed_secs: u64,
    pub stress_cycles: usize,
    pub max_panes: usize,
}

impl SoakReport {
    /// Plain-text report; never includes connection or secret material.
    pub fn format(&self) -> String {
        format!(
            "=== Wormhole soak report (no secrets) ===\n\
             phase: {:?}\n\
             planned_hours: {}\n\
             elapsed_secs: {}\n\
             stress_cycles: {}\n\
             max_panes: {}\n\
             === end soak report ===\n",
            self.phase,
            self.planned_hours,
            self.elapsed_secs,
            self.stress_cycles,
            self.max_panes
        )
    }
}

/// Glue runner: start / cancel / poll / status / report over soak helpers.
#[derive(Debug)]
pub struct SoakRunner<C: SoakClock> {
    clock: C,
    planned: Duration,
    phase: SoakPhase,
    started_at: Option<MonoInstant>,
    ended_at: Option<MonoInstant>,
    stress_cycles: usize,
    stress_batch: usize,
}

impl<C: SoakClock> SoakRunner<C> {
    /// Runner with the documented multi-hour planned duration.
    pub fn new(clock: C) -> Self {
        Self::with_duration(clock, Duration::from_secs(SOAK_SESSION_HOURS.saturating_mul(3600)))
    }

    /// Runner with an explicit planned duration (tests use short values).
    pub fn with_duration(clock: C, planned: Duration) -> Self {
        Self {
            clock,
            planned,
            phase: SoakPhase::Idle,
            started_at: None,
            ended_at: None,
            stress_cycles: 0,
            stress_batch: DEFAULT_STRESS_BATCH,
        }
    }

    /// How many [`quad_pane_layout_stress`] iterations each [`poll`] runs while running.
    pub fn set_stress_batch(&mut self, batch: usize) {
        self.stress_batch = batch.max(1);
    }

    /// Begin a soak. Resets per-run counters. Fails if already running.
    pub fn start(&mut self) -> Result<(), SoakError> {
        if self.phase == SoakPhase::Running {
            return Err(SoakError::AlreadyRunning);
        }
        let now = self.clock.now();
        self.phase = SoakPhase::Running;
        self.started_at = Some(now);
        self.ended_at = None;
        self.stress_cycles = 0;
        Ok(())
    }

    /// Cancel a running soak early. Fails if not running.
    pub fn cancel(&mut self) -> Result<(), SoakError> {
        if self.phase != SoakPhase::Running {
            return Err(SoakError::NotRunning);
        }
        self.phase = SoakPhase::Cancelled;
        self.ended_at = Some(self.clock.now());
        Ok(())
    }

    /// Advance lifecycle from the clock; while running, exercise pane stress.
    ///
    /// Completes automatically when `now >= started + planned`. No-op when not running.
    pub fn poll(&mut self) {
        if self.phase != SoakPhase::Running {
            return;
        }
        // stress_batch is always >= 1 (DEFAULT_STRESS_BATCH / set_stress_batch.max(1)).
        self.stress_cycles =
            self.stress_cycles.saturating_add(quad_pane_layout_stress(self.stress_batch));
        let now = self.clock.now();
        let started = self.started_at.expect("running implies started_at");
        let deadline = started.saturating_add(self.planned);
        if now >= deadline {
            self.phase = SoakPhase::Completed;
            self.ended_at = Some(now);
        }
    }

    /// Current status snapshot (secrets-free).
    pub fn status(&self) -> SoakStatus {
        SoakStatus {
            phase: self.phase,
            planned: self.planned,
            elapsed: self.elapsed_now(),
            stress_cycles: self.stress_cycles,
            max_panes: MAX_PANES,
        }
    }

    /// Secrets-free report for the current/last run.
    pub fn report(&self) -> SoakReport {
        let planned_hours = self.planned.as_secs() / 3600;
        SoakReport {
            phase: self.phase,
            planned_hours,
            elapsed_secs: self.elapsed_now().as_secs(),
            stress_cycles: self.stress_cycles,
            max_panes: MAX_PANES,
        }
    }

    fn elapsed_now(&self) -> Duration {
        let Some(started) = self.started_at else {
            return Duration::ZERO;
        };
        let end = self.ended_at.unwrap_or_else(|| self.clock.now());
        end.as_duration().saturating_sub(started.as_duration())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_cancel_status_round_trip() {
        let clock = FakeClock::new();
        let mut runner = SoakRunner::with_duration(clock.clone(), Duration::from_secs(60));
        assert_eq!(runner.status().phase, SoakPhase::Idle);

        runner.start().expect("start");
        assert_eq!(runner.status().phase, SoakPhase::Running);
        assert!(runner.start().is_err());

        clock.advance(Duration::from_secs(10));
        runner.poll();
        let status = runner.status();
        assert_eq!(status.phase, SoakPhase::Running);
        assert_eq!(status.elapsed, Duration::from_secs(10));
        assert!(status.stress_cycles >= 1);
        assert_eq!(status.max_panes, MAX_PANES);

        runner.cancel().expect("cancel");
        assert_eq!(runner.status().phase, SoakPhase::Cancelled);
        assert!(runner.cancel().is_err());

        let report = runner.report();
        assert_eq!(report.phase, SoakPhase::Cancelled);
        assert_eq!(report.elapsed_secs, 10);
        assert!(report.stress_cycles >= 1);
    }

    #[test]
    fn fake_clock_completes_without_real_wait() {
        let clock = FakeClock::new();
        // Planned "8 hours" compressed via fake clock — still uses SOAK_SESSION_HOURS API path.
        let planned = Duration::from_secs(SOAK_SESSION_HOURS * 3600);
        let mut runner = SoakRunner::new(clock.clone());
        assert_eq!(runner.status().planned, planned);

        runner.start().unwrap();
        clock.advance(planned.saturating_sub(Duration::from_secs(1)));
        runner.poll();
        assert_eq!(runner.status().phase, SoakPhase::Running);

        clock.advance(Duration::from_secs(1));
        runner.poll();
        assert_eq!(runner.status().phase, SoakPhase::Completed);
        assert_eq!(runner.report().planned_hours, SOAK_SESSION_HOURS);
        assert_eq!(runner.report().elapsed_secs, planned.as_secs());
    }

    #[test]
    fn report_text_has_no_secret_markers() {
        let clock = FakeClock::new();
        let mut runner = SoakRunner::with_duration(clock.clone(), Duration::from_secs(5));
        runner.start().unwrap();
        runner.poll();
        clock.advance(Duration::from_secs(5));
        runner.poll();

        let text = runner.report().format();
        assert!(text.contains("phase: Completed"));
        assert!(text.contains("planned_hours:"));
        assert!(text.contains("stress_cycles:"));
        assert!(text.contains("no secrets"));

        let lower = text.to_ascii_lowercase();
        for key in ["password=", "token=", "secret="] {
            assert!(
                !lower.contains(key),
                "soak report leaked assignment marker {key}:\n{text}"
            );
        }
        assert!(!lower.contains(r"\wormhole\keys"));
        assert!(!lower.contains(r"\wormhole\tunnels"));
    }

    #[test]
    fn restart_after_completed_resets_counters() {
        let clock = FakeClock::new();
        let mut runner = SoakRunner::with_duration(clock.clone(), Duration::from_millis(100));
        runner.set_stress_batch(2);
        runner.start().unwrap();
        runner.poll();
        let first_cycles = runner.status().stress_cycles;
        assert_eq!(first_cycles, 2);

        clock.advance(Duration::from_millis(100));
        runner.poll();
        assert_eq!(runner.status().phase, SoakPhase::Completed);

        runner.start().unwrap();
        assert_eq!(runner.status().phase, SoakPhase::Running);
        assert_eq!(runner.status().stress_cycles, 0);
        assert_eq!(runner.status().elapsed, Duration::ZERO);
    }

    #[test]
    fn double_start_while_running_is_rejected() {
        let clock = FakeClock::new();
        let mut runner = SoakRunner::with_duration(clock, Duration::from_secs(30));
        runner.start().unwrap();
        let before = runner.status();
        assert_eq!(runner.start(), Err(SoakError::AlreadyRunning));
        assert_eq!(runner.status(), before);
    }

    #[test]
    fn cancel_when_idle_and_double_cancel_leave_state_stable() {
        let clock = FakeClock::new();
        let mut runner = SoakRunner::with_duration(clock.clone(), Duration::from_secs(30));
        assert_eq!(runner.cancel(), Err(SoakError::NotRunning));
        assert_eq!(runner.status().phase, SoakPhase::Idle);

        runner.start().unwrap();
        clock.advance(Duration::from_secs(3));
        runner.poll();
        runner.cancel().unwrap();
        let after_cancel = runner.status();
        assert_eq!(after_cancel.phase, SoakPhase::Cancelled);
        assert_eq!(after_cancel.elapsed, Duration::from_secs(3));

        // Cancel is not Ok-idempotent, but must not mutate a finished cancel.
        assert_eq!(runner.cancel(), Err(SoakError::NotRunning));
        assert_eq!(runner.status(), after_cancel);
    }

    #[test]
    fn poll_after_cancel_is_noop_and_elapsed_freezes() {
        let clock = FakeClock::new();
        let mut runner = SoakRunner::with_duration(clock.clone(), Duration::from_secs(60));
        runner.start().unwrap();
        runner.poll();
        clock.advance(Duration::from_secs(7));
        runner.cancel().unwrap();
        let frozen = runner.status();

        clock.advance(Duration::from_secs(1_000));
        runner.poll();
        runner.poll();
        let after = runner.status();
        assert_eq!(after.phase, SoakPhase::Cancelled);
        assert_eq!(after.elapsed, frozen.elapsed);
        assert_eq!(after.stress_cycles, frozen.stress_cycles);
        assert_eq!(after.elapsed, Duration::from_secs(7));
    }

    #[test]
    fn fake_clock_set_never_rewinds() {
        let clock = FakeClock::new();
        let mut runner = SoakRunner::with_duration(clock.clone(), Duration::from_secs(3600));
        runner.start().unwrap();
        clock.advance(Duration::from_secs(100));
        runner.poll();
        let elapsed = runner.status().elapsed;
        assert_eq!(elapsed, Duration::from_secs(100));

        clock.set(Duration::from_secs(10)); // attempted rewind — ignored
        assert_eq!(clock.now().as_duration(), Duration::from_secs(100));
        assert_eq!(runner.status().elapsed, elapsed);

        clock.set(Duration::from_secs(150)); // forward jump ok
        assert_eq!(clock.now().as_duration(), Duration::from_secs(150));
        assert_eq!(runner.status().elapsed, Duration::from_secs(150));
        assert_eq!(runner.status().phase, SoakPhase::Running);
    }

    #[test]
    fn clock_freeze_keeps_running_until_advance_and_poll() {
        let clock = FakeClock::new();
        let mut runner = SoakRunner::with_duration(clock.clone(), Duration::from_secs(10));
        runner.start().unwrap();
        runner.poll();
        runner.poll();
        assert_eq!(runner.status().phase, SoakPhase::Running);
        assert_eq!(runner.status().elapsed, Duration::ZERO);

        clock.advance(Duration::from_secs(10));
        // Status may show elapsed past planned before poll completes the phase.
        assert_eq!(runner.status().elapsed, Duration::from_secs(10));
        assert_eq!(runner.status().phase, SoakPhase::Running);
        runner.poll();
        assert_eq!(runner.status().phase, SoakPhase::Completed);
    }

    #[test]
    fn restart_after_cancel_resets_counters() {
        let clock = FakeClock::new();
        let mut runner = SoakRunner::with_duration(clock.clone(), Duration::from_secs(60));
        runner.start().unwrap();
        runner.poll();
        clock.advance(Duration::from_secs(5));
        runner.cancel().unwrap();
        assert!(runner.status().stress_cycles >= 1);

        runner.start().unwrap();
        assert_eq!(runner.status().phase, SoakPhase::Running);
        assert_eq!(runner.status().stress_cycles, 0);
        assert_eq!(runner.status().elapsed, Duration::ZERO);
    }

    #[test]
    fn zero_planned_completes_on_first_poll() {
        let clock = FakeClock::new();
        let mut runner = SoakRunner::with_duration(clock, Duration::ZERO);
        runner.start().unwrap();
        assert_eq!(runner.status().phase, SoakPhase::Running);
        runner.poll();
        assert_eq!(runner.status().phase, SoakPhase::Completed);
        assert_eq!(runner.report().elapsed_secs, 0);
        assert_eq!(runner.report().planned_hours, 0);
    }

    #[test]
    fn cancel_after_completed_does_not_rewrite_phase() {
        let clock = FakeClock::new();
        let mut runner = SoakRunner::with_duration(clock.clone(), Duration::from_secs(1));
        runner.start().unwrap();
        clock.advance(Duration::from_secs(1));
        runner.poll();
        assert_eq!(runner.status().phase, SoakPhase::Completed);
        let before = runner.status();
        assert_eq!(runner.cancel(), Err(SoakError::NotRunning));
        assert_eq!(runner.status(), before);
    }
}
