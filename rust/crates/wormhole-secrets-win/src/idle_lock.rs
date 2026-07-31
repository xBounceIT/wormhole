//! App idle-lock timeout glue — pure Rust, no GPUI / no `GetLastInputInfo`.
//!
//! Thin policy beside C# `AppInactivityLockEvaluator` / `MainWindow` idle timer:
//! hosts call [`AppIdleLockGlue::note_activity`] (or [`mark_unlocked`]) when the
//! user is active / finishes unlock; [`AppIdleLockGlue::should_lock`] compares
//! elapsed idle against the configured minutes using an injectable clock.
//!
//! | Condition | Result |
//! |---|---|
//! | [`AppAuthenticationMode::Disabled`] | never locks |
//! | `timeout_minutes == None` (UI "Never") | never locks |
//! | `timeout_minutes <= 0` (hostile / corrupt) | **fail closed** → lock when auth enabled |
//! | elapsed since last activity ≥ timeout | lock |
//! | already locked | `false` (do not re-fire) |
//!
//! Production OS idle sampling (`GetLastInputInfo`) and suspend-gap estimation
//! remain host responsibilities — this stub tracks last-activity only.
//! [`FakeIdleClock`] keeps unit tests deterministic (no wall sleep).
//!
//! **Never** log PIN / password / biometric material — this module holds no
//! secrets. [`Debug`] exposes mode-adjacent counters and durations only.

use std::cell::Cell;
use std::fmt;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use crate::AppAuthenticationMode;

/// Monotonic instant as a duration since an arbitrary epoch.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IdleInstant {
    since_epoch: Duration,
}

impl IdleInstant {
    /// Epoch (`Duration::ZERO`).
    pub const ZERO: Self = Self {
        since_epoch: Duration::ZERO,
    };

    /// Construct from a duration since the clock epoch.
    pub const fn from_duration(since_epoch: Duration) -> Self {
        Self { since_epoch }
    }

    /// Duration since the clock epoch.
    pub const fn since_epoch(self) -> Duration {
        self.since_epoch
    }

    /// Elapsed time from `earlier` to `self` (saturating).
    pub fn saturating_duration_since(self, earlier: Self) -> Duration {
        self.since_epoch.saturating_sub(earlier.since_epoch)
    }
}

impl fmt::Debug for IdleInstant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("IdleInstant")
            .field(&self.since_epoch)
            .finish()
    }
}

/// Injectable monotonic clock (production: wall/`Instant`; tests: [`FakeIdleClock`]).
pub trait IdleLockClock {
    /// Current monotonic time.
    fn now(&self) -> IdleInstant;
}

/// Controllable clock for deterministic idle-lock unit tests.
#[derive(Clone)]
pub struct FakeIdleClock {
    now: Rc<Cell<Duration>>,
}

impl fmt::Debug for FakeIdleClock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeIdleClock")
            .field("now", &self.now.get())
            .finish()
    }
}

impl FakeIdleClock {
    /// Start at [`IdleInstant::ZERO`].
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
    /// elapsed idle cannot shrink mid-test.
    pub fn set(&self, at: Duration) {
        self.now.set(self.now.get().max(at));
    }
}

impl Default for FakeIdleClock {
    fn default() -> Self {
        Self::new()
    }
}

impl IdleLockClock for FakeIdleClock {
    fn now(&self) -> IdleInstant {
        IdleInstant::from_duration(self.now.get())
    }
}

/// Process-relative wall clock backed by [`std::time::Instant`].
#[derive(Debug, Clone)]
pub struct SystemIdleLockClock {
    epoch: std::time::Instant,
}

impl SystemIdleLockClock {
    /// Capture `Instant::now()` as the idle-lock epoch.
    pub fn new() -> Self {
        Self {
            epoch: std::time::Instant::now(),
        }
    }
}

impl Default for SystemIdleLockClock {
    fn default() -> Self {
        Self::new()
    }
}

impl IdleLockClock for SystemIdleLockClock {
    fn now(&self) -> IdleInstant {
        IdleInstant::from_duration(self.epoch.elapsed())
    }
}

/// Thin idle-lock policy: last-activity + timeout → should-lock decision.
///
/// Does **not** own [`crate::AppAuthenticationService`] / Hello unlock — hosts
/// call this from a timer tick, then show the lock overlay / Hello UI.
pub struct AppIdleLockGlue {
    last_activity: IdleInstant,
    note_calls: AtomicUsize,
    evaluate_calls: AtomicUsize,
}

impl fmt::Debug for AppIdleLockGlue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppIdleLockGlue")
            .field("last_activity", &self.last_activity)
            .field("note_calls", &self.note_calls.load(Ordering::SeqCst))
            .field("evaluate_calls", &self.evaluate_calls.load(Ordering::SeqCst))
            .finish()
    }
}

impl AppIdleLockGlue {
/// Start tracking activity at `now` (typically [`IdleLockClock::now`] at
/// unlock / construction — a stale epoch makes idle look already elapsed).
pub fn new(now: IdleInstant) -> Self {
        Self {
            last_activity: now,
            note_calls: AtomicUsize::new(0),
            evaluate_calls: AtomicUsize::new(0),
        }
    }

    /// Glue + shared [`FakeIdleClock`] starting at epoch zero.
    pub fn with_fake() -> (Self, FakeIdleClock) {
        let clock = FakeIdleClock::new();
        let glue = Self::new(clock.now());
        (glue, clock)
    }

    /// Last recorded activity / unlock instant.
    pub fn last_activity(&self) -> IdleInstant {
        self.last_activity
    }

    /// How many times [`note_activity`] / [`mark_unlocked`] ran.
    pub fn note_calls(&self) -> usize {
        self.note_calls.load(Ordering::SeqCst)
    }

    /// How many times [`should_lock`] ran.
    pub fn evaluate_calls(&self) -> usize {
        self.evaluate_calls.load(Ordering::SeqCst)
    }

    /// Record user activity — resets the idle clock (does not unlock).
    pub fn note_activity(&mut self, now: IdleInstant) {
        self.note_calls.fetch_add(1, Ordering::SeqCst);
        // Activity in the past of last_activity is ignored (monotonic idle).
        if now >= self.last_activity {
            self.last_activity = now;
        }
    }

    /// After a successful unlock (C# `MarkUnlocked`) — resets idle tracking.
    pub fn mark_unlocked(&mut self, now: IdleInstant) {
        self.note_activity(now);
    }

    /// Whether the host should show the lock overlay.
    ///
    /// `timeout_minutes`: `None` = Never; `Some(n)` with `n <= 0` fail-closed
    /// locks when auth is enabled; positive `n` locks after `n` minutes idle.
    pub fn should_lock(
        &self,
        mode: AppAuthenticationMode,
        timeout_minutes: Option<i32>,
        is_already_locked: bool,
        now: IdleInstant,
    ) -> bool {
        self.evaluate_calls.fetch_add(1, Ordering::SeqCst);

        if is_already_locked {
            return false;
        }
        if mode == AppAuthenticationMode::Disabled {
            return false;
        }

        let Some(minutes) = timeout_minutes else {
            // UI "Never".
            return false;
        };

        // Hostile / corrupt zero or negative duration → fail closed (lock).
        if minutes <= 0 {
            return true;
        }

        let timeout = Duration::from_secs((minutes as u64).saturating_mul(60));
        let idle = now.saturating_duration_since(self.last_activity);
        idle >= timeout
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minutes(n: u64) -> Duration {
        Duration::from_secs(n.saturating_mul(60))
    }

    #[test]
    fn disabled_mode_never_locks() {
        let (mut glue, clock) = AppIdleLockGlue::with_fake();
        glue.mark_unlocked(clock.now());
        clock.advance(minutes(60));
        assert!(!glue.should_lock(
            AppAuthenticationMode::Disabled,
            Some(1),
            false,
            clock.now()
        ));
        assert!(!glue.should_lock(
            AppAuthenticationMode::Disabled,
            Some(0),
            false,
            clock.now()
        ));
        assert!(!glue.should_lock(
            AppAuthenticationMode::Disabled,
            Some(-5),
            false,
            clock.now()
        ));
    }

    #[test]
    fn none_timeout_never_locks() {
        let (mut glue, clock) = AppIdleLockGlue::with_fake();
        glue.mark_unlocked(clock.now());
        clock.advance(minutes(60));
        assert!(!glue.should_lock(
            AppAuthenticationMode::Pin,
            None,
            false,
            clock.now()
        ));
    }

    #[test]
    fn idle_past_timeout_locks() {
        let (mut glue, clock) = AppIdleLockGlue::with_fake();
        glue.mark_unlocked(clock.now());
        clock.advance(minutes(6));
        assert!(glue.should_lock(
            AppAuthenticationMode::Pin,
            Some(5),
            false,
            clock.now()
        ));
    }

    #[test]
    fn activity_resets_idle_window() {
        let (mut glue, clock) = AppIdleLockGlue::with_fake();
        glue.mark_unlocked(clock.now());
        clock.advance(minutes(4));
        assert!(!glue.should_lock(
            AppAuthenticationMode::Password,
            Some(5),
            false,
            clock.now()
        ));
        glue.note_activity(clock.now());
        clock.advance(minutes(4));
        assert!(!glue.should_lock(
            AppAuthenticationMode::Password,
            Some(5),
            false,
            clock.now()
        ));
        clock.advance(minutes(1));
        assert!(glue.should_lock(
            AppAuthenticationMode::Password,
            Some(5),
            false,
            clock.now()
        ));
    }

    #[test]
    fn recent_unlock_prevents_immediate_relock() {
        let (mut glue, clock) = AppIdleLockGlue::with_fake();
        clock.advance(minutes(10));
        glue.mark_unlocked(clock.now());
        clock.advance(minutes(1));
        assert!(!glue.should_lock(
            AppAuthenticationMode::WindowsHello,
            Some(5),
            false,
            clock.now()
        ));
    }

    #[test]
    fn already_locked_does_not_refire() {
        let (mut glue, clock) = AppIdleLockGlue::with_fake();
        glue.mark_unlocked(clock.now());
        clock.advance(minutes(20));
        assert!(!glue.should_lock(
            AppAuthenticationMode::Pin,
            Some(5),
            true,
            clock.now()
        ));
        // Fail-closed zero also suppressed when already locked.
        assert!(!glue.should_lock(
            AppAuthenticationMode::Pin,
            Some(0),
            true,
            clock.now()
        ));
    }

    #[test]
    fn zero_and_negative_timeout_fail_closed_lock() {
        let (mut glue, clock) = AppIdleLockGlue::with_fake();
        glue.mark_unlocked(clock.now());
        // No idle needed — invalid duration fail-closed.
        assert!(glue.should_lock(
            AppAuthenticationMode::Pin,
            Some(0),
            false,
            clock.now()
        ));
        assert!(glue.should_lock(
            AppAuthenticationMode::Password,
            Some(-1),
            false,
            clock.now()
        ));
        assert!(glue.should_lock(
            AppAuthenticationMode::WindowsHello,
            Some(i32::MIN),
            false,
            clock.now()
        ));
    }

    #[test]
    fn exactly_at_timeout_locks() {
        let (mut glue, clock) = AppIdleLockGlue::with_fake();
        glue.mark_unlocked(clock.now());
        clock.advance(minutes(5));
        assert!(glue.should_lock(
            AppAuthenticationMode::Pin,
            Some(5),
            false,
            clock.now()
        ));
    }

    #[test]
    fn just_under_timeout_stays_unlocked() {
        let (mut glue, clock) = AppIdleLockGlue::with_fake();
        glue.mark_unlocked(clock.now());
        clock.advance(Duration::from_secs(5 * 60 - 1));
        assert!(!glue.should_lock(
            AppAuthenticationMode::Pin,
            Some(5),
            false,
            clock.now()
        ));
    }

    #[test]
    fn fake_clock_set_never_rewinds() {
        let clock = FakeIdleClock::new();
        clock.advance(minutes(3));
        clock.set(minutes(1)); // rewind attempt ignored
        assert_eq!(clock.now().since_epoch(), minutes(3));
        clock.set(minutes(4));
        assert_eq!(clock.now().since_epoch(), minutes(4));
    }

    #[test]
    fn note_activity_ignores_rewound_now() {
        let (mut glue, clock) = AppIdleLockGlue::with_fake();
        clock.advance(minutes(2));
        glue.note_activity(clock.now());
        let marked = glue.last_activity();
        glue.note_activity(IdleInstant::ZERO); // hostile rewind
        assert_eq!(glue.last_activity(), marked);
        assert_eq!(glue.note_calls(), 2);
    }

    #[test]
    fn debug_exposes_counts_not_secrets() {
        let (mut glue, clock) = AppIdleLockGlue::with_fake();
        glue.note_activity(clock.now());
        let _ = glue.should_lock(AppAuthenticationMode::Pin, Some(15), false, clock.now());
        let dbg = format!("{glue:?}");
        assert!(dbg.contains("note_calls"));
        assert!(dbg.contains("evaluate_calls"));
        assert!(!dbg.contains("hunter2"));
        assert!(!dbg.contains("PIN"));
        let clock_dbg = format!("{clock:?}");
        assert!(clock_dbg.contains("FakeIdleClock"));
    }

    #[test]
    fn system_clock_is_monotonic() {
        let clock = SystemIdleLockClock::new();
        let a = clock.now();
        let b = clock.now();
        assert!(b >= a);
        // Wall clock is usable as IdleLockClock (no Fake required for hosts).
        let mut glue = AppIdleLockGlue::new(a);
        glue.note_activity(b);
        assert!(!glue.should_lock(
            AppAuthenticationMode::Disabled,
            Some(1),
            false,
            clock.now()
        ));
    }

    #[test]
    fn large_positive_timeout_does_not_lock_immediately() {
        let (mut glue, clock) = AppIdleLockGlue::with_fake();
        glue.mark_unlocked(clock.now());
        // i32::MAX minutes must not wrap / panic; still under timeout at t=0.
        assert!(!glue.should_lock(
            AppAuthenticationMode::Pin,
            Some(i32::MAX),
            false,
            clock.now()
        ));
        clock.advance(minutes(1));
        assert!(!glue.should_lock(
            AppAuthenticationMode::Pin,
            Some(i32::MAX),
            false,
            clock.now()
        ));
    }

    #[test]
    fn stale_epoch_construction_locks_when_now_advanced() {
        // Hosts should seed with clock.now(); a stale ZERO epoch means full idle.
        let glue = AppIdleLockGlue::new(IdleInstant::ZERO);
        let later = IdleInstant::from_duration(minutes(20));
        assert!(glue.should_lock(
            AppAuthenticationMode::Pin,
            Some(5),
            false,
            later
        ));
    }

    #[test]
    fn public_types_are_usable_via_crate_prelude() {
        use crate::{
            AppIdleLockGlue, FakeIdleClock, IdleInstant, IdleLockClock, SystemIdleLockClock,
        };
        let clock = FakeIdleClock::new();
        let _sys = SystemIdleLockClock::new();
        let mut glue = AppIdleLockGlue::new(IdleInstant::ZERO);
        let now: IdleInstant = IdleLockClock::now(&clock);
        glue.note_activity(now);
        assert!(!glue.should_lock(
            AppAuthenticationMode::Disabled,
            Some(0),
            false,
            now
        ));
    }
}
