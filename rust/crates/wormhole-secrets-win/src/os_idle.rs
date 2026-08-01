//! OS-level idle sampling via Win32 `GetLastInputInfo` — app-lock Lab unit.
//!
//! C# parity: `MainWindow.GetSystemIdleTime` (`MainWindow.xaml.cs`) +
//! `Helpers/Win32Interop.cs` call `GetLastInputInfo(ref LASTINPUTINFO)` and
//! compute `unchecked((uint)GetTickCount64()) - dwTime`. `dwTime` is
//! **milliseconds since boot** (same units as `GetTickCount`), so the same
//! mod-2³² wrap math applies here. On API failure the C# host returns
//! `TimeSpan.Zero` (fail-open); this module instead surfaces
//! [`IdleSampleError`] so Rust hosts can fail **closed** (lock when idle
//! cannot be verified).
//!
//! The real sampler ([`Win32InputIdleSampler`]) maps the last-input tick onto
//! the timeline of an injected [`IdleLockClock`] (reused from
//! [`crate::idle_lock`]): `last_input = now − elapsed`. The `now` passed to
//! [`idle_duration`] / [`should_lock_with_os_idle`] must come from the **same
//! clock** the sampler was built with (clone it — instants from different
//! epochs are incomparable).
//!
//! | Condition | [`idle_duration`] | [`should_lock_with_os_idle`] |
//! |---|---|---|
//! | sampling failed ([`IdleSampleError`]) | `None` | `true` — cannot verify activity (fail closed) |
//! | [`AppAuthenticationMode::Disabled`] | — | `false` (never locks) |
//! | `timeout_minutes == None` (UI "Never") | — | `false` |
//! | `timeout_minutes <= 0` (hostile / corrupt) | — | `true` (fail closed, same as `AppIdleLockGlue`) |
//! | already locked | — | `false` (do not re-fire) |
//! | last activity / unlock within timeout (C# recent-unlock guard) | — | `false` |
//! | app-activity idle ≥ timeout **and** OS idle ≥ timeout | — | `true` |
//! | `now` before last input (clock skew) | `Some(0)` — saturating | no lock via the OS leg |
//! | elapsed ≥ 2³² ms (49.7-day boot wrap) | mod-2³² (C# `unchecked` parity) | any real lock policy fires at minutes scale first |
//!
//! Suspend-gap estimation (C# `AppInactivityLockEvaluator.SuspendedTimerGap`,
//! 45 s heuristic) stays a **host** responsibility — this module samples on
//! demand only.
//!
//! **Never** log input content — this module holds no secrets. [`Debug`]
//! exposes durations and error codes only.

use std::cell::Cell;
use std::fmt;
use std::rc::Rc;
use std::time::Duration;

use crate::{AppAuthenticationMode, AppIdleLockGlue, IdleInstant, IdleLockClock};

/// Failure sampling OS-level idle input.
///
/// Fail-closed convention: hosts treat any [`Err`] as "idle cannot be
/// verified" and lock when the idle-lock policy is armed (see
/// [`should_lock_with_os_idle`]). Never panic on these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdleSampleError {
    /// `GetLastInputInfo` failed.
    Win32 {
        /// API or operation name.
        op: &'static str,
        /// Windows error code (`GetLastError`).
        code: u32,
    },
    /// `GetTickCount64` could not be resolved from kernel32 (broken process).
    TickSourceUnavailable,
    /// Not running on Windows.
    UnsupportedPlatform,
}

impl fmt::Display for IdleSampleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Win32 { op, code } => write!(f, "{op} failed with Win32 error {code}"),
            Self::TickSourceUnavailable => {
                write!(f, "GetTickCount64 could not be resolved from kernel32")
            }
            Self::UnsupportedPlatform => write!(f, "OS idle sampling requires Windows"),
        }
    }
}

impl std::error::Error for IdleSampleError {}

/// Injectable OS idle sampler (`GetLastInputInfo`; fake in tests).
///
/// [`last_input_instant`](InputIdleSampler::last_input_instant) returns the
/// last OS-wide input event as an [`IdleInstant`] on the timeline of the
/// injected clock, so `now − last_input` is the OS idle duration.
pub trait InputIdleSampler {
    /// Instant of the most recent OS input, on the injected clock's timeline.
    fn last_input_instant(&self) -> Result<IdleInstant, IdleSampleError>;
}

/// Deterministic idle sampler for unit tests (never touches Win32).
///
/// Script last-input on the fake epoch timeline (`IdleInstant::ZERO`); tests
/// that share a [`crate::FakeIdleClock`] with the host align the scripted
/// instant to that clock's timeline manually (e.g.
/// `set_last_input(clock.now().since_epoch())`). [`Debug`] exposes only the
/// duration / error code.
#[derive(Clone)]
pub struct FakeInputIdleSampler {
    state: Rc<Cell<Result<IdleInstant, IdleSampleError>>>,
}

impl fmt::Debug for FakeInputIdleSampler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeInputIdleSampler")
            .field("sample", &self.state.get())
            .finish()
    }
}

impl FakeInputIdleSampler {
    /// Start with last input at the fake epoch (`IdleInstant::ZERO`).
    pub fn new() -> Self {
        Self {
            state: Rc::new(Cell::new(Ok(IdleInstant::ZERO))),
        }
    }

    /// Script the last OS input `Duration` since the fake epoch.
    pub fn set_last_input(&self, at: Duration) {
        self.state.set(Ok(IdleInstant::from_duration(at)));
    }

    /// Script a sampling failure (fail-closed paths).
    pub fn fail(&self, err: IdleSampleError) {
        self.state.set(Err(err));
    }

    /// Current scripted sample (parity with the trait surface).
    pub fn sample(&self) -> Result<IdleInstant, IdleSampleError> {
        self.state.get()
    }
}

impl Default for FakeInputIdleSampler {
    fn default() -> Self {
        Self::new()
    }
}

impl InputIdleSampler for FakeInputIdleSampler {
    fn last_input_instant(&self) -> Result<IdleInstant, IdleSampleError> {
        self.sample()
    }
}

/// Production idle sampler: Win32 `GetLastInputInfo` on an injected clock
/// timeline.
///
/// `clock` provides the timeline the last-input instant is mapped onto; pass
/// the **same clock** (a clone) to the host's `now()` / timer tick, or instants
/// are incomparable. The current boot tick is read via `GetTickCount64`
/// resolved once from kernel32 at first sample (the workspace `windows`
/// feature set does not bind it — `Win32_System_SystemInformation` is not
/// enabled, and `kernel32` is always loaded in a Windows process).
#[derive(Debug, Clone)]
pub struct Win32InputIdleSampler<C: IdleLockClock> {
    clock: C,
}

impl<C: IdleLockClock> Win32InputIdleSampler<C> {
    /// Build a sampler sharing the clock timeline with the host.
    pub fn new(clock: C) -> Self {
        Self { clock }
    }
}

#[cfg(windows)]
impl<C: IdleLockClock> InputIdleSampler for Win32InputIdleSampler<C> {
    fn last_input_instant(&self) -> Result<IdleInstant, IdleSampleError> {
        let now = self.clock.now();
        let last_input = last_input_tick()?;
        let now_tick = tick_count_64()?;
        Ok(last_input_on_clock(now, boot_elapsed_ms(now_tick, last_input)))
    }
}

/// Elapsed milliseconds between the boot ticks, mod 2³².
///
/// `dwTime` is ms since boot in `GetTickCount` units; C# computes
/// `unchecked((uint)GetTickCount64()) - dwTime` (u32 wrap arithmetic). The
/// full-width subtraction masked to 32 bits is the same mod-2³² result, and
/// stays bounded for `GetLastInputInfo` ticks recorded before a 49.7-day boot
/// wrap. Pure arithmetic — the Win32 caller is `#[cfg(windows)]`.
fn boot_elapsed_ms(now_tick: u64, last_input_tick: u32) -> u64 {
    now_tick.wrapping_sub(u64::from(last_input_tick)) & 0xFFFF_FFFF
}

/// Map a since-boot elapsed onto the injected clock's timeline (saturating).
///
/// If the clock epoch was captured after boot (e.g. the app started minutes
/// after the machine did), the last input cannot precede the epoch — clamp at
/// `IdleInstant::ZERO` so idle reads as the app uptime (a lower bound of the
/// true OS idle; the lock decision stays C#-parity through the app leg).
fn last_input_on_clock(now: IdleInstant, elapsed_ms: u64) -> IdleInstant {
    IdleInstant::from_duration(now.since_epoch().saturating_sub(Duration::from_millis(elapsed_ms)))
}

#[cfg(not(windows))]
impl<C: IdleLockClock> InputIdleSampler for Win32InputIdleSampler<C> {
    fn last_input_instant(&self) -> Result<IdleInstant, IdleSampleError> {
        Err(IdleSampleError::UnsupportedPlatform)
    }
}

/// Convenience helper: OS idle duration = `now − last input` (saturating).
///
/// `None` when sampling failed — fail-closed hosts treat that as "cannot
/// verify activity" and lock when the policy is armed (see
/// [`should_lock_with_os_idle`]). Never panics.
pub fn idle_duration(sampler: &dyn InputIdleSampler, now: IdleInstant) -> Option<Duration> {
    match sampler.last_input_instant() {
        Err(_) => None,
        Ok(last_input) => Some(now.saturating_duration_since(last_input)),
    }
}

/// Compose [`AppIdleLockGlue`] policy with the OS idle sample.
///
/// Fail-closed table (see the module header): Disabled / "Never" never lock;
/// hostile zero/negative minutes lock; already-locked never re-fires; a failed
/// OS sample locks; otherwise both the app-activity leg **and** the OS leg must
/// reach or exceed the timeout (`>=`, C# `effectiveIdle >= timeout` parity). The
/// app-activity leg doubles as the C# recent-unlock
/// guard (`AppInactivityLockEvaluator`: no lock before `timeout` since the last
/// unlock) — when the host also calls [`AppIdleLockGlue::note_activity`], that
/// leg additionally requires the last Wormhole interaction to be stale (strictly
/// more conservative than C#, which ignores app activity; app input implies OS
/// input, so the legs coincide in the exact-input model).
pub fn should_lock_with_os_idle(
    glue: &AppIdleLockGlue,
    mode: AppAuthenticationMode,
    timeout_minutes: Option<i32>,
    is_already_locked: bool,
    sampler: &dyn InputIdleSampler,
    now: IdleInstant,
) -> bool {
    // Policy short-circuits, mirroring AppIdleLockGlue::should_lock.
    if is_already_locked || mode == AppAuthenticationMode::Disabled {
        return false;
    }
    let Some(minutes) = timeout_minutes else {
        return false; // UI "Never".
    };
    if minutes <= 0 {
        return true; // Hostile / corrupt duration — fail closed, same as the glue.
    }

    // C# recent-unlock guard: never lock before the timeout has elapsed since
    // the last activity / unlock (prevents instant re-lock after unlock).
    if !glue.should_lock(mode, Some(minutes), false, now) {
        return false;
    }

    let timeout = Duration::from_secs((minutes as u64).saturating_mul(60));
    match idle_duration(sampler, now) {
        // Sampling failed — cannot verify the user is active; fail closed.
        None => true,
        Some(os_idle) => os_idle >= timeout,
    }
}

/// `GetLastInputInfo` wrapper: last-input tick (ms since boot, u32 wrap).
#[cfg(windows)]
fn last_input_tick() -> Result<u32, IdleSampleError> {
    use windows::Win32::Foundation::{GetLastError, SetLastError, WIN32_ERROR};
    use windows::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};

    let mut info = LASTINPUTINFO {
        // `cbSize` must be `sizeof(LASTINPUTINFO)` before the call (C# parity:
        // `Marshal.SizeOf<LASTINPUTINFO>()`).
        cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32,
        dwTime: 0,
    };
    unsafe {
        SetLastError(WIN32_ERROR(0));
        if GetLastInputInfo(&mut info).as_bool() {
            Ok(info.dwTime)
        } else {
            Err(IdleSampleError::Win32 {
                op: "GetLastInputInfo",
                code: GetLastError().0,
            })
        }
    }
}

/// `GetTickCount64` (ms since boot), resolved once from kernel32.
///
/// # Safety
///
/// `GetProcAddress` returns the FARPROC-shaped
/// `Option<unsafe extern "system" fn() -> isize>`; the null check guarantees a
/// value. `GetTickCount64` returns `ULONGLONG` in the same return register
/// (RAX on x64, X0 on arm64) that the `isize`-typed declaration reads, so
/// casting the **return value** `isize as u64` is a defined two's-complement
/// bit-exact cast — no function-pointer transmute is involved.
#[cfg(windows)]
fn tick_count_64() -> Result<u64, IdleSampleError> {
    use std::sync::OnceLock;

    // FARPROC's `isize` return shares the register with `ULONGLONG`; the
    // value-level `as u64` cast is applied at the call site.
    type RawTick64 = unsafe extern "system" fn() -> isize;

    fn resolve() -> Option<RawTick64> {
        use windows::core::{w, PCSTR};
        use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

        let kernel32 = unsafe { GetModuleHandleW(w!("kernel32.dll")) }.ok()?;
        let proc = unsafe {
            GetProcAddress(
                kernel32,
                PCSTR::from_raw(c"GetTickCount64".as_ptr().cast::<u8>()),
            )
        };
        // FARPROC is `Option<unsafe extern "system" fn() -> isize>`.
        let tick = proc?;
        Some(tick)
    }

    static TICK64: OnceLock<Option<RawTick64>> = OnceLock::new();
    let Some(tick) = TICK64.get_or_init(resolve) else {
        return Err(IdleSampleError::TickSourceUnavailable);
    };
    Ok(unsafe { tick() } as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FakeIdleClock;
    #[cfg(windows)]
    use crate::SystemIdleLockClock;

    fn minutes(n: u64) -> Duration {
        Duration::from_secs(n.saturating_mul(60))
    }

    fn armed_minutes(n: i32) -> Option<i32> {
        Some(n)
    }

    #[test]
    fn fake_sampler_defaults_to_epoch_last_input() {
        let sampler = FakeInputIdleSampler::new();
        assert_eq!(
            sampler.sample().unwrap().since_epoch(),
            Duration::ZERO
        );
    }

    #[test]
    fn fake_sampler_reports_injected_last_input() {
        let sampler = FakeInputIdleSampler::new();
        sampler.set_last_input(minutes(3));
        assert_eq!(sampler.sample().unwrap().since_epoch(), minutes(3));
        let via_trait: &dyn InputIdleSampler = &sampler;
        assert_eq!(
            via_trait.last_input_instant().unwrap().since_epoch(),
            minutes(3)
        );
    }

    #[test]
    fn fake_sampler_error_roundtrips() {
        let sampler = FakeInputIdleSampler::new();
        sampler.fail(IdleSampleError::Win32 {
            op: "GetLastInputInfo",
            code: 5,
        });
        assert_eq!(
            sampler.sample(),
            Err(IdleSampleError::Win32 {
                op: "GetLastInputInfo",
                code: 5
            })
        );
    }

    #[test]
    fn idle_duration_is_now_minus_last_input() {
        let sampler = FakeInputIdleSampler::new();
        sampler.set_last_input(minutes(3));
        let now = IdleInstant::from_duration(minutes(10));
        assert_eq!(idle_duration(&sampler, now), Some(minutes(7)));
    }

    #[test]
    fn idle_duration_zero_when_now_equals_last_input() {
        let sampler = FakeInputIdleSampler::new();
        let now = IdleInstant::from_duration(minutes(5));
        sampler.set_last_input(now.since_epoch());
        assert_eq!(idle_duration(&sampler, now), Some(Duration::ZERO));
    }

    #[test]
    fn idle_duration_saturates_on_clock_rewind() {
        let sampler = FakeInputIdleSampler::new();
        sampler.set_last_input(minutes(10));
        let now = IdleInstant::from_duration(minutes(3)); // hostile rewind
        assert_eq!(idle_duration(&sampler, now), Some(Duration::ZERO));
    }

    #[test]
    fn idle_duration_none_when_sampling_fails() {
        let sampler = FakeInputIdleSampler::new();
        sampler.fail(IdleSampleError::TickSourceUnavailable);
        let now = IdleInstant::from_duration(minutes(10));
        assert_eq!(idle_duration(&sampler, now), None);
    }

    #[test]
    fn idle_duration_composes_with_shared_fake_clock_timeline() {
        let clock = FakeIdleClock::new();
        clock.advance(minutes(5));
        let sampler = FakeInputIdleSampler::new();
        sampler.set_last_input(minutes(2));
        assert_eq!(
            idle_duration(&sampler, clock.now()),
            Some(minutes(3))
        );
    }

    #[test]
    fn should_lock_os_idle_disabled_and_never_never_lock() {
        let (mut glue, clock) = AppIdleLockGlue::with_fake();
        glue.mark_unlocked(clock.now());
        clock.advance(minutes(60));
        let sampler = FakeInputIdleSampler::new(); // OS idle = full 60 min
        assert!(!should_lock_with_os_idle(
            &glue,
            AppAuthenticationMode::Disabled,
            armed_minutes(5),
            false,
            &sampler,
            clock.now()
        ));
        assert!(!should_lock_with_os_idle(
            &glue,
            AppAuthenticationMode::Pin,
            None,
            false,
            &sampler,
            clock.now()
        ));
    }

    #[test]
    fn should_lock_os_idle_hostile_minutes_fail_closed() {
        let (mut glue, clock) = AppIdleLockGlue::with_fake();
        glue.mark_unlocked(clock.now());
        let sampler = FakeInputIdleSampler::new();
        // No idle needed — invalid duration fail-closed (glue parity).
        assert!(should_lock_with_os_idle(
            &glue,
            AppAuthenticationMode::Pin,
            armed_minutes(0),
            false,
            &sampler,
            clock.now()
        ));
        assert!(should_lock_with_os_idle(
            &glue,
            AppAuthenticationMode::Password,
            armed_minutes(-1),
            false,
            &sampler,
            clock.now()
        ));
        assert!(should_lock_with_os_idle(
            &glue,
            AppAuthenticationMode::WindowsHello,
            armed_minutes(i32::MIN),
            false,
            &sampler,
            clock.now()
        ));
    }

    #[test]
    fn should_lock_os_idle_already_locked_does_not_refire() {
        let (mut glue, clock) = AppIdleLockGlue::with_fake();
        glue.mark_unlocked(clock.now());
        clock.advance(minutes(60));
        let sampler = FakeInputIdleSampler::new();
        assert!(!should_lock_with_os_idle(
            &glue,
            AppAuthenticationMode::Pin,
            armed_minutes(5),
            true,
            &sampler,
            clock.now()
        ));
        // Fail-closed zero also suppressed when already locked.
        assert!(!should_lock_with_os_idle(
            &glue,
            AppAuthenticationMode::Pin,
            armed_minutes(0),
            true,
            &sampler,
            clock.now()
        ));
    }

    #[test]
    fn should_lock_os_idle_past_timeout_locks() {
        let (mut glue, clock) = AppIdleLockGlue::with_fake();
        glue.mark_unlocked(clock.now());
        clock.advance(minutes(6));
        let sampler = FakeInputIdleSampler::new(); // last input at epoch → idle 6 min
        assert!(should_lock_with_os_idle(
            &glue,
            AppAuthenticationMode::Pin,
            armed_minutes(5),
            false,
            &sampler,
            clock.now()
        ));
    }

    #[test]
    fn should_lock_os_idle_just_under_timeout_stays_unlocked() {
        let (mut glue, clock) = AppIdleLockGlue::with_fake();
        glue.mark_unlocked(clock.now());
        clock.advance(Duration::from_secs(5 * 60 - 1));
        let sampler = FakeInputIdleSampler::new();
        assert!(!should_lock_with_os_idle(
            &glue,
            AppAuthenticationMode::Password,
            armed_minutes(5),
            false,
            &sampler,
            clock.now()
        ));
    }

    #[test]
    fn should_lock_os_idle_exactly_at_timeout_locks() {
        let (mut glue, clock) = AppIdleLockGlue::with_fake();
        glue.mark_unlocked(clock.now());
        clock.advance(minutes(5));
        let sampler = FakeInputIdleSampler::new();
        assert!(should_lock_with_os_idle(
            &glue,
            AppAuthenticationMode::Pin,
            armed_minutes(5),
            false,
            &sampler,
            clock.now()
        ));
    }

    #[test]
    fn should_lock_os_idle_recent_unlock_prevents_immediate_relock() {
        // C# guard: no lock before `timeout` since unlock — even when the OS
        // sample alone would already be at the timeout (post-unlock period).
        let (mut glue, clock) = AppIdleLockGlue::with_fake();
        clock.advance(minutes(10));
        glue.mark_unlocked(clock.now());
        clock.advance(minutes(1));
        let sampler = FakeInputIdleSampler::new();
        assert!(!should_lock_with_os_idle(
            &glue,
            AppAuthenticationMode::WindowsHello,
            armed_minutes(5),
            false,
            &sampler,
            clock.now()
        ));
    }

    #[test]
    fn should_lock_os_idle_fail_closed_on_sample_error() {
        let (mut glue, clock) = AppIdleLockGlue::with_fake();
        glue.mark_unlocked(clock.now());
        clock.advance(minutes(6));
        let sampler = FakeInputIdleSampler::new();
        sampler.fail(IdleSampleError::Win32 {
            op: "GetLastInputInfo",
            code: 0x8000_0000,
        });
        // Cannot verify activity → fail closed.
        assert!(should_lock_with_os_idle(
            &glue,
            AppAuthenticationMode::Pin,
            armed_minutes(5),
            false,
            &sampler,
            clock.now()
        ));
    }

    #[test]
    fn should_lock_os_idle_requires_app_activity_stale_too() {
        // AND semantics: recent Wormhole interaction keeps the app unlocked
        // even when the OS sample alone exceeds the timeout (app input implies
        // OS input, so this only bites when the OS missed the input).
        let (mut glue, clock) = AppIdleLockGlue::with_fake();
        glue.mark_unlocked(clock.now());
        clock.advance(minutes(4));
        glue.note_activity(clock.now());
        clock.advance(minutes(2)); // now t=6m; app idle 2m < 5m
        let sampler = FakeInputIdleSampler::new(); // OS idle 6m ≥ 5m
        assert!(!should_lock_with_os_idle(
            &glue,
            AppAuthenticationMode::Pin,
            armed_minutes(5),
            false,
            &sampler,
            clock.now()
        ));
    }

    #[test]
    fn should_lock_os_idle_increments_glue_evaluate_counter() {
        let (mut glue, clock) = AppIdleLockGlue::with_fake();
        glue.mark_unlocked(clock.now());
        clock.advance(minutes(6));
        let sampler = FakeInputIdleSampler::new();
        let _ = should_lock_with_os_idle(
            &glue,
            AppAuthenticationMode::Pin,
            armed_minutes(5),
            false,
            &sampler,
            clock.now()
        );
        assert_eq!(glue.evaluate_calls(), 1);
    }

    #[test]
    fn boot_elapsed_ms_matches_csharp_unchecked_arithmetic() {
        // Plain subtraction below 2³² ms.
        assert_eq!(boot_elapsed_ms(3_600_000, 60_000), 3_540_000);
        // now_tick ≥ 2³²: C# truncates now to u32 first; the mask yields the
        // same mod-2³² result.
        let now_tick = (1u64 << 32) + 1_000;
        assert_eq!(boot_elapsed_ms(now_tick, 0), 1_000);
        // Both operands on the wrapped side: C# `(uint)now - dwTime` wraps.
        let last = (1u64 << 32) - 5_000;
        assert_eq!(boot_elapsed_ms(now_tick, last as u32), 6_000);
        // Bounded to u32 range — the mask can never be dropped unnoticed.
        assert_eq!(boot_elapsed_ms(now_tick, last as u32) >> 32, 0);
    }

    #[test]
    fn boot_elapsed_ms_wrap_is_equivalent_to_u32_truncation() {
        // Parity with C# `unchecked((uint)GetTickCount64()) - dwTime` across
        // the wrap boundary: full-64-bit subtract + mask ≡ u32 truncate + u32
        // wrapping sub.
        for now_tick in [0u64, 1, 0xFFFF_FFFF, 1 << 32, (1 << 32) + 7_000_000_000] {
            let csharp_now = now_tick as u32;
            for last_input in [0u32, 1, 0xFFFF_FFFF, 500_000] {
                let csharp = csharp_now.wrapping_sub(last_input);
                assert_eq!(boot_elapsed_ms(now_tick, last_input), u64::from(csharp));
            }
        }
    }

    #[test]
    fn last_input_on_clock_places_elapsed_on_clock_timeline() {
        let now = IdleInstant::from_duration(minutes(10));
        assert_eq!(
            last_input_on_clock(now, minutes(7).as_millis() as u64).since_epoch(),
            minutes(3)
        );
    }

    #[test]
    fn last_input_on_clock_zero_elapsed_keeps_now() {
        let now = IdleInstant::from_duration(minutes(10));
        assert_eq!(last_input_on_clock(now, 0).since_epoch(), minutes(10));
    }

    #[test]
    fn last_input_on_clock_saturates_when_elapsed_exceeds_epoch() {
        // Epoch captured after boot (app start minutes after boot): last input
        // cannot precede the epoch — clamp at ZERO, so idle reads as app uptime.
        let now = IdleInstant::from_duration(minutes(5));
        assert_eq!(
            last_input_on_clock(now, minutes(120).as_millis() as u64),
            IdleInstant::ZERO
        );
    }

    #[test]
    fn last_input_on_clock_accepts_max_masked_elapsed_without_overflow() {
        // 2³² - 1 ms is the largest value boot_elapsed_ms can produce;
        // Duration::from_millis must not overflow and the saturating sub must
        // not panic.
        let now = IdleInstant::from_duration(minutes(60));
        assert_eq!(last_input_on_clock(now, 0xFFFF_FFFF), IdleInstant::ZERO);
    }

    #[test]
    fn should_lock_os_idle_clock_skew_disables_os_leg() {
        // Documented table row: sampler reports last input *after* `now`
        // (hostile skew / mixed clock timelines) — idle_duration saturates to
        // Some(0), so the OS leg can never fire on its own.
        let (mut glue, clock) = AppIdleLockGlue::with_fake();
        glue.mark_unlocked(clock.now());
        clock.advance(minutes(6));
        let sampler = FakeInputIdleSampler::new();
        sampler.set_last_input(minutes(7)); // after `now` (6 min)
        assert!(!should_lock_with_os_idle(
            &glue,
            AppAuthenticationMode::Pin,
            armed_minutes(5),
            false,
            &sampler,
            clock.now()
        ));
    }

    #[test]
    fn should_lock_os_idle_sample_error_still_requires_stale_app_leg() {
        // Fail-closed on sample error — but only when the policy is armed AND
        // the recent-activity guard has passed; a fresh unlock suppresses the
        // lock exactly like the armed-success path (and sampling never runs).
        let (mut glue, clock) = AppIdleLockGlue::with_fake();
        clock.advance(minutes(10));
        glue.mark_unlocked(clock.now());
        clock.advance(minutes(1));
        let sampler = FakeInputIdleSampler::new();
        sampler.fail(IdleSampleError::Win32 {
            op: "GetLastInputInfo",
            code: 5,
        });
        assert!(!should_lock_with_os_idle(
            &glue,
            AppAuthenticationMode::Pin,
            armed_minutes(5),
            false,
            &sampler,
            clock.now()
        ));
    }

    #[test]
    fn idle_sample_error_display_covers_all_variants_without_payload() {
        let cases = [
            (
                IdleSampleError::Win32 {
                    op: "GetLastInputInfo",
                    code: 5,
                },
                "GetLastInputInfo failed with Win32 error 5",
            ),
            (
                IdleSampleError::TickSourceUnavailable,
                "GetTickCount64 could not be resolved from kernel32",
            ),
            (
                IdleSampleError::UnsupportedPlatform,
                "OS idle sampling requires Windows",
            ),
        ];
        for (err, expected) in cases {
            assert_eq!(err.to_string(), expected);
            let debug = format!("{err:?}");
            assert!(!debug.contains("hunter2"));
            assert!(!debug.contains("PIN"));
        }
    }

    #[test]
    fn debug_and_error_never_echo_secrets() {
        let sampler = FakeInputIdleSampler::new();
        sampler.set_last_input(minutes(3));
        let dbg = format!("{sampler:?}");
        assert!(dbg.contains("FakeInputIdleSampler"));
        assert!(!dbg.contains("hunter2"));
        assert!(!dbg.contains("PIN"));

        let err = IdleSampleError::Win32 {
            op: "GetLastInputInfo",
            code: 5,
        };
        let text = format!("{err} / {err:?}");
        assert!(!text.contains("hunter2"));
        assert!(text.contains("GetLastInputInfo"));
        assert!(text.contains("Win32 error 5"));
    }

    #[cfg(windows)]
    #[test]
    fn win32_sampler_presence_check_does_not_panic() {
        // Compile-time presence of the real sampler. Never asserts a value
        // (CI determinism) — it must merely construct and return Ok or Err.
        let sampler = Win32InputIdleSampler::new(SystemIdleLockClock::new());
        if let Ok(instant) = sampler.last_input_instant() {
            let _ = instant.since_epoch();
        }
        let _ = format!("{sampler:?}");
    }

    #[cfg(not(windows))]
    #[test]
    fn win32_sampler_unsupported_off_windows() {
        let sampler = Win32InputIdleSampler::new(FakeIdleClock::new());
        assert_eq!(
            sampler.last_input_instant(),
            Err(IdleSampleError::UnsupportedPlatform)
        );
    }
}
