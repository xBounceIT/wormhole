//! Trailing-edge debounce for RDP remote desktop resolution updates.
//!
//! Mirrors C# `RdpSurfaceHost` (`ResolutionDebounceMs` = 250): layout ticks may
//! push rapid [`PhysicalBounds`] / desktop-size changes; only the **last** size
//! is emitted after a quiet period. Pure logic — never calls Connect / OCX.
//!
//! Drive with an injected monotonic clock ([`MonoTime`]) so unit tests can use a
//! fake ticker; [`ResolutionDebouncer::instant`] sets a zero delay for immediate
//! emit-on-push.

use std::time::Duration;

use crate::PhysicalBounds;

use super::host_bounds::HostBounds;

/// Default quiet period matching C# `RdpSurfaceHost.ResolutionDebounceMs`.
pub const RESOLUTION_DEBOUNCE_DEFAULT: Duration = Duration::from_millis(250);

/// Remote desktop pixel size candidate (width × height).
///
/// Origin / DPI from layout bounds are ignored — only size is renegotiated.
/// Axes are integer (`u32`); NaN / non-finite floats are not representable —
/// callers convert from layout integers (or clamp negatives to 0 via
/// [`DesktopSize::from_host_bounds`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DesktopSize {
    /// Width in physical pixels.
    pub width: u32,
    /// Height in physical pixels.
    pub height: u32,
}

impl DesktopSize {
    /// Create a desktop size.
    pub const fn new(width: u32, height: u32) -> Self {
        Self { width, height }
    }

    /// True when either axis is zero (nothing useful to renegotiate).
    pub const fn is_degenerate(self) -> bool {
        self.width == 0 || self.height == 0
    }

    /// Extract size from layout bounds (ignores `x` / `y` / `dpi`).
    pub const fn from_physical(bounds: PhysicalBounds) -> Self {
        Self {
            width: bounds.width,
            height: bounds.height,
        }
    }

    /// Extract size from overlay [`HostBounds`] (negative axes → 0).
    pub const fn from_host_bounds(bounds: HostBounds) -> Self {
        Self {
            width: if bounds.width > 0 {
                bounds.width as u32
            } else {
                0
            },
            height: if bounds.height > 0 {
                bounds.height as u32
            } else {
                0
            },
        }
    }
}

/// Hook invoked when a debounced size should be applied (no Connect).
///
/// Production will map this to `UpdateSessionDisplaySettings` / VM
/// `UpdateRemoteResolution`; tests record calls.
pub trait ApplyDesktopSize {
    /// Apply (or record) the coalesced desktop size.
    fn apply_desktop_size(&mut self, size: DesktopSize);
}

impl<F> ApplyDesktopSize for F
where
    F: FnMut(DesktopSize),
{
    fn apply_desktop_size(&mut self, size: DesktopSize) {
        self(size);
    }
}

/// Caller-supplied monotonic time for debounce deadlines (fake clock in tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MonoTime(Duration);

impl MonoTime {
    /// Epoch / test origin.
    pub const ZERO: Self = Self(Duration::ZERO);

    /// Construct from whole milliseconds.
    pub const fn from_millis(ms: u64) -> Self {
        Self(Duration::from_millis(ms))
    }

    /// Construct from a [`Duration`] since an arbitrary origin.
    pub const fn from_duration(d: Duration) -> Self {
        Self(d)
    }

    /// Elapsed duration since the arbitrary origin.
    pub const fn as_duration(self) -> Duration {
        self.0
    }

    /// Saturating add (used for deadline = now + delay).
    pub fn saturating_add(self, delay: Duration) -> Self {
        Self(self.0.saturating_add(delay))
    }
}

/// Coalesces rapid desktop-size updates; last-wins; trailing-edge delay.
///
/// # Semantics
///
/// - [`push`](Self::push) / [`push_physical`](Self::push_physical) /
///   [`push_host_bounds`](Self::push_host_bounds) replace any pending size and
///   restart the quiet timer (last-wins).
/// - Degenerate sizes (`width` or `height` == 0) are ignored (no schedule).
/// - [`poll`](Self::poll) emits when `now >= due_at`, then records the size so
///   identical follow-ups are skipped until a different size is pushed.
/// - [`flush`](Self::flush) emits the pending size immediately (still deduped
///   against the last emitted size).
/// - [`cancel`](Self::cancel) / [`Drop`] discard pending without emitting
///   (Drop never flushes — would commit [`last_emitted`](Self::last_emitted)
///   even without an [`ApplyDesktopSize`] sink).
/// - [`due_at`](Self::due_at) exposes the quiet-period deadline for tests /
///   diagnostics; [`flush`](Self::flush) always clears it.
///
/// Does **not** call Connect or touch the OCX.
#[derive(Debug)]
pub struct ResolutionDebouncer {
    delay: Duration,
    pending: Option<DesktopSize>,
    due_at: Option<MonoTime>,
    last_emitted: Option<DesktopSize>,
}

impl ResolutionDebouncer {
    /// Create a debouncer with the given quiet period.
    ///
    /// `Duration::ZERO` (see [`instant`](Self::instant)) emits on push when the
    /// size differs from the last emitted value.
    pub const fn new(delay: Duration) -> Self {
        Self {
            delay,
            pending: None,
            due_at: None,
            last_emitted: None,
        }
    }

    /// Debouncer with [`RESOLUTION_DEBOUNCE_DEFAULT`] (250 ms).
    pub const fn with_default_delay() -> Self {
        Self::new(RESOLUTION_DEBOUNCE_DEFAULT)
    }

    /// Instant mode: zero delay; a changing size emits from [`push`](Self::push).
    pub const fn instant() -> Self {
        Self::new(Duration::ZERO)
    }

    /// Configured quiet period.
    pub const fn delay(&self) -> Duration {
        self.delay
    }

    /// Pending size waiting for the quiet period (if any).
    pub const fn pending(&self) -> Option<DesktopSize> {
        self.pending
    }

    /// True when a size is scheduled and not yet emitted / cancelled.
    pub const fn is_pending(&self) -> bool {
        self.pending.is_some()
    }

    /// Last size successfully emitted via poll / flush / instant push.
    pub const fn last_emitted(&self) -> Option<DesktopSize> {
        self.last_emitted
    }

    /// Scheduled quiet-period deadline, if any.
    pub const fn due_at(&self) -> Option<MonoTime> {
        self.due_at
    }

    /// Forget the last emitted size so the next matching push can emit again
    /// (e.g. after Connected / AutoReconnected — C# clears negotiated cache).
    pub fn reset_last_emitted(&mut self) {
        self.last_emitted = None;
    }

    /// Schedule `size` (last-wins). Returns `Some` when instant mode emits now.
    pub fn push(&mut self, size: DesktopSize, now: MonoTime) -> Option<DesktopSize> {
        if size.is_degenerate() {
            return None;
        }
        self.pending = Some(size);
        if self.delay.is_zero() {
            return self.flush();
        }
        self.due_at = Some(now.saturating_add(self.delay));
        None
    }

    /// Schedule size from [`PhysicalBounds`] (width/height only).
    pub fn push_physical(&mut self, bounds: PhysicalBounds, now: MonoTime) -> Option<DesktopSize> {
        self.push(DesktopSize::from_physical(bounds), now)
    }

    /// Schedule size from [`HostBounds`] (width/height only).
    pub fn push_host_bounds(&mut self, bounds: HostBounds, now: MonoTime) -> Option<DesktopSize> {
        self.push(DesktopSize::from_host_bounds(bounds), now)
    }

    /// Emit pending size if the quiet period has elapsed.
    pub fn poll(&mut self, now: MonoTime) -> Option<DesktopSize> {
        let due = self.due_at?;
        if now < due {
            return None;
        }
        self.flush()
    }

    /// Emit pending size immediately (deduped against last emitted).
    ///
    /// Always clears [`due_at`](Self::due_at) so a flush/poll race cannot leave
    /// a stale deadline that would make a later empty `poll` keep retrying.
    pub fn flush(&mut self) -> Option<DesktopSize> {
        self.due_at = None;
        let size = self.pending.take()?;
        if self.last_emitted == Some(size) {
            return None;
        }
        self.last_emitted = Some(size);
        Some(size)
    }

    /// Discard pending without emitting (also clears the quiet-period deadline).
    pub fn cancel(&mut self) {
        self.pending = None;
        self.due_at = None;
    }

    /// [`poll`](Self::poll) then invoke [`ApplyDesktopSize`] when a size emits.
    pub fn poll_apply<A: ApplyDesktopSize + ?Sized>(&mut self, now: MonoTime, sink: &mut A) {
        if let Some(size) = self.poll(now) {
            sink.apply_desktop_size(size);
        }
    }

    /// [`flush`](Self::flush) then invoke [`ApplyDesktopSize`] when a size emits.
    pub fn flush_apply<A: ApplyDesktopSize + ?Sized>(&mut self, sink: &mut A) {
        if let Some(size) = self.flush() {
            sink.apply_desktop_size(size);
        }
    }

    /// Instant-mode / push path: apply through the hook when push emits.
    pub fn push_apply<A: ApplyDesktopSize + ?Sized>(
        &mut self,
        size: DesktopSize,
        now: MonoTime,
        sink: &mut A,
    ) {
        if let Some(emitted) = self.push(size, now) {
            sink.apply_desktop_size(emitted);
        }
    }
}

impl Default for ResolutionDebouncer {
    fn default() -> Self {
        Self::with_default_delay()
    }
}

impl Drop for ResolutionDebouncer {
    fn drop(&mut self) {
        // Cancel-on-drop (C# stops `_resolutionTimer` on Unloaded): never flush
        // a pending size. Drop has no [`ApplyDesktopSize`] sink — cancel keeps
        // the contract explicit so a mistaken flush-on-drop cannot be "fixed"
        // by discarding a returned `Some` while still mutating `last_emitted`.
        self.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn size(w: u32, h: u32) -> DesktopSize {
        DesktopSize::new(w, h)
    }

    #[test]
    fn default_delay_is_250ms() {
        assert_eq!(
            ResolutionDebouncer::with_default_delay().delay(),
            RESOLUTION_DEBOUNCE_DEFAULT
        );
        assert_eq!(
            ResolutionDebouncer::default().delay(),
            Duration::from_millis(250)
        );
        assert_eq!(RESOLUTION_DEBOUNCE_DEFAULT, Duration::from_millis(250));
    }

    #[test]
    fn coalesce_last_wins_before_deadline() {
        let mut d = ResolutionDebouncer::new(Duration::from_millis(250));
        let t0 = MonoTime::ZERO;
        assert!(d.push(size(800, 600), t0).is_none());
        assert!(d.push(size(1024, 768), MonoTime::from_millis(50)).is_none());
        assert!(d.push(size(1920, 1080), MonoTime::from_millis(100)).is_none());
        assert_eq!(d.pending(), Some(size(1920, 1080)));
        // Still inside the *restarted* window from t=100.
        assert!(d.poll(MonoTime::from_millis(300)).is_none());
        assert_eq!(d.poll(MonoTime::from_millis(350)), Some(size(1920, 1080)));
        assert!(!d.is_pending());
        assert_eq!(d.last_emitted(), Some(size(1920, 1080)));
    }

    #[test]
    fn poll_before_due_returns_none() {
        let mut d = ResolutionDebouncer::new(Duration::from_millis(100));
        d.push(size(640, 480), MonoTime::from_millis(0));
        assert_eq!(d.due_at(), Some(MonoTime::from_millis(100)));
        assert!(d.poll(MonoTime::from_millis(99)).is_none());
        assert_eq!(d.poll(MonoTime::from_millis(100)), Some(size(640, 480)));
        assert!(d.due_at().is_none());
    }

    #[test]
    fn flush_emits_pending_early() {
        let mut d = ResolutionDebouncer::new(Duration::from_millis(250));
        d.push(size(1280, 800), MonoTime::ZERO);
        assert_eq!(d.flush(), Some(size(1280, 800)));
        assert!(!d.is_pending());
        assert!(d.due_at().is_none());
        assert!(d.flush().is_none());
    }

    #[test]
    fn flush_then_poll_does_not_double_emit() {
        let mut d = ResolutionDebouncer::new(Duration::from_millis(250));
        d.push(size(800, 600), MonoTime::ZERO);
        assert_eq!(d.flush(), Some(size(800, 600)));
        // Fake clock past the original deadline — must not re-emit.
        assert!(d.poll(MonoTime::from_millis(10_000)).is_none());
        assert_eq!(d.last_emitted(), Some(size(800, 600)));
    }

    #[test]
    fn poll_then_flush_does_not_double_emit() {
        let mut d = ResolutionDebouncer::new(Duration::from_millis(50));
        d.push(size(1024, 768), MonoTime::ZERO);
        assert_eq!(d.poll(MonoTime::from_millis(50)), Some(size(1024, 768)));
        assert!(d.flush().is_none());
        assert!(d.poll(MonoTime::from_millis(10_000)).is_none());
    }

    #[test]
    fn flush_and_poll_dedup_identical_size() {
        let mut d = ResolutionDebouncer::new(Duration::from_millis(10));
        d.push(size(800, 600), MonoTime::ZERO);
        assert_eq!(d.flush(), Some(size(800, 600)));
        d.push(size(800, 600), MonoTime::from_millis(1));
        assert!(d.is_pending());
        assert!(d.flush().is_none());
        d.reset_last_emitted();
        d.push(size(800, 600), MonoTime::from_millis(2));
        assert_eq!(d.flush(), Some(size(800, 600)));
    }

    #[test]
    fn cancel_clears_pending_without_emit() {
        let mut d = ResolutionDebouncer::new(Duration::from_millis(250));
        d.push(size(800, 600), MonoTime::ZERO);
        d.cancel();
        assert!(!d.is_pending());
        assert!(d.due_at().is_none());
        assert!(d.flush().is_none());
        assert!(d.poll(MonoTime::from_millis(1000)).is_none());
        assert!(d.last_emitted().is_none());
    }

    #[test]
    fn cancel_matches_drop_contract_no_last_emitted() {
        // Drop must cancel, not flush: flush would commit last_emitted even
        // without an ApplyDesktopSize sink.
        let mut d = ResolutionDebouncer::new(Duration::from_millis(10));
        d.push(size(1024, 768), MonoTime::ZERO);
        assert!(d.last_emitted().is_none());
        d.cancel();
        assert!(d.last_emitted().is_none());
        assert!(!d.is_pending());
    }

    #[test]
    fn cancel_on_drop_does_not_apply_or_commit() {
        let mut applied: Vec<DesktopSize> = Vec::new();
        {
            let mut d = ResolutionDebouncer::new(Duration::from_millis(10));
            d.push_apply(size(1024, 768), MonoTime::ZERO, &mut |s| applied.push(s));
            assert!(d.is_pending());
            assert_eq!(d.due_at(), Some(MonoTime::from_millis(10)));
            // Pending is overdue on a fake clock past due_at, but we never poll —
            // Drop must cancel (not flush/apply).
            drop(d);
        }
        assert!(applied.is_empty());
    }

    #[test]
    fn instant_mode_emits_on_push() {
        let mut d = ResolutionDebouncer::instant();
        assert_eq!(d.delay(), Duration::ZERO);
        assert_eq!(d.push(size(640, 480), MonoTime::ZERO), Some(size(640, 480)));
        assert!(!d.is_pending());
        assert!(d.due_at().is_none());
        // Identical size suppressed.
        assert!(d.push(size(640, 480), MonoTime::from_millis(1)).is_none());
        assert_eq!(
            d.push(size(800, 600), MonoTime::from_millis(2)),
            Some(size(800, 600))
        );
    }

    #[test]
    fn apply_desktop_size_hook_on_poll() {
        let mut d = ResolutionDebouncer::new(Duration::from_millis(50));
        let mut got = None;
        d.push(size(1600, 900), MonoTime::ZERO);
        d.poll_apply(MonoTime::from_millis(49), &mut |s| got = Some(s));
        assert!(got.is_none());
        d.poll_apply(MonoTime::from_millis(50), &mut |s| got = Some(s));
        assert_eq!(got, Some(size(1600, 900)));
    }

    #[test]
    fn flush_apply_dedup_skips_sink() {
        let mut d = ResolutionDebouncer::new(Duration::from_millis(10));
        let mut n = 0usize;
        d.push(size(800, 600), MonoTime::ZERO);
        d.flush_apply(&mut |_| n += 1);
        assert_eq!(n, 1);
        d.push(size(800, 600), MonoTime::from_millis(1));
        d.flush_apply(&mut |_| n += 1);
        assert_eq!(n, 1);
    }

    #[test]
    fn push_physical_and_host_bounds() {
        let mut d = ResolutionDebouncer::instant();
        let phys = PhysicalBounds {
            x: 10,
            y: 20,
            width: 900,
            height: 700,
            dpi: 144,
        };
        assert_eq!(
            d.push_physical(phys, MonoTime::ZERO),
            Some(DesktopSize::new(900, 700))
        );
        d.reset_last_emitted();
        assert_eq!(
            d.push_host_bounds(HostBounds::new(1, 2, 640, 480), MonoTime::ZERO),
            Some(DesktopSize::new(640, 480))
        );
    }

    #[test]
    fn degenerate_sizes_ignored() {
        let mut d = ResolutionDebouncer::new(Duration::from_millis(10));
        assert!(d.push(size(0, 480), MonoTime::ZERO).is_none());
        assert!(d.push(size(640, 0), MonoTime::ZERO).is_none());
        assert!(d.push(size(0, 0), MonoTime::ZERO).is_none());
        assert!(!d.is_pending());
        assert!(d
            .push_host_bounds(HostBounds::new(0, 0, -1, 100), MonoTime::ZERO)
            .is_none());
        assert!(d
            .push_host_bounds(HostBounds::new(0, 0, i32::MIN, i32::MIN), MonoTime::ZERO)
            .is_none());
        // Zero physical axes — no panic, no schedule.
        assert!(d
            .push_physical(
                PhysicalBounds {
                    x: 0,
                    y: 0,
                    width: 0,
                    height: 0,
                    dpi: 96,
                },
                MonoTime::ZERO
            )
            .is_none());
    }

    #[test]
    fn degenerate_push_does_not_clobber_pending() {
        let mut d = ResolutionDebouncer::new(Duration::from_millis(100));
        d.push(size(800, 600), MonoTime::ZERO);
        assert!(d.push(size(0, 600), MonoTime::from_millis(10)).is_none());
        assert_eq!(d.pending(), Some(size(800, 600)));
        assert_eq!(d.poll(MonoTime::from_millis(100)), Some(size(800, 600)));
    }

    #[test]
    fn push_apply_instant_invokes_trait() {
        let mut d = ResolutionDebouncer::instant();
        let mut got = None;
        d.push_apply(size(1280, 720), MonoTime::ZERO, &mut |s| got = Some(s));
        assert_eq!(got, Some(size(1280, 720)));
        // Degenerate must not invoke the sink.
        d.push_apply(size(0, 720), MonoTime::from_millis(1), &mut |_| {
            panic!("degenerate must not apply");
        });
    }

    #[test]
    fn mono_time_saturating_add_for_deadline() {
        let now = MonoTime::from_duration(Duration::MAX);
        let due = now.saturating_add(Duration::from_millis(250));
        assert_eq!(due, MonoTime::from_duration(Duration::MAX));
        let mut d = ResolutionDebouncer::new(Duration::from_millis(250));
        assert!(d.push(size(640, 480), now).is_none());
        assert_eq!(d.poll(due), Some(size(640, 480)));
    }
}
