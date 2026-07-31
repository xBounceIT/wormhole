//! Layout size → [`ResolutionDebouncer`] → RDP surface Fake (no OCX).
//!
//! Thin glue mirroring C# `RdpSurfaceHost.ApplyLayout` →
//! `ScheduleResolutionRefresh` → `ApplyResolution` → `UpdateRemoteResolution`,
//! without Connect / `UpdateSessionDisplaySettings`. The existing
//! [`ResolutionDebouncer`] is wired, not rewritten.
//!
//! Layout ticks may arrive faster than the quiet period; the debouncer
//! coalesces last-wins. Callers drive time via [`MonoTime`] (fake clock in tests).

use crate::PhysicalBounds;

use super::host_bounds::HostBounds;
use super::resolution::{
    ApplyDesktopSize, DesktopSize, MonoTime, ResolutionDebouncer, RESOLUTION_DEBOUNCE_DEFAULT,
};

/// C# `HostBounds.IsDegenerate()` default (`minDim: 8`) used by `ApplyLayout`
/// before scheduling a resolution refresh. Seed `1×1` and sub-8 px slots skip.
pub const LAYOUT_RESOLUTION_MIN_DIM: u32 = 8;

/// Fail-closed convert of layout float axes → [`DesktopSize`].
///
/// Rejects non-finite (NaN / ±∞), negative, and values that round above
/// `u32::MAX`. Zero after rounding yields [`None`] (degenerate). Integer layout
/// paths never hit this — use [`DesktopSize::from_physical`] /
/// [`DesktopSize::from_host_bounds`] instead.
pub fn desktop_size_from_layout_f64(width: f64, height: f64) -> Option<DesktopSize> {
    let w = finite_axis_to_u32(width)?;
    let h = finite_axis_to_u32(height)?;
    let size = DesktopSize::new(w, h);
    if size.is_degenerate() {
        return None;
    }
    Some(size)
}

fn finite_axis_to_u32(v: f64) -> Option<u32> {
    if !v.is_finite() || v < 0.0 {
        return None;
    }
    let rounded = v.round();
    if rounded > f64::from(u32::MAX) {
        return None;
    }
    // rounded is finite, ≥ 0, ≤ u32::MAX
    Some(rounded as u32)
}

/// Stand-in for a live RDP surface's `UpdateRemoteResolution` / OCX apply.
///
/// Records coalesced desktop sizes; never touches COM / Connect.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FakeRdpResizeSurface {
    applied: Vec<DesktopSize>,
}

impl FakeRdpResizeSurface {
    /// Empty Fake (no applies yet).
    pub const fn new() -> Self {
        Self {
            applied: Vec::new(),
        }
    }

    /// All sizes applied through [`ApplyDesktopSize`], in order.
    pub fn applied(&self) -> &[DesktopSize] {
        &self.applied
    }

    /// Most recent applied size, if any.
    pub fn last_applied(&self) -> Option<DesktopSize> {
        self.applied.last().copied()
    }

    /// Number of applies (tests / diagnostics).
    pub fn apply_count(&self) -> usize {
        self.applied.len()
    }

    /// Clear recorded applies (does not touch the debouncer).
    pub fn clear(&mut self) {
        self.applied.clear();
    }
}

impl ApplyDesktopSize for FakeRdpResizeSurface {
    fn apply_desktop_size(&mut self, size: DesktopSize) {
        self.applied.push(size);
    }
}

/// Pane / broker layout size change → debounce → [`ApplyDesktopSize`] sink.
///
/// Default sink is [`FakeRdpResizeSurface`]. Production will swap in a hook that
/// calls `UpdateSessionDisplaySettings` once a Connected session exists.
#[derive(Debug)]
pub struct RdpResolutionLayoutGlue<S: ApplyDesktopSize = FakeRdpResizeSurface> {
    debouncer: ResolutionDebouncer,
    surface: S,
    /// Skip schedule when either axis is below this (C# layout `IsDegenerate(8)`).
    min_dim: u32,
}

impl RdpResolutionLayoutGlue<FakeRdpResizeSurface> {
    /// Glue with default 250 ms debounce and an empty Fake surface.
    pub fn with_fake() -> Self {
        Self::new(FakeRdpResizeSurface::new())
    }

    /// Instant-mode glue (zero delay) + Fake — useful for unit tests.
    pub fn with_fake_instant() -> Self {
        Self::with_debouncer(ResolutionDebouncer::instant(), FakeRdpResizeSurface::new())
    }
}

impl<S: ApplyDesktopSize> RdpResolutionLayoutGlue<S> {
    /// Wrap `surface` with [`ResolutionDebouncer::with_default_delay`].
    pub fn new(surface: S) -> Self {
        Self::with_debouncer(ResolutionDebouncer::with_default_delay(), surface)
    }

    /// Wrap an existing debouncer (e.g. [`ResolutionDebouncer::instant`]) + sink.
    pub fn with_debouncer(debouncer: ResolutionDebouncer, surface: S) -> Self {
        Self {
            debouncer,
            surface,
            min_dim: LAYOUT_RESOLUTION_MIN_DIM,
        }
    }

    /// Override layout min dimension (tests). Default [`LAYOUT_RESOLUTION_MIN_DIM`].
    pub fn with_min_dim(mut self, min_dim: u32) -> Self {
        self.min_dim = min_dim;
        self
    }

    /// Configured quiet period.
    pub fn delay(&self) -> std::time::Duration {
        self.debouncer.delay()
    }

    /// Default delay constant (250 ms) — same as the owned debouncer default.
    pub const fn default_delay() -> std::time::Duration {
        RESOLUTION_DEBOUNCE_DEFAULT
    }

    /// Layout min-dimension gate.
    pub fn min_dim(&self) -> u32 {
        self.min_dim
    }

    /// Pending coalesced size (not yet applied), if any.
    pub fn pending(&self) -> Option<DesktopSize> {
        self.debouncer.pending()
    }

    /// True when a size is scheduled and not yet emitted / cancelled.
    pub fn is_pending(&self) -> bool {
        self.debouncer.is_pending()
    }

    /// Quiet-period deadline, if scheduled.
    pub fn due_at(&self) -> Option<MonoTime> {
        self.debouncer.due_at()
    }

    /// Last size applied to the sink (via poll / flush / instant push).
    pub fn last_emitted(&self) -> Option<DesktopSize> {
        self.debouncer.last_emitted()
    }

    /// Borrow the surface sink (Fake applied list, etc.).
    pub fn surface(&self) -> &S {
        &self.surface
    }

    /// Mutably borrow the surface sink.
    pub fn surface_mut(&mut self) -> &mut S {
        &mut self.surface
    }

    /// Borrow the inner debouncer (tests / diagnostics).
    pub fn debouncer(&self) -> &ResolutionDebouncer {
        &self.debouncer
    }

    /// Push a layout desktop size. Returns `true` when scheduled or instant-applied.
    ///
    /// Fail-closed: axes below [`Self::min_dim`] or degenerate (`0`) do not
    /// schedule and do **not** cancel an existing pending size (C# `ApplyLayout`
    /// early-return).
    pub fn on_layout_size(&mut self, size: DesktopSize, now: MonoTime) -> bool {
        if size.width < self.min_dim || size.height < self.min_dim {
            return false;
        }
        if size.is_degenerate() {
            return false;
        }
        if let Some(emitted) = self.debouncer.push(size, now) {
            self.surface.apply_desktop_size(emitted);
            return true;
        }
        self.debouncer.is_pending()
    }

    /// Push size from broker [`PhysicalBounds`] (width/height only).
    pub fn on_layout_physical(&mut self, bounds: PhysicalBounds, now: MonoTime) -> bool {
        self.on_layout_size(DesktopSize::from_physical(bounds), now)
    }

    /// Push size from overlay [`HostBounds`] (negative axes → 0 via conversion).
    pub fn on_layout_host_bounds(&mut self, bounds: HostBounds, now: MonoTime) -> bool {
        // Match C# ApplyLayout: skip when below min_dim before scheduling.
        if bounds.is_degenerate(self.min_dim as i32) {
            return false;
        }
        self.on_layout_size(DesktopSize::from_host_bounds(bounds), now)
    }

    /// Push size from float layout axes (NaN / ∞ / negative / overflow → fail-closed).
    ///
    /// Fail-closed paths return `false` and do **not** cancel an existing pending size.
    pub fn on_layout_f64(&mut self, width: f64, height: f64, now: MonoTime) -> bool {
        match desktop_size_from_layout_f64(width, height) {
            Some(size) => self.on_layout_size(size, now),
            None => false,
        }
    }

    /// Emit when the quiet period has elapsed; applies to the surface.
    pub fn poll(&mut self, now: MonoTime) -> Option<DesktopSize> {
        let size = self.debouncer.poll(now)?;
        self.surface.apply_desktop_size(size);
        Some(size)
    }

    /// Emit pending immediately; applies to the surface when not deduped.
    pub fn flush(&mut self) -> Option<DesktopSize> {
        let size = self.debouncer.flush()?;
        self.surface.apply_desktop_size(size);
        Some(size)
    }

    /// Discard pending without applying (teardown / Unloaded parity).
    pub fn cancel(&mut self) {
        self.debouncer.cancel();
    }

    /// Clear last-emitted cache after Connected / AutoReconnected so the same
    /// size can renegotiate (C# clears `_lastNegotiated*`).
    pub fn on_connected_reset(&mut self) {
        self.debouncer.reset_last_emitted();
    }

    /// Consume glue into debouncer + surface.
    pub fn into_parts(self) -> (ResolutionDebouncer, S) {
        (self.debouncer, self.surface)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn size(w: u32, h: u32) -> DesktopSize {
        DesktopSize::new(w, h)
    }

    #[test]
    fn fake_records_poll_apply() {
        let mut g = RdpResolutionLayoutGlue::with_fake();
        assert_eq!(g.delay(), Duration::from_millis(250));
        assert_eq!(g.min_dim(), LAYOUT_RESOLUTION_MIN_DIM);

        assert!(g.on_layout_size(size(800, 600), MonoTime::ZERO));
        assert_eq!(g.pending(), Some(size(800, 600)));
        assert_eq!(g.surface().apply_count(), 0);

        assert!(g.poll(MonoTime::from_millis(249)).is_none());
        assert_eq!(g.poll(MonoTime::from_millis(250)), Some(size(800, 600)));
        assert_eq!(g.surface().applied(), &[size(800, 600)]);
        assert_eq!(g.surface().last_applied(), Some(size(800, 600)));
    }

    #[test]
    fn rapid_fire_coalesce_last_wins() {
        let mut g = RdpResolutionLayoutGlue::with_fake();
        assert!(g.on_layout_size(size(640, 480), MonoTime::ZERO));
        assert!(g.on_layout_size(size(800, 600), MonoTime::from_millis(20)));
        assert!(g.on_layout_size(size(1920, 1080), MonoTime::from_millis(40)));
        assert_eq!(g.pending(), Some(size(1920, 1080)));
        // Deadline restarted at t=40 → due at 290.
        assert!(g.poll(MonoTime::from_millis(280)).is_none());
        assert_eq!(g.poll(MonoTime::from_millis(290)), Some(size(1920, 1080)));
        assert_eq!(g.surface().apply_count(), 1);
        assert_eq!(g.surface().last_applied(), Some(size(1920, 1080)));
    }

    #[test]
    fn identical_size_still_restarts_quiet_deadline() {
        // C# ScheduleResolutionRefresh Stop/Start even when size is unchanged.
        let mut g = RdpResolutionLayoutGlue::with_fake();
        assert!(g.on_layout_size(size(800, 600), MonoTime::ZERO));
        assert!(g.on_layout_size(size(800, 600), MonoTime::from_millis(20)));
        assert_eq!(g.due_at(), Some(MonoTime::from_millis(270)));
        assert!(g.poll(MonoTime::from_millis(250)).is_none());
        assert_eq!(g.poll(MonoTime::from_millis(270)), Some(size(800, 600)));
        assert_eq!(g.surface().apply_count(), 1);
    }

    #[test]
    fn zero_and_below_min_dim_fail_closed() {
        let mut g = RdpResolutionLayoutGlue::with_fake();
        assert!(!g.on_layout_size(size(0, 600), MonoTime::ZERO));
        assert!(!g.on_layout_size(size(800, 0), MonoTime::ZERO));
        assert!(!g.on_layout_size(size(7, 600), MonoTime::ZERO)); // < 8
        assert!(!g.on_layout_size(size(800, 7), MonoTime::ZERO));
        assert!(!g.on_layout_size(size(8, 7), MonoTime::ZERO)); // exact boundary reject
        assert!(!g.is_pending());
        assert_eq!(g.surface().apply_count(), 0);

        // Exact LAYOUT_RESOLUTION_MIN_DIM × LAYOUT_RESOLUTION_MIN_DIM schedules.
        assert!(g.on_layout_size(
            size(LAYOUT_RESOLUTION_MIN_DIM, LAYOUT_RESOLUTION_MIN_DIM),
            MonoTime::ZERO
        ));
        assert_eq!(
            g.pending(),
            Some(size(LAYOUT_RESOLUTION_MIN_DIM, LAYOUT_RESOLUTION_MIN_DIM))
        );

        // Seed 1×1 must not schedule resolution.
        assert!(!g.on_layout_physical(
            PhysicalBounds {
                x: 0,
                y: 0,
                width: 1,
                height: 1,
                dpi: 96,
            },
            MonoTime::from_millis(1)
        ));
        // Sub-min / seed must not clobber the pending 8×8.
        assert_eq!(
            g.pending(),
            Some(size(LAYOUT_RESOLUTION_MIN_DIM, LAYOUT_RESOLUTION_MIN_DIM))
        );
    }

    #[test]
    fn degenerate_layout_does_not_clobber_pending() {
        let mut g = RdpResolutionLayoutGlue::with_fake();
        assert!(g.on_layout_size(size(1024, 768), MonoTime::ZERO));
        assert!(!g.on_layout_size(size(0, 768), MonoTime::from_millis(10)));
        assert!(!g.on_layout_size(size(7, 768), MonoTime::from_millis(20)));
        assert_eq!(g.pending(), Some(size(1024, 768)));
        assert_eq!(g.poll(MonoTime::from_millis(250)), Some(size(1024, 768)));
    }

    #[test]
    fn nan_inf_negative_f64_fail_closed() {
        assert!(desktop_size_from_layout_f64(f64::NAN, 600.0).is_none());
        assert!(desktop_size_from_layout_f64(800.0, f64::NAN).is_none());
        assert!(desktop_size_from_layout_f64(f64::INFINITY, 600.0).is_none());
        assert!(desktop_size_from_layout_f64(800.0, f64::NEG_INFINITY).is_none());
        assert!(desktop_size_from_layout_f64(-1.0, 600.0).is_none());
        assert!(desktop_size_from_layout_f64(800.0, -0.5).is_none());
        assert!(desktop_size_from_layout_f64(0.0, 600.0).is_none());
        assert!(desktop_size_from_layout_f64(f64::from(u32::MAX) + 1.0, 600.0).is_none());
        assert_eq!(
            desktop_size_from_layout_f64(800.4, 600.6),
            Some(size(800, 601))
        );
        // Sub-min after round is still a DesktopSize; glue min_dim rejects later.
        assert_eq!(desktop_size_from_layout_f64(7.4, 600.0), Some(size(7, 600)));

        let mut g = RdpResolutionLayoutGlue::with_fake();
        assert!(!g.on_layout_f64(f64::NAN, 600.0, MonoTime::ZERO));
        assert!(!g.on_layout_f64(800.0, f64::INFINITY, MonoTime::ZERO));
        assert!(g.on_layout_f64(1280.0, 720.0, MonoTime::ZERO));
        assert_eq!(g.pending(), Some(size(1280, 720)));
    }

    #[test]
    fn nan_inf_f64_does_not_clobber_pending() {
        let mut g = RdpResolutionLayoutGlue::with_fake();
        assert!(g.on_layout_size(size(1024, 768), MonoTime::ZERO));
        assert!(!g.on_layout_f64(f64::NAN, 768.0, MonoTime::from_millis(10)));
        assert!(!g.on_layout_f64(1024.0, f64::INFINITY, MonoTime::from_millis(20)));
        assert!(!g.on_layout_f64(-1.0, 768.0, MonoTime::from_millis(30)));
        assert!(!g.on_layout_f64(7.0, 768.0, MonoTime::from_millis(40))); // sub-min after convert
        assert_eq!(g.pending(), Some(size(1024, 768)));
        assert_eq!(g.poll(MonoTime::from_millis(250)), Some(size(1024, 768)));
        assert_eq!(g.surface().apply_count(), 1);
    }

    #[test]
    fn physical_and_host_bounds_paths() {
        let mut g = RdpResolutionLayoutGlue::with_fake_instant();
        assert!(g.on_layout_physical(
            PhysicalBounds {
                x: 10,
                y: 20,
                width: 900,
                height: 700,
                dpi: 144,
            },
            MonoTime::ZERO
        ));
        assert_eq!(g.surface().last_applied(), Some(size(900, 700)));

        g.on_connected_reset();
        assert!(g.on_layout_host_bounds(HostBounds::new(1, 2, 640, 480), MonoTime::ZERO));
        assert_eq!(g.surface().last_applied(), Some(size(640, 480)));

        // Negative host axes → degenerate after conversion; also fails min_dim.
        assert!(!g.on_layout_host_bounds(HostBounds::new(0, 0, -1, 100), MonoTime::ZERO));
        assert!(!g.on_layout_host_bounds(HostBounds::SEED, MonoTime::ZERO)); // 1×1 < 8
    }

    #[test]
    fn flush_applies_early_cancel_does_not() {
        let mut g = RdpResolutionLayoutGlue::with_fake();
        assert!(g.on_layout_size(size(1600, 900), MonoTime::ZERO));
        assert_eq!(g.flush(), Some(size(1600, 900)));
        assert_eq!(g.surface().apply_count(), 1);

        assert!(g.on_layout_size(size(800, 600), MonoTime::from_millis(1)));
        g.cancel();
        assert!(!g.is_pending());
        assert!(g.poll(MonoTime::from_millis(10_000)).is_none());
        assert_eq!(g.surface().apply_count(), 1);
    }

    #[test]
    fn flush_then_poll_does_not_double_apply_surface() {
        let mut g = RdpResolutionLayoutGlue::with_fake();
        assert!(g.on_layout_size(size(800, 600), MonoTime::ZERO));
        assert_eq!(g.flush(), Some(size(800, 600)));
        assert_eq!(g.surface().apply_count(), 1);
        // Past the original quiet deadline — must not re-apply to Fake.
        assert!(g.poll(MonoTime::from_millis(10_000)).is_none());
        assert_eq!(g.surface().applied(), &[size(800, 600)]);
    }

    #[test]
    fn cancel_on_drop_does_not_apply_pending() {
        // into_parts + drop debouncer (explicit cancel-on-drop contract).
        let mut g = RdpResolutionLayoutGlue::with_fake();
        assert!(g.on_layout_size(size(1024, 768), MonoTime::ZERO));
        assert!(g.is_pending());
        assert_eq!(g.surface().apply_count(), 0);
        let (debouncer, surface) = g.into_parts();
        drop(debouncer); // cancel-on-drop — never flush/apply
        assert_eq!(surface.apply_count(), 0);
        assert!(surface.last_applied().is_none());

        // Drop the whole glue while pending is overdue on the fake clock.
        let applied = std::rc::Rc::new(std::cell::RefCell::new(Vec::<DesktopSize>::new()));
        let sink = applied.clone();
        {
            let mut g = RdpResolutionLayoutGlue::with_debouncer(
                ResolutionDebouncer::new(Duration::from_millis(10)),
                move |s| sink.borrow_mut().push(s),
            );
            assert!(g.on_layout_size(size(1920, 1080), MonoTime::ZERO));
            assert_eq!(g.due_at(), Some(MonoTime::from_millis(10)));
            // Never poll past due — Drop must cancel, not apply.
            drop(g);
        }
        assert!(applied.borrow().is_empty());
    }

    #[test]
    fn connected_reset_allows_same_size_again() {
        let mut g = RdpResolutionLayoutGlue::with_fake_instant();
        assert!(g.on_layout_size(size(800, 600), MonoTime::ZERO));
        assert_eq!(g.surface().apply_count(), 1);
        // Identical suppressed.
        assert!(!g.on_layout_size(size(800, 600), MonoTime::from_millis(1)));
        assert_eq!(g.surface().apply_count(), 1);
        g.on_connected_reset();
        assert!(g.on_layout_size(size(800, 600), MonoTime::from_millis(2)));
        assert_eq!(g.surface().apply_count(), 2);
    }

    #[test]
    fn connected_reset_with_pending_identical_emits_on_poll() {
        // C# clears _lastNegotiated* on Connected while a debounce tick may still be armed.
        let mut g = RdpResolutionLayoutGlue::with_fake();
        assert!(g.on_layout_size(size(800, 600), MonoTime::ZERO));
        assert_eq!(g.poll(MonoTime::from_millis(250)), Some(size(800, 600)));
        assert_eq!(g.surface().apply_count(), 1);

        // Reschedule the same size (would dedupe without reset).
        assert!(g.on_layout_size(size(800, 600), MonoTime::from_millis(300)));
        assert!(g.is_pending());
        g.on_connected_reset();
        assert_eq!(
            g.poll(MonoTime::from_millis(550)),
            Some(size(800, 600))
        );
        assert_eq!(g.surface().apply_count(), 2);
        assert_eq!(g.surface().last_applied(), Some(size(800, 600)));
    }

    #[test]
    fn custom_min_dim_for_tests() {
        let mut g = RdpResolutionLayoutGlue::with_fake_instant().with_min_dim(1);
        assert!(g.on_layout_size(size(1, 1), MonoTime::ZERO));
        assert_eq!(g.surface().last_applied(), Some(size(1, 1)));
        assert!(!g.on_layout_size(size(0, 1), MonoTime::from_millis(1)));
    }
}
