//! Soak / benchmark harness stubs (no live sessions yet).
//!
//! The quad-pane stress uses a **local** layout model that mirrors
//! `wormhole_ui::WorkspaceState` / `MAX_PANES = 4` so this crate stays
//! independent of the GPUI shell crate while other migration streams land.
//!
//! Lifecycle glue (start / cancel / status / report + [`crate::FakeClock`])
//! lives in [`crate::runner`].

/// Planned multi-hour soak duration (placeholder for future ignored/live runs).
pub const SOAK_SESSION_HOURS: u64 = 8;

/// Hard cap matching `wormhole_ui::MAX_PANES` / migration plan (quad-split max).
pub const MAX_PANES: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PaneLayout {
    Single,
    VerticalSplit,
    HorizontalSplit,
    Quad,
}

impl PaneLayout {
    fn for_count(count: usize) -> Self {
        match count {
            0 | 1 => Self::Single,
            2 => Self::VerticalSplit,
            3 => Self::HorizontalSplit,
            _ => Self::Quad,
        }
    }
}

/// Minimal pane set for soak stress (ids stable across close — same contract as UI).
#[derive(Debug, Clone)]
struct StressWorkspace {
    panes: Vec<u8>,
    focused: u8,
    layout: PaneLayout,
}

impl StressWorkspace {
    fn single() -> Self {
        Self {
            panes: vec![0],
            focused: 0,
            layout: PaneLayout::Single,
        }
    }

    fn split(&mut self) -> Result<u8, ()> {
        if self.panes.len() >= MAX_PANES {
            return Err(());
        }
        let next = (0..MAX_PANES as u8)
            .find(|id| !self.panes.contains(id))
            .expect("free pane slot exists when under MAX_PANES");
        self.panes.push(next);
        self.focused = next;
        self.layout = PaneLayout::for_count(self.panes.len());
        Ok(next)
    }

    fn close(&mut self, id: u8) -> Result<(), ()> {
        if self.panes.len() == 1 {
            return Err(());
        }
        let idx = self.panes.iter().position(|p| *p == id).ok_or(())?;
        self.panes.remove(idx);
        self.layout = PaneLayout::for_count(self.panes.len());
        if self.focused == id {
            let neighbor = idx.min(self.panes.len() - 1);
            self.focused = self.panes[neighbor];
        }
        Ok(())
    }
}

/// Fast unit stress: exercise split/close/focus up to the quad-pane layout.
///
/// Returns the number of successful split→close cycles completed.
pub fn quad_pane_layout_stress(iterations: usize) -> usize {
    let mut completed = 0usize;
    for _ in 0..iterations {
        let mut ws = StressWorkspace::single();
        assert_eq!(ws.layout, PaneLayout::Single);

        for expected_count in 2..=MAX_PANES {
            let id = ws.split().expect("split under MAX_PANES");
            assert_eq!(ws.panes.len(), expected_count);
            assert!(ws.panes.contains(&id));
            ws.focused = id;
        }
        assert_eq!(ws.layout, PaneLayout::Quad);
        assert_eq!(ws.panes.len(), MAX_PANES);
        assert!(ws.split().is_err(), "5th pane must be rejected");

        while ws.panes.len() > 1 {
            let victim = ws.panes[0];
            ws.close(victim).expect("close non-last pane");
        }
        assert_eq!(ws.panes.len(), 1);

        for _ in 0..(MAX_PANES - 1) {
            ws.split().expect("re-split");
        }
        assert_eq!(ws.layout, PaneLayout::Quad);
        completed += 1;
    }
    completed
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn quad_pane_layout_stress_is_fast() {
        let start = Instant::now();
        let n = quad_pane_layout_stress(256);
        assert_eq!(n, 256);
        // Pure state machine — must stay well under a second on CI agents.
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "quad-pane stress took {:?}",
            start.elapsed()
        );
    }

    /// Placeholder for an 8-hour live session soak (ignored — do not run in CI).
    ///
    /// Future: keep a GPUI shell + N sessions open for [`SOAK_SESSION_HOURS`],
    /// assert no panic / broker leak. Manual: `cargo test -p wormhole-diagnostics
    /// -- --ignored soak_eight_hour_session_placeholder`.
    #[test]
    #[ignore = "8h soak placeholder — enable manually when a live harness exists"]
    fn soak_eight_hour_session_placeholder() {
        let _hours = SOAK_SESSION_HOURS;
        // Stub: real soak will sleep / drive sessions for SOAK_SESSION_HOURS.
        // Intentionally empty so `--ignored` does not block a developer machine
        // for eight hours until the harness is wired.
        assert_eq!(SOAK_SESSION_HOURS, 8);
    }
}
