use uuid::Uuid;

use crate::tabs::TabStrip;
use crate::theme::{ThemeTokens, THEME};
use crate::workspace::{PaneId, WorkspaceState};
use crate::UiError;

/// Primary navigation regions in the left sidebar (mirrors WinUI nav).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SidebarRegion {
    Connections,
    Credentials,
    Sessions,
    Tunnels,
    Settings,
}

impl SidebarRegion {
    pub const ALL: [SidebarRegion; 5] = [
        Self::Connections,
        Self::Credentials,
        Self::Sessions,
        Self::Tunnels,
        Self::Settings,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Connections => "Connections",
            Self::Credentials => "Credentials",
            Self::Sessions => "Sessions",
            Self::Tunnels => "Tunnels",
            Self::Settings => "Settings",
        }
    }

    pub fn parse(name: &str) -> Result<Self, UiError> {
        match name {
            "Connections" => Ok(Self::Connections),
            "Credentials" => Ok(Self::Credentials),
            "Sessions" => Ok(Self::Sessions),
            "Tunnels" => Ok(Self::Tunnels),
            "Settings" => Ok(Self::Settings),
            _ => Err(UiError::InvalidSidebarRegion),
        }
    }
}

/// Top-level shell: sidebar selection + tab strip + multi-pane workspace.
#[derive(Debug, Clone)]
pub struct ShellState {
    pub sidebar: SidebarRegion,
    pub tabs: TabStrip,
    pub workspace: WorkspaceState,
    pub theme: ThemeTokens,
}

impl Default for ShellState {
    fn default() -> Self {
        Self::new()
    }
}

impl ShellState {
    pub fn new() -> Self {
        Self {
            sidebar: SidebarRegion::Connections,
            tabs: TabStrip::new(),
            workspace: WorkspaceState::single_pane(),
            theme: THEME,
        }
    }

    pub fn select_sidebar(&mut self, region: SidebarRegion) {
        self.sidebar = region;
    }

    /// Split the focused pane vertically at the default ratio (≤ [`crate::MAX_PANES`]).
    pub fn split_pane(&mut self) -> Result<PaneId, UiError> {
        self.workspace.split()
    }

    /// Split the focused pane along `axis` at `ratio` (NaN / ±Inf rejected; finite clamped).
    pub fn split_pane_directed(
        &mut self,
        axis: crate::SplitAxis,
        ratio: f32,
    ) -> Result<PaneId, UiError> {
        let target = self.workspace.focused();
        self.workspace.split_directed(target, axis, ratio)
    }

    /// Close a workspace pane (collapse its parent split) and clear tab assignments.
    pub fn close_pane(&mut self, id: PaneId) -> Result<(), UiError> {
        self.workspace.close_pane(id)?;
        self.tabs.clear_pane(id);
        Ok(())
    }

    /// Merge/unsplit `id` into its sibling — same tree op as [`Self::close_pane`].
    pub fn merge_pane(&mut self, id: PaneId) -> Result<(), UiError> {
        self.close_pane(id)
    }

    /// Adjust the parent-split ratio for `pane` (NaN / ±Inf rejected; finite clamped).
    pub fn set_split_ratio(&mut self, pane: PaneId, ratio: f32) -> Result<(), UiError> {
        self.workspace.set_split_ratio(pane, ratio)
    }

    /// Assign a tab to a pane that currently exists in the workspace.
    pub fn assign_tab_pane(&mut self, tab_id: Uuid, pane: PaneId) -> Result<(), UiError> {
        if !self.workspace.contains(pane) {
            return Err(UiError::UnknownPane(pane.0));
        }
        self.tabs.assign_pane(tab_id, pane)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sidebar_regions_round_trip() {
        for region in SidebarRegion::ALL {
            assert_eq!(SidebarRegion::parse(region.as_str()).unwrap(), region);
        }
        assert!(SidebarRegion::parse("Nope").is_err());
    }

    #[test]
    fn new_shell_defaults() {
        let shell = ShellState::new();
        assert_eq!(shell.sidebar, SidebarRegion::Connections);
        assert!(shell.tabs.is_empty());
        assert_eq!(shell.workspace.pane_count(), 1);
        assert_eq!(shell.theme, THEME);
    }

    #[test]
    fn close_pane_clears_tab_assignments() {
        let mut shell = ShellState::new();
        let p1 = shell.split_pane().unwrap();
        let p2 = shell.split_pane().unwrap();
        let tab = shell.tabs.open("VNC");
        shell.assign_tab_pane(tab, p2).unwrap();
        assert_eq!(shell.tabs.active_tab().unwrap().pane, Some(p2));

        shell.close_pane(p2).unwrap();
        assert_eq!(shell.tabs.tabs()[0].pane, None);
        assert!(shell.workspace.contains(p1));
        assert!(!shell.workspace.contains(p2));
    }

    #[test]
    fn assign_tab_rejects_unknown_pane() {
        let mut shell = ShellState::new();
        let tab = shell.tabs.open("SSH");
        assert_eq!(
            shell.assign_tab_pane(tab, PaneId(3)),
            Err(UiError::UnknownPane(3))
        );
    }

    #[test]
    fn pane_limit_through_shell() {
        let mut shell = ShellState::new();
        for _ in 0..3 {
            shell.split_pane().unwrap();
        }
        assert_eq!(shell.workspace.pane_count(), 4);
        assert!(shell.split_pane().is_err());
    }

    #[test]
    fn close_pane_then_resplit_does_not_revive_tab_assignment() {
        let mut shell = ShellState::new();
        let closed = shell.split_pane().unwrap();
        let tab = shell.tabs.open("SSH");
        shell.assign_tab_pane(tab, closed).unwrap();
        shell.close_pane(closed).unwrap();
        assert_eq!(shell.tabs.tabs()[0].pane, None);

        // Lowest free slot is reused — assignment must stay cleared (no silent revive).
        let reused = shell.split_pane().unwrap();
        assert_eq!(reused, closed);
        assert_eq!(shell.tabs.tabs()[0].pane, None);
        assert!(shell.workspace.pane_count() <= crate::MAX_PANES);
    }

    #[test]
    fn assign_after_close_rejects_stale_pane() {
        let mut shell = ShellState::new();
        let p = shell.split_pane().unwrap();
        let tab = shell.tabs.open("RDP");
        shell.close_pane(p).unwrap();
        assert_eq!(
            shell.assign_tab_pane(tab, p),
            Err(UiError::UnknownPane(p.0))
        );
    }

    #[test]
    fn directed_split_merge_and_ratio_through_shell() {
        use crate::pane_layout::{SplitAxis, SPLIT_RATIO_MAX};

        let mut shell = ShellState::new();
        let p1 = shell
            .split_pane_directed(SplitAxis::Horizontal, 0.95)
            .unwrap();
        assert_eq!(p1, PaneId(1));
        assert_eq!(
            shell.workspace.layout().ratio_for_pane(PaneId(0)),
            Some(SPLIT_RATIO_MAX)
        );
        shell.set_split_ratio(PaneId(1), 0.5).unwrap();
        assert_eq!(
            shell.workspace.layout().ratio_for_pane(PaneId(1)),
            Some(0.5)
        );
        for bad in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            assert_eq!(
                shell.split_pane_directed(SplitAxis::Vertical, bad),
                Err(UiError::InvalidSplitRatio)
            );
            assert_eq!(
                shell.set_split_ratio(PaneId(1), bad),
                Err(UiError::InvalidSplitRatio)
            );
        }
        assert_eq!(
            shell.workspace.layout().ratio_for_pane(PaneId(1)),
            Some(0.5)
        );
        assert_eq!(shell.workspace.pane_count(), 2);
        shell.merge_pane(p1).unwrap();
        assert_eq!(shell.workspace.pane_count(), 1);
        assert!(shell.tabs.tabs().iter().all(|t| t.pane != Some(p1)));
    }

    #[test]
    fn last_pane_close_does_not_clear_tab_assignment() {
        let mut shell = ShellState::new();
        let tab = shell.tabs.open("SSH");
        shell.assign_tab_pane(tab, PaneId(0)).unwrap();
        assert_eq!(shell.close_pane(PaneId(0)), Err(UiError::LastPane));
        assert_eq!(shell.merge_pane(PaneId(0)), Err(UiError::LastPane));
        assert_eq!(shell.tabs.tabs()[0].pane, Some(PaneId(0)));
        assert_eq!(shell.workspace.pane_count(), 1);
    }
}
