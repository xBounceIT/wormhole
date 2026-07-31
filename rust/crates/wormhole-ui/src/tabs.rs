use uuid::Uuid;

use crate::workspace::PaneId;
use crate::UiError;

/// One session tab in the chrome strip (protocol details live elsewhere).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTab {
    pub id: Uuid,
    pub title: String,
    /// Pane that currently hosts this tab's surface (if assigned).
    pub pane: Option<PaneId>,
}

impl SessionTab {
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            title: title.into(),
            pane: None,
        }
    }
}

/// Ordered tab strip with an optional active tab.
#[derive(Debug, Clone, Default)]
pub struct TabStrip {
    tabs: Vec<SessionTab>,
    active: Option<Uuid>,
}

impl TabStrip {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.tabs.is_empty()
    }

    pub fn len(&self) -> usize {
        self.tabs.len()
    }

    pub fn tabs(&self) -> &[SessionTab] {
        &self.tabs
    }

    pub fn active_id(&self) -> Option<Uuid> {
        self.active
    }

    pub fn active_tab(&self) -> Option<&SessionTab> {
        let id = self.active?;
        self.tabs.iter().find(|t| t.id == id)
    }

    pub fn open(&mut self, title: impl Into<String>) -> Uuid {
        let tab = SessionTab::new(title);
        let id = tab.id;
        self.tabs.push(tab);
        self.active = Some(id);
        id
    }

    pub fn activate(&mut self, id: Uuid) -> Result<(), UiError> {
        if !self.tabs.iter().any(|t| t.id == id) {
            return Err(UiError::UnknownTab(id));
        }
        self.active = Some(id);
        Ok(())
    }

    pub fn close(&mut self, id: Uuid) -> Result<(), UiError> {
        let idx = self
            .tabs
            .iter()
            .position(|t| t.id == id)
            .ok_or(UiError::UnknownTab(id))?;
        self.tabs.remove(idx);
        if self.active == Some(id) {
            self.active = if self.tabs.is_empty() {
                None
            } else {
                let neighbor = idx.min(self.tabs.len() - 1);
                Some(self.tabs[neighbor].id)
            };
        }
        Ok(())
    }

    /// Assign a tab to a pane. Does **not** validate that `pane` exists in a workspace —
    /// prefer [`crate::ShellState::assign_tab_pane`] for coordinated updates.
    pub fn assign_pane(&mut self, id: Uuid, pane: PaneId) -> Result<(), UiError> {
        let tab = self
            .tabs
            .iter_mut()
            .find(|t| t.id == id)
            .ok_or(UiError::UnknownTab(id))?;
        tab.pane = Some(pane);
        Ok(())
    }

    /// Clear pane assignments that point at `pane` (after the workspace closes it).
    pub fn clear_pane(&mut self, pane: PaneId) {
        for tab in &mut self.tabs {
            if tab.pane == Some(pane) {
                tab.pane = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_activate_close() {
        let mut strip = TabStrip::new();
        let a = strip.open("SSH: box");
        let b = strip.open("RDP: dc");
        assert_eq!(strip.len(), 2);
        assert_eq!(strip.active_id(), Some(b));
        strip.activate(a).unwrap();
        assert_eq!(strip.active_id(), Some(a));
        strip.close(a).unwrap();
        assert_eq!(strip.len(), 1);
        assert_eq!(strip.active_id(), Some(b));
        strip.close(b).unwrap();
        assert!(strip.is_empty());
        assert_eq!(strip.active_id(), None);
    }

    #[test]
    fn clear_pane_only_matching() {
        let mut strip = TabStrip::new();
        let a = strip.open("A");
        let b = strip.open("B");
        strip.assign_pane(a, PaneId(1)).unwrap();
        strip.assign_pane(b, PaneId(2)).unwrap();
        strip.clear_pane(PaneId(1));
        assert_eq!(strip.tabs()[0].pane, None);
        assert_eq!(strip.tabs()[1].pane, Some(PaneId(2)));
    }

    #[test]
    fn close_unknown_and_activate_unknown() {
        let mut strip = TabStrip::new();
        let missing = Uuid::nil();
        assert_eq!(strip.close(missing), Err(UiError::UnknownTab(missing)));
        assert_eq!(strip.activate(missing), Err(UiError::UnknownTab(missing)));
    }
}
