//! Session tab list state — pure Rust, no GPUI window required.
//!
//! Keys tabs by [`SessionId`] (caller-owned; typically the orchestrator's session id
//! converted via `wormhole_app::to_ui_session_id`). Distinct from [`crate::TabStrip`],
//! which owns generated tab UUIDs + pane assignment for shell chrome. This module is
//! **not** the GPUI-shipped tab strip.

use uuid::Uuid;
use wormhole_domain::ProtocolType;

use crate::UiError;

/// Stable identity for a live session tab.
///
/// Callers supply the id on open (orchestrator handle / future session registry). The tab
/// bar does not allocate ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(pub Uuid);

impl SessionId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub const fn from_uuid(id: Uuid) -> Self {
        Self(id)
    }

    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Uuid> for SessionId {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Soft-handle tab titles: drop Unicode control characters (NUL / C0 / C1 / DEL).
/// Empty input (or all-controls) stays empty — never rejected.
pub fn sanitize_session_tab_title(title: impl Into<String>) -> String {
    title
        .into()
        .chars()
        .filter(|c| !c.is_control())
        .collect()
}

/// Short protocol badge rendered on the tab chrome (SSH / RDP / …).
///
/// Mirrors session [`ProtocolType`] values (skips retired SFTP = 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolBadge {
    Ssh,
    Rdp,
    Http,
    Https,
    Serial,
    Vnc,
}

impl ProtocolBadge {
    pub const ALL: [ProtocolBadge; 6] = [
        Self::Ssh,
        Self::Rdp,
        Self::Http,
        Self::Https,
        Self::Serial,
        Self::Vnc,
    ];

    /// Compact label for the tab strip (e.g. `"SSH"`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ssh => "SSH",
            Self::Rdp => "RDP",
            Self::Http => "HTTP",
            Self::Https => "HTTPS",
            Self::Serial => "Serial",
            Self::Vnc => "VNC",
        }
    }

    pub const fn from_protocol(protocol: ProtocolType) -> Self {
        match protocol {
            ProtocolType::Ssh => Self::Ssh,
            ProtocolType::Rdp => Self::Rdp,
            ProtocolType::Http => Self::Http,
            ProtocolType::Https => Self::Https,
            ProtocolType::Serial => Self::Serial,
            ProtocolType::Vnc => Self::Vnc,
        }
    }

    pub const fn to_protocol(self) -> ProtocolType {
        match self {
            Self::Ssh => ProtocolType::Ssh,
            Self::Rdp => ProtocolType::Rdp,
            Self::Http => ProtocolType::Http,
            Self::Https => ProtocolType::Https,
            Self::Serial => ProtocolType::Serial,
            Self::Vnc => ProtocolType::Vnc,
        }
    }
}

impl From<ProtocolType> for ProtocolBadge {
    fn from(protocol: ProtocolType) -> Self {
        Self::from_protocol(protocol)
    }
}

impl From<ProtocolBadge> for ProtocolType {
    fn from(badge: ProtocolBadge) -> Self {
        badge.to_protocol()
    }
}

impl std::fmt::Display for ProtocolBadge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One row in the session tab list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTabModel {
    pub session_id: SessionId,
    pub title: String,
    pub badge: ProtocolBadge,
}

impl SessionTabModel {
    pub fn new(
        session_id: SessionId,
        title: impl Into<String>,
        badge: ProtocolBadge,
    ) -> Self {
        Self {
            session_id,
            title: sanitize_session_tab_title(title),
            badge,
        }
    }
}

/// Ordered session tab list with an optional active session.
#[derive(Debug, Clone, Default)]
pub struct SessionTabBarState {
    tabs: Vec<SessionTabModel>,
    active: Option<SessionId>,
}

impl SessionTabBarState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.tabs.is_empty()
    }

    pub fn len(&self) -> usize {
        self.tabs.len()
    }

    pub fn tabs(&self) -> &[SessionTabModel] {
        &self.tabs
    }

    pub fn active_id(&self) -> Option<SessionId> {
        self.active
    }

    pub fn get(&self, id: SessionId) -> Option<&SessionTabModel> {
        self.tabs.iter().find(|t| t.session_id == id)
    }

    pub fn active_tab(&self) -> Option<&SessionTabModel> {
        self.active.and_then(|id| self.get(id))
    }

    pub fn contains(&self, id: SessionId) -> bool {
        self.get(id).is_some()
    }

    /// Open a tab for `session_id`, activate it, and append to the strip.
    ///
    /// Fails with [`UiError::DuplicateSession`] if the id is already open.
    /// Titles are soft-sanitized (see [`sanitize_session_tab_title`]).
    pub fn open(
        &mut self,
        session_id: SessionId,
        title: impl Into<String>,
        badge: ProtocolBadge,
    ) -> Result<(), UiError> {
        if self.contains(session_id) {
            return Err(UiError::DuplicateSession(session_id.0));
        }
        self.tabs
            .push(SessionTabModel::new(session_id, title, badge));
        self.active = Some(session_id);
        Ok(())
    }

    pub fn activate(&mut self, id: SessionId) -> Result<(), UiError> {
        if !self.contains(id) {
            return Err(UiError::UnknownSession(id.0));
        }
        self.active = Some(id);
        Ok(())
    }

    /// Close the tab for `id`. If it was active, activate a neighbor (prefer the tab
    /// that slid into the same index, else the previous one).
    pub fn close(&mut self, id: SessionId) -> Result<(), UiError> {
        let idx = self
            .tabs
            .iter()
            .position(|t| t.session_id == id)
            .ok_or(UiError::UnknownSession(id.0))?;
        self.tabs.remove(idx);
        if self.active == Some(id) {
            self.active = if self.tabs.is_empty() {
                None
            } else {
                let neighbor = idx.min(self.tabs.len() - 1);
                Some(self.tabs[neighbor].session_id)
            };
        }
        Ok(())
    }

    /// Rename an open tab's title (badge / id unchanged). Soft-sanitized.
    pub fn set_title(&mut self, id: SessionId, title: impl Into<String>) -> Result<(), UiError> {
        let tab = self
            .tabs
            .iter_mut()
            .find(|t| t.session_id == id)
            .ok_or(UiError::UnknownSession(id.0))?;
        tab.title = sanitize_session_tab_title(title);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid() -> SessionId {
        SessionId::new()
    }

    #[test]
    fn open_activate_close_by_session_id() {
        let mut bar = SessionTabBarState::new();
        let a = sid();
        let b = sid();
        bar.open(a, "prod / web-1", ProtocolBadge::Ssh).unwrap();
        bar.open(b, "dc", ProtocolBadge::Rdp).unwrap();
        assert_eq!(bar.len(), 2);
        assert_eq!(bar.active_id(), Some(b));
        assert_eq!(bar.active_tab().unwrap().badge, ProtocolBadge::Rdp);

        bar.activate(a).unwrap();
        assert_eq!(bar.active_id(), Some(a));
        assert_eq!(bar.active_tab().unwrap().title, "prod / web-1");

        bar.close(a).unwrap();
        assert_eq!(bar.len(), 1);
        assert_eq!(bar.active_id(), Some(b));
        bar.close(b).unwrap();
        assert!(bar.is_empty());
        assert_eq!(bar.active_id(), None);
    }

    #[test]
    fn close_background_keeps_active() {
        let mut bar = SessionTabBarState::new();
        let a = sid();
        let b = sid();
        let c = sid();
        bar.open(a, "A", ProtocolBadge::Ssh).unwrap();
        bar.open(b, "B", ProtocolBadge::Vnc).unwrap();
        bar.open(c, "C", ProtocolBadge::Http).unwrap();
        bar.activate(b).unwrap();
        bar.close(a).unwrap();
        assert_eq!(bar.active_id(), Some(b));
        assert_eq!(bar.len(), 2);
        assert!(!bar.contains(a));
    }

    #[test]
    fn close_active_middle_selects_neighbor_at_index() {
        let mut bar = SessionTabBarState::new();
        let a = sid();
        let b = sid();
        let c = sid();
        bar.open(a, "A", ProtocolBadge::Ssh).unwrap();
        bar.open(b, "B", ProtocolBadge::Rdp).unwrap();
        bar.open(c, "C", ProtocolBadge::Serial).unwrap();
        bar.activate(b).unwrap();
        bar.close(b).unwrap();
        // Index 1 now holds former-C.
        assert_eq!(bar.active_id(), Some(c));
        assert_eq!(
            bar.tabs().iter().map(|t| t.session_id).collect::<Vec<_>>(),
            vec![a, c]
        );
    }

    #[test]
    fn close_active_first_selects_new_first() {
        let mut bar = SessionTabBarState::new();
        let a = sid();
        let b = sid();
        let c = sid();
        bar.open(a, "A", ProtocolBadge::Ssh).unwrap();
        bar.open(b, "B", ProtocolBadge::Rdp).unwrap();
        bar.open(c, "C", ProtocolBadge::Vnc).unwrap();
        bar.activate(a).unwrap();
        bar.close(a).unwrap();
        assert_eq!(bar.active_id(), Some(b));
        assert_eq!(
            bar.tabs().iter().map(|t| t.session_id).collect::<Vec<_>>(),
            vec![b, c]
        );
    }

    #[test]
    fn close_active_last_selects_previous() {
        let mut bar = SessionTabBarState::new();
        let a = sid();
        let b = sid();
        let c = sid();
        bar.open(a, "A", ProtocolBadge::Ssh).unwrap();
        bar.open(b, "B", ProtocolBadge::Rdp).unwrap();
        bar.open(c, "C", ProtocolBadge::Https).unwrap();
        // open leaves c active
        assert_eq!(bar.active_id(), Some(c));
        bar.close(c).unwrap();
        assert_eq!(bar.active_id(), Some(b));
        assert_eq!(
            bar.tabs().iter().map(|t| t.session_id).collect::<Vec<_>>(),
            vec![a, b]
        );
    }

    #[test]
    fn close_only_active_clears_selection() {
        let mut bar = SessionTabBarState::new();
        let a = sid();
        bar.open(a, "solo", ProtocolBadge::Serial).unwrap();
        bar.close(a).unwrap();
        assert!(bar.is_empty());
        assert_eq!(bar.active_id(), None);
        assert!(bar.active_tab().is_none());
    }

    #[test]
    fn duplicate_open_rejected() {
        let mut bar = SessionTabBarState::new();
        let id = sid();
        bar.open(id, "first", ProtocolBadge::Https).unwrap();
        let before = bar.clone();
        assert_eq!(
            bar.open(id, "again", ProtocolBadge::Ssh),
            Err(UiError::DuplicateSession(id.0))
        );
        assert_eq!(bar.len(), before.len());
        assert_eq!(bar.active_id(), before.active_id());
        assert_eq!(bar.active_tab().unwrap().title, "first");
        assert_eq!(bar.active_tab().unwrap().badge, ProtocolBadge::Https);
        assert_eq!(bar.tabs(), before.tabs());
    }

    #[test]
    fn unknown_session_errors_leave_state_unchanged() {
        let mut bar = SessionTabBarState::new();
        let kept = sid();
        bar.open(kept, "kept", ProtocolBadge::Ssh).unwrap();
        let before = bar.clone();
        let missing = sid();

        assert_eq!(
            bar.activate(missing),
            Err(UiError::UnknownSession(missing.0))
        );
        assert_eq!(bar.tabs(), before.tabs());
        assert_eq!(bar.active_id(), before.active_id());

        assert_eq!(
            bar.close(missing),
            Err(UiError::UnknownSession(missing.0))
        );
        assert_eq!(bar.tabs(), before.tabs());
        assert_eq!(bar.active_id(), before.active_id());

        assert_eq!(
            bar.set_title(missing, "x"),
            Err(UiError::UnknownSession(missing.0))
        );
        assert_eq!(bar.tabs(), before.tabs());
        assert_eq!(bar.get(kept).unwrap().title, "kept");
    }

    #[test]
    fn double_close_second_is_unknown() {
        let mut bar = SessionTabBarState::new();
        let id = sid();
        bar.open(id, "once", ProtocolBadge::Rdp).unwrap();
        bar.close(id).unwrap();
        assert_eq!(
            bar.close(id),
            Err(UiError::UnknownSession(id.0))
        );
        assert!(bar.is_empty());
        assert_eq!(bar.active_id(), None);
    }

    #[test]
    fn set_title_updates_model() {
        let mut bar = SessionTabBarState::new();
        let id = sid();
        bar.open(id, "old", ProtocolBadge::Ssh).unwrap();
        bar.set_title(id, "folder / new").unwrap();
        assert_eq!(bar.get(id).unwrap().title, "folder / new");
        assert_eq!(bar.get(id).unwrap().badge, ProtocolBadge::Ssh);
    }

    #[test]
    fn empty_and_hostile_titles_are_soft_handled() {
        let mut bar = SessionTabBarState::new();
        let empty_id = sid();
        let hostile_id = sid();

        bar.open(empty_id, "", ProtocolBadge::Http).unwrap();
        assert_eq!(bar.get(empty_id).unwrap().title, "");

        // NUL + C0 + DEL mixed with printable; soft-strip controls, keep text.
        bar.open(
            hostile_id,
            "a\0b\u{0007}c\u{007f}d\ne",
            ProtocolBadge::Vnc,
        )
        .unwrap();
        assert_eq!(bar.get(hostile_id).unwrap().title, "abcde");

        // All-controls → empty; never Err.
        bar.set_title(empty_id, "\0\u{001f}\u{0085}").unwrap();
        assert_eq!(bar.get(empty_id).unwrap().title, "");

        // Non-control Unicode (emoji / ZWJ / accents) preserved.
        bar.set_title(hostile_id, "café 🖥️").unwrap();
        assert_eq!(bar.get(hostile_id).unwrap().title, "café 🖥️");

        assert_eq!(
            sanitize_session_tab_title("x\ty\rz"),
            "xyz",
            "whitespace controls are stripped"
        );
    }

    #[test]
    fn protocol_badge_round_trips_protocol_type() {
        // Discriminants that ProtocolType accepts (retired SFTP=2 excluded).
        const PROTOCOL_DISCRIMINANTS: [i32; 6] = [0, 1, 3, 4, 5, 6];
        assert_eq!(ProtocolBadge::ALL.len(), PROTOCOL_DISCRIMINANTS.len());

        for &disc in &PROTOCOL_DISCRIMINANTS {
            let protocol = ProtocolType::try_from(disc).unwrap();
            let badge = ProtocolBadge::from_protocol(protocol);
            assert_eq!(badge.to_protocol(), protocol);
            assert_eq!(ProtocolBadge::from(protocol), badge);
            assert_eq!(ProtocolType::from(badge), protocol);
            assert!(
                ProtocolBadge::ALL.contains(&badge),
                "badge for discriminant {disc} missing from ALL"
            );
            assert!(!badge.as_str().is_empty());
        }

        assert!(ProtocolType::try_from(2).is_err(), "retired SFTP stays rejected");

        assert_eq!(
            ProtocolBadge::from(ProtocolType::Serial),
            ProtocolBadge::Serial
        );
        assert_eq!(ProtocolBadge::from(ProtocolType::Vnc), ProtocolBadge::Vnc);
        assert_eq!(ProtocolBadge::Serial.as_str(), "Serial");
        assert_eq!(ProtocolBadge::Vnc.as_str(), "VNC");
    }

    #[test]
    fn session_id_from_uuid() {
        let u = Uuid::nil();
        let id = SessionId::from_uuid(u);
        assert_eq!(id.as_uuid(), u);
        assert_eq!(SessionId::from(u), id);
        assert_eq!(id.to_string(), u.to_string());
    }
}
