//! Stable session identity — allocated by the orchestrator, consumed by UI glue.

use uuid::Uuid;

/// Caller-facing identity for a live [`crate::SessionHandle`].
///
/// Distinct from connection-node UUIDs. Tab chrome maps this id 1:1 (see
/// `wormhole-app::session_tabs`); the UI crate keeps a parallel newtype and converts
/// via [`SessionId::as_uuid`] / [`SessionId::from_uuid`].
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_uuid_round_trips() {
        for u in [Uuid::nil(), Uuid::from_u128(u128::MAX), Uuid::new_v4()] {
            let id = SessionId::from_uuid(u);
            assert_eq!(id.as_uuid(), u);
            assert_eq!(SessionId::from(u), id);
            assert_eq!(SessionId(u), id);
            assert_eq!(id.to_string(), u.to_string());
        }
    }

    #[test]
    fn new_is_unique() {
        assert_ne!(SessionId::new(), SessionId::new());
    }

    #[test]
    fn debug_and_display_are_uuid_bits_only() {
        let id = SessionId::from_uuid(Uuid::from_u128(0xdead_beef));
        let dbg = format!("{id:?}");
        let display = id.to_string();
        assert!(dbg.contains(&display));
        assert!(!dbg.to_lowercase().contains("password"));
        assert!(!display.to_lowercase().contains("password"));
    }
}
