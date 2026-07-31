//! Live SSH session registry Fake for MCP tools (pure Rust; no live MCP / SSH).
//!
//! Mirrors the *catalog surface* of C# `IMcpSessionRegistry` / `McpSessionRegistry`:
//! MCP tools may only see **already-open, connected** SSH sessions. There is no
//! tool to open a connection or read saved credentials.
//!
//! C# discovers sessions by scanning UI tabs (`IsMcpConnected`). This Lab Fake
//! instead exposes explicit [`FakeMcpSessionRegistry::register`] /
//! [`FakeMcpSessionRegistry::unregister`] so unit tests can seed ids without a
//! shell / GPUI host. Fail-closed on blank / control-char ids, non-Connected
//! register, duplicate register, and unknown unregister.
//!
//! **Not** Streamable HTTP, bearer mint, or command execution — those stay on
//! the host / tool stubs. Approval-gate Fake glue
//! ([`crate::FakeMcpToolApprovalGlue`]) optionally consumes this registry for
//! Connected eligibility before Approve/Deny/Cancel.

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;

use crate::McpError;

/// C# `SessionStatus` values exposed on `McpSessionInfo.Status` (`.ToString()`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum McpSessionStatus {
    Disconnected,
    Connecting,
    Connected,
    Failed,
}

impl McpSessionStatus {
    /// Stable C# enum name (MCP `list_sessions` status field).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disconnected => "Disconnected",
            Self::Connecting => "Connecting",
            Self::Connected => "Connected",
            Self::Failed => "Failed",
        }
    }

    pub const fn is_connected(self) -> bool {
        matches!(self, Self::Connected)
    }
}

impl fmt::Display for McpSessionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Metadata about a live SSH session exposed to MCP clients (C# `McpSessionInfo`).
///
/// Deliberately omits passwords, private keys, bearer tokens, and terminal
/// output so [`Debug`] cannot leak secrets.
#[derive(Clone, PartialEq, Eq)]
pub struct McpSessionInfo {
    pub id: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub title: String,
    pub status: McpSessionStatus,
}

impl McpSessionInfo {
    /// Construct a session row. `id` is validated on register (trim + fail-closed).
    pub fn new(
        id: impl Into<String>,
        host: impl Into<String>,
        port: u16,
        username: impl Into<String>,
        title: impl Into<String>,
        status: McpSessionStatus,
    ) -> Self {
        Self {
            id: id.into(),
            host: host.into(),
            port,
            username: username.into(),
            title: title.into(),
            status,
        }
    }

    /// Connected session helper (common Fake seed).
    pub fn connected(
        id: impl Into<String>,
        host: impl Into<String>,
        port: u16,
        username: impl Into<String>,
        title: impl Into<String>,
    ) -> Self {
        Self::new(id, host, port, username, title, McpSessionStatus::Connected)
    }
}

impl fmt::Debug for McpSessionInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("McpSessionInfo")
            .field("id", &self.id)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("title", &self.title)
            .field("status", &self.status.as_str())
            // Intentionally no token / password / terminal fields.
            .finish()
    }
}

/// DI surface for listing MCP-visible SSH sessions (C# `IMcpSessionRegistry.ListSessionsAsync`).
///
/// Lab Fake adds register/unregister; production will scan live tabs later.
pub trait McpSessionRegistry: Send + Sync {
    /// Connected sessions only (C# `IsMcpConnected` filter).
    fn list_sessions(&self) -> Vec<McpSessionInfo>;
}

/// Canonicalize + validate a session id (trim; reject blank / control chars).
///
/// Shared by the session registry Fake and the approval-gate glue.
pub fn canonicalize_session_id(raw: &str) -> Result<String, McpError> {
    let id = raw.trim();
    if id.is_empty() {
        return Err(McpError::Message("MCP session id is required".to_owned()));
    }
    if id.chars().any(|c| c.is_control()) {
        return Err(McpError::Message(
            "MCP session id contains control characters".to_owned(),
        ));
    }
    Ok(id.to_owned())
}

fn ensure_connected(info: &McpSessionInfo) -> Result<(), McpError> {
    if !info.status.is_connected() {
        return Err(McpError::Message(
            "That SSH session is not connected.".to_owned(),
        ));
    }
    Ok(())
}

/// In-memory Fake registry for unit tests / headless demos (no UI tabs, no SSH).
///
/// Register only **Connected** sessions; unregister by id. [`list_sessions`]
/// returns Connected rows in insertion order. [`Debug`] reports counts + ids
/// only — never bearer tokens or secrets.
#[derive(Default)]
pub struct FakeMcpSessionRegistry {
    inner: Mutex<FakeMcpSessionRegistryInner>,
}

#[derive(Default)]
struct FakeMcpSessionRegistryInner {
    /// Insertion-ordered ids; map holds the latest metadata per id.
    order: Vec<String>,
    sessions: HashMap<String, McpSessionInfo>,
}

impl FakeMcpSessionRegistry {
    /// Empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed with connected sessions (fails closed on invalid / duplicate / non-Connected).
    pub fn with_sessions(
        sessions: impl IntoIterator<Item = McpSessionInfo>,
    ) -> Result<Self, McpError> {
        let reg = Self::new();
        for info in sessions {
            reg.register(info)?;
        }
        Ok(reg)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, FakeMcpSessionRegistryInner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Register an already-open **Connected** session id for MCP tools.
    ///
    /// Fail-closed: blank / control-char id, non-Connected status, duplicate id.
    pub fn register(&self, mut info: McpSessionInfo) -> Result<(), McpError> {
        info.id = canonicalize_session_id(&info.id)?;
        ensure_connected(&info)?;
        let mut guard = self.lock();
        if guard.sessions.contains_key(&info.id) {
            return Err(McpError::Message(format!(
                "MCP session id '{}' is already registered",
                info.id
            )));
        }
        guard.order.push(info.id.clone());
        guard.sessions.insert(info.id.clone(), info);
        Ok(())
    }

    /// Remove a previously registered session id (tab close / disconnect).
    ///
    /// Fail-closed on unknown id (after trim). Blank / control-char ids reject
    /// before the lookup.
    pub fn unregister(&self, session_id: &str) -> Result<(), McpError> {
        let id = canonicalize_session_id(session_id)?;
        let mut guard = self.lock();
        if guard.sessions.remove(&id).is_none() {
            return Err(McpError::Message(format!(
                "No live SSH session with id '{id}'. Call list_sessions for current ids."
            )));
        }
        guard.order.retain(|existing| existing != &id);
        Ok(())
    }

    /// Resolve a connected session by id (C# `ResolveApprovedAsync` id lookup, no approval).
    ///
    /// Unknown id or non-Connected status → fail closed (agent-readable message).
    pub fn get_connected(&self, session_id: &str) -> Result<McpSessionInfo, McpError> {
        let id = canonicalize_session_id(session_id)?;
        let guard = self.lock();
        let Some(info) = guard.sessions.get(&id) else {
            return Err(McpError::Message(format!(
                "No live SSH session with id '{id}'. Call list_sessions for current ids."
            )));
        };
        ensure_connected(info)?;
        Ok(info.clone())
    }

    /// Number of registered sessions (including any that were marked non-Connected
    /// via future updates — today only Connected rows can be inserted).
    pub fn len(&self) -> usize {
        self.lock().sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.lock().sessions.is_empty()
    }

    /// Registered ids in insertion order (tests / diagnostics — safe to log).
    pub fn registered_ids(&self) -> Vec<String> {
        let guard = self.lock();
        guard.order.clone()
    }
}

impl McpSessionRegistry for FakeMcpSessionRegistry {
    fn list_sessions(&self) -> Vec<McpSessionInfo> {
        let guard = self.lock();
        guard
            .order
            .iter()
            .filter_map(|id| guard.sessions.get(id))
            .filter(|info| info.status.is_connected())
            .cloned()
            .collect()
    }
}

impl fmt::Debug for FakeMcpSessionRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let guard = self.lock();
        f.debug_struct("FakeMcpSessionRegistry")
            .field("session_count", &guard.sessions.len())
            .field("ids", &guard.order)
            // Intentionally no token / secret / password fields.
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(id: &str) -> McpSessionInfo {
        McpSessionInfo::connected(id, "host.example", 22, "alice", "prod")
    }

    #[test]
    fn register_list_unregister_round_trip() {
        let reg = FakeMcpSessionRegistry::new();
        assert!(reg.is_empty());
        reg.register(sample("a")).unwrap();
        reg.register(sample("b")).unwrap();
        assert_eq!(reg.len(), 2);
        let listed = reg.list_sessions();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].id, "a");
        assert_eq!(listed[1].id, "b");
        assert_eq!(listed[0].status, McpSessionStatus::Connected);
        assert_eq!(listed[0].host, "host.example");
        assert_eq!(listed[0].port, 22);
        assert_eq!(listed[0].username, "alice");
        assert_eq!(listed[0].title, "prod");

        reg.unregister("a").unwrap();
        assert_eq!(reg.list_sessions().len(), 1);
        assert_eq!(reg.list_sessions()[0].id, "b");
        assert_eq!(reg.registered_ids(), vec!["b".to_owned()]);
    }

    #[test]
    fn register_rejects_non_connected() {
        let reg = FakeMcpSessionRegistry::new();
        for status in [
            McpSessionStatus::Disconnected,
            McpSessionStatus::Connecting,
            McpSessionStatus::Failed,
        ] {
            let err = reg
                .register(McpSessionInfo::new(
                    "x",
                    "h",
                    22,
                    "u",
                    "t",
                    status,
                ))
                .unwrap_err();
            assert!(matches!(err, McpError::Message(_)));
            assert!(err.to_string().contains("not connected"));
        }
        assert!(reg.is_empty());
    }

    #[test]
    fn register_rejects_blank_padded_and_control_char_ids() {
        let reg = FakeMcpSessionRegistry::new();
        assert!(reg.register(sample("")).is_err());
        assert!(reg.register(sample("   ")).is_err());
        assert!(reg
            .register(sample("bad\nid"))
            .unwrap_err()
            .to_string()
            .contains("control"));
        assert!(reg.register(sample("nul\0id")).is_err());
        assert!(reg.is_empty());
    }

    #[test]
    fn register_trims_id_and_rejects_duplicate() {
        let reg = FakeMcpSessionRegistry::new();
        reg.register(sample("  sess-1  ")).unwrap();
        assert_eq!(reg.registered_ids(), vec!["sess-1".to_owned()]);
        let dup = reg.register(sample("sess-1")).unwrap_err();
        assert!(dup.to_string().contains("already registered"));
        // Padded duplicate of the same canonical id also fails.
        let dup_pad = reg.register(sample("  sess-1  ")).unwrap_err();
        assert!(dup_pad.to_string().contains("already registered"));
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn unregister_fail_closed_on_unknown_and_blank() {
        let reg = FakeMcpSessionRegistry::new();
        let unknown = reg.unregister("missing").unwrap_err();
        assert!(unknown.to_string().contains("No live SSH session"));
        assert!(unknown.to_string().contains("list_sessions"));
        assert!(reg.unregister("").is_err());
        assert!(reg.unregister("  ").is_err());
        assert!(reg.unregister("bad\nid").is_err());
    }

    #[test]
    fn get_connected_resolves_and_fail_closed() {
        let reg = FakeMcpSessionRegistry::new();
        reg.register(sample("s1")).unwrap();
        let got = reg.get_connected("  s1  ").unwrap();
        assert_eq!(got.id, "s1");
        let missing = reg.get_connected("nope").unwrap_err();
        assert!(missing.to_string().contains("No live SSH session"));
        assert!(reg.get_connected("").is_err());
    }

    #[test]
    fn with_sessions_seeds_or_rejects() {
        let ok = FakeMcpSessionRegistry::with_sessions([sample("a"), sample("b")]).unwrap();
        assert_eq!(ok.list_sessions().len(), 2);

        let bad = FakeMcpSessionRegistry::with_sessions([
            sample("a"),
            McpSessionInfo::new("b", "h", 22, "u", "t", McpSessionStatus::Failed),
        ]);
        assert!(bad.is_err());

        let dup = FakeMcpSessionRegistry::with_sessions([sample("a"), sample("a")]);
        assert!(dup.is_err());
    }

    #[test]
    fn list_sessions_trait_filters_connected_only() {
        // Defensive: if a non-Connected row were somehow present, list must omit it.
        let reg = FakeMcpSessionRegistry::new();
        {
            let mut guard = reg.lock();
            let id = "ghost".to_owned();
            guard.order.push(id.clone());
            guard.sessions.insert(
                id.clone(),
                McpSessionInfo::new(id, "h", 22, "u", "t", McpSessionStatus::Disconnected),
            );
        }
        assert!(reg.list_sessions().is_empty());
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn re_register_after_unregister_allowed() {
        let reg = FakeMcpSessionRegistry::new();
        reg.register(sample("s")).unwrap();
        reg.unregister("s").unwrap();
        reg.register(sample("s")).unwrap();
        assert_eq!(reg.list_sessions().len(), 1);
    }

    #[test]
    fn unregister_middle_preserves_insertion_order() {
        let reg = FakeMcpSessionRegistry::new();
        reg.register(sample("a")).unwrap();
        reg.register(sample("b")).unwrap();
        reg.register(sample("c")).unwrap();
        reg.unregister("b").unwrap();
        let ids: Vec<_> = reg.list_sessions().into_iter().map(|s| s.id).collect();
        assert_eq!(ids, vec!["a".to_owned(), "c".to_owned()]);
        assert_eq!(reg.registered_ids(), vec!["a".to_owned(), "c".to_owned()]);
    }

    #[test]
    fn status_display_matches_csharp_names() {
        assert_eq!(McpSessionStatus::Connected.as_str(), "Connected");
        assert_eq!(McpSessionStatus::Disconnected.to_string(), "Disconnected");
        assert_eq!(McpSessionStatus::Connecting.as_str(), "Connecting");
        assert_eq!(McpSessionStatus::Failed.as_str(), "Failed");
    }

    #[test]
    fn debug_omits_token_wording_and_secrets() {
        let reg = FakeMcpSessionRegistry::new();
        reg.register(sample("s1")).unwrap();
        let dbg = format!("{reg:?}");
        assert!(dbg.contains("FakeMcpSessionRegistry"));
        assert!(dbg.contains("session_count"));
        assert!(dbg.contains("s1"));
        assert!(!dbg.to_ascii_lowercase().contains("bearer"));
        assert!(!dbg.to_ascii_lowercase().contains("token"));
        assert!(!dbg.contains("password"));
        assert!(!dbg.contains("secret"));

        let info = sample("s1");
        let info_dbg = format!("{info:?}");
        assert!(!info_dbg.to_ascii_lowercase().contains("bearer"));
        assert!(!info_dbg.to_ascii_lowercase().contains("token"));
        assert!(!info_dbg.contains("password"));
    }

    #[test]
    fn error_messages_never_mention_bearer_or_token() {
        let reg = FakeMcpSessionRegistry::new();
        let errs = [
            reg.register(sample("")).unwrap_err().to_string(),
            reg.register(sample("x\ny")).unwrap_err().to_string(),
            reg.register(McpSessionInfo::new(
                "z",
                "h",
                22,
                "u",
                "t",
                McpSessionStatus::Disconnected,
            ))
            .unwrap_err()
            .to_string(),
            reg.unregister("missing").unwrap_err().to_string(),
        ];
        for msg in errs {
            assert!(!msg.to_ascii_lowercase().contains("bearer"));
            assert!(!msg.to_ascii_lowercase().contains("token"));
        }
    }

    #[test]
    fn port_zero_metadata_allowed_like_csharp_missing_profile() {
        let reg = FakeMcpSessionRegistry::new();
        reg.register(McpSessionInfo::connected("s", "", 0, "", "tab"))
            .unwrap();
        let listed = reg.list_sessions();
        assert_eq!(listed[0].port, 0);
        assert_eq!(listed[0].host, "");
    }
}
