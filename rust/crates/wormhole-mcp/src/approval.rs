//! MCP tool approval gate Fake glue (Approve / Deny / Cancel; no live tool exec).
//!
//! Thin Lab stub mirroring C# `EnsureMcpApprovedAsync` / `ResolveApprovedAsync`:
//! before any session-control `execute_tool`, the agent must pass an explicit
//! per-session allow. UI chrome lands later; tests drive
//! [`SessionApprovalGate::open_channel`] or [`FakeMcpApprovalUi`].
//!
//! Fail-closed map:
//! - default AutoDeny / Deny / Cancel / channel closed / response dropped → error
//! - blank / control-char session id → error (before the channel)
//! - optional [`FakeMcpSessionRegistry`]: only **registered Connected** ids eligible
//! - after Approve → live exec still unwired (`execute_tool` fail-closed)
//!
//! [`Debug`] on the gate / Fake UI / glue never carries bearer tokens or secrets.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex};

use tokio::sync::{mpsc, oneshot};

use crate::capability::{TOOL_READ_TERMINAL, TOOL_RUN_COMMAND, TOOL_SEND_TEXT};
use crate::session_registry::{canonicalize_session_id, FakeMcpSessionRegistry};
use crate::McpError;

/// Decision for a pending session-control approval.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDecision {
    Approve,
    Deny,
    /// User dismissed the prompt without Allow/Deny (fail closed; distinct copy).
    Cancel,
}

impl ApprovalDecision {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "Approve",
            Self::Deny => "Deny",
            Self::Cancel => "Cancel",
        }
    }
}

impl fmt::Debug for ApprovalDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Display for ApprovalDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A pending approval request waiting for the UI (or test harness).
///
/// Deliberately omits bearer tokens, passwords, and command/terminal text so
/// [`Debug`] cannot leak secrets.
pub struct ApprovalRequest {
    pub session_id: String,
    pub tool: &'static str,
    pub respond: oneshot::Sender<ApprovalDecision>,
}

impl fmt::Debug for ApprovalRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApprovalRequest")
            .field("session_id", &self.session_id)
            .field("tool", &self.tool)
            .field("respond", &"<oneshot>")
            // Intentionally no token / password / command / terminal fields.
            .finish()
    }
}

#[derive(Debug)]
enum GateMode {
    /// No listener — deny (fail closed).
    AutoDeny,
    /// Tests / headless — approve every request.
    AutoApprove,
    /// Forward requests to a consumer (UI stub / Fake).
    Channel(mpsc::UnboundedSender<ApprovalRequest>),
}

/// Session approval gate shared by MCP tools and the host UI.
pub struct SessionApprovalGate {
    mode: Mutex<GateMode>,
    /// Sessions already approved for this process (C# keeps this on the VM).
    approved: Mutex<HashMap<String, bool>>,
}

impl Default for SessionApprovalGate {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionApprovalGate {
    pub fn new() -> Self {
        Self {
            mode: Mutex::new(GateMode::AutoDeny),
            approved: Mutex::new(HashMap::new()),
        }
    }

    /// Fail closed until a UI / test attaches.
    pub fn set_auto_deny(&self) {
        *self.mode.lock().unwrap_or_else(|p| p.into_inner()) = GateMode::AutoDeny;
    }

    /// Approve every request without prompting (unit tests).
    pub fn set_auto_approve(&self) {
        *self.mode.lock().unwrap_or_else(|p| p.into_inner()) = GateMode::AutoApprove;
    }

    /// Install an unbounded Approve/Deny/Cancel channel; returns the receiver side.
    pub fn open_channel(&self) -> mpsc::UnboundedReceiver<ApprovalRequest> {
        let (tx, rx) = mpsc::unbounded_channel();
        *self.mode.lock().unwrap_or_else(|p| p.into_inner()) = GateMode::Channel(tx);
        rx
    }

    /// Mark a session as already approved (skips the prompt on later tools).
    ///
    /// Blank / control-char ids are ignored (no padded keys in the cache).
    pub fn mark_approved(&self, session_id: impl Into<String>) {
        let Ok(id) = canonicalize_session_id(&session_id.into()) else {
            return;
        };
        self.approved
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(id, true);
    }

    pub fn clear_approvals(&self) {
        self.approved
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
    }

    pub fn is_approved(&self, session_id: &str) -> bool {
        let Ok(id) = canonicalize_session_id(session_id) else {
            return false;
        };
        self.approved
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&id)
            .copied()
            .unwrap_or(false)
    }

    pub fn approved_count(&self) -> usize {
        self.approved
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len()
    }

    /// Ensure the session is approved for AI-agent control.
    ///
    /// Returns `Ok(())` when approved, `Err` when denied / cancelled / no listener.
    /// Blank / control-char session ids fail closed before the channel.
    pub async fn ensure_approved(
        &self,
        session_id: &str,
        tool: &'static str,
    ) -> Result<(), McpError> {
        let session_id = canonicalize_session_id(session_id)?;
        let tool = canonicalize_approval_tool(tool)?;

        {
            let map = self.approved.lock().unwrap_or_else(|p| p.into_inner());
            if map.get(&session_id).copied().unwrap_or(false) {
                return Ok(());
            }
        }

        let (respond_tx, respond_rx) = oneshot::channel();
        {
            let mode = self.mode.lock().unwrap_or_else(|p| p.into_inner());
            match &*mode {
                GateMode::AutoApprove => {
                    drop(mode);
                    self.mark_approved(session_id);
                    return Ok(());
                }
                GateMode::AutoDeny => {
                    return Err(denied_error());
                }
                GateMode::Channel(tx) => {
                    let req = ApprovalRequest {
                        session_id: session_id.clone(),
                        tool,
                        respond: respond_tx,
                    };
                    if tx.send(req).is_err() {
                        return Err(McpError::Message("MCP approval channel closed.".into()));
                    }
                }
            }
        }

        match respond_rx.await {
            Ok(ApprovalDecision::Approve) => {
                self.mark_approved(session_id);
                Ok(())
            }
            Ok(ApprovalDecision::Deny) => Err(denied_error()),
            Ok(ApprovalDecision::Cancel) => Err(cancelled_error()),
            Err(_) => Err(McpError::Message("MCP approval response dropped.".into())),
        }
    }
}

impl fmt::Debug for SessionApprovalGate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mode = self.mode.lock().unwrap_or_else(|p| p.into_inner());
        let mode_label = match &*mode {
            GateMode::AutoDeny => "AutoDeny",
            GateMode::AutoApprove => "AutoApprove",
            GateMode::Channel(_) => "Channel",
        };
        f.debug_struct("SessionApprovalGate")
            .field("mode", &mode_label)
            .field("approved_count", &self.approved_count())
            // Intentionally no token / secret / password fields.
            .finish()
    }
}

fn denied_error() -> McpError {
    McpError::Message("The user denied AI-agent control of that session.".into())
}

fn cancelled_error() -> McpError {
    McpError::Message("The user cancelled AI-agent approval for that session.".into())
}

/// Session-control tools that require per-session approval (C# `ResolveApprovedAsync`).
fn canonicalize_approval_tool(tool: &str) -> Result<&'static str, McpError> {
    let name = tool.trim();
    if name.is_empty() {
        return Err(McpError::Message("MCP approval tool name is required".into()));
    }
    if name.chars().any(|c| c.is_control()) {
        return Err(McpError::Message(
            "MCP approval tool name contains control characters".into(),
        ));
    }
    match name {
        TOOL_RUN_COMMAND => Ok(TOOL_RUN_COMMAND),
        TOOL_SEND_TEXT => Ok(TOOL_SEND_TEXT),
        TOOL_READ_TERMINAL => Ok(TOOL_READ_TERMINAL),
        _ => Err(McpError::Message(format!(
            "MCP approval is not applicable for tool '{name}'"
        ))),
    }
}

/// Approve a pending request (returns `false` if the waiter already dropped).
pub fn approve_pending(req: ApprovalRequest) -> bool {
    req.respond.send(ApprovalDecision::Approve).is_ok()
}

/// Deny a pending request (fail closed at `ensure_approved` / `execute_tool`).
pub fn deny_pending(req: ApprovalRequest) -> bool {
    req.respond.send(ApprovalDecision::Deny).is_ok()
}

/// Cancel / dismiss a pending request (fail closed; distinct from Deny).
pub fn cancel_pending(req: ApprovalRequest) -> bool {
    req.respond.send(ApprovalDecision::Cancel).is_ok()
}

/// Scripted Fake UI responder for [`SessionApprovalGate`] channel tests.
///
/// Each [`answer_next`](FakeMcpApprovalUi::answer_next) dequeues one scripted
/// decision. Exhausted script → Cancel (fail closed), matching SAML Fake `None`.
/// [`Debug`] reports queue length only — never session ids from the live channel.
pub struct FakeMcpApprovalUi {
    script: Mutex<VecDeque<ApprovalDecision>>,
}

impl Default for FakeMcpApprovalUi {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeMcpApprovalUi {
    pub fn new() -> Self {
        Self {
            script: Mutex::new(VecDeque::new()),
        }
    }

    pub fn with_script(decisions: impl IntoIterator<Item = ApprovalDecision>) -> Self {
        Self {
            script: Mutex::new(decisions.into_iter().collect()),
        }
    }

    pub fn push(&self, decision: ApprovalDecision) {
        self.script
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push_back(decision);
    }

    pub fn remaining(&self) -> usize {
        self.script.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    /// Wait for one pending request and answer from the script (or Cancel).
    pub async fn answer_next(
        &self,
        rx: &mut mpsc::UnboundedReceiver<ApprovalRequest>,
    ) -> Result<ApprovalDecision, McpError> {
        let req = rx.recv().await.ok_or_else(|| {
            McpError::Message("MCP approval channel closed.".into())
        })?;
        let decision = self
            .script
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .pop_front()
            .unwrap_or(ApprovalDecision::Cancel);
        let _ = req.respond.send(decision);
        Ok(decision)
    }
}

impl fmt::Debug for FakeMcpApprovalUi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeMcpApprovalUi")
            .field("script_len", &self.remaining())
            // Intentionally no token / secret fields; script is Approve/Deny/Cancel only.
            .finish()
    }
}

/// Thin Fake glue: optional Connected registry → Approve/Deny/Cancel → fail-closed
/// `execute_tool` (**no** live MCP / SSH execution).
///
/// When [`Self::with_registry`] is used, only registered **Connected** sessions
/// are eligible (C# `IsMcpConnected` + id lookup). Without a registry, only the
/// approval channel gates the call (blank / control-char ids still reject).
pub struct FakeMcpToolApprovalGlue {
    gate: Arc<SessionApprovalGate>,
    registry: Option<Arc<FakeMcpSessionRegistry>>,
}

impl Default for FakeMcpToolApprovalGlue {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeMcpToolApprovalGlue {
    /// Gate only (no session registry) — AutoDeny until a channel / auto-approve.
    pub fn new() -> Self {
        Self {
            gate: Arc::new(SessionApprovalGate::new()),
            registry: None,
        }
    }

    /// Gate + Connected-only eligibility via [`FakeMcpSessionRegistry`].
    pub fn with_registry(registry: Arc<FakeMcpSessionRegistry>) -> Self {
        Self {
            gate: Arc::new(SessionApprovalGate::new()),
            registry: Some(registry),
        }
    }

    /// Share an existing gate (e.g. host-owned) with optional registry.
    pub fn from_parts(
        gate: Arc<SessionApprovalGate>,
        registry: Option<Arc<FakeMcpSessionRegistry>>,
    ) -> Self {
        Self { gate, registry }
    }

    pub fn gate(&self) -> Arc<SessionApprovalGate> {
        Arc::clone(&self.gate)
    }

    pub fn registry(&self) -> Option<Arc<FakeMcpSessionRegistry>> {
        self.registry.as_ref().map(Arc::clone)
    }

    pub fn open_channel(&self) -> mpsc::UnboundedReceiver<ApprovalRequest> {
        self.gate.open_channel()
    }

    pub fn set_auto_approve(&self) {
        self.gate.set_auto_approve();
    }

    pub fn set_auto_deny(&self) {
        self.gate.set_auto_deny();
    }

    /// Eligibility + approval only (does not attempt tool execution).
    pub async fn ensure_allowed(
        &self,
        session_id: &str,
        tool: &'static str,
    ) -> Result<(), McpError> {
        let canonical_id = if let Some(reg) = &self.registry {
            // Fail-closed: unknown / blank / control-char / non-Connected.
            reg.get_connected(session_id)?.id
        } else {
            canonicalize_session_id(session_id)?
        };
        self.gate.ensure_approved(&canonical_id, tool).await
    }

    /// Before execute: Connected eligibility (if registry) + Approve/Deny/Cancel,
    /// then fail closed — **no** live tool execution.
    pub async fn execute_tool(
        &self,
        session_id: &str,
        tool: &'static str,
    ) -> Result<(), McpError> {
        self.ensure_allowed(session_id, tool).await?;
        Err(McpError::Message(
            "MCP tool execution not wired (Fake approval glue)".into(),
        ))
    }
}

impl fmt::Debug for FakeMcpToolApprovalGlue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeMcpToolApprovalGlue")
            .field("gate", &self.gate)
            .field("has_registry", &self.registry.is_some())
            .field(
                "registry_len",
                &self.registry.as_ref().map(|r| r.len()).unwrap_or(0),
            )
            // Intentionally no token / secret / password fields.
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session_registry::{McpSessionInfo, McpSessionStatus};
    use crate::capability::TOOL_LIST_SESSIONS;

    fn sample(id: &str) -> McpSessionInfo {
        McpSessionInfo::connected(id, "host.example", 22, "alice", "prod")
    }

    #[tokio::test]
    async fn auto_deny_fail_closed() {
        let gate = SessionApprovalGate::new();
        let err = gate
            .ensure_approved("sess-1", TOOL_RUN_COMMAND)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("denied"));
        assert!(!err.to_string().to_ascii_lowercase().contains("bearer"));
        assert!(!err.to_string().to_ascii_lowercase().contains("token"));
    }

    #[tokio::test]
    async fn blank_and_control_session_id_rejected_before_channel() {
        let gate = SessionApprovalGate::new();
        gate.set_auto_approve();
        assert!(gate.ensure_approved("", TOOL_RUN_COMMAND).await.is_err());
        assert!(gate.ensure_approved("   ", TOOL_RUN_COMMAND).await.is_err());
        assert!(gate
            .ensure_approved("bad\nid", TOOL_RUN_COMMAND)
            .await
            .is_err());
        assert_eq!(gate.approved_count(), 0);
    }

    #[tokio::test]
    async fn blank_and_unknown_tool_rejected() {
        let gate = SessionApprovalGate::new();
        gate.set_auto_approve();
        assert!(gate.ensure_approved("s1", "").await.is_err());
        let list = gate
            .ensure_approved("s1", TOOL_LIST_SESSIONS)
            .await
            .unwrap_err();
        assert!(list.to_string().contains("not applicable"));
        assert!(gate
            .ensure_approved("s1", "run\0command")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn channel_approve_deny_cancel() {
        let gate = Arc::new(SessionApprovalGate::new());
        let mut rx = gate.open_channel();

        let g = Arc::clone(&gate);
        let pending =
            tokio::spawn(async move { g.ensure_approved("sess-1", TOOL_RUN_COMMAND).await });
        let req = rx.recv().await.expect("approve request");
        assert_eq!(req.session_id, "sess-1");
        assert_eq!(req.tool, TOOL_RUN_COMMAND);
        assert!(approve_pending(req));
        pending.await.unwrap().unwrap();
        assert!(gate.is_approved("sess-1"));
        // Cached approval skips channel.
        gate.ensure_approved("sess-1", TOOL_SEND_TEXT)
            .await
            .unwrap();

        gate.clear_approvals();
        let g = Arc::clone(&gate);
        let pending =
            tokio::spawn(async move { g.ensure_approved("sess-2", TOOL_READ_TERMINAL).await });
        let req = rx.recv().await.expect("deny request");
        assert!(deny_pending(req));
        let err = pending.await.unwrap().unwrap_err();
        assert!(err.to_string().contains("denied"));
        assert!(!gate.is_approved("sess-2"));

        let g = Arc::clone(&gate);
        let pending =
            tokio::spawn(async move { g.ensure_approved("sess-3", TOOL_SEND_TEXT).await });
        let req = rx.recv().await.expect("cancel request");
        assert!(cancel_pending(req));
        let err = pending.await.unwrap().unwrap_err();
        assert!(err.to_string().contains("cancelled"));
        assert!(!gate.is_approved("sess-3"));
    }

    #[tokio::test]
    async fn fake_ui_script_and_exhausted_cancels() {
        let gate = Arc::new(SessionApprovalGate::new());
        let mut rx = gate.open_channel();
        let ui = FakeMcpApprovalUi::with_script([
            ApprovalDecision::Approve,
            ApprovalDecision::Deny,
        ]);

        let g = Arc::clone(&gate);
        let pending =
            tokio::spawn(async move { g.ensure_approved("a", TOOL_RUN_COMMAND).await });
        let decided = ui.answer_next(&mut rx).await.unwrap();
        assert_eq!(decided, ApprovalDecision::Approve);
        pending.await.unwrap().unwrap();

        gate.clear_approvals();
        let g = Arc::clone(&gate);
        let pending =
            tokio::spawn(async move { g.ensure_approved("b", TOOL_SEND_TEXT).await });
        let decided = ui.answer_next(&mut rx).await.unwrap();
        assert_eq!(decided, ApprovalDecision::Deny);
        let err = pending.await.unwrap().unwrap_err();
        assert!(err.to_string().contains("denied"));

        let g = Arc::clone(&gate);
        let pending =
            tokio::spawn(async move { g.ensure_approved("c", TOOL_RUN_COMMAND).await });
        // Exhausted → Cancel fail-closed.
        let decided = ui.answer_next(&mut rx).await.unwrap();
        assert_eq!(decided, ApprovalDecision::Cancel);
        let err = pending.await.unwrap().unwrap_err();
        assert!(err.to_string().contains("cancelled"));
    }

    #[tokio::test]
    async fn channel_closed_when_receiver_dropped() {
        let gate = SessionApprovalGate::new();
        let rx = gate.open_channel();
        drop(rx);
        let err = gate
            .ensure_approved("s1", TOOL_RUN_COMMAND)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("channel closed"));
    }

    #[tokio::test]
    async fn glue_without_registry_gates_then_fail_closed_execute() {
        let glue = FakeMcpToolApprovalGlue::new();
        let err = glue
            .execute_tool("sess-1", TOOL_RUN_COMMAND)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("denied"));

        glue.set_auto_approve();
        let err = glue
            .execute_tool("sess-1", TOOL_RUN_COMMAND)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not wired"));
        assert!(!err.to_string().to_ascii_lowercase().contains("bearer"));
        assert!(!err.to_string().to_ascii_lowercase().contains("token"));
        // ensure_allowed alone succeeds after approve cache.
        glue.ensure_allowed("sess-1", TOOL_SEND_TEXT)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn glue_with_registry_requires_connected() {
        let reg = Arc::new(FakeMcpSessionRegistry::new());
        reg.register(sample("live")).unwrap();
        let glue = FakeMcpToolApprovalGlue::with_registry(Arc::clone(&reg));
        glue.set_auto_approve();

        let missing = glue
            .execute_tool("missing", TOOL_RUN_COMMAND)
            .await
            .unwrap_err();
        assert!(missing.to_string().contains("No live SSH session"));

        let err = glue
            .execute_tool("live", TOOL_RUN_COMMAND)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not wired"));

        // Non-Connected cannot be registered; defensive unknown after unregister.
        reg.unregister("live").unwrap();
        let gone = glue
            .ensure_allowed("live", TOOL_SEND_TEXT)
            .await
            .unwrap_err();
        assert!(gone.to_string().contains("No live SSH session"));
    }

    #[tokio::test]
    async fn glue_channel_cancel_fail_closed_with_shared_registry() {
        let reg = Arc::new(
            FakeMcpSessionRegistry::with_sessions([sample("s1")]).unwrap(),
        );
        let glue = FakeMcpToolApprovalGlue::with_registry(Arc::clone(&reg));
        let mut rx = glue.open_channel();
        let glue2 = FakeMcpToolApprovalGlue::from_parts(glue.gate(), glue.registry());
        let pending =
            tokio::spawn(async move { glue2.execute_tool("s1", TOOL_SEND_TEXT).await });
        let req = rx.recv().await.expect("pending");
        assert_eq!(req.session_id, "s1");
        assert_eq!(req.tool, TOOL_SEND_TEXT);
        assert!(cancel_pending(req));
        let err = pending.await.unwrap().unwrap_err();
        assert!(err.to_string().contains("cancelled"));
    }

    #[tokio::test]
    async fn dropped_response_fail_closed() {
        let gate = Arc::new(SessionApprovalGate::new());
        let mut rx = gate.open_channel();
        let g = Arc::clone(&gate);
        let pending =
            tokio::spawn(async move { g.ensure_approved("s", TOOL_RUN_COMMAND).await });
        let req = rx.recv().await.expect("pending");
        drop(req); // abandon oneshot without Approve/Deny/Cancel
        let err = pending.await.unwrap().unwrap_err();
        assert!(err.to_string().contains("dropped"));
    }

    #[test]
    fn debug_omits_token_wording() {
        let gate = SessionApprovalGate::new();
        let dbg = format!("{gate:?}");
        assert!(dbg.contains("SessionApprovalGate"));
        assert!(dbg.contains("AutoDeny"));
        assert!(!dbg.to_ascii_lowercase().contains("bearer"));
        assert!(!dbg.to_ascii_lowercase().contains("token"));
        assert!(!dbg.contains("password"));

        let ui = FakeMcpApprovalUi::with_script([ApprovalDecision::Deny]);
        let ui_dbg = format!("{ui:?}");
        assert!(ui_dbg.contains("script_len"));
        assert!(!ui_dbg.to_ascii_lowercase().contains("bearer"));

        let glue = FakeMcpToolApprovalGlue::new();
        let glue_dbg = format!("{glue:?}");
        assert!(glue_dbg.contains("has_registry"));
        assert!(!glue_dbg.to_ascii_lowercase().contains("bearer"));
        assert!(!glue_dbg.to_ascii_lowercase().contains("token"));

        let req_dbg = format!(
            "{:?}",
            ApprovalRequest {
                session_id: "s".into(),
                tool: TOOL_RUN_COMMAND,
                respond: oneshot::channel().0,
            }
        );
        assert!(req_dbg.contains("session_id"));
        assert!(!req_dbg.to_ascii_lowercase().contains("bearer"));
        assert!(!req_dbg.to_ascii_lowercase().contains("token"));
    }

    #[tokio::test]
    async fn padded_session_id_canonicalized_for_cache() {
        let gate = SessionApprovalGate::new();
        gate.set_auto_approve();
        gate.ensure_approved("  s1  ", TOOL_RUN_COMMAND)
            .await
            .unwrap();
        assert!(gate.is_approved("s1"));
        assert!(gate.is_approved("  s1  "));
        assert_eq!(gate.approved_count(), 1);

        // Direct mark_approved also canonicalizes (no padded cache keys).
        gate.clear_approvals();
        gate.mark_approved("  s2  ");
        assert!(gate.is_approved("s2"));
        assert_eq!(gate.approved_count(), 1);
        gate.mark_approved(""); // ignored
        gate.mark_approved("bad\nid"); // ignored
        assert_eq!(gate.approved_count(), 1);
    }

    #[tokio::test]
    async fn registry_present_rejects_even_when_auto_approve() {
        // Eligibility runs before approval — unknown never reaches the channel.
        let glue = FakeMcpToolApprovalGlue::with_registry(Arc::new(FakeMcpSessionRegistry::new()));
        let mut rx = glue.open_channel();
        let err = glue
            .execute_tool("ghost", TOOL_RUN_COMMAND)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("No live SSH session"));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn non_connected_status_not_registerable_so_ineligible() {
        let reg = FakeMcpSessionRegistry::new();
        assert!(reg
            .register(McpSessionInfo::new(
                "x",
                "h",
                22,
                "u",
                "t",
                McpSessionStatus::Disconnected,
            ))
            .is_err());
    }
}
