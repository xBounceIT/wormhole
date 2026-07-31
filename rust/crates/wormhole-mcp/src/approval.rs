//! Per-session MCP approval stub (approve / deny channel).
//!
//! Mirrors C# `EnsureMcpApprovedAsync`: tools that drive a live SSH session must
//! wait for an explicit allow before continuing. UI wiring lands later; tests
//! can auto-approve or drive the channel.

use std::collections::HashMap;
use std::sync::Mutex;

use tokio::sync::{mpsc, oneshot};

use crate::McpError;

/// Decision for a pending session-control approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDecision {
    Approve,
    Deny,
}

/// A pending approval request waiting for the UI (or test harness).
#[derive(Debug)]
pub struct ApprovalRequest {
    pub session_id: String,
    pub tool: &'static str,
    pub respond: oneshot::Sender<ApprovalDecision>,
}

#[derive(Debug)]
enum GateMode {
    /// No listener — deny (fail closed).
    AutoDeny,
    /// Tests / headless — approve every request.
    AutoApprove,
    /// Forward requests to a consumer (UI stub).
    Channel(mpsc::UnboundedSender<ApprovalRequest>),
}

/// Session approval gate shared by MCP tools and the host UI.
#[derive(Debug)]
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

    /// Install an unbounded approve/deny channel; returns the receiver side.
    pub fn open_channel(&self) -> mpsc::UnboundedReceiver<ApprovalRequest> {
        let (tx, rx) = mpsc::unbounded_channel();
        *self.mode.lock().unwrap_or_else(|p| p.into_inner()) = GateMode::Channel(tx);
        rx
    }

    /// Mark a session as already approved (skips the prompt on later tools).
    pub fn mark_approved(&self, session_id: impl Into<String>) {
        self.approved
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(session_id.into(), true);
    }

    pub fn clear_approvals(&self) {
        self.approved
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
    }

    /// Ensure the session is approved for AI-agent control.
    ///
    /// Returns `Ok(())` when approved, `Err` when denied or no listener.
    pub async fn ensure_approved(
        &self,
        session_id: &str,
        tool: &'static str,
    ) -> Result<(), McpError> {
        {
            let map = self.approved.lock().unwrap_or_else(|p| p.into_inner());
            if map.get(session_id).copied().unwrap_or(false) {
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
                    return Err(McpError::Message(
                        "The user denied AI-agent control of that session.".into(),
                    ));
                }
                GateMode::Channel(tx) => {
                    let req = ApprovalRequest {
                        session_id: session_id.to_owned(),
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
            Ok(ApprovalDecision::Deny) => Err(McpError::Message(
                "The user denied AI-agent control of that session.".into(),
            )),
            Err(_) => Err(McpError::Message("MCP approval response dropped.".into())),
        }
    }
}
