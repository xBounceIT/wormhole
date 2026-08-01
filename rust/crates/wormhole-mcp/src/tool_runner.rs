//! MCP tool-runner glue for the live SSH tools (Fake-first; no real SSH/HTTP).
//!
//! Mirrors the *execution surface* of C# `McpSshTools` + `McpSessionRegistry`:
//! the four tools (`list_sessions`, `run_command`, `send_text`, `read_terminal`)
//! drive **already-open, connected SSH sessions only**, and the first action on a
//! session must pass the existing per-session approval gate
//! ([`crate::SessionApprovalGate`]). There is no open-connection tool and no
//! read-credentials tool — parity with the deliberate C# scope.
//!
//! [`McpToolRunnerGlue`] orchestrates three injectable seams — an
//! [`McpShellRunner`] (production would wrap SSH `ShellCommandRunner`; here only
//! [`FakeMcpShellRunner`]), an [`McpToolDispatch`] streamable-HTTP-shaped
//! dispatch seam (production wires the rmcp handler; here [`FakeMcpToolDispatch`]
//! records), and the shared approval gate + [`crate::FakeMcpSessionRegistry`]
//! (Connected-only eligibility, reused from the approval-gate glue). No axum / rmcp
//! dependency is added; both seams are trivial trait objects.
//!
//! Fail-closed map (tool returns `Err`, shell never invoked where marked):
//!
//! | Condition | Result |
//! |---|---|
//! | unknown / blank / control-char / non-Connected session id | **error**, shell not invoked |
//! | empty `command` / `text` | **error** before any approval prompt |
//! | first action not yet approved (Deny / Cancel / closed / no listener) | **error**, shell not invoked |
//! | already-approved session, later actions | proceeds **without** re-prompting (C# first-touch dialog) |
//! | exhausted / scripted-error [`FakeMcpShellRunner`] | **error** surfaced (no partial write dropped) |
//! | [`McpToolDispatch`] record failure | **error** surfaced (no silent drop) |
//! | `list_sessions` | no approval needed; prints connected sessions |
//!
//! [`Debug`] on results / args / Fakes reports **lengths only** — never command
//! text, terminal output, or session credentials (matches C# `McpAudit` logging,
//! which logs byte counts, not bodies).

use std::collections::VecDeque;
use std::fmt;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use crate::approval::SessionApprovalGate;
use crate::capability::{
    TOOL_LIST_SESSIONS, TOOL_READ_TERMINAL, TOOL_RUN_COMMAND, TOOL_SEND_TEXT,
};
use crate::session_registry::{FakeMcpSessionRegistry, McpSessionInfo, McpSessionRegistry};
use crate::McpError;

/// C# `ShellCommandResult` shape returned by a single `run_command` execution.
///
/// [`Debug`] reports the output **length** only — captured output may contain
/// inline secrets (C# `McpSessionRegistry` audit logs `{Length} chars`, never the
/// body).
#[derive(Clone, PartialEq, Eq)]
pub struct McpShellCommandResult {
    /// Captured stdout for the command.
    pub output: String,
    /// Process exit code.
    pub exit_code: i32,
    /// Set when the command hit the host timeout (C# `TimedOut`).
    pub timed_out: bool,
    /// Set when captured output was truncated (C# `Truncated`).
    pub truncated: bool,
}

impl McpShellCommandResult {
    /// Simple success helper (`exit_code = 0`, not timed out / truncated).
    pub fn success(output: impl Into<String>) -> Self {
        Self {
            output: output.into(),
            exit_code: 0,
            timed_out: false,
            truncated: false,
        }
    }
}

impl fmt::Debug for McpShellCommandResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("McpShellCommandResult")
            .field("output_len", &self.output.len())
            .field("exit_code", &self.exit_code)
            .field("timed_out", &self.timed_out)
            .field("truncated", &self.truncated)
            // Intentionally no captured output body (could hold inline secrets).
            .finish()
    }
}

/// Execution seam for driving a live SSH session's terminal.
///
/// The real product host would wrap SSH `ShellCommandRunner`; this crate ships
/// only [`FakeMcpShellRunner`] (scripted output / errors) so unit tests never
/// touch a shell. All methods take the already-canonicalized session id; callers
/// failing closed here are [`McpToolRunnerGlue`] (registry + approval first).
#[async_trait]
pub trait McpShellRunner: Send + Sync + fmt::Debug {
    /// Run a single shell command at the session prompt.
    async fn run_command(
        &self,
        session_id: &str,
        command: &str,
    ) -> Result<McpShellCommandResult, McpError>;
    /// Type raw text into the session exactly as if the user typed it (no capture).
    async fn send_text(&self, session_id: &str, text: &str) -> Result<(), McpError>;
    /// Return recent terminal output (scrollback) for the session.
    async fn read_terminal(&self, session_id: &str) -> Result<String, McpError>;
}

/// Which shell method a [`McpShellCallRecord`] observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpShellCallKind {
    RunCommand,
    SendText,
    ReadTerminal,
}

impl McpShellCallKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RunCommand => "run_command",
            Self::SendText => "send_text",
            Self::ReadTerminal => "read_terminal",
        }
    }
}

/// One observed shell invocation on [`FakeMcpShellRunner`].
///
/// [`Debug`] is safe by construction: only the argument **length** is recorded,
/// never the command / text body (matches C# cautious logging).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpShellCallRecord {
    pub kind: McpShellCallKind,
    pub session_id: String,
    /// Length of the command / text argument (0 for `read_terminal`).
    pub arg_len: usize,
}

/// Scripted result queue for a single [`FakeMcpShellRunner`] method.
///
/// Manually implements `Default` (derive would impose an unnecessary
/// `T: Default` bound; `VecDeque<T>` itself is unconditionally `Default`).
struct ResultQueue<T> {
    items: VecDeque<Result<T, McpError>>,
}

impl<T> Default for ResultQueue<T> {
    fn default() -> Self {
        Self {
            items: VecDeque::new(),
        }
    }
}

impl<T> ResultQueue<T> {
    fn push(&mut self, result: Result<T, McpError>) {
        self.items.push_back(result);
    }

    /// Pop the next scripted result; **exhausted → fail closed**.
    fn pop(&mut self, kind: McpShellCallKind) -> Result<T, McpError> {
        self.items.pop_front().unwrap_or_else(|| {
            Err(McpError::Message(format!(
                "FakeMcpShellRunner has no scripted {} result left (fail closed)",
                kind.as_str()
            )))
        })
    }

    fn len(&self) -> usize {
        self.items.len()
    }
}

/// Scripted [`McpShellRunner`] for unit tests — no shell involved.
///
/// Each of the three methods consumes a scripted
/// `Result`; an exhausted script fails closed rather than silently returning
/// something. All calls are recorded (kind + id + argument length only) on
/// [`Self::calls`] so tests can pin "shell never invoked" on Deny / unknown id.
#[derive(Default)]
pub struct FakeMcpShellRunner {
    run: Mutex<ResultQueue<McpShellCommandResult>>,
    send: Mutex<ResultQueue<()>>,
    read: Mutex<ResultQueue<String>>,
    calls: Mutex<Vec<McpShellCallRecord>>,
}

impl FakeMcpShellRunner {
    /// Empty runner — every call fails closed until scripted.
    pub fn new() -> Self {
        Self::default()
    }

    fn lock_run(&self) -> std::sync::MutexGuard<'_, ResultQueue<McpShellCommandResult>> {
        self.run.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn lock_send(&self) -> std::sync::MutexGuard<'_, ResultQueue<()>> {
        self.send.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn lock_read(&self) -> std::sync::MutexGuard<'_, ResultQueue<String>> {
        self.read.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn record(&self, kind: McpShellCallKind, session_id: &str, arg_len: usize) {
        self.calls.lock().unwrap_or_else(|p| p.into_inner()).push(
            McpShellCallRecord {
                kind,
                session_id: session_id.to_owned(),
                arg_len,
            },
        );
    }

    /// Script one successful `run_command` result.
    pub fn push_run(&self, result: McpShellCommandResult) {
        self.lock_run().push(Ok(result));
    }

    /// Script one failing `run_command` result (surfaced by the glue — never dropped).
    pub fn push_run_err(&self, err: McpError) {
        self.lock_run().push(Err(err));
    }

    /// Script one successful `send_text`.
    pub fn push_send_ok(&self) {
        self.lock_send().push(Ok(()));
    }

    /// Script one failing `send_text`.
    pub fn push_send_err(&self, err: McpError) {
        self.lock_send().push(Err(err));
    }

    /// Script one successful `read_terminal` output.
    pub fn push_read(&self, output: impl Into<String>) {
        self.lock_read().push(Ok(output.into()));
    }

    /// Script one failing `read_terminal`.
    pub fn push_read_err(&self, err: McpError) {
        self.lock_read().push(Err(err));
    }

    /// Calls observed so far (kind + id + arg length only — no bodies).
    pub fn calls(&self) -> Vec<McpShellCallRecord> {
        self.calls.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    pub fn call_count(&self) -> usize {
        self.calls.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    pub fn run_script_len(&self) -> usize {
        self.lock_run().len()
    }

    pub fn send_script_len(&self) -> usize {
        self.lock_send().len()
    }

    pub fn read_script_len(&self) -> usize {
        self.lock_read().len()
    }
}

#[async_trait]
impl McpShellRunner for FakeMcpShellRunner {
    async fn run_command(
        &self,
        session_id: &str,
        command: &str,
    ) -> Result<McpShellCommandResult, McpError> {
        self.record(McpShellCallKind::RunCommand, session_id, command.len());
        self.lock_run().pop(McpShellCallKind::RunCommand)
    }

    async fn send_text(&self, session_id: &str, text: &str) -> Result<(), McpError> {
        self.record(McpShellCallKind::SendText, session_id, text.len());
        self.lock_send().pop(McpShellCallKind::SendText)
    }

    async fn read_terminal(&self, session_id: &str) -> Result<String, McpError> {
        self.record(McpShellCallKind::ReadTerminal, session_id, 0);
        self.lock_read().pop(McpShellCallKind::ReadTerminal)
    }
}

impl fmt::Debug for FakeMcpShellRunner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeMcpShellRunner")
            .field("run_script_len", &self.run_script_len())
            .field("send_script_len", &self.send_script_len())
            .field("read_script_len", &self.read_script_len())
            .field("call_count", &self.call_count())
            // Intentionally no command / text / terminal bodies.
            .finish()
    }
}

/// Single tool result returned by [`McpToolRunnerGlue`].
///
/// `text` is stdout for `run_command`, `"ok"` for `send_text`, terminal output
/// for `read_terminal`, and the session list for `list_sessions`; `exit_code` is
/// `Some` only for `run_command`. [`Debug`] prints the text **length** only —
/// the payload can contain inline secrets / terminal output (C# never logs it).
#[derive(Clone, PartialEq, Eq)]
pub struct McpToolResult {
    pub text: String,
    pub exit_code: Option<i32>,
}

impl fmt::Debug for McpToolResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("McpToolResult")
            .field("text_len", &self.text.len())
            .field("exit_code", &self.exit_code)
            .finish()
    }
}

/// Tool arguments forwarded on [`McpDispatchRequest`].
///
/// Only the argument relevant to the tool is populated; [`Debug`] reports
/// **lengths** only, never the body.
#[derive(Clone, PartialEq, Eq)]
pub struct ToolCallArgs {
    pub command: Option<String>,
    pub text: Option<String>,
}

impl ToolCallArgs {
    pub fn none() -> Self {
        Self {
            command: None,
            text: None,
        }
    }

    pub fn command(command: impl Into<String>) -> Self {
        Self {
            command: Some(command.into()),
            text: None,
        }
    }

    pub fn text(text: impl Into<String>) -> Self {
        Self {
            command: None,
            text: Some(text.into()),
        }
    }
}

impl fmt::Debug for ToolCallArgs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ToolCallArgs")
            .field("command_len", &self.command.as_ref().map(String::len))
            .field("text_len", &self.text.as_ref().map(String::len))
            // Intentionally no command / text bodies.
            .finish()
    }
}

/// A validated, approved tool call being delivered to the dispatch layer.
///
/// `.tool` is a constants::`TOOL_*` name; `.session_id` is canonicalized and
/// `""` for `list_sessions` (which has no session). [`Debug`] shows arg lengths
/// only.
#[derive(Clone, PartialEq, Eq)]
pub struct McpDispatchRequest {
    pub tool: &'static str,
    pub session_id: String,
    pub args: ToolCallArgs,
}

impl fmt::Debug for McpDispatchRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("McpDispatchRequest")
            .field("tool", &self.tool)
            .field("session_id", &self.session_id)
            .field("args", &self.args)
            // `args` Debug already prints lengths only; no bearer / credential fields.
            .finish()
    }
}

/// Streamable-HTTP dispatch seam (rmcp-shaped) for delivered tool calls.
///
/// The product host wires an implementation that forwards to the rmcp handler's
/// `dispatch_tool`; this crate ships [`FakeMcpToolDispatch`], which records every
/// delivered request (tool + args + session id) and returns recorded status. No
/// axum / rmcp code lives here.
#[async_trait]
pub trait McpToolDispatch: Send + Sync + fmt::Debug {
    /// Deliver an already-validated, already-approved tool call.
    ///
    /// `Err` fails the whole tool call (no partial result is produced silently).
    async fn dispatch(&self, request: McpDispatchRequest) -> Result<(), McpError>;
}

/// Recording [`McpToolDispatch`] for unit tests.
///
/// [`Self::recorded`] returns delivered requests (tool name + args + session id)
/// in call order. [`Self::fail_next`] scripts a one-shot failure used to pin
/// "dispatch error surfaced, nothing silently dropped".
#[derive(Default)]
pub struct FakeMcpToolDispatch {
    recorded: Mutex<Vec<McpDispatchRequest>>,
    failure: Mutex<Option<McpError>>,
}

impl FakeMcpToolDispatch {
    /// Empty recorder — every delivery succeeds and is recorded.
    pub fn new() -> Self {
        Self::default()
    }

    /// Deliveries recorded so far (tool + args + session id).
    pub fn recorded(&self) -> Vec<McpDispatchRequest> {
        self.recorded.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    pub fn recorded_count(&self) -> usize {
        self.recorded.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    /// Script one delivery failure (consumed on the next [`Self::dispatch`]).
    pub fn fail_next(&self, err: McpError) {
        *self.failure.lock().unwrap_or_else(|p| p.into_inner()) = Some(err);
    }
}

#[async_trait]
impl McpToolDispatch for FakeMcpToolDispatch {
    async fn dispatch(&self, request: McpDispatchRequest) -> Result<(), McpError> {
        if let Some(err) = self.failure.lock().unwrap_or_else(|p| p.into_inner()).take() {
            return Err(err);
        }
        self.recorded.lock().unwrap_or_else(|p| p.into_inner()).push(request);
        Ok(())
    }
}

impl fmt::Debug for FakeMcpToolDispatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeMcpToolDispatch")
            .field("recorded_count", &self.recorded_count())
            .field("has_failure", &self.failure.lock().unwrap_or_else(|p| p.into_inner()).is_some())
            .finish()
    }
}

/// Glue that executes the four MCP SSH tools against injectable seams.
///
/// Per tool call (C# `ResolveApprovedAsync` ordering, with input validation
/// first): resolve the **Connected** session from the registry → approve the
/// first action via the shared [`SessionApprovalGate`] → invoke the
/// [`McpShellRunner`] → record the delivered call on [`McpToolDispatch`]. Denied /
/// cancelled / closed / unknown / not-connected calls never reach the shell.
/// `list_sessions` needs no approval and just lists the registry.
///
/// This supersedes `FakeMcpToolApprovalGlue::execute_tool` (which always failed
/// "not wired") by actually dispatching through the seams — the approval
/// semantics and Connected eligibility are unchanged.
pub struct McpToolRunnerGlue {
    gate: Arc<SessionApprovalGate>,
    registry: Arc<FakeMcpSessionRegistry>,
    runner: Arc<dyn McpShellRunner>,
    dispatch: Arc<dyn McpToolDispatch>,
}

impl McpToolRunnerGlue {
    /// Fresh gate + empty registry + injected seams.
    pub fn new(
        runner: Arc<dyn McpShellRunner>,
        dispatch: Arc<dyn McpToolDispatch>,
    ) -> Self {
        Self::from_parts(
            Arc::new(SessionApprovalGate::new()),
            Arc::new(FakeMcpSessionRegistry::new()),
            runner,
            dispatch,
        )
    }

    /// Same as [`Self::new`] but with a pre-seeded registry shared with the host.
    pub fn with_registry(
        registry: Arc<FakeMcpSessionRegistry>,
        runner: Arc<dyn McpShellRunner>,
        dispatch: Arc<dyn McpToolDispatch>,
    ) -> Self {
        Self::from_parts(Arc::new(SessionApprovalGate::new()), registry, runner, dispatch)
    }

    /// Share an existing gate + registry with the app (default AutoDeny until a
    /// UI / test channel attaches — mirror of `FakeMcpToolApprovalGlue::from_parts`).
    pub fn from_parts(
        gate: Arc<SessionApprovalGate>,
        registry: Arc<FakeMcpSessionRegistry>,
        runner: Arc<dyn McpShellRunner>,
        dispatch: Arc<dyn McpToolDispatch>,
    ) -> Self {
        Self {
            gate,
            registry,
            runner,
            dispatch,
        }
    }

    pub fn gate(&self) -> Arc<SessionApprovalGate> {
        Arc::clone(&self.gate)
    }

    pub fn registry(&self) -> Arc<FakeMcpSessionRegistry> {
        Arc::clone(&self.registry)
    }

    pub fn runner(&self) -> Arc<dyn McpShellRunner> {
        Arc::clone(&self.runner)
    }

    pub fn dispatch(&self) -> Arc<dyn McpToolDispatch> {
        Arc::clone(&self.dispatch)
    }

    /// Open an Approve/Deny/Cancel channel on the gate (test / UI wiring).
    pub fn open_channel(
        &self,
    ) -> tokio::sync::mpsc::UnboundedReceiver<crate::ApprovalRequest> {
        self.gate.open_channel()
    }

    /// Auto-approve every first action (unit tests).
    pub fn set_auto_approve(&self) {
        self.gate.set_auto_approve();
    }

    /// Auto-deny every first action (fail closed until a channel attaches).
    pub fn set_auto_deny(&self) {
        self.gate.set_auto_deny();
    }

    /// List the connected sessions (no approval needed; `list_sessions` tool).
    pub async fn list_sessions(&self) -> Result<McpToolResult, McpError> {
        let sessions = self.registry.list_sessions();
        let text = render_sessions(&sessions);
        self.record(TOOL_LIST_SESSIONS, "", ToolCallArgs::none())
            .await?;
        Ok(McpToolResult {
            text,
            exit_code: None,
        })
    }

    /// `run_command` — returns stdout + exit code in [`McpToolResult`].
    pub async fn run_command(
        &self,
        session_id: &str,
        command: &str,
    ) -> Result<McpToolResult, McpError> {
        if command.is_empty() {
            return Err(McpError::Message(
                "MCP run_command requires a non-empty command.".into(),
            ));
        }
        let info = self.approve(session_id, TOOL_RUN_COMMAND).await?;
        let result = self.runner.run_command(&info.id, command).await?;
        self.record(TOOL_RUN_COMMAND, &info.id, ToolCallArgs::command(command))
            .await?;
        Ok(McpToolResult {
            text: result.output,
            exit_code: Some(result.exit_code),
        })
    }

    /// `send_text` — raw bytes typed into the session; returns `"ok"`.
    pub async fn send_text(
        &self,
        session_id: &str,
        text: &str,
    ) -> Result<McpToolResult, McpError> {
        if text.is_empty() {
            return Err(McpError::Message(
                "MCP send_text requires non-empty text.".into(),
            ));
        }
        let info = self.approve(session_id, TOOL_SEND_TEXT).await?;
        self.runner.send_text(&info.id, text).await?;
        self.record(TOOL_SEND_TEXT, &info.id, ToolCallArgs::text(text))
            .await?;
        Ok(McpToolResult {
            text: "ok".into(),
            exit_code: None,
        })
    }

    /// `read_terminal` — recent terminal output for the session.
    pub async fn read_terminal(&self, session_id: &str) -> Result<McpToolResult, McpError> {
        let info = self.approve(session_id, TOOL_READ_TERMINAL).await?;
        let text = self.runner.read_terminal(&info.id).await?;
        self.record(TOOL_READ_TERMINAL, &info.id, ToolCallArgs::none())
            .await?;
        Ok(McpToolResult {
            text,
            exit_code: None,
        })
    }

    /// Dispatch-shaped entry mirroring rmcp `dispatch_tool(name, arguments)`.
    ///
    /// `session_id` is ignored by `list_sessions`; `args` carries the tool's own
    /// argument. Unknown tool names fail closed.
    pub async fn dispatch_tool(
        &self,
        name: &str,
        session_id: &str,
        args: ToolCallArgs,
    ) -> Result<McpToolResult, McpError> {
        match name {
            TOOL_LIST_SESSIONS => self.list_sessions().await,
            TOOL_RUN_COMMAND => {
                let command = args
                    .command
                    .ok_or_else(|| McpError::Message("run_command requires a command".into()))?;
                self.run_command(session_id, &command).await
            }
            TOOL_SEND_TEXT => {
                let text = args
                    .text
                    .ok_or_else(|| McpError::Message("send_text requires text".into()))?;
                self.send_text(session_id, &text).await
            }
            TOOL_READ_TERMINAL => self.read_terminal(session_id).await,
            other => Err(McpError::Message(format!(
                "MCP tool '{other}' is not executable"
            ))),
        }
    }

    /// Connected eligibility (registry) + first-touch approval (C# `ResolveApprovedAsync`).
    ///
    /// Unknown / blank / control-char / non-Connected ids fail before the gate,
    /// exactly like `FakeMcpToolApprovalGlue::ensure_allowed`.
    async fn approve(&self, session_id: &str, tool: &'static str) -> Result<McpSessionInfo, McpError> {
        let info = self.registry.get_connected(session_id)?;
        self.gate.ensure_approved(&info.id, tool).await?;
        Ok(info)
    }

    /// Deliver the executed call to the dispatch layer (record failure fails the tool).
    async fn record(
        &self,
        tool: &'static str,
        session_id: &str,
        args: ToolCallArgs,
    ) -> Result<(), McpError> {
        self.dispatch
            .dispatch(McpDispatchRequest {
                tool,
                session_id: session_id.to_owned(),
                args,
            })
            .await
    }
}

impl fmt::Debug for McpToolRunnerGlue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("McpToolRunnerGlue")
            .field("gate", &self.gate)
            .field("registry", &self.registry)
            .field("runner", &self.runner)
            .field("dispatch", &self.dispatch)
            // Seams' Debug impls are length/count-only; no bearer / credential fields.
            .finish()
    }
}

/// Render connected sessions as plain text lines (id host port username title
/// status). Deterministic Lab shape — C# returns a structured list; this Lab has
/// no serde dependency when the `rmcp` feature is off.
fn render_sessions(sessions: &[McpSessionInfo]) -> String {
    let mut out = String::new();
    for (i, info) in sessions.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&format!(
            "{} {} {} {} {} {}",
            sanitize_line_field(&info.id),
            sanitize_line_field(&info.host),
            info.port,
            sanitize_line_field(&info.username),
            sanitize_line_field(&info.title),
            info.status.as_str()
        ));
    }
    out
}

/// Neutralize control characters (newline, CR, tab, NUL, ESC, …) that would
/// otherwise corrupt the line-oriented `list_sessions` text. Session ids are
/// already validated control-free by the registry, but host / username / title
/// come from the live tab bar unvalidated — a remote SSH server can set the tab
/// title via OSC escape sequences, and C# `McpSshTools` returns a structured
/// list while this Lab's plain-text shape must stay line-stable for MCP clients.
fn sanitize_line_field(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::{approve_pending, cancel_pending, deny_pending};
    use crate::capability::TOOL_LIST_SESSIONS;

    fn sample_session_registry(ids: &[&str]) -> Arc<FakeMcpSessionRegistry> {
        let reg = FakeMcpSessionRegistry::new();
        for id in ids {
            reg.register(McpSessionInfo::connected(*id, "host.example", 22, "alice", "prod"))
                .unwrap();
        }
        Arc::new(reg)
    }

    fn seeded(id: &str) -> Arc<FakeMcpSessionRegistry> {
        sample_session_registry(&[id])
    }

    /// Build the glue from concrete Arc'd fakes (unsize-coerced trait objects).
    fn glue_with(
        reg: Arc<FakeMcpSessionRegistry>,
        runner: &Arc<FakeMcpShellRunner>,
        dispatch: &Arc<FakeMcpToolDispatch>,
    ) -> McpToolRunnerGlue {
        McpToolRunnerGlue::with_registry(
            reg,
            Arc::clone(runner) as Arc<dyn McpShellRunner>,
            Arc::clone(dispatch) as Arc<dyn McpToolDispatch>,
        )
    }

    #[tokio::test]
    async fn run_command_approve_executes_and_returns_stdout_exit() {
        let reg = seeded("s1");
        let runner = Arc::new(FakeMcpShellRunner::new());
        runner.push_run(McpShellCommandResult {
            output: "hello".into(),
            exit_code: 0,
            timed_out: false,
            truncated: false,
        });
        let dispatch = Arc::new(FakeMcpToolDispatch::new());
        let glue = glue_with(reg.clone(), &runner, &dispatch);

        glue.set_auto_approve();
        let result = glue.run_command("s1", "echo hi").await.unwrap();
        assert_eq!(result.text, "hello");
        assert_eq!(result.exit_code, Some(0));
        assert!(glue.gate().is_approved("s1"));

        let rec = dispatch.recorded();
        assert_eq!(rec.len(), 1);
        assert_eq!(rec[0].tool, TOOL_RUN_COMMAND);
        assert_eq!(rec[0].session_id, "s1");
        assert_eq!(rec[0].args.command.as_deref(), Some("echo hi"));
    }

    #[tokio::test]
    async fn deny_does_not_execute_and_fails_closed() {
        let reg = seeded("s1");
        let runner = Arc::new(FakeMcpShellRunner::new());
        runner.push_run(McpShellCommandResult::success("SHOULD NOT RUN"));
        let dispatch = Arc::new(FakeMcpToolDispatch::new());
        let glue = glue_with(reg.clone(), &runner, &dispatch);
        let mut rx = glue.open_channel();
        let gate = glue.gate();

        let pending = tokio::spawn(async move { glue.run_command("s1", "evil").await });
        let req = rx.recv().await.expect("pending approve");
        assert!(deny_pending(req));
        let err = pending.await.unwrap().unwrap_err();
        assert!(err.to_string().contains("denied"));
        assert!(!gate.is_approved("s1"), "denied session stays unapproved");
        assert_eq!(runner.call_count(), 0, "shell must not run");
        assert_eq!(dispatch.recorded_count(), 0);
    }

    #[tokio::test]
    async fn cancel_does_not_execute_and_fails_closed() {
        let reg = seeded("s3");
        let runner = Arc::new(FakeMcpShellRunner::new());
        let dispatch = Arc::new(FakeMcpToolDispatch::new());
        let glue = glue_with(reg.clone(), &runner, &dispatch);
        let gate = glue.gate();
        let mut rx = glue.open_channel();

        let pending = tokio::spawn(async move { glue.send_text("s3", "whoami\r").await });
        let req = rx.recv().await.expect("pending approve");
        assert!(cancel_pending(req));
        let err = pending.await.unwrap().unwrap_err();
        assert!(err.to_string().contains("cancelled"));
        assert!(!gate.is_approved("s3"));
        assert_eq!(runner.call_count(), 0, "shell must not run");
        assert_eq!(dispatch.recorded_count(), 0);
    }

    #[tokio::test]
    async fn auto_deny_without_listener_fails_closed() {
        let reg = seeded("s1");
        let runner = Arc::new(FakeMcpShellRunner::new());
        let dispatch = Arc::new(FakeMcpToolDispatch::new());
        let glue = glue_with(reg, &runner, &dispatch);
        let err = glue.read_terminal("s1").await.unwrap_err();
        assert!(err.to_string().contains("denied"));
        assert_eq!(runner.call_count(), 0, "shell must not run");
    }

    #[tokio::test]
    async fn approve_once_then_later_calls_skip_prompt() {
        let reg = seeded("s1");
        let runner = Arc::new(FakeMcpShellRunner::new());
        runner.push_run(McpShellCommandResult::success("first"));
        runner.push_run(McpShellCommandResult::success("second"));
        let dispatch = Arc::new(FakeMcpToolDispatch::new());
        let glue = glue_with(reg.clone(), &runner, &dispatch);
        let mut rx = glue.open_channel();
        // Capture shared parts before `glue` is moved into the spawned task.
        let shared_gate = glue.gate();
        let shared_registry = glue.registry();

        // First action prompts; approve it.
        let pending = tokio::spawn(async move { glue.run_command("s1", "cmd one").await });
        let req = rx.recv().await.expect("first approve");
        assert_eq!(req.session_id, "s1");
        assert_eq!(req.tool, TOOL_RUN_COMMAND);
        assert!(approve_pending(req));
        pending.await.unwrap().unwrap();

        // Second action on the same session must NOT re-prompt. Build a second
        // glue sharing the same gate + registry so the approval cache carries over.
        let glue2 = McpToolRunnerGlue::from_parts(
            shared_gate,
            shared_registry,
            Arc::clone(&runner) as Arc<dyn McpShellRunner>,
            Arc::clone(&dispatch) as Arc<dyn McpToolDispatch>,
        );
        let second = glue2.run_command("s1", "cmd two").await.unwrap();
        assert_eq!(second.text, "second");
        assert!(rx.try_recv().is_err(), "no second approval prompt");
        assert_eq!(dispatch.recorded_count(), 2);
    }

    #[tokio::test]
    async fn unknown_session_denied_shell_never_invoked() {
        let reg = Arc::new(FakeMcpSessionRegistry::new()); // empty
        let runner = Arc::new(FakeMcpShellRunner::new());
        runner.push_run(McpShellCommandResult::success("nope"));
        let dispatch = Arc::new(FakeMcpToolDispatch::new());
        let glue = glue_with(reg, &runner, &dispatch);
        glue.set_auto_approve();

        let err = glue.run_command("ghost", "whoami").await.unwrap_err();
        assert!(err.to_string().contains("No live SSH session"));
        assert_eq!(runner.call_count(), 0, "shell must never run");
        assert_eq!(dispatch.recorded_count(), 0);
    }

    #[tokio::test]
    async fn empty_command_and_text_rejected_before_approval() {
        let reg = seeded("s1");
        let runner = Arc::new(FakeMcpShellRunner::new());
        let dispatch = Arc::new(FakeMcpToolDispatch::new());
        let glue = glue_with(reg.clone(), &runner, &dispatch);
        let mut rx = glue.open_channel();

        assert!(glue
            .run_command("s1", "")
            .await
            .unwrap_err()
            .to_string()
            .contains("non-empty"));
        assert!(glue
            .send_text("s1", "")
            .await
            .unwrap_err()
            .to_string()
            .contains("non-empty"));
        assert!(rx.try_recv().is_err(), "invalid input must not prompt");
        assert_eq!(runner.call_count(), 0, "shell must never run");
        assert_eq!(dispatch.recorded_count(), 0);
        assert!(!glue.gate().is_approved("s1"));
    }

    #[tokio::test]
    async fn read_on_unknown_or_not_connected_fails_closed() {
        let reg = seeded("s1");
        let runner = Arc::new(FakeMcpShellRunner::new());
        let dispatch = Arc::new(FakeMcpToolDispatch::new());
        let glue = glue_with(reg, &runner, &dispatch);
        glue.set_auto_approve();

        let err = glue.read_terminal("not-open").await.unwrap_err();
        assert!(err.to_string().contains("No live SSH session"));
        assert_eq!(runner.call_count(), 0, "shell must never run");
    }

    #[tokio::test]
    async fn exhausted_shell_script_fails_closed() {
        let reg = seeded("s1");
        let runner = Arc::new(FakeMcpShellRunner::new()); // no script
        let dispatch = Arc::new(FakeMcpToolDispatch::new());
        let glue = glue_with(reg, &runner, &dispatch);
        glue.set_auto_approve();

        let err = glue.run_command("s1", "boom").await.unwrap_err();
        assert!(err.to_string().contains("no scripted run_command result"));
        assert_eq!(dispatch.recorded_count(), 0, "no record of a failed exec");
    }

    #[tokio::test]
    async fn exhausted_send_and_read_scripts_fail_closed() {
        // Each method has its own result queue; an empty queue fails closed and
        // nothing is recorded to dispatch (no phantom "ok" / empty read).
        let reg = seeded("s1");
        let runner = Arc::new(FakeMcpShellRunner::new());
        let dispatch = Arc::new(FakeMcpToolDispatch::new());
        let glue = glue_with(reg, &runner, &dispatch);
        glue.set_auto_approve();

        let send_err = glue.send_text("s1", "hi\r").await.unwrap_err();
        assert!(send_err.to_string().contains("no scripted send_text result"));
        let read_err = glue.read_terminal("s1").await.unwrap_err();
        assert!(read_err.to_string().contains("no scripted read_terminal result"));
        assert_eq!(runner.call_count(), 2, "both attempts reached the runner");
        assert_eq!(dispatch.recorded_count(), 0, "no failed exec recorded");
    }

    #[tokio::test]
    async fn shell_error_surfaced_not_dropped() {
        let reg = seeded("s1");
        let runner = Arc::new(FakeMcpShellRunner::new());
        runner.push_send_err(McpError::Message("connection reset".into()));
        let dispatch = Arc::new(FakeMcpToolDispatch::new());
        let glue = glue_with(reg, &runner, &dispatch);
        glue.set_auto_approve();

        let err = glue.send_text("s1", "echo hi\r").await.unwrap_err();
        assert!(err.to_string().contains("connection reset"));
        assert_eq!(dispatch.recorded_count(), 0);
    }

    #[tokio::test]
    async fn dispatch_failure_surfaces_no_partial_result() {
        let reg = seeded("s1");
        let runner = Arc::new(FakeMcpShellRunner::new());
        runner.push_run(McpShellCommandResult::success("ran anyway"));
        let dispatch = Arc::new(FakeMcpToolDispatch::new());
        dispatch.fail_next(McpError::Message("dispatch refused".into()));
        let glue = glue_with(reg, &runner, &dispatch);
        glue.set_auto_approve();

        let err = glue.run_command("s1", "echo hi").await.unwrap_err();
        assert!(err.to_string().contains("dispatch refused"));
        assert_eq!(dispatch.recorded_count(), 0, "failed delivery not recorded");
    }

    #[tokio::test]
    async fn send_text_returns_ok_and_dispatches() {
        let reg = seeded("s2");
        let runner = Arc::new(FakeMcpShellRunner::new());
        runner.push_send_ok();
        let dispatch = Arc::new(FakeMcpToolDispatch::new());
        let glue = glue_with(reg, &runner, &dispatch);
        glue.set_auto_approve();

        let result = glue.send_text("s2", "useradd\r").await.unwrap();
        assert_eq!(result.text, "ok");
        assert_eq!(result.exit_code, None);
        let rec = dispatch.recorded();
        assert_eq!(rec[0].tool, TOOL_SEND_TEXT);
        assert_eq!(rec[0].session_id, "s2");
        assert_eq!(rec[0].args.text.as_deref(), Some("useradd\r"));
    }

    #[tokio::test]
    async fn list_sessions_requires_no_approval_and_renders_connected() {
        let reg = sample_session_registry(&["a", "b"]);
        let runner = Arc::new(FakeMcpShellRunner::new());
        let dispatch = Arc::new(FakeMcpToolDispatch::new());
        let glue = glue_with(reg, &runner, &dispatch);
        // No auto-approve: list_sessions must still work.
        let result = glue.list_sessions().await.unwrap();
        let lines: Vec<_> = result.text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("a host.example 22 alice prod Connected"));
        assert!(lines[1].starts_with("b host.example 22 alice prod Connected"));
        assert_eq!(result.exit_code, None);
        assert_eq!(dispatch.recorded()[0].tool, TOOL_LIST_SESSIONS);
    }

    #[tokio::test]
    async fn dispatch_tool_routes_by_name_and_rejects_unknown() {
        let reg = seeded("s1");
        let runner = Arc::new(FakeMcpShellRunner::new());
        runner.push_run(McpShellCommandResult::success("x"));
        runner.push_read("pty output");
        let dispatch = Arc::new(FakeMcpToolDispatch::new());
        let glue = glue_with(reg, &runner, &dispatch);
        glue.set_auto_approve();

        let ran = glue
            .dispatch_tool(TOOL_RUN_COMMAND, "s1", ToolCallArgs::command("ls"))
            .await
            .unwrap();
        assert_eq!(ran.text, "x");
        let read = glue
            .dispatch_tool(TOOL_READ_TERMINAL, "s1", ToolCallArgs::none())
            .await
            .unwrap();
        assert_eq!(read.text, "pty output");

        let missing_arg = glue
            .dispatch_tool(TOOL_RUN_COMMAND, "s1", ToolCallArgs::none())
            .await
            .unwrap_err();
        assert!(missing_arg.to_string().contains("requires a command"));

        let unknown = glue
            .dispatch_tool("not_a_tool", "s1", ToolCallArgs::none())
            .await
            .unwrap_err();
        assert!(unknown.to_string().contains("not executable"));
    }

    #[tokio::test]
    async fn approve_via_one_tool_then_other_tools_skip_prompt() {
        // C# first-touch dialog: one approval per session, all tools then pass.
        let reg = seeded("s1");
        let runner = Arc::new(FakeMcpShellRunner::new());
        runner.push_run(McpShellCommandResult::success("ran"));
        runner.push_send_ok();
        runner.push_read("pty");
        let dispatch = Arc::new(FakeMcpToolDispatch::new());
        let glue = glue_with(reg, &runner, &dispatch);
        let mut rx = glue.open_channel();
        let shared_gate = glue.gate();
        let shared_registry = glue.registry();

        let pending = tokio::spawn(async move { glue.run_command("s1", "cmd").await });
        let req = rx.recv().await.expect("first approve");
        assert_eq!(req.tool, TOOL_RUN_COMMAND);
        assert!(approve_pending(req));
        pending.await.unwrap().unwrap();

        let glue2 = McpToolRunnerGlue::from_parts(
            shared_gate,
            shared_registry,
            Arc::clone(&runner) as Arc<dyn McpShellRunner>,
            Arc::clone(&dispatch) as Arc<dyn McpToolDispatch>,
        );
        let sent = glue2.send_text("s1", "ctrl-c\r").await.unwrap();
        assert_eq!(sent.text, "ok");
        let read = glue2.read_terminal("s1").await.unwrap();
        assert_eq!(read.text, "pty");
        assert!(rx.try_recv().is_err(), "no further approval prompts");
        assert_eq!(dispatch.recorded_count(), 3);
        assert_eq!(runner.call_count(), 3);
    }

    #[tokio::test]
    async fn list_sessions_dispatch_failure_surfaces_error() {
        let reg = seeded("s1");
        let runner = Arc::new(FakeMcpShellRunner::new());
        let dispatch = Arc::new(FakeMcpToolDispatch::new());
        dispatch.fail_next(McpError::Message("dispatch refused".into()));
        let glue = glue_with(reg, &runner, &dispatch);

        let err = glue.list_sessions().await.unwrap_err();
        assert!(err.to_string().contains("dispatch refused"));
    }

    #[tokio::test]
    async fn dispatch_tool_accepts_padded_session_id() {
        let reg = seeded("s1");
        let runner = Arc::new(FakeMcpShellRunner::new());
        runner.push_run(McpShellCommandResult::success("ok"));
        let dispatch = Arc::new(FakeMcpToolDispatch::new());
        let glue = glue_with(reg, &runner, &dispatch);
        glue.set_auto_approve();

        let result = glue
            .dispatch_tool(TOOL_RUN_COMMAND, "  s1  ", ToolCallArgs::command("ls"))
            .await
            .unwrap();
        assert_eq!(result.text, "ok");
        // Canonical id flows to the shell and the dispatch record.
        let rec = dispatch.recorded();
        assert_eq!(rec.len(), 1);
        assert_eq!(rec[0].session_id, "s1");
        let calls = runner.calls();
        assert_eq!(calls[0].session_id, "s1");
    }

    #[tokio::test]
    async fn shell_call_records_argument_lengths_only() {
        let reg = seeded("s1");
        let runner = Arc::new(FakeMcpShellRunner::new());
        runner.push_run(McpShellCommandResult::success("x"));
        runner.push_send_ok();
        runner.push_read("y");
        let dispatch = Arc::new(FakeMcpToolDispatch::new());
        let glue = glue_with(reg, &runner, &dispatch);
        glue.set_auto_approve();

        glue.run_command("s1", "echo hi").await.unwrap();
        glue.send_text("s1", "whoami\r").await.unwrap();
        glue.read_terminal("s1").await.unwrap();

        let calls = runner.calls();
        assert_eq!(
            calls[0],
            McpShellCallRecord {
                kind: McpShellCallKind::RunCommand,
                session_id: "s1".into(),
                arg_len: 7,
            }
        );
        assert_eq!(calls[1].kind, McpShellCallKind::SendText);
        assert_eq!(calls[1].arg_len, 7);
        assert_eq!(calls[2].kind, McpShellCallKind::ReadTerminal);
        assert_eq!(calls[2].arg_len, 0);
    }

    #[tokio::test]
    async fn list_sessions_sanitizes_control_chars_from_metadata() {
        // A remote server can set the tab title via OSC escape sequences; the
        // line-oriented list_sessions text must not be splittable by the client.
        let reg = FakeMcpSessionRegistry::new();
        reg.register(McpSessionInfo::connected(
            "s1",
            "host.example\r",
            22,
            "alice",
            "prod\nevil\ns2",
        ))
        .unwrap();
        let runner = Arc::new(FakeMcpShellRunner::new());
        let dispatch = Arc::new(FakeMcpToolDispatch::new());
        let glue = glue_with(Arc::new(reg), &runner, &dispatch);

        let result = glue.list_sessions().await.unwrap();
        let text = result.text;
        assert_eq!(text.lines().count(), 1, "no injected lines");
        assert!(!text.contains('\r'));
        assert!(text.contains("host.example"));
        assert!(text.contains("prod evil s2"));
    }

    #[test]
    fn debug_redacts_bodies_and_never_mentions_credentials() {
        let result = McpToolResult {
            text: "mysql -ptoppass".into(),
            exit_code: Some(1),
        };
        let rdbg = format!("{result:?}");
        assert!(rdbg.contains("text_len"));
        assert!(!rdbg.contains("toppass"));
        assert!(!rdbg.contains("mysql"));

        let cmd = McpShellCommandResult {
            output: "secret inline".into(),
            exit_code: 0,
            timed_out: false,
            truncated: false,
        };
        let cdbg = format!("{cmd:?}");
        assert!(cdbg.contains("output_len"));
        assert!(!cdbg.contains("secret inline"));

        let args = ToolCallArgs::command("do --pass=topsecret");
        let adbg = format!("{args:?}");
        assert!(adbg.contains("command_len"));
        assert!(!adbg.contains("topsecret"));

        let req = McpDispatchRequest {
            tool: TOOL_RUN_COMMAND,
            session_id: "s1".into(),
            args: ToolCallArgs::text("password123"),
        };
        let rqdbg = format!("{req:?}");
        assert!(rqdbg.contains("session_id"));
        assert!(!rqdbg.contains("password123"));
        assert!(!rqdbg.to_ascii_lowercase().contains("bearer"));
        assert!(!rqdbg.contains("password"));

        let runner = FakeMcpShellRunner::new();
        runner.push_run(McpShellCommandResult::success("corp secret"));
        let rudbg = format!("{runner:?}");
        assert!(!rudbg.contains("corp secret"));
        assert!(!rudbg.to_ascii_lowercase().contains("bearer"));

        let dispatch = FakeMcpToolDispatch::new();
        let dd = format!("{dispatch:?}");
        assert!(!dd.to_ascii_lowercase().contains("bearer"));
    }
}
