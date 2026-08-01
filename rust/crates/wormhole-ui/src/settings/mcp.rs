//! Settings → MCP: loopback Streamable HTTP server toggle / port / bearer token glue.
//!
//! Lab scope: VM + Fake glue only. C# parity: `ViewModels/SettingsViewModel.cs` MCP
//! section (`OnEnableMcpServerChanged` / `OnMcpServerPortChanged` / `RevealMcpTokenAsync`
//! / `CopyMcpTokenAsync` / `RegenerateMcpTokenAsync`) + `Services/Mcp/McpServerHost.cs`
//! constants. There is **no** live server start/stop here — the VM emits an *apply
//! command* and the Fake host records the last applied `(enabled, port)`. No GPUI, no
//! WebView, no runtime.
//!
//! The toggle flow mirrors the C# `_suppressMcpToggle` re-entrancy guard with an
//! [`McpSettingsVm::is_applying`] flag: a nested toggle while an apply is in flight is
//! ignored, and a failed apply reverts the VM field + persisted document **without**
//! firing a second apply (the guard still holds during the revert).
//!
//! Port validation imports [`wormhole_mcp::validate_mcp_port`] — the port rules are
//! **not** duplicated here; the `u16` conversion supplies the 1..=65535 envelope.
//!
//! | Port input | Result |
//! |---|---|
//! | `1..=65535` (fits `u16` and passes `validate_mcp_port`) | persists; applies on next toggle |
//! | `0` | rejected (wormhole-mcp `InvalidPort`), error surfaced, **not** persisted |
//! | negative / `> u16::MAX` (hostile) | rejected, error surfaced, **not** persisted |
//! | hostile value already on disk (corrupt JSON) | clamped to [`wormhole_mcp::DEFAULT_MCP_PORT`] at VM construction |
//!
//! Tokens come from an injectable synchronous [`McpTokenHandle`]; products wrap
//! `wormhole_mcp::get_or_create_token` / `regenerate_token` (async over the async
//! `wormhole_mcp::McpTokenStore`, which does not fit this GPUI-free synchronous VM).
//! Regeneration mints via [`wormhole_mcp::generate_bearer_token`]. The VM never
//! retains a token — reveal/copy return it to the caller — and [`Debug`](std::fmt::Debug)
//! shows presence only.

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use thiserror::Error;
use wormhole_mcp::{generate_bearer_token, validate_mcp_port, DEFAULT_MCP_PORT};

use super::model::AppSettings;
use super::store::{MemorySettingsStore, SettingsError, SettingsStore};

/// Port validation error (fail-closed entry gate).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum McpPortError {
    /// Outside the `u16` envelope (`0` handled below only when it fits).
    #[error("MCP port must be between 1 and 65535 (got {0})")]
    OutOfRange(i32),
    /// wormhole-mcp `validate_mcp_port` rejection (its own message: port `0`).
    #[error("{0}")]
    Rejected(String),
}

/// Apply-command failure from the host (C# `ApplyMcpToggleAsync` catch block).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{0}")]
pub struct McpApplyError(pub String);

/// Bearer-token handle failure (message never contains token material).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("MCP token store error: {0}")]
pub struct McpTokenError(pub String);

/// VM-level errors (C# dialogs: "Couldn't start MCP server", "Couldn't read MCP token",
/// and the silent port guard which this Lab surfaces fail-closed instead).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum McpSettingsError {
    #[error("{0}")]
    Port(McpPortError),
    #[error("settings load error: {0}")]
    Load(SettingsError),
    #[error("settings persist error: {0}")]
    Persist(SettingsError),
    #[error("MCP server apply failed: {0}")]
    Apply(McpApplyError),
    #[error("{0}")]
    Token(McpTokenError),
}

/// Synchronous bearer-token handle injected into the VM.
///
/// C# `_mcpHost.GetOrCreateTokenAsync` / `RegenerateTokenAsync` are async (CredMgr +
/// gate); the product host wraps `wormhole_mcp::get_or_create_token` /
/// `regenerate_token` with its own runtime and implements this trait. The lab uses
/// [`FakeMcpTokenHandle`].
pub trait McpTokenHandle: Send + Sync {
    /// Read-or-mint the token (C# `GetOrCreateTokenAsync`).
    fn get_or_create(&self) -> Result<String, McpTokenError>;
    /// Replace the stored token with a fresh one (C# `RegenerateTokenAsync`).
    fn regenerate(&self) -> Result<String, McpTokenError>;
    /// Whether a non-empty token is stored (UI hint; never reveals it).
    fn has_token(&self) -> bool;
}

/// Deterministic in-memory token handle for the lab harness.
///
/// `get_or_create` returns the seeded token or mints one via
/// [`wormhole_mcp::generate_bearer_token`]; `regenerate` always mints. Failures are
/// scriptable so tests can exercise the fail-closed paths.
#[derive(Default)]
pub struct FakeMcpTokenHandle {
    token: Mutex<Option<String>>,
    get_failures_left: AtomicUsize,
    regenerate_failures_left: AtomicUsize,
    regenerate_calls: AtomicUsize,
    get_calls: AtomicUsize,
}

impl FakeMcpTokenHandle {
    /// Empty handle (mints on first `get_or_create`).
    pub fn new() -> Self {
        Self::default()
    }

    /// Handle pre-seeded with a token.
    pub fn with_token(token: impl Into<String>) -> Self {
        Self {
            token: Mutex::new(Some(token.into())),
            ..Self::default()
        }
    }

    /// Lab seed token (deterministic, clearly not a real secret).
    pub fn seeded() -> Self {
        Self::with_token("lab-seed-mcp-bearer-token")
    }

    /// Script the next `n` `get_or_create` calls to fail.
    pub fn set_get_failures(&self, n: usize) {
        self.get_failures_left.store(n, Ordering::SeqCst);
    }

    /// Script the next `n` `regenerate` calls to fail.
    pub fn set_regenerate_failures(&self, n: usize) {
        self.regenerate_failures_left.store(n, Ordering::SeqCst);
    }

    /// How many `regenerate` calls ran.
    pub fn regenerate_calls(&self) -> usize {
        self.regenerate_calls.load(Ordering::SeqCst)
    }

    /// How many `get_or_create` calls ran.
    pub fn get_calls(&self) -> usize {
        self.get_calls.load(Ordering::SeqCst)
    }

    /// Stored token (lab inspection / assertions only — never log it).
    pub fn stored_token(&self) -> Option<String> {
        self.token
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}

impl fmt::Debug for FakeMcpTokenHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let present = self
            .stored_token()
            .as_ref()
            .is_some_and(|t| !t.is_empty());
        f.debug_struct("FakeMcpTokenHandle")
            .field("token", &if present { "[REDACTED]" } else { "None" })
            .field("get_calls", &self.get_calls())
            .field("regenerate_calls", &self.regenerate_calls())
            .finish()
    }
}

impl McpTokenHandle for FakeMcpTokenHandle {
    fn get_or_create(&self) -> Result<String, McpTokenError> {
        self.get_calls.fetch_add(1, Ordering::SeqCst);
        let left = self.get_failures_left.load(Ordering::SeqCst);
        if left > 0 {
            self.get_failures_left.fetch_sub(1, Ordering::SeqCst);
            return Err(McpTokenError("fake token read failure".into()));
        }
        let existing = self.stored_token();
        match existing.filter(|t| !t.is_empty()) {
            Some(token) => Ok(token),
            None => {
                let minted = generate_bearer_token()
                    .map_err(|e| McpTokenError(e.to_string()))?;
                *self.token.lock().unwrap_or_else(|p| p.into_inner()) = Some(minted.clone());
                Ok(minted)
            }
        }
    }

    fn regenerate(&self) -> Result<String, McpTokenError> {
        self.regenerate_calls.fetch_add(1, Ordering::SeqCst);
        let left = self.regenerate_failures_left.load(Ordering::SeqCst);
        if left > 0 {
            self.regenerate_failures_left.fetch_sub(1, Ordering::SeqCst);
            return Err(McpTokenError("fake token regenerate failure".into()));
        }
        let minted =
            generate_bearer_token().map_err(|e| McpTokenError(e.to_string()))?;
        *self.token.lock().unwrap_or_else(|p| p.into_inner()) = Some(minted.clone());
        Ok(minted)
    }

    fn has_token(&self) -> bool {
        self.stored_token()
            .as_ref()
            .is_some_and(|t| !t.is_empty())
    }
}

/// Apply-command host (C# `IMcpServerHost.StartAsync` / `StopAsync`).
///
/// The lab implementation is [`FakeMcpApplyHost`], which records the last applied
/// `(enabled, port)` and is scriptable for failure injection. The `sink` parameter is
/// the re-entrancy seam: a host may deliver a nested user toggle during the apply;
/// the VM ignores it while the guard is held (C# `_suppressMcpToggle`).
pub trait McpApplyHost: Send + Sync {
    /// Start (`enabled == true`) or stop the server for the committed port.
    ///
    /// Returning `Err` mirrors a failed `StartAsync` — the VM reverts without a
    /// second apply.
    fn apply(
        &self,
        enabled: bool,
        port: i32,
        sink: &mut dyn McpNestedSink,
    ) -> Result<(), McpApplyError>;
    /// Host-side running state (C# `McpServerHost.IsRunning`).
    fn is_running(&self) -> bool;
}

/// Re-entrancy seam: a host can hand a nested toggle back to the VM while an apply
/// is in flight. [`McpSettingsVm`] implements this — the change is ignored while
/// [`McpSettingsVm::is_applying`] is set, so no second apply can fire (the C#
/// `_suppressMcpToggle` guarded revert scenario).
pub trait McpNestedSink {
    /// Attempt a toggle change from inside an in-flight apply (ignored while guarded).
    fn nested_toggle(&mut self, enabled: bool);
}

/// Deterministic apply-command host for the lab harness.
#[derive(Default)]
pub struct FakeMcpApplyHost {
    log: Mutex<Vec<(bool, i32)>>,
    failures_left: AtomicUsize,
    running: AtomicBool,
}

impl FakeMcpApplyHost {
    /// Fresh, non-running host.
    pub fn new() -> Self {
        Self::default()
    }

    /// Recorded apply commands in order (lab assertions).
    pub fn apply_log(&self) -> Vec<(bool, i32)> {
        self.log.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// How many apply commands were recorded.
    pub fn apply_calls(&self) -> usize {
        self.log.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    /// Last applied `(enabled, port)`, if any.
    pub fn last_applied(&self) -> Option<(bool, i32)> {
        self.apply_log().pop()
    }

    /// Script the next `n` applies to fail (start/stop errors).
    pub fn set_failures(&mut self, n: usize) {
        self.failures_left.store(n, Ordering::SeqCst);
    }

    /// Force host running state (lab seeding; `is_running` only).
    pub fn set_running(&mut self, running: bool) {
        self.running.store(running, Ordering::SeqCst);
    }
}

impl fmt::Debug for FakeMcpApplyHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeMcpApplyHost")
            .field("apply_log", &self.apply_log())
            .field("failures_left", &self.failures_left.load(Ordering::SeqCst))
            .field("running", &self.running.load(Ordering::SeqCst))
            .finish()
    }
}

impl McpApplyHost for FakeMcpApplyHost {
    fn apply(
        &self,
        enabled: bool,
        port: i32,
        _sink: &mut dyn McpNestedSink,
    ) -> Result<(), McpApplyError> {
        let left = self.failures_left.load(Ordering::SeqCst);
        if left > 0 {
            self.failures_left.fetch_sub(1, Ordering::SeqCst);
            return Err(McpApplyError("fake MCP apply failure".into()));
        }
        // Host-level safety net (C# `McpServerHost` AlreadyRunning parity).
        if enabled && self.running.load(Ordering::SeqCst) {
            return Err(McpApplyError("MCP server is already running".into()));
        }
        self.log.lock().unwrap_or_else(|p| p.into_inner()).push((enabled, port));
        self.running.store(enabled, Ordering::SeqCst);
        Ok(())
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

/// UI-facing MCP section state (subset of C# `SettingsViewModel` MCP bindings).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpSettingsUiState {
    /// `EnableMcpServer` toggle value.
    pub enabled: bool,
    /// `McpServerPort` (int; C# keeps a double).
    pub port: i32,
    /// [`wormhole_mcp::DEFAULT_MCP_PORT`] (8765) when nothing is set.
    pub default_port: i32,
    /// Re-entrancy guard (C# `_suppressMcpToggle` window, widened to the whole apply).
    pub is_applying: bool,
    /// Host `IsRunning` when last inspected.
    pub is_running: bool,
    /// Last successfully applied command `(enabled, port)`.
    pub last_applied: Option<(bool, i32)>,
    /// Apply commands emitted.
    pub apply_count: usize,
    /// Token presence (never the token itself).
    pub token_present: bool,
    /// `IsMcpTokenRevealed`.
    pub token_revealed: bool,
    /// Reveal / copy / regenerate command counts.
    pub reveal_count: usize,
    pub copy_count: usize,
    pub regenerate_count: usize,
    /// Last error copy (UI-safe; never token material).
    pub last_error: Option<String>,
}

impl Default for McpSettingsUiState {
    fn default() -> Self {
        Self {
            enabled: false,
            port: DEFAULT_MCP_PORT as i32,
            default_port: DEFAULT_MCP_PORT as i32,
            is_applying: false,
            is_running: false,
            last_applied: None,
            apply_count: 0,
            token_present: false,
            token_revealed: false,
            reveal_count: 0,
            copy_count: 0,
            regenerate_count: 0,
            last_error: None,
        }
    }
}

/// Validate a settings port through [`wormhole_mcp::validate_mcp_port`].
///
/// The `u16` conversion supplies the 1..=65535 envelope (a hostile `i32` cannot fit);
/// `validate_mcp_port` rejects `0`. No rules are duplicated here.
pub fn validate_mcp_port_setting(port: i32) -> Result<u16, McpPortError> {
    let port = u16::try_from(port).map_err(|_| McpPortError::OutOfRange(port))?;
    validate_mcp_port(port).map_err(|e| McpPortError::Rejected(e.to_string()))?;
    Ok(port)
}

/// Settings → MCP view-model: toggle + port over a [`SettingsStore`], apply-command
/// host, token handle, and the C# `_suppressMcpToggle` re-entrancy guard.
pub struct McpSettingsVm {
    store: Arc<dyn SettingsStore>,
    enabled: bool,
    port: i32,
    applying: bool,
    last_applied: Option<(bool, i32)>,
    apply_count: usize,
    token_revealed: bool,
    reveal_count: usize,
    copy_count: usize,
    regenerate_count: usize,
    last_error: Option<String>,
    token_handle: Arc<dyn McpTokenHandle>,
    host: Arc<dyn McpApplyHost>,
}

impl fmt::Debug for McpSettingsVm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never render store paths, host handles, or token material.
        f.debug_struct("McpSettingsVm")
            .field("enabled", &self.enabled)
            .field("port", &self.port)
            .field("is_applying", &self.applying)
            .field("last_applied", &self.last_applied)
            .field("apply_count", &self.apply_count)
            .field("token_revealed", &self.token_revealed)
            .field("last_error", &self.last_error)
            .field("token_handle", &"<McpTokenHandle>")
            .field("host", &"<McpApplyHost>")
            .field("store", &"<SettingsStore>")
            .finish()
    }
}

impl McpSettingsVm {
    /// Load the current settings and build the VM over injectable host + token handles.
    pub fn new(
        store: Arc<dyn SettingsStore>,
        token_handle: Arc<dyn McpTokenHandle>,
        host: Arc<dyn McpApplyHost>,
    ) -> Result<Self, McpSettingsError> {
        let current = store.load().map_err(McpSettingsError::Load)?;
        Ok(Self::from_settings(store, current, token_handle, host))
    }

    /// Build over an explicit settings snapshot (skips the store read).
    ///
    /// A corrupt / hostile stored port is clamped to [`wormhole_mcp::DEFAULT_MCP_PORT`]
    /// (fail-closed default when unset — C# would let a hostile value reach the host).
    pub fn from_settings(
        store: Arc<dyn SettingsStore>,
        current: AppSettings,
        token_handle: Arc<dyn McpTokenHandle>,
        host: Arc<dyn McpApplyHost>,
    ) -> Self {
        let port = match validate_mcp_port_setting(current.mcp_server_port) {
            Ok(port) => port as i32,
            Err(_) => DEFAULT_MCP_PORT as i32,
        };
        Self {
            store,
            enabled: current.enable_mcp_server,
            port,
            applying: false,
            last_applied: None,
            apply_count: 0,
            token_revealed: false,
            reveal_count: 0,
            copy_count: 0,
            regenerate_count: 0,
            last_error: None,
            token_handle,
            host,
        }
    }

    /// Current toggle value.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Current port (always valid: 1..=65535).
    pub fn port(&self) -> i32 {
        self.port
    }

    /// Re-entrancy guard state (C# `_suppressMcpToggle`).
    pub fn is_applying(&self) -> bool {
        self.applying
    }

    /// Last successfully applied `(enabled, port)`.
    pub fn last_applied(&self) -> Option<(bool, i32)> {
        self.last_applied
    }

    /// Apply commands emitted so far.
    pub fn apply_count(&self) -> usize {
        self.apply_count
    }

    /// `IsMcpTokenRevealed`.
    pub fn token_revealed(&self) -> bool {
        self.token_revealed
    }

    /// Last error copy (UI-safe; never token material).
    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    /// Derived UI state.
    pub fn ui_state(&self) -> McpSettingsUiState {
        McpSettingsUiState {
            enabled: self.enabled,
            port: self.port,
            default_port: DEFAULT_MCP_PORT as i32,
            is_applying: self.applying,
            is_running: self.host.is_running(),
            last_applied: self.last_applied,
            apply_count: self.apply_count,
            token_present: self.token_handle.has_token(),
            token_revealed: self.token_revealed,
            reveal_count: self.reveal_count,
            copy_count: self.copy_count,
            regenerate_count: self.regenerate_count,
            last_error: self.last_error.clone(),
        }
    }

    /// Reload toggle + port from the store (C# constructor / refresh paths).
    pub fn reload(&mut self) -> Result<(), McpSettingsError> {
        let current = self.store.load().map_err(McpSettingsError::Load)?;
        self.enabled = current.enable_mcp_server;
        if let Ok(port) = validate_mcp_port_setting(current.mcp_server_port) {
            self.port = port as i32;
        }
        Ok(())
    }

    /// Flip the enable toggle (C# `OnEnableMcpServerChanged` + `ApplyMcpToggleAsync`).
    ///
    /// Persists first, then emits the apply command. A nested toggle while the guard
    /// is held is ignored; a failed apply reverts the VM field and the persisted
    /// document **without** firing a second apply.
    pub fn set_enabled(&mut self, enabled: bool) -> Result<(), McpSettingsError> {
        if self.applying {
            return Ok(());
        }
        if self.enabled == enabled {
            return Ok(());
        }

        self.applying = true;
        self.enabled = enabled;

        let host = Arc::clone(&self.host);
        let port = self.port;
        let result = match self.save_enabled_doc(enabled) {
            Ok(()) => match host.apply(enabled, port, self) {
                Ok(()) => {
                    self.apply_count += 1;
                    self.last_applied = Some((enabled, port));
                    Ok(())
                }
                Err(e) => Err(McpSettingsError::Apply(e)),
            },
            Err(e) => Err(e),
        };

        if result.is_err() {
            // Revert without re-entering: the guard is still held, so nothing fires.
            self.enabled = !enabled;
            let _ = self.save_enabled_doc(!enabled);
        }
        self.applying = false;
        self.record_error(result.as_ref().err());
        result
    }

    /// Change the port (C# `OnMcpServerPortChanged`; takes effect on the next apply).
    ///
    /// Fail-closed: zero / negative / `> 65535` refuse to apply, surface an error, and
    /// are **not** persisted.
    pub fn set_port(&mut self, port: i32) -> Result<(), McpSettingsError> {
        let validated = validate_mcp_port_setting(port).map_err(McpSettingsError::Port)?;
        if self.port == validated as i32 {
            return Ok(());
        }
        let before = self.port;
        self.port = validated as i32;
        let result = self.save_port_doc();
        if result.is_err() {
            self.port = before;
        }
        self.record_error(result.as_ref().err());
        result
    }

    /// Reveal the bearer token (C# `RevealMcpTokenAsync` reveal half).
    ///
    /// Returns the token to the caller; the VM never retains it.
    pub fn reveal_token(&mut self) -> Result<String, McpSettingsError> {
        self.token_operation(McpTokenOp::Reveal)
    }

    /// Copy the bearer token (C# `CopyMcpTokenAsync`).
    ///
    /// Returns the token to the caller (clipboard is the host's job).
    pub fn copy_token(&mut self) -> Result<String, McpSettingsError> {
        self.token_operation(McpTokenOp::Copy)
    }

    /// Replace the bearer token (C# `RegenerateMcpTokenAsync`; confirmation dialog is
    /// the host's job). Leaves the token revealed, like C#.
    pub fn regenerate_token(&mut self) -> Result<String, McpSettingsError> {
        match self.token_handle.regenerate() {
            Ok(token) => {
                self.regenerate_count += 1;
                self.token_revealed = true;
                self.record_error(None);
                Ok(token)
            }
            Err(e) => {
                let err = McpSettingsError::Token(e);
                self.record_error(Some(&err));
                Err(err)
            }
        }
    }

    /// Hide a revealed token (C# `RevealMcpTokenAsync` hide half).
    pub fn conceal_token(&mut self) {
        self.token_revealed = false;
    }

    fn token_operation(&mut self, op: McpTokenOp) -> Result<String, McpSettingsError> {
        match self.token_handle.get_or_create() {
            Ok(token) => {
                match op {
                    McpTokenOp::Reveal => {
                        self.reveal_count += 1;
                        self.token_revealed = true;
                    }
                    McpTokenOp::Copy => {
                        self.copy_count += 1;
                    }
                }
                self.record_error(None);
                Ok(token)
            }
            Err(e) => {
                let err = McpSettingsError::Token(e);
                self.record_error(Some(&err));
                Err(err)
            }
        }
    }

    fn save_enabled_doc(&mut self, enabled: bool) -> Result<(), McpSettingsError> {
        let mut current = self.store.load().map_err(McpSettingsError::Load)?;
        current.enable_mcp_server = enabled;
        current.mcp_server_port = self.port;
        self.store.save(&current).map_err(McpSettingsError::Persist)
    }

    fn save_port_doc(&mut self) -> Result<(), McpSettingsError> {
        let mut current = self.store.load().map_err(McpSettingsError::Load)?;
        current.mcp_server_port = self.port;
        self.store.save(&current).map_err(McpSettingsError::Persist)
    }

    fn record_error(&mut self, error: Option<&McpSettingsError>) {
        self.last_error = error.map(ToString::to_string);
    }
}

impl McpNestedSink for McpSettingsVm {
    fn nested_toggle(&mut self, enabled: bool) {
        // Guarded: while an apply is in flight this is a no-op (C# `_suppressMcpToggle`).
        let _ = self.set_enabled(enabled);
    }
}

#[derive(Clone, Copy)]
enum McpTokenOp {
    Reveal,
    Copy,
}

/// Lab harness: scriptable apply host + token handle + the memory settings store.
pub struct McpSettingsFakeHarness {
    /// Scriptable apply-command host (shared with the VM).
    pub host: Arc<FakeMcpApplyHost>,
    /// Scriptable token handle (shared with the VM).
    pub token: Arc<FakeMcpTokenHandle>,
    /// The memory settings store behind the VM (assertions).
    pub store: Arc<MemorySettingsStore>,
}

impl fmt::Debug for McpSettingsFakeHarness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("McpSettingsFakeHarness")
            .field("host", &self.host)
            .field("token", &self.token)
            .field("store", &"<MemorySettingsStore>")
            .finish()
    }
}

/// Composed MCP settings glue: [`McpSettingsVm`] + scripted Fakes + cached UI state.
pub struct McpSettingsGlue {
    vm: McpSettingsVm,
    ui: McpSettingsUiState,
}

impl fmt::Debug for McpSettingsGlue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("McpSettingsGlue")
            .field("vm", &self.vm)
            .field("ui", &self.ui)
            .finish()
    }
}

impl McpSettingsGlue {
    /// Glue over an existing VM (cached UI state).
    pub fn new(vm: McpSettingsVm) -> Self {
        let ui = vm.ui_state();
        Self { vm, ui }
    }

    /// Lab harness over a seeded settings snapshot.
    pub fn with_fake_harness(seed: AppSettings) -> (Self, McpSettingsFakeHarness) {
        let store = Arc::new(MemorySettingsStore::new(seed));
        let token = Arc::new(FakeMcpTokenHandle::seeded());
        let host = Arc::new(FakeMcpApplyHost::new());
        let harness = McpSettingsFakeHarness {
            host: Arc::clone(&host),
            token: Arc::clone(&token),
            store: Arc::clone(&store),
        };
        let vm = McpSettingsVm::from_settings(
            Arc::clone(&store) as Arc<dyn SettingsStore>,
            store.snapshot(),
            Arc::clone(&token) as Arc<dyn McpTokenHandle>,
            Arc::clone(&host) as Arc<dyn McpApplyHost>,
        );
        (Self::new(vm), harness)
    }

    /// Borrow current UI state.
    pub fn ui_state(&self) -> &McpSettingsUiState {
        &self.ui
    }

    /// Borrow the view-model.
    pub fn vm(&self) -> &McpSettingsVm {
        &self.vm
    }

    /// Mutable view-model (advanced hosts / tests).
    pub fn vm_mut(&mut self) -> &mut McpSettingsVm {
        &mut self.vm
    }

    /// Refresh cached UI state after external mutations.
    pub fn refresh_ui_state(&mut self) {
        self.ui = self.vm.ui_state();
    }

    /// Toggle (delegates; refreshes UI state).
    pub fn set_enabled(&mut self, enabled: bool) -> Result<(), McpSettingsError> {
        let result = self.vm.set_enabled(enabled);
        self.refresh_ui_state();
        result
    }

    /// Set the port (delegates; refreshes UI state).
    pub fn set_port(&mut self, port: i32) -> Result<(), McpSettingsError> {
        let result = self.vm.set_port(port);
        self.refresh_ui_state();
        result
    }

    /// Reveal the bearer token (delegates; refreshes UI state).
    pub fn reveal_token(&mut self) -> Result<String, McpSettingsError> {
        let result = self.vm.reveal_token();
        self.refresh_ui_state();
        result
    }

    /// Copy the bearer token (delegates; refreshes UI state).
    pub fn copy_token(&mut self) -> Result<String, McpSettingsError> {
        let result = self.vm.copy_token();
        self.refresh_ui_state();
        result
    }

    /// Regenerate the bearer token (delegates; refreshes UI state).
    pub fn regenerate_token(&mut self) -> Result<String, McpSettingsError> {
        let result = self.vm.regenerate_token();
        self.refresh_ui_state();
        result
    }

    /// Hide a revealed token (delegates; refreshes UI state).
    pub fn conceal_token(&mut self) {
        self.vm.conceal_token();
        self.refresh_ui_state();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Applies once, then re-enters the VM with the opposite toggle mid-apply
    /// (simulates a user flip while the C# `StartAsync` is in flight).
    struct ReentrantHost {
        inner: FakeMcpApplyHost,
    }

    impl McpApplyHost for ReentrantHost {
        fn apply(
            &self,
            enabled: bool,
            port: i32,
            sink: &mut dyn McpNestedSink,
        ) -> Result<(), McpApplyError> {
            sink.nested_toggle(!enabled);
            self.inner.apply(enabled, port, sink)
        }

        fn is_running(&self) -> bool {
            self.inner.is_running()
        }
    }

    struct FailNTimesStore {
        inner: MemorySettingsStore,
        failures_left: AtomicUsize,
    }

    impl FailNTimesStore {
        fn new(settings: AppSettings, failures: usize) -> Self {
            Self {
                inner: MemorySettingsStore::new(settings),
                failures_left: AtomicUsize::new(failures),
            }
        }
    }

    impl SettingsStore for FailNTimesStore {
        fn load(&self) -> Result<AppSettings, SettingsError> {
            self.inner.load()
        }

        fn save(&self, settings: &AppSettings) -> Result<(), SettingsError> {
            let left = self.failures_left.load(Ordering::SeqCst);
            if left > 0 {
                self.failures_left.fetch_sub(1, Ordering::SeqCst);
                return Err(SettingsError::Io("injected save failure".into()));
            }
            self.inner.save(settings)
        }
    }

    fn harness() -> (McpSettingsGlue, McpSettingsFakeHarness) {
        McpSettingsGlue::with_fake_harness(AppSettings::default())
    }

    #[test]
    fn invalid_ports_rejected_fail_closed_not_persisted() {
        let (mut glue, harness) = harness();
        for hostile in [0, -1, 65536, i32::MAX, i32::MIN] {
            let err = glue.set_port(hostile).unwrap_err();
            assert!(matches!(err, McpSettingsError::Port(_)));
            assert_eq!(harness.store.snapshot().mcp_server_port, 8765);
            assert_eq!(glue.vm().port(), 8765);
        }
        assert_eq!(harness.host.apply_calls(), 0);
    }

    #[test]
    fn valid_ports_persist() {
        let (mut glue, harness) = harness();
        for port in [1, 65535, 9000] {
            glue.set_port(port).unwrap();
            assert_eq!(harness.store.snapshot().mcp_server_port, port);
            assert_eq!(glue.vm().port(), port);
            assert!(glue.vm().last_error().is_none());
        }
    }

    #[test]
    fn hostile_stored_port_clamped_to_default() {
        let mut settings = AppSettings::default();
        settings.mcp_server_port = 99999;
        let store = Arc::new(MemorySettingsStore::new(settings));
        let vm = McpSettingsVm::new(
            store,
            Arc::new(FakeMcpTokenHandle::seeded()),
            Arc::new(FakeMcpApplyHost::new()),
        )
        .unwrap();
        assert_eq!(vm.port(), DEFAULT_MCP_PORT as i32);
        let mut settings = AppSettings::default();
        settings.mcp_server_port = -5;
        let store = Arc::new(MemorySettingsStore::new(settings));
        let vm = McpSettingsVm::new(
            store,
            Arc::new(FakeMcpTokenHandle::seeded()),
            Arc::new(FakeMcpApplyHost::new()),
        )
        .unwrap();
        assert_eq!(vm.port(), DEFAULT_MCP_PORT as i32);
    }

    #[test]
    fn default_port_matches_wormhole_mcp() {
        assert_eq!(DEFAULT_MCP_PORT, 8765);
        assert_eq!(AppSettings::default().mcp_server_port, 8765);
        assert_eq!(
            validate_mcp_port_setting(8765).unwrap(),
            DEFAULT_MCP_PORT
        );
    }

    #[test]
    fn enable_toggle_persists_and_fake_records_apply() {
        let (mut glue, harness) = harness();
        glue.set_enabled(true).unwrap();
        assert!(harness.store.snapshot().enable_mcp_server);
        assert_eq!(harness.store.snapshot().mcp_server_port, 8765);
        assert_eq!(harness.host.last_applied(), Some((true, 8765)));
        assert_eq!(harness.host.apply_calls(), 1);
        assert!(glue.vm().enabled());
        assert_eq!(glue.ui_state().last_applied, Some((true, 8765)));
        assert!(glue.ui_state().is_running);
    }

    #[test]
    fn disable_toggle_persists_and_applies_stop() {
        let (mut glue, harness) = harness();
        glue.set_enabled(true).unwrap();
        glue.set_enabled(false).unwrap();
        assert!(!harness.store.snapshot().enable_mcp_server);
        assert_eq!(harness.host.last_applied(), Some((false, 8765)));
        assert_eq!(harness.host.apply_calls(), 2);
        assert!(!glue.vm().enabled());
    }

    #[test]
    fn reentrant_nested_toggle_ignored_while_applying() {
        let store = Arc::new(MemorySettingsStore::new(AppSettings::default()));
        let token = Arc::new(FakeMcpTokenHandle::seeded());
        let host = Arc::new(ReentrantHost {
            inner: FakeMcpApplyHost::new(),
        });
        let mut vm = McpSettingsVm::new(
            Arc::clone(&store) as Arc<dyn SettingsStore>,
            Arc::clone(&token) as Arc<dyn McpTokenHandle>,
            host as Arc<dyn McpApplyHost>,
        )
        .unwrap();
        vm.set_enabled(true).unwrap();
        // The nested opposite toggle fired mid-apply was ignored by the guard.
        assert!(vm.enabled());
        assert_eq!(vm.apply_count(), 1);
        assert!(store.snapshot().enable_mcp_server);
        assert_eq!(vm.last_error(), None);
    }

    #[test]
    fn failed_apply_reverts_without_second_apply() {
        let store = Arc::new(MemorySettingsStore::new(AppSettings::default()));
        let token = Arc::new(FakeMcpTokenHandle::seeded());
        let mut host = FakeMcpApplyHost::new();
        host.set_failures(1);
        let host = Arc::new(host);
        let mut vm = McpSettingsVm::new(
            Arc::clone(&store) as Arc<dyn SettingsStore>,
            Arc::clone(&token) as Arc<dyn McpTokenHandle>,
            Arc::clone(&host) as Arc<dyn McpApplyHost>,
        )
        .unwrap();
        let err = vm.set_enabled(true).unwrap_err();
        assert!(matches!(err, McpSettingsError::Apply(_)));
        assert!(!vm.enabled());
        assert!(!store.snapshot().enable_mcp_server);
        // Failures are consumed without logging; the revert must not re-apply.
        assert_eq!(host.apply_calls(), 0);
        assert_eq!(host.last_applied(), None);
        assert_eq!(vm.apply_count(), 0);
        // A later toggle succeeds and logs exactly one apply.
        let mut vm2 = McpSettingsVm::new(
            Arc::clone(&store) as Arc<dyn SettingsStore>,
            Arc::clone(&token) as Arc<dyn McpTokenHandle>,
            Arc::clone(&host) as Arc<dyn McpApplyHost>,
        )
        .unwrap();
        vm2.set_enabled(true).unwrap();
        assert_eq!(host.apply_calls(), 1);
        assert_eq!(host.last_applied(), Some((true, 8765)));
    }

    #[test]
    fn reentrant_nested_toggle_ignored_then_failed_apply_reverts_guarded() {
        // The C# `_suppressMcpToggle` guarded-revert scenario: a user flips the
        // toggle mid-apply, the apply then FAILS. The nested flip is ignored
        // while the guard is held, and the revert completes without re-entering
        // (no second apply can fire). `ReentrantHost` with a scripted inner
        // host — no separate failing variant needed.
        let store = Arc::new(MemorySettingsStore::new(AppSettings::default()));
        let token = Arc::new(FakeMcpTokenHandle::seeded());
        let mut inner = FakeMcpApplyHost::new();
        inner.set_failures(1);
        let host = Arc::new(ReentrantHost { inner });
        let mut vm = McpSettingsVm::new(
            Arc::clone(&store) as Arc<dyn SettingsStore>,
            Arc::clone(&token) as Arc<dyn McpTokenHandle>,
            Arc::clone(&host) as Arc<dyn McpApplyHost>,
        )
        .unwrap();
        let err = vm.set_enabled(true).unwrap_err();
        assert!(matches!(err, McpSettingsError::Apply(_)));
        // Reverted toggle + persisted document.
        assert!(!vm.enabled());
        assert!(!store.snapshot().enable_mcp_server);
        // Nested flip ignored; the failed apply logged nothing; no re-apply.
        assert_eq!(vm.apply_count(), 0);
        assert_eq!(vm.last_applied(), None);
        assert_eq!(host.inner.apply_calls(), 0);
        assert!(vm.last_error().is_some());
        // Guard released after the revert — later toggles work normally.
        assert!(!vm.is_applying());
        vm.set_enabled(true).unwrap();
        assert!(vm.enabled());
        assert!(store.snapshot().enable_mcp_server);
        assert_eq!(host.inner.apply_calls(), 1);
        assert_eq!(host.inner.last_applied(), Some((true, 8765)));
    }

    #[test]
    fn port_persist_failure_reverts_field_and_surfaces_error() {
        let settings = AppSettings::default();
        let store = Arc::new(FailNTimesStore::new(settings, 1));
        let token = Arc::new(FakeMcpTokenHandle::seeded());
        let host = Arc::new(FakeMcpApplyHost::new());
        let mut vm = McpSettingsVm::new(
            Arc::clone(&store) as Arc<dyn SettingsStore>,
            Arc::clone(&token) as Arc<dyn McpTokenHandle>,
            Arc::clone(&host) as Arc<dyn McpApplyHost>,
        )
        .unwrap();
        let err = vm.set_port(9100).unwrap_err();
        assert!(matches!(err, McpSettingsError::Persist(_)));
        // Field and document both keep the prior valid port; nothing applied.
        assert_eq!(vm.port(), 8765);
        assert_eq!(store.inner.snapshot().mcp_server_port, 8765);
        assert_eq!(host.apply_calls(), 0);
        assert!(vm.last_error().is_some());
        // Next attempt succeeds once the injected failure is consumed.
        vm.set_port(9100).unwrap();
        assert_eq!(vm.port(), 9100);
        assert_eq!(store.inner.snapshot().mcp_server_port, 9100);
        assert!(vm.last_error().is_none());
    }

    #[test]
    fn failed_persist_reverts_toggle_without_apply() {
        let settings = AppSettings::default();
        let store = Arc::new(FailNTimesStore::new(settings, 1));
        let token = Arc::new(FakeMcpTokenHandle::seeded());
        let host = Arc::new(FakeMcpApplyHost::new());
        let mut vm = McpSettingsVm::new(
            Arc::clone(&store) as Arc<dyn SettingsStore>,
            Arc::clone(&token) as Arc<dyn McpTokenHandle>,
            Arc::clone(&host) as Arc<dyn McpApplyHost>,
        )
        .unwrap();
        let err = vm.set_enabled(true).unwrap_err();
        assert!(matches!(err, McpSettingsError::Persist(_)));
        assert!(!vm.enabled());
        assert_eq!(host.apply_calls(), 0);
        assert_eq!(vm.apply_count(), 0);
    }

    #[test]
    fn port_change_applies_on_next_toggle() {
        let (mut glue, harness) = harness();
        glue.set_port(9100).unwrap();
        assert_eq!(harness.store.snapshot().mcp_server_port, 9100);
        glue.set_enabled(true).unwrap();
        assert_eq!(harness.host.last_applied(), Some((true, 9100)));
    }

    #[test]
    fn token_ops_and_debug_redaction() {
        let (mut glue, harness) = harness();
        let revealed = glue.reveal_token().unwrap();
        assert!(!revealed.is_empty());
        assert!(glue.ui_state().token_present);
        assert!(glue.vm().token_revealed());
        assert_eq!(glue.ui_state().reveal_count, 1);
        let dbg = format!("{glue:?}");
        assert!(!dbg.contains(&revealed));
        assert!(!dbg.contains("lab-seed"));
        let harness_dbg = format!("{harness:?}");
        assert!(harness_dbg.contains("[REDACTED]"));
        assert!(!harness_dbg.contains(&revealed));
        assert!(!harness_dbg.contains("lab-seed"));
        // Copy returns the same token without re-minting.
        let copied = glue.copy_token().unwrap();
        assert_eq!(copied, revealed);
        assert_eq!(harness.token.get_calls(), 2);
        // Regenerate mints a fresh token and leaves it revealed (C# parity).
        let regenerated = glue.regenerate_token().unwrap();
        assert_ne!(regenerated, revealed);
        assert_eq!(harness.token.regenerate_calls(), 1);
        assert!(glue.vm().token_revealed());
    }

    #[test]
    fn token_operation_failure_fail_closed() {
        let (mut glue, harness) = harness();
        harness.token.set_get_failures(1);
        let err = glue.reveal_token().unwrap_err();
        assert!(matches!(err, McpSettingsError::Token(_)));
        assert_eq!(glue.ui_state().reveal_count, 0);
        assert!(!glue.vm().token_revealed());
        let dbg = format!("{glue:?}");
        assert!(!dbg.contains("bearer"));
    }

    #[test]
    fn conceal_token_hides_revealed() {
        let (mut glue, _) = harness();
        glue.reveal_token().unwrap();
        assert!(glue.vm().token_revealed());
        assert!(glue.ui_state().token_revealed);
        glue.conceal_token();
        assert!(!glue.vm().token_revealed());
        assert!(!glue.ui_state().token_revealed);
        // Conceal keeps the stored token present (reveal hints stay truthful).
        assert!(glue.ui_state().token_present);
    }

    #[test]
    fn regenerate_failure_fail_closed() {
        let (mut glue, harness) = harness();
        harness.token.set_regenerate_failures(1);
        let err = glue.regenerate_token().unwrap_err();
        assert!(matches!(err, McpSettingsError::Token(_)));
        assert_eq!(harness.token.regenerate_calls(), 1);
        assert!(!glue.ui_state().token_revealed);
    }

    #[test]
    fn reload_restores_persisted_document() {
        let (mut glue, harness) = harness();
        glue.set_enabled(true).unwrap();
        glue.set_port(9100).unwrap();
        // External mutation (C# settings service changed elsewhere).
        let mut external = harness.store.snapshot();
        external.enable_mcp_server = false;
        harness.store.save(&external).unwrap();
        glue.vm_mut().reload().unwrap();
        assert!(!glue.vm().enabled());
        assert_eq!(glue.vm().port(), 9100);
    }

    #[test]
    fn reload_keeps_last_valid_port_when_disk_turns_hostile() {
        let (mut glue, harness) = harness();
        glue.set_port(9100).unwrap();
        // The document is corrupted out-of-band (hostile port 0).
        let mut external = harness.store.snapshot();
        external.mcp_server_port = 0;
        harness.store.save(&external).unwrap();
        glue.vm_mut().reload().unwrap();
        // Fail-closed: the hostile value is never adopted; the last valid
        // port survives; the document is not silently rewritten.
        assert_eq!(glue.vm().port(), 9100);
        assert_eq!(harness.store.snapshot().mcp_server_port, 0);
        // The next toggle persists the valid VM port over the hostile value.
        glue.set_enabled(true).unwrap();
        assert_eq!(harness.host.last_applied(), Some((true, 9100)));
        assert_eq!(harness.store.snapshot().mcp_server_port, 9100);
    }

    #[test]
    fn glue_reflects_reverted_state_after_failed_apply() {
        let store = Arc::new(MemorySettingsStore::new(AppSettings::default()));
        let token = Arc::new(FakeMcpTokenHandle::seeded());
        let mut host = FakeMcpApplyHost::new();
        host.set_failures(1);
        let host = Arc::new(host);
        let mut glue = McpSettingsGlue::new(
            McpSettingsVm::new(
                Arc::clone(&store) as Arc<dyn SettingsStore>,
                Arc::clone(&token) as Arc<dyn McpTokenHandle>,
                Arc::clone(&host) as Arc<dyn McpApplyHost>,
            )
            .unwrap(),
        );
        let err = glue.set_enabled(true).unwrap_err();
        assert!(matches!(err, McpSettingsError::Apply(_)));
        // The cached UI state is refreshed with the reverted (guarded) state.
        assert!(!glue.ui_state().enabled);
        assert!(!glue.ui_state().is_applying);
        assert_eq!(glue.ui_state().apply_count, 0);
        assert_eq!(glue.ui_state().last_applied, None);
        assert!(glue.ui_state().last_error.is_some());
        assert!(!glue.ui_state().is_running);
    }
}