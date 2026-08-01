//! Loopback MCP server host for the Rust migration.
//!
//! Mirrors `Services/Mcp` (`IMcpServerHost` / `McpServerHost`): bind **127.0.0.1** only,
//! bearer token via CredMgr helper or generated in-memory store. Uses official [`rmcp`]
//! Streamable HTTP when the `rmcp` feature is enabled.

mod approval;
mod bind;
mod capability;
mod error;
mod host;
mod live_tab_scan;
#[cfg(feature = "rmcp")]
mod rmcp_handler;
mod session_registry;
mod shutdown_order;
mod stub;
mod token;
mod tool_runner;

pub use approval::{
    approve_pending, cancel_pending, deny_pending, ApprovalDecision, ApprovalRequest,
    FakeMcpApprovalUi, FakeMcpToolApprovalGlue, SessionApprovalGate,
};
pub use bind::{
    ensure_bound_loopback, is_loopback_ip, is_unspecified_ip, loopback_endpoint_url, loopback_v4,
    parse_loopback_bind, validate_loopback_bind, validate_loopback_host, validate_mcp_port,
};
pub use capability::{
    capability_report_for_bind, capability_report_for_bind_str, capability_report_from_tools_list,
    wormhole_capability_report, wormhole_tool_catalog, FakeMcpCapabilityServer,
    McpCapabilityReport, McpToolCapability, ToolsListEntry, ToolsListResponse, TOOL_LIST_SESSIONS,
    TOOL_READ_TERMINAL, TOOL_RUN_COMMAND, TOOL_SEND_TEXT,
};
pub use error::McpError;
pub use host::McpServerHost;
pub use live_tab_scan::{
    FakeMcpOpenTabSource, McpLiveTabScanner, McpOpenTabSource, McpScanReport, ScanTick,
};
pub use session_registry::{
    canonicalize_session_id, FakeMcpSessionRegistry, McpSessionInfo, McpSessionRegistry,
    McpSessionStatus,
};
pub use shutdown_order::{
    mcp_stopped_before_webview_flush, prepare_for_process_exit, validate_shutdown_order,
    AppExitShutdownStep, CSHARP_PARITY_SHUTDOWN_ORDER, FakeAppExitShutdownGlue,
    MCP_STOP_TIMEOUT, ShutdownOrderError,
};
pub use stub::HttpPlaceholderMcpHost;
pub use token::{
    extract_bearer_token, generate_bearer_token, is_authorized, tokens_equal, McpTokenStore,
    MemoryTokenStore,
};
pub use tool_runner::{
    FakeMcpShellRunner, FakeMcpToolDispatch, McpDispatchRequest, McpShellCallKind,
    McpShellCallRecord, McpShellCommandResult, McpShellRunner, McpToolDispatch, McpToolResult,
    McpToolRunnerGlue, ToolCallArgs,
};

#[cfg(feature = "secrets")]
pub use token::CredMgrTokenStore;

#[cfg(feature = "rmcp")]
pub use rmcp_handler::{wormhole_mcp_tools, RmcpLoopbackHost, WormholeMcpHandler};

/// Default port — matches C# `McpServerHost.DefaultPort`.
pub const DEFAULT_MCP_PORT: u16 = 8765;
