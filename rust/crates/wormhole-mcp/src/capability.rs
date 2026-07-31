//! tools/list → capability summary glue (diagnostics / settings Fake).
//!
//! Thin Lab stub: maps the MCP `tools/list` response **shape** (name +
//! description only — no input schemas, no bearer tokens) into a secrets-free
//! [`McpCapabilityReport`] for diagnostics and Settings Fake UIs.
//!
//! [`FakeMcpCapabilityServer`] advertises the canonical C# `McpSshTools` surface
//! without binding a socket or executing tools. Bind / host validation
//! **consumes** [`crate::bind`] helpers (fail-closed off-loopback) — it does
//! not reimplement them. Tool-name summarization fail-closes on blank names,
//! ASCII/Unicode control characters (diagnostics line spoofing), and duplicates.
//!
//! **Not** live Streamable HTTP, CredMgr, or SSH session control.

use std::fmt;
use std::net::SocketAddr;

use crate::bind::{
    loopback_endpoint_url, loopback_v4, parse_loopback_bind, validate_loopback_bind,
    validate_mcp_port,
};
use crate::{McpError, DEFAULT_MCP_PORT};

/// C# `McpSshTools` names — advertised via `tools/list` (implementations stubbed).
pub const TOOL_LIST_SESSIONS: &str = "list_sessions";
pub const TOOL_RUN_COMMAND: &str = "run_command";
pub const TOOL_SEND_TEXT: &str = "send_text";
pub const TOOL_READ_TERMINAL: &str = "read_terminal";

/// Canonical Wormhole tools/list catalog (name + description; no schemas).
///
/// **Names** match `Services/Mcp/McpSshTools.cs`. Descriptions are the shared Lab
/// copy also consumed by `wormhole_mcp_tools` when the `rmcp` feature is on
/// (abbreviated vs the longer C# `[Description]` strings — capability glue does
/// not carry input schemas).
pub fn wormhole_tool_catalog() -> &'static [(&'static str, &'static str)] {
    &[
        (
            TOOL_LIST_SESSIONS,
            "List the SSH sessions currently open and connected in Wormhole.",
        ),
        (
            TOOL_RUN_COMMAND,
            "Run a single shell command on a connected SSH session (approval required).",
        ),
        (
            TOOL_SEND_TEXT,
            "Type raw text into a connected SSH session (approval required).",
        ),
        (
            TOOL_READ_TERMINAL,
            "Return recent terminal output from a connected SSH session (approval required).",
        ),
    ]
}

/// One `tools/list` item (response shape stripped to capability fields).
///
/// Intentionally omits `inputSchema` and any auth material.
#[derive(Clone, PartialEq, Eq)]
pub struct ToolsListEntry {
    pub name: String,
    pub description: String,
}

impl fmt::Debug for ToolsListEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ToolsListEntry")
            .field("name", &self.name)
            .field("description_len", &self.description.len())
            .finish()
    }
}

/// MCP `tools/list` result shape used by the capability glue (no pagination cursor).
#[derive(Clone, PartialEq, Eq)]
pub struct ToolsListResponse {
    pub tools: Vec<ToolsListEntry>,
}

impl fmt::Debug for ToolsListResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ToolsListResponse")
            .field("tool_count", &self.tools.len())
            .field("tools", &self.tools)
            .finish()
    }
}

impl ToolsListResponse {
    /// Empty list (valid MCP shape; report will show zero tools).
    pub fn empty() -> Self {
        Self { tools: Vec::new() }
    }

    /// Canonical Wormhole SSH tools surface.
    pub fn wormhole_ssh_tools() -> Self {
        Self {
            tools: wormhole_tool_catalog()
                .iter()
                .map(|(name, description)| ToolsListEntry {
                    name: (*name).to_owned(),
                    description: (*description).to_owned(),
                })
                .collect(),
        }
    }
}

/// One advertised tool in a capability summary (diagnostics / settings).
#[derive(Clone, PartialEq, Eq)]
pub struct McpToolCapability {
    pub name: String,
    pub description: String,
}

impl fmt::Debug for McpToolCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("McpToolCapability")
            .field("name", &self.name)
            .field("description_len", &self.description.len())
            .finish()
    }
}

/// Secrets-free MCP capability summary for diagnostics / Settings Fake.
///
/// Never carries a bearer token. `tools_executable` is always `false` for this
/// stub (no live tool execution). Session id tracking for `list_sessions` lives
/// in [`crate::FakeMcpSessionRegistry`] — not wired into HTTP dispatch here.
#[derive(Clone, PartialEq, Eq)]
pub struct McpCapabilityReport {
    pub endpoint_url: String,
    pub port: u16,
    pub running: bool,
    pub tools: Vec<McpToolCapability>,
    /// Always `false` for Fake / Lab stubs — call stubs exist, live SSH is TODO.
    pub tools_executable: bool,
}

impl fmt::Debug for McpCapabilityReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("McpCapabilityReport")
            .field("endpoint_url", &self.endpoint_url)
            .field("port", &self.port)
            .field("running", &self.running)
            .field("tool_count", &self.tools.len())
            .field("tools", &self.tools)
            .field("tools_executable", &self.tools_executable)
            .finish()
    }
}

impl McpCapabilityReport {
    /// Tool names only (stable order from the source list).
    pub fn tool_names(&self) -> Vec<&str> {
        self.tools.iter().map(|t| t.name.as_str()).collect()
    }

    /// Plain-text block for diagnostics paste (no secrets).
    pub fn format_for_diagnostics(&self) -> String {
        let mut out = String::new();
        out.push_str("=== Wormhole MCP capability (no secrets) ===\n");
        out.push_str(&format!("endpoint: {}\n", self.endpoint_url));
        out.push_str(&format!("port: {}\n", self.port));
        out.push_str(&format!(
            "running: {}\n",
            if self.running { "yes" } else { "no" }
        ));
        out.push_str(&format!(
            "tools_executable: {}\n",
            if self.tools_executable { "yes" } else { "no" }
        ));
        out.push_str("tools:\n");
        if self.tools.is_empty() {
            out.push_str("  (none)\n");
        } else {
            for tool in &self.tools {
                out.push_str(&format!("  - {}\n", tool.name));
            }
        }
        out.push_str("=== end MCP capability ===\n");
        out
    }
}

/// Map a `tools/list` response → capability summary for a loopback port.
///
/// Fail-closed: port `0`, blank tool names, control characters in names, and
/// duplicate names (after trim). Endpoint is always `http://127.0.0.1:{port}`
/// via [`loopback_endpoint_url`]. `tools_executable` is always `false`.
pub fn capability_report_from_tools_list(
    port: u16,
    running: bool,
    list: &ToolsListResponse,
) -> Result<McpCapabilityReport, McpError> {
    validate_mcp_port(port)?;
    let tools = summarize_tools(list)?;
    Ok(McpCapabilityReport {
        endpoint_url: loopback_endpoint_url(port),
        port,
        running,
        tools,
        tools_executable: false,
    })
}

/// Same as [`capability_report_from_tools_list`], but validates the bind address
/// with existing loopback helpers (reject LAN / wildcard / mapped / zone-id).
pub fn capability_report_for_bind(
    bind: SocketAddr,
    running: bool,
    list: &ToolsListResponse,
) -> Result<McpCapabilityReport, McpError> {
    validate_loopback_bind(bind)?;
    capability_report_from_tools_list(bind.port(), running, list)
}

/// Parse + validate a bind string, then summarize tools (consumes [`parse_loopback_bind`]).
pub fn capability_report_for_bind_str(
    bind: &str,
    running: bool,
    list: &ToolsListResponse,
) -> Result<McpCapabilityReport, McpError> {
    let addr = parse_loopback_bind(bind)?;
    capability_report_for_bind(addr, running, list)
}

/// Canonical Wormhole tools/list → capability report (loopback port, not running).
pub fn wormhole_capability_report(port: u16) -> Result<McpCapabilityReport, McpError> {
    capability_report_from_tools_list(port, false, &ToolsListResponse::wormhole_ssh_tools())
}

fn summarize_tools(list: &ToolsListResponse) -> Result<Vec<McpToolCapability>, McpError> {
    let mut tools: Vec<McpToolCapability> = Vec::with_capacity(list.tools.len());
    for entry in &list.tools {
        let name = entry.name.trim();
        if name.is_empty() {
            return Err(McpError::Message(
                "tools/list entry missing name".to_owned(),
            ));
        }
        // Diagnostics paste is line-oriented; control chars / newlines would spoof fields.
        if name.chars().any(|c| c.is_control()) {
            return Err(McpError::Message(
                "tools/list entry name contains control characters".to_owned(),
            ));
        }
        if tools.iter().any(|t| t.name == name) {
            return Err(McpError::Message(
                "tools/list duplicate tool name".to_owned(),
            ));
        }
        tools.push(McpToolCapability {
            name: name.to_owned(),
            description: entry.description.trim().to_owned(),
        });
    }
    Ok(tools)
}

/// Canonical tools/list (trimmed names/descriptions; same fail-closed rules as summarize).
fn canonicalize_tools_list(list: ToolsListResponse) -> Result<ToolsListResponse, McpError> {
    Ok(ToolsListResponse {
        tools: summarize_tools(&list)?
            .into_iter()
            .map(|t| ToolsListEntry {
                name: t.name,
                description: t.description,
            })
            .collect(),
    })
}

/// In-memory Fake MCP server for diagnostics / Settings — **no** socket, **no**
/// tool execution, **no** bearer token storage.
///
/// Start validates the configured port via [`loopback_v4`] (fail-closed). Callers
/// that want to probe an arbitrary bind use [`Self::validate_bind`] /
/// [`capability_report_for_bind`].
#[derive(Clone)]
pub struct FakeMcpCapabilityServer {
    port: u16,
    running: bool,
    tools: ToolsListResponse,
}

impl FakeMcpCapabilityServer {
    /// Default port ([`DEFAULT_MCP_PORT`]) + canonical Wormhole tools.
    pub fn new() -> Self {
        Self::with_port(DEFAULT_MCP_PORT).expect("default MCP port is valid")
    }

    /// Construct with a fixed port (rejects port `0`).
    pub fn with_port(port: u16) -> Result<Self, McpError> {
        validate_mcp_port(port)?;
        Ok(Self {
            port,
            running: false,
            tools: ToolsListResponse::wormhole_ssh_tools(),
        })
    }

    /// Construct with an explicit tools/list shape (still loopback-only endpoint).
    pub fn with_port_and_tools(port: u16, tools: ToolsListResponse) -> Result<Self, McpError> {
        validate_mcp_port(port)?;
        // Canonicalize early so tools_list() matches capability_report() names.
        let tools = canonicalize_tools_list(tools)?;
        Ok(Self {
            port,
            running: false,
            tools,
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn is_running(&self) -> bool {
        self.running
    }

    pub fn endpoint_url(&self) -> String {
        loopback_endpoint_url(self.port)
    }

    /// Mark running after confirming the port is a valid loopback bind target.
    ///
    /// Does **not** open a socket (Fake). Fail-closed on port `0` / invalid port.
    pub fn start(&mut self) -> Result<(), McpError> {
        let _addr = loopback_v4(self.port)?;
        self.running = true;
        Ok(())
    }

    pub fn stop(&mut self) {
        self.running = false;
    }

    /// Consume bind helpers — reject non-loopback addresses (no reimplementation).
    pub fn validate_bind(addr: SocketAddr) -> Result<(), McpError> {
        validate_loopback_bind(addr)
    }

    /// tools/list shape currently advertised by this Fake.
    pub fn tools_list(&self) -> &ToolsListResponse {
        &self.tools
    }

    /// Capability summary for diagnostics / Settings Fake.
    pub fn capability_report(&self) -> Result<McpCapabilityReport, McpError> {
        capability_report_from_tools_list(self.port, self.running, &self.tools)
    }

    /// Live tools/call is intentionally unwired — always fail closed.
    pub fn execute_tool(&self, name: &str) -> Result<(), McpError> {
        let _ = name;
        Err(McpError::Message(
            "MCP tool execution not wired (Fake capability server)".to_owned(),
        ))
    }
}

impl Default for FakeMcpCapabilityServer {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for FakeMcpCapabilityServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeMcpCapabilityServer")
            .field("port", &self.port)
            .field("running", &self.running)
            .field("tool_count", &self.tools.tools.len())
            .field("endpoint_url", &self.endpoint_url())
            // Intentionally no token / secret fields.
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port)
    }

    #[test]
    fn wormhole_catalog_matches_csharp_names() {
        let list = ToolsListResponse::wormhole_ssh_tools();
        let names: Vec<_> = list.tools.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(
            names,
            [
                TOOL_LIST_SESSIONS,
                TOOL_RUN_COMMAND,
                TOOL_SEND_TEXT,
                TOOL_READ_TERMINAL,
            ]
        );
        assert_eq!(list.tools.len(), 4);
        for tool in &list.tools {
            assert!(!tool.description.is_empty());
        }
    }

    #[test]
    fn capability_report_from_tools_list_loopback_only() {
        let report =
            capability_report_from_tools_list(8765, true, &ToolsListResponse::wormhole_ssh_tools())
                .unwrap();
        assert_eq!(report.endpoint_url, "http://127.0.0.1:8765");
        assert!(report.running);
        assert!(!report.tools_executable);
        assert_eq!(report.tool_names(), vec![
            TOOL_LIST_SESSIONS,
            TOOL_RUN_COMMAND,
            TOOL_SEND_TEXT,
            TOOL_READ_TERMINAL,
        ]);
        let text = report.format_for_diagnostics();
        assert!(text.contains("list_sessions"));
        assert!(!text.to_ascii_lowercase().contains("bearer"));
        assert!(!text.to_ascii_lowercase().contains("token"));
    }

    #[test]
    fn capability_rejects_port_zero_and_blank_tool_names() {
        assert!(matches!(
            capability_report_from_tools_list(0, false, &ToolsListResponse::empty()),
            Err(McpError::InvalidPort(0))
        ));
        let bad = ToolsListResponse {
            tools: vec![ToolsListEntry {
                name: "  ".into(),
                description: "x".into(),
            }],
        };
        let err = capability_report_from_tools_list(8765, false, &bad).unwrap_err();
        assert!(matches!(err, McpError::Message(_)));
        assert!(!err.to_string().to_ascii_lowercase().contains("bearer"));
    }

    #[test]
    fn capability_report_for_bind_fail_closed_off_loopback() {
        let list = ToolsListResponse::wormhole_ssh_tools();
        assert!(capability_report_for_bind(v4(127, 0, 0, 1, 8765), false, &list).is_ok());

        let hostile = [
            v4(0, 0, 0, 0, 8765),
            v4(192, 168, 1, 1, 8765),
            v4(8, 8, 8, 8, 8765),
            SocketAddr::new(IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()), 8765),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 8765),
        ];
        for addr in hostile {
            assert!(
                capability_report_for_bind(addr, false, &list).is_err(),
                "must reject {addr}"
            );
        }

        assert!(capability_report_for_bind_str("127.0.0.1:9001", true, &list).is_ok());
        assert!(capability_report_for_bind_str("0.0.0.0:8765", false, &list).is_err());
        assert!(capability_report_for_bind_str("[::ffff:127.0.0.1]:8765", false, &list).is_err());
        assert!(capability_report_for_bind_str("[::1%1]:8765", false, &list).is_err());
    }

    #[test]
    fn fake_server_lifecycle_and_no_execution() {
        let mut fake = FakeMcpCapabilityServer::with_port(9_101).unwrap();
        assert!(!fake.is_running());
        assert_eq!(fake.endpoint_url(), "http://127.0.0.1:9101");
        fake.start().unwrap();
        assert!(fake.is_running());
        let report = fake.capability_report().unwrap();
        assert!(report.running);
        assert!(!report.tools_executable);
        assert_eq!(report.tools.len(), 4);

        let exec_err = fake.execute_tool(TOOL_LIST_SESSIONS).unwrap_err();
        assert!(matches!(exec_err, McpError::Message(_)));
        assert!(exec_err.to_string().contains("not wired"));

        fake.stop();
        assert!(!fake.is_running());
    }

    #[test]
    fn fake_rejects_port_zero_and_hostile_bind() {
        assert!(matches!(
            FakeMcpCapabilityServer::with_port(0),
            Err(McpError::InvalidPort(0))
        ));
        assert!(FakeMcpCapabilityServer::validate_bind(v4(127, 0, 0, 1, 8765)).is_ok());
        assert!(FakeMcpCapabilityServer::validate_bind(v4(0, 0, 0, 0, 8765)).is_err());
        assert!(FakeMcpCapabilityServer::validate_bind(v4(10, 0, 0, 1, 8765)).is_err());
    }

    #[test]
    fn fake_with_blank_tool_name_rejected_at_construction() {
        let bad = ToolsListResponse {
            tools: vec![ToolsListEntry {
                name: String::new(),
                description: "oops".into(),
            }],
        };
        assert!(FakeMcpCapabilityServer::with_port_and_tools(8765, bad).is_err());
    }

    #[test]
    fn summarize_rejects_control_chars_and_duplicates() {
        let newline_name = ToolsListResponse {
            tools: vec![ToolsListEntry {
                name: "list_sessions\nrunning: yes".into(),
                description: "x".into(),
            }],
        };
        let err = capability_report_from_tools_list(8765, false, &newline_name).unwrap_err();
        assert!(matches!(err, McpError::Message(_)));
        assert!(err.to_string().contains("control"));
        assert!(!err.to_string().to_ascii_lowercase().contains("bearer"));

        let nul_name = ToolsListResponse {
            tools: vec![ToolsListEntry {
                name: "run\0command".into(),
                description: "x".into(),
            }],
        };
        assert!(capability_report_from_tools_list(8765, false, &nul_name).is_err());

        let dup = ToolsListResponse {
            tools: vec![
                ToolsListEntry {
                    name: TOOL_LIST_SESSIONS.into(),
                    description: "a".into(),
                },
                ToolsListEntry {
                    name: format!("  {TOOL_LIST_SESSIONS}  "),
                    description: "b".into(),
                },
            ],
        };
        let dup_err = capability_report_from_tools_list(8765, false, &dup).unwrap_err();
        assert!(dup_err.to_string().contains("duplicate"));
    }

    #[test]
    fn with_port_and_tools_canonicalizes_trimmed_names() {
        let padded = ToolsListResponse {
            tools: vec![ToolsListEntry {
                name: "  list_sessions  ".into(),
                description: "  desc  ".into(),
            }],
        };
        let fake = FakeMcpCapabilityServer::with_port_and_tools(8765, padded).unwrap();
        assert_eq!(fake.tools_list().tools[0].name, TOOL_LIST_SESSIONS);
        assert_eq!(fake.tools_list().tools[0].description, "desc");
        assert_eq!(
            fake.capability_report().unwrap().tool_names(),
            vec![TOOL_LIST_SESSIONS]
        );
    }

    #[test]
    fn execute_tool_fail_closed_for_every_catalog_tool_while_running() {
        let mut fake = FakeMcpCapabilityServer::new();
        fake.start().unwrap();
        for (name, _) in wormhole_tool_catalog() {
            let err = fake.execute_tool(name).unwrap_err();
            assert!(
                matches!(err, McpError::Message(_)),
                "execute_tool({name}) must fail closed"
            );
            assert!(err.to_string().contains("not wired"));
            assert!(!err.to_string().to_ascii_lowercase().contains("bearer"));
            assert!(!err.to_string().to_ascii_lowercase().contains("token"));
        }
        // Unknown name still fail-closed (no live dispatch).
        let unknown = fake.execute_tool("not_a_real_tool").unwrap_err();
        assert!(unknown.to_string().contains("not wired"));
    }

    #[test]
    fn capability_report_for_bind_accepts_ipv6_loopback() {
        let list = ToolsListResponse::wormhole_ssh_tools();
        let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8765);
        let report = capability_report_for_bind(addr, true, &list).unwrap();
        // Endpoint URL is always hard-coded 127.0.0.1 (never advertise ::1 / mapped).
        assert_eq!(report.endpoint_url, "http://127.0.0.1:8765");
        assert!(report.running);
        assert!(!report.tools_executable);
    }

    #[test]
    fn diagnostics_text_is_line_stable_for_canonical_catalog() {
        let report = wormhole_capability_report(DEFAULT_MCP_PORT).unwrap();
        let text = report.format_for_diagnostics();
        assert!(!text.contains('\r'));
        for line in text.lines() {
            // No spoofed key lines from tool names.
            if line.starts_with("  - ") {
                assert!(!line[4..].contains(':'));
            }
        }
        assert!(!text.to_ascii_lowercase().contains("bearer"));
        assert!(!text.to_ascii_lowercase().contains("token"));
    }

    #[test]
    fn debug_omits_secrets_and_token_wording() {
        let fake = FakeMcpCapabilityServer::new();
        let dbg = format!("{fake:?}");
        assert!(dbg.contains("FakeMcpCapabilityServer"));
        assert!(dbg.contains("port"));
        assert!(!dbg.to_ascii_lowercase().contains("bearer"));
        assert!(!dbg.to_ascii_lowercase().contains("token"));
        assert!(!dbg.contains("secret"));

        let report = fake.capability_report().unwrap();
        let report_dbg = format!("{report:?}");
        assert!(!report_dbg.to_ascii_lowercase().contains("bearer"));
        assert!(!report_dbg.to_ascii_lowercase().contains("token"));
        // Descriptions are summarized by length in Debug, not full body — still ok if present;
        // must not invent credential fields.
        assert!(!report_dbg.contains("password"));
    }

    #[test]
    fn wormhole_capability_report_helper() {
        let report = wormhole_capability_report(DEFAULT_MCP_PORT).unwrap();
        assert_eq!(report.port, DEFAULT_MCP_PORT);
        assert!(!report.running);
        assert_eq!(report.tools.len(), 4);
    }
}
