use async_trait::async_trait;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use wormhole_mcp::{
    is_authorized, is_loopback_ip, loopback_endpoint_url, validate_loopback_bind,
    validate_mcp_port, HttpPlaceholderMcpHost, McpError, McpServerHost, McpTokenStore,
    MemoryTokenStore, DEFAULT_MCP_PORT,
};

struct FailingTokenStore;

#[async_trait]
impl McpTokenStore for FailingTokenStore {
    async fn peek(&self) -> Result<Option<String>, McpError> {
        Ok(None)
    }

    async fn store(&self, _token: &str) -> Result<(), McpError> {
        Err(McpError::TokenStore("injected store failure".into()))
    }
}

fn free_loopback_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral bind");
    listener.local_addr().expect("local addr").port()
}
#[tokio::test]
async fn placeholder_start_stop_and_token() {
    let host = HttpPlaceholderMcpHost::with_port(DEFAULT_MCP_PORT).unwrap();
    assert!(!host.is_running());
    assert_eq!(host.endpoint_url(), "http://127.0.0.1:8765");
    assert!(host.endpoint_url().starts_with("http://127.0.0.1:"));
    host.start().await.unwrap();
    assert!(host.is_running());
    let token = host.get_or_create_token().await.unwrap();
    assert!(!token.is_empty());
    assert_eq!(
        host.peek_token().await.unwrap().as_deref(),
        Some(token.as_str())
    );
    let regenerated = host.regenerate_token().await.unwrap();
    assert_ne!(regenerated, token);
    assert_eq!(
        host.peek_token().await.unwrap().as_deref(),
        Some(regenerated.as_str())
    );
    host.stop().await.unwrap();
    assert!(!host.is_running());
}
#[tokio::test]
async fn placeholder_as_trait_object() {
    let host: Arc<dyn McpServerHost> = Arc::new(HttpPlaceholderMcpHost::new());
    host.start().await.unwrap();
    assert!(host.is_running());
    host.stop().await.unwrap();
}
#[tokio::test]
async fn placeholder_rejects_empty_stored_token() {
    let store = Arc::new(MemoryTokenStore::with_token(""));
    let host = HttpPlaceholderMcpHost::with_port_and_store(9_002, store).unwrap();
    let token = host.get_or_create_token().await.unwrap();
    assert!(!token.is_empty());
}

#[tokio::test]
async fn placeholder_start_rolls_back_running_on_token_failure() {
    let host =
        HttpPlaceholderMcpHost::with_port_and_store(9_003, Arc::new(FailingTokenStore)).unwrap();
    let err = host.start().await.unwrap_err();
    assert!(matches!(err, McpError::TokenStore(_)));
    assert!(
        !host.is_running(),
        "failed start must not leave the host marked running"
    );
}
#[tokio::test]
async fn rejects_port_zero() {
    let err = match HttpPlaceholderMcpHost::with_port(0) {
        Ok(_) => panic!("port 0 must be rejected"),
        Err(e) => e,
    };
    assert!(matches!(err, McpError::InvalidPort(0)));
    assert!(matches!(
        validate_mcp_port(0),
        Err(McpError::InvalidPort(0))
    ));
}
#[tokio::test]
async fn endpoint_url_is_loopback_only() {
    let url = loopback_endpoint_url(8765);
    assert_eq!(url, "http://127.0.0.1:8765");
    assert!(!url.contains("0.0.0.0"));
    assert!(!url.contains("[::]"));
    let host = HttpPlaceholderMcpHost::with_port(9_001).unwrap();
    assert_eq!(host.endpoint_url(), "http://127.0.0.1:9001");
}
#[tokio::test]
async fn rejects_non_loopback_bind_addr() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8765);
    let err = validate_loopback_bind(addr).unwrap_err();
    assert!(matches!(err, McpError::NonLoopbackBind(_)));
    assert!(!is_loopback_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
    assert!(is_loopback_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    assert!(!is_loopback_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
}

#[tokio::test]
async fn rejects_hostile_bind_strings_and_hosts() {
    use wormhole_mcp::{parse_loopback_bind, validate_loopback_host};

    for input in [
        "0.0.0.0:8765",
        "[::]:8765",
        "[::0]:8765",
        "192.168.1.10:8765",
        "10.0.0.1:8765",
        "8.8.8.8:443",
        "*:8765",
        "*",
        "[::ffff:8.8.8.8]:8765",
        "[::ffff:0.0.0.0]:8765",
        "[::ffff:0:0]:8765",
        "[::ffff:127.0.0.1]:8765",
        "localhost:8765",
        "example.com:8765",
        "[::1%1]:8765",
    ] {
        assert!(
            parse_loopback_bind(input).is_err(),
            "must reject hostile bind {input}"
        );
    }
    assert!(parse_loopback_bind("127.0.0.1:8765").is_ok());
    assert!(parse_loopback_bind("[::1]:8765").is_ok());

    for host in [
        "0.0.0.0",
        "*",
        "::",
        "192.168.1.1",
        "8.8.8.8",
        "::ffff:127.0.0.1",
        "::ffff:0:0",
        "localhost.",
    ] {
        assert!(
            validate_loopback_host(host).is_err(),
            "must reject hostile host {host}"
        );
    }
    assert!(validate_loopback_host("127.0.0.1").is_ok());
    assert!(validate_loopback_host("localhost").is_ok());
    assert!(validate_loopback_host("::1").is_ok());
}
#[tokio::test]
async fn idempotent_start_stop() {
    let host = HttpPlaceholderMcpHost::new();
    host.start().await.unwrap();
    host.start().await.unwrap();
    assert!(host.is_running());
    host.stop().await.unwrap();
    host.stop().await.unwrap();
    assert!(!host.is_running());
}
#[tokio::test]
async fn approval_defaults_to_fail_closed() {
    let host = HttpPlaceholderMcpHost::new();
    let err = host
        .approval()
        .ensure_approved("sess-x", "run_command")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("denied"));
}
#[tokio::test]
async fn bearer_helpers_match_csharp_case_rules() {
    assert!(is_authorized(Some("BEARER good"), "good"));
    assert!(is_authorized(Some("Bearer good"), "good"));
    assert!(!is_authorized(Some("Bearer good"), ""));
}
#[cfg(feature = "rmcp")]
mod rmcp_http {
    use super::*;
    use rmcp::handler::server::ServerHandler;
    use serde_json::json;
    use wormhole_mcp::{
        wormhole_mcp_tools, ApprovalDecision, RmcpLoopbackHost, SessionApprovalGate,
        WormholeMcpHandler, TOOL_LIST_SESSIONS, TOOL_READ_TERMINAL, TOOL_RUN_COMMAND,
        TOOL_SEND_TEXT,
    };
    async fn raw_http(
        port: u16,
        method: &str,
        path: &str,
        auth: Option<&str>,
        body: &str,
    ) -> (u16, String) {
        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        let auth_line = match auth {
            Some(t) => format!("Authorization: Bearer {t}\r\n"),
            None => String::new(),
        };
        let content_len = if body.is_empty() {
            String::new()
        } else {
            format!(
                "Content-Length: {}\r\nContent-Type: application/json\r\n",
                body.len()
            )
        };
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n{auth_line}{content_len}\r\n{body}"
        );
        stream.write_all(req.as_bytes()).await.expect("write");
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.expect("read");
        let text = String::from_utf8_lossy(&buf).into_owned();
        let status = text
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        (status, text)
    }
    async fn raw_http_get(port: u16, path: &str, auth: Option<&str>) -> (u16, String) {
        raw_http(port, "GET", path, auth, "").await
    }
    #[tokio::test]
    async fn rmcp_start_rolls_back_when_bind_fails() {
        let port = free_loopback_port();
        let _holder = std::net::TcpListener::bind(("127.0.0.1", port)).expect("hold port");
        let host = RmcpLoopbackHost::with_port(port).unwrap();
        let err = host.start().await.unwrap_err();
        assert!(matches!(err, McpError::Bind(_)));
        assert!(!host.is_running());
    }

    #[tokio::test]
    async fn rmcp_host_rejects_port_zero() {
        let err = match RmcpLoopbackHost::with_port(0) {
            Ok(_) => panic!("port 0 must be rejected"),
            Err(e) => e,
        };
        assert!(matches!(err, McpError::InvalidPort(0)));
    }
    #[tokio::test]
    async fn rmcp_host_rejects_non_loopback_bind() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8765);
        let err = RmcpLoopbackHost::validate_bind_addr(addr).unwrap_err();
        assert!(matches!(err, McpError::NonLoopbackBind(_)));
    }
    #[tokio::test]
    async fn rmcp_tools_list_matches_csharp_surface() {
        let names: Vec<_> = wormhole_mcp_tools()
            .into_iter()
            .map(|t| t.name.to_string())
            .collect();
        assert_eq!(
            names,
            vec![
                TOOL_LIST_SESSIONS,
                TOOL_RUN_COMMAND,
                TOOL_SEND_TEXT,
                TOOL_READ_TERMINAL
            ]
        );
    }
    #[tokio::test]
    async fn rmcp_bind_health_and_reject_bad_token() {
        let port = free_loopback_port();
        let store = Arc::new(MemoryTokenStore::with_token("unit-test-good-token"));
        let host = RmcpLoopbackHost::with_port_and_store(port, store).unwrap();
        assert!(host.endpoint_url().starts_with("http://127.0.0.1:"));
        assert!(!host.endpoint_url().contains("/mcp"));
        assert_eq!(host.endpoint_url(), format!("http://127.0.0.1:{port}"));
        host.start().await.expect("bind start");
        assert!(host.is_running());
        tokio::time::sleep(Duration::from_millis(50)).await;
        let (no_auth, _) = raw_http_get(port, "/health", None).await;
        assert_eq!(no_auth, 401);
        let (bad, body) = raw_http_get(port, "/health", Some("wrong-token")).await;
        assert_eq!(bad, 401);
        assert!(body.contains("Unauthorized"));
        let token = host.get_or_create_token().await.unwrap();
        assert_eq!(token, "unit-test-good-token");
        let (ok, body) = raw_http_get(port, "/health", Some(&token)).await;
        assert_eq!(ok, 200, "body={body}");
        assert!(body.contains("ok"));
        // MCP root path also requires bearer (not only /health).
        let (mcp_no_auth, _) = raw_http(port, "POST", "/", None, "{}").await;
        assert_eq!(mcp_no_auth, 401);
        let (mcp_bad, _) = raw_http(port, "POST", "/", Some("wrong-token"), "{}").await;
        assert_eq!(mcp_bad, 401);
        let info = host.handler().get_info();
        assert_eq!(info.server_info.name, "wormhole");
        assert!(info.capabilities.tools.is_some());
        host.stop().await.unwrap();
        assert!(!host.is_running());
    }
    #[tokio::test]
    async fn regenerate_rotates_live_bearer() {
        let port = free_loopback_port();
        let store = Arc::new(MemoryTokenStore::with_token("first-token"));
        let host = RmcpLoopbackHost::with_port_and_store(port, store).unwrap();
        host.start().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let (ok, _) = raw_http_get(port, "/health", Some("first-token")).await;
        assert_eq!(ok, 200);
        let next = host.regenerate_token().await.unwrap();
        assert_ne!(next, "first-token");
        let (stale, _) = raw_http_get(port, "/health", Some("first-token")).await;
        assert_eq!(stale, 401);
        let (fresh, _) = raw_http_get(port, "/health", Some(&next)).await;
        assert_eq!(fresh, 200);
        host.stop().await.unwrap();
    }
    #[tokio::test]
    async fn approval_channel_approve_and_deny() {
        let host = RmcpLoopbackHost::with_port(free_loopback_port()).unwrap();
        let gate = host.approval();
        let mut rx = gate.open_channel();
        let gate2 = Arc::clone(&gate);
        let pending =
            tokio::spawn(async move { gate2.ensure_approved("sess-1", TOOL_RUN_COMMAND).await });
        let req = rx.recv().await.expect("approval request");
        assert_eq!(req.session_id, "sess-1");
        assert_eq!(req.tool, TOOL_RUN_COMMAND);
        req.respond.send(ApprovalDecision::Approve).unwrap();
        pending.await.unwrap().unwrap();
        gate.ensure_approved("sess-1", TOOL_SEND_TEXT)
            .await
            .unwrap();
        gate.clear_approvals();
        let gate3 = Arc::clone(&gate);
        let pending =
            tokio::spawn(async move { gate3.ensure_approved("sess-2", TOOL_READ_TERMINAL).await });
        let req = rx.recv().await.expect("deny request");
        req.respond.send(ApprovalDecision::Deny).unwrap();
        let err = pending.await.unwrap().unwrap_err();
        assert!(err.to_string().contains("denied"));
    }
    #[tokio::test]
    async fn tool_stubs_fail_closed_and_never_fetch_urls() {
        let gate = Arc::new(SessionApprovalGate::new());
        let handler = WormholeMcpHandler::new(Arc::clone(&gate));
        // Default AutoDeny — no network, denied before any session work.
        let denied = handler
            .dispatch_tool(
                TOOL_RUN_COMMAND,
                Some(
                    json!({
                        "sessionId": "http://169.254.169.254/latest/meta-data/",
                        "command": "curl http://evil.example"
                    })
                    .as_object()
                    .cloned()
                    .unwrap(),
                ),
            )
            .await
            .unwrap();
        let denied_text = format!("{denied:?}");
        assert!(denied_text.contains("denied") || denied_text.to_lowercase().contains("denied"));
        gate.set_auto_approve();
        let approved_stub = handler
            .dispatch_tool(
                TOOL_RUN_COMMAND,
                Some(
                    json!({
                        "sessionId": "http://169.254.169.254/latest/meta-data/",
                        "command": "curl http://evil.example"
                    })
                    .as_object()
                    .cloned()
                    .unwrap(),
                ),
            )
            .await
            .unwrap();
        let stub_text = format!("{approved_stub:?}");
        assert!(stub_text.contains("not wired"));
        // list_sessions returns empty JSON array, still no network.
        let listed = handler
            .dispatch_tool(TOOL_LIST_SESSIONS, None)
            .await
            .unwrap();
        let listed_text = format!("{listed:?}");
        assert!(listed_text.contains("[]"));
    }
}
#[cfg(feature = "secrets")]
mod secrets_store {
    use wormhole_mcp::CredMgrTokenStore;
    use wormhole_mcp::McpTokenStore;
    #[tokio::test]
    async fn cred_mgr_store_uses_fixed_mcp_credential_id() {
        assert_eq!(
            wormhole_secrets_win::MCP_TOKEN_CREDENTIAL_ID.to_string(),
            "a7f3c1e2-9b6d-4e8a-bf21-7c0d2e5a4b91"
        );
        let store = CredMgrTokenStore::new();
        // Missing credential is Ok(None); must not panic or log a token.
        let _ = store.peek().await.expect("peek");
    }
}
