//! `rmcp` ServerHandler + Streamable HTTP loopback host.
use crate::approval::SessionApprovalGate;
use crate::bind::{
    ensure_bound_loopback, is_loopback_ip, loopback_endpoint_url, loopback_v4,
    validate_loopback_bind, validate_mcp_port,
};
use crate::capability::{
    wormhole_tool_catalog, TOOL_LIST_SESSIONS, TOOL_READ_TERMINAL, TOOL_RUN_COMMAND,
    TOOL_SEND_TEXT,
};
use crate::token::{self, is_authorized, McpTokenStore, MemoryTokenStore};
use crate::{McpError, McpServerHost, DEFAULT_MCP_PORT};
use async_trait::async_trait;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use rmcp::handler::server::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ContentBlock, Implementation, ListToolsResult,
    PaginatedRequestParams, ServerCapabilities, ServerInfo, Tool,
};
use rmcp::service::RequestContext;
use rmcp::transport::streamable_http_server::session::never::NeverSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{ErrorData as RmcpError, RoleServer};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::{Mutex as AsyncMutex, RwLock};
use tokio_util::sync::CancellationToken;

fn empty_object_schema() -> Arc<rmcp::model::JsonObject> {
    let mut obj = rmcp::model::JsonObject::new();
    obj.insert("type".into(), serde_json::json!("object"));
    obj.insert("properties".into(), serde_json::json!({}));
    Arc::new(obj)
}
fn object_schema(properties: serde_json::Value, required: &[&str]) -> Arc<rmcp::model::JsonObject> {
    let mut obj = rmcp::model::JsonObject::new();
    obj.insert("type".into(), serde_json::json!("object"));
    obj.insert("properties".into(), properties);
    obj.insert("required".into(), serde_json::json!(required));
    Arc::new(obj)
}

/// Tool definitions matching `Services/Mcp/McpSshTools.cs`.
///
/// Names / descriptions come from [`wormhole_tool_catalog`]; input schemas stay here
/// (capability glue deliberately omits schemas).
pub fn wormhole_mcp_tools() -> Vec<Tool> {
    let catalog = wormhole_tool_catalog();
    let desc = |name: &str| {
        catalog
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, d)| *d)
            .expect("catalog must include every tool name")
    };
    vec![
        Tool::new(
            TOOL_LIST_SESSIONS,
            desc(TOOL_LIST_SESSIONS),
            empty_object_schema(),
        ),
        Tool::new(
            TOOL_RUN_COMMAND,
            desc(TOOL_RUN_COMMAND),
            object_schema(
                serde_json::json!({
                    "sessionId": { "type": "string" },
                    "command": { "type": "string" },
                    "timeoutSeconds": { "type": "integer", "default": 30 }
                }),
                &["sessionId", "command"],
            ),
        ),
        Tool::new(
            TOOL_SEND_TEXT,
            desc(TOOL_SEND_TEXT),
            object_schema(
                serde_json::json!({
                    "sessionId": { "type": "string" },
                    "text": { "type": "string" }
                }),
                &["sessionId", "text"],
            ),
        ),
        Tool::new(
            TOOL_READ_TERMINAL,
            desc(TOOL_READ_TERMINAL),
            object_schema(
                serde_json::json!({
                    "sessionId": { "type": "string" },
                    "maxBytes": { "type": "integer", "default": 65536 }
                }),
                &["sessionId"],
            ),
        ),
    ]
}
/// Official-sdk handler — tools/list matches C#; call_tool stubs go through approval.
#[derive(Clone)]
pub struct WormholeMcpHandler {
    approval: Arc<SessionApprovalGate>,
}
impl WormholeMcpHandler {
    pub fn new(approval: Arc<SessionApprovalGate>) -> Self {
        Self { approval }
    }
    pub fn approval(&self) -> Arc<SessionApprovalGate> {
        Arc::clone(&self.approval)
    }
    fn session_id_arg(args: &Option<serde_json::Map<String, serde_json::Value>>) -> Option<String> {
        args.as_ref()
            .and_then(|m| m.get("sessionId").or_else(|| m.get("session_id")))
            .and_then(|v| v.as_str())
            .map(str::to_owned)
    }
    /// Dispatch a tool call without an HTTP/`RequestContext` (tests + stub path).
    ///
    /// Stubs never open sockets or fetch URLs — session control tools only consult the
    /// approval gate, then return a fixed "not wired" error.
    pub async fn dispatch_tool(
        &self,
        name: &str,
        arguments: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> Result<CallToolResult, RmcpError> {
        match name {
            TOOL_LIST_SESSIONS => Ok(CallToolResult::success(vec![ContentBlock::text("[]")])),
            TOOL_RUN_COMMAND | TOOL_SEND_TEXT | TOOL_READ_TERMINAL => {
                let session_id = Self::session_id_arg(&arguments).unwrap_or_default();
                if session_id.is_empty() {
                    return Ok(CallToolResult::error(vec![ContentBlock::text(
                        "sessionId is required",
                    )]));
                }
                let tool: &'static str = match name {
                    TOOL_RUN_COMMAND => TOOL_RUN_COMMAND,
                    TOOL_SEND_TEXT => TOOL_SEND_TEXT,
                    _ => TOOL_READ_TERMINAL,
                };
                match self.approval.ensure_approved(&session_id, tool).await {
                    Ok(()) => Ok(CallToolResult::error(vec![ContentBlock::text(
                        "SSH session registry not wired yet",
                    )])),
                    Err(e) => Ok(CallToolResult::error(vec![ContentBlock::text(
                        e.to_string(),
                    )])),
                }
            }
            other => Err(RmcpError::invalid_params(
                format!("unknown tool: {other}"),
                None,
            )),
        }
    }
}
impl ServerHandler for WormholeMcpHandler {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("wormhole", env!("CARGO_PKG_VERSION")))
    }
    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListToolsResult, RmcpError>> + Send + '_ {
        async { Ok(ListToolsResult::with_all_items(wormhole_mcp_tools())) }
    }
    fn get_tool(&self, name: &str) -> Option<Tool> {
        wormhole_mcp_tools().into_iter().find(|t| t.name == name)
    }
    fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<rmcp::model::CallToolResponse, RmcpError>> + Send + '_
    {
        async move {
            let result = self
                .dispatch_tool(request.name.as_ref(), request.arguments)
                .await?;
            Ok(result.into())
        }
    }
}
#[derive(Clone)]
struct AuthState {
    expected: Arc<RwLock<String>>,
}
/// Host that binds Streamable HTTP on **127.0.0.1 only** with bearer auth.
///
/// Tokens are never written to tracing fields. Non-loopback peers are rejected.
pub struct RmcpLoopbackHost {
    port: AtomicU16,
    running: AtomicBool,
    token_store: Arc<dyn McpTokenStore>,
    token_gate: AsyncMutex<()>,
    lifecycle: AsyncMutex<()>,
    expected_token: Arc<RwLock<String>>,
    approval: Arc<SessionApprovalGate>,
    handler: Arc<WormholeMcpHandler>,
    shutdown: Mutex<Option<CancellationToken>>,
    server_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}
impl RmcpLoopbackHost {
    pub fn new() -> Self {
        Self::with_port(DEFAULT_MCP_PORT).expect("default MCP port is valid")
    }
    pub fn with_port(port: u16) -> Result<Self, McpError> {
        Self::with_port_and_store(port, Arc::new(MemoryTokenStore::new()))
    }
    pub fn with_port_and_store(
        port: u16,
        token_store: Arc<dyn McpTokenStore>,
    ) -> Result<Self, McpError> {
        validate_mcp_port(port)?;
        let approval = Arc::new(SessionApprovalGate::new());
        Ok(Self {
            port: AtomicU16::new(port),
            running: AtomicBool::new(false),
            token_store,
            token_gate: AsyncMutex::new(()),
            lifecycle: AsyncMutex::new(()),
            expected_token: Arc::new(RwLock::new(String::new())),
            approval: Arc::clone(&approval),
            handler: Arc::new(WormholeMcpHandler::new(approval)),
            shutdown: Mutex::new(None),
            server_task: Mutex::new(None),
        })
    }
    /// Reject a non-loopback bind address before start.
    pub fn validate_bind_addr(addr: SocketAddr) -> Result<(), McpError> {
        validate_loopback_bind(addr)
    }
    pub fn handler(&self) -> Arc<WormholeMcpHandler> {
        Arc::clone(&self.handler)
    }
    pub fn approval(&self) -> Arc<SessionApprovalGate> {
        Arc::clone(&self.approval)
    }
    async fn sync_expected_token(&self, token: &str) {
        *self.expected_token.write().await = token.to_owned();
    }
}
impl Default for RmcpLoopbackHost {
    fn default() -> Self {
        Self::new()
    }
}
async fn health_handler() -> impl IntoResponse {
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({ "status": "ok" })),
    )
}
async fn auth_and_loopback_middleware(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<AuthState>,
    headers: HeaderMap,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    if !is_loopback_ip(peer.ip()) {
        return (
            StatusCode::FORBIDDEN,
            "Forbidden: non-loopback peer rejected.",
        )
            .into_response();
    }
    let expected = state.expected.read().await.clone();
    let presented = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    if is_authorized(presented, &expected) {
        next.run(request).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            "Unauthorized: missing or invalid bearer token.",
        )
            .into_response()
    }
}
fn build_router(
    handler: WormholeMcpHandler,
    auth: AuthState,
    cancel: CancellationToken,
    port: u16,
) -> Router {
    let config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_json_response(true)
        .with_cancellation_token(cancel)
        .with_allowed_hosts([
            "127.0.0.1".to_string(),
            format!("127.0.0.1:{port}"),
            "localhost".to_string(),
            format!("localhost:{port}"),
            "[::1]".to_string(),
            format!("[::1]:{port}"),
        ]);
    let mcp_service = StreamableHttpService::new(
        move || Ok(handler.clone()),
        Arc::new(NeverSessionManager::default()),
        config,
    );
    Router::new()
        .route("/health", get(health_handler))
        // MCP at `/` to match C# `MapMcp()` root mount; health stays beside it.
        .fallback_service(mcp_service)
        .layer(middleware::from_fn_with_state(
            auth,
            auth_and_loopback_middleware,
        ))
}
#[async_trait]
impl McpServerHost for RmcpLoopbackHost {
    fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
    fn port(&self) -> u16 {
        self.port.load(Ordering::SeqCst)
    }
    fn endpoint_url(&self) -> String {
        // Parity with C# `EndpointUrl` (`http://127.0.0.1:{port}`); MCP is mounted at `/`.
        loopback_endpoint_url(self.port())
    }
    async fn start(&self) -> Result<(), McpError> {
        let _gate = self.lifecycle.lock().await;
        if self.running.load(Ordering::SeqCst) {
            return Ok(());
        }
        let port = self.port();
        let addr = loopback_v4(port)?;
        // get_or_create_token syncs expected_token for the auth middleware.
        let _token = self.get_or_create_token().await?;
        let cancel = CancellationToken::new();
        let auth = AuthState {
            expected: Arc::clone(&self.expected_token),
        };
        let router = build_router((*self.handler).clone(), auth, cancel.child_token(), port);
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(McpError::Bind)?;
        let local = listener.local_addr().map_err(McpError::Bind)?;
        // Fail-closed if the OS somehow reports a non-loopback local address.
        ensure_bound_loopback(local)?;
        let serve_cancel = cancel.clone();
        let task = tokio::spawn(async move {
            let server = axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(async move {
                serve_cancel.cancelled().await;
            });
            if let Err(e) = server.await {
                tracing::warn!(error = %e, "MCP HTTP server exited with error");
            }
        });
        *self.shutdown.lock().unwrap_or_else(|p| p.into_inner()) = Some(cancel);
        *self.server_task.lock().unwrap_or_else(|p| p.into_inner()) = Some(task);
        self.running.store(true, Ordering::SeqCst);
        // Endpoint only — never the token.
        tracing::info!(
            endpoint = %self.endpoint_url(),
            "MCP Streamable HTTP listening (loopback only)"
        );
        Ok(())
    }
    async fn stop(&self) -> Result<(), McpError> {
        let _gate = self.lifecycle.lock().await;
        if !self.running.load(Ordering::SeqCst) {
            return Ok(());
        }
        if let Some(cancel) = self
            .shutdown
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
        {
            cancel.cancel();
        }
        let handle = self
            .server_task
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
        if let Some(handle) = handle {
            let _ = handle.await;
        }
        self.running.store(false, Ordering::SeqCst);
        tracing::info!("MCP Streamable HTTP stopped");
        Ok(())
    }
    async fn get_or_create_token(&self) -> Result<String, McpError> {
        let minted =
            token::get_or_create_token(self.token_store.as_ref(), &self.token_gate).await?;
        self.sync_expected_token(&minted).await;
        Ok(minted)
    }
    async fn peek_token(&self) -> Result<Option<String>, McpError> {
        self.token_store.peek().await
    }
    async fn regenerate_token(&self) -> Result<String, McpError> {
        let minted = token::regenerate_token(self.token_store.as_ref(), &self.token_gate).await?;
        self.sync_expected_token(&minted).await;
        // Intentionally no tracing of the token value.
        Ok(minted)
    }
}
