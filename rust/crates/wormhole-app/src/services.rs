use std::sync::Arc;

use crate::placeholders::{stub_connection_store, stub_secret_store, ConnectionStore, SecretStore};

#[cfg(feature = "mcp")]
use wormhole_mcp::McpServerHost;

#[cfg(feature = "tunnels")]
use wormhole_tunnels::TunnelManager;

#[cfg(feature = "ui")]
use wormhole_ui::ShellState;

#[cfg(feature = "http")]
use wormhole_http::HttpConnectionTarget;

#[cfg(feature = "session")]
use wormhole_session::SessionOrchestrator;

/// Application service bag — mirrors DI registrations in `App.xaml.cs`.
pub struct AppServices {
    pub storage: Arc<dyn ConnectionStore>,
    pub secrets: Arc<dyn SecretStore>,

    #[cfg(feature = "tunnels")]
    pub tunnels: Option<Arc<TunnelManager>>,

    #[cfg(feature = "mcp")]
    pub mcp: Option<Arc<dyn McpServerHost>>,

    /// GPUI shell state (sidebar / tabs / panes). Optional until a window owns it.
    #[cfg(feature = "ui")]
    pub ui: Option<Arc<std::sync::Mutex<ShellState>>>,

    /// Marker that the VNC protocol crate is linked (session factory lands later).
    #[cfg(feature = "vnc")]
    pub vnc: Option<VncHandle>,

    /// Last / placeholder HTTP navigation target (WebView2 wiring later).
    #[cfg(feature = "http")]
    pub http: Option<Arc<HttpConnectionTarget>>,

    /// Presence handle for the SFTP crate (serialized session factory lands later).
    #[cfg(feature = "sftp")]
    pub sftp: Option<SftpHandle>,

    /// Protocol session orchestrator (Serial / SSH password / HTTP targets + tunnel lease).
    #[cfg(feature = "session")]
    pub session: Option<Arc<SessionOrchestrator>>,

    #[cfg(feature = "domain")]
    pub domain_marker: DomainMarker,

    #[cfg(feature = "storage")]
    pub storage_crate: bool,

    #[cfg(feature = "secrets")]
    pub secrets_crate: bool,
}

/// Presence marker that the domain crate is linked (pure types; no runtime service yet).
#[cfg(feature = "domain")]
#[derive(Debug, Clone, Copy, Default)]
pub struct DomainMarker;

/// Presence handle for the VNC crate (protocol types available; live engine optional).
#[cfg(feature = "vnc")]
#[derive(Debug, Clone, Copy, Default)]
pub struct VncHandle;

#[cfg(feature = "vnc")]
impl VncHandle {
    pub fn security_none_type(self) -> u8 {
        wormhole_vnc::SECURITY_TYPE_NONE
    }
}

/// Presence handle for the SFTP crate (serialized ops + queue; live russh channel later).
#[cfg(feature = "sftp")]
#[derive(Debug, Clone, Copy, Default)]
pub struct SftpHandle;

#[cfg(feature = "sftp")]
impl SftpHandle {
    /// Touch the serialization type so `cargo check -p wormhole-app` proves the crate unifies.
    pub fn gate_name(self) -> &'static str {
        std::any::type_name::<wormhole_sftp::SerializedSftpSession<wormhole_sftp::FakeSftpBackend>>()
    }
}

/// Smoke marker that the session orchestrator crate is linked.
#[cfg(feature = "session")]
#[derive(Debug, Clone, Copy, Default)]
pub struct SessionHandleMarker;

#[cfg(feature = "session")]
impl SessionHandleMarker {
    pub fn state_connected_name(self) -> &'static str {
        // Touch the state enum so the crate stays unified in check builds.
        let _ = wormhole_session::SessionState::Connected;
        "Connected"
    }
}

impl AppServices {
    pub fn builder() -> AppServicesBuilder {
        AppServicesBuilder::default()
    }
}

#[derive(Default)]
pub struct AppServicesBuilder {
    storage: Option<Arc<dyn ConnectionStore>>,
    secrets: Option<Arc<dyn SecretStore>>,
    #[cfg(feature = "tunnels")]
    tunnels: Option<Arc<TunnelManager>>,
    #[cfg(feature = "mcp")]
    mcp: Option<Arc<dyn McpServerHost>>,
    #[cfg(feature = "ui")]
    ui: Option<Arc<std::sync::Mutex<ShellState>>>,
    #[cfg(feature = "vnc")]
    vnc: Option<VncHandle>,
    #[cfg(feature = "http")]
    http: Option<Arc<HttpConnectionTarget>>,
    #[cfg(feature = "sftp")]
    sftp: Option<SftpHandle>,
    #[cfg(feature = "session")]
    session: Option<Arc<SessionOrchestrator>>,
}

impl AppServicesBuilder {
    pub fn storage(mut self, store: Arc<dyn ConnectionStore>) -> Self {
        self.storage = Some(store);
        self
    }

    pub fn secrets(mut self, store: Arc<dyn SecretStore>) -> Self {
        self.secrets = Some(store);
        self
    }

    #[cfg(feature = "tunnels")]
    pub fn tunnels(mut self, manager: Arc<TunnelManager>) -> Self {
        self.tunnels = Some(manager);
        self
    }

    #[cfg(feature = "mcp")]
    pub fn mcp(mut self, host: Arc<dyn McpServerHost>) -> Self {
        self.mcp = Some(host);
        self
    }

    #[cfg(feature = "ui")]
    pub fn ui(mut self, shell: Arc<std::sync::Mutex<ShellState>>) -> Self {
        self.ui = Some(shell);
        self
    }

    #[cfg(feature = "vnc")]
    pub fn vnc(mut self, handle: VncHandle) -> Self {
        self.vnc = Some(handle);
        self
    }

    #[cfg(feature = "http")]
    pub fn http(mut self, target: Arc<HttpConnectionTarget>) -> Self {
        self.http = Some(target);
        self
    }

    #[cfg(feature = "sftp")]
    pub fn sftp(mut self, handle: SftpHandle) -> Self {
        self.sftp = Some(handle);
        self
    }

    #[cfg(feature = "session")]
    pub fn session(mut self, orch: Arc<SessionOrchestrator>) -> Self {
        self.session = Some(orch);
        self
    }

    pub fn build(self) -> AppServices {
        AppServices {
            storage: self.storage.unwrap_or_else(stub_connection_store),
            secrets: self.secrets.unwrap_or_else(stub_secret_store),
            #[cfg(feature = "tunnels")]
            tunnels: self.tunnels,
            #[cfg(feature = "mcp")]
            mcp: self.mcp,
            #[cfg(feature = "ui")]
            ui: self.ui,
            #[cfg(feature = "vnc")]
            vnc: self.vnc,
            #[cfg(feature = "http")]
            http: self.http,
            #[cfg(feature = "sftp")]
            sftp: self.sftp,
            #[cfg(feature = "session")]
            session: self.session,
            #[cfg(feature = "domain")]
            domain_marker: DomainMarker,
            #[cfg(feature = "storage")]
            storage_crate: true,
            #[cfg(feature = "secrets")]
            secrets_crate: true,
        }
    }
}

/// Default skeleton wiring: stub storage/secrets traits + optional protocol handles.
///
/// When `storage` / `secrets` / `ui` / `vnc` / `http` features are on, the corresponding
/// crates are linked; concrete DB/CredMgr/GPUI handles are still constructed by the host.
pub fn build_default_services() -> AppServices {
    let builder = AppServices::builder();

    #[cfg(feature = "tunnels")]
    let tunnel_manager = {
        let manager = TunnelManager::new(wormhole_tunnels::default_stub_providers())
            .expect("stub providers register uniquely");
        Arc::new(manager)
    };

    #[cfg(feature = "tunnels")]
    let builder = builder.tunnels(Arc::clone(&tunnel_manager));

    #[cfg(feature = "mcp")]
    let builder = {
        use wormhole_mcp::HttpPlaceholderMcpHost;
        builder.mcp(Arc::new(HttpPlaceholderMcpHost::new()))
    };

    #[cfg(feature = "ui")]
    let builder = builder.ui(Arc::new(std::sync::Mutex::new(ShellState::new())));

    #[cfg(feature = "vnc")]
    let builder = builder.vnc(VncHandle);

    #[cfg(feature = "sftp")]
    let builder = builder.sftp(SftpHandle);

    #[cfg(feature = "session")]
    let builder = {
        use wormhole_session::{
            EmptyCredentialResolver, LiveSerialConnector, LiveSshConnector, ManagerTunnelBroker,
            SessionOrchestrator,
        };
        let tunnels: Option<Arc<dyn wormhole_session::TunnelBroker>> = {
            #[cfg(feature = "tunnels")]
            {
                Some(Arc::new(ManagerTunnelBroker::new(Arc::clone(&tunnel_manager))))
            }
            #[cfg(not(feature = "tunnels"))]
            {
                None
            }
        };
        let orch = SessionOrchestrator::new(
            Arc::new(LiveSerialConnector),
            Arc::new(LiveSshConnector),
            tunnels,
            Arc::new(EmptyCredentialResolver),
        );
        builder.session(Arc::new(orch))
    };

    // Touch optional crates so `cargo check -p wormhole-app` proves they unify.
    #[cfg(feature = "storage")]
    {
        let _ = std::any::type_name::<wormhole_storage::SqliteConnectionFactory>();
    }
    #[cfg(feature = "secrets")]
    {
        let _ = wormhole_secrets_win::MCP_TOKEN_CREDENTIAL_ID;
        // Bitwarden CLI session remains fail-closed until bw process wiring lands.
        let _ = wormhole_secrets_win::StubBitwardenSession;
        let _ = wormhole_secrets_win::BITWARDEN_CLI_SESSION_GAP;
    }
    #[cfg(feature = "domain")]
    {
        let _ = wormhole_domain::TunnelKind::WireGuard;
    }
    #[cfg(feature = "http")]
    {
        let _ = wormhole_http::HARDENING_BROWSER_ARGS;
    }
    #[cfg(feature = "vnc")]
    {
        let _ = wormhole_vnc::SECURITY_TYPE_VNC_AUTH;
    }
    #[cfg(feature = "sftp")]
    {
        let _ = wormhole_sftp::is_safe_remote_name("readme.txt");
    }
    #[cfg(feature = "ui")]
    {
        let _ = wormhole_ui::THEME.terminal_bg;
    }
    #[cfg(feature = "update")]
    {
        let _ = wormhole_update::update_cache_dir();
    }
    #[cfg(feature = "session")]
    {
        let _ = SessionHandleMarker.state_connected_name();
    }

    builder.build()
}
