//! AppServices composition smoke tests.

use std::sync::Arc;

use wormhole_app::{build_default_services, AppServices, StubConnectionStore, StubSecretStore};

#[test]
fn build_default_services_wires_optional_arcs() {
    let services = build_default_services();
    // Storage/secrets placeholders are always present (local stubs until real crates wire in).
    let _ = Arc::clone(&services.storage);
    let _ = Arc::clone(&services.secrets);

    #[cfg(feature = "tunnels")]
    {
        assert!(services.tunnels.is_some());
        let mgr = services.tunnels.as_ref().unwrap();
        // Arc lifetime: cloning keeps the manager alive independently of AppServices drop order.
        let cloned = Arc::clone(mgr);
        assert!(Arc::strong_count(mgr) >= 2);
        drop(cloned);
    }

    #[cfg(feature = "mcp")]
    {
        assert!(services.mcp.is_some());
        let host = services.mcp.as_ref().unwrap();
        assert_eq!(host.port(), wormhole_mcp::DEFAULT_MCP_PORT);
        assert!(host.endpoint_url().starts_with("http://127.0.0.1:"));
    }

    #[cfg(feature = "domain")]
    {
        let _ = services.domain_marker;
    }

    #[cfg(feature = "ui")]
    {
        let shell = services.ui.as_ref().expect("default wires ui");
        let guard = shell.lock().expect("shell mutex");
        assert_eq!(guard.sidebar, wormhole_ui::SidebarRegion::Connections);
        assert_eq!(guard.workspace.pane_count(), 1);
    }

    #[cfg(feature = "vnc")]
    {
        let handle = services.vnc.expect("default wires vnc");
        assert_eq!(handle.security_none_type(), wormhole_vnc::SECURITY_TYPE_NONE);
    }

    #[cfg(feature = "http")]
    {
        // Default leaves http unset; host may inject a target via AppServicesBuilder::http.
        assert!(services.http.is_none());
        let target = wormhole_http::build_direct_target(
            wormhole_http::HttpScheme::Https,
            "fw.local",
            443,
            false,
        )
        .expect("sample target");
        let with_http = AppServices::builder()
            .http(Arc::new(target))
            .build();
        assert!(with_http.http.is_some());
        assert_eq!(
            with_http.http.as_ref().unwrap().navigate_uri,
            "https://fw.local:443/"
        );
    }

    #[cfg(feature = "sftp")]
    {
        let handle = services.sftp.expect("default wires sftp");
        assert!(handle.gate_name().contains("SerializedSftpSession"));
    }

    #[cfg(feature = "session")]
    {
        let orch = services.session.as_ref().expect("default wires session");
        let _ = Arc::clone(orch);
        assert_eq!(
            wormhole_app::SessionHandleMarker.state_connected_name(),
            "Connected"
        );
    }
}

#[test]
fn builder_allows_omitting_optional_deps() {
    let services = AppServices::builder()
        .storage(Arc::new(StubConnectionStore))
        .secrets(Arc::new(StubSecretStore))
        .build();

    #[cfg(feature = "tunnels")]
    assert!(services.tunnels.is_none());

    #[cfg(feature = "mcp")]
    assert!(services.mcp.is_none());

    #[cfg(feature = "ui")]
    assert!(services.ui.is_none());

    #[cfg(feature = "vnc")]
    assert!(services.vnc.is_none());

    #[cfg(feature = "http")]
    assert!(services.http.is_none());

    #[cfg(feature = "sftp")]
    assert!(services.sftp.is_none());

    #[cfg(feature = "session")]
    assert!(services.session.is_none());

    // Keep the bag alive under `--no-default-features` (no optional asserts above).
    let _ = Arc::clone(&services.storage);
    let _ = Arc::clone(&services.secrets);
}

#[tokio::test]
async fn stub_stores_respond() {
    let services = build_default_services();
    services.storage.ping().await.unwrap();
    let secret = services
        .secrets
        .read_tunnel_secret(uuid::Uuid::nil())
        .await
        .unwrap();
    assert!(secret.is_none());
}
