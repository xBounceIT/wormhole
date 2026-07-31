//! Sidecar control-plane tests — no Docker; uses the package `fake-tunnel-sidecar` binary.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use uuid::Uuid;
use wormhole_tunnels::{
    parse_ready_or_socks_line, validate_sidecar_dir, AzureVpnProvider, CiscoSecureClientProvider,
    FortinetProvider, OpenVpnProvider, SidecarProcess, StormshieldProvider, TunnelConfigSnapshot,
    TunnelError, TunnelKind, TunnelManager, TunnelProvider, TunnelState, WatchguardProvider,
    WireGuardProvider, MAX_HANDSHAKE_LINE_BYTES,
};

#[test]
fn parse_ready_and_socks_lines() {
    assert_eq!(parse_ready_or_socks_line("READY 18080").unwrap(), 18080);
    assert_eq!(parse_ready_or_socks_line("SOCKS 9050").unwrap(), 9050);
    assert!(parse_ready_or_socks_line("READY 0").is_err());
    assert!(parse_ready_or_socks_line("NOPE 1").is_err());
    assert!(parse_ready_or_socks_line("READY 18080 evil").is_err());
    assert!(parse_ready_or_socks_line(&"A".repeat(MAX_HANDSHAKE_LINE_BYTES + 1)).is_err());
}

#[test]
fn sidecar_dir_rejects_path_traversal() {
    assert!(validate_sidecar_dir("C:\\good\\sidecars").is_some());
    assert!(validate_sidecar_dir("..\\evil").is_none());
    assert!(validate_sidecar_dir("C:\\a\\..\\b").is_none());
    assert!(validate_sidecar_dir("foo\0bar").is_none());
}

#[tokio::test]
async fn handshake_with_fake_sidecar_binary() {
    let bin = fake_sidecar_exe();
    let mut proc = SidecarProcess::spawn(&bin, &[]).await.expect("spawn fake");
    let port = proc
        .handshake(br#"{"mock":true}"#, Duration::from_secs(5))
        .await
        .expect("handshake");
    assert_eq!(port, 18_765);
    assert_eq!(proc.socks_port(), Some(18_765));
    proc.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn wireguard_provider_talks_to_fake_sidecar() {
    let provider = WireGuardProvider::with_binary_path(fake_sidecar_exe())
        .with_ready_timeout(Duration::from_secs(5));
    let config = TunnelConfigSnapshot::new(Uuid::new_v4(), TunnelKind::WireGuard, "fake");
    let marker = br#"{"interface_private_key":"SUPER_SECRET_KEY_XYZ","endpoint":"10.0.0.1"}"#;
    let instance = provider
        .establish(&config, marker)
        .await
        .expect("establish via fake sidecar");
    assert_eq!(
        instance.socks5_endpoint().map(|e| e.addr.port()),
        Some(18_765)
    );
    assert_eq!(instance.state(), TunnelState::Up);
    instance.close().await;
    assert_eq!(instance.state(), TunnelState::Closed);
}

#[tokio::test]
async fn openvpn_provider_talks_to_fake_sidecar() {
    let provider = OpenVpnProvider::with_binary_path(fake_sidecar_exe())
        .with_ready_timeout(Duration::from_secs(5));
    let config = TunnelConfigSnapshot::new(Uuid::new_v4(), TunnelKind::OpenVpn, "fake-ovpn");
    let instance = provider
        .establish(&config, br#"{"profile_ovpn":"client","mock":true}"#)
        .await
        .expect("openvpn establish via fake sidecar");
    assert_eq!(
        instance.socks5_endpoint().map(|e| e.addr.port()),
        Some(18_765)
    );
    assert_eq!(instance.state(), TunnelState::Up);
    instance.close().await;
}

#[tokio::test]
async fn fortinet_provider_talks_to_fake_sidecar() {
    let provider = FortinetProvider::with_binary_path(fake_sidecar_exe())
        .with_ready_timeout(Duration::from_secs(5));
    let config = TunnelConfigSnapshot::new(Uuid::new_v4(), TunnelKind::Fortinet, "fake-forti");
    let instance = provider
        .establish(
            &config,
            br#"{"host":"vpn.example","username":"u","password":"p","mock":true}"#,
        )
        .await
        .expect("fortinet establish via fake sidecar");
    assert_eq!(
        instance.socks5_endpoint().map(|e| e.addr.port()),
        Some(18_765)
    );
    assert_eq!(instance.state(), TunnelState::Up);
    instance.close().await;
}

#[tokio::test]
async fn watchguard_provider_talks_to_fake_ovpn_sidecar() {
    let provider = WatchguardProvider::with_binary_path(fake_sidecar_exe())
        .with_ready_timeout(Duration::from_secs(5));
    let config = TunnelConfigSnapshot::new(Uuid::new_v4(), TunnelKind::Watchguard, "fake-wg");
    let instance = provider
        .establish(&config, br#"{"profile_ovpn":"client","mock":true}"#)
        .await
        .expect("watchguard establish via fake sidecar");
    assert_eq!(
        instance.socks5_endpoint().map(|e| e.addr.port()),
        Some(18_765)
    );
    instance.close().await;
}

#[tokio::test]
async fn stormshield_and_azure_share_ovpn_sidecar_path() {
    for (kind, provider) in [
        (
            TunnelKind::Stormshield,
            Arc::new(StormshieldProvider::with_binary_path(fake_sidecar_exe()))
                as Arc<dyn TunnelProvider>,
        ),
        (
            TunnelKind::AzureVpn,
            Arc::new(AzureVpnProvider::with_binary_path(fake_sidecar_exe()))
                as Arc<dyn TunnelProvider>,
        ),
    ] {
        let config = TunnelConfigSnapshot::new(Uuid::new_v4(), kind, "ovpn-backed");
        let instance = provider
            .establish(&config, br#"{"profile_ovpn":"client","mock":true}"#)
            .await
            .expect("ovpn-backed establish");
        assert_eq!(
            instance.socks5_endpoint().map(|e| e.addr.port()),
            Some(18_765)
        );
        instance.close().await;
    }
}

#[tokio::test]
async fn cisco_provider_talks_to_fake_sidecar() {
    let provider = CiscoSecureClientProvider::with_binary_path(fake_sidecar_exe())
        .with_ready_timeout(Duration::from_secs(5));
    let config =
        TunnelConfigSnapshot::new(Uuid::new_v4(), TunnelKind::CiscoSecureClient, "fake-cisco");
    let instance = provider
        .establish(
            &config,
            br#"{"host":"vpn.example","username":"u","password":"p","mock":true}"#,
        )
        .await
        .expect("cisco establish via fake sidecar");
    assert_eq!(
        instance.socks5_endpoint().map(|e| e.addr.port()),
        Some(18_765)
    );
    assert_eq!(instance.state(), TunnelState::Up);
    instance.close().await;
}

#[tokio::test]
async fn ovpn_backed_wrong_shape_does_not_pretend_up_with_fake_sidecar() {
    // Fake READY ignores stdin — shape gate must still fail closed.
    for (kind, provider) in [
        (
            TunnelKind::Watchguard,
            Arc::new(
                WatchguardProvider::with_binary_path(fake_sidecar_exe())
                    .with_ready_timeout(Duration::from_secs(2)),
            ) as Arc<dyn TunnelProvider>,
        ),
        (
            TunnelKind::Stormshield,
            Arc::new(
                StormshieldProvider::with_binary_path(fake_sidecar_exe())
                    .with_ready_timeout(Duration::from_secs(2)),
            ) as Arc<dyn TunnelProvider>,
        ),
        (
            TunnelKind::AzureVpn,
            Arc::new(
                AzureVpnProvider::with_binary_path(fake_sidecar_exe())
                    .with_ready_timeout(Duration::from_secs(2)),
            ) as Arc<dyn TunnelProvider>,
        ),
    ] {
        let config = TunnelConfigSnapshot::new(Uuid::new_v4(), kind, "bad-shape");
        let err = match provider
            .establish(
                &config,
                br#"{"Server":"vpn.example","Password":"SHAPE_SECRET_MARKER","mock":true}"#,
            )
            .await
        {
            Ok(_) => panic!("{kind:?} must not Up on editor blob"),
            Err(e) => e,
        };
        assert!(matches!(err, TunnelError::Establish(_)), "{kind:?}: {err:?}");
        let rendered = format!("{err}");
        assert!(
            !rendered.contains("SHAPE_SECRET_MARKER"),
            "{kind:?}: {rendered}"
        );
        assert_eq!(provider.kind(), kind);
    }
}

#[tokio::test]
async fn cisco_wrong_shape_does_not_pretend_up_with_fake_sidecar() {
    let provider = CiscoSecureClientProvider::with_binary_path(fake_sidecar_exe())
        .with_ready_timeout(Duration::from_secs(2));
    let config =
        TunnelConfigSnapshot::new(Uuid::new_v4(), TunnelKind::CiscoSecureClient, "bad-shape");
    let err = match provider
        .establish(
            &config,
            br#"{"Host":"vpn.example","Password":"CISCO_SHAPE_SECRET"}"#,
        )
        .await
    {
        Ok(_) => panic!("must not Up on PascalCase editor blob"),
        Err(e) => e,
    };
    assert!(matches!(err, TunnelError::Establish(_)), "{err:?}");
    assert!(!format!("{err}").contains("CISCO_SHAPE_SECRET"));
}

#[tokio::test]
async fn cisco_missing_binary_through_manager_is_not_connected() {
    let provider: Arc<dyn TunnelProvider> = Arc::new(CiscoSecureClientProvider::with_binary_path(
        std::env::temp_dir().join("wormhole-ciscoproxy-missing-integration.exe"),
    ));
    let manager = TunnelManager::new([provider]).unwrap();
    let config = TunnelConfigSnapshot::new(Uuid::new_v4(), TunnelKind::CiscoSecureClient, "missing");
    let err = match manager
        .establish(config, br#"{"host":"vpn.example"}"#.to_vec())
        .await
    {
        Ok(_) => panic!("expected BinaryNotFound"),
        Err(e) => e,
    };
    assert!(
        matches!(err, TunnelError::BinaryNotFound { .. }),
        "expected BinaryNotFound, got {err:?}"
    );
}

#[tokio::test]
async fn openvpn_missing_binary_through_manager_is_not_connected() {
    let provider: Arc<dyn TunnelProvider> = Arc::new(OpenVpnProvider::with_binary_path(
        std::env::temp_dir().join("wormhole-ovpnproxy-missing-integration.exe"),
    ));
    let manager = TunnelManager::new([provider]).unwrap();
    let config = TunnelConfigSnapshot::new(Uuid::new_v4(), TunnelKind::OpenVpn, "missing");
    let err = match manager
        .establish(config, br#"{"profile_ovpn":"x"}"#.to_vec())
        .await
    {
        Ok(_) => panic!("expected BinaryNotFound"),
        Err(e) => e,
    };
    assert!(
        matches!(err, TunnelError::BinaryNotFound { .. }),
        "expected BinaryNotFound, got {err:?}"
    );
}

#[tokio::test]
async fn missing_binary_through_manager_is_not_connected() {
    let provider: Arc<dyn TunnelProvider> = Arc::new(WireGuardProvider::with_binary_path(
        std::env::temp_dir().join("wormhole-wgproxy-missing-integration.exe"),
    ));
    let manager = TunnelManager::new([provider]).unwrap();
    let config = TunnelConfigSnapshot::new(Uuid::new_v4(), TunnelKind::WireGuard, "missing");
    let err = match manager
        .establish(config, br#"{"interface_private_key":"x"}"#.to_vec())
        .await
    {
        Ok(_) => panic!("expected BinaryNotFound"),
        Err(e) => e,
    };
    assert!(
        matches!(err, TunnelError::BinaryNotFound { .. }),
        "expected BinaryNotFound, got {err:?}"
    );
}

#[tokio::test]
async fn oversized_stdout_is_rejected_and_process_dies() {
    let bin = fake_sidecar_exe();
    let mut proc = SidecarProcess::spawn(&bin, &["--oversized"])
        .await
        .expect("spawn");
    let pid = proc.pid().expect("pid");
    let err = proc
        .handshake(br#"{"k":"v"}"#, Duration::from_secs(3))
        .await
        .expect_err("oversized must fail");
    assert!(
        matches!(err, TunnelError::Establish(_)),
        "expected Establish, got {err:?}"
    );
    let rendered = format!("{err}");
    assert!(
        rendered.contains("exceeded") || rendered.contains("handshake"),
        "{rendered}"
    );
    // Must not leave a zombie: shutdown/kill on failure path.
    proc.shutdown().await.expect("shutdown");
    wait_until_process_gone(pid, Duration::from_secs(3)).await;
}

#[tokio::test]
async fn bad_ready_line_is_rejected_and_process_dies() {
    let bin = fake_sidecar_exe();
    let mut proc = SidecarProcess::spawn(&bin, &["--bad-ready"])
        .await
        .expect("spawn");
    let pid = proc.pid().expect("pid");
    let err = proc
        .handshake(br#"{"k":"v"}"#, Duration::from_secs(3))
        .await
        .expect_err("bad ready must fail");
    assert!(matches!(err, TunnelError::Establish(_)), "{err:?}");
    proc.shutdown().await.expect("shutdown");
    wait_until_process_gone(pid, Duration::from_secs(3)).await;
}

#[tokio::test]
async fn hang_handshake_times_out_and_kill_reaps_child() {
    let provider = WireGuardProvider::with_binary_path(fake_sidecar_exe())
        .with_extra_args(["--hang"])
        .with_ready_timeout(Duration::from_millis(400));
    let config = TunnelConfigSnapshot::new(Uuid::new_v4(), TunnelKind::WireGuard, "hang");
    let err = match provider
        .establish(&config, br#"{"interface_private_key":"hang-secret-MARKER"}"#)
        .await
    {
        Ok(_) => panic!("hang must not become Up"),
        Err(e) => e,
    };
    assert!(matches!(err, TunnelError::Establish(_)), "{err:?}");
    let rendered = format!("{err} {err:?}");
    assert!(
        !rendered.contains("hang-secret-MARKER"),
        "secret must not appear in error: {rendered}"
    );
    assert_eq!(provider.establish_count(), 1);
}

#[tokio::test]
async fn openvpn_hang_handshake_times_out_not_up() {
    let provider = OpenVpnProvider::with_binary_path(fake_sidecar_exe())
        .with_extra_args(["--hang"])
        .with_ready_timeout(Duration::from_millis(400));
    let config = TunnelConfigSnapshot::new(Uuid::new_v4(), TunnelKind::OpenVpn, "hang-ovpn");
    let err = match provider
        .establish(
            &config,
            br#"{"profile_ovpn":"client","password":"ovpn-hang-SECRET-MARKER"}"#,
        )
        .await
    {
        Ok(_) => panic!("hang must not become Up"),
        Err(e) => e,
    };
    assert!(matches!(err, TunnelError::Establish(_)), "{err:?}");
    let rendered = format!("{err} {err:?}");
    assert!(
        !rendered.contains("ovpn-hang-SECRET-MARKER"),
        "secret must not appear in error: {rendered}"
    );
    assert_eq!(provider.establish_count(), 1);
}

#[tokio::test]
async fn fortinet_hang_handshake_times_out_not_up() {
    let provider = FortinetProvider::with_binary_path(fake_sidecar_exe())
        .with_extra_args(["--hang"])
        .with_ready_timeout(Duration::from_millis(400));
    let config = TunnelConfigSnapshot::new(Uuid::new_v4(), TunnelKind::Fortinet, "hang-forti");
    let err = match provider
        .establish(
            &config,
            br#"{"host":"vpn.example","username":"u","password":"forti-hang-SECRET-MARKER"}"#,
        )
        .await
    {
        Ok(_) => panic!("hang must not become Up"),
        Err(e) => e,
    };
    assert!(matches!(err, TunnelError::Establish(_)), "{err:?}");
    let rendered = format!("{err} {err:?}");
    assert!(
        !rendered.contains("forti-hang-SECRET-MARKER"),
        "secret must not appear in error: {rendered}"
    );
    assert_eq!(provider.establish_count(), 1);
}

#[tokio::test]
async fn fortinet_missing_binary_through_manager_is_not_connected() {
    let provider: Arc<dyn TunnelProvider> = Arc::new(FortinetProvider::with_binary_path(
        std::env::temp_dir().join("wormhole-fortiproxy-missing-integration.exe"),
    ));
    let manager = TunnelManager::new([provider]).unwrap();
    let config = TunnelConfigSnapshot::new(Uuid::new_v4(), TunnelKind::Fortinet, "missing");
    let err = match manager
        .establish(
            config,
            br#"{"host":"vpn.example","username":"u","password":"p"}"#.to_vec(),
        )
        .await
    {
        Ok(_) => panic!("expected BinaryNotFound"),
        Err(e) => e,
    };
    assert!(
        matches!(err, TunnelError::BinaryNotFound { .. }),
        "expected BinaryNotFound, got {err:?}"
    );
}

#[tokio::test]
async fn openvpn_manager_coalesce_uses_one_sidecar_spawn() {
    let concrete = Arc::new(
        OpenVpnProvider::with_binary_path(fake_sidecar_exe())
            .with_extra_args(["--delay-ready", "120"])
            .with_ready_timeout(Duration::from_secs(5)),
    );
    let provider: Arc<dyn TunnelProvider> = concrete.clone();
    let manager = TunnelManager::new([provider]).unwrap();
    let config = TunnelConfigSnapshot::new(Uuid::new_v4(), TunnelKind::OpenVpn, "coalesce-ovpn");
    let secret = br#"{"profile_ovpn":"client","password":"coalesce-SECRET-do-not-log"}"#.to_vec();

    let (a, b) = tokio::join!(
        manager.establish(config.clone(), secret.clone()),
        manager.establish(config.clone(), secret),
    );
    let lease_a = a.expect("lease a");
    let lease_b = b.expect("lease b");

    assert_eq!(manager.establish_start_count(), 1);
    assert_eq!(concrete.establish_count(), 1);
    assert!(std::sync::Arc::ptr_eq(lease_a.instance(), lease_b.instance()));
    assert_eq!(
        lease_a.instance().socks5_endpoint().map(|e| e.addr.port()),
        Some(18_765)
    );

    lease_a.release();
    lease_b.release();
    assert_eq!(manager.pool_ref_count(config.id), 0);
}

#[tokio::test]
async fn stderr_flood_does_not_deadlock_handshake() {
    let bin = fake_sidecar_exe();
    let mut proc = SidecarProcess::spawn(&bin, &["--stderr-flood"])
        .await
        .expect("spawn");
    let port = proc
        .handshake(br#"{"mock":true}"#, Duration::from_secs(5))
        .await
        .expect("handshake despite stderr flood");
    assert_eq!(port, 18_765);
    proc.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn wireguard_manager_coalesce_uses_one_sidecar_spawn() {
    let concrete = Arc::new(
        WireGuardProvider::with_binary_path(fake_sidecar_exe())
            .with_extra_args(["--delay-ready", "120"])
            .with_ready_timeout(Duration::from_secs(5)),
    );
    let provider: Arc<dyn TunnelProvider> = concrete.clone();
    let manager = TunnelManager::new([provider]).unwrap();
    let config = TunnelConfigSnapshot::new(Uuid::new_v4(), TunnelKind::WireGuard, "coalesce");
    let secret = br#"{"interface_private_key":"coalesce-SECRET-do-not-log"}"#.to_vec();

    let (a, b) = tokio::join!(
        manager.establish(config.clone(), secret.clone()),
        manager.establish(config.clone(), secret),
    );
    let lease_a = a.expect("lease a");
    let lease_b = b.expect("lease b");

    assert_eq!(manager.establish_start_count(), 1);
    assert_eq!(concrete.establish_count(), 1);
    assert!(std::sync::Arc::ptr_eq(lease_a.instance(), lease_b.instance()));
    assert_eq!(
        lease_a.instance().socks5_endpoint().map(|e| e.addr.port()),
        Some(18_765)
    );

    lease_a.release();
    lease_b.release();
    assert_eq!(manager.pool_ref_count(config.id), 0);
}

#[tokio::test]
async fn wireguard_failure_does_not_leave_pool_or_pretend_up() {
    let provider: Arc<dyn TunnelProvider> = Arc::new(
        WireGuardProvider::with_binary_path(fake_sidecar_exe())
            .with_extra_args(["--bad-ready"])
            .with_ready_timeout(Duration::from_secs(3)),
    );
    let manager = TunnelManager::new([provider]).unwrap();
    let config = TunnelConfigSnapshot::new(Uuid::new_v4(), TunnelKind::WireGuard, "bad");
    let err = match manager
        .establish(config.clone(), br#"{"interface_private_key":"x"}"#.to_vec())
        .await
    {
        Ok(_) => panic!("bad ready must not establish"),
        Err(e) => e,
    };
    assert!(matches!(err, TunnelError::Establish(_)), "{err:?}");
    assert_eq!(manager.pool_ref_count(config.id), 0);
}

fn fake_sidecar_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_fake-tunnel-sidecar"))
}

async fn wait_until_process_gone(pid: u32, budget: Duration) {
    let start = std::time::Instant::now();
    while start.elapsed() < budget {
        if !process_exists(pid) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("process {pid} still alive after {budget:?}");
}

#[cfg(windows)]
fn process_exists(pid: u32) -> bool {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    // `tasklist` /FI returns exit 0 even when empty on some hosts; parse output instead.
    let output = std::process::Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/NH"])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    match output {
        Ok(o) => {
            let text = String::from_utf8_lossy(&o.stdout);
            text.contains(&pid.to_string())
        }
        Err(_) => false,
    }
}

#[cfg(not(windows))]
fn process_exists(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}
