//! Lease ref-count and establish-coalesce regression tests.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use uuid::Uuid;
use wormhole_tunnels::{
    FakeTunnelProvider, StubTunnelInstance, TunnelConfigSnapshot, TunnelError, TunnelInstance,
    TunnelKind, TunnelManager, TunnelProvider, TunnelState, WireGuardProvider,
};

fn wg_config(name: &str) -> TunnelConfigSnapshot {
    TunnelConfigSnapshot::new(Uuid::new_v4(), TunnelKind::WireGuard, name)
}

async fn wait_until(mut pred: impl FnMut() -> bool, label: &str) {
    for _ in 0..100 {
        if pred() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("timed out waiting for {label}");
}

#[tokio::test]
async fn coalesce_concurrent_establish_calls_one_provider() {
    // Parity with C# ConcurrentEstablishes_CoalesceIntoOneProviderCall: same TunnelConfigId
    // joiners share one provider establish → one OTP / one VPN login.
    let provider = Arc::new(FakeTunnelProvider::with_delay(
        TunnelKind::WireGuard,
        Duration::from_millis(80),
    ));
    let as_trait: Arc<dyn TunnelProvider> = provider.clone();
    let manager = TunnelManager::new([as_trait]).unwrap();
    let config = wg_config("lab");

    let (lease_a, lease_b) = tokio::join!(
        manager.establish(config.clone(), vec![1, 2, 3]),
        manager.establish(config.clone(), vec![1, 2, 3]),
    );
    let lease_a = lease_a.expect("lease a");
    let lease_b = lease_b.expect("lease b");

    assert_eq!(manager.establish_start_count(), 1);
    assert_eq!(
        provider.establish_count(),
        1,
        "coalesce must invoke FakeTunnelProvider::establish once (one OTP)"
    );
    assert_eq!(manager.pool_ref_count(config.id), 2);
    assert!(Arc::ptr_eq(lease_a.instance(), lease_b.instance()));

    lease_a.release();
    assert_eq!(manager.pool_ref_count(config.id), 1);
    lease_b.release();
    assert_eq!(manager.pool_ref_count(config.id), 0);
}

#[tokio::test]
async fn last_lease_release_evicts_pool_entry() {
    let provider: Arc<dyn TunnelProvider> = Arc::new(FakeTunnelProvider::new(TunnelKind::WireGuard));
    let manager = TunnelManager::new([provider]).unwrap();
    let config = wg_config("solo");

    let lease1 = manager
        .establish(config.clone(), b"secret".to_vec())
        .await
        .unwrap();
    let lease2 = manager
        .establish(config.clone(), b"secret".to_vec())
        .await
        .unwrap();

    assert_eq!(manager.establish_start_count(), 1);
    assert_eq!(manager.pool_ref_count(config.id), 2);

    drop(lease1);
    assert_eq!(manager.pool_ref_count(config.id), 1);

    drop(lease2);
    assert_eq!(manager.pool_ref_count(config.id), 0);

    let lease3 = manager
        .establish(config.clone(), b"secret".to_vec())
        .await
        .unwrap();
    assert_eq!(manager.establish_start_count(), 2);
    assert_eq!(manager.pool_ref_count(config.id), 1);
    drop(lease3);
}

#[tokio::test]
async fn last_lease_closes_underlying_instance() {
    let concrete = Arc::new(FakeTunnelProvider::new(TunnelKind::WireGuard));
    let forced = StubTunnelInstance::up_with_socks(19_001);
    concrete.force_next_instance(Arc::clone(&forced));
    let provider: Arc<dyn TunnelProvider> = concrete;
    let manager = TunnelManager::new([provider]).unwrap();
    let config = wg_config("close");

    let lease = manager.establish(config.clone(), vec![]).await.unwrap();
    assert_eq!(forced.close_count(), 0);
    lease.release();
    wait_until(|| forced.close_count() >= 1, "instance close").await;
    assert_eq!(forced.close_count(), 1);
    assert_eq!(manager.pool_ref_count(config.id), 0);
}

#[tokio::test]
async fn reused_live_tunnel_does_not_reestablish() {
    let concrete = Arc::new(FakeTunnelProvider::new(TunnelKind::WireGuard));
    let provider: Arc<dyn TunnelProvider> = concrete.clone();
    let manager = TunnelManager::new([provider]).unwrap();
    let config = wg_config("reuse");

    let first = manager.establish(config.clone(), vec![]).await.unwrap();
    let second = manager.establish(config.clone(), vec![]).await.unwrap();

    assert_eq!(concrete.establish_count(), 1);
    assert!(first.instance().socks5_endpoint().is_some());
    drop(first);
    drop(second);
}

#[tokio::test]
async fn updated_at_bump_invalidates_pooled_tunnel() {
    // Parity with C# EditedConfig_GetsFreshTunnel_WhileOldLeasesDrain: editor save bumps
    // UpdatedAt → pool must not hand out the pre-edit instance; old leases still drain it.
    let concrete = Arc::new(FakeTunnelProvider::new(TunnelKind::WireGuard));
    let old_inst = StubTunnelInstance::up_with_socks(19_020);
    let new_inst = StubTunnelInstance::up_with_socks(19_021);
    concrete.force_next_instance(Arc::clone(&old_inst));
    let provider: Arc<dyn TunnelProvider> = concrete.clone();
    let manager = TunnelManager::new([provider]).unwrap();
    let mut config = wg_config("edited");

    let first = manager.establish(config.clone(), vec![]).await.unwrap();
    assert_eq!(concrete.establish_count(), 1);
    let old_as_trait: Arc<dyn TunnelInstance> = Arc::clone(&old_inst) as _;
    assert!(Arc::ptr_eq(first.instance(), &old_as_trait));

    // Saving the tunnel editor bumps the row's UpdatedAt (even payload-only edits).
    config.updated_at = SystemTime::UNIX_EPOCH + Duration::from_secs(42);
    concrete.force_next_instance(Arc::clone(&new_inst));
    let second = manager.establish(config.clone(), vec![]).await.unwrap();
    assert_eq!(concrete.establish_count(), 2);
    assert!(!Arc::ptr_eq(first.instance(), second.instance()));
    let new_as_trait: Arc<dyn TunnelInstance> = Arc::clone(&new_inst) as _;
    assert!(Arc::ptr_eq(second.instance(), &new_as_trait));

    // Pool tracks the fresh entry only; outstanding old lease still owns the prior instance.
    assert_eq!(manager.pool_ref_count(config.id), 1);

    drop(first);
    wait_until(|| old_inst.close_count() >= 1, "old instance close").await;
    assert_eq!(old_inst.close_count(), 1);
    assert_eq!(new_inst.close_count(), 0);

    drop(second);
    wait_until(|| new_inst.close_count() >= 1, "new instance close").await;
    assert_eq!(new_inst.close_count(), 1);
    assert_eq!(manager.pool_ref_count(config.id), 0);
}

#[tokio::test]
async fn failed_instance_gets_fresh_establish() {
    let concrete = Arc::new(FakeTunnelProvider::new(TunnelKind::WireGuard));
    let first_inst = StubTunnelInstance::up_with_socks(19_010);
    concrete.force_next_instance(Arc::clone(&first_inst));
    let provider: Arc<dyn TunnelProvider> = concrete.clone();
    let manager = TunnelManager::new([provider]).unwrap();
    let config = wg_config("dead");

    let lease = manager.establish(config.clone(), vec![]).await.unwrap();
    first_inst.mark_failed();
    // Keep the dead lease outstanding (C#: outstanding leases drain the old instance).
    let fresh = manager.establish(config.clone(), vec![]).await.unwrap();
    assert_eq!(concrete.establish_count(), 2);
    assert!(!Arc::ptr_eq(lease.instance(), fresh.instance()));
    drop(lease);
    drop(fresh);
}

#[tokio::test]
async fn closed_instance_gets_fresh_establish() {
    let concrete = Arc::new(FakeTunnelProvider::new(TunnelKind::WireGuard));
    let first_inst = StubTunnelInstance::up_with_socks(19_011);
    concrete.force_next_instance(Arc::clone(&first_inst));
    let provider: Arc<dyn TunnelProvider> = concrete.clone();
    let manager = TunnelManager::new([provider]).unwrap();
    let config = wg_config("closed");

    let lease = manager.establish(config.clone(), vec![]).await.unwrap();
    first_inst.mark_closed();
    let fresh = manager.establish(config.clone(), vec![]).await.unwrap();
    assert_eq!(concrete.establish_count(), 2);
    drop(lease);
    drop(fresh);
}

#[tokio::test]
async fn last_release_racing_establish_never_hands_out_closed_instance() {
    // Attack: double establish race against last-lease dispose. Pre-fix, release dropped the
    // entry lock before pool eviction so a joiner could resurrect a zero-ref entry and receive
    // the instance that release was about to close (C# holds one gate for RefCount + Evict).
    let concrete = Arc::new(FakeTunnelProvider::new(TunnelKind::WireGuard));
    let provider: Arc<dyn TunnelProvider> = concrete.clone();
    let manager = Arc::new(TunnelManager::new([provider]).unwrap());
    let config = wg_config("resurrect");

    for _ in 0..80 {
        let lease = manager
            .establish(config.clone(), vec![])
            .await
            .expect("seed lease");
        let old = Arc::clone(lease.instance());

        let manager2 = Arc::clone(&manager);
        let config2 = config.clone();
        let racing = tokio::spawn(async move { manager2.establish(config2, vec![]).await });

        tokio::task::yield_now().await;
        drop(lease);

        let fresh = racing
            .await
            .expect("join")
            .expect("establish after last release");
        assert_eq!(
            fresh.instance().state(),
            TunnelState::Up,
            "lease must not observe a closing/closed resurrected instance"
        );
        if Arc::ptr_eq(fresh.instance(), &old) {
            // Reused before the last release completed — still live.
            assert_eq!(old.state(), TunnelState::Up);
        }
        drop(fresh);
        wait_until(
            || manager.pool_ref_count(config.id) == 0,
            "pool drain between race rounds",
        )
        .await;
    }
}

#[tokio::test]
async fn one_of_two_waiters_cancel_other_still_gets_lease() {
    // Dispose-order / partial cancel: aborting one coalesce waiter must not cancel the shared
    // establish or leak the remaining waiter's ref.
    let concrete = Arc::new(FakeTunnelProvider::with_delay(
        TunnelKind::WireGuard,
        Duration::from_millis(120),
    ));
    let provider: Arc<dyn TunnelProvider> = concrete.clone();
    let manager = Arc::new(TunnelManager::new([provider]).unwrap());
    let config = wg_config("partial-cancel");

    let manager_a = Arc::clone(&manager);
    let config_a = config.clone();
    let waiter_a = tokio::spawn(async move { manager_a.establish(config_a, vec![7]).await });

    tokio::time::sleep(Duration::from_millis(20)).await;

    let manager_b = Arc::clone(&manager);
    let config_b = config.clone();
    let waiter_b = tokio::spawn(async move { manager_b.establish(config_b, vec![7]).await });

    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(manager.pool_ref_count(config.id), 2);

    waiter_a.abort();
    let join_err = match waiter_a.await {
        Ok(_) => panic!("expected aborted waiter"),
        Err(e) => e,
    };
    assert!(join_err.is_cancelled());

    let lease = waiter_b.await.expect("join b").expect(" surviving waiter lease");
    assert_eq!(concrete.establish_count(), 1, "shared establish must still complete once");
    assert_eq!(manager.pool_ref_count(config.id), 1);
    assert_eq!(lease.instance().state(), TunnelState::Up);
    lease.release();
    assert_eq!(manager.pool_ref_count(config.id), 0);
}

#[tokio::test]
async fn updated_at_bump_during_in_flight_establish_starts_fresh() {
    // UpdatedAt bump while the first establish is still in the provider — new caller must not
    // join the pre-edit future; outstanding waiter still drains the old instance.
    let concrete = Arc::new(FakeTunnelProvider::with_delay(
        TunnelKind::WireGuard,
        Duration::from_millis(100),
    ));
    let provider: Arc<dyn TunnelProvider> = concrete.clone();
    let manager = Arc::new(TunnelManager::new([provider]).unwrap());
    let mut config = wg_config("edit-inflight");

    let manager_a = Arc::clone(&manager);
    let config_a = config.clone();
    let first = tokio::spawn(async move { manager_a.establish(config_a, vec![]).await });

    tokio::time::sleep(Duration::from_millis(25)).await;
    assert_eq!(manager.pool_ref_count(config.id), 1);
    assert_eq!(concrete.establish_count(), 1);

    config.updated_at = SystemTime::UNIX_EPOCH + Duration::from_secs(99);
    let second = manager
        .establish(config.clone(), vec![])
        .await
        .expect("post-edit establish");

    let first = first.await.expect("join").expect("pre-edit waiter");
    assert_eq!(concrete.establish_count(), 2);
    assert!(!Arc::ptr_eq(first.instance(), second.instance()));
    assert_eq!(first.instance().state(), TunnelState::Up);
    assert_eq!(second.instance().state(), TunnelState::Up);
    // Pool tracks only the post-edit entry.
    assert_eq!(manager.pool_ref_count(config.id), 1);

    drop(first);
    drop(second);
    wait_until(
        || manager.pool_ref_count(config.id) == 0,
        "pool drain after edit-inflight",
    )
    .await;
}

#[tokio::test]
async fn drop_mid_establish_releases_refcount_and_cancels() {
    let concrete = Arc::new(FakeTunnelProvider::with_delay(
        TunnelKind::WireGuard,
        Duration::from_millis(200),
    ));
    let provider: Arc<dyn TunnelProvider> = concrete.clone();
    let manager = Arc::new(TunnelManager::new([provider]).unwrap());
    let config = wg_config("cancel");

    let manager2 = Arc::clone(&manager);
    let config2 = config.clone();
    let handle = tokio::spawn(async move {
        manager2.establish(config2, vec![9]).await
    });

    // Let acquire_entry run and start the delayed provider.
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(manager.pool_ref_count(config.id), 1);

    handle.abort();
    let join_err = match handle.await {
        Ok(_) => panic!("expected aborted task"),
        Err(e) => e,
    };
    assert!(join_err.is_cancelled());

    // Drop guard must release; pool empty and cancelled flag set so orphaned instance closes.
    wait_until(|| manager.pool_ref_count(config.id) == 0, "pool drain after abort").await;
    // Provider may still be finishing its delay; wait for the establish call to complete.
    wait_until(|| concrete.establish_count() >= 1, "provider establish finished").await;
    assert_eq!(concrete.establish_count(), 1);

    // Next establish starts fresh (not stuck on a leaked entry).
    let lease = manager.establish(config.clone(), vec![]).await.unwrap();
    assert_eq!(manager.establish_start_count(), 2);
    drop(lease);
}

#[tokio::test]
async fn provider_failure_evicts_and_releases_all_waiters() {
    let concrete = Arc::new(FakeTunnelProvider::with_delay(
        TunnelKind::WireGuard,
        Duration::from_millis(40),
    ));
    concrete.fail_next("otp rejected");
    let provider: Arc<dyn TunnelProvider> = concrete.clone();
    let manager = TunnelManager::new([provider]).unwrap();
    let config = wg_config("fail");

    let (a, b) = tokio::join!(
        manager.establish(config.clone(), vec![]),
        manager.establish(config.clone(), vec![]),
    );
    assert!(matches!(a, Err(TunnelError::Establish(_))));
    assert!(matches!(b, Err(TunnelError::Establish(_))));
    assert_eq!(manager.pool_ref_count(config.id), 0);
    assert_eq!(concrete.establish_count(), 1);

    // Fresh attempt after failure.
    let ok = manager.establish(config.clone(), vec![]).await.unwrap();
    assert_eq!(concrete.establish_count(), 2);
    drop(ok);
}

#[tokio::test]
async fn production_wireguard_missing_binary_is_not_connected() {
    // WireGuard / OpenVPN / Fortinet / Cisco / ovpn-backed kinds share READY/SOCKS:
    // missing exe → BinaryNotFound, never a fake Up/Connected.
    // Secret must pass the WG shape gate so we reach binary locate (not Establish).
    use wormhole_tunnels::FAKE_WIREGUARD_SIDECAR_JSON;
    let missing = std::env::temp_dir().join("wormhole-wgproxy-missing-lease-test.exe");
    let provider = WireGuardProvider::with_binary_path(&missing);
    let as_trait: Arc<dyn TunnelProvider> =
        Arc::new(WireGuardProvider::with_binary_path(&missing));
    let manager = TunnelManager::new([as_trait]).unwrap();
    let config = wg_config("stub");

    let err = match manager
        .establish(config, FAKE_WIREGUARD_SIDECAR_JSON.to_vec())
        .await
    {
        Ok(_) => panic!("missing sidecar must not establish a live tunnel"),
        Err(e) => e,
    };
    assert!(
        matches!(err, TunnelError::BinaryNotFound { .. }),
        "manager must preserve BinaryNotFound, got {err:?}"
    );
    let direct = match provider
        .establish(
            &TunnelConfigSnapshot::new(Uuid::new_v4(), TunnelKind::WireGuard, "x"),
            FAKE_WIREGUARD_SIDECAR_JSON,
        )
        .await
    {
        Ok(_) => panic!("missing sidecar must not establish"),
        Err(e) => e,
    };
    assert!(matches!(direct, TunnelError::BinaryNotFound { .. }));
    // Secret must never appear in the Display/Debug of the error.
    let rendered = format!("{direct} {direct:?}");
    assert!(!rendered.contains("interface_private_key"));
    assert!(!rendered.contains(r#""x""#));
}

#[tokio::test]
async fn manager_errors_never_echo_secret_blob() {
    let concrete = Arc::new(FakeTunnelProvider::new(TunnelKind::WireGuard));
    concrete.fail_next("otp rejected");
    let provider: Arc<dyn TunnelProvider> = concrete;
    let manager = TunnelManager::new([provider]).unwrap();
    let config = wg_config("redact");
    const MARKER: &[u8] = b"SUPER_SECRET_TUNNEL_PAYLOAD_MARKER";

    let err = match manager.establish(config, MARKER.to_vec()).await {
        Ok(_) => panic!("expected establish failure"),
        Err(e) => e,
    };
    assert!(matches!(err, TunnelError::Establish(_)));
    let rendered = format!("{err:?} {err} {manager:?}");
    assert!(
        !rendered.contains("SUPER_SECRET_TUNNEL_PAYLOAD_MARKER"),
        "secret blob must not appear in Debug/Display: {rendered}"
    );
}

#[tokio::test]
async fn fake_provider_debug_omits_fail_next_message() {
    let fake = FakeTunnelProvider::new(TunnelKind::WireGuard);
    fake.fail_next("SECRET_IN_FAIL_NEXT");
    let dbg = format!("{fake:?}");
    assert!(dbg.contains("FakeTunnelProvider"));
    assert!(dbg.contains("has_fail_next: true"));
    assert!(
        !dbg.contains("SECRET_IN_FAIL_NEXT"),
        "fail_next payload must not appear in Debug: {dbg}"
    );
}

#[tokio::test]
async fn lease_debug_is_opaque() {
    let provider: Arc<dyn TunnelProvider> = Arc::new(FakeTunnelProvider::new(TunnelKind::WireGuard));
    let manager = TunnelManager::new([provider]).unwrap();
    let lease = manager
        .establish(wg_config("dbg"), b"LEASE_DEBUG_SECRET_MARKER".to_vec())
        .await
        .unwrap();
    let rendered = format!("{lease:?} {manager:?}");
    assert!(rendered.contains("TunnelLease"));
    assert!(rendered.contains("armed: true"));
    assert!(
        !rendered.contains("LEASE_DEBUG_SECRET_MARKER"),
        "secret must not appear in lease/manager Debug: {rendered}"
    );
    lease.release();
}

#[tokio::test]
async fn production_openvpn_missing_binary_is_not_connected() {
    use wormhole_tunnels::OpenVpnProvider;
    let provider = OpenVpnProvider::with_binary_path(
        std::env::temp_dir().join("wormhole-ovpnproxy-missing-lease-test.exe"),
    );
    let err = match provider
        .establish(
            &TunnelConfigSnapshot::new(Uuid::new_v4(), TunnelKind::OpenVpn, "x"),
            br#"{"profile_ovpn":"client","password":"lease-SECRET-marker"}"#,
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
    let rendered = format!("{err} {err:?}");
    assert!(!rendered.contains("lease-SECRET-marker"));
}

#[tokio::test]
async fn production_fortinet_missing_binary_is_not_connected() {
    use wormhole_tunnels::FortinetProvider;
    let provider = FortinetProvider::with_binary_path(
        std::env::temp_dir().join("wormhole-fortiproxy-missing-lease-test.exe"),
    );
    let err = match provider
        .establish(
            &TunnelConfigSnapshot::new(Uuid::new_v4(), TunnelKind::Fortinet, "x"),
            b"secret",
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
    let rendered = format!("{err} {err:?}");
    assert!(!rendered.contains("secret"));
}

#[tokio::test]
async fn bind_local_forwarder_reuses_port_for_same_target() {
    let inst = StubTunnelInstance::up_with_socks(1);
    let port1 = TunnelInstance::bind_local_forwarder(inst.as_ref(), "host.example", 3389)
        .await
        .expect("bind");
    let same = TunnelInstance::bind_local_forwarder(inst.as_ref(), "HOST.EXAMPLE", 3389)
        .await
        .expect("reuse");
    let other = TunnelInstance::bind_local_forwarder(inst.as_ref(), "host.example", 22)
        .await
        .expect("other target");
    assert_eq!(port1, same);
    assert_ne!(port1, other);
    inst.close().await;
}

#[tokio::test]
async fn bind_local_forwarder_rejects_failed_tunnel() {
    let inst = StubTunnelInstance::failed();
    let err = match TunnelInstance::bind_local_forwarder(inst.as_ref(), "host.example", 3389).await
    {
        Ok(_) => panic!("expected TunnelUnavailable"),
        Err(e) => e,
    };
    assert!(matches!(
        err,
        TunnelError::TunnelUnavailable {
            state: wormhole_tunnels::TunnelState::Failed
        }
    ));
}

#[tokio::test]
async fn duplicate_provider_registration_rejected() {
    let a: Arc<dyn TunnelProvider> = Arc::new(FakeTunnelProvider::new(TunnelKind::WireGuard));
    let b: Arc<dyn TunnelProvider> = Arc::new(FakeTunnelProvider::new(TunnelKind::WireGuard));
    let err = match TunnelManager::new([a, b]) {
        Ok(_) => panic!("expected duplicate rejection"),
        Err(e) => e,
    };
    assert!(matches!(err, TunnelError::Establish(_)));
}
