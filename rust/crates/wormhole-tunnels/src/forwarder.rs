//! Loopback TCP forwarder: `127.0.0.1:0` → SOCKS5 → fixed target.
//!
//! Mirrors `Services/Tunneling/LocalTcpForwarder.cs` + the reuse map in
//! `SocksTunnelInstance.BindLocalForwarderAsync`. Used for RDP/VNC which cannot
//! speak SOCKS5 directly.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, watch};
use tokio::task::JoinHandle;

use crate::socks5::{validate_target, Socks5Client};
use crate::{Socks5Endpoint, TunnelError, TunnelState};

/// One live loopback listener forwarding to a fixed `host:port` through SOCKS5.
pub struct LocalForwarder {
    target_host: String,
    target_port: u16,
    local_port: u16,
    alive: Arc<AtomicBool>,
    shutdown_tx: watch::Sender<bool>,
    /// `Option` so [`Self::shutdown`] / [`Drop`] can take the handle without
    /// partial-move conflicts under `Drop`.
    accept_task: Option<JoinHandle<()>>,
    /// In-flight bridge tasks; aborted on [`Self::shutdown`] / [`Drop`].
    bridges: Arc<StdMutex<Vec<JoinHandle<()>>>>,
}

impl LocalForwarder {
    /// Bind `127.0.0.1:0`, start the accept loop, return the forwarder.
    pub async fn start(
        socks: Socks5Endpoint,
        target_host: &str,
        target_port: u16,
    ) -> Result<Self, TunnelError> {
        let host = validate_target(target_host, target_port)?;

        let listener = TcpListener::bind(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .map_err(|e| TunnelError::Forwarder(format!("bind 127.0.0.1:0 failed: {e}")))?;
        let local_addr = listener
            .local_addr()
            .map_err(|e| TunnelError::Forwarder(format!("local_addr failed: {e}")))?;
        // Invariant: never advertise a non-loopback bind.
        if !local_addr.ip().is_loopback() {
            return Err(TunnelError::Forwarder(format!(
                "refusing non-loopback forwarder bind at {local_addr}"
            )));
        }
        let local_port = local_addr.port();

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let alive = Arc::new(AtomicBool::new(true));
        let alive_flag = alive.clone();
        let host_owned = host.to_string();
        let bridges = Arc::new(StdMutex::new(Vec::new()));
        let bridges_for_loop = bridges.clone();

        let accept_task = tokio::spawn(async move {
            accept_loop(
                listener,
                socks,
                host_owned,
                target_port,
                shutdown_rx,
                bridges_for_loop,
            )
            .await;
            alive_flag.store(false, Ordering::SeqCst);
        });

        Ok(Self {
            target_host: host.to_string(),
            target_port,
            local_port,
            alive,
            shutdown_tx,
            accept_task: Some(accept_task),
            bridges,
        })
    }

    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    pub fn target_host(&self) -> &str {
        &self.target_host
    }

    pub fn target_port(&self) -> u16 {
        self.target_port
    }

    /// False once the accept loop has exited (dispose or crash).
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
            && self
                .accept_task
                .as_ref()
                .is_some_and(|task| !task.is_finished())
    }

    pub async fn shutdown(mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(task) = self.accept_task.take() {
            let _ = task.await;
        }
        abort_bridges(&self.bridges);
    }
}

impl Drop for LocalForwarder {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(task) = self.accept_task.take() {
            task.abort();
            // Abort is async: wait until accept_loop is gone so it cannot push a
            // bridge handle after we drain `bridges` (which would detach a leak).
            let start = std::time::Instant::now();
            while !task.is_finished()
                && start.elapsed() < std::time::Duration::from_millis(200)
            {
                std::thread::yield_now();
            }
        }
        abort_bridges(&self.bridges);
    }
}

fn abort_bridges(bridges: &StdMutex<Vec<JoinHandle<()>>>) {
    let mut gate = bridges.lock().unwrap_or_else(|p| p.into_inner());
    for handle in gate.drain(..) {
        handle.abort();
    }
}

async fn accept_loop(
    listener: TcpListener,
    socks: Socks5Endpoint,
    target_host: String,
    target_port: u16,
    mut shutdown_rx: watch::Receiver<bool>,
    bridges: Arc<StdMutex<Vec<JoinHandle<()>>>>,
) {
    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((client, _)) => {
                        let host = target_host.clone();
                        let handle = tokio::spawn(async move {
                            handle_client(client, socks, &host, target_port).await;
                        });
                        let mut gate = bridges.lock().unwrap_or_else(|p| p.into_inner());
                        gate.retain(|h| !h.is_finished());
                        gate.push(handle);
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "local tunnel forwarder accept loop crashed");
                        break;
                    }
                }
            }
        }
    }
}

async fn handle_client(
    mut client: TcpStream,
    socks: Socks5Endpoint,
    target_host: &str,
    target_port: u16,
) {
    let _ = client.set_nodelay(true);
    let mut tunnel = match Socks5Client::connect(socks, target_host, target_port).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                host = %target_host,
                port = target_port,
                error = %e,
                "forwarder failed to dial through tunnel"
            );
            return;
        }
    };
    // copy_bidirectional shuts down each write half on peer EOF so half-close
    // does not strand a unidirectional copy (parity with C# WhenAny + close).
    let _ = copy_bidirectional(&mut client, &mut tunnel).await;
}

/// Reuses one live listener per `(host, port)` for a shared tunnel lifetime.
///
/// Parity with C# `SocksTunnelInstance`: TunnelManager pools one instance per
/// config, so repeated RDP/VNC connects must not stack loopback listeners.
#[derive(Default)]
pub struct ForwarderRegistry {
    forwarders: Mutex<Vec<LocalForwarder>>,
}

impl ForwarderRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind or reuse a forwarder; returns the local port.
    pub async fn bind_or_reuse(
        &self,
        socks: Socks5Endpoint,
        host: &str,
        port: u16,
    ) -> Result<u16, TunnelError> {
        // Fail closed before touching the registry / binding a listener.
        let host = validate_target(host, port)?;

        let mut gate = self.forwarders.lock().await;

        // Replace crashed listeners; re-check after each shutdown because another
        // task may have inserted while we dropped the gate.
        loop {
            let Some(idx) = find_forwarder(&gate, host, port) else {
                break;
            };
            if gate[idx].is_alive() {
                return Ok(gate[idx].local_port());
            }
            let stale = gate.remove(idx);
            drop(gate);
            stale.shutdown().await;
            gate = self.forwarders.lock().await;
        }

        // Lock is held across the loopback bind (microseconds) so concurrent
        // same-target callers serialize into one listener — parity with C#
        // SocksTunnelInstance's sync gate around LocalTcpForwarder.Start.
        let fwd = LocalForwarder::start(socks, host, port).await?;
        let bound = fwd.local_port();
        gate.push(fwd);
        Ok(bound)
    }

    pub async fn close_all(&self) {
        let mut gate = self.forwarders.lock().await;
        let drained: Vec<_> = gate.drain(..).collect();
        drop(gate);
        for fwd in drained {
            fwd.shutdown().await;
        }
    }
}

fn find_forwarder(forwarders: &[LocalForwarder], host: &str, port: u16) -> Option<usize> {
    forwarders.iter().position(|fwd| {
        fwd.target_port() == port && fwd.target_host().eq_ignore_ascii_case(host.trim())
    })
}

/// Shared bind path for any [`TunnelInstance`] that exposes a SOCKS5 endpoint.
pub async fn bind_local_forwarder_for(
    state: TunnelState,
    socks: Option<Socks5Endpoint>,
    registry: &ForwarderRegistry,
    host: &str,
    port: u16,
) -> Result<u16, TunnelError> {
    match state {
        TunnelState::Closed | TunnelState::Failed | TunnelState::Idle => {
            return Err(TunnelError::TunnelUnavailable { state });
        }
        TunnelState::Establishing | TunnelState::Up => {}
    }
    let socks = socks.ok_or(TunnelError::NoSocksEndpoint)?;
    registry.bind_or_reuse(socks, host, port).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const VER: u8 = 0x05;
    const METHOD_NO_AUTH: u8 = 0x00;
    const ATYP_DOMAIN: u8 = 0x03;
    const ATYP_IPV4: u8 = 0x01;
    const REP_SUCCESS: u8 = 0x00;

    /// Tiny SOCKS5 mock that dials the real target (echo server) after CONNECT.
    async fn spawn_bridging_socks() -> (Socks5Endpoint, JoinHandle<()>) {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut client, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut hdr = [0u8; 2];
                    if client.read_exact(&mut hdr).await.is_err() {
                        return;
                    }
                    let mut methods = vec![0u8; hdr[1] as usize];
                    if client.read_exact(&mut methods).await.is_err() {
                        return;
                    }
                    let _ = client.write_all(&[VER, METHOD_NO_AUTH]).await;

                    let mut req = [0u8; 4];
                    if client.read_exact(&mut req).await.is_err() {
                        return;
                    }
                    let target = match req[3] {
                        ATYP_IPV4 => {
                            let mut ip = [0u8; 4];
                            if client.read_exact(&mut ip).await.is_err() {
                                return;
                            }
                            Ipv4Addr::from(ip).to_string()
                        }
                        ATYP_DOMAIN => {
                            let mut len = [0u8; 1];
                            if client.read_exact(&mut len).await.is_err() {
                                return;
                            }
                            let mut host = vec![0u8; len[0] as usize];
                            if client.read_exact(&mut host).await.is_err() {
                                return;
                            }
                            String::from_utf8_lossy(&host).into_owned()
                        }
                        _ => return,
                    };
                    let mut port_buf = [0u8; 2];
                    if client.read_exact(&mut port_buf).await.is_err() {
                        return;
                    }
                    let port = u16::from_be_bytes(port_buf);
                    let _ = client
                        .write_all(&[VER, REP_SUCCESS, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
                        .await;

                    let mut upstream = match TcpStream::connect((target.as_str(), port)).await {
                        Ok(s) => s,
                        Err(_) => return,
                    };
                    let _ = copy_bidirectional(&mut client, &mut upstream).await;
                });
            }
        });
        (Socks5Endpoint::new(addr), handle)
    }

    async fn spawn_echo() -> (u16, JoinHandle<()>) {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            let Ok((mut client, _)) = listener.accept().await else {
                return;
            };
            let mut buf = [0u8; 64];
            loop {
                match client.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if client.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
        (port, handle)
    }

    #[tokio::test]
    async fn local_forwarder_bridges_via_socks_to_echo() {
        let (echo_port, echo_task) = spawn_echo().await;
        let (socks, socks_task) = spawn_bridging_socks().await;

        let fwd = LocalForwarder::start(socks, "127.0.0.1", echo_port)
            .await
            .unwrap();
        let local_port = fwd.local_port();
        assert!(local_port > 0);

        let mut client = TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], local_port)))
            .await
            .unwrap();
        client.write_all(b"hello-rdp").await.unwrap();
        let mut buf = [0u8; 9];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello-rdp");

        fwd.shutdown().await;
        echo_task.abort();
        socks_task.abort();
    }

    #[tokio::test]
    async fn local_forwarder_binds_loopback_only() {
        let (socks, socks_task) = spawn_bridging_socks().await;
        let fwd = LocalForwarder::start(socks, "host.internal", 3389)
            .await
            .unwrap();
        let addr = SocketAddr::from(([127, 0, 0, 1], fwd.local_port()));
        // Connecting via loopback works; the listener was bound to 127.0.0.1:0.
        let ok = TcpStream::connect(addr).await;
        assert!(ok.is_ok());
        assert!(fwd.is_alive());
        fwd.shutdown().await;
        socks_task.abort();
    }

    #[tokio::test]
    async fn local_forwarder_rejects_empty_host_and_port_zero() {
        let socks = Socks5Endpoint::loopback(9);
        assert!(matches!(
            LocalForwarder::start(socks, "", 3389).await,
            Err(TunnelError::InvalidTarget { .. })
        ));
        assert!(matches!(
            LocalForwarder::start(socks, "h", 0).await,
            Err(TunnelError::InvalidTarget { port: 0, .. })
        ));
    }

    #[tokio::test]
    async fn local_forwarder_shutdown_stops_accept() {
        let (socks, socks_task) = spawn_bridging_socks().await;
        let fwd = LocalForwarder::start(socks, "host.internal", 3389)
            .await
            .unwrap();
        let port = fwd.local_port();
        fwd.shutdown().await;

        // Accept loop gone — new connects must fail (connection refused / reset).
        let err = TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], port))).await;
        assert!(err.is_err());
        socks_task.abort();
    }

    #[tokio::test]
    async fn local_forwarder_drop_aborts_accept_loop() {
        let (socks, socks_task) = spawn_bridging_socks().await;
        let fwd = LocalForwarder::start(socks, "host.internal", 3389)
            .await
            .unwrap();
        let port = fwd.local_port();
        drop(fwd);
        // Give the aborted accept task a tick to release the port.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let err = TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], port))).await;
        assert!(err.is_err(), "drop must not leave an orphaned listener");
        socks_task.abort();
    }

    #[tokio::test]
    async fn registry_reuses_listener_for_same_target() {
        let (socks, socks_task) = spawn_bridging_socks().await;
        let registry = ForwarderRegistry::new();

        let port1 = registry
            .bind_or_reuse(socks, "host.internal", 3389)
            .await
            .unwrap();
        let same = registry
            .bind_or_reuse(socks, "HOST.INTERNAL", 3389)
            .await
            .unwrap();
        let other = registry
            .bind_or_reuse(socks, "host.internal", 22)
            .await
            .unwrap();

        assert_eq!(port1, same);
        assert_ne!(port1, other);

        registry.close_all().await;
        socks_task.abort();
    }

    #[tokio::test]
    async fn registry_rejects_empty_host_and_port_zero() {
        let socks = Socks5Endpoint::loopback(9);
        let registry = ForwarderRegistry::new();
        assert!(matches!(
            registry.bind_or_reuse(socks, "  ", 3389).await,
            Err(TunnelError::InvalidTarget { .. })
        ));
        assert!(matches!(
            registry.bind_or_reuse(socks, "h", 0).await,
            Err(TunnelError::InvalidTarget { port: 0, .. })
        ));
    }

    #[tokio::test]
    async fn registry_concurrent_same_target_reuses_one_port() {
        let (socks, socks_task) = spawn_bridging_socks().await;
        let registry = Arc::new(ForwarderRegistry::new());

        let mut joins = Vec::new();
        for _ in 0..16 {
            let reg = registry.clone();
            joins.push(tokio::spawn(async move {
                reg.bind_or_reuse(socks, "shared.internal", 3389).await
            }));
        }
        let mut ports = Vec::new();
        for j in joins {
            ports.push(j.await.unwrap().unwrap());
        }
        let first = ports[0];
        assert!(ports.iter().all(|p| *p == first));

        registry.close_all().await;
        socks_task.abort();
    }

    #[tokio::test]
    async fn bind_local_forwarder_for_rejects_unavailable_states() {
        let socks = Socks5Endpoint::loopback(9);
        let registry = ForwarderRegistry::new();
        for state in [
            TunnelState::Idle,
            TunnelState::Closed,
            TunnelState::Failed,
        ] {
            let err = bind_local_forwarder_for(state, Some(socks), &registry, "h", 22)
                .await
                .unwrap_err();
            assert!(matches!(
                err,
                TunnelError::TunnelUnavailable { state: s } if s == state
            ));
        }
        let err = bind_local_forwarder_for(TunnelState::Up, None, &registry, "h", 22)
            .await
            .unwrap_err();
        assert!(matches!(err, TunnelError::NoSocksEndpoint));
    }
}
