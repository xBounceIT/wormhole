//! File-transfer dialog glue: connected SSH → SOCKS select → transfer queue.
//!
//! Thin parity with C# `FileTransferDialogService` / `SshSessionViewModel.CanOpenFileTransfer`
//! (no GPUI): fail closed unless an SSH session is Connected; resolve route via
//! [`select_sftp_transport`]; run file jobs through [`TransferQueue`] (cancel /
//! single-flight). Live russh SFTP dial stays deferred — callers supply a ready
//! [`SftpOps`] backend (`FakeSftpBackend` in tests).
//!
//! **No credentials** on this surface — passwords / keys stay on the SSH tab /
//! secret stores. `Debug` never carries secret-shaped fields.

use std::fmt;
use std::sync::Arc;

use crate::fake::FakeSftpBackend;
use crate::ops::SftpOps;
use crate::queue::{TransferDirection, TransferQueue};
use crate::session::SerializedSftpSession;
use crate::transport::{select_sftp_transport, SftpTransport, TunnelSocksSource};
use crate::SftpError;
use crate::Result;

/// Minimal SSH tab context required to open file transfer.
///
/// Mirrors C# `CanOpenFileTransfer` (`Status == Connected`) plus the host/title
/// the dialog chrome shows. Does **not** hold passwords, keys, or tunnel secrets.
#[derive(Clone)]
pub struct ConnectedSshContext {
    pub host: String,
    pub port: u16,
    pub connection_title: String,
    /// `true` only when the SSH tab reports Connected.
    pub connected: bool,
}

impl ConnectedSshContext {
    /// Connected SSH tab (normal open path).
    pub fn connected(host: impl Into<String>, port: u16, title: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port,
            connection_title: title.into(),
            connected: true,
        }
    }

    /// Explicit disconnected / not-ready tab (must fail closed on open).
    pub fn disconnected(host: impl Into<String>, port: u16, title: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port,
            connection_title: title.into(),
            connected: false,
        }
    }
}

impl fmt::Debug for ConnectedSshContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectedSshContext")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("connection_title", &self.connection_title)
            .field("connected", &self.connected)
            .finish()
    }
}

/// Opened file-transfer dialog state (resolved transport + serialized queue).
///
/// Dual-pane UI, conflict overlays, and local FS browsing stay with the host.
/// This type owns the transfer strip and the Direct/SOCKS route chosen at open.
pub struct FileTransferDialogState<B: SftpOps> {
    connection_title: String,
    remote_host: String,
    remote_port: u16,
    transport: SftpTransport,
    queue: TransferQueue<B>,
}

impl<B: SftpOps + 'static> fmt::Debug for FileTransferDialogState<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileTransferDialogState")
            .field("connection_title", &self.connection_title)
            .field("remote_host", &self.remote_host)
            .field("remote_port", &self.remote_port)
            .field("transport", &self.transport)
            .field("job_count", &self.queue.jobs().len())
            .finish()
    }
}

impl<B: SftpOps + 'static> FileTransferDialogState<B> {
    pub fn connection_title(&self) -> &str {
        &self.connection_title
    }

    pub fn remote_host(&self) -> &str {
        &self.remote_host
    }

    pub fn remote_port(&self) -> u16 {
        self.remote_port
    }

    pub fn transport(&self) -> &SftpTransport {
        &self.transport
    }

    pub fn queue(&self) -> &TransferQueue<B> {
        &self.queue
    }

    pub fn session(&self) -> &Arc<SerializedSftpSession<B>> {
        self.queue.session()
    }

    /// Start one file transfer under the session cancel / single-flight gate.
    ///
    /// Delegates to [`TransferQueue::enqueue_and_run_file`] — does not reimplement
    /// serialization or cancel semantics.
    pub async fn start_transfer(
        &self,
        direction: TransferDirection,
        source_path: impl Into<String>,
        destination_path: impl Into<String>,
        payload: Option<Vec<u8>>,
    ) -> Result<u64> {
        self.queue
            .enqueue_and_run_file(direction, source_path, destination_path, payload)
            .await
    }
}

/// Open dialog state from an optional connected SSH context + tunnel SOCKS view.
///
/// | `ssh` | Result |
/// |---|---|
/// | `None` | [`SftpError::SshSessionRequired`] |
/// | `Some` with `connected == false` or blank/`trim`-empty host | [`SftpError::SshSessionRequired`] |
/// | `Some` connected | [`select_sftp_transport`] then wrap `backend` |
///
/// On success, `remote_host` is the trimmed SSH host (whitespace-padded inputs
/// are normalized so a later dial does not see leading/trailing spaces).
///
/// Does **not** dial SFTP or accept credentials — `backend` must already be ready
/// (Fake in unit tests; live russh channel wiring later).
pub fn open_from_ssh_session<B: SftpOps + 'static>(
    ssh: Option<&ConnectedSshContext>,
    tunnel: Option<&dyn TunnelSocksSource>,
    backend: B,
) -> Result<FileTransferDialogState<B>> {
    let ssh = ssh.ok_or(SftpError::SshSessionRequired)?;
    let host = ssh.host.trim();
    if !ssh.connected || host.is_empty() {
        return Err(SftpError::SshSessionRequired);
    }
    let transport = select_sftp_transport(tunnel)?;
    let session = SerializedSftpSession::new(backend).into_arc();
    Ok(FileTransferDialogState {
        connection_title: ssh.connection_title.clone(),
        remote_host: host.to_string(),
        remote_port: ssh.port,
        transport,
        queue: TransferQueue::new(session),
    })
}

/// Unit-test helper: Fake backend + optional tunnel SOCKS stub.
pub fn open_with_fake(
    ssh: Option<&ConnectedSshContext>,
    tunnel: Option<&dyn TunnelSocksSource>,
) -> Result<FileTransferDialogState<FakeSftpBackend>> {
    open_from_ssh_session(ssh, tunnel, FakeSftpBackend::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::queue::TransferStatus;
    use crate::transport::{FakeTunnelSocks, Socks5Endpoint};
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn none_ssh_fails_closed() {
        let err = open_with_fake(None, None).unwrap_err();
        assert!(matches!(err, SftpError::SshSessionRequired));
        assert_eq!(
            err.public_message(),
            "file transfer requires a connected SSH session"
        );
        assert_eq!(format!("{err:?}"), "SshSessionRequired");
    }

    #[test]
    fn disconnected_ssh_fails_closed() {
        let ssh = ConnectedSshContext::disconnected("host.example", 22, "box");
        let err = open_with_fake(Some(&ssh), None).unwrap_err();
        assert!(matches!(err, SftpError::SshSessionRequired));
    }

    #[test]
    fn blank_host_fails_closed() {
        for host in ["", "   ", "\t\n"] {
            let ssh = ConnectedSshContext::connected(host, 22, "box");
            let err = open_with_fake(Some(&ssh), None).unwrap_err();
            assert!(
                matches!(err, SftpError::SshSessionRequired),
                "host={host:?}"
            );
        }
    }

    #[test]
    fn padded_host_is_trimmed_on_open() {
        let ssh = ConnectedSshContext::connected("  ssh.example  ", 22, "prod");
        let state = open_with_fake(Some(&ssh), None).unwrap();
        assert_eq!(state.remote_host(), "ssh.example");
        assert!(state.transport().is_direct());
    }

    #[test]
    fn connected_no_tunnel_selects_direct() {
        let ssh = ConnectedSshContext::connected("ssh.example", 22, "prod");
        let state = open_with_fake(Some(&ssh), None).unwrap();
        assert!(state.transport().is_direct());
        assert_eq!(state.remote_host(), "ssh.example");
        assert_eq!(state.remote_port(), 22);
        assert_eq!(state.connection_title(), "prod");
        assert!(state.session().is_connected());
    }

    #[test]
    fn connected_with_socks_selects_socks5() {
        let ssh = ConnectedSshContext::connected("ssh.example", 22, "prod");
        let tunnel = FakeTunnelSocks::loopback(1080).unwrap();
        let state = open_with_fake(Some(&ssh), Some(&tunnel)).unwrap();
        let ep = state.transport().socks5().expect("socks");
        assert_eq!(ep.addr.port(), 1080);
    }

    #[test]
    fn tunnel_without_socks_fails_closed() {
        let ssh = ConnectedSshContext::connected("ssh.example", 22, "prod");
        let tunnel = FakeTunnelSocks::none();
        let err = open_with_fake(Some(&ssh), Some(&tunnel)).unwrap_err();
        assert!(matches!(err, SftpError::TunnelSocksRequired));
    }

    #[test]
    fn tunnel_zero_port_socks_fails_closed() {
        let ssh = ConnectedSshContext::connected("ssh.example", 22, "prod");
        let tunnel = FakeTunnelSocks::with_socks5(Socks5Endpoint::new(SocketAddr::from((
            Ipv4Addr::LOCALHOST,
            0,
        ))));
        let err = open_with_fake(Some(&ssh), Some(&tunnel)).unwrap_err();
        assert!(matches!(err, SftpError::InvalidSocksPort(0)));
        assert!(open_with_fake(Some(&ssh), None).unwrap().transport().is_direct());
    }

    #[test]
    fn debug_surfaces_omit_secrets() {
        let ssh = ConnectedSshContext::connected("ssh.example", 22, "prod");
        let state = open_with_fake(Some(&ssh), None).unwrap();
        for s in [format!("{ssh:?}"), format!("{state:?}")] {
            let lower = s.to_ascii_lowercase();
            assert!(!lower.contains("password"), "{s}");
            assert!(!lower.contains("secret"), "{s}");
            assert!(!lower.contains("token"), "{s}");
            assert!(!s.contains("hunter2"), "{s}");
        }
        assert!(!format!("{:?}", SftpError::SshSessionRequired).contains("password"));
    }

    #[tokio::test]
    async fn start_transfer_completes_single_job() {
        let ssh = ConnectedSshContext::connected("ssh.example", 22, "prod");
        let state = open_with_fake(Some(&ssh), None).unwrap();
        let id = state
            .start_transfer(
                TransferDirection::Upload,
                "local/a.txt",
                "/home/user/a.txt",
                Some(b"hello".to_vec()),
            )
            .await
            .unwrap();
        let jobs = state.queue().jobs();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].id, id);
        assert_eq!(jobs[0].status, TransferStatus::Completed);
        assert_eq!(state.session().ops_completed(), 1);
        assert!(state.session().backend().exists("/home/user/a.txt").await.unwrap());
    }

    #[tokio::test]
    async fn double_start_transfer_stays_single_flight() {
        let ssh = ConnectedSshContext::connected("ssh.example", 22, "prod");
        let backend = FakeSftpBackend::with_delay(Duration::from_millis(40));
        let state = Arc::new(open_from_ssh_session(Some(&ssh), None, backend).unwrap());

        let a = {
            let s = Arc::clone(&state);
            tokio::spawn(async move {
                s.start_transfer(
                    TransferDirection::Upload,
                    "local/a.txt",
                    "/home/user/a.txt",
                    Some(b"one".to_vec()),
                )
                .await
            })
        };
        let b = {
            let s = Arc::clone(&state);
            tokio::spawn(async move {
                s.start_transfer(
                    TransferDirection::Upload,
                    "local/b.txt",
                    "/home/user/b.txt",
                    Some(b"two".to_vec()),
                )
                .await
            })
        };

        let (ra, rb) = tokio::join!(a, b);
        ra.unwrap().unwrap();
        rb.unwrap().unwrap();

        assert_eq!(
            state
                .session()
                .backend()
                .peak_in_flight
                .load(Ordering::SeqCst),
            1,
            "dialog start_transfer must not overlap backend ops"
        );
        let jobs = state.queue().jobs();
        assert_eq!(jobs.len(), 2);
        assert!(jobs.iter().all(|j| j.status == TransferStatus::Completed));
        assert_eq!(state.session().ops_completed(), 2);
    }

    #[tokio::test]
    async fn cancel_mid_transfer_marks_job_cancelled_via_queue() {
        let ssh = ConnectedSshContext::connected("ssh.example", 22, "prod");
        let backend = FakeSftpBackend::with_delay(Duration::from_millis(200));
        let state = Arc::new(open_from_ssh_session(Some(&ssh), None, backend).unwrap());

        let s = Arc::clone(&state);
        let handle = tokio::spawn(async move {
            s.start_transfer(
                TransferDirection::Upload,
                "local/slow.txt",
                "/home/user/slow.txt",
                Some(b"x".to_vec()),
            )
            .await
        });
        tokio::time::sleep(Duration::from_millis(30)).await;
        handle.abort();
        let _ = handle.await;
        // Allow session worker to finish (gate held until complete).
        tokio::time::sleep(Duration::from_millis(250)).await;

        let jobs = state.queue().jobs();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].status, TransferStatus::Cancelled);

        // Gate free for a follow-up transfer (existing cancel single-flight).
        let id = state
            .start_transfer(
                TransferDirection::Upload,
                "local/next.txt",
                "/home/user/next.txt",
                Some(b"ok".to_vec()),
            )
            .await
            .unwrap();
        assert_eq!(
            state
                .queue()
                .jobs()
                .iter()
                .find(|j| j.id == id)
                .unwrap()
                .status,
            TransferStatus::Completed
        );
    }

    #[tokio::test]
    async fn cancel_queued_start_transfer_skips_then_next_completes() {
        let ssh = ConnectedSshContext::connected("ssh.example", 22, "prod");
        let backend = FakeSftpBackend::with_delay(Duration::from_millis(200));
        let state = Arc::new(open_from_ssh_session(Some(&ssh), None, backend).unwrap());

        let holder = {
            let s = Arc::clone(&state);
            tokio::spawn(async move {
                s.start_transfer(
                    TransferDirection::Upload,
                    "local/a.txt",
                    "/home/user/a.txt",
                    Some(b"one".to_vec()),
                )
                .await
            })
        };
        tokio::time::sleep(Duration::from_millis(30)).await;

        let waiter = {
            let s = Arc::clone(&state);
            tokio::spawn(async move {
                s.start_transfer(
                    TransferDirection::Upload,
                    "local/b.txt",
                    "/home/user/b.txt",
                    Some(b"two".to_vec()),
                )
                .await
            })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        waiter.abort();
        let _ = waiter.await;

        holder.await.unwrap().unwrap();

        state
            .start_transfer(
                TransferDirection::Upload,
                "local/c.txt",
                "/home/user/c.txt",
                Some(b"three".to_vec()),
            )
            .await
            .unwrap();

        let jobs = state.queue().jobs();
        assert_eq!(jobs.len(), 3);
        assert_eq!(jobs[0].status, TransferStatus::Completed);
        assert_eq!(jobs[1].status, TransferStatus::Cancelled);
        assert_eq!(jobs[2].status, TransferStatus::Completed);
        assert_eq!(
            state.session().ops_completed(),
            2,
            "pre-gate cancel via start_transfer must skip waiter backend"
        );
        assert!(!state.session().backend().exists("/home/user/b.txt").await.unwrap());
    }
}
