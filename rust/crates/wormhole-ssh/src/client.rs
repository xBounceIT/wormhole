//! russh connect + interactive shell channel stub.

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use russh::client::{self, Handle, Msg};
use russh::keys::ssh_key::PublicKey;
use russh::{Channel, ChannelMsg, Disconnect, Preferred};
use tokio::time::timeout;
use wormhole_terminal::TerminalSize;

use crate::auth::{
    authenticate_with, ensure_auth_method_supported, PasswordAuth, RusshAuthenticator,
    SshAuthMethod,
};
use crate::error::SshError;
use crate::known_hosts::{
    compute_fingerprint, host_identity, HostKeyPolicy, KnownHostsStore,
};
use crate::transport::{open_transport, SshTransport};
use crate::Result;

/// Connect options for the shell spike.
#[derive(Debug, Clone)]
pub struct SshConnectOptions {
    pub host: String,
    pub port: u16,
    pub auth: SshAuthMethod,
    pub term: TerminalSize,
    pub transport: SshTransport,
    pub connect_timeout: Duration,
    /// Escape hatch: accept any server host key (skips store / policy).
    pub accept_any_host_key: bool,
    /// Policy consulted when `accept_any_host_key` is false and a store is set.
    pub host_key_policy: HostKeyPolicy,
    /// Optional known_hosts store (`%LOCALAPPDATA%\Wormhole\known_hosts` by default path).
    pub known_hosts: Option<KnownHostsStore>,
}

impl Default for SshConnectOptions {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            port: 22,
            auth: SshAuthMethod::Password(PasswordAuth {
                username: String::new(),
                password: String::new(),
            }),
            term: TerminalSize::DEFAULT,
            transport: SshTransport::Direct,
            connect_timeout: Duration::from_secs(15),
            accept_any_host_key: true,
            host_key_policy: HostKeyPolicy::TrustOnFirstUse,
            known_hosts: None,
        }
    }
}

/// OpenSSH-style SHA-256 fingerprint of a russh/ssh-key public key (wire bytes).
pub fn fingerprint_public_key(server_public_key: &PublicKey) -> Result<String> {
    let bytes = server_public_key
        .to_bytes()
        .map_err(|e| SshError::Other(format!("encode host key: {e}")))?;
    Ok(compute_fingerprint(&bytes))
}

/// Host-key gate used by the russh handler.
///
/// - `accept_any_host_key` → always accept (spike / Quick Connect escape hatch).
/// - otherwise consult `known_hosts` with `policy` (TOFU may persist).
/// - no store and not accept-any → reject.
pub fn accept_server_host_key(
    accept_any_host_key: bool,
    known_hosts: Option<&mut KnownHostsStore>,
    host: &str,
    fingerprint: &str,
    policy: HostKeyPolicy,
) -> Result<bool> {
    if accept_any_host_key {
        return Ok(true);
    }
    let Some(store) = known_hosts else {
        return Ok(false);
    };
    let known = store.get(host).map(str::to_string);
    let ok = store.accept(host, fingerprint, policy)?;
    if !ok {
        if let Some(expected) = known {
            return Err(SshError::HostKeyMismatch {
                host: host.to_string(),
                expected,
                actual: fingerprint.to_string(),
            });
        }
    }
    Ok(ok)
}

struct SpikeHandler {
    host_id: String,
    accept_any_host_key: bool,
    host_key_policy: HostKeyPolicy,
    known_hosts: Option<KnownHostsStore>,
}

impl client::Handler for SpikeHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> std::result::Result<bool, Self::Error> {
        let fingerprint = match fingerprint_public_key(server_public_key) {
            Ok(fp) => fp,
            Err(_) => return Ok(false),
        };
        match accept_server_host_key(
            self.accept_any_host_key,
            self.known_hosts.as_mut(),
            &self.host_id,
            &fingerprint,
            self.host_key_policy,
        ) {
            Ok(accepted) => Ok(accepted),
            // russh only gets bool from check_server_key; mismatch rejects the key.
            Err(SshError::HostKeyMismatch { .. }) => Ok(false),
            Err(_) => Ok(false),
        }
    }
}

/// Connected SSH session handle (spike).
pub struct SshClientSession {
    handle: Handle<SpikeHandler>,
}

/// Interactive shell channel stub — write/read/resize only.
pub struct ShellChannelStub {
    channel: Channel<Msg>,
}

impl SshClientSession {
    /// Disconnect cleanly.
    pub async fn disconnect(self) -> Result<()> {
        self.handle
            .disconnect(Disconnect::ByApplication, "", "en")
            .await?;
        Ok(())
    }
}

impl ShellChannelStub {
    /// Write bytes to the remote shell (stdin).
    pub async fn write_all(&mut self, data: &[u8]) -> Result<()> {
        self.channel.data(data).await?;
        Ok(())
    }

    /// Request a PTY window-size change.
    pub async fn resize(&mut self, columns: u32, rows: u32) -> Result<()> {
        validate_shell_resize(columns, rows)?;
        self.channel
            .window_change(columns, rows, 0, 0)
            .await?;
        Ok(())
    }

    /// Poll the next channel message (stdout/stderr/eof/exit).
    pub async fn recv(&mut self) -> Option<ChannelMsg> {
        self.channel.wait().await
    }

    /// Close the channel.
    pub async fn close(self) -> Result<()> {
        self.channel.close().await?;
        Ok(())
    }
}

/// Resolve host:port, open transport (direct / SOCKS5 hook), authenticate, open shell.
///
/// Auth dispatches on [`SshConnectOptions::auth`] (password / private key live;
/// agent and keyboard-interactive return [`SshError::AuthNotImplemented`]
/// **before** any network I/O).
pub async fn connect_password_shell(
    options: SshConnectOptions,
) -> Result<(SshClientSession, ShellChannelStub)> {
    // Fail closed for stubs before dial / host-key / russh handshake.
    ensure_auth_method_supported(&options.auth)?;

    let addr = resolve_addr(&options.host, options.port)?;
    let stream = timeout(options.connect_timeout, open_transport(&options.transport, addr))
        .await
        .map_err(|_| SshError::Other("SSH connect timed out".into()))??;

    let config = Arc::new(client::Config {
        preferred: Preferred::DEFAULT,
        ..Default::default()
    });
    let handler = SpikeHandler {
        host_id: host_identity(&options.host, Some(options.port)),
        accept_any_host_key: options.accept_any_host_key,
        host_key_policy: options.host_key_policy,
        known_hosts: options.known_hosts,
    };

    let mut handle = client::connect_stream(config, stream, handler).await?;

    // Move auth out of options so secrets are not retained after authenticate_with.
    let auth = options.auth;
    let mut authenticator = RusshAuthenticator::new(&mut handle);
    authenticate_with(&mut authenticator, auth).await?;

    let channel = handle.channel_open_session().await?;
    let cols = options.term.columns.max(1);
    let rows = options.term.rows.max(1);
    channel
        .request_pty(false, "xterm-256color", cols, rows, 0, 0, &[])
        .await?;
    channel.request_shell(true).await?;

    Ok((
        SshClientSession { handle },
        ShellChannelStub { channel },
    ))
}

/// Reject zero geometry before issuing a window-change request.
pub fn validate_shell_resize(columns: u32, rows: u32) -> Result<()> {
    if columns == 0 || rows == 0 {
        return Err(SshError::Other(
            "SSH resize columns/rows must be > 0".into(),
        ));
    }
    Ok(())
}

fn resolve_addr(host: &str, port: u16) -> Result<SocketAddr> {
    let mut addrs = (host, port)
        .to_socket_addrs()
        .map_err(|e| SshError::Other(format!("resolve {host}:{port}: {e}")))?;
    addrs
        .next()
        .ok_or_else(|| SshError::Other(format!("no addresses for {host}:{port}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{PrivateKeySource, SshAuthMethod};
    use crate::known_hosts::{HostKeyPolicy, KnownHostsStore};
    use crate::transport::Socks5Endpoint;

    #[tokio::test]
    #[ignore = "requires a reachable SSH server"]
    async fn password_shell_against_live_server() {
        let host = std::env::var("WORMHOLE_SSH_HOST").unwrap_or_else(|_| "127.0.0.1".into());
        let port: u16 = std::env::var("WORMHOLE_SSH_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(22);
        let username = std::env::var("WORMHOLE_SSH_USER").expect("WORMHOLE_SSH_USER");
        let password = std::env::var("WORMHOLE_SSH_PASSWORD").expect("WORMHOLE_SSH_PASSWORD");

        let (_session, mut shell) = connect_password_shell(SshConnectOptions {
            host,
            port,
            auth: SshAuthMethod::Password(PasswordAuth { username, password }),
            ..Default::default()
        })
        .await
        .expect("connect");

        shell.write_all(b"echo wormhole\n").await.expect("write");
        let _ = shell.recv().await;
    }

    #[tokio::test]
    async fn socks5_hook_is_wired_but_unimplemented() {
        let err = open_transport(
            &SshTransport::Socks5(Socks5Endpoint {
                proxy_host: "127.0.0.1".into(),
                proxy_port: 1080,
                username: None,
                password: None,
            }),
            "127.0.0.1:22".parse().unwrap(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, SshError::Socks5NotImplemented(_)));
    }

    #[test]
    fn connect_options_debug_redacts_auth_secrets() {
        let opts = SshConnectOptions {
            auth: SshAuthMethod::PrivateKey {
                username: "u".into(),
                source: PrivateKeySource::Bytes(b"key-material-secret".to_vec()),
                passphrase: Some("pp".into()),
            },
            ..Default::default()
        };
        let rendered = format!("{opts:?}");
        assert!(!rendered.contains("key-material-secret"));
        assert!(!rendered.contains("pp"));
        assert!(rendered.contains("<redacted>") || rendered.contains("len"));
    }

    #[test]
    fn host_key_policy_hook_accept_any() {
        assert!(accept_server_host_key(
            true,
            None,
            "h:22",
            "SHA256:x",
            HostKeyPolicy::RejectMismatch,
        )
        .unwrap());
        assert!(!accept_server_host_key(
            false,
            None,
            "h:22",
            "SHA256:x",
            HostKeyPolicy::TrustOnFirstUse,
        )
        .unwrap());
    }

    #[test]
    fn host_key_hook_tofu_with_temp_store() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = KnownHostsStore::empty(dir.path().join("known_hosts"));
        assert!(accept_server_host_key(
            false,
            Some(&mut store),
            "srv:22",
            "SHA256:pin",
            HostKeyPolicy::TrustOnFirstUse,
        )
        .unwrap());
        assert_eq!(store.get("srv:22"), Some("SHA256:pin"));

        let err = accept_server_host_key(
            false,
            Some(&mut store),
            "srv:22",
            "SHA256:other",
            HostKeyPolicy::TrustOnFirstUse,
        )
        .unwrap_err();
        assert!(matches!(err, SshError::HostKeyMismatch { .. }));
    }

    #[test]
    fn resize_rejects_zero_geometry() {
        assert!(validate_shell_resize(0, 24).is_err());
        assert!(validate_shell_resize(80, 0).is_err());
        assert!(validate_shell_resize(80, 24).is_ok());
    }

    #[test]
    fn socks5_endpoint_debug_redacts_password() {
        let ep = Socks5Endpoint {
            proxy_host: "127.0.0.1".into(),
            proxy_port: 1080,
            username: Some("u".into()),
            password: Some("proxy-secret".into()),
        };
        let rendered = format!("{ep:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("proxy-secret"));
    }

    #[tokio::test]
    async fn connect_timeout_surfaces_as_error() {
        // Unroutable TEST-NET address; expect timeout (or immediate connect failure).
        let err = match connect_password_shell(SshConnectOptions {
            host: "192.0.2.1".into(),
            port: 22,
            connect_timeout: Duration::from_millis(50),
            auth: SshAuthMethod::Password(PasswordAuth {
                username: "n/a".into(),
                password: "n/a".into(),
            }),
            ..Default::default()
        })
        .await
        {
            Ok(_) => panic!("expected connect failure"),
            Err(e) => e,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("timed out") || msg.contains("russh") || msg.contains("I/O"),
            "unexpected error: {msg}"
        );
    }

    #[tokio::test]
    async fn connect_agent_stub_fails_before_network() {
        // Agent must fail closed before SOCKS/direct dial (no silent success).
        let err = match connect_password_shell(SshConnectOptions {
            auth: SshAuthMethod::Agent {
                username: "alice".into(),
            },
            transport: SshTransport::Socks5(Socks5Endpoint {
                proxy_host: "127.0.0.1".into(),
                proxy_port: 1080,
                username: None,
                password: None,
            }),
            ..Default::default()
        })
        .await
        {
            Ok(_) => panic!("expected AuthNotImplemented"),
            Err(e) => e,
        };
        assert!(matches!(err, SshError::AuthNotImplemented("agent")));
    }

    #[tokio::test]
    async fn connect_kbi_stub_fails_before_network() {
        let err = match connect_password_shell(SshConnectOptions {
            auth: SshAuthMethod::KeyboardInteractive {
                username: "alice".into(),
            },
            host: "192.0.2.1".into(),
            connect_timeout: Duration::from_millis(50),
            ..Default::default()
        })
        .await
        {
            Ok(_) => panic!("expected AuthNotImplemented"),
            Err(e) => e,
        };
        assert!(matches!(
            err,
            SshError::AuthNotImplemented("keyboard-interactive")
        ));
    }
}
