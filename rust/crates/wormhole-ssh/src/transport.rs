//! Transport hook points for direct TCP and future SOCKS5 (VPN sidecars).
//!
//! Wormhole routes SSH through a tunnel SOCKS5 endpoint today
//! (`Services/Tunneling/Socks5Client.cs`). russh's `connect_stream` accepts any
//! `AsyncRead + AsyncWrite`, so SOCKS dialing plugs in *before* SSH without
//! changing the auth/shell path.

use std::fmt;
use std::net::SocketAddr;

use tokio::net::TcpStream;

use crate::error::SshError;
use crate::Result;

/// Endpoint description for a future SOCKS5 dialer (VPN sidecar loopback).
#[derive(Clone, PartialEq, Eq)]
pub struct Socks5Endpoint {
    pub proxy_host: String,
    pub proxy_port: u16,
    /// Optional username/password for SOCKS5 auth (unused in v1 sidecars).
    pub username: Option<String>,
    pub password: Option<String>,
}

impl fmt::Debug for Socks5Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Socks5Endpoint")
            .field("proxy_host", &self.proxy_host)
            .field("proxy_port", &self.proxy_port)
            .field("username", &self.username)
            .field(
                "password",
                &self.password.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// How the SSH client should obtain its byte stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshTransport {
    /// Connect directly to the SSH target (no tunnel).
    Direct,
    /// Dial via a SOCKS5 proxy (VPN sidecar). Implementation is a hook stub.
    Socks5(Socks5Endpoint),
}

/// Open a TCP stream suitable for `russh::client::connect_stream`.
pub async fn open_transport(transport: &SshTransport, target: SocketAddr) -> Result<TcpStream> {
    match transport {
        SshTransport::Direct => Ok(TcpStream::connect(target).await?),
        SshTransport::Socks5(endpoint) => {
            // Hook point: dial `endpoint`, perform SOCKS5 CONNECT to `target`,
            // then return the established stream to russh. Mirrors C# Socks5Client.
            // Do not interpolate SOCKS credentials into the error string.
            let _ = target;
            Err(SshError::Socks5NotImplemented(format!(
                "socks5://{}:{}",
                endpoint.proxy_host, endpoint.proxy_port
            )))
        }
    }
}

/// Convenience: direct TCP.
pub async fn connect_direct(target: SocketAddr) -> Result<TcpStream> {
    open_transport(&SshTransport::Direct, target).await
}

/// Convenience: SOCKS5 hook (currently always errors).
pub async fn connect_via_socks5(endpoint: &Socks5Endpoint, target: SocketAddr) -> Result<TcpStream> {
    open_transport(&SshTransport::Socks5(endpoint.clone()), target).await
}

/// Alias kept for docs / call-site naming symmetry with Direct.
pub type DirectTcpTransport = SshTransport;
pub type Socks5TransportHook = Socks5Endpoint;
pub type TcpStreamTransport = TcpStream;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn socks5_error_omits_credentials() {
        let err = connect_via_socks5(
            &Socks5Endpoint {
                proxy_host: "127.0.0.1".into(),
                proxy_port: 1080,
                username: Some("user".into()),
                password: Some("secret".into()),
            },
            "127.0.0.1:22".parse().unwrap(),
        )
        .await
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("127.0.0.1:1080"));
        assert!(!msg.contains("secret"));
        assert!(!msg.contains("user"));
    }
}
