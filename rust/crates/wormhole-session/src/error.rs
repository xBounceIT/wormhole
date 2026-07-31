//! Session errors — Display / thiserror messages never include passwords or secret blobs.

use thiserror::Error;
use wormhole_domain::ProtocolType;

use crate::rdp_vnc::UnsupportedProtocolReason;

/// Crate-level result alias.
pub type Result<T> = std::result::Result<T, SessionError>;

/// Typed session orchestrator failures.
#[derive(Debug, Error)]
pub enum SessionError {
    #[error("session connect cancelled")]
    Cancelled,

    /// RDP/VNC (and future stubs): fail closed with a structured reason + prepared request.
    #[error("protocol {protocol} is not supported by the session orchestrator yet: {reason}")]
    UnsupportedProtocol {
        protocol: ProtocolType,
        reason: UnsupportedProtocolReason,
    },

    #[error("tunnel is enabled but tunnel_config_id is missing")]
    TunnelConfigMissing,

    #[error("tunnel connect args are required when tunnel_enabled is true")]
    TunnelArgsMissing,

    #[error("tunnel secret is missing for the requested tunnel config")]
    TunnelSecretMissing,

    #[error("SSH password is required (inline password or credential_id)")]
    PasswordRequired,

    #[error("connection node is missing required fields for a session profile")]
    IncompleteNode,

    #[error("SSH over tunnel requires a SOCKS5 endpoint on the lease")]
    TunnelSocksRequired,

    #[error("serial: {0}")]
    Serial(#[from] wormhole_serial::SerialError),

    #[error("ssh: {0}")]
    Ssh(#[from] wormhole_ssh::SshError),

    #[error("http: {0}")]
    Http(#[from] wormhole_http::HttpError),

    #[error("tunnel: {0}")]
    Tunnel(#[from] wormhole_tunnels::TunnelError),

    #[error("invalid port {0}")]
    InvalidPort(i32),

    #[error("{0}")]
    Other(String),
}

impl SessionError {
    /// True when the failure is a cooperative cancel (caller cancelled the token).
    pub fn is_cancelled(&self) -> bool {
        matches!(
            self,
            Self::Cancelled | Self::Tunnel(wormhole_tunnels::TunnelError::Cancelled)
        )
    }
}
