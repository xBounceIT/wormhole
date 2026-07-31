use thiserror::Error;

#[derive(Debug, Error)]
pub enum TunnelError {
    #[error("no tunnel provider registered for kind '{0:?}'")]
    NoProvider(crate::TunnelKind),
    /// TunnelConfigs metadata row missing for the requested id (fail-closed).
    #[error("tunnel config not found: {id}")]
    ConfigNotFound {
        id: uuid::Uuid,
    },
    /// DPAPI / secret store returned no payload for the config id (fail-closed).
    #[error("tunnel secret missing for config: {id}")]
    SecretMissing {
        id: uuid::Uuid,
    },
    /// Config or provider kind does not match the establish path (e.g. WireGuard glue).
    #[error("tunnel kind mismatch: expected {expected:?}, got {actual:?}")]
    WrongKind {
        expected: crate::TunnelKind,
        actual: crate::TunnelKind,
    },
    #[error("tunnel establishment failed: {0}")]
    Establish(String),
    #[error("tunnel establishment cancelled")]
    Cancelled,
    #[error(
        "tunnel provider for {kind:?} is not implemented in the skeleton (sidecar: {sidecar})"
    )]
    NotImplemented {
        kind: crate::TunnelKind,
        sidecar: &'static str,
    },
    /// Sidecar `.exe` missing — never treat this as a successful Connected/Up tunnel.
    #[error("sidecar binary '{binary}' not found; searched: {searched:?}")]
    BinaryNotFound {
        binary: String,
        searched: Vec<String>,
    },
    #[error("tunnel has no SOCKS5 endpoint to bind a local forwarder through")]
    NoSocksEndpoint,
    #[error("tunnel is not available for bind (state={state:?})")]
    TunnelUnavailable { state: crate::TunnelState },
    #[error("invalid forwarder target {host}:{port}: {reason}")]
    InvalidTarget {
        host: String,
        port: u16,
        reason: String,
    },
    #[error("SOCKS5: {0}")]
    Socks5(String),
    #[error("local forwarder: {0}")]
    Forwarder(String),
    #[error(transparent)]
    Other(#[from] Box<dyn std::error::Error + Send + Sync>),
}
