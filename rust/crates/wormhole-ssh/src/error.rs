use thiserror::Error;

/// SSH spike errors.
#[derive(Debug, Error)]
pub enum SshError {
    #[error("SSH feature `client` is disabled in this build")]
    ClientFeatureDisabled,
    #[error("SSH I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[cfg(feature = "client")]
    #[error("russh error: {0}")]
    Russh(#[from] russh::Error),
    #[error("authentication failed")]
    AuthFailed,
    #[error("SSH auth method not implemented: {0}")]
    AuthNotImplemented(&'static str),
    #[error("failed to load private key: {0}")]
    PrivateKeyLoad(String),
    #[error("SSH host key mismatch for {host}: expected {expected}, got {actual}")]
    HostKeyMismatch {
        host: String,
        expected: String,
        actual: String,
    },
    /// User (or [`NullHostKeyPrompt`](crate::NullHostKeyPrompt)) rejected an **unknown**
    /// host key — fail closed. `fingerprint` is the captured SHA256 pin only (never raw
    /// key bytes). Reject of a **changed** key uses [`Self::HostKeyMismatch`] so the
    /// UI keeps expected vs actual.
    #[error("SSH host key rejected for {host} ({reason})")]
    HostKeyRejected {
        host: String,
        /// Always `"unknown"` today (changed → [`Self::HostKeyMismatch`]).
        reason: &'static str,
        fingerprint: String,
    },
    #[error("SOCKS5 transport not implemented yet (hook point only): {0}")]
    Socks5NotImplemented(String),
    #[error("{0}")]
    Other(String),
}
