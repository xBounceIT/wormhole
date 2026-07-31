use std::fmt;

use thiserror::Error;

#[derive(Error)]
pub enum SftpError {
    #[error("SFTP session is closed")]
    Closed,
    /// File-transfer dialog opened without a Connected SSH tab (C# `CanOpenFileTransfer`).
    #[error("file transfer requires a connected SSH session")]
    SshSessionRequired,
    #[error("SFTP path not found: {0}")]
    NotFound(String),
    #[error("unsafe remote name rejected: {0}")]
    UnsafeName(String),
    /// Tunnel lease present but no SOCKS5 endpoint (C# `SftpService` fail-closed).
    #[error("SFTP over tunnel requires a SOCKS5 endpoint on the lease")]
    TunnelSocksRequired,
    /// SOCKS listener port must be non-zero.
    #[error("invalid SOCKS5 port {0}")]
    InvalidSocksPort(u16),
    /// Free-form op failure. Display/Debug are redacted; see [`Self::public_message`].
    #[error("SFTP operation failed: {msg}", msg = redact_secretish(.0))]
    Operation(String),
    /// Transport/backend failure. Display/Debug never echo the payload (may hold secrets).
    #[error("SFTP backend error")]
    Backend(String),
}

impl fmt::Debug for SftpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => f.write_str("Closed"),
            Self::SshSessionRequired => f.write_str("SshSessionRequired"),
            Self::NotFound(path) => f.debug_tuple("NotFound").field(path).finish(),
            Self::UnsafeName(name) => f.debug_tuple("UnsafeName").field(name).finish(),
            Self::TunnelSocksRequired => f.write_str("TunnelSocksRequired"),
            Self::InvalidSocksPort(port) => f.debug_tuple("InvalidSocksPort").field(port).finish(),
            Self::Operation(msg) => f
                .debug_tuple("Operation")
                .field(&redact_secretish(msg))
                .finish(),
            Self::Backend(_) => f.write_str("Backend([redacted])"),
        }
    }
}

impl SftpError {
    /// Human-readable message safe for transfer-strip / UI surfaces.
    ///
    /// Never echoes raw [`Self::Backend`] payloads (may contain transport noise or
    /// credential material from lower layers). Paths and unsafe names are kept —
    /// they are not secrets.
    pub fn public_message(&self) -> String {
        match self {
            Self::Closed => "SFTP session is closed".into(),
            Self::SshSessionRequired => "file transfer requires a connected SSH session".into(),
            Self::NotFound(path) => format!("SFTP path not found: {path}"),
            Self::UnsafeName(name) => format!("unsafe remote name rejected: {name}"),
            Self::TunnelSocksRequired => {
                "SFTP over tunnel requires a SOCKS5 endpoint on the lease".into()
            }
            Self::InvalidSocksPort(port) => format!("invalid SOCKS5 port {port}"),
            Self::Operation(msg) => format!("SFTP operation failed: {}", redact_secretish(msg)),
            Self::Backend(_) => "SFTP backend error".into(),
        }
    }
}

/// Strip common credential-shaped tokens from free-form operation messages.
fn redact_secretish(msg: &str) -> String {
    // Conservative: if a message looks like it embeds password/key material, truncate
    // to a generic label rather than echo it into the transfer strip.
    let lower = msg.to_ascii_lowercase();
    const MARKERS: &[&str] = &[
        "password",
        "passwd",
        "private_key",
        "private-key",
        "passphrase",
        "secret",
        "token",
        "credential",
    ];
    if MARKERS.iter().any(|m| lower.contains(m)) {
        "[redacted]".into()
    } else {
        msg.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_public_message_hides_payload() {
        let err = SftpError::Backend("auth failed password=hunter2".into());
        let msg = err.public_message();
        assert_eq!(msg, "SFTP backend error");
        assert!(!msg.contains("hunter2"));
        // Display must also hide the payload.
        assert_eq!(format!("{err}"), "SFTP backend error");
        assert!(!format!("{err}").contains("hunter2"));
        assert!(!format!("{err:?}").contains("hunter2"));
        assert!(format!("{err:?}").contains("redacted"));
    }

    #[test]
    fn operation_public_message_redacts_passwordish() {
        let err = SftpError::Operation("upload failed password=hunter2".into());
        assert_eq!(err.public_message(), "SFTP operation failed: [redacted]");
        assert_eq!(format!("{err}"), "SFTP operation failed: [redacted]");
        assert!(!format!("{err:?}").contains("hunter2"));
    }

    #[test]
    fn not_found_keeps_path() {
        let err = SftpError::NotFound("/home/user/a.txt".into());
        assert!(err.public_message().contains("/home/user/a.txt"));
    }
}
