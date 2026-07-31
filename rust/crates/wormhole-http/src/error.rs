use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum HttpError {
    #[error("host must not be empty")]
    EmptyHost,

    #[error("host is malformed or contains forbidden characters")]
    InvalidHost,

    #[error("scheme must be http or https")]
    InvalidScheme,

    #[error("port must be in 1..=65535, got {0}")]
    InvalidPort(i32),

    /// Navigate URI missing — fail closed before Fake / live WebView navigate.
    #[error("navigate URI must not be empty")]
    EmptyNavigateUri,

    /// Bitwarden extension WebView2 profiles are HTTPS-only (logical target).
    #[error("Bitwarden browser profiles require an HTTPS logical target")]
    BitwardenRequiresHttps,

    /// Empty / whitespace path rejected before Fake wipe or profile join.
    #[error("path must not be empty")]
    EmptyPath,

    /// Isolated `env-<id>` segment missing or not a single relative folder name.
    #[error("isolated profile id must not be empty")]
    EmptyIsolatedId,

    /// Fake store refused identical web + Bitwarden roots (wipe would be unsafe).
    #[error("web browser and Bitwarden profile roots must differ")]
    WebProfileRootCollision,
}