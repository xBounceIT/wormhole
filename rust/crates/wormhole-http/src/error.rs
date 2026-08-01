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

    /// Refused identical or nested web + Bitwarden roots (a wipe would otherwise
    /// reach the persistent Bitwarden storage).
    #[error("web browser and Bitwarden profile roots must differ")]
    WebProfileRootCollision,

    /// Web profile path escaped the web root (`..`, absolute, empty) — rejected
    /// before any wipe IO. Never embeds the offending path.
    #[error("web browser profile path is not confined under the web root")]
    UnsafeProfilePath,

    /// Injectable web-profile filesystem operation failed (IO / confinement / not found).
    #[error("web profile filesystem: {0}")]
    ProfileFs(crate::profile_fs::ProfileFsError),
}

impl From<crate::profile_fs::ProfileFsError> for HttpError {
    fn from(value: crate::profile_fs::ProfileFsError) -> Self {
        HttpError::ProfileFs(value)
    }
}
