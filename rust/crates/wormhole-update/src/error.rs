//! Update check / download errors (never embed secret material).

use std::fmt;

/// Crate-level result alias.
pub type Result<T> = std::result::Result<T, UpdateError>;

/// Cap attacker-controlled strings embedded in errors (version tags, URLs, names).
const ERR_CTX_MAX: usize = 256;

/// Failures from version parse, check stubs, download, or hash verify.
#[derive(Debug)]
pub enum UpdateError {
    /// Tag / version string could not be parsed (System.Version parity).
    InvalidVersion(String),
    /// Repository URL is missing or not a GitHub URL.
    InvalidRepository(String),
    /// Expected SHA-256 did not match computed digest.
    Sha256Mismatch {
        /// Expected lowercase hex.
        expected: String,
        /// Computed lowercase hex.
        computed: String,
    },
    /// SHA-256 sidecar / expected digest was malformed.
    InvalidSha256(String),
    /// Changelog / release metadata fetch is stubbed / not implemented.
    ChangelogFetchStub,
    /// Live GitHub `releases/latest` check is stubbed (no HTTP in this crate).
    CheckNetworkStub,
    /// Download path is stubbed (no live HTTP in this crate).
    DownloadStub,
    /// Installer file name contained path separators or `..`.
    UnsafeFileName(String),
    /// Installer / release URL used a disallowed scheme (e.g. `file://`).
    DisallowedUrl(String),
    /// In-memory installer payload exceeded the fail-closed size cap.
    InstallerTooLarge {
        /// Observed byte length.
        size: usize,
        /// Configured maximum.
        max: usize,
    },
    /// Installer flow precondition not met (nothing staged / wrong stage).
    ///
    /// Returned when [`crate::UpdateInstallerGlue::verify`] /
    /// [`prepare_and_launch`](crate::UpdateInstallerGlue::prepare_and_launch) is
    /// driven out of sequence — fail closed, never launch from the wrong stage.
    InstallerNotStaged,
    /// Live installer launch failed (host's `Process.Start` wrapper returned an error).
    ///
    /// The glue transitions to a `LaunchFailed` phase and **never reports success**.
    InstallerLaunchFailed(String),
    /// The Bitwarden-flush / session-close hook before launch failed
    /// (C# `PrepareForProcessExitAsync`). Aborts **before** launching.
    PrepareForInstallFailed(String),
    /// Filesystem I/O while writing the installer temp / cache file.
    Io(std::io::Error),
}

impl UpdateError {
    /// Truncate attacker-controlled context for safe embedding in error variants.
    pub(crate) fn clip_ctx(s: &str) -> String {
        match s.char_indices().nth(ERR_CTX_MAX) {
            None => s.to_string(),
            Some((idx, _)) => format!("{}…", &s[..idx]),
        }
    }
}

impl fmt::Display for UpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidVersion(s) => write!(f, "invalid version tag: {s}"),
            Self::InvalidRepository(s) => write!(f, "invalid repository URL: {s}"),
            Self::Sha256Mismatch { expected, computed } => {
                write!(f, "SHA-256 mismatch: expected {expected}, got {computed}")
            }
            Self::InvalidSha256(s) => write!(f, "invalid SHA-256 digest: {s}"),
            Self::ChangelogFetchStub => {
                write!(f, "changelog fetch is a stub (no HTTP in wormhole-update)")
            }
            Self::CheckNetworkStub => {
                write!(
                    f,
                    "live update check is a stub (no HTTP; use NetworkStubUpdateChecker / FakeUpdateChecker)"
                )
            }
            Self::DownloadStub => {
                write!(f, "live installer download is a stub (use download_bytes_to_temp)")
            }
            Self::UnsafeFileName(s) => write!(f, "unsafe installer file name: {s}"),
            Self::DisallowedUrl(s) => write!(f, "disallowed update URL scheme/host: {s}"),
            Self::InstallerTooLarge { size, max } => {
                write!(f, "installer payload too large: {size} bytes (max {max})")
            }
            Self::InstallerNotStaged => {
                write!(f, "installer flow is not in the expected stage (not staged yet or wrong phase)")
            }
            Self::InstallerLaunchFailed(s) => write!(f, "failed to launch installer: {s}"),
            Self::PrepareForInstallFailed(s) => write!(f, "failed to prepare for install: {s}"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for UpdateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for UpdateError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clip_ctx_caps_long_attacker_strings() {
        let long: String = std::iter::repeat_n('a', ERR_CTX_MAX + 50).collect();
        let clipped = UpdateError::clip_ctx(&long);
        assert!(clipped.chars().count() <= ERR_CTX_MAX + 1); // + ellipsis
        assert!(clipped.ends_with('…'));
    }
}
