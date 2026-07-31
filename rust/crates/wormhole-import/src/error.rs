//! Import / backup errors.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ImportError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("XML error: {0}")]
    Xml(String),
    #[error("{0}")]
    InvalidData(String),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    /// mRemoteNG connection protocol is not imported (HTTP / HTTPS / Serial / Telnet / others).
    ///
    /// Planning soft-skips these leaves (`ImportPlan.skipped`); this variant is the
    /// explicit classification returned by [`crate::try_map_protocol`]. It does **not**
    /// abort [`crate::plan_nodes`] for Connection leaves.
    #[error(
        "unsupported mRemoteNG protocol '{0}' (import supports SSH, RDP, and VNC only; \
         HTTP, HTTPS, Serial, Telnet, and other protocols are not mapped)"
    )]
    UnsupportedProtocol(String),
    #[error(transparent)]
    Decrypt(#[from] crate::crypto::DecryptError),
    /// SQLite / repository failure while applying an import plan.
    #[cfg(feature = "storage")]
    #[error(transparent)]
    Storage(#[from] wormhole_storage::StorageError),
}
