//! Serialized SFTP session + transfer queue for Wormhole.
//!
//! Mirrors C# `ISftpSession` / `FileTransferOrchestrator`: **one SFTP op at a time
//! per session**. File-transfer dialog glue opens from a connected SSH context and
//! wires SOCKS select + the cancel/single-flight queue. Progress callback glue
//! normalizes cumulative byte reports for the transfer strip. Conflict overlay
//! policy glue maps exists → Skip/Overwrite/Rename/Cancel (Fake; no GPUI).
//! Prewarm / tunnel-borrow Fake glue caches a Fake SFTP handle on SSH Connected.
//! See `docs/migration/11-sftp.md`.

mod conflict;
mod dialog;
mod entry;
mod error;
mod fake;
mod ops;
mod path;
mod prewarm;
mod progress;
mod queue;
mod session;
mod transport;

#[cfg(feature = "russh")]
mod russh_backend;

pub use conflict::{
    apply_conflict_choice, resolve_conflict_overlay, suggest_rename_name,
    validate_conflict_context, ConflictChoice, ConflictContext, ConflictDecision,
    ConflictOutcome, ConflictOverlayError, ConflictOverlayPrompt, FakeConflictOverlay,
};
pub use dialog::{
    open_from_ssh_session, open_with_fake, ConnectedSshContext, FileTransferDialogState,
};
pub use entry::SftpEntry;
pub use error::SftpError;
pub use fake::FakeSftpBackend;
pub use ops::SftpOps;
pub use path::{is_safe_remote_name, remote_join};
pub use prewarm::{
    BorrowedShellTunnel, FakePrewarmConnectMode, FakePrewarmedSftp, FakeShellTunnel,
    PrewarmToken, PrewarmedSftpPair, SftpPrewarmGlue,
};
pub use progress::{
    report_progress, report_to_callback, run_fake_transfer, RecordingProgressCallback,
    TransferProgress, TransferProgressCallback, TransferProgressError,
};
pub use queue::{
    TransferDirection, TransferItem, TransferJob, TransferQueue, TransferRequest, TransferStatus,
};
pub use session::SerializedSftpSession;
pub use transport::{
    select_sftp_transport, FakeTunnelSocks, Socks5Endpoint, SftpTransport, TunnelSocksSource,
};

#[cfg(feature = "russh")]
pub use russh_backend::RusshSftpMarker;

/// Crate-level result alias.
pub type Result<T> = std::result::Result<T, SftpError>;
