//! Pure connection-editor dialog state machine (no GPUI).
//!
//! Mirrors `ConnectionEditorViewModel` / `NewConnectionDialog` concepts using
//! `wormhole-domain` types. See `docs/migration/20-connection-editor.md`.

mod host_spec;
mod http_address;
#[cfg(feature = "storage")]
mod persist;
mod rdp_drives;
mod state;
mod tunnel;
mod validation;
mod visible;

#[cfg(feature = "storage")]
pub use persist::{
    load_inline_secret, save_validated_editor, EditorSaveError, EditorSaveOp, EditorSaveResult,
};
pub(crate) use http_address::{format_http_address, parse_http_address};
pub use state::{
    ConnectionEditorMode, ConnectionEditorState, CredentialUiMode, RdpDriveRedirectMode,
    SshAutoSudoMode, WriteOptions,
};
pub use tunnel::{TunnelUiSelection, TunnelUiState};
pub use validation::{ValidationError, ValidationReport};
pub use visible::VisibleFields;
