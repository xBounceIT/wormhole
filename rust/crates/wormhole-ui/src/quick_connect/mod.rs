//! Quick Connect pure state / validation (no GPUI).
//!
//! Mirrors `Views/Controls/QuickConnectBar` + `DialogService.PromptQuickConnectCoreAsync`
//! + `QuickConnectViewModel` accept path: seed → edit → validate → ephemeral node/profile.
//! Full multi-tab field editing is delegated to [`crate::connection_editor`].
//!
//! Session-orchestrator connect glue (Fake-friendly, no GPUI) lives in [`session_connect`]
//! behind `--features session`. Recent-history MRU glue (Fake store) lives in [`history`].
//!
//! See `docs/migration/21-quick-connect.md` and `docs/migration/16-session-orchestrator.md`.

mod history;
#[cfg(feature = "session")]
mod session_connect;
mod state;

pub use history::{
    FakeQuickConnectHistoryStore, QuickConnectHistoryEntry, QuickConnectHistoryError,
    QuickConnectHistoryKey, QuickConnectHistoryStore, QuickConnectHistoryVm,
    DEFAULT_HISTORY_CAPACITY,
};
#[cfg(feature = "session")]
pub use session_connect::{
    connect_prepared, connect_quick_connect, prepare_connect, prepare_connect_ephemeral,
    QuickConnectConnectRequest,
};
pub use state::{
    default_port, protocol_picker, seed_connection_node, BuildError, QuickConnectResult,
    QuickConnectState, TargetField, PROTOCOL_PICKER,
};
