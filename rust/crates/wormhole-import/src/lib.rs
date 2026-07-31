//! mRemoteNG import + Wormhole backup envelope spike for the Rust migration.
//!
//! Mirrors `Services/MRemoteNg/*` (XML parse + SSH/RDP/VNC planning) and the
//! lightweight `Models/Backup` document envelope. Password decrypt uses
//! AES-256-GCM with mRemoteNG's **16-byte nonce** — see
//! [`crypto::decrypt_password_utf8`] and `docs/migration/12-import.md`.
//!
//! With the `storage` feature (default), [`apply_import_plan`] writes planned
//! nodes through [`wormhole_storage::ConnectionRepository`] (transactional
//! batch; Credential Manager still stubbed). Soft-skips surface as a secrets-free
//! [`ImportSkipReport`] via [`report_unsupported_skips`] (Fake reporter; no GPUI).

mod backup;
mod crypto;
mod error;
mod limits;
mod mremoteng;
mod protocol;
mod skip_report;

#[cfg(feature = "storage")]
mod apply;

#[cfg(feature = "storage")]
pub use apply::{
    apply_connection_nodes, apply_import_plan, planned_to_connection_node, ApplyImportResult,
};
pub use backup::{
    encryption as BackupEncryption, inspect_backup_json, inspect_backup_path, BackupDocument,
    BackupEncryptedPayload, BackupInspectResult, BackupPayload, CURRENT_SCHEMA_VERSION,
};
pub use crypto::{decrypt_password_utf8, DecryptError};
pub use error::ImportError;
pub use limits::{
    ensure_file_size_acceptable, validate_user_path, MAX_IMPORT_FILE_BYTES, MAX_NODE_COUNT,
};
pub use mremoteng::{
    inspect_xml, parse_xml, parse_xml_bytes, parse_xml_path, plan_nodes, ImportPlan,
    MRemoteNgFileInfo, MRemoteNgRawNode, MRemoteNgRoot, PlannedNode, MAX_NESTING_DEPTH,
    PROTECTED_VERIFIER,
};
pub use protocol::{map_protocol, try_map_protocol, MappedProtocol};
pub use skip_report::{
    format_skip_summary, report_unsupported_skips, FakeImportSkipReporter, ImportSkipReport,
    UnsupportedProtocolSkip, UNSUPPORTED_PROTOCOL_REASON,
};
