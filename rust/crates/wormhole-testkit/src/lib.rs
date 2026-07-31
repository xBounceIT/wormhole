//! Shared test helpers / fixture paths for Wormhole Rust crates.
//!
//! Fixtures under `fixtures/` are schema-only (no secrets, no real connection data).

use std::path::{Path, PathBuf};

/// Absolute path to this crate's `fixtures/` directory.
pub fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

/// Path to the empty anonymized Wormhole schema SQLite file (`empty-schema.db`).
///
/// Schema matches `Data/Migrations` through `0015_bitwarden_credential_cache` with
/// `__migration_history` populated. Contains no rows with secrets or real hosts.
pub fn empty_schema_db() -> PathBuf {
    fixtures_dir().join("empty-schema.db")
}

/// Synthetic mRemoteNG-shaped XML export (`mremoteng-sample.xml`).
///
/// Uses documentation-range hosts (`192.0.2.0/24`) and empty / placeholder
/// password fields — no real credentials.
pub fn mremoteng_sample_xml() -> PathBuf {
    fixtures_dir().join("mremoteng-sample.xml")
}
