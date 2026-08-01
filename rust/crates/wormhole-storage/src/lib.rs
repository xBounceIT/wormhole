//! SQLite persistence for the Wormhole Rust migration.
//!
//! Mirrors the C# stack in `Data/` + `Services/AppSettingsService`:
//! - [`SqliteConnectionFactory`] -- one connection per operation (pooling via rusqlite defaults)
//! - [`MigrationRunner`] -- embedded `Data/Migrations/*.sql`, alphabetical, `__migration_history`
//! - [`ConnectionRepository`] -- read/write path for connection / folder nodes
//!   (including folder CRUD + connection reparent / duplicate stubs)
//! - [`TunnelConfigRepository`] -- tunnel metadata rows (secrets stay DPAPI / out-of-band)
//! - [`CredentialRepository`] + [`credential_glue`] -- credential profile metadata CRUD
//!   (passwords stay CredMgr / Fake stubs; never in SQLite)
//! - [`BitwardenCredentialCacheRepository`] -- Bitwarden login display cache (SQLite +
//!   [`FakeBitwardenCredentialCacheRepository`]; metadata + virtual ids only; the entry
//!   type lives in `wormhole_secrets_win`)
//! - [`SettingsStore`] -- `%LOCALAPPDATA%\Wormhole\settings.json` (fail closed on corrupt JSON)
//!
//! Domain row shapes come from [`wormhole_domain`]. GUID columns use .NET format `D`
//! strings; timestamps use .NET round-trip `O` text.

mod connection;
pub mod credential_glue;
mod error;
mod migrate;
mod models;
mod repos;
mod settings;
mod types;

pub use connection::SqliteConnectionFactory;
pub use credential_glue::{
    CredentialProfileDraft, CredentialSecrets, MemoryCredentialSecrets, create_credential_profile,
    delete_credential_profile, rename_credential_profile,
};
pub use error::{Result, StorageError};
pub use migrate::{Migration, MigrationRunner, embedded_migrations};
pub use models::{CredentialProfile, StoredConnectionNode, TunnelConfig};
pub use repos::{
    BitwardenCredentialCacheRepository, ConnectionRepository, CredentialRepository,
    FakeBitwardenCredentialCacheRepository, SqliteBitwardenCredentialCacheRepository,
    TunnelConfigRepository,
};
pub use settings::{
    AppAuthenticationFallbackMethod, AppAuthenticationMode, AppSettings, ApplicationTheme,
    BITWARDEN_ONBOARDING_INTRODUCED_SCHEMA_VERSION, BitwardenBrowserExtensionSource,
    BitwardenCliServerRegion, CURRENT_SCHEMA_VERSION, SettingsStore, default_app_data_dir,
    default_settings_path,
};
pub use types::{format_guid_d, format_timestamp_o, parse_guid_d, parse_timestamp_o};

// Re-export domain types commonly needed by storage callers.
pub use wormhole_domain::{
    BITWARDEN_PASSWORD_FIELD_PATH, ConnectionNode, CredentialBindingMode, CredentialKind,
    CredentialSecretProvider, NodeKind, ProtocolType, SerialFlowControlMode, SerialParityMode,
    SerialStopBitsMode, TunnelKind,
};
