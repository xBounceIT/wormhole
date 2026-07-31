//! Credential profile metadata repository (SQLite only — no password bodies).
//!
//! Mirrors C# `Data/Repositories/CredentialRepository.cs`. Passwords live in
//! CredMgr (`Wormhole:<guid:D>`); private-key bytes live under `keys\` DPAPI —
//! both out of band. See [`crate::credential_glue`] for create/rename/delete
//! helpers + Memory secret-cleanup stubs.

use chrono::{DateTime, Utc};
use rusqlite::{params, OptionalExtension, Row};
use uuid::Uuid;
use wormhole_domain::{
    CredentialKind, CredentialSecretProvider, ProtocolType, BITWARDEN_PASSWORD_FIELD_PATH,
};

use crate::models::CredentialProfile;
use crate::types::{format_guid_d, format_timestamp_o, parse_guid_d, parse_timestamp_o};
use crate::{Result, SqliteConnectionFactory, StorageError};

/// Canonical SELECT/INSERT column list — mirrors C# `CredentialRepository.SelectColumns`.
/// Metadata only (never password / key material columns).
const SELECT_COLUMNS: &str = "Id, Name, Username, Domain, Kind, PrivateKeyFileName, Protocol, \
        SecretProvider, BitwardenItemId, BitwardenItemName, BitwardenFieldPath, CreatedAt";

/// Access to the `CredentialProfiles` table (metadata only).
pub struct CredentialRepository<'a> {
    factory: &'a SqliteConnectionFactory,
}

impl<'a> CredentialRepository<'a> {
    pub fn new(factory: &'a SqliteConnectionFactory) -> Self {
        Self { factory }
    }

    /// All credential profiles ordered by `Name` (same as C# `GetAllAsync`).
    pub fn list_all(&self) -> Result<Vec<CredentialProfile>> {
        let conn = self.factory.open()?;
        let sql = format!("SELECT {SELECT_COLUMNS} FROM CredentialProfiles ORDER BY Name;");
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], map_credential_profile)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Lookup by primary key (format-`D` GUID string in SQLite).
    ///
    /// Comparison is ASCII case-insensitive (same rationale as
    /// [`crate::ConnectionRepository::get_by_id`]).
    pub fn get_by_id(&self, id: Uuid) -> Result<Option<CredentialProfile>> {
        let conn = self.factory.open()?;
        let sql =
            format!("SELECT {SELECT_COLUMNS} FROM CredentialProfiles WHERE Id = ?1 COLLATE NOCASE;");
        let mut stmt = conn.prepare(&sql)?;
        let id_text = format_guid_d(id);
        Ok(stmt
            .query_row(params![id_text], map_credential_profile)
            .optional()?)
    }

    /// Insert a metadata row. Stamps `CreatedAt` to UTC now (format `O`).
    ///
    /// Name is trimmed; blank / whitespace-only names are rejected (`InvalidArgument`).
    /// Does **not** write any password or private-key bytes — CredMgr / DPAPI stay out of band.
    /// Blank / whitespace `BitwardenFieldPath` normalizes to [`BITWARDEN_PASSWORD_FIELD_PATH`];
    /// non-blank paths are trimmed (C# `NormalizeBitwardenFieldPath`).
    pub fn insert(&self, mut profile: CredentialProfile) -> Result<CredentialProfile> {
        profile.name = require_nonblank_credential_name(&profile.name)?;
        profile.bitwarden_field_path =
            Some(normalize_bitwarden_field_path(profile.bitwarden_field_path.as_deref()));
        profile.created_at = Utc::now();

        let conn = self.factory.open()?;
        let sql = format!(
            "INSERT INTO CredentialProfiles ({SELECT_COLUMNS})
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12);"
        );
        conn.execute(
            &sql,
            params![
                format_guid_d(profile.id),
                profile.name,
                profile.username,
                profile.domain,
                profile.kind.as_i32(),
                profile.private_key_file_name,
                profile.protocol.as_i32(),
                profile.secret_provider.as_i32(),
                profile.bitwarden_item_id,
                profile.bitwarden_item_name,
                profile.bitwarden_field_path,
                format_timestamp_o(profile.created_at),
            ],
        )?;
        Ok(profile)
    }

    /// Persist metadata fields except `Id` / `CreatedAt` (C# `UpdateAsync` parity).
    ///
    /// Name is trimmed; blank names are rejected. `BitwardenFieldPath` blank/whitespace
    /// → [`BITWARDEN_PASSWORD_FIELD_PATH`]; non-blank paths trimmed. Does **not** touch
    /// CredMgr / DPAPI.
    pub fn update(&self, profile: &CredentialProfile) -> Result<()> {
        let name = require_nonblank_credential_name(&profile.name)?;
        let field_path = normalize_bitwarden_field_path(profile.bitwarden_field_path.as_deref());
        let conn = self.factory.open()?;
        conn.execute(
            "UPDATE CredentialProfiles SET
                Name = ?1,
                Username = ?2,
                Domain = ?3,
                Kind = ?4,
                PrivateKeyFileName = ?5,
                Protocol = ?6,
                SecretProvider = ?7,
                BitwardenItemId = ?8,
                BitwardenItemName = ?9,
                BitwardenFieldPath = ?10
             WHERE Id = ?11 COLLATE NOCASE;",
            params![
                name,
                profile.username,
                profile.domain,
                profile.kind.as_i32(),
                profile.private_key_file_name,
                profile.protocol.as_i32(),
                profile.secret_provider.as_i32(),
                profile.bitwarden_item_id,
                profile.bitwarden_item_name,
                field_path,
                format_guid_d(profile.id),
            ],
        )?;
        Ok(())
    }

    /// Delete a credential profile metadata row by id.
    ///
    /// **Fail-open on in-use profiles:** does **not** check `Nodes.CredentialId` /
    /// `RdpGatewayCredentialId`, does not delete CredMgr / DPAPI secrets, and succeeds
    /// (or silently affects 0 rows) even if connections still reference the id.
    /// Matching C# `CredentialRepository.DeleteAsync` — callers that own secret cleanup
    /// should use [`crate::credential_glue::delete_credential_profile`].
    pub fn delete(&self, id: Uuid) -> Result<()> {
        let conn = self.factory.open()?;
        conn.execute(
            "DELETE FROM CredentialProfiles WHERE Id = ?1 COLLATE NOCASE;",
            params![format_guid_d(id)],
        )?;
        Ok(())
    }
}

fn require_nonblank_credential_name(name: &str) -> Result<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(StorageError::InvalidArgument(
            "credential profile name must be non-blank".into(),
        ));
    }
    Ok(trimmed.to_owned())
}

/// Blank / whitespace → [`BITWARDEN_PASSWORD_FIELD_PATH`]; otherwise trim
/// (C# `CredentialsViewModel.NormalizeBitwardenFieldPath`).
///
/// Always returns a concrete path — column is `NOT NULL` with the same default.
fn normalize_bitwarden_field_path(path: Option<&str>) -> String {
    match path {
        None => BITWARDEN_PASSWORD_FIELD_PATH.to_owned(),
        Some(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                BITWARDEN_PASSWORD_FIELD_PATH.to_owned()
            } else {
                trimmed.to_owned()
            }
        }
    }
}

fn map_credential_profile(row: &Row<'_>) -> rusqlite::Result<CredentialProfile> {
    let kind_i32: i32 = row.get("Kind")?;
    let kind = CredentialKind::try_from(kind_i32).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Integer,
            format!("unknown CredentialKind {kind_i32}: {e}").into(),
        )
    })?;
    let protocol_i32: i32 = row.get("Protocol")?;
    let protocol = ProtocolType::try_from(protocol_i32).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Integer,
            format!("unknown ProtocolType {protocol_i32}: {e}").into(),
        )
    })?;
    let provider_i32: i32 = row.get("SecretProvider")?;
    let secret_provider = CredentialSecretProvider::try_from(provider_i32).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Integer,
            format!("unknown CredentialSecretProvider {provider_i32}: {e}").into(),
        )
    })?;
    Ok(CredentialProfile {
        id: parse_guid_col(row, "Id")?,
        name: row.get("Name")?,
        username: row.get("Username")?,
        domain: row.get("Domain")?,
        kind,
        private_key_file_name: row.get("PrivateKeyFileName")?,
        protocol,
        secret_provider,
        bitwarden_item_id: row.get("BitwardenItemId")?,
        bitwarden_item_name: row.get("BitwardenItemName")?,
        bitwarden_field_path: row.get("BitwardenFieldPath")?,
        created_at: parse_ts_col(row, "CreatedAt")?,
    })
}

fn parse_guid_col(row: &Row<'_>, col: &str) -> rusqlite::Result<Uuid> {
    let s: String = row.get(col)?;
    parse_guid_d(&s).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })
}

fn parse_ts_col(row: &Row<'_>, col: &str) -> rusqlite::Result<DateTime<Utc>> {
    let s: String = row.get(col)?;
    parse_timestamp_o(&s).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })
}
