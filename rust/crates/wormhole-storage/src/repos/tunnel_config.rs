//! Tunnel config metadata repository (SQLite only — no secret payloads).
//!
//! Mirrors C# `Data/Repositories/TunnelConfigRepository.cs`. Secrets stay
//! DPAPI-encrypted under `%LOCALAPPDATA%\Wormhole\tunnels\` (out of band).

use chrono::{DateTime, Utc};
use rusqlite::{params, OptionalExtension, Row};
use uuid::Uuid;
use wormhole_domain::TunnelKind;

use crate::models::TunnelConfig;
use crate::types::{format_guid_d, format_timestamp_o, parse_guid_d, parse_timestamp_o};
use crate::{Result, SqliteConnectionFactory, StorageError};

/// Canonical SELECT/INSERT column list — mirrors C# `TunnelConfigRepository.SelectColumns`.
/// Metadata only (never secret columns). `update` sets Name/Kind/UpdatedAt only.
const SELECT_COLUMNS: &str = "Id, Name, Kind, CreatedAt, UpdatedAt";

/// Access to the `TunnelConfigs` table (metadata only).
pub struct TunnelConfigRepository<'a> {
    factory: &'a SqliteConnectionFactory,
}

impl<'a> TunnelConfigRepository<'a> {
    pub fn new(factory: &'a SqliteConnectionFactory) -> Self {
        Self { factory }
    }

    /// All tunnel configs ordered by `Name` (same as C# `GetAllAsync`).
    pub fn list_all(&self) -> Result<Vec<TunnelConfig>> {
        let conn = self.factory.open()?;
        let sql = format!("SELECT {SELECT_COLUMNS} FROM TunnelConfigs ORDER BY Name;");
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], map_tunnel_config)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Lookup by primary key (format-`D` GUID string in SQLite).
    ///
    /// Comparison is ASCII case-insensitive (same rationale as
    /// [`crate::ConnectionRepository::get_by_id`]).
    pub fn get_by_id(&self, id: Uuid) -> Result<Option<TunnelConfig>> {
        let conn = self.factory.open()?;
        let sql = format!("SELECT {SELECT_COLUMNS} FROM TunnelConfigs WHERE Id = ?1 COLLATE NOCASE;");
        let mut stmt = conn.prepare(&sql)?;
        let id_text = format_guid_d(id);
        Ok(stmt
            .query_row(params![id_text], map_tunnel_config)
            .optional()?)
    }

    /// Insert a metadata row. Stamps `CreatedAt` / `UpdatedAt` to UTC now (format `O`).
    ///
    /// Name is trimmed; blank / whitespace-only names are rejected (`InvalidArgument`).
    /// Does **not** write any secret payload — DPAPI files are handled by secrets code.
    pub fn insert(&self, id: Uuid, name: &str, kind: TunnelKind) -> Result<TunnelConfig> {
        let name = require_nonblank_tunnel_name(name)?;
        let now = Utc::now();
        let config = TunnelConfig {
            id,
            name,
            kind,
            created_at: now,
            updated_at: now,
        };
        let conn = self.factory.open()?;
        let sql = format!(
            "INSERT INTO TunnelConfigs ({SELECT_COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5);"
        );
        conn.execute(
            &sql,
            params![
                format_guid_d(config.id),
                config.name,
                config.kind.as_i32(),
                format_timestamp_o(config.created_at),
                format_timestamp_o(config.updated_at),
            ],
        )?;
        Ok(config)
    }

    /// Persist `Name` / `Kind` / `UpdatedAt`. Leaves `CreatedAt` / `Id` unchanged.
    ///
    /// Persists the caller-supplied `UpdatedAt` **verbatim** — it does **not** stamp
    /// "now" itself. That timing is load-bearing: `TunnelManager`'s shared-tunnel pool
    /// snapshots `UpdatedAt` to detect config edits, and the edit must become visible
    /// to the pool only **after** the new DPAPI payload is on disk, or a connection
    /// starting mid-save would cache the old payload under the new timestamp. Editors
    /// write Name/Kind with the old stamp first, store the payload, then call
    /// [`update`] again with a freshly bumped `UpdatedAt` to publish the change.
    /// Auto-stamping "now" here would reintroduce that race (C# `UpdateAsync` parity).
    ///
    /// Name is trimmed before write; blank names are rejected.
    pub fn update(&self, config: &TunnelConfig) -> Result<()> {
        let name = require_nonblank_tunnel_name(&config.name)?;
        let conn = self.factory.open()?;
        conn.execute(
            "UPDATE TunnelConfigs SET
                Name = ?1,
                Kind = ?2,
                UpdatedAt = ?3
             WHERE Id = ?4 COLLATE NOCASE;",
            params![
                name,
                config.kind.as_i32(),
                format_timestamp_o(config.updated_at),
                format_guid_d(config.id),
            ],
        )?;
        Ok(())
    }

    /// Delete a tunnel config metadata row by id.
    ///
    /// **Fail-open on in-use configs:** does **not** check `Nodes.TunnelConfigId`, does
    /// not delete DPAPI secret files, and succeeds (or silently affects 0 rows) even if
    /// connections still reference the id. Matching C# `TunnelConfigRepository.DeleteAsync`
    /// — the editor / ViewModel must refuse delete when nodes still point here (see C#
    /// `TunnelConfigsViewModel.DeleteTunnelAsync` + `IX_Nodes_TunnelConfigId`).
    pub fn delete(&self, id: Uuid) -> Result<()> {
        let conn = self.factory.open()?;
        conn.execute(
            "DELETE FROM TunnelConfigs WHERE Id = ?1 COLLATE NOCASE;",
            params![format_guid_d(id)],
        )?;
        Ok(())
    }
}

fn require_nonblank_tunnel_name(name: &str) -> Result<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(StorageError::InvalidArgument(
            "tunnel config name must be non-blank".into(),
        ));
    }
    Ok(trimmed.to_owned())
}

fn map_tunnel_config(row: &Row<'_>) -> rusqlite::Result<TunnelConfig> {
    let kind_i32: i32 = row.get("Kind")?;
    let kind = TunnelKind::try_from(kind_i32).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Integer,
            format!("unknown TunnelKind {kind_i32}: {e}").into(),
        )
    })?;
    Ok(TunnelConfig {
        id: parse_guid_col(row, "Id")?,
        name: row.get("Name")?,
        kind,
        created_at: parse_ts_col(row, "CreatedAt")?,
        updated_at: parse_ts_col(row, "UpdatedAt")?,
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
