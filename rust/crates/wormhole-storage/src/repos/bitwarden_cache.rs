//! Bitwarden login display-cache repository (SQLite, metadata only).
//!
//! Mirrors C# `Data/Repositories/BitwardenCredentialCacheRepository.cs` +
//! `Models/BitwardenCredentialCacheEntry.cs` + the virtual-id ensure step from
//! `Services/Bitwarden/BitwardenVirtualCredentialIds.cs`. The canonical row type is
//! `wormhole_secrets_win::BitwardenCredentialCacheEntry` (stable SHA-256 virtual ids).
//!
//! | Input condition | Behavior |
//! |---|---|
//! | blank / whitespace `ItemId` | row dropped (**fail closed**, never an error) |
//! | blank `Name` | falls back to the trimmed `ItemId` |
//! | blank `Username` / `RevisionDate` | stored as `NULL` (`None`) |
//! | `LastSeenSyncUtc` / `UpdatedAtUtc` at the year-0001 sentinel (C# `default(DateTimeOffset)`) | replaced with the operation's sync time |
//! | duplicate `ItemId` (byte equality) | last occurrence wins |
//! | result ordering | by `Name`, byte order (C# `StringComparer.Ordinal` / SQL `ORDER BY Name`); equal `Name`s tie-break by `ItemId` (deterministic — C# leaves ties unspecified) |
//! | empty full-sync payload | `DELETE FROM BitwardenCredentialCache` (whole table) |
//! | SQL failure inside `replace_from_full_sync` | whole transaction rolls back |
//! | whitespace-only `ItemId` row read from DB | `get_all` fails closed (`StorageError`) — such rows are never written by this repo |
//!
//! Cache rows are display metadata + virtual credential ids only — **never** password
//! or private-key material, and nothing here logs entries. Hosts inject
//! [`FakeBitwardenCredentialCacheRepository`] for tests / labs (no live `bw` spawn).

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use rusqlite::{Row, params, params_from_iter};
use uuid::Uuid;
use wormhole_secrets_win::{BitwardenCredentialCacheEntry, ensure_cache_entry_ids};

use crate::types::{format_guid_d, format_timestamp_o, parse_guid_d, parse_timestamp_o};
use crate::{Result, SqliteConnectionFactory, StorageError};

/// Canonical SELECT/INSERT column list — mirrors C# `SelectColumns`.
/// Metadata only (no password / key material columns).
const SELECT_COLUMNS: &str = "ItemId, SshCredentialId, RdpCredentialId, VncCredentialId, \
        Name, Username, RevisionDate, LastSeenSyncUtc, UpdatedAtUtc";

/// C# `default(DateTimeOffset)` sentinel (year 0001) meaning "not assigned".
///
/// Entries carrying this value in `LastSeenSyncUtc` / `UpdatedAtUtc` get the
/// operation's sync time substituted (C# `Normalize`). Rows read back from SQLite
/// always carry real timestamps, so the sentinel only appears on caller-built entries.
const UNASSIGNED_TIMESTAMP: DateTime<Utc> = DateTime::<Utc>::MIN_UTC;

/// Repository for the Bitwarden display cache (C# `IBitwardenCredentialCacheRepository`).
pub trait BitwardenCredentialCacheRepository {
    /// All cache rows ordered by `Name` (byte order), with virtual ids ensured
    /// (C# `GetAllAsync`).
    fn get_all(&self) -> Result<Vec<BitwardenCredentialCacheEntry>>;

    /// Replace the whole cache from a full vault sync (C# `ReplaceFromFullSyncAsync`).
    ///
    /// Normalizes + upserts `entries`, then deletes stale rows: the entire table when
    /// `entries` normalizes to empty, otherwise every row whose `ItemId` is not kept.
    /// Runs in one transaction — any failure rolls the whole replacement back.
    fn replace_from_full_sync(
        &self,
        entries: &[BitwardenCredentialCacheEntry],
        sync_time_utc: DateTime<Utc>,
    ) -> Result<()>;

    /// Upsert imported entries only — never deletes stale rows (C# `UpsertImportedAsync`).
    ///
    /// Uses `Utc::now()` as the default sync time; empty input is a no-op.
    fn upsert_imported(&self, entries: &[BitwardenCredentialCacheEntry]) -> Result<()>;
}

/// SQLite-backed [`BitwardenCredentialCacheRepository`] (one connection per operation).
pub struct SqliteBitwardenCredentialCacheRepository<'a> {
    factory: &'a SqliteConnectionFactory,
}

impl<'a> SqliteBitwardenCredentialCacheRepository<'a> {
    /// Wrap a connection factory.
    pub fn new(factory: &'a SqliteConnectionFactory) -> Self {
        Self { factory }
    }
}

impl BitwardenCredentialCacheRepository for SqliteBitwardenCredentialCacheRepository<'_> {
    fn get_all(&self) -> Result<Vec<BitwardenCredentialCacheEntry>> {
        let conn = self.factory.open()?;
        let sql = format!("SELECT {SELECT_COLUMNS} FROM BitwardenCredentialCache ORDER BY Name;");
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], map_cache_entry)?;
        let mut entries = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        for entry in &mut entries {
            ensure_cache_entry_ids(entry);
        }
        Ok(entries)
    }

    fn replace_from_full_sync(
        &self,
        entries: &[BitwardenCredentialCacheEntry],
        sync_time_utc: DateTime<Utc>,
    ) -> Result<()> {
        let normalized = normalize_entries(entries, sync_time_utc);
        let mut conn = self.factory.open()?;
        let tx = conn.transaction()?;
        for entry in &normalized {
            upsert_on(&tx, entry)?;
        }
        if normalized.is_empty() {
            tx.execute("DELETE FROM BitwardenCredentialCache;", [])?;
        } else {
            let placeholders = (1..=normalized.len())
                .map(|i| format!("?{i}"))
                .collect::<Vec<_>>()
                .join(", ");
            let sql = format!(
                "DELETE FROM BitwardenCredentialCache WHERE ItemId NOT IN ({placeholders});"
            );
            let mut stmt = tx.prepare(&sql)?;
            let ids = normalized.iter().map(|e| e.item_id.as_str());
            stmt.execute(params_from_iter(ids))?;
        }
        tx.commit()?;
        Ok(())
    }

    fn upsert_imported(&self, entries: &[BitwardenCredentialCacheEntry]) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }
        let normalized = normalize_entries(entries, Utc::now());
        let mut conn = self.factory.open()?;
        let tx = conn.transaction()?;
        for entry in &normalized {
            upsert_on(&tx, entry)?;
        }
        tx.commit()?;
        Ok(())
    }
}

/// In-memory [`BitwardenCredentialCacheRepository`] for tests / labs (no SQLite, no `bw`).
///
/// Writes go through the same normalization as the SQLite repo, so host-visible
/// behavior (trimming, dedupe, ordering, virtual-id ensure) matches production.
/// `Debug` reports the row count only — never entry content.
#[derive(Default)]
pub struct FakeBitwardenCredentialCacheRepository {
    entries: Mutex<Vec<BitwardenCredentialCacheEntry>>,
}

impl FakeBitwardenCredentialCacheRepository {
    /// Empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed raw entries (sorted + id-ensured on read, like the SQLite repo).
    pub fn with_entries(entries: impl IntoIterator<Item = BitwardenCredentialCacheEntry>) -> Self {
        Self {
            entries: Mutex::new(entries.into_iter().collect()),
        }
    }
}

impl fmt::Debug for FakeBitwardenCredentialCacheRepository {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeBitwardenCredentialCacheRepository")
            .field("len", &self.entries.lock().expect("mutex").len())
            .finish()
    }
}

impl BitwardenCredentialCacheRepository for FakeBitwardenCredentialCacheRepository {
    fn get_all(&self) -> Result<Vec<BitwardenCredentialCacheEntry>> {
        let mut entries = self.entries.lock().expect("mutex").clone();
        for entry in &mut entries {
            if entry.item_id.trim().is_empty() {
                // Same fail-closed contract as the SQLite repo: blank ItemId rows
                // are never written by Normalize; treat as corruption.
                return Err(StorageError::Sqlite(blank_item_id_error()));
            }
            ensure_cache_entry_ids(entry);
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    }

    fn replace_from_full_sync(
        &self,
        entries: &[BitwardenCredentialCacheEntry],
        sync_time_utc: DateTime<Utc>,
    ) -> Result<()> {
        let normalized = normalize_entries(entries, sync_time_utc);
        let mut guard = self.entries.lock().expect("mutex");
        guard.clear();
        guard.extend(normalized);
        Ok(())
    }

    fn upsert_imported(&self, entries: &[BitwardenCredentialCacheEntry]) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }
        let normalized = normalize_entries(entries, Utc::now());
        let mut guard = self.entries.lock().expect("mutex");
        for entry in normalized {
            if let Some(existing) = guard.iter_mut().find(|e| e.item_id == entry.item_id) {
                *existing = entry;
            } else {
                guard.push(entry);
            }
        }
        Ok(())
    }
}

/// Normalize entries the way C# `BitwardenCredentialCacheRepository.Normalize` does.
///
/// Drops blank / whitespace `ItemId`s (fail closed), trims every text field, falls
/// blank `Name` back to the trimmed `ItemId`, converts blank `Username` /
/// `RevisionDate` to `None`, substitutes the sync time for year-0001 timestamps,
/// ensures virtual ids, dedupes by `ItemId` (byte equality, last wins), and orders
/// by `Name` (byte order; equal `Name`s tie-break by `ItemId` so the upsert order —
/// and thus SQLite `rowid` order — is deterministic, keeping the fake and the SQLite
/// repo identical and tests stable across runs).
fn normalize_entries(
    entries: &[BitwardenCredentialCacheEntry],
    default_sync_time_utc: DateTime<Utc>,
) -> Vec<BitwardenCredentialCacheEntry> {
    let mut by_item_id: HashMap<String, BitwardenCredentialCacheEntry> = HashMap::new();
    for entry in entries {
        let item_id = entry.item_id.trim();
        if item_id.is_empty() {
            continue;
        }
        let mut normalized = BitwardenCredentialCacheEntry {
            item_id: item_id.to_owned(),
            ssh_credential_id: entry.ssh_credential_id,
            rdp_credential_id: entry.rdp_credential_id,
            vnc_credential_id: entry.vnc_credential_id,
            name: if entry.name.trim().is_empty() {
                item_id.to_owned()
            } else {
                entry.name.trim().to_owned()
            },
            username: trim_to_option(entry.username.as_deref()),
            revision_date: trim_to_option(entry.revision_date.as_deref()),
            last_seen_sync_utc: if entry.last_seen_sync_utc == UNASSIGNED_TIMESTAMP {
                default_sync_time_utc
            } else {
                entry.last_seen_sync_utc
            },
            updated_at_utc: if entry.updated_at_utc == UNASSIGNED_TIMESTAMP {
                default_sync_time_utc
            } else {
                entry.updated_at_utc
            },
        };
        ensure_cache_entry_ids(&mut normalized);
        by_item_id.insert(normalized.item_id.clone(), normalized);
    }
    let mut ordered: Vec<_> = by_item_id.into_values().collect();
    ordered.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.item_id.cmp(&b.item_id)));
    ordered
}

/// Blank / whitespace → `None`; otherwise trimmed (C# `IsNullOrWhiteSpace` checks).
fn trim_to_option(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|trimmed| !trimmed.is_empty())
        .map(str::to_owned)
}

/// INSERT … ON CONFLICT(ItemId) DO UPDATE — C# `UpsertAsync`.
fn upsert_on(conn: &rusqlite::Connection, entry: &BitwardenCredentialCacheEntry) -> Result<()> {
    conn.execute(
        "INSERT INTO BitwardenCredentialCache
            (ItemId, SshCredentialId, RdpCredentialId, VncCredentialId,
             Name, Username, RevisionDate, LastSeenSyncUtc, UpdatedAtUtc)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(ItemId) DO UPDATE SET
             SshCredentialId = excluded.SshCredentialId,
             RdpCredentialId = excluded.RdpCredentialId,
             VncCredentialId = excluded.VncCredentialId,
             Name = excluded.Name,
             Username = excluded.Username,
             RevisionDate = excluded.RevisionDate,
             LastSeenSyncUtc = excluded.LastSeenSyncUtc,
             UpdatedAtUtc = excluded.UpdatedAtUtc;",
        params![
            entry.item_id,
            format_guid_d(entry.ssh_credential_id),
            format_guid_d(entry.rdp_credential_id),
            format_guid_d(entry.vnc_credential_id),
            entry.name,
            entry.username,
            entry.revision_date,
            format_timestamp_o(entry.last_seen_sync_utc),
            format_timestamp_o(entry.updated_at_utc),
        ],
    )?;
    Ok(())
}

fn map_cache_entry(row: &Row<'_>) -> rusqlite::Result<BitwardenCredentialCacheEntry> {
    let item_id: String = row.get("ItemId")?;
    if item_id.trim().is_empty() {
        // Never written by this repo (Normalize drops blanks); a blank row means
        // DB corruption. Fail closed like C# `EnsureIds` (which throws) — nil
        // virtual ids must never surface to pickers.
        return Err(blank_item_id_error());
    }
    Ok(BitwardenCredentialCacheEntry {
        item_id,
        ssh_credential_id: parse_guid_col(row, "SshCredentialId")?,
        rdp_credential_id: parse_guid_col(row, "RdpCredentialId")?,
        vnc_credential_id: parse_guid_col(row, "VncCredentialId")?,
        name: row.get("Name")?,
        username: row.get("Username")?,
        revision_date: row.get("RevisionDate")?,
        last_seen_sync_utc: parse_ts_col(row, "LastSeenSyncUtc")?,
        updated_at_utc: parse_ts_col(row, "UpdatedAtUtc")?,
    })
}

fn blank_item_id_error() -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        0,
        rusqlite::types::Type::Text,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "blank BitwardenCredentialCache ItemId",
        )),
    )
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
