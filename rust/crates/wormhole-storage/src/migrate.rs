//! Embedded SQL migrations — mirrors `Data/MigrationRunner.cs`.

use std::collections::HashSet;

use chrono::Utc;
use rusqlite::Connection;

use crate::types::format_timestamp_o;
use crate::{Result, SqliteConnectionFactory, StorageError};

/// A single migration script identified by its filename stem (e.g. `0001_initial`).
#[derive(Debug, Clone)]
pub struct Migration {
    pub id: String,
    pub sql: String,
}

impl Migration {
    pub fn new(id: impl Into<String>, sql: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            sql: sql.into(),
        }
    }
}

/// Applies pending SQL migrations in alphabetical order, tracking applied IDs in
/// `__migration_history` (same shape as the C# runner).
pub struct MigrationRunner {
    migrations: Vec<Migration>,
}

impl MigrationRunner {
    /// Runner over the embedded `Data/Migrations/*.sql` scripts.
    pub fn embedded() -> Self {
        Self {
            migrations: embedded_migrations(),
        }
    }

    /// Test-friendly constructor with an explicit migration list (already sorted preferred).
    pub fn with_migrations(mut migrations: Vec<Migration>) -> Self {
        migrations.sort_by(|a, b| a.id.cmp(&b.id));
        Self { migrations }
    }

    /// Apply all pending migrations using a fresh connection from `factory`.
    pub fn run(&self, factory: &SqliteConnectionFactory) -> Result<()> {
        let mut conn = factory.open()?;
        // Factory already applied pragmas; skip a redundant configure.
        self.apply_pending(&mut conn)
    }

    /// Apply pending migrations on an existing connection.
    pub fn run_on(&self, conn: &mut Connection) -> Result<()> {
        // Callers may pass a raw rusqlite connection; enforce the same pragmas as the factory.
        crate::connection::configure_connection(conn)?;
        self.apply_pending(conn)
    }

    fn apply_pending(&self, conn: &mut Connection) -> Result<()> {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS __migration_history (
                Id TEXT PRIMARY KEY NOT NULL,
                AppliedAtUtc TEXT NOT NULL
            );
            "#,
        )?;

        let applied = load_applied(conn)?;
        let pending: Vec<&Migration> = self
            .migrations
            .iter()
            .filter(|m| !applied.contains(&m.id))
            .collect();

        for migration in pending {
            let tx = conn.transaction().map_err(|source| StorageError::Migration {
                id: migration.id.clone(),
                source,
            })?;
            tx.execute_batch(&migration.sql)
                .map_err(|source| StorageError::Migration {
                    id: migration.id.clone(),
                    source,
                })?;
            let applied_at = format_timestamp_o(Utc::now());
            tx.execute(
                "INSERT INTO __migration_history (Id, AppliedAtUtc) VALUES (?1, ?2);",
                rusqlite::params![migration.id, applied_at],
            )
            .map_err(|source| StorageError::Migration {
                id: migration.id.clone(),
                source,
            })?;
            tx.commit().map_err(|source| StorageError::Migration {
                id: migration.id.clone(),
                source,
            })?;
        }

        Ok(())
    }

    /// Migration IDs in apply order.
    pub fn migration_ids(&self) -> impl Iterator<Item = &str> {
        self.migrations.iter().map(|m| m.id.as_str())
    }
}

fn load_applied(conn: &Connection) -> Result<HashSet<String>> {
    let mut stmt = conn.prepare("SELECT Id FROM __migration_history;")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    let mut applied = HashSet::new();
    for id in rows {
        applied.insert(id?);
    }
    Ok(applied)
}

/// Embedded migrations from `Data/Migrations/*.sql`, sorted alphabetically by id
/// (filename without `.sql`), matching C# `LoadEmbeddedMigrations`.
///
/// Paths are relative to this source file → repo `Data/Migrations/`.
pub fn embedded_migrations() -> Vec<Migration> {
    // include_str! paths are relative to this file (`src/migrate.rs`).
    // src/ → crate → crates → rust → repo root → Data/Migrations
    macro_rules! mig {
        ($file:literal) => {{
            let id = $file.trim_end_matches(".sql");
            Migration::new(id, include_str!(concat!("../../../../Data/Migrations/", $file)))
        }};
    }

    let mut migrations = vec![
        mig!("0001_initial.sql"),
        mig!("0002_credential_protocol.sql"),
        mig!("0003_add_tunnel_config.sql"),
        mig!("0003_rdp_extras.sql"),
        mig!("0004_rdp_use_external_client.sql"),
        mig!("0005_aad_credentials_use_external_client.sql"),
        mig!("0006_aad_node_fields_use_external_client.sql"),
        mig!("0007_nodes_parent_sort_index.sql"),
        mig!("0007_rdp_server_auth_warn_mapping.sql"),
        mig!("0008_ssh_auto_sudo.sql"),
        mig!("0009_drop_sftp_protocol.sql"),
        mig!("0010_inline_password.sql"),
        mig!("0011_http_ignore_cert_errors.sql"),
        mig!("0012_credential_inheritance.sql"),
        mig!("0013_serial_protocol.sql"),
        mig!("0014_bitwarden_credentials.sql"),
        mig!("0015_bitwarden_credential_cache.sql"),
    ];
    migrations.sort_by(|a, b| a.id.cmp(&b.id));
    migrations
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn embedded_ids_are_alphabetical_and_match_filenames() {
        let ids: Vec<_> = embedded_migrations().into_iter().map(|m| m.id).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted);
        assert_eq!(ids.first().map(String::as_str), Some("0001_initial"));
        assert_eq!(
            ids.last().map(String::as_str),
            Some("0015_bitwarden_credential_cache")
        );
        assert_eq!(ids.len(), 17);
        // Dual 0003_/0007_ files ship in alphabetical order.
        let i_tunnel = ids.iter().position(|i| i == "0003_add_tunnel_config").unwrap();
        let i_rdp = ids.iter().position(|i| i == "0003_rdp_extras").unwrap();
        assert!(i_tunnel < i_rdp);
    }

    #[test]
    fn embedded_ids_match_on_disk_data_migrations() {
        // CARGO_MANIFEST_DIR = rust/crates/wormhole-storage → repo Data/Migrations.
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../Data/Migrations");
        let mut on_disk: Vec<String> = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("sql"))
            .filter_map(|p| {
                p.file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
            })
            .collect();
        on_disk.sort();
        let embedded: Vec<String> = embedded_migrations().into_iter().map(|m| m.id).collect();
        assert_eq!(
            embedded, on_disk,
            "embedded_migrations() drifted from Data/Migrations/*.sql — add/remove include_str! entries"
        );
    }
}
