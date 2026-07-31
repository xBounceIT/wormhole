//! Integration tests for migrations, connection read/write path, and settings JSON.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

use chrono::Utc;
use tempfile::TempDir;
use uuid::Uuid;
use wormhole_domain::InheritanceResolver;
use wormhole_domain::ResolveError;
use wormhole_storage::{
    format_guid_d, format_timestamp_o, parse_timestamp_o, AppSettings, ConnectionNode,
    ConnectionRepository, CredentialBindingMode, Migration, MigrationRunner, NodeKind, ProtocolType,
    SerialFlowControlMode, SerialParityMode, SerialStopBitsMode, SettingsStore,
    SqliteConnectionFactory, StorageError, TunnelConfig, TunnelConfigRepository, TunnelKind,
};

fn temp_db() -> (TempDir, PathBuf, SqliteConnectionFactory) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("wormhole.db");
    let factory = SqliteConnectionFactory::new(&path);
    (dir, path, factory)
}

#[test]
fn apply_all_embedded_migrations_on_empty_db() {
    let (_dir, _path, factory) = temp_db();
    let runner = MigrationRunner::embedded();
    runner.run(&factory).expect("migrate");

    let conn = factory.open().unwrap();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM __migration_history;", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 17);

    let ids: Vec<String> = {
        let mut stmt = conn
            .prepare("SELECT Id FROM __migration_history ORDER BY Id;")
            .unwrap();
        stmt.query_map([], |r| r.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    };
    assert_eq!(ids.first().map(String::as_str), Some("0001_initial"));
    assert_eq!(
        ids.last().map(String::as_str),
        Some("0015_bitwarden_credential_cache")
    );

    // AppliedAtUtc must be .NET O-parseable.
    let applied_at: String = conn
        .query_row(
            "SELECT AppliedAtUtc FROM __migration_history WHERE Id = '0001_initial';",
            [],
            |r| r.get(0),
        )
        .unwrap();
    parse_timestamp_o(&applied_at).expect("AppliedAtUtc O format");

    // Core tables exist after full chain.
    for table in [
        "Nodes",
        "CredentialProfiles",
        "TunnelConfigs",
        "BitwardenCredentialCache",
    ] {
        let exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1;",
                [table],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(exists, 1, "missing table {table}");
    }

    // Idempotent second run.
    runner.run(&factory).expect("re-migrate");
    let count2: i64 = conn
        .query_row("SELECT COUNT(*) FROM __migration_history;", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count2, 17);
}

#[test]
fn migration_rollback_on_failure() {
    let (_dir, _path, factory) = temp_db();
    let runner = MigrationRunner::with_migrations(vec![
        Migration::new("0001_one", "CREATE TABLE t1 (Id INTEGER PRIMARY KEY);"),
        Migration::new(
            "0002_bad",
            "CREATE TABLE t2 (Id INTEGER PRIMARY KEY); INVALID SQL HERE;",
        ),
    ]);
    assert!(runner.run(&factory).is_err());

    let conn = factory.open().unwrap();
    let tables: Vec<String> = {
        let mut stmt = conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name;",
            )
            .unwrap();
        stmt.query_map([], |r| r.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    };
    assert!(tables.contains(&"t1".to_string()));
    assert!(!tables.contains(&"t2".to_string()));
    let applied: Vec<String> = {
        let mut stmt = conn
            .prepare("SELECT Id FROM __migration_history ORDER BY Id;")
            .unwrap();
        stmt.query_map([], |r| r.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    };
    assert_eq!(applied, vec!["0001_one".to_string()]);
}

#[test]
fn list_folders_and_connections_after_seed() {
    let (_dir, _path, factory) = temp_db();
    MigrationRunner::embedded().run(&factory).unwrap();

    let folder_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
    let conn_id = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();
    let now = format_timestamp_o(Utc::now());

    {
        let conn = factory.open().unwrap();
        conn.execute(
            "INSERT INTO Nodes (Id, ParentId, Name, Kind, SortOrder, CreatedAt, UpdatedAt)
             VALUES (?1, NULL, 'Lab', 0, 0, ?2, ?2);",
            rusqlite::params![format_guid_d(folder_id), now],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO Nodes (
                Id, ParentId, Name, Kind, SortOrder, Protocol, Host, Port, CreatedAt, UpdatedAt
             ) VALUES (?1, ?2, 'demo-ssh', 1, 0, 0, '127.0.0.1', 22, ?3, ?3);",
            rusqlite::params![format_guid_d(conn_id), format_guid_d(folder_id), now],
        )
        .unwrap();
    }

    let repo = ConnectionRepository::new(&factory);
    let all = repo.list_all().unwrap();
    assert_eq!(all.len(), 2);

    let folders = repo.list_folders().unwrap();
    assert_eq!(folders.len(), 1);
    assert_eq!(folders[0].node.name, "Lab");
    assert_eq!(folders[0].node.kind, NodeKind::Folder);
    assert!(folders[0].is_folder());

    let connections = repo.list_connections().unwrap();
    assert_eq!(connections.len(), 1);
    assert_eq!(connections[0].node.name, "demo-ssh");
    assert_eq!(connections[0].node.protocol, Some(ProtocolType::Ssh));
    assert_eq!(connections[0].node.host.as_deref(), Some("127.0.0.1"));
    assert_eq!(connections[0].node.port, Some(22));
    assert_eq!(connections[0].node.parent_id, Some(folder_id));

    let by_id = repo.get_by_id(conn_id).unwrap().expect("found");
    assert_eq!(by_id.node.id, conn_id);
    assert!(repo.get_by_id(Uuid::nil()).unwrap().is_none());
}

#[test]
fn credential_mode_and_serial_enums_map() {
    let (_dir, _path, factory) = temp_db();
    MigrationRunner::embedded().run(&factory).unwrap();
    let id = Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap();
    let now = format_timestamp_o(Utc::now());

    {
        let conn = factory.open().unwrap();
        conn.execute(
            "INSERT INTO Nodes (
                Id, ParentId, Name, Kind, SortOrder, Protocol, Host,
                CredentialMode, SerialBaudRate, SerialDataBits, SerialStopBits, SerialParity, SerialFlowControl,
                CreatedAt, UpdatedAt
             ) VALUES (?1, NULL, 'COM端口', 1, 0, 5, 'COM10', 2, 115200, 8, 1, 2, 1, ?2, ?2);",
            rusqlite::params![format_guid_d(id), now],
        )
        .unwrap();
    }

    let repo = ConnectionRepository::new(&factory);
    let row = repo.get_by_id(id).unwrap().unwrap();
    assert_eq!(row.node.name, "COM端口");
    assert_eq!(row.node.protocol, Some(ProtocolType::Serial));
    assert_eq!(row.node.credential_mode, Some(CredentialBindingMode::Saved));
    assert_eq!(row.node.serial_baud_rate, Some(115200));
    assert_eq!(row.node.serial_data_bits, Some(8));
    assert_eq!(row.node.serial_stop_bits, Some(SerialStopBitsMode::One));
    assert_eq!(row.node.serial_parity, Some(SerialParityMode::Even));
    assert_eq!(
        row.node.serial_flow_control,
        Some(SerialFlowControlMode::XonXoff)
    );
}

#[test]
fn tunnel_enabled_tri_state_maps_to_option_bool() {
    let (_dir, _path, factory) = temp_db();
    MigrationRunner::embedded().run(&factory).unwrap();
    let now = format_timestamp_o(Utc::now());

    let inherit = Uuid::parse_str("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa1").unwrap();
    let off = Uuid::parse_str("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa2").unwrap();
    let on = Uuid::parse_str("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa3").unwrap();
    let tunnel_cfg = Uuid::parse_str("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb").unwrap();

    {
        let conn = factory.open().unwrap();
        conn.execute(
            "INSERT INTO Nodes (Id, ParentId, Name, Kind, SortOrder, TunnelEnabled, TunnelConfigId, CreatedAt, UpdatedAt)
             VALUES (?1, NULL, 'inherit', 0, 0, NULL, NULL, ?2, ?2);",
            rusqlite::params![format_guid_d(inherit), now],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO Nodes (Id, ParentId, Name, Kind, SortOrder, TunnelEnabled, TunnelConfigId, CreatedAt, UpdatedAt)
             VALUES (?1, NULL, 'off', 0, 1, 0, NULL, ?2, ?2);",
            rusqlite::params![format_guid_d(off), now],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO Nodes (Id, ParentId, Name, Kind, SortOrder, TunnelEnabled, TunnelConfigId, CreatedAt, UpdatedAt)
             VALUES (?1, NULL, 'on', 0, 2, 1, ?2, ?3, ?3);",
            rusqlite::params![format_guid_d(on), format_guid_d(tunnel_cfg), now],
        )
        .unwrap();
    }

    let repo = ConnectionRepository::new(&factory);
    let inherit_n = repo.get_by_id(inherit).unwrap().unwrap();
    assert_eq!(inherit_n.node.tunnel_enabled, None);
    assert_eq!(inherit_n.node.tunnel_config_id, None);

    let off_n = repo.get_by_id(off).unwrap().unwrap();
    assert_eq!(off_n.node.tunnel_enabled, Some(false));

    let on_n = repo.get_by_id(on).unwrap().unwrap();
    assert_eq!(on_n.node.tunnel_enabled, Some(true));
    assert_eq!(on_n.node.tunnel_config_id, Some(tunnel_cfg));
}

#[test]
fn foreign_keys_enforced_on_parent_id() {
    let (_dir, _path, factory) = temp_db();
    MigrationRunner::embedded().run(&factory).unwrap();
    let now = format_timestamp_o(Utc::now());
    let orphan = Uuid::parse_str("cccccccc-cccc-cccc-cccc-cccccccccccc").unwrap();
    let missing_parent = Uuid::parse_str("dddddddd-dddd-dddd-dddd-dddddddddddd").unwrap();

    let conn = factory.open().unwrap();
    let fk: i64 = conn
        .query_row("PRAGMA foreign_keys;", [], |r| r.get(0))
        .unwrap();
    assert_eq!(fk, 1, "foreign_keys must be ON");

    let err = conn.execute(
        "INSERT INTO Nodes (Id, ParentId, Name, Kind, SortOrder, CreatedAt, UpdatedAt)
         VALUES (?1, ?2, 'orphan', 1, 0, ?3, ?3);",
        rusqlite::params![
            format_guid_d(orphan),
            format_guid_d(missing_parent),
            now
        ],
    );
    assert!(err.is_err(), "orphan ParentId must fail FK check");
}

#[test]
fn corrupted_applied_at_does_not_block_idempotent_migrate() {
    let (_dir, _path, factory) = temp_db();
    MigrationRunner::embedded().run(&factory).unwrap();

    {
        let conn = factory.open().unwrap();
        conn.execute(
            "UPDATE __migration_history SET AppliedAtUtc = 'not-a-date' WHERE Id = '0001_initial';",
            [],
        )
        .unwrap();
    }

    // Runner only reads Id from history — corrupt AppliedAt must not block re-run.
    MigrationRunner::embedded()
        .run(&factory)
        .expect("re-migrate with corrupt AppliedAtUtc");

    let conn = factory.open().unwrap();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM __migration_history;", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 17);
}

#[test]
fn corrupted_created_at_fails_read_path() {
    let (_dir, _path, factory) = temp_db();
    MigrationRunner::embedded().run(&factory).unwrap();
    let id = Uuid::parse_str("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee").unwrap();

    {
        let conn = factory.open().unwrap();
        conn.execute(
            "INSERT INTO Nodes (Id, ParentId, Name, Kind, SortOrder, CreatedAt, UpdatedAt)
             VALUES (?1, NULL, 'bad-ts', 0, 0, 'not-a-date', '2026-07-31T10:18:44.0000000Z');",
            rusqlite::params![format_guid_d(id)],
        )
        .unwrap();
    }

    let repo = ConnectionRepository::new(&factory);
    let err = repo.list_all().unwrap_err();
    assert!(
        matches!(err, StorageError::Sqlite(_)),
        "corrupt CreatedAt must surface as sqlite mapping error, got {err:?}"
    );
}

#[test]
fn retired_sftp_protocol_value_rejected() {
    let (_dir, _path, factory) = temp_db();
    MigrationRunner::embedded().run(&factory).unwrap();
    let id = Uuid::parse_str("ffffffff-ffff-ffff-ffff-fffffffffff1").unwrap();
    let now = format_timestamp_o(Utc::now());

    {
        let conn = factory.open().unwrap();
        conn.execute(
            "INSERT INTO Nodes (Id, ParentId, Name, Kind, SortOrder, Protocol, Host, Port, CreatedAt, UpdatedAt)
             VALUES (?1, NULL, 'legacy-sftp', 1, 0, 2, '127.0.0.1', 22, ?2, ?2);",
            rusqlite::params![format_guid_d(id), now],
        )
        .unwrap();
    }

    let repo = ConnectionRepository::new(&factory);
    assert!(repo.get_by_id(id).is_err());
}

#[test]
fn uppercase_guid_round_trips_on_read() {
    let (_dir, _path, factory) = temp_db();
    MigrationRunner::embedded().run(&factory).unwrap();
    let id = Uuid::parse_str("ABCDEF01-2345-6789-ABCD-EF0123456789").unwrap();
    let now = format_timestamp_o(Utc::now());

    {
        let conn = factory.open().unwrap();
        conn.execute(
            "INSERT INTO Nodes (Id, ParentId, Name, Kind, SortOrder, CreatedAt, UpdatedAt)
             VALUES (?1, NULL, 'upper', 0, 0, ?2, ?2);",
            rusqlite::params!["ABCDEF01-2345-6789-ABCD-EF0123456789", now],
        )
        .unwrap();
    }

    let repo = ConnectionRepository::new(&factory);
    let via_list = repo.list_all().unwrap();
    assert_eq!(via_list.len(), 1);
    assert_eq!(via_list[0].node.id, id);

    let row = repo.get_by_id(id).unwrap().expect("COLLATE NOCASE find");
    assert_eq!(row.node.id, id);
    assert_eq!(row.node.name, "upper");
}

#[test]
fn concurrent_opens_list_all() {
    let (_dir, path, factory) = temp_db();
    MigrationRunner::embedded().run(&factory).unwrap();
    let now = format_timestamp_o(Utc::now());
    let id = Uuid::parse_str("12121212-1212-1212-1212-121212121212").unwrap();
    {
        let conn = factory.open().unwrap();
        conn.execute(
            "INSERT INTO Nodes (Id, ParentId, Name, Kind, SortOrder, CreatedAt, UpdatedAt)
             VALUES (?1, NULL, 'concurrent', 0, 0, ?2, ?2);",
            rusqlite::params![format_guid_d(id), now],
        )
        .unwrap();
    }

    let path = Arc::new(path);
    let mut handles = Vec::new();
    for _ in 0..8 {
        let path = Arc::clone(&path);
        handles.push(thread::spawn(move || {
            let factory = SqliteConnectionFactory::new(path.as_path());
            let repo = ConnectionRepository::new(&factory);
            let all = repo.list_all().expect("concurrent list_all");
            assert_eq!(all.len(), 1);
        }));
    }
    for h in handles {
        h.join().expect("thread");
    }
}

#[test]
fn open_golden_empty_schema_fixture() {
    let fixture = wormhole_testkit::empty_schema_db();
    assert!(
        fixture.exists(),
        "missing golden fixture at {} — run: cargo test -p wormhole-storage --test generate_empty_schema_fixture -- --ignored",
        fixture.display()
    );

    // Copy to temp so we never mutate the checked-in fixture.
    let dir = TempDir::new().unwrap();
    let copy = dir.path().join("empty-schema.db");
    fs::copy(&fixture, &copy).unwrap();

    let factory = SqliteConnectionFactory::new(&copy);
    let repo = ConnectionRepository::new(&factory);
    let all = repo.list_all().unwrap();
    assert!(all.is_empty(), "golden fixture must be schema-only");

    let folders = repo.list_folders().unwrap();
    assert!(folders.is_empty());

    let conn = factory.open().unwrap();
    let mig_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM __migration_history;", [], |r| r.get(0))
        .unwrap();
    assert_eq!(mig_count, 17);

    let embedded: Vec<String> = MigrationRunner::embedded()
        .migration_ids()
        .map(str::to_owned)
        .collect();
    let fixture_ids: Vec<String> = {
        let mut stmt = conn
            .prepare("SELECT Id FROM __migration_history ORDER BY Id;")
            .unwrap();
        stmt.query_map([], |r| r.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    };
    assert_eq!(fixture_ids, embedded);

    // No secrets / connection rows in any data table.
    for table in [
        "Nodes",
        "CredentialProfiles",
        "TunnelConfigs",
        "BitwardenCredentialCache",
    ] {
        let n: i64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM {table};"), [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0, "{table} must be empty in golden fixture");
    }

    // Scan non-history cells for secret-like payloads (migration ids may contain 'password').
    let secret_needles = [
        "BEGIN RSA",
        "BEGIN OPENSSH",
        "ssh-rsa ",
        "SVPNCOOKIE",
        "api_key=",
        "token=",
    ];
    for table in [
        "Nodes",
        "CredentialProfiles",
        "TunnelConfigs",
        "BitwardenCredentialCache",
    ] {
        let mut stmt = conn.prepare(&format!("SELECT * FROM {table};")).unwrap();
        let col_count = stmt.column_count();
        let mut rows = stmt.query([]).unwrap();
        while let Some(row) = rows.next().unwrap() {
            for i in 0..col_count {
                if let Ok(s) = row.get::<_, String>(i) {
                    for needle in secret_needles {
                        assert!(
                            !s.contains(needle),
                            "fixture {table} col {i} looks like a secret"
                        );
                    }
                }
            }
        }
    }
}

fn folder_node(id: Uuid, name: &str) -> ConnectionNode {
    ConnectionNode {
        id,
        name: name.into(),
        kind: NodeKind::Folder,
        ..ConnectionNode::default()
    }
}

fn ssh_node(id: Uuid, parent: Option<Uuid>, name: &str, host: &str) -> ConnectionNode {
    ConnectionNode {
        id,
        parent_id: parent,
        name: name.into(),
        kind: NodeKind::Connection,
        protocol: Some(ProtocolType::Ssh),
        host: Some(host.into()),
        port: Some(22),
        ..ConnectionNode::default()
    }
}

#[test]
fn insert_update_delete_round_trip_preserves_guid_d_and_timestamp_o() {
    let (_dir, _path, factory) = temp_db();
    MigrationRunner::embedded().run(&factory).unwrap();
    let repo = ConnectionRepository::new(&factory);

    let folder_id = Uuid::parse_str("a1111111-1111-1111-1111-111111111111").unwrap();
    let conn_id = Uuid::parse_str("a2222222-2222-2222-2222-222222222222").unwrap();

    let stored_folder = repo.insert(&folder_node(folder_id, "Lab")).unwrap();
    assert_eq!(stored_folder.node.id, folder_id);
    assert_eq!(stored_folder.created_at, stored_folder.updated_at);

    let stored_conn = repo
        .insert(&ssh_node(conn_id, Some(folder_id), "demo", "127.0.0.1"))
        .unwrap();
    assert_eq!(stored_conn.node.parent_id, Some(folder_id));

    // Writers emit lowercase format D + parseable O timestamps.
    {
        let conn = factory.open().unwrap();
        let (id_text, created, updated): (String, String, String) = conn
            .query_row(
                "SELECT Id, CreatedAt, UpdatedAt FROM Nodes WHERE Id = ?1;",
                rusqlite::params![format_guid_d(conn_id)],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(id_text, "a2222222-2222-2222-2222-222222222222");
        parse_timestamp_o(&created).unwrap();
        parse_timestamp_o(&updated).unwrap();
    }

    let created_at = stored_conn.created_at;
    std::thread::sleep(std::time::Duration::from_millis(5));

    let mut updated = stored_conn.node.clone();
    updated.name = "demo-renamed".into();
    updated.host = Some("10.0.0.1".into());
    updated.tunnel_enabled = Some(false);
    repo.update(&updated).unwrap();

    let row = repo.get_by_id(conn_id).unwrap().unwrap();
    assert_eq!(row.node.name, "demo-renamed");
    assert_eq!(row.node.host.as_deref(), Some("10.0.0.1"));
    assert_eq!(row.node.tunnel_enabled, Some(false));
    assert_eq!(row.created_at, created_at);
    assert!(row.updated_at >= created_at);

    repo.delete(folder_id).unwrap();
    // ON DELETE CASCADE removes children.
    assert!(repo.get_by_id(folder_id).unwrap().is_none());
    assert!(repo.get_by_id(conn_id).unwrap().is_none());
    assert!(repo.list_all().unwrap().is_empty());
}

#[test]
fn insert_rejects_orphan_parent_when_foreign_keys_on() {
    let (_dir, _path, factory) = temp_db();
    MigrationRunner::embedded().run(&factory).unwrap();
    let repo = ConnectionRepository::new(&factory);
    let missing = Uuid::parse_str("b1111111-1111-1111-1111-111111111111").unwrap();
    let child = Uuid::parse_str("b2222222-2222-2222-2222-222222222222").unwrap();
    let err = repo
        .insert(&ssh_node(child, Some(missing), "orphan", "127.0.0.1"))
        .unwrap_err();
    assert!(matches!(err, StorageError::Sqlite(_)), "got {err:?}");
}

#[test]
fn insert_many_is_transactional_parent_before_child() {
    let (_dir, _path, factory) = temp_db();
    MigrationRunner::embedded().run(&factory).unwrap();
    let repo = ConnectionRepository::new(&factory);

    let folder_id = Uuid::parse_str("d1111111-1111-1111-1111-111111111111").unwrap();
    let ssh_id = Uuid::parse_str("d2222222-2222-2222-2222-222222222222").unwrap();
    let rdp_id = Uuid::parse_str("d3333333-3333-3333-3333-333333333333").unwrap();

    let mut rdp = ConnectionNode {
        id: rdp_id,
        parent_id: Some(folder_id),
        name: "dc-rdp".into(),
        kind: NodeKind::Connection,
        protocol: Some(ProtocolType::Rdp),
        host: Some("192.0.2.20".into()),
        port: Some(3389),
        username: Some("admin".into()),
        rdp_domain: Some("LAB".into()),
        ..ConnectionNode::default()
    };
    rdp.sort_order = 1;

    let stored = repo
        .insert_many(&[
            folder_node(folder_id, "Lab"),
            ssh_node(ssh_id, Some(folder_id), "jump-ssh", "192.0.2.10"),
            rdp,
        ])
        .unwrap();
    assert_eq!(stored.len(), 3);
    assert_eq!(stored[0].created_at, stored[2].created_at);

    let conns = repo.list_connections().unwrap();
    assert_eq!(conns.len(), 2);
    assert!(conns.iter().any(|n| {
        n.node.name == "jump-ssh" && n.node.protocol == Some(ProtocolType::Ssh)
    }));
    assert!(conns.iter().any(|n| {
        n.node.name == "dc-rdp"
            && n.node.protocol == Some(ProtocolType::Rdp)
            && n.node.rdp_domain.as_deref() == Some("LAB")
    }));
}

#[test]
fn insert_many_rolls_back_entire_batch_on_fk_failure() {
    let (_dir, _path, factory) = temp_db();
    MigrationRunner::embedded().run(&factory).unwrap();
    let repo = ConnectionRepository::new(&factory);

    let root = Uuid::parse_str("e1111111-1111-1111-1111-111111111111").unwrap();
    let missing = Uuid::parse_str("e2222222-2222-2222-2222-222222222222").unwrap();
    let orphan = Uuid::parse_str("e3333333-3333-3333-3333-333333333333").unwrap();

    let err = repo
        .insert_many(&[
            folder_node(root, "Lab"),
            ssh_node(orphan, Some(missing), "orphan", "127.0.0.1"),
        ])
        .unwrap_err();
    assert!(matches!(err, StorageError::Sqlite(_)), "got {err:?}");
    assert!(
        repo.list_all().unwrap().is_empty(),
        "transactional insert_many must not leave the root row"
    );
}

#[test]
fn insert_many_rolls_back_on_duplicate_primary_key() {
    let (_dir, _path, factory) = temp_db();
    MigrationRunner::embedded().run(&factory).unwrap();
    let repo = ConnectionRepository::new(&factory);

    let shared = Uuid::parse_str("f1111111-1111-1111-1111-111111111111").unwrap();
    let other = Uuid::parse_str("f2222222-2222-2222-2222-222222222222").unwrap();

    let err = repo
        .insert_many(&[
            folder_node(shared, "first"),
            folder_node(other, "second"),
            folder_node(shared, "duplicate-id"),
        ])
        .unwrap_err();
    assert!(matches!(err, StorageError::Sqlite(_)), "got {err:?}");
    assert!(
        repo.list_all().unwrap().is_empty(),
        "duplicate PK mid-batch must roll back prior inserts"
    );
}

#[test]
fn insert_many_rejects_child_before_parent_and_rolls_back() {
    let (_dir, _path, factory) = temp_db();
    MigrationRunner::embedded().run(&factory).unwrap();
    let repo = ConnectionRepository::new(&factory);

    let folder_id = Uuid::parse_str("f3333333-3333-3333-3333-333333333333").unwrap();
    let child_id = Uuid::parse_str("f4444444-4444-4444-4444-444444444444").unwrap();

    // Child precedes its parent in the slice — FK fails immediately; no partial commit.
    let err = repo
        .insert_many(&[
            ssh_node(child_id, Some(folder_id), "too-early", "192.0.2.10"),
            folder_node(folder_id, "Lab"),
        ])
        .unwrap_err();
    assert!(matches!(err, StorageError::Sqlite(_)), "got {err:?}");
    assert!(
        repo.list_all().unwrap().is_empty(),
        "child-before-parent must not leave either row"
    );
}

#[test]
fn insert_many_rolls_back_when_id_collides_with_preexisting_row() {
    let (_dir, _path, factory) = temp_db();
    MigrationRunner::embedded().run(&factory).unwrap();
    let repo = ConnectionRepository::new(&factory);

    let existing = Uuid::parse_str("f5555555-5555-5555-5555-555555555555").unwrap();
    let batch_root = Uuid::parse_str("f6666666-6666-6666-6666-666666666666").unwrap();
    repo.insert(&folder_node(existing, "preexisting")).unwrap();

    let err = repo
        .insert_many(&[
            folder_node(batch_root, "import-root"),
            folder_node(existing, "collision"),
        ])
        .unwrap_err();
    assert!(matches!(err, StorageError::Sqlite(_)), "got {err:?}");
    let all = repo.list_all().unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].node.name, "preexisting");
}

#[test]
fn update_many_is_transactional() {
    let (_dir, _path, factory) = temp_db();
    MigrationRunner::embedded().run(&factory).unwrap();
    let repo = ConnectionRepository::new(&factory);

    let a = Uuid::parse_str("c1111111-1111-1111-1111-111111111111").unwrap();
    let b = Uuid::parse_str("c2222222-2222-2222-2222-222222222222").unwrap();
    repo.insert(&folder_node(a, "A")).unwrap();
    repo.insert(&folder_node(b, "B")).unwrap();

    let mut na = folder_node(a, "A2");
    na.sort_order = 1;
    let mut nb = folder_node(b, "B2");
    nb.sort_order = 2;
    repo.update_many(&[na, nb]).unwrap();

    let all = repo.list_all().unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].node.name, "A2");
    assert_eq!(all[1].node.name, "B2");
}

#[test]
fn update_many_rolls_back_on_hostile_parent_id() {
    let (_dir, _path, factory) = temp_db();
    MigrationRunner::embedded().run(&factory).unwrap();
    let repo = ConnectionRepository::new(&factory);

    let a = Uuid::parse_str("c3333333-3333-3333-3333-333333333333").unwrap();
    let b = Uuid::parse_str("c4444444-4444-4444-4444-444444444444").unwrap();
    let missing = Uuid::parse_str("c5555555-5555-5555-5555-555555555555").unwrap();
    repo.insert(&folder_node(a, "A")).unwrap();
    repo.insert(&folder_node(b, "B")).unwrap();

    let mut na = folder_node(a, "A-should-not-persist");
    na.sort_order = 9;
    let mut nb = folder_node(b, "B-hostile");
    nb.parent_id = Some(missing); // FK violation mid-batch

    let err = repo.update_many(&[na, nb]).unwrap_err();
    assert!(matches!(err, StorageError::Sqlite(_)), "got {err:?}");

    let all = repo.list_all().unwrap();
    assert_eq!(all.len(), 2);
    let names: Vec<_> = all.iter().map(|n| n.node.name.as_str()).collect();
    assert!(names.contains(&"A"));
    assert!(names.contains(&"B"));
    assert!(!names.contains(&"A-should-not-persist"));
    assert_eq!(repo.get_by_id(a).unwrap().unwrap().node.sort_order, 0);
}

#[test]
fn delete_folder_cascades_nested_children_no_orphans() {
    let (_dir, _path, factory) = temp_db();
    MigrationRunner::embedded().run(&factory).unwrap();
    let repo = ConnectionRepository::new(&factory);

    let root = Uuid::parse_str("e1111111-1111-1111-1111-111111111111").unwrap();
    let mid = Uuid::parse_str("e2222222-2222-2222-2222-222222222222").unwrap();
    let leaf = Uuid::parse_str("e3333333-3333-3333-3333-333333333333").unwrap();
    let sibling = Uuid::parse_str("e4444444-4444-4444-4444-444444444444").unwrap();

    repo.insert(&folder_node(root, "root")).unwrap();
    let mut mid_node = folder_node(mid, "mid");
    mid_node.parent_id = Some(root);
    repo.insert(&mid_node).unwrap();
    repo.insert(&ssh_node(leaf, Some(mid), "leaf", "10.0.0.1"))
        .unwrap();
    repo.insert(&folder_node(sibling, "keep")).unwrap();

    repo.delete(root).unwrap();

    assert!(repo.get_by_id(root).unwrap().is_none());
    assert!(repo.get_by_id(mid).unwrap().is_none());
    assert!(repo.get_by_id(leaf).unwrap().is_none());
    assert_eq!(repo.list_all().unwrap().len(), 1);
    assert_eq!(repo.get_by_id(sibling).unwrap().unwrap().node.name, "keep");
}

#[test]
fn delete_many_is_all_or_nothing_visible() {
    let (_dir, _path, factory) = temp_db();
    MigrationRunner::embedded().run(&factory).unwrap();
    let repo = ConnectionRepository::new(&factory);
    let a = Uuid::parse_str("f1111111-1111-1111-1111-111111111111").unwrap();
    let b = Uuid::parse_str("f2222222-2222-2222-2222-222222222222").unwrap();
    repo.insert(&folder_node(a, "A")).unwrap();
    repo.insert(&folder_node(b, "B")).unwrap();
    repo.delete_many(&[a, b]).unwrap();
    assert!(repo.list_all().unwrap().is_empty());
}

#[test]
fn write_path_binds_hostile_name_without_sql_injection() {
    let (_dir, _path, factory) = temp_db();
    MigrationRunner::embedded().run(&factory).unwrap();
    let repo = ConnectionRepository::new(&factory);
    let id = Uuid::parse_str("f3333333-3333-3333-3333-333333333333").unwrap();
    let hostile = "'; DROP TABLE Nodes;--";
    repo.insert(&folder_node(id, hostile)).unwrap();
    let row = repo.get_by_id(id).unwrap().unwrap();
    assert_eq!(row.node.name, hostile);
    // Nodes table must still exist and hold the row.
    assert_eq!(repo.list_all().unwrap().len(), 1);
}

#[test]
fn delete_many_empty_is_noop() {
    let (_dir, _path, factory) = temp_db();
    MigrationRunner::embedded().run(&factory).unwrap();
    let repo = ConnectionRepository::new(&factory);
    repo.delete_many(&[]).unwrap();
    repo.update_many(&[]).unwrap();
}

#[test]
fn update_host_fingerprint_rejects_blank_and_writes_o_timestamp() {
    let (_dir, _path, factory) = temp_db();
    MigrationRunner::embedded().run(&factory).unwrap();
    let repo = ConnectionRepository::new(&factory);
    let id = Uuid::parse_str("d1111111-1111-1111-1111-111111111111").unwrap();
    repo.insert(&ssh_node(id, None, "ssh", "127.0.0.1")).unwrap();

    assert!(matches!(
        repo.update_host_fingerprint(Uuid::nil(), "fp").unwrap_err(),
        StorageError::InvalidArgument(_)
    ));
    assert!(matches!(
        repo.update_host_fingerprint(id, "  ").unwrap_err(),
        StorageError::InvalidArgument(_)
    ));

    repo.update_host_fingerprint(id, "SHA256:deadbeef").unwrap();
    let row = repo.get_by_id(id).unwrap().unwrap();
    assert_eq!(
        row.node.ssh_known_host_fingerprint.as_deref(),
        Some("SHA256:deadbeef")
    );
}

fn assert_folder_row_has_no_secrets(node: &ConnectionNode) {
    assert!(node.credential_id.is_none());
    assert!(node.credential_mode.is_none());
    assert!(node.username.is_none());
    assert!(node.use_inline_password.is_none());
    assert!(node.rdp_gateway_credential_id.is_none());
    assert!(node.ssh_key_file_name.is_none());
    assert!(node.ssh_known_host_fingerprint.is_none());
    assert!(node.tunnel_config_id.is_none());
}

#[test]
fn folder_crud_create_rename_delete_temp_sqlite() {
    let (_dir, _path, factory) = temp_db();
    MigrationRunner::embedded().run(&factory).unwrap();
    let repo = ConnectionRepository::new(&factory);

    assert!(matches!(
        repo.create_folder("   ", None).unwrap_err(),
        StorageError::InvalidArgument(_)
    ));
    assert!(matches!(
        repo.create_folder("\u{3000}\t", None).unwrap_err(),
        StorageError::InvalidArgument(_)
    ));

    let root = repo.create_folder(" Lab ", None).unwrap();
    assert_eq!(root.node.name, "Lab");
    assert_eq!(root.node.kind, NodeKind::Folder);
    assert!(root.node.parent_id.is_none());
    assert_eq!(root.node.sort_order, 0);
    assert_folder_row_has_no_secrets(&root.node);
    assert!(root.node.host.is_none());

    let nested = repo
        .create_folder("Nested", Some(root.node.id))
        .unwrap();
    assert_eq!(nested.node.parent_id, Some(root.node.id));
    assert_eq!(nested.node.sort_order, 0);
    assert_folder_row_has_no_secrets(&nested.node);

    let sibling = repo.create_folder("Sibling", None).unwrap();
    assert_eq!(sibling.node.sort_order, 1);

    let unicode = repo.create_folder("ラボ 📁", None).unwrap();
    assert_eq!(unicode.node.name, "ラボ 📁");
    assert_eq!(unicode.node.sort_order, 2);
    assert_folder_row_has_no_secrets(&unicode.node);

    let renamed = repo
        .rename_folder(root.node.id, "  Lab-2  ")
        .unwrap();
    assert_eq!(renamed.node.name, "Lab-2");
    assert!(matches!(
        repo.rename_folder(root.node.id, " \n ").unwrap_err(),
        StorageError::InvalidArgument(_)
    ));

    // Cannot nest under a connection.
    let conn_id = Uuid::parse_str("a0a0a0a0-a0a0-a0a0-a0a0-a0a0a0a0a0a0").unwrap();
    repo.insert(&ssh_node(conn_id, Some(root.node.id), "ssh", "127.0.0.1"))
        .unwrap();
    assert!(matches!(
        repo.create_folder("bad", Some(conn_id)).unwrap_err(),
        StorageError::InvalidArgument(_)
    ));
    assert!(matches!(
        repo.rename_folder(conn_id, "nope").unwrap_err(),
        StorageError::InvalidArgument(_)
    ));
    assert!(matches!(
        repo.delete_folder(conn_id).unwrap_err(),
        StorageError::InvalidArgument(_)
    ));

    let missing = Uuid::parse_str("ffffffff-ffff-ffff-ffff-ffffffffffff").unwrap();
    assert!(matches!(
        repo.create_folder("orphan-parent", Some(missing)).unwrap_err(),
        StorageError::NotFound(id) if id == missing
    ));
    assert!(matches!(
        repo.rename_folder(missing, "x").unwrap_err(),
        StorageError::NotFound(id) if id == missing
    ));
    assert!(matches!(
        repo.delete_folder(missing).unwrap_err(),
        StorageError::NotFound(id) if id == missing
    ));

    repo.delete_folder(root.node.id).unwrap();
    assert!(repo.get_by_id(root.node.id).unwrap().is_none());
    assert!(repo.get_by_id(nested.node.id).unwrap().is_none());
    assert!(repo.get_by_id(conn_id).unwrap().is_none());
    assert_eq!(repo.list_all().unwrap().len(), 2);
    assert_eq!(
        repo.get_by_id(sibling.node.id).unwrap().unwrap().node.name,
        "Sibling"
    );
    assert_eq!(
        repo.get_by_id(unicode.node.id).unwrap().unwrap().node.name,
        "ラボ 📁"
    );
}

#[test]
fn reparent_connection_stub_updates_parent_and_inheritance_chain() {
    let (_dir, _path, factory) = temp_db();
    MigrationRunner::embedded().run(&factory).unwrap();
    let repo = ConnectionRepository::new(&factory);

    let folder_a = repo.create_folder("A", None).unwrap();
    let folder_b = repo.create_folder("B", None).unwrap();

    // Folder B supplies an inheritable host (no secrets in the row).
    let mut b = folder_b.node.clone();
    b.host = Some("inherited.example".into());
    b.port = Some(22);
    b.protocol = Some(ProtocolType::Ssh);
    repo.update(&b).unwrap();

    // Pre-existing sibling under B so append SortOrder must be max+1 (not 0).
    let sibling_id = Uuid::parse_str("b1b1b1b1-b1b1-b1b1-b1b1-b1b1b1b1b1b1").unwrap();
    let mut sibling = ssh_node(sibling_id, Some(folder_b.node.id), "sibling", "192.0.2.1");
    sibling.sort_order = 0;
    repo.insert(&sibling).unwrap();
    assert_eq!(repo.next_sort_order(Some(folder_b.node.id)).unwrap(), 1);

    let conn_id = Uuid::parse_str("b0b0b0b0-b0b0-b0b0-b0b0-b0b0b0b0b0b0").unwrap();
    // Leaf omits host/port so InheritanceResolver supplies them from the parent folder.
    let mut leaf = ConnectionNode {
        id: conn_id,
        parent_id: Some(folder_a.node.id),
        name: "leaf".into(),
        kind: NodeKind::Connection,
        protocol: Some(ProtocolType::Ssh),
        host: None,
        port: None,
        ..ConnectionNode::default()
    };
    leaf.sort_order = 0;
    repo.insert(&leaf).unwrap();

    let moved = repo
        .reparent_connection(conn_id, Some(folder_b.node.id))
        .unwrap();
    assert_eq!(moved.node.parent_id, Some(folder_b.node.id));
    assert_eq!(moved.node.sort_order, 1);

    // Idempotent reparent keeps SortOrder.
    let again = repo
        .reparent_connection(conn_id, Some(folder_b.node.id))
        .unwrap();
    assert_eq!(again.node.sort_order, 1);

    // Reject connection-as-parent / folder-as-move-target misuse.
    assert!(matches!(
        repo.reparent_connection(conn_id, Some(conn_id)).unwrap_err(),
        StorageError::InvalidArgument(_)
    ));
    assert!(matches!(
        repo.reparent_connection(folder_a.node.id, Some(folder_b.node.id))
            .unwrap_err(),
        StorageError::InvalidArgument(_)
    ));
    let missing = Uuid::parse_str("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee").unwrap();
    assert!(matches!(
        repo.reparent_connection(conn_id, Some(missing)).unwrap_err(),
        StorageError::NotFound(id) if id == missing
    ));
    assert!(matches!(
        repo.reparent_connection(missing, Some(folder_b.node.id))
            .unwrap_err(),
        StorageError::NotFound(id) if id == missing
    ));

    // InheritanceResolver still walks ParentId after reparent (domain contract).
    let all = repo.list_all().unwrap();
    let by_id: std::collections::HashMap<_, _> = all
        .into_iter()
        .map(|s| (s.node.id, s.node))
        .collect();
    let profile = InheritanceResolver::new()
        .resolve(by_id.get(&conn_id).unwrap(), &by_id)
        .expect("resolve after reparent");
    assert_eq!(profile.host, "inherited.example");
    assert_eq!(profile.port, 22);

    // Detach to root — ParentId walk must not still see folder B's host.
    let rooted = repo.reparent_connection(conn_id, None).unwrap();
    assert!(rooted.node.parent_id.is_none());
    let all = repo.list_all().unwrap();
    let by_id: std::collections::HashMap<_, _> = all
        .into_iter()
        .map(|s| (s.node.id, s.node))
        .collect();
    let err = InheritanceResolver::new()
        .resolve(by_id.get(&conn_id).unwrap(), &by_id)
        .expect_err("root leaf without host must fail closed");
    assert!(matches!(
        err,
        ResolveError::MissingHost { ref name } if name == "leaf"
    ));
}

#[test]
fn next_sort_order_saturates_at_i32_max() {
    let (_dir, _path, factory) = temp_db();
    MigrationRunner::embedded().run(&factory).unwrap();
    let repo = ConnectionRepository::new(&factory);

    let id = Uuid::parse_str("c0c0c0c0-c0c0-c0c0-c0c0-c0c0c0c0c0c0").unwrap();
    let mut node = folder_node(id, "maxed");
    node.sort_order = i32::MAX;
    repo.insert(&node).unwrap();
    assert_eq!(repo.next_sort_order(None).unwrap(), i32::MAX);
}

#[test]
fn concurrent_create_folder_assigns_distinct_sort_orders() {
    let (_dir, _path, factory) = temp_db();
    MigrationRunner::embedded().run(&factory).unwrap();
    let factory = Arc::new(factory);

    let mut handles = Vec::new();
    for i in 0..8 {
        let factory = Arc::clone(&factory);
        handles.push(thread::spawn(move || {
            let repo = ConnectionRepository::new(&factory);
            repo.create_folder(&format!("f{i}"), None)
                .unwrap()
                .node
                .sort_order
        }));
    }
    let mut orders: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    orders.sort_unstable();
    assert_eq!(orders, (0..8).collect::<Vec<_>>());
}

#[test]
fn settings_store_temp_dir_round_trip_and_fail_closed() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("settings.json");
    let store = SettingsStore::new(&path);

    let mut settings = AppSettings::default();
    settings.sidebar_width = 280;
    settings.prompt_before_tunnel_connect = false;
    store.save(&settings).unwrap();

    let loaded = store.load().unwrap();
    assert_eq!(loaded.sidebar_width, 280);
    assert!(!loaded.prompt_before_tunnel_connect);

    // No secrets in fixtures.
    let raw = fs::read_to_string(&path).unwrap();
    assert!(!raw.contains("BEGIN "));
    assert!(!raw.to_ascii_lowercase().contains("\"password\":"));

    fs::write(&path, b"{broken").unwrap();
    assert!(matches!(
        store.load().unwrap_err(),
        StorageError::CorruptSettings { .. }
    ));
}

#[test]
fn tunnel_config_insert_list_get_update_delete_round_trip() {
    let (_dir, _path, factory) = temp_db();
    MigrationRunner::embedded().run(&factory).unwrap();
    let repo = TunnelConfigRepository::new(&factory);

    let id_b = Uuid::parse_str("a1111111-bbbb-1111-1111-111111111111").unwrap();
    let id_a = Uuid::parse_str("a2222222-aaaa-2222-2222-222222222222").unwrap();

    let stored_b = repo
        .insert(id_b, "bravo-wg", TunnelKind::WireGuard)
        .unwrap();
    assert_eq!(stored_b.id, id_b);
    assert_eq!(stored_b.name, "bravo-wg");
    assert_eq!(stored_b.kind, TunnelKind::WireGuard);
    assert_eq!(stored_b.created_at, stored_b.updated_at);

    let stored_a = repo.insert(id_a, "alpha-ovpn", TunnelKind::OpenVpn).unwrap();
    assert_eq!(stored_a.kind, TunnelKind::OpenVpn);

    // list_all is ordered by Name.
    let all = repo.list_all().unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].name, "alpha-ovpn");
    assert_eq!(all[1].name, "bravo-wg");

    let got = repo.get_by_id(id_b).unwrap().unwrap();
    assert_eq!(got.name, "bravo-wg");

    // Case-insensitive GUID lookup (hand-edited DBs may store uppercase).
    {
        let conn = factory.open().unwrap();
        conn.execute(
            "UPDATE TunnelConfigs SET Id = ?1 WHERE Id = ?2;",
            rusqlite::params![
                "A1111111-BBBB-1111-1111-111111111111",
                format_guid_d(id_b)
            ],
        )
        .unwrap();
    }
    assert_eq!(repo.get_by_id(id_b).unwrap().unwrap().name, "bravo-wg");

    // Writers emit lowercase format D + parseable O timestamps; no secret columns.
    {
        let conn = factory.open().unwrap();
        // Re-insert a fresh row for writer-shape assertions (prior row was uppercased).
        let id_c = Uuid::parse_str("a3333333-cccc-3333-3333-333333333333").unwrap();
        repo.insert(id_c, "charlie", TunnelKind::AzureVpn).unwrap();
        let (id_text, name, kind, created, updated): (String, String, i32, String, String) = conn
            .query_row(
                "SELECT Id, Name, Kind, CreatedAt, UpdatedAt FROM TunnelConfigs WHERE Id = ?1;",
                rusqlite::params![format_guid_d(id_c)],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert_eq!(id_text, "a3333333-cccc-3333-3333-333333333333");
        assert_eq!(name, "charlie");
        assert_eq!(kind, 5);
        parse_timestamp_o(&created).unwrap();
        parse_timestamp_o(&updated).unwrap();

        let col_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('TunnelConfigs');",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(col_count, 5, "TunnelConfigs must stay metadata-only");
    }

    repo.delete(id_a).unwrap();
    assert!(repo.get_by_id(id_a).unwrap().is_none());

    repo.delete(id_b).unwrap();
    // Remaining: charlie from writer-shape block.
    assert_eq!(repo.list_all().unwrap().len(), 1);
}

#[test]
fn tunnel_config_update_preserves_caller_updated_at_verbatim() {
    // Parity with C# TunnelConfigRepository.UpdateAsync: do NOT auto-stamp UpdatedAt.
    // TunnelManager invalidates pooled tunnels when UpdatedAt changes; editors must bump
    // only after the DPAPI payload is on disk (Name/Kind first with old stamp, then bump).
    let (_dir, _path, factory) = temp_db();
    MigrationRunner::embedded().run(&factory).unwrap();
    let repo = TunnelConfigRepository::new(&factory);

    let id = Uuid::parse_str("b1111111-1111-1111-1111-111111111111").unwrap();
    let stored = repo.insert(id, "edge", TunnelKind::Fortinet).unwrap();
    let created_at = stored.created_at;
    // Use the DB-round-tripped stamp so later equality checks are stable under O truncation.
    let old_stamp = repo.get_by_id(id).unwrap().unwrap().updated_at;

    std::thread::sleep(std::time::Duration::from_millis(5));

    // Name/Kind write with the OLD stamp (payload not published yet).
    let mut row = TunnelConfig {
        id,
        name: "edge-renamed".into(),
        kind: TunnelKind::Watchguard,
        created_at,
        updated_at: old_stamp,
    };
    repo.update(&row).unwrap();

    let after_name = repo.get_by_id(id).unwrap().unwrap();
    assert_eq!(after_name.name, "edge-renamed");
    assert_eq!(after_name.kind, TunnelKind::Watchguard);
    assert_eq!(after_name.updated_at, old_stamp);
    assert_eq!(
        format_timestamp_o(after_name.created_at),
        format_timestamp_o(created_at)
    );

    // Publish invalidation only after "secret store" would have completed.
    let bump = Utc::now();
    assert!(bump > old_stamp);
    row.updated_at = bump;
    repo.update(&row).unwrap();

    let after_bump = repo.get_by_id(id).unwrap().unwrap();
    // Round-trip through format O (7 fractional digits) — compare the persisted text shape.
    assert_eq!(
        format_timestamp_o(after_bump.updated_at),
        format_timestamp_o(bump)
    );
    assert!(after_bump.updated_at > old_stamp);
    assert_eq!(
        format_timestamp_o(after_bump.created_at),
        format_timestamp_o(created_at)
    );
    assert_eq!(after_bump.name, "edge-renamed");
}

#[test]
fn tunnel_config_duplicate_name_rejected_by_unique_index() {
    let (_dir, _path, factory) = temp_db();
    MigrationRunner::embedded().run(&factory).unwrap();
    let repo = TunnelConfigRepository::new(&factory);

    let a = Uuid::parse_str("c1111111-1111-1111-1111-111111111111").unwrap();
    let b = Uuid::parse_str("c2222222-2222-2222-2222-222222222222").unwrap();
    repo.insert(a, "dup", TunnelKind::WireGuard).unwrap();
    let err = repo.insert(b, "dup", TunnelKind::OpenVpn).unwrap_err();
    assert!(matches!(err, StorageError::Sqlite(_)), "got {err:?}");
    assert_eq!(repo.list_all().unwrap().len(), 1);
}

#[test]
fn tunnel_config_binds_hostile_name_without_sql_injection() {
    let (_dir, _path, factory) = temp_db();
    MigrationRunner::embedded().run(&factory).unwrap();
    let repo = TunnelConfigRepository::new(&factory);
    let id = Uuid::parse_str("d1111111-dddd-1111-1111-111111111111").unwrap();
    let hostile = "'; DROP TABLE TunnelConfigs;--";
    repo.insert(id, hostile, TunnelKind::CiscoSecureClient)
        .unwrap();
    let row = repo.get_by_id(id).unwrap().unwrap();
    assert_eq!(row.name, hostile);
    assert_eq!(repo.list_all().unwrap().len(), 1);
}

#[test]
fn tunnel_config_rejects_unknown_kind_on_read() {
    let (_dir, _path, factory) = temp_db();
    MigrationRunner::embedded().run(&factory).unwrap();
    let id = Uuid::parse_str("e1111111-eeee-1111-1111-111111111111").unwrap();
    {
        let conn = factory.open().unwrap();
        conn.execute(
            "INSERT INTO TunnelConfigs (Id, Name, Kind, CreatedAt, UpdatedAt)
             VALUES (?1, 'bad', 99, ?2, ?2);",
            rusqlite::params![format_guid_d(id), format_timestamp_o(Utc::now())],
        )
        .unwrap();
    }
    let repo = TunnelConfigRepository::new(&factory);
    let err = repo.list_all().unwrap_err();
    assert!(matches!(err, StorageError::Sqlite(_)), "got {err:?}");
    let err = repo.get_by_id(id).unwrap_err();
    assert!(matches!(err, StorageError::Sqlite(_)), "got {err:?}");
}

#[test]
fn tunnel_config_rejects_blank_name_on_insert_and_update() {
    let (_dir, _path, factory) = temp_db();
    MigrationRunner::embedded().run(&factory).unwrap();
    let repo = TunnelConfigRepository::new(&factory);
    let id = Uuid::parse_str("f1111111-ffff-1111-1111-111111111111").unwrap();

    for blank in ["", "   ", "\t\n"] {
        let err = repo
            .insert(id, blank, TunnelKind::WireGuard)
            .unwrap_err();
        assert!(
            matches!(err, StorageError::InvalidArgument(_)),
            "insert blank {blank:?}: {err:?}"
        );
    }
    assert!(repo.list_all().unwrap().is_empty());

    let stored = repo.insert(id, "  keep-me  ", TunnelKind::OpenVpn).unwrap();
    assert_eq!(stored.name, "keep-me");
    assert_eq!(repo.get_by_id(id).unwrap().unwrap().name, "keep-me");

    let mut row = repo.get_by_id(id).unwrap().unwrap();
    row.name = "   ".into();
    let err = repo.update(&row).unwrap_err();
    assert!(matches!(err, StorageError::InvalidArgument(_)), "got {err:?}");
    assert_eq!(repo.get_by_id(id).unwrap().unwrap().name, "keep-me");

    row.name = "  renamed  ".into();
    repo.update(&row).unwrap();
    assert_eq!(repo.get_by_id(id).unwrap().unwrap().name, "renamed");
}

#[test]
fn tunnel_config_duplicate_id_insert_rejected() {
    let (_dir, _path, factory) = temp_db();
    MigrationRunner::embedded().run(&factory).unwrap();
    let repo = TunnelConfigRepository::new(&factory);
    let id = Uuid::parse_str("f2222222-ffff-2222-2222-222222222222").unwrap();
    repo.insert(id, "first", TunnelKind::WireGuard).unwrap();
    let err = repo
        .insert(id, "second", TunnelKind::Fortinet)
        .unwrap_err();
    assert!(matches!(err, StorageError::Sqlite(_)), "got {err:?}");
    let all = repo.list_all().unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].name, "first");
    assert_eq!(all[0].kind, TunnelKind::WireGuard);
}

#[test]
fn tunnel_config_update_duplicate_name_rejected() {
    let (_dir, _path, factory) = temp_db();
    MigrationRunner::embedded().run(&factory).unwrap();
    let repo = TunnelConfigRepository::new(&factory);
    let a = Uuid::parse_str("f3333333-ffff-3333-3333-333333333333").unwrap();
    let b = Uuid::parse_str("f4444444-ffff-4444-4444-444444444444").unwrap();
    repo.insert(a, "alpha", TunnelKind::WireGuard).unwrap();
    let mut beta = repo.insert(b, "beta", TunnelKind::OpenVpn).unwrap();
    beta.name = "alpha".into();
    let err = repo.update(&beta).unwrap_err();
    assert!(matches!(err, StorageError::Sqlite(_)), "got {err:?}");
    assert_eq!(repo.get_by_id(b).unwrap().unwrap().name, "beta");
}

#[test]
fn tunnel_config_delete_succeeds_even_when_node_references_id() {
    // Repo-layer fail-open: C# DeleteAsync likewise does not check Nodes.TunnelConfigId;
    // editors must refuse in-use deletes (TunnelConfigsViewModel + IX_Nodes_TunnelConfigId).
    let (_dir, _path, factory) = temp_db();
    MigrationRunner::embedded().run(&factory).unwrap();
    let repo = TunnelConfigRepository::new(&factory);
    let tunnel_id = Uuid::parse_str("f5555555-ffff-5555-5555-555555555555").unwrap();
    let node_id = Uuid::parse_str("f6666666-ffff-6666-6666-666666666666").unwrap();
    repo.insert(tunnel_id, "in-use", TunnelKind::WireGuard).unwrap();
    {
        let conn = factory.open().unwrap();
        let now = format_timestamp_o(Utc::now());
        conn.execute(
            "INSERT INTO Nodes (Id, ParentId, Name, Kind, SortOrder, TunnelEnabled, TunnelConfigId, CreatedAt, UpdatedAt)
             VALUES (?1, NULL, 'conn', 1, 0, 1, ?2, ?3, ?3);",
            rusqlite::params![format_guid_d(node_id), format_guid_d(tunnel_id), now],
        )
        .unwrap();
    }
    repo.delete(tunnel_id).unwrap();
    assert!(repo.get_by_id(tunnel_id).unwrap().is_none());
    // Orphan reference left on the node — intentional repo fail-open.
    let conn = factory.open().unwrap();
    let leftover: String = conn
        .query_row(
            "SELECT TunnelConfigId FROM Nodes WHERE Id = ?1;",
            rusqlite::params![format_guid_d(node_id)],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(leftover, format_guid_d(tunnel_id));
}
