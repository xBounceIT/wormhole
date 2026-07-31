//! Ignored helper: regenerate `wormhole-testkit/fixtures/empty-schema.db`.
//!
//! ```powershell
//! cargo test -p wormhole-storage --test generate_empty_schema_fixture -- --ignored --nocapture
//! ```

use std::fs;

use wormhole_storage::{MigrationRunner, SqliteConnectionFactory};

#[test]
#[ignore = "run manually to regenerate the golden empty-schema fixture"]
fn generate_empty_schema_fixture() {
    let dest = wormhole_testkit::empty_schema_db();
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    if dest.exists() {
        fs::remove_file(&dest).unwrap();
    }

    let factory = SqliteConnectionFactory::new(&dest);
    MigrationRunner::embedded().run(&factory).expect("migrate fixture");

    // Ensure schema-only (no node rows).
    let conn = factory.open().unwrap();
    let nodes: i64 = conn
        .query_row("SELECT COUNT(*) FROM Nodes;", [], |r| r.get(0))
        .unwrap();
    assert_eq!(nodes, 0);

    println!("wrote {}", dest.display());
}
