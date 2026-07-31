//! Temp-DB round-trips for connection-editor save → `ConnectionRepository` glue.
//!
//! Requires `--features storage`. Uses [`FakePasswordStore`] so CredMgr is never touched.

use uuid::Uuid;
use wormhole_domain::{CredentialBindingMode, ProtocolType};
use wormhole_secrets_win::{FakePasswordStore, PasswordStore};
use wormhole_storage::{ConnectionRepository, MigrationRunner, SqliteConnectionFactory};
use wormhole_ui::{
    load_inline_secret, save_validated_editor, ConnectionEditorMode, ConnectionEditorState,
    EditorSaveError, EditorSaveOp,
};

fn factory() -> (tempfile::TempDir, SqliteConnectionFactory) {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("wormhole.db");
    let factory = SqliteConnectionFactory::new(&db);
    MigrationRunner::embedded().run(&factory).unwrap();
    (dir, factory)
}

fn valid_rdp() -> ConnectionEditorState {
    let mut s = ConnectionEditorState::new(ConnectionEditorMode::Persistent);
    s.name = "desk".into();
    s.protocol = ProtocolType::Rdp;
    s.host = "rdp.local".into();
    s.port = Some(3389);
    s
}

#[test]
fn insert_then_update_round_trip_preserves_fields() {
    let (_dir, factory) = factory();
    let repo = ConnectionRepository::new(&factory);
    let passwords = FakePasswordStore::new();

    let mut state = valid_rdp();
    state.username = "admin".into();
    let inserted =
        save_validated_editor(&mut state, &repo, &passwords, EditorSaveOp::Insert).unwrap();
    let id = inserted.stored.node.id;

    let mut again = ConnectionEditorState::new(ConnectionEditorMode::Persistent);
    again.load_from(&inserted.stored.node, ConnectionEditorMode::Persistent);
    again.name = "desk-2".into();
    again.port = Some(3390);
    let updated =
        save_validated_editor(&mut again, &repo, &passwords, EditorSaveOp::Update).unwrap();

    assert_eq!(updated.stored.node.id, id);
    assert_eq!(updated.stored.node.name, "desk-2");
    assert_eq!(updated.stored.node.port, Some(3390));
    assert_eq!(updated.stored.node.username.as_deref(), Some("admin"));
    assert!(passwords.is_empty());
}

#[test]
fn inline_password_stays_out_of_band_across_insert_and_clear() {
    let (_dir, factory) = factory();
    let repo = ConnectionRepository::new(&factory);
    let passwords = FakePasswordStore::new();

    let mut state = valid_rdp();
    state.set_use_saved_credentials(false);
    state.inline_password = "inline-rdp-secret".into();
    let inserted =
        save_validated_editor(&mut state, &repo, &passwords, EditorSaveOp::Insert).unwrap();
    let id = inserted.stored.node.id;

    let row = repo.get_by_id(id).unwrap().unwrap();
    assert_eq!(row.node.use_inline_password, Some(true));
    assert_eq!(
        passwords.read(&id).unwrap().as_deref(),
        Some("inline-rdp-secret")
    );
    assert!(state.inline_password.is_empty());
    assert!(!format!("{state:?}").contains("inline-rdp-secret"));
    assert!(!format!("{inserted:?}").contains("inline-rdp-secret"));

    // Clear password while staying inline → purge CredMgr (never store "").
    let mut cleared = ConnectionEditorState::new(ConnectionEditorMode::Persistent);
    cleared.load_from(&row.node, ConnectionEditorMode::Persistent);
    cleared.set_use_saved_credentials(false);
    cleared.inline_password.clear();
    save_validated_editor(&mut cleared, &repo, &passwords, EditorSaveOp::Update).unwrap();
    assert!(passwords.read(&id).unwrap().is_none());
}

#[test]
fn http_connection_insert_has_no_credmgr_touch_for_password() {
    let (_dir, factory) = factory();
    let repo = ConnectionRepository::new(&factory);
    let passwords = FakePasswordStore::new();

    let mut state = ConnectionEditorState::new(ConnectionEditorMode::Persistent);
    state.name = "fw".into();
    state.protocol = ProtocolType::Http;
    state.host = "10.0.0.1:8443".into();
    // Hostile: leftover chrome password must not be stored for credential-less protocols.
    state.inline_password = "should-not-store".into();

    let result =
        save_validated_editor(&mut state, &repo, &passwords, EditorSaveOp::Insert).unwrap();
    assert_eq!(result.stored.node.use_inline_password, Some(false));
    assert!(passwords.read(&result.stored.node.id).unwrap().is_none());
    // delete still runs (idempotent purge) — store must not.
    assert_eq!(passwords.store_calls(), 0);
    assert!(!format!("{result:?}").contains("should-not-store"));
}

#[test]
fn update_nil_id_rejected_without_writes() {
    let (_dir, factory) = factory();
    let repo = ConnectionRepository::new(&factory);
    let passwords = FakePasswordStore::new();

    let mut state = valid_rdp();
    state.editing_node_id = Uuid::nil();
    let err =
        save_validated_editor(&mut state, &repo, &passwords, EditorSaveOp::Update).unwrap_err();
    assert!(matches!(err, EditorSaveError::InvalidNode(_)));
    assert!(repo.list_all().unwrap().is_empty());
}

#[test]
fn leaving_inline_for_saved_credential_purges_secret() {
    let (_dir, factory) = factory();
    let repo = ConnectionRepository::new(&factory);
    let passwords = FakePasswordStore::new();

    let mut state = valid_rdp();
    state.set_use_saved_credentials(false);
    state.inline_password = "s3cret".into();
    let inserted =
        save_validated_editor(&mut state, &repo, &passwords, EditorSaveOp::Insert).unwrap();
    let id = inserted.stored.node.id;

    let mut edited = ConnectionEditorState::new(ConnectionEditorMode::Persistent);
    edited.load_from(&inserted.stored.node, ConnectionEditorMode::Persistent);
    edited.set_use_saved_credentials(true);
    let cred = Uuid::new_v4();
    edited.credential_id = Some(cred);
    edited.credential_mode = Some(CredentialBindingMode::Saved);

    save_validated_editor(&mut edited, &repo, &passwords, EditorSaveOp::Update).unwrap();
    let row = repo.get_by_id(id).unwrap().unwrap();
    assert_eq!(row.node.credential_id, Some(cred));
    assert_eq!(row.node.use_inline_password, Some(false));
    assert!(passwords.read(&id).unwrap().is_none());
    assert!(passwords.read(&cred).unwrap().is_none());
}

#[test]
fn edit_after_load_inline_secret_preserves_password_on_rename() {
    let (_dir, factory) = factory();
    let repo = ConnectionRepository::new(&factory);
    let passwords = FakePasswordStore::new();

    let mut state = valid_rdp();
    state.set_use_saved_credentials(false);
    state.inline_password = "persist-me".into();
    let inserted =
        save_validated_editor(&mut state, &repo, &passwords, EditorSaveOp::Insert).unwrap();
    let id = inserted.stored.node.id;

    let mut edited = ConnectionEditorState::new(ConnectionEditorMode::Persistent);
    edited.load_from(&inserted.stored.node, ConnectionEditorMode::Persistent);
    load_inline_secret(&mut edited, &passwords).unwrap();
    edited.name = "desk-renamed".into();
    save_validated_editor(&mut edited, &repo, &passwords, EditorSaveOp::Update).unwrap();

    assert_eq!(
        passwords.read(&id).unwrap().as_deref(),
        Some("persist-me")
    );
    assert_eq!(repo.get_by_id(id).unwrap().unwrap().node.name, "desk-renamed");
}
