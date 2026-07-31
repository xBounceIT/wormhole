//! Validated [`ConnectionEditorState`] → SQLite insert/update + out-of-band CredMgr glue.
//!
//! Mirrors `ConnectionTreeViewModel.SafeAddAsync` / `SafeUpdateAsync` +
//! `ApplyInlineSecretAsync`: the DB row never holds the plaintext; CredMgr (or a
//! [`PasswordStore`] fake) is keyed by **node Id**. See
//! `docs/migration/20-connection-editor.md`.

use std::fmt;

use uuid::Uuid;
use wormhole_domain::NodeKind;
use wormhole_secrets_win::PasswordStore;
use wormhole_storage::{ConnectionRepository, StoredConnectionNode};

use super::state::{ConnectionEditorMode, ConnectionEditorState};
use super::validation::ValidationReport;

/// Insert a new connection row vs update an existing one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EditorSaveOp {
    /// `ConnectionRepository::insert` (new tree connection).
    Insert,
    /// `ConnectionRepository::update` (edit existing connection).
    Update,
}

/// Successful persist — domain row + audit timestamps. Never carries a password.
#[derive(Debug, Clone)]
pub struct EditorSaveResult {
    pub stored: StoredConnectionNode,
    pub op: EditorSaveOp,
}

/// Failures from validate → write → CredMgr apply. Display/Debug never embed secrets.
#[derive(Clone)]
pub enum EditorSaveError {
    /// Editor failed the save-button validation matrix.
    Validation(ValidationReport),
    /// Quick Connect / ephemeral editors are not persisted through this path.
    EphemeralNotPersistable,
    /// Nil id on update, or unexpected non-connection kind after write.
    InvalidNode(&'static str),
    /// SQLite / repository failure (message only — no secrets).
    Storage(String),
    /// CredMgr / [`PasswordStore`] failure (message only — no secrets).
    Secrets(String),
}

impl fmt::Debug for EditorSaveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation(report) => f.debug_tuple("Validation").field(report).finish(),
            Self::EphemeralNotPersistable => write!(f, "EphemeralNotPersistable"),
            Self::InvalidNode(msg) => f.debug_tuple("InvalidNode").field(msg).finish(),
            Self::Storage(msg) => f.debug_tuple("Storage").field(msg).finish(),
            Self::Secrets(msg) => f.debug_tuple("Secrets").field(msg).finish(),
        }
    }
}

impl fmt::Display for EditorSaveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation(report) => {
                write!(f, "connection editor validation failed")?;
                if let Some(first) = report.errors.first() {
                    write!(f, ": {}", first.as_str())?;
                }
                Ok(())
            }
            Self::EphemeralNotPersistable => {
                write!(
                    f,
                    "Quick Connect editor state cannot be saved to the connection repository"
                )
            }
            Self::InvalidNode(msg) => write!(f, "invalid connection node for save: {msg}"),
            Self::Storage(msg) => write!(f, "storage error: {msg}"),
            Self::Secrets(msg) => write!(f, "credential store error: {msg}"),
        }
    }
}

impl std::error::Error for EditorSaveError {}

/// Populate [`ConnectionEditorState::inline_password`] from CredMgr when editing a
/// connection that already uses an inline password.
///
/// Mirrors C# `ConnectionEditorViewModel.LoadInlineSecretAsync` — call after
/// [`ConnectionEditorState::load_from`] so a subsequent save that does not clear
/// the password field re-stores the same secret instead of purging it.
pub fn load_inline_secret(
    state: &mut ConnectionEditorState,
    passwords: &dyn PasswordStore,
) -> Result<(), EditorSaveError> {
    if !state.loaded_uses_inline_password() || state.editing_node_id.is_nil() {
        return Ok(());
    }
    let secret = passwords
        .read(&state.editing_node_id)
        .map_err(|e| EditorSaveError::Secrets(e.to_string()))?;
    state.inline_password = secret.unwrap_or_default();
    Ok(())
}

/// Validate `state`, map to a [`ConnectionNode`], insert or update via `repo`, then
/// apply the out-of-band inline password through `passwords`.
///
/// - Pending plaintext never lands on the node / SQLite row.
/// - CredMgr key is the **node Id** (not a saved credential id).
/// - Blank inline password or leaving inline mode **deletes** any prior secret.
/// - Clears [`ConnectionEditorState::inline_password`] after a successful apply.
/// - On `Insert`, a CredMgr failure after the DB write rolls back the new row so
///   retry stays an Insert (Update path keeps the committed row; chrome retains
///   the plaintext for retry).
///
/// `Debug` of `state` continues to redact the password field.
pub fn save_validated_editor(
    state: &mut ConnectionEditorState,
    repo: &ConnectionRepository<'_>,
    passwords: &dyn PasswordStore,
    op: EditorSaveOp,
) -> Result<EditorSaveResult, EditorSaveError> {
    if state.mode != ConnectionEditorMode::Persistent {
        return Err(EditorSaveError::EphemeralNotPersistable);
    }

    let report = state.validate();
    if !report.is_valid() {
        return Err(EditorSaveError::Validation(report));
    }

    if op == EditorSaveOp::Insert && state.editing_node_id.is_nil() {
        state.editing_node_id = Uuid::new_v4();
    }
    if op == EditorSaveOp::Update && state.editing_node_id.is_nil() {
        return Err(EditorSaveError::InvalidNode(
            "update requires a non-nil editing_node_id",
        ));
    }

    let (node, pending) = state.to_connection_node();
    if node.kind != NodeKind::Connection {
        return Err(EditorSaveError::InvalidNode(
            "editor save only supports connection nodes",
        ));
    }

    let stored = match op {
        EditorSaveOp::Insert => repo
            .insert(&node)
            .map_err(|e| EditorSaveError::Storage(e.to_string()))?,
        EditorSaveOp::Update => {
            repo.update(&node)
                .map_err(|e| EditorSaveError::Storage(e.to_string()))?;
            repo.get_by_id(node.id)
                .map_err(|e| EditorSaveError::Storage(e.to_string()))?
                .ok_or(EditorSaveError::InvalidNode(
                    "updated connection row was not found",
                ))?
        }
    };

    // Prefer the repository's node snapshot for flags; pending stays local.
    // CredMgr key must be the node Id (never a saved CredentialId).
    debug_assert_eq!(stored.node.id, node.id);
    if let Err(err) = apply_inline_secret(passwords, &stored.node, pending.as_deref()) {
        if op == EditorSaveOp::Insert {
            // Best-effort compensating delete so a failed CredMgr hand-off does not
            // leave a UseInlinePassword row that Insert cannot retry cleanly.
            let _ = repo.delete(stored.node.id);
        }
        // Keep state.inline_password for retry (unlike C# finally-clear on the draft).
        return Err(err);
    }

    // Drop plaintext from the editor chrome after CredMgr hand-off (C# clears
    // PendingInlinePassword on the draft node).
    state.inline_password.clear();

    Ok(EditorSaveResult { stored, op })
}

/// Persist or purge the inline per-connection password after the DB row commits.
///
/// Parity with `ConnectionTreeViewModel.ApplyInlineSecretAsync`.
fn apply_inline_secret(
    passwords: &dyn PasswordStore,
    node: &wormhole_domain::ConnectionNode,
    pending: Option<&str>,
) -> Result<(), EditorSaveError> {
    if node.kind != NodeKind::Connection {
        return Ok(());
    }

    let use_inline = node.use_inline_password == Some(true);
    match (use_inline, pending) {
        (true, Some(secret)) if !secret.is_empty() => {
            passwords
                .store(&node.id, secret)
                .map_err(|e| EditorSaveError::Secrets(e.to_string()))?;
        }
        _ => {
            // Delete (never store empty): switched to saved/prompt, or blank inline.
            passwords
                .delete(&node.id)
                .map_err(|e| EditorSaveError::Secrets(e.to_string()))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use wormhole_domain::ProtocolType;
    use wormhole_secrets_win::{
        FakePasswordStore, PasswordStore, MAX_PASSWORD_UTF16_BYTES,
    };
    use wormhole_storage::{MigrationRunner, SqliteConnectionFactory};

    fn migrated_factory() -> (tempfile::TempDir, SqliteConnectionFactory) {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("wormhole.db");
        let factory = SqliteConnectionFactory::new(&db);
        MigrationRunner::embedded().run(&factory).unwrap();
        (dir, factory)
    }

    fn valid_ssh_editor(name: &str, host: &str) -> ConnectionEditorState {
        let mut s = ConnectionEditorState::new(ConnectionEditorMode::Persistent);
        s.name = name.into();
        s.protocol = ProtocolType::Ssh;
        s.host = host.into();
        s.port = Some(22);
        s
    }

    /// PasswordStore that fails `store` once CredMgr would otherwise succeed.
    struct FailingStore {
        inner: FakePasswordStore,
        fail_store: AtomicBool,
    }

    impl FailingStore {
        fn new() -> Self {
            Self {
                inner: FakePasswordStore::new(),
                fail_store: AtomicBool::new(true),
            }
        }
    }

    impl PasswordStore for FailingStore {
        fn store(&self, credential_id: &Uuid, password: &str) -> wormhole_secrets_win::Result<()> {
            if self.fail_store.swap(false, Ordering::SeqCst) {
                return Err(wormhole_secrets_win::SecretsError::Win32 {
                    op: "CredWriteW",
                    code: 5,
                });
            }
            self.inner.store(credential_id, password)
        }

        fn read(&self, credential_id: &Uuid) -> wormhole_secrets_win::Result<Option<String>> {
            self.inner.read(credential_id)
        }

        fn delete(&self, credential_id: &Uuid) -> wormhole_secrets_win::Result<()> {
            self.inner.delete(credential_id)
        }
    }

    #[test]
    fn insert_round_trip_without_inline_password() {
        let (_dir, factory) = migrated_factory();
        let repo = ConnectionRepository::new(&factory);
        let passwords = FakePasswordStore::new();

        let mut state = valid_ssh_editor("prod", "host.example");
        let result =
            save_validated_editor(&mut state, &repo, &passwords, EditorSaveOp::Insert).unwrap();

        assert_eq!(result.op, EditorSaveOp::Insert);
        assert!(!result.stored.node.id.is_nil());
        assert_eq!(result.stored.node.name, "prod");
        assert_eq!(result.stored.node.host.as_deref(), Some("host.example"));
        assert_eq!(result.stored.node.use_inline_password, Some(false));
        assert!(passwords.is_empty());

        let loaded = repo.get_by_id(result.stored.node.id).unwrap().unwrap();
        assert_eq!(loaded.node.name, "prod");
        assert!(!format!("{result:?}").contains("s3cret"));
    }

    #[test]
    fn insert_stores_inline_password_out_of_band() {
        let (_dir, factory) = migrated_factory();
        let repo = ConnectionRepository::new(&factory);
        let passwords = FakePasswordStore::new();

        let mut state = valid_ssh_editor("inline", "host");
        state.set_use_saved_credentials(false);
        state.inline_password = "s3cret".into();

        let result =
            save_validated_editor(&mut state, &repo, &passwords, EditorSaveOp::Insert).unwrap();

        let row = repo.get_by_id(result.stored.node.id).unwrap().unwrap();
        assert_eq!(row.node.use_inline_password, Some(true));
        // SQLite row must not contain the secret (no password column); CredMgr does.
        assert_eq!(
            passwords.read(&row.node.id).unwrap().as_deref(),
            Some("s3cret")
        );
        assert!(state.inline_password.is_empty());
        assert!(!format!("{state:?}").contains("s3cret"));
        assert!(!format!("{result:?}").contains("s3cret"));
    }

    #[test]
    fn insert_blank_inline_password_does_not_store_empty() {
        let (_dir, factory) = migrated_factory();
        let repo = ConnectionRepository::new(&factory);
        let passwords = FakePasswordStore::new();

        let mut state = valid_ssh_editor("inline", "host");
        state.set_use_saved_credentials(false);
        state.inline_password.clear();

        let result =
            save_validated_editor(&mut state, &repo, &passwords, EditorSaveOp::Insert).unwrap();

        assert_eq!(result.stored.node.use_inline_password, Some(true));
        assert!(passwords.read(&result.stored.node.id).unwrap().is_none());
        assert_eq!(passwords.delete_calls(), 1);
    }

    #[test]
    fn update_round_trip_and_purge_when_leaving_inline() {
        let (_dir, factory) = migrated_factory();
        let repo = ConnectionRepository::new(&factory);
        let passwords = FakePasswordStore::new();

        let mut state = valid_ssh_editor("inline", "host");
        state.set_use_saved_credentials(false);
        state.inline_password = "s3cret".into();
        let inserted =
            save_validated_editor(&mut state, &repo, &passwords, EditorSaveOp::Insert).unwrap();
        let id = inserted.stored.node.id;
        assert_eq!(
            passwords.read(&id).unwrap().as_deref(),
            Some("s3cret")
        );

        // Switch to saved credential — stale CredMgr entry must go.
        let mut edited = ConnectionEditorState::new(ConnectionEditorMode::Persistent);
        edited.load_from(&inserted.stored.node, ConnectionEditorMode::Persistent);
        edited.set_use_saved_credentials(true);
        let cred_id = Uuid::new_v4();
        edited.credential_id = Some(cred_id);
        edited.credential_mode = Some(wormhole_domain::CredentialBindingMode::Saved);
        edited.name = "renamed".into();

        let updated =
            save_validated_editor(&mut edited, &repo, &passwords, EditorSaveOp::Update).unwrap();
        assert_eq!(updated.op, EditorSaveOp::Update);
        assert_eq!(updated.stored.node.name, "renamed");
        assert_eq!(updated.stored.node.credential_id, Some(cred_id));
        assert_eq!(updated.stored.node.use_inline_password, Some(false));
        assert!(passwords.read(&id).unwrap().is_none());
        // Saved credential secret must never be written under the credential Id.
        assert!(passwords.read(&cred_id).unwrap().is_none());
    }

    #[test]
    fn validation_failure_skips_storage_and_secrets() {
        let (_dir, factory) = migrated_factory();
        let repo = ConnectionRepository::new(&factory);
        let passwords = FakePasswordStore::new();

        let mut state = ConnectionEditorState::new(ConnectionEditorMode::Persistent);
        state.inline_password = "must-not-store".into();
        let err = save_validated_editor(&mut state, &repo, &passwords, EditorSaveOp::Insert)
            .unwrap_err();
        assert!(matches!(err, EditorSaveError::Validation(_)));
        assert!(repo.list_all().unwrap().is_empty());
        assert!(passwords.is_empty());
        assert!(!format!("{err:?}").contains("must-not-store"));
        assert!(!format!("{err}").contains("must-not-store"));
    }

    #[test]
    fn quick_connect_rejected() {
        let (_dir, factory) = migrated_factory();
        let repo = ConnectionRepository::new(&factory);
        let passwords = FakePasswordStore::new();

        let mut state = ConnectionEditorState::new(ConnectionEditorMode::QuickConnect);
        state.host = "h".into();
        let err = save_validated_editor(&mut state, &repo, &passwords, EditorSaveOp::Insert)
            .unwrap_err();
        assert!(matches!(err, EditorSaveError::EphemeralNotPersistable));
    }

    #[test]
    fn load_inline_secret_then_update_preserves_credmgr_entry() {
        let (_dir, factory) = migrated_factory();
        let repo = ConnectionRepository::new(&factory);
        let passwords = FakePasswordStore::new();

        let mut state = valid_ssh_editor("inline", "host");
        state.set_use_saved_credentials(false);
        state.inline_password = "keep-me".into();
        let inserted =
            save_validated_editor(&mut state, &repo, &passwords, EditorSaveOp::Insert).unwrap();
        let id = inserted.stored.node.id;

        let mut edited = ConnectionEditorState::new(ConnectionEditorMode::Persistent);
        edited.load_from(&inserted.stored.node, ConnectionEditorMode::Persistent);
        assert!(edited.inline_password.is_empty());
        load_inline_secret(&mut edited, &passwords).unwrap();
        assert_eq!(edited.inline_password, "keep-me");
        edited.name = "renamed".into();

        save_validated_editor(&mut edited, &repo, &passwords, EditorSaveOp::Update).unwrap();
        assert_eq!(
            passwords.read(&id).unwrap().as_deref(),
            Some("keep-me")
        );
        let row = repo.get_by_id(id).unwrap().unwrap();
        assert_eq!(row.node.name, "renamed");
        assert_eq!(row.node.use_inline_password, Some(true));
    }

    #[test]
    fn load_inline_secret_noop_when_not_inline() {
        let (_dir, factory) = migrated_factory();
        let repo = ConnectionRepository::new(&factory);
        let passwords = FakePasswordStore::new();

        let mut state = valid_ssh_editor("saved", "host");
        let inserted =
            save_validated_editor(&mut state, &repo, &passwords, EditorSaveOp::Insert).unwrap();
        // Hostile: leftover entry under node id must not be loaded for non-inline.
        passwords.store(&inserted.stored.node.id, "stale").unwrap();

        let mut edited = ConnectionEditorState::new(ConnectionEditorMode::Persistent);
        edited.load_from(&inserted.stored.node, ConnectionEditorMode::Persistent);
        load_inline_secret(&mut edited, &passwords).unwrap();
        assert!(edited.inline_password.is_empty());
    }

    #[test]
    fn insert_secrets_failure_rolls_back_row_and_keeps_chrome_password() {
        let (_dir, factory) = migrated_factory();
        let repo = ConnectionRepository::new(&factory);
        let passwords = FailingStore::new();

        let mut state = valid_ssh_editor("inline", "host");
        state.set_use_saved_credentials(false);
        state.inline_password = "s3cret".into();

        let err = save_validated_editor(&mut state, &repo, &passwords, EditorSaveOp::Insert)
            .unwrap_err();
        assert!(matches!(err, EditorSaveError::Secrets(_)));
        assert!(!format!("{err}").contains("s3cret"));
        assert_eq!(state.inline_password, "s3cret");
        assert!(repo.list_all().unwrap().is_empty());

        // Retry Insert succeeds once the store accepts writes.
        let result =
            save_validated_editor(&mut state, &repo, &passwords, EditorSaveOp::Insert).unwrap();
        assert_eq!(
            passwords.read(&result.stored.node.id).unwrap().as_deref(),
            Some("s3cret")
        );
        assert!(state.inline_password.is_empty());
    }

    #[test]
    fn insert_oversized_password_fails_closed_without_orphan_row() {
        let (_dir, factory) = migrated_factory();
        let repo = ConnectionRepository::new(&factory);
        let passwords = FakePasswordStore::new();

        let mut state = valid_ssh_editor("inline", "host");
        state.set_use_saved_credentials(false);
        // One UTF-16 unit over the CredMgr limit (ASCII → 2 bytes each).
        let over = "x".repeat((MAX_PASSWORD_UTF16_BYTES / 2) + 1);
        state.inline_password = over.clone();

        let err = save_validated_editor(&mut state, &repo, &passwords, EditorSaveOp::Insert)
            .unwrap_err();
        assert!(matches!(err, EditorSaveError::Secrets(_)));
        assert!(!format!("{err:?}").contains(&over));
        assert_eq!(state.inline_password, over);
        assert!(repo.list_all().unwrap().is_empty());
        assert_eq!(passwords.store_calls(), 1);
        assert_eq!(passwords.reject_calls(), 1);
        assert!(passwords.is_empty());
    }

    #[test]
    fn update_missing_row_skips_secrets() {
        let (_dir, factory) = migrated_factory();
        let repo = ConnectionRepository::new(&factory);
        let passwords = FakePasswordStore::new();

        let mut state = valid_ssh_editor("ghost", "host");
        state.editing_node_id = Uuid::new_v4();
        state.set_use_saved_credentials(false);
        state.inline_password = "must-not-store".into();

        let err =
            save_validated_editor(&mut state, &repo, &passwords, EditorSaveOp::Update).unwrap_err();
        assert!(matches!(err, EditorSaveError::InvalidNode(_)));
        assert!(passwords.is_empty());
        assert_eq!(passwords.store_calls(), 0);
        assert_eq!(passwords.delete_calls(), 0);
        assert_eq!(state.inline_password, "must-not-store");
    }
}
