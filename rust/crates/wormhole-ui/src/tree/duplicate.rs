//! Connection-tree Duplicate glue (pure state).
//!
//! Mirrors C# `ConnectionTreeViewModel.Duplicate` + `ConnectionNode.CloneAsNewIdentity`:
//! copy the source node's **own** fields (not the inheritance-resolved profile) under the
//! same parent with a fresh Id, `" (copy)"` name suffix, and append `SortOrder`.
//!
//! Folders are rejected (`NotAConnection`) — C# silently no-ops; Lab fail-closes.
//! Missing source fail-closes. **No secret bodies** are copied into SQLite / Fake rows:
//! CredMgr inline passwords are keyed by node Id (flag cleared); shared credential /
//! tunnel **ids** are re-used by design (pool references, not secret material).
//!
//! Persist stub:
//! - Fake / [`MemoryConnectionSource`] appends the built row.
//! - `--features storage` calls [`wormhole_storage::ConnectionRepository::duplicate_connection`].
//!
//! No GPUI.

use thiserror::Error;
use uuid::Uuid;
use wormhole_domain::{ConnectionNode, NodeKind};

use super::reparent::next_sort_order;
use super::source::{ConnectionNodeSource, MemoryConnectionSource};
use super::TreeError;

/// Suffix appended to the source display name (C# `$"{source.Name} (copy)"`).
pub const DUPLICATE_NAME_SUFFIX: &str = " (copy)";

/// A built duplicate ready to persist (not yet written).
#[derive(Debug, Clone)]
pub struct BuiltDuplicate {
    pub source_id: Uuid,
    pub node: ConnectionNode,
}

/// Duplicate validation / apply failures.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DuplicateError {
    /// Source id missing from the flat snapshot / repository.
    #[error("node not found: {0}")]
    NotFound(Uuid),

    /// Folders cannot be duplicated (C# Duplicate command no-ops; Lab rejects).
    #[error("duplicate requires a connection node (got folder {0})")]
    NotAConnection(Uuid),

    /// Built / applied row id already present in the Fake snapshot (hostile collision).
    #[error("duplicate id already exists: {0}")]
    IdCollision(Uuid),

    /// [`ConnectionNodeSource::list_all`] failed.
    #[error(transparent)]
    Source(#[from] TreeError),

    /// Storage / repository failure (message only — no secrets).
    #[error("storage error: {0}")]
    Storage(String),
}

/// Build a duplicate connection under the same parent from a flat snapshot.
///
/// - Missing id → [`DuplicateError::NotFound`]
/// - Folder → [`DuplicateError::NotAConnection`]
/// - Otherwise: [`ConnectionNode::clone_as_new_identity`], name `"{name} (copy)"`,
///   `SortOrder` = next sibling under `ParentId`
pub fn build_duplicate(
    nodes: &[ConnectionNode],
    source_id: Uuid,
) -> Result<BuiltDuplicate, DuplicateError> {
    let source = nodes
        .iter()
        .find(|n| n.id == source_id)
        .ok_or(DuplicateError::NotFound(source_id))?;
    if source.kind != NodeKind::Connection {
        return Err(DuplicateError::NotAConnection(source_id));
    }

    let mut node = source.clone_as_new_identity();
    // Extremely unlikely; regenerate once if the fresh id collides with the snapshot.
    if nodes.iter().any(|n| n.id == node.id) {
        node.id = Uuid::new_v4();
        if nodes.iter().any(|n| n.id == node.id) {
            return Err(DuplicateError::IdCollision(node.id));
        }
    }
    node.name = format!("{}{DUPLICATE_NAME_SUFFIX}", source.name);
    node.parent_id = source.parent_id;
    node.sort_order = next_sort_order(nodes, source.parent_id);

    Ok(BuiltDuplicate { source_id, node })
}

/// Same as [`build_duplicate`], loading via a [`ConnectionNodeSource`] (Fake /
/// [`MemoryConnectionSource`] in unit tests).
pub fn build_duplicate_from<S: ConnectionNodeSource + ?Sized>(
    source: &S,
    source_id: Uuid,
) -> Result<BuiltDuplicate, DuplicateError> {
    let nodes = source.list_all()?;
    build_duplicate(&nodes, source_id)
}

/// Append a built duplicate onto the Fake [`MemoryConnectionSource`].
///
/// Re-builds against the **live** snapshot (source still a connection) so a stale
/// [`BuiltDuplicate`] fail-closes after delete / kind drift. Keeps `built.node.id` when
/// that id is still free (hosts may have already advertised it); otherwise uses the
/// freshly minted id. Always takes live name / parent / sort / identity-scoped clears.
pub fn apply_duplicate_memory(
    source: &mut MemoryConnectionSource,
    built: &BuiltDuplicate,
) -> Result<ConnectionNode, DuplicateError> {
    let live = build_duplicate(source.nodes(), built.source_id)?;
    let mut node = live.node;
    if built.node.id != node.id {
        if source.nodes().iter().any(|n| n.id == built.node.id) {
            return Err(DuplicateError::IdCollision(built.node.id));
        }
        node.id = built.node.id;
    }
    // Identity-scoped clears (also enforced by clone_as_new_identity on the live rebuild).
    node.ssh_known_host_fingerprint = None;
    node.use_inline_password = Some(false);

    if source.nodes().iter().any(|n| n.id == node.id) {
        return Err(DuplicateError::IdCollision(node.id));
    }
    let mut nodes = source.nodes().to_vec();
    nodes.push(node.clone());
    source.set_nodes(nodes);
    Ok(node)
}

/// Build then append on Fake [`MemoryConnectionSource`].
pub fn duplicate_memory(
    source: &mut MemoryConnectionSource,
    source_id: Uuid,
) -> Result<ConnectionNode, DuplicateError> {
    let built = build_duplicate(source.nodes(), source_id)?;
    apply_duplicate_memory(source, &built)
}

/// Persist a connection duplicate via storage.
///
/// Repository loads the source row (fail-closed missing), rejects folders, inserts the
/// clone. Never copies CredMgr / DPAPI secret bodies — only node metadata (+ shared pool
/// credential / tunnel ids).
#[cfg(feature = "storage")]
pub fn duplicate_connection_storage(
    repo: &wormhole_storage::ConnectionRepository<'_>,
    source_id: Uuid,
) -> Result<wormhole_storage::StoredConnectionNode, DuplicateError> {
    const FOLDER_MSG: &str = "duplicate_connection requires a connection node";
    repo.duplicate_connection(source_id)
        .map_err(|e| match e {
            wormhole_storage::StorageError::NotFound(id) => DuplicateError::NotFound(id),
            wormhole_storage::StorageError::InvalidArgument(msg) if msg == FOLDER_MSG => {
                DuplicateError::NotAConnection(source_id)
            }
            other => DuplicateError::Storage(other.to_string()),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use wormhole_domain::ProtocolType;

    fn folder(id: Uuid, parent: Option<Uuid>, name: &str, sort: i32) -> ConnectionNode {
        ConnectionNode {
            id,
            parent_id: parent,
            name: name.to_string(),
            kind: NodeKind::Folder,
            sort_order: sort,
            ..Default::default()
        }
    }

    fn conn(id: Uuid, parent: Option<Uuid>, name: &str, sort: i32) -> ConnectionNode {
        ConnectionNode {
            id,
            parent_id: parent,
            name: name.to_string(),
            kind: NodeKind::Connection,
            sort_order: sort,
            protocol: Some(ProtocolType::Ssh),
            host: Some("h".into()),
            credential_id: Some(Uuid::new_v4()),
            use_inline_password: Some(true),
            ssh_known_host_fingerprint: Some("pinned".into()),
            tunnel_config_id: Some(Uuid::new_v4()),
            ..Default::default()
        }
    }

    #[test]
    fn duplicates_connection_under_same_parent() {
        let folder_id = Uuid::new_v4();
        let leaf = Uuid::new_v4();
        let nodes = vec![
            folder(folder_id, None, "A", 0),
            conn(leaf, Some(folder_id), "prod", 0),
        ];
        let built = build_duplicate(&nodes, leaf).unwrap();
        assert_eq!(built.source_id, leaf);
        assert_ne!(built.node.id, leaf);
        assert_eq!(built.node.parent_id, Some(folder_id));
        assert_eq!(built.node.name, "prod (copy)");
        assert_eq!(built.node.sort_order, 1);
        assert_eq!(built.node.kind, NodeKind::Connection);
        assert_eq!(built.node.host.as_deref(), Some("h"));
        assert!(built.node.ssh_known_host_fingerprint.is_none());
        assert_eq!(built.node.use_inline_password, Some(false));
        // Shared pool refs preserved (not secret bodies).
        assert_eq!(
            built.node.credential_id,
            nodes[1].credential_id
        );
        assert_eq!(
            built.node.tunnel_config_id,
            nodes[1].tunnel_config_id
        );
    }

    #[test]
    fn rejects_folder_and_missing() {
        let folder_id = Uuid::new_v4();
        let missing = Uuid::new_v4();
        let nodes = vec![folder(folder_id, None, "A", 0)];
        assert_eq!(
            build_duplicate(&nodes, folder_id).unwrap_err(),
            DuplicateError::NotAConnection(folder_id)
        );
        assert_eq!(
            build_duplicate(&nodes, missing).unwrap_err(),
            DuplicateError::NotFound(missing)
        );
    }

    #[test]
    fn memory_duplicate_appends_and_fail_closes_deleted_source() {
        let folder_id = Uuid::new_v4();
        let leaf = Uuid::new_v4();
        let mut source = MemoryConnectionSource::new(vec![
            folder(folder_id, None, "A", 0),
            conn(leaf, Some(folder_id), "prod", 0),
        ]);
        let copy = duplicate_memory(&mut source, leaf).unwrap();
        assert_eq!(source.nodes().len(), 3);
        assert!(source.nodes().iter().any(|n| n.id == copy.id));

        let stale = BuiltDuplicate {
            source_id: leaf,
            node: copy.clone(),
        };
        // Delete source — apply must fail closed.
        let kept: Vec<_> = source
            .nodes()
            .iter()
            .filter(|n| n.id != leaf)
            .cloned()
            .collect();
        source.set_nodes(kept);
        assert_eq!(
            apply_duplicate_memory(&mut source, &stale).unwrap_err(),
            DuplicateError::NotFound(leaf)
        );
    }

    #[test]
    fn build_from_fake_source_and_source_failure() {
        let folder_id = Uuid::new_v4();
        let leaf = Uuid::new_v4();
        let source = MemoryConnectionSource::new(vec![
            folder(folder_id, None, "A", 0),
            conn(leaf, Some(folder_id), "prod", 0),
        ]);
        let built = build_duplicate_from(&source, leaf).unwrap();
        assert_eq!(built.node.name, "prod (copy)");

        struct FailingConnectionSource;
        impl ConnectionNodeSource for FailingConnectionSource {
            fn list_all(&self) -> Result<Vec<ConnectionNode>, TreeError> {
                Err(TreeError::Load("injected source failure".into()))
            }
        }
        let err = build_duplicate_from(&FailingConnectionSource, leaf).unwrap_err();
        assert_eq!(
            err,
            DuplicateError::Source(TreeError::Load("injected source failure".into()))
        );
    }

    #[test]
    fn root_connection_duplicate_and_sort_saturates() {
        let leaf = Uuid::new_v4();
        let sibling = Uuid::new_v4();
        let nodes = vec![
            conn(sibling, None, "other", i32::MAX),
            conn(leaf, None, "rooty", 0),
        ];
        let built = build_duplicate(&nodes, leaf).unwrap();
        assert!(built.node.parent_id.is_none());
        assert_eq!(built.node.sort_order, i32::MAX);
        assert_eq!(built.node.name, "rooty (copy)");
    }

    #[test]
    fn apply_rejects_id_collision_on_stale_handle() {
        let folder_id = Uuid::new_v4();
        let leaf = Uuid::new_v4();
        let mut source = MemoryConnectionSource::new(vec![
            folder(folder_id, None, "A", 0),
            conn(leaf, Some(folder_id), "prod", 0),
        ]);
        let built = build_duplicate(source.nodes(), leaf).unwrap();
        // Insert a hostile row that steals the built id before apply.
        let mut nodes = source.nodes().to_vec();
        nodes.push(ConnectionNode {
            id: built.node.id,
            parent_id: Some(folder_id),
            name: "hijack".into(),
            kind: NodeKind::Connection,
            sort_order: 9,
            protocol: Some(ProtocolType::Ssh),
            host: Some("x".into()),
            ..Default::default()
        });
        source.set_nodes(nodes);
        assert_eq!(
            apply_duplicate_memory(&mut source, &built).unwrap_err(),
            DuplicateError::IdCollision(built.node.id)
        );
    }

    #[test]
    fn no_password_body_on_node_after_duplicate() {
        // ConnectionNode has no password body field; inline flag must be false and
        // host-key pin must not carry over (CredMgr secrets stay keyed by Id out-of-band).
        let leaf = Uuid::new_v4();
        let nodes = vec![conn(leaf, None, "secretish", 0)];
        let built = build_duplicate(&nodes, leaf).unwrap();
        assert_eq!(built.node.use_inline_password, Some(false));
        assert!(built.node.ssh_known_host_fingerprint.is_none());
        let debug = format!("{:?}", built.node);
        assert!(!debug.contains("pinned"));
        // No plaintext password payload — only the boolean flag field name may appear.
        assert!(!debug.contains("hunter2"));
        assert!(!debug.contains("PendingInlinePassword"));
    }

    #[test]
    fn unicode_name_and_stacked_copy_suffix() {
        let leaf = Uuid::new_v4();
        let nodes = vec![conn(leaf, None, "ラボ", 0)];
        let first = build_duplicate(&nodes, leaf).unwrap();
        assert_eq!(first.node.name, "ラボ (copy)");
        assert_eq!(
            format!("{}{DUPLICATE_NAME_SUFFIX}", "ラボ"),
            first.node.name
        );
        let mut with_copy = nodes;
        with_copy.push(first.node.clone());
        let second = build_duplicate(&with_copy, first.node.id).unwrap();
        assert_eq!(second.node.name, "ラボ (copy) (copy)");
    }

    #[test]
    fn apply_rejects_when_source_becomes_folder() {
        let folder_id = Uuid::new_v4();
        let leaf = Uuid::new_v4();
        let mut source = MemoryConnectionSource::new(vec![
            folder(folder_id, None, "A", 0),
            conn(leaf, Some(folder_id), "prod", 0),
        ]);
        let built = build_duplicate(source.nodes(), leaf).unwrap();
        // Drift: replace the connection with a folder of the same id.
        let mutated: Vec<_> = source
            .nodes()
            .iter()
            .map(|n| {
                if n.id == leaf {
                    folder(leaf, Some(folder_id), "was-conn", 0)
                } else {
                    n.clone()
                }
            })
            .collect();
        source.set_nodes(mutated);
        assert_eq!(
            apply_duplicate_memory(&mut source, &built).unwrap_err(),
            DuplicateError::NotAConnection(leaf)
        );
    }

    #[test]
    fn apply_keeps_advertised_id_when_free() {
        let leaf = Uuid::new_v4();
        let mut source = MemoryConnectionSource::new(vec![conn(leaf, None, "prod", 0)]);
        let built = build_duplicate(source.nodes(), leaf).unwrap();
        let advertised = built.node.id;
        // Force a re-mint by applying after another sibling was added (sort changes);
        // advertised id must still win when free.
        let mut nodes = source.nodes().to_vec();
        nodes.push(conn(Uuid::new_v4(), None, "other", 1));
        source.set_nodes(nodes);
        let applied = apply_duplicate_memory(&mut source, &built).unwrap();
        assert_eq!(applied.id, advertised);
        assert_eq!(applied.sort_order, 2); // live rebuild
        assert_eq!(applied.use_inline_password, Some(false));
    }

    #[cfg(feature = "storage")]
    mod storage_glue {
        use super::*;
        use wormhole_storage::{ConnectionRepository, MigrationRunner, SqliteConnectionFactory};

        #[test]
        fn storage_duplicate_connection_only() {
            let dir = tempfile::tempdir().unwrap();
            let factory = SqliteConnectionFactory::new(dir.path().join("wormhole.db"));
            MigrationRunner::embedded().run(&factory).unwrap();
            let repo = ConnectionRepository::new(&factory);

            let folder_a = repo.create_folder("A", None).unwrap();
            let cred = Uuid::new_v4();
            let tunnel = Uuid::new_v4();
            let conn_id = Uuid::new_v4();
            repo.insert(&ConnectionNode {
                id: conn_id,
                parent_id: Some(folder_a.node.id),
                name: "prod".into(),
                kind: NodeKind::Connection,
                sort_order: 0,
                protocol: Some(ProtocolType::Ssh),
                host: Some("h".into()),
                credential_id: Some(cred),
                use_inline_password: Some(true),
                ssh_known_host_fingerprint: Some("pinned".into()),
                tunnel_config_id: Some(tunnel),
                ..Default::default()
            })
            .unwrap();

            let stored = duplicate_connection_storage(&repo, conn_id).unwrap();
            assert_ne!(stored.node.id, conn_id);
            assert_eq!(stored.node.parent_id, Some(folder_a.node.id));
            assert_eq!(stored.node.name, "prod (copy)");
            assert_eq!(stored.node.credential_id, Some(cred));
            assert_eq!(stored.node.tunnel_config_id, Some(tunnel));
            assert!(stored.node.ssh_known_host_fingerprint.is_none());
            assert_eq!(stored.node.use_inline_password, Some(false));

            // Folder rejected
            assert_eq!(
                duplicate_connection_storage(&repo, folder_a.node.id).unwrap_err(),
                DuplicateError::NotAConnection(folder_a.node.id)
            );

            // Missing fail-closed
            let missing = Uuid::new_v4();
            assert_eq!(
                duplicate_connection_storage(&repo, missing).unwrap_err(),
                DuplicateError::NotFound(missing)
            );

            // Row count: folder + source + copy
            assert_eq!(repo.list_all().unwrap().len(), 3);
        }
    }
}
