//! Connection-tree reparent / drag validation glue (pure state).
//!
//! Mirrors C# `ConnectionTreeViewModel.ShouldRejectDragSelection` + the validation
//! subset of `PersistTreeStructureAsync` (search-mode no-op, no children under
//! connections, no folder→descendant cycles). Allows folder **and** connection
//! moves at the validation layer — C# persists both via `UpdateManyAsync`.
//!
//! Persist stub:
//! - Fake / [`MemoryConnectionSource`] mutates `ParentId` (+ append `SortOrder`) for
//!   either kind.
//! - `--features storage` calls [`wormhole_storage::ConnectionRepository::reparent_connection`]
//!   for **connections** only (folder-into-folder full reorder stays UI-side later).
//!
//! No GPUI. Distinct from credential-picker UI in `connection_editor`.

use std::collections::{HashMap, HashSet};

use thiserror::Error;
use uuid::Uuid;
use wormhole_domain::{ConnectionNode, NodeKind};

use super::source::{ConnectionNodeSource, MemoryConnectionSource};
use super::TreeError;

/// Flags that gate drag / reparent (C# `IsSearchActive`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReparentOptions {
    /// When true, every reparent / drag selection is rejected (C# search mode).
    pub search_active: bool,
}

impl ReparentOptions {
    pub const fn new(search_active: bool) -> Self {
        Self { search_active }
    }
}

/// A validated ParentId change (not yet persisted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedReparent {
    pub node_id: Uuid,
    pub kind: NodeKind,
    pub old_parent_id: Option<Uuid>,
    pub new_parent_id: Option<Uuid>,
}

impl ValidatedReparent {
    /// True when ParentId is unchanged (idempotent no-op for hosts).
    pub fn is_noop(&self) -> bool {
        self.old_parent_id == self.new_parent_id
    }
}

/// Reparent / drag validation failures.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ReparentError {
    /// C# `IsSearchActive` — drag persist and selection moves are disabled.
    #[error("reparent rejected: search mode is active")]
    SearchActive,

    /// Node id missing from the flat snapshot.
    #[error("node not found: {0}")]
    NotFound(Uuid),

    /// New parent exists but is a connection (connections cannot contain children).
    #[error("new parent must be a folder (got connection {0})")]
    TargetNotFolder(Uuid),

    /// Moving a node under itself or under one of its descendants.
    #[error("reparent would create an ancestor→descendant cycle")]
    WouldCreateCycle,

    /// [`ConnectionNodeSource::list_all`] failed.
    #[error(transparent)]
    Source(#[from] TreeError),

    /// Folder move validated, but storage stub only persists connection reparents.
    #[error("folder reparent is validated only; storage persist stub is connection-only")]
    FolderPersistUnsupported,

    /// Storage / repository failure (message only — no secrets).
    #[error("storage error: {0}")]
    Storage(String),
}

/// Validate a proposed `ParentId` change against a flat snapshot.
///
/// Rules (C# intent subset):
/// - `search_active` → [`ReparentError::SearchActive`]
/// - missing node / missing new parent → [`ReparentError::NotFound`]
/// - new parent is a connection → [`ReparentError::TargetNotFolder`]
/// - new parent is self or a descendant of the moved node → [`ReparentError::WouldCreateCycle`]
/// - otherwise Ok (folder **or** connection may move; root when `new_parent_id` is `None`)
pub fn validate_reparent(
    nodes: &[ConnectionNode],
    node_id: Uuid,
    new_parent_id: Option<Uuid>,
    options: ReparentOptions,
) -> Result<ValidatedReparent, ReparentError> {
    if options.search_active {
        return Err(ReparentError::SearchActive);
    }

    let by_id: HashMap<Uuid, &ConnectionNode> = nodes.iter().map(|n| (n.id, n)).collect();
    let node = by_id
        .get(&node_id)
        .copied()
        .ok_or(ReparentError::NotFound(node_id))?;

    if let Some(parent_id) = new_parent_id {
        if parent_id == node_id {
            return Err(ReparentError::WouldCreateCycle);
        }
        let parent = by_id
            .get(&parent_id)
            .copied()
            .ok_or(ReparentError::NotFound(parent_id))?;
        if parent.kind != NodeKind::Folder {
            return Err(ReparentError::TargetNotFolder(parent_id));
        }
        // Ancestor→descendant: walking up from the *new parent* hits the moved node.
        if is_ancestor_of(&by_id, node_id, parent_id) {
            return Err(ReparentError::WouldCreateCycle);
        }
    }

    Ok(ValidatedReparent {
        node_id,
        kind: node.kind,
        old_parent_id: node.parent_id,
        new_parent_id,
    })
}

/// Same as [`validate_reparent`], loading via a [`ConnectionNodeSource`] (Fake /
/// [`MemoryConnectionSource`] in unit tests).
pub fn validate_reparent_from<S: ConnectionNodeSource + ?Sized>(
    source: &S,
    node_id: Uuid,
    new_parent_id: Option<Uuid>,
    options: ReparentOptions,
) -> Result<ValidatedReparent, ReparentError> {
    let nodes = source.list_all()?;
    validate_reparent(&nodes, node_id, new_parent_id, options)
}

/// C# `ShouldRejectDragSelection` — reject when search is active, or when the
/// drag set contains both an ancestor and one of its descendants.
///
/// Single-id (or empty) selections are allowed when search is off.
pub fn should_reject_drag_selection(
    nodes: &[ConnectionNode],
    dragged_ids: &[Uuid],
    options: ReparentOptions,
) -> bool {
    if options.search_active {
        return true;
    }

    let dragged: HashSet<Uuid> = dragged_ids.iter().copied().collect();
    if dragged.len() < 2 {
        return false;
    }

    let by_id: HashMap<Uuid, &ConnectionNode> = nodes.iter().map(|n| (n.id, n)).collect();
    for &id in &dragged {
        let mut seen = HashSet::new();
        let mut current = by_id.get(&id).and_then(|n| n.parent_id);
        while let Some(pid) = current {
            if !seen.insert(pid) {
                break; // hostile ParentId cycle
            }
            if dragged.contains(&pid) {
                return true;
            }
            current = by_id.get(&pid).and_then(|n| n.parent_id);
        }
    }
    false
}

/// Same as [`should_reject_drag_selection`], loading via a [`ConnectionNodeSource`].
pub fn should_reject_drag_selection_from<S: ConnectionNodeSource + ?Sized>(
    source: &S,
    dragged_ids: &[Uuid],
    options: ReparentOptions,
) -> Result<bool, ReparentError> {
    let nodes = source.list_all()?;
    Ok(should_reject_drag_selection(&nodes, dragged_ids, options))
}

/// Apply a validated reparent on the Fake [`MemoryConnectionSource`].
///
/// Updates `ParentId` and appends under the new parent (`SortOrder` = max sibling + 1).
/// Idempotent when the live snapshot already has the target parent.
/// Works for folder **and** connection.
///
/// Re-validates search / existence / folder target / cycle against the **current**
/// Fake snapshot (C# `PersistTreeStructureAsync` also re-checks `IsSearchActive`).
/// Stale [`ValidatedReparent`] values therefore fail closed instead of writing a
/// cycle or succeeding after the node was deleted.
///
/// Returns the **fresh** [`ValidatedReparent`] from the live snapshot (correct
/// `old_parent_id` for change-notifier hosts even if the input handle was stale).
pub fn apply_reparent_memory(
    source: &mut MemoryConnectionSource,
    validated: &ValidatedReparent,
    options: ReparentOptions,
) -> Result<ValidatedReparent, ReparentError> {
    // Re-check against live nodes — do not trust a stale ValidatedReparent alone.
    let fresh = validate_reparent(
        source.nodes(),
        validated.node_id,
        validated.new_parent_id,
        options,
    )?;
    if fresh.is_noop() {
        return Ok(fresh);
    }

    let mut nodes = source.nodes().to_vec();
    let idx = nodes
        .iter()
        .position(|n| n.id == fresh.node_id)
        .ok_or(ReparentError::NotFound(fresh.node_id))?;

    let next_sort = next_sort_order(&nodes, fresh.new_parent_id);
    nodes[idx].parent_id = fresh.new_parent_id;
    nodes[idx].sort_order = next_sort;
    source.set_nodes(nodes);
    Ok(fresh)
}

/// Validate then apply on Fake [`MemoryConnectionSource`] (folder or connection).
pub fn reparent_memory(
    source: &mut MemoryConnectionSource,
    node_id: Uuid,
    new_parent_id: Option<Uuid>,
    options: ReparentOptions,
) -> Result<ValidatedReparent, ReparentError> {
    // Use the live slice (no extra `list_all` clone); `apply_reparent_memory` re-checks.
    let validated = validate_reparent(source.nodes(), node_id, new_parent_id, options)?;
    apply_reparent_memory(source, &validated, options)
}

/// Validate then persist a **connection** reparent via storage.
///
/// Folder moves fail with [`ReparentError::FolderPersistUnsupported`] after a successful
/// validate (hosts may still use [`reparent_memory`] / later `UpdateMany`). Search /
/// cycle / kind checks run in glue **before** the repository call.
#[cfg(feature = "storage")]
pub fn reparent_connection_storage(
    repo: &wormhole_storage::ConnectionRepository<'_>,
    nodes: &[ConnectionNode],
    connection_id: Uuid,
    new_parent_folder_id: Option<Uuid>,
    options: ReparentOptions,
) -> Result<wormhole_storage::StoredConnectionNode, ReparentError> {
    let validated = validate_reparent(nodes, connection_id, new_parent_folder_id, options)?;
    if validated.kind != NodeKind::Connection {
        return Err(ReparentError::FolderPersistUnsupported);
    }
    if validated.is_noop() {
        // Mirror storage stub idempotent path: return current row without rewrite.
        return repo
            .get_by_id(connection_id)
            .map_err(|e| ReparentError::Storage(e.to_string()))?
            .ok_or(ReparentError::NotFound(connection_id));
    }
    // Prefer validated parent (same as the arg after a successful validate).
    repo.reparent_connection(connection_id, validated.new_parent_id)
        .map_err(|e| match e {
            wormhole_storage::StorageError::NotFound(id) => ReparentError::NotFound(id),
            other => ReparentError::Storage(other.to_string()),
        })
}

/// `true` when `ancestor_id` appears on the parent chain of `node_id` (exclusive).
fn is_ancestor_of(
    by_id: &HashMap<Uuid, &ConnectionNode>,
    ancestor_id: Uuid,
    node_id: Uuid,
) -> bool {
    let mut seen = HashSet::new();
    let mut current = by_id.get(&node_id).and_then(|n| n.parent_id);
    while let Some(pid) = current {
        if !seen.insert(pid) {
            break; // hostile cycle in ParentId chain
        }
        if pid == ancestor_id {
            return true;
        }
        current = by_id.get(&pid).and_then(|n| n.parent_id);
    }
    false
}

/// Next sibling `SortOrder` under `parent_id` (max + 1, or 0 when empty; saturates).
pub(crate) fn next_sort_order(nodes: &[ConnectionNode], parent_id: Option<Uuid>) -> i32 {
    let mut max: Option<i32> = None;
    for n in nodes {
        if n.parent_id == parent_id {
            max = Some(max.map_or(n.sort_order, |m| m.max(n.sort_order)));
        }
    }
    max.map_or(0, |m| m.saturating_add(1))
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
            ..Default::default()
        }
    }

    fn sample_tree() -> (Uuid, Uuid, Uuid, Uuid, Vec<ConnectionNode>) {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let c = Uuid::new_v4();
        let leaf = Uuid::new_v4();
        // A
        // └─ B
        //    └─ C
        //       └─ leaf (connection)
        let nodes = vec![
            folder(a, None, "A", 0),
            folder(b, Some(a), "B", 0),
            folder(c, Some(b), "C", 0),
            conn(leaf, Some(c), "leaf", 0),
        ];
        (a, b, c, leaf, nodes)
    }

    #[test]
    fn search_active_rejects_validate_and_drag() {
        let (a, _b, _c, leaf, nodes) = sample_tree();
        let opts = ReparentOptions::new(true);
        assert_eq!(
            validate_reparent(&nodes, leaf, Some(a), opts).unwrap_err(),
            ReparentError::SearchActive
        );
        assert!(should_reject_drag_selection(&nodes, &[leaf], opts));
    }

    #[test]
    fn allows_connection_move_to_folder_and_root() {
        let (a, _b, _c, leaf, nodes) = sample_tree();
        let opts = ReparentOptions::default();
        let v = validate_reparent(&nodes, leaf, Some(a), opts).unwrap();
        assert_eq!(v.kind, NodeKind::Connection);
        assert_eq!(v.new_parent_id, Some(a));
        assert!(!v.is_noop());

        let to_root = validate_reparent(&nodes, leaf, None, opts).unwrap();
        assert!(to_root.new_parent_id.is_none());
    }

    #[test]
    fn allows_folder_move_to_sibling_branch() {
        let (a, b, c, _leaf, nodes) = sample_tree();
        let opts = ReparentOptions::default();
        // Move C under A (sibling of B) — not a descendant cycle.
        let v = validate_reparent(&nodes, c, Some(a), opts).unwrap();
        assert_eq!(v.kind, NodeKind::Folder);
        assert_eq!(v.old_parent_id, Some(b));
        assert_eq!(v.new_parent_id, Some(a));
    }

    #[test]
    fn rejects_folder_into_descendant_cycle() {
        let (a, _b, c, _leaf, nodes) = sample_tree();
        let opts = ReparentOptions::default();
        // Move A under C (C is descendant of A).
        assert_eq!(
            validate_reparent(&nodes, a, Some(c), opts).unwrap_err(),
            ReparentError::WouldCreateCycle
        );
        assert_eq!(
            validate_reparent(&nodes, a, Some(a), opts).unwrap_err(),
            ReparentError::WouldCreateCycle
        );
    }

    #[test]
    fn rejects_connection_as_parent() {
        let (_a, _b, _c, leaf, nodes) = sample_tree();
        let other = Uuid::new_v4();
        let mut nodes = nodes;
        nodes.push(conn(other, None, "other", 1));
        let opts = ReparentOptions::default();
        assert_eq!(
            validate_reparent(&nodes, other, Some(leaf), opts).unwrap_err(),
            ReparentError::TargetNotFolder(leaf)
        );
    }

    #[test]
    fn rejects_missing_ids() {
        let (_a, _b, _c, leaf, nodes) = sample_tree();
        let missing = Uuid::new_v4();
        let opts = ReparentOptions::default();
        assert_eq!(
            validate_reparent(&nodes, missing, None, opts).unwrap_err(),
            ReparentError::NotFound(missing)
        );
        assert_eq!(
            validate_reparent(&nodes, leaf, Some(missing), opts).unwrap_err(),
            ReparentError::NotFound(missing)
        );
    }

    #[test]
    fn idempotent_same_parent_is_noop() {
        let (_a, _b, c, leaf, nodes) = sample_tree();
        let opts = ReparentOptions::default();
        let v = validate_reparent(&nodes, leaf, Some(c), opts).unwrap();
        assert!(v.is_noop());
    }

    #[test]
    fn drag_rejects_ancestor_and_descendant_together() {
        let (a, b, _c, leaf, nodes) = sample_tree();
        let opts = ReparentOptions::default();
        assert!(!should_reject_drag_selection(&nodes, &[leaf], opts));
        assert!(!should_reject_drag_selection(
            &nodes,
            &[a, Uuid::new_v4()],
            opts
        )); // unknown id ignored in chain walk
        assert!(should_reject_drag_selection(&nodes, &[a, b], opts));
        assert!(should_reject_drag_selection(&nodes, &[a, leaf], opts));
        // b is ancestor of leaf → reject
        assert!(should_reject_drag_selection(&nodes, &[b, leaf], opts));
        // two unrelated roots — allow
        let other = Uuid::new_v4();
        let mut nodes = nodes;
        nodes.push(folder(other, None, "Other", 1));
        assert!(!should_reject_drag_selection(&nodes, &[a, other], opts));
    }

    #[test]
    fn memory_reparent_moves_connection_and_folder() {
        let (a, b, c, leaf, nodes) = sample_tree();
        let mut source = MemoryConnectionSource::new(nodes);
        let opts = ReparentOptions::default();

        let v = reparent_memory(&mut source, leaf, Some(a), opts).unwrap();
        assert_eq!(v.new_parent_id, Some(a));
        let moved = source.nodes().iter().find(|n| n.id == leaf).unwrap();
        assert_eq!(moved.parent_id, Some(a));
        // Append under A — sibling B has sort 0 → leaf gets 1
        assert_eq!(moved.sort_order, 1);

        // Folder move: C under A
        let v2 = reparent_memory(&mut source, c, Some(a), opts).unwrap();
        assert_eq!(v2.kind, NodeKind::Folder);
        let folder_c = source.nodes().iter().find(|n| n.id == c).unwrap();
        assert_eq!(folder_c.parent_id, Some(a));
        assert_eq!(folder_c.sort_order, 2); // after B(0) and leaf(1)

        // Search blocks memory apply
        assert_eq!(
            reparent_memory(&mut source, b, None, ReparentOptions::new(true)).unwrap_err(),
            ReparentError::SearchActive
        );
    }

    #[test]
    fn validate_from_fake_source() {
        let (a, _b, _c, leaf, nodes) = sample_tree();
        let source = MemoryConnectionSource::new(nodes);
        let v = validate_reparent_from(&source, leaf, Some(a), ReparentOptions::default()).unwrap();
        assert_eq!(v.node_id, leaf);
        assert!(!should_reject_drag_selection_from(
            &source,
            &[leaf],
            ReparentOptions::default()
        )
        .unwrap());
    }

    #[test]
    fn source_load_failure_propagates() {
        struct FailingConnectionSource;
        impl ConnectionNodeSource for FailingConnectionSource {
            fn list_all(&self) -> Result<Vec<ConnectionNode>, TreeError> {
                Err(TreeError::Load("injected source failure".into()))
            }
        }
        let id = Uuid::new_v4();
        let err = validate_reparent_from(
            &FailingConnectionSource,
            id,
            None,
            ReparentOptions::default(),
        )
        .unwrap_err();
        assert_eq!(
            err,
            ReparentError::Source(TreeError::Load("injected source failure".into()))
        );
        let drag_err = should_reject_drag_selection_from(
            &FailingConnectionSource,
            &[id],
            ReparentOptions::default(),
        )
        .unwrap_err();
        assert_eq!(
            drag_err,
            ReparentError::Source(TreeError::Load("injected source failure".into()))
        );
    }

    #[test]
    fn apply_rejects_stale_validated_that_would_cycle() {
        let (a, _b, c, _leaf, mut nodes) = sample_tree();
        let d = Uuid::new_v4();
        nodes.push(folder(d, None, "D", 1));
        let mut source = MemoryConnectionSource::new(nodes);
        let opts = ReparentOptions::default();
        // Valid at capture time: move A (and its subtree) under sibling root D.
        let stale = validate_reparent_from(&source, a, Some(d), opts).unwrap();
        // Drift: hang D under C (a descendant of A) — applying the stale move cycles.
        reparent_memory(&mut source, d, Some(c), opts).unwrap();
        assert_eq!(
            apply_reparent_memory(&mut source, &stale, opts).unwrap_err(),
            ReparentError::WouldCreateCycle
        );
    }

    #[test]
    fn apply_noop_still_requires_node() {
        let (_a, _b, c, leaf, nodes) = sample_tree();
        let mut source = MemoryConnectionSource::new(nodes);
        let stale = ValidatedReparent {
            node_id: leaf,
            kind: NodeKind::Connection,
            old_parent_id: Some(c),
            new_parent_id: Some(c),
        };
        assert!(stale.is_noop());
        // Delete the node from the Fake snapshot.
        let kept: Vec<_> = source
            .nodes()
            .iter()
            .filter(|n| n.id != leaf)
            .cloned()
            .collect();
        source.set_nodes(kept);
        assert_eq!(
            apply_reparent_memory(&mut source, &stale, ReparentOptions::default()).unwrap_err(),
            ReparentError::NotFound(leaf)
        );
    }

    #[test]
    fn apply_rejects_when_search_becomes_active() {
        let (a, _b, _c, leaf, nodes) = sample_tree();
        let mut source = MemoryConnectionSource::new(nodes);
        let stale =
            validate_reparent_from(&source, leaf, Some(a), ReparentOptions::default()).unwrap();
        assert_eq!(
            apply_reparent_memory(&mut source, &stale, ReparentOptions::new(true)).unwrap_err(),
            ReparentError::SearchActive
        );
        // Snapshot unchanged.
        assert_eq!(
            source.nodes().iter().find(|n| n.id == leaf).unwrap().parent_id,
            stale.old_parent_id
        );
    }

    #[test]
    fn memory_noop_preserves_sort_order() {
        let (_a, _b, c, leaf, nodes) = sample_tree();
        let mut source = MemoryConnectionSource::new(nodes);
        let before = source
            .nodes()
            .iter()
            .find(|n| n.id == leaf)
            .unwrap()
            .sort_order;
        let v = reparent_memory(&mut source, leaf, Some(c), ReparentOptions::default()).unwrap();
        assert!(v.is_noop());
        let after = source
            .nodes()
            .iter()
            .find(|n| n.id == leaf)
            .unwrap()
            .sort_order;
        assert_eq!(before, after);
    }

    #[test]
    fn rejects_mid_chain_folder_into_descendant() {
        let (_a, b, c, _leaf, nodes) = sample_tree();
        // B → C is a direct child; moving B under C must cycle.
        assert_eq!(
            validate_reparent(&nodes, b, Some(c), ReparentOptions::default()).unwrap_err(),
            ReparentError::WouldCreateCycle
        );
    }

    #[test]
    fn next_sort_saturates_at_i32_max() {
        let parent = Uuid::new_v4();
        let moving = Uuid::new_v4();
        let nodes = vec![
            folder(parent, None, "P", 0),
            folder(Uuid::new_v4(), Some(parent), "full", i32::MAX),
            conn(moving, None, "m", 0),
        ];
        let mut source = MemoryConnectionSource::new(nodes);
        let v = reparent_memory(
            &mut source,
            moving,
            Some(parent),
            ReparentOptions::default(),
        )
        .unwrap();
        assert!(!v.is_noop());
        let moved = source.nodes().iter().find(|n| n.id == moving).unwrap();
        assert_eq!(moved.sort_order, i32::MAX); // saturating_add
    }

    #[test]
    fn empty_drag_selection_allowed_when_search_off() {
        let (_a, _b, _c, _leaf, nodes) = sample_tree();
        assert!(!should_reject_drag_selection(
            &nodes,
            &[],
            ReparentOptions::default()
        ));
        assert!(should_reject_drag_selection(
            &nodes,
            &[],
            ReparentOptions::new(true)
        ));
    }

    #[cfg(feature = "storage")]
    mod storage_glue {
        use super::*;
        use wormhole_storage::{ConnectionRepository, MigrationRunner, SqliteConnectionFactory};

        #[test]
        fn storage_reparent_after_validate() {
            let dir = tempfile::tempdir().unwrap();
            let factory = SqliteConnectionFactory::new(dir.path().join("wormhole.db"));
            MigrationRunner::embedded().run(&factory).unwrap();
            let repo = ConnectionRepository::new(&factory);

            let folder_a = repo.create_folder("A", None).unwrap();
            let folder_b = repo.create_folder("B", None).unwrap();
            let conn_id = Uuid::new_v4();
            repo.insert(&ConnectionNode {
                id: conn_id,
                parent_id: Some(folder_a.node.id),
                name: "prod".into(),
                kind: NodeKind::Connection,
                sort_order: 0,
                protocol: Some(ProtocolType::Ssh),
                host: Some("h".into()),
                ..Default::default()
            })
            .unwrap();

            let nodes: Vec<_> = repo
                .list_all()
                .unwrap()
                .into_iter()
                .map(|s| s.node)
                .collect();

            let stored = reparent_connection_storage(
                &repo,
                &nodes,
                conn_id,
                Some(folder_b.node.id),
                ReparentOptions::default(),
            )
            .unwrap();
            assert_eq!(stored.node.parent_id, Some(folder_b.node.id));

            // Folder persist unsupported
            let err = reparent_connection_storage(
                &repo,
                &nodes,
                folder_a.node.id,
                Some(folder_b.node.id),
                ReparentOptions::default(),
            )
            .unwrap_err();
            assert_eq!(err, ReparentError::FolderPersistUnsupported);

            // Search blocks before storage
            assert_eq!(
                reparent_connection_storage(
                    &repo,
                    &nodes,
                    conn_id,
                    Some(folder_a.node.id),
                    ReparentOptions::new(true),
                )
                .unwrap_err(),
                ReparentError::SearchActive
            );
        }

        #[test]
        fn storage_noop_returns_current_row() {
            let dir = tempfile::tempdir().unwrap();
            let factory = SqliteConnectionFactory::new(dir.path().join("wormhole.db"));
            MigrationRunner::embedded().run(&factory).unwrap();
            let repo = ConnectionRepository::new(&factory);

            let folder_a = repo.create_folder("A", None).unwrap();
            let conn_id = Uuid::new_v4();
            repo.insert(&ConnectionNode {
                id: conn_id,
                parent_id: Some(folder_a.node.id),
                name: "prod".into(),
                kind: NodeKind::Connection,
                sort_order: 7,
                protocol: Some(ProtocolType::Ssh),
                host: Some("h".into()),
                ..Default::default()
            })
            .unwrap();

            let nodes: Vec<_> = repo
                .list_all()
                .unwrap()
                .into_iter()
                .map(|s| s.node)
                .collect();

            let stored = reparent_connection_storage(
                &repo,
                &nodes,
                conn_id,
                Some(folder_a.node.id),
                ReparentOptions::default(),
            )
            .unwrap();
            assert_eq!(stored.node.parent_id, Some(folder_a.node.id));
            assert_eq!(stored.node.sort_order, 7);
        }
    }
}
