//! Thin connection-tree filter glue: query → visible [`ConnectionNode`] ids.
//!
//! Pure Rust; no GPUI. Works on a flat snapshot (e.g. from [`MemoryConnectionSource`]).
//! Distinct from [`ConnectionTreeModel`](super::ConnectionTreeModel) expand/projection —
//! this returns the **id set** hosts can use to decide which rows stay visible.
//!
//! Matching: case-insensitive substring on **name** or **host** (C# tree search is
//! name-only today; host is an intentional Rust glue extension for Quick Connect / tooltip
//! parity). Empty / whitespace query → every node id. Non-empty query keeps **ancestor
//! folders** of matches so nested hits remain reachable; a folder-name hit does **not**
//! force its unmatched subtree into the set.
//!
//! Missing parents are not emitted as phantom ids (orphan matches still appear via DFS
//! promotion). No display cap — hosts that need projection/expand use
//! [`ConnectionTreeModel`](super::ConnectionTreeModel).

use std::collections::{HashMap, HashSet};

use uuid::Uuid;
use wormhole_domain::ConnectionNode;

use super::source::ConnectionNodeSource;
use super::TreeError;

/// Ids that should remain visible under `query`.
///
/// - Empty / whitespace → all node ids (stable DFS: roots by `SortOrder`/`Name`, then children).
/// - Otherwise → name **or** host substring match (case-insensitive), plus ancestor folders
///   that exist in the snapshot.
pub fn visible_connection_ids(nodes: &[ConnectionNode], query: &str) -> Vec<Uuid> {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return ordered_all_ids(nodes);
    }
    let query_lower = trimmed.to_lowercase();
    let by_id: HashMap<Uuid, &ConnectionNode> = nodes.iter().map(|n| (n.id, n)).collect();
    let mut direct: Vec<Uuid> = Vec::new();
    for n in nodes {
        let host_lower = n.host.as_deref().map(str::to_lowercase);
        if fields_match_query_lower(&n.name.to_lowercase(), host_lower.as_deref(), &query_lower) {
            direct.push(n.id);
        }
    }

    let mut visible: HashSet<Uuid> = direct.iter().copied().collect();
    for id in &direct {
        let mut current = by_id.get(id).and_then(|n| n.parent_id);
        while let Some(pid) = current {
            let Some(parent) = by_id.get(&pid) else {
                // Missing parent → orphan match; do not insert a phantom id.
                break;
            };
            if !visible.insert(pid) {
                break;
            }
            current = parent.parent_id;
        }
    }

    ordered_visible_ids(nodes, &visible)
}

/// Same as [`visible_connection_ids`], loading via a [`ConnectionNodeSource`].
pub fn visible_connection_ids_from<S: ConnectionNodeSource + ?Sized>(
    source: &S,
    query: &str,
) -> Result<Vec<Uuid>, TreeError> {
    let nodes = source.list_all()?;
    Ok(visible_connection_ids(&nodes, query))
}

/// Case-insensitive substring on already-lowercased name / host / query.
///
/// Shared by [`visible_connection_ids`] / [`node_matches_query`] and
/// [`ConnectionTreeModel`](super::ConnectionTreeModel) search indexing.
pub fn fields_match_query_lower(
    name_lower: &str,
    host_lower: Option<&str>,
    query_lower: &str,
) -> bool {
    if query_lower.is_empty() {
        return false;
    }
    if name_lower.contains(query_lower) {
        return true;
    }
    host_lower.is_some_and(|h| h.contains(query_lower))
}

/// Case-insensitive substring on name or host.
///
/// `query` may be any casing and may include leading/trailing whitespace (trimmed);
/// it is lowercased internally. Callers may still pre-lowercase for hot loops —
/// double-lowercase is harmless.
pub fn node_matches_query(node: &ConnectionNode, query: &str) -> bool {
    let query_lower = query.trim().to_lowercase();
    fields_match_query_lower(
        &node.name.to_lowercase(),
        node.host.as_deref().map(str::to_lowercase).as_deref(),
        &query_lower,
    )
}

fn ordered_all_ids(nodes: &[ConnectionNode]) -> Vec<Uuid> {
    let all: HashSet<Uuid> = nodes.iter().map(|n| n.id).collect();
    ordered_visible_ids(nodes, &all)
}

fn cmp_node_ids(by_id: &HashMap<Uuid, &ConnectionNode>, a: &Uuid, b: &Uuid) -> std::cmp::Ordering {
    let na = by_id[a];
    let nb = by_id[b];
    na.sort_order
        .cmp(&nb.sort_order)
        .then_with(|| na.name.cmp(&nb.name))
        .then_with(|| a.cmp(b))
}

fn ordered_visible_ids(nodes: &[ConnectionNode], visible: &HashSet<Uuid>) -> Vec<Uuid> {
    let by_id: HashMap<Uuid, &ConnectionNode> = nodes.iter().map(|n| (n.id, n)).collect();
    let mut by_parent: HashMap<Option<Uuid>, Vec<Uuid>> = HashMap::new();
    for n in nodes {
        by_parent.entry(n.parent_id).or_default().push(n.id);
    }
    for children in by_parent.values_mut() {
        children.sort_by(|a, b| cmp_node_ids(&by_id, a, b));
    }

    let mut roots = by_parent.remove(&None).unwrap_or_default();
    // Orphans (missing parent) promoted like the tree model.
    let mut orphans = Vec::new();
    for (parent, kids) in &by_parent {
        let Some(pid) = parent else { continue };
        if !by_id.contains_key(pid) {
            orphans.extend(kids.iter().copied());
        }
    }
    orphans.sort_by(|a, b| cmp_node_ids(&by_id, a, b));
    roots.extend(orphans);

    let mut out = Vec::with_capacity(visible.len());
    let mut stack: Vec<Uuid> = roots.into_iter().rev().collect();
    let mut seen = HashSet::new();
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        if visible.contains(&id) {
            out.push(id);
        }
        // Walk children even when parent is not visible so orphaned visible
        // descendants under a filtered-out folder still appear (should not happen
        // when ancestors are always included; kept for robustness).
        if let Some(children) = by_parent.get(&Some(id)) {
            for child in children.iter().rev() {
                stack.push(*child);
            }
        }
    }

    // Parent cycles (or other graphs with no root/orphan entry) leave visible
    // nodes unreached by DFS — append them in stable SortOrder/Name/id order.
    let mut leftover: Vec<Uuid> = visible
        .iter()
        .copied()
        .filter(|id| by_id.contains_key(id) && !seen.contains(id))
        .collect();
    leftover.sort_by(|a, b| cmp_node_ids(&by_id, a, b));
    out.extend(leftover);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::source::MemoryConnectionSource;
    use std::collections::HashSet;
    use wormhole_domain::{NodeKind, ProtocolType};

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

    fn conn(
        id: Uuid,
        parent: Option<Uuid>,
        name: &str,
        host: &str,
        sort: i32,
    ) -> ConnectionNode {
        ConnectionNode {
            id,
            parent_id: parent,
            name: name.to_string(),
            kind: NodeKind::Connection,
            sort_order: sort,
            protocol: Some(ProtocolType::Ssh),
            host: Some(host.into()),
            ..Default::default()
        }
    }

    #[test]
    fn empty_query_returns_all_ids_dfs_order() {
        let servers = Uuid::new_v4();
        let other = Uuid::new_v4();
        let prod = Uuid::new_v4();
        let nodes = vec![
            folder(servers, None, "Servers", 0),
            folder(other, None, "Other", 1),
            conn(prod, Some(servers), "prod-web", "10.0.0.1", 0),
        ];
        assert_eq!(
            visible_connection_ids(&nodes, ""),
            vec![servers, prod, other]
        );
        assert_eq!(
            visible_connection_ids(&nodes, "   "),
            vec![servers, prod, other]
        );
    }

    #[test]
    fn name_match_keeps_ancestor_folder() {
        let servers = Uuid::new_v4();
        let other = Uuid::new_v4();
        let prod = Uuid::new_v4();
        let leaf = Uuid::new_v4();
        let nodes = vec![
            folder(servers, None, "Servers", 0),
            folder(other, None, "Other", 1),
            conn(prod, Some(servers), "prod-web", "10.0.0.1", 0),
            conn(leaf, Some(other), "leaf", "192.168.1.1", 0),
        ];
        let ids = visible_connection_ids(&nodes, "prod");
        assert_eq!(ids, vec![servers, prod]);
        assert!(!ids.contains(&other));
        assert!(!ids.contains(&leaf));
    }

    #[test]
    fn host_match_keeps_ancestor_folder() {
        let parent = Uuid::new_v4();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let nodes = vec![
            folder(parent, None, "Lab", 0),
            conn(a, Some(parent), "alpha", "db.internal", 0),
            conn(b, Some(parent), "beta", "web.example", 1),
        ];
        let ids = visible_connection_ids(&nodes, "db.int");
        assert_eq!(ids, vec![parent, a]);
        assert!(!ids.contains(&b));
    }

    #[test]
    fn host_match_case_insensitive() {
        let id = Uuid::new_v4();
        let nodes = vec![conn(id, None, "box", "Prod.Example.COM", 0)];
        assert_eq!(visible_connection_ids(&nodes, "PROD.example"), vec![id]);
    }

    #[test]
    fn folder_name_match_does_not_force_subtree() {
        let folder_id = Uuid::new_v4();
        let alpha = Uuid::new_v4();
        let beta = Uuid::new_v4();
        let nodes = vec![
            folder(folder_id, None, "Linux", 0),
            conn(alpha, Some(folder_id), "alpha", "a.local", 0),
            conn(beta, Some(folder_id), "beta", "b.local", 1),
        ];
        let ids = visible_connection_ids(&nodes, "Lin");
        assert_eq!(ids, vec![folder_id]);
        assert!(!ids.contains(&alpha));
        assert!(!ids.contains(&beta));
    }

    #[test]
    fn no_matches_returns_empty() {
        let id = Uuid::new_v4();
        let nodes = vec![conn(id, None, "box", "10.0.0.1", 0)];
        assert!(visible_connection_ids(&nodes, "zzz-nope").is_empty());
    }

    #[test]
    fn from_memory_source() {
        let id = Uuid::new_v4();
        let source = MemoryConnectionSource::new(vec![conn(id, None, "box", "10.0.0.9", 0)]);
        let ids = visible_connection_ids_from(&source, "0.0.9").unwrap();
        assert_eq!(ids, vec![id]);
    }

    #[test]
    fn nested_match_includes_full_ancestor_chain() {
        let root = Uuid::new_v4();
        let mid = Uuid::new_v4();
        let leaf = Uuid::new_v4();
        let nodes = vec![
            folder(root, None, "Root", 0),
            folder(mid, Some(root), "Mid", 0),
            conn(leaf, Some(mid), "leaf", "needle.host", 0),
        ];
        assert_eq!(
            visible_connection_ids(&nodes, "needle"),
            vec![root, mid, leaf]
        );
    }

    #[test]
    fn orphan_match_does_not_emit_phantom_parent() {
        let missing = Uuid::new_v4();
        let leaf = Uuid::new_v4();
        let nodes = vec![conn(leaf, Some(missing), "orphan-box", "10.0.0.5", 0)];
        let ids = visible_connection_ids(&nodes, "orphan");
        assert_eq!(ids, vec![leaf]);
        assert!(!ids.contains(&missing));
    }

    #[test]
    fn none_host_matches_name_only() {
        let id = Uuid::new_v4();
        let nodes = vec![ConnectionNode {
            id,
            parent_id: None,
            name: "serial-line".into(),
            kind: NodeKind::Connection,
            sort_order: 0,
            protocol: Some(ProtocolType::Serial),
            host: None,
            ..Default::default()
        }];
        assert_eq!(visible_connection_ids(&nodes, "serial"), vec![id]);
        assert!(visible_connection_ids(&nodes, "COM1").is_empty());
    }

    #[test]
    fn empty_snapshot_returns_empty() {
        assert!(visible_connection_ids(&[], "").is_empty());
        assert!(visible_connection_ids(&[], "x").is_empty());
    }

    #[test]
    fn node_matches_query_lowercases_caller_query() {
        let id = Uuid::new_v4();
        let node = conn(id, None, "Prod-Web", "Host.Example", 0);
        // Public API must not require a pre-lowercased query.
        assert!(node_matches_query(&node, "PROD"));
        assert!(node_matches_query(&node, "host.example"));
        assert!(!node_matches_query(&node, ""));
        assert!(!node_matches_query(&node, "   "));
    }

    #[test]
    fn from_failing_source_propagates_load_error() {
        struct FailingConnectionSource;
        impl ConnectionNodeSource for FailingConnectionSource {
            fn list_all(&self) -> Result<Vec<ConnectionNode>, TreeError> {
                Err(TreeError::Load("injected source failure".into()))
            }
        }
        let err = visible_connection_ids_from(&FailingConnectionSource, "x").unwrap_err();
        assert_eq!(err, TreeError::Load("injected source failure".into()));
    }

    #[test]
    fn filter_ids_match_model_projection_set() {
        let root = Uuid::new_v4();
        let mid = Uuid::new_v4();
        let other = Uuid::new_v4();
        let prod = Uuid::new_v4();
        let leaf = Uuid::new_v4();
        let nodes = vec![
            folder(root, None, "Root", 0),
            folder(mid, Some(root), "Mid", 0),
            folder(other, None, "Other", 1),
            conn(prod, Some(mid), "prod-web", "10.0.0.1", 0),
            conn(leaf, Some(other), "leaf", "192.168.1.1", 0),
        ];
        let filter_ids: HashSet<_> = visible_connection_ids(&nodes, "prod").into_iter().collect();

        let mut model = crate::tree::ConnectionTreeModel::new();
        model.load_nodes(nodes);
        model.set_search_text("prod");
        let mut model_ids = HashSet::new();
        let mut stack: Vec<Uuid> = model.display_roots().to_vec();
        while let Some(id) = stack.pop() {
            if model_ids.insert(id) {
                stack.extend(model.display_children(id).iter().copied());
            }
        }
        assert_eq!(filter_ids, model_ids);
        assert_eq!(filter_ids, HashSet::from([root, mid, prod]));
    }

    #[test]
    fn query_trims_leading_trailing_whitespace() {
        let id = Uuid::new_v4();
        let nodes = vec![conn(id, None, "prod-web", "10.0.0.1", 0)];
        assert_eq!(visible_connection_ids(&nodes, "  prod  "), vec![id]);
        assert!(node_matches_query(&nodes[0], "  PROD  "));
    }

    #[test]
    fn parent_cycle_terminates_and_emits_visible() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let leaf = Uuid::new_v4();
        // A ↔ B cycle; leaf under A — no None-parent root.
        let nodes = vec![
            folder(a, Some(b), "A", 0),
            folder(b, Some(a), "B", 0),
            conn(leaf, Some(a), "cycle-leaf", "1.2.3.4", 0),
        ];
        let ids = visible_connection_ids(&nodes, "cycle-leaf");
        assert!(ids.contains(&leaf));
        assert!(ids.contains(&a));
        assert!(ids.contains(&b));
        assert_eq!(ids.len(), 3);
    }
}
