//! Connection tree view-model: load, search/filter projection, folder expand.

use std::collections::{HashMap, HashSet};

use uuid::Uuid;
use wormhole_domain::{ConnectionNode, NodeKind};

use super::error::TreeError;
use super::node::TreeNode;
use super::source::ConnectionNodeSource;

/// Cap on displayed search hits (mirrors C# `MaxDisplayedSearchMatches`).
pub const MAX_DISPLAYED_SEARCH_MATCHES: usize = 500;

/// GPUI-independent connection tree model.
///
/// Loads a flat node list via [`ConnectionNodeSource`], builds parent/child links,
/// supports case-insensitive name/host search with path projection, and tracks folder
/// expand state (including restore-after-search).
#[derive(Debug, Clone)]
pub struct ConnectionTreeModel {
    nodes: HashMap<Uuid, TreeNode>,
    roots: Vec<Uuid>,
    search_text: String,
    search_active: bool,
    search_status_text: String,
    search_display_roots: Vec<Uuid>,
    /// When search is active, projected children per included folder.
    filtered_children: HashMap<Uuid, Vec<Uuid>>,
    /// Prior expand state captured when a folder first enters a search projection.
    search_expansion_overrides: Option<HashMap<Uuid, bool>>,
}

impl Default for ConnectionTreeModel {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionTreeModel {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            roots: Vec::new(),
            search_text: String::new(),
            search_active: false,
            search_status_text: String::new(),
            search_display_roots: Vec::new(),
            filtered_children: HashMap::new(),
            search_expansion_overrides: None,
        }
    }

    /// Replace the tree from a node source (preserves expand state for surviving ids).
    pub fn load_from<S: ConnectionNodeSource + ?Sized>(
        &mut self,
        source: &S,
    ) -> Result<(), TreeError> {
        let flat = source.list_all()?;
        self.rebuild_from_flat(flat);
        self.reapply_current_filter();
        Ok(())
    }

    /// Load from an already-fetched flat list (tests / storage callers).
    pub fn load_nodes(&mut self, flat: Vec<ConnectionNode>) {
        self.rebuild_from_flat(flat);
        self.reapply_current_filter();
    }

    pub fn search_text(&self) -> &str {
        &self.search_text
    }

    pub fn is_search_active(&self) -> bool {
        self.search_active
    }

    pub fn search_status_text(&self) -> &str {
        &self.search_status_text
    }

    /// Root ids for the current projection (full tree or search).
    pub fn display_roots(&self) -> &[Uuid] {
        if self.search_active {
            &self.search_display_roots
        } else {
            &self.roots
        }
    }

    /// Unfiltered root ids.
    pub fn roots(&self) -> &[Uuid] {
        &self.roots
    }

    pub fn node(&self, id: Uuid) -> Option<&TreeNode> {
        self.nodes.get(&id)
    }

    pub fn node_mut(&mut self, id: Uuid) -> Option<&mut TreeNode> {
        self.nodes.get_mut(&id)
    }

    /// Children shown for `id` under the current projection.
    pub fn display_children(&self, id: Uuid) -> &[Uuid] {
        if self.search_active {
            self.filtered_children
                .get(&id)
                .map(Vec::as_slice)
                .unwrap_or(&[])
        } else {
            self.nodes
                .get(&id)
                .map(|n| n.children.as_slice())
                .unwrap_or(&[])
        }
    }

    pub fn set_expanded(&mut self, id: Uuid, expanded: bool) -> bool {
        let Some(node) = self.nodes.get_mut(&id) else {
            return false;
        };
        if !node.is_folder() {
            return false;
        }
        node.is_expanded = expanded;
        true
    }

    pub fn expand_all(&mut self) {
        for node in self.nodes.values_mut() {
            if node.is_folder() {
                node.is_expanded = true;
            }
        }
    }

    pub fn collapse_all(&mut self) {
        for node in self.nodes.values_mut() {
            if node.is_folder() {
                node.is_expanded = false;
            }
        }
    }

    /// Update search text and reproject immediately (no debounce — host may debounce).
    pub fn set_search_text(&mut self, text: impl Into<String>) {
        let new_value = text.into();
        let was_filtering = !self.search_text.trim().is_empty();
        let is_filtering = !new_value.trim().is_empty();

        if !was_filtering && is_filtering {
            self.search_expansion_overrides = Some(HashMap::new());
        }

        self.search_text = new_value;
        self.apply_filter_and_maybe_restore(was_filtering, is_filtering);
    }

    /// Depth-first visible rows respecting expand state (full tree) or search projection.
    pub fn flatten_visible(&self) -> Vec<FlattenedRow> {
        let mut out = Vec::new();
        let mut stack: Vec<(Uuid, usize)> = self
            .display_roots()
            .iter()
            .rev()
            .map(|id| (*id, 0))
            .collect();

        let mut seen = HashSet::new();
        while let Some((id, depth)) = stack.pop() {
            if !seen.insert(id) {
                continue;
            }
            let Some(node) = self.nodes.get(&id) else {
                continue;
            };
            out.push(FlattenedRow {
                id,
                depth,
                name: node.name.clone(),
                kind: node.kind,
                is_expanded: node.is_expanded,
            });
            if node.is_folder() && node.is_expanded {
                let children = self.display_children(id);
                for child in children.iter().rev() {
                    stack.push((*child, depth + 1));
                }
            }
        }
        out
    }

    fn apply_filter_and_maybe_restore(&mut self, was_filtering: bool, is_filtering: bool) {
        self.reapply_current_filter();

        if was_filtering && !is_filtering {
            if let Some(overrides) = self.search_expansion_overrides.take() {
                for (id, was_expanded) in overrides {
                    if let Some(node) = self.nodes.get_mut(&id) {
                        if node.is_folder() {
                            node.is_expanded = was_expanded;
                        }
                    }
                }
            }
        }
    }

    fn reapply_current_filter(&mut self) {
        let trimmed = self.search_text.trim();
        if trimmed.is_empty() {
            self.apply_full_projection();
            return;
        }
        let query = trimmed.to_owned();
        let projection = self.build_search_projection(&query);
        self.apply_search_projection(projection);
    }

    fn apply_full_projection(&mut self) {
        self.filtered_children.clear();
        self.search_display_roots.clear();
        self.search_status_text.clear();
        self.search_active = false;
    }

    fn apply_search_projection(&mut self, projection: SearchProjection) {
        let overrides = self
            .search_expansion_overrides
            .get_or_insert_with(HashMap::new);

        for id in &projection.included {
            let Some(node) = self.nodes.get(id) else {
                continue;
            };
            if node.is_folder() {
                overrides.entry(*id).or_insert(node.is_expanded);
            }
        }

        self.filtered_children = projection.children_by_parent;
        self.search_display_roots = projection.roots;
        self.search_status_text =
            build_search_status_text(projection.displayed_matches, projection.total_matches);
        self.search_active = true;

        for id in projection.ancestors_to_expand {
            if let Some(node) = self.nodes.get_mut(&id) {
                if node.is_folder() {
                    node.is_expanded = true;
                }
            }
        }
    }

    fn build_search_projection(&self, query: &str) -> SearchProjection {
        let index = self.build_search_index();
        let mut projection = SearchProjection::default();
        // Lowercase once (OrdinalIgnoreCase-style); still count past the display cap
        // so status text can report "Showing first N of M" without projecting M rows.
        let query_lower = query.to_lowercase();

        for (i, entry) in index.iter().enumerate() {
            if !entry_matches_query_lower(entry, &query_lower) {
                continue;
            }
            projection.total_matches += 1;
            if projection.displayed_matches >= MAX_DISPLAYED_SEARCH_MATCHES {
                continue;
            }
            projection.displayed_matches += 1;
            include_search_path(&mut projection, &index, i);
        }

        projection
    }

    fn build_search_index(&self) -> Vec<SearchIndexEntry> {
        let mut entries = Vec::with_capacity(self.nodes.len());
        let mut stack: Vec<(Uuid, i32)> = self
            .roots
            .iter()
            .rev()
            .map(|id| (*id, -1))
            .collect();
        let mut seen = HashSet::new();

        while let Some((id, parent_index)) = stack.pop() {
            if !seen.insert(id) {
                continue;
            }
            let Some(node) = self.nodes.get(&id) else {
                continue;
            };
            let entry_index = entries.len() as i32;
            entries.push(SearchIndexEntry {
                id,
                name_lower: node.name.to_lowercase(),
                host_lower: node.host.as_deref().map(str::to_lowercase),
                kind: node.kind,
                parent_index,
            });
            for child in node.children.iter().rev() {
                stack.push((*child, entry_index));
            }
        }

        entries
    }

    fn rebuild_from_flat(&mut self, flat: Vec<ConnectionNode>) {
        let prior_expanded: HashMap<Uuid, bool> = self
            .nodes
            .iter()
            .filter(|(_, n)| n.is_folder())
            .map(|(id, n)| (*id, n.is_expanded))
            .collect();

        let mut by_parent: HashMap<Option<Uuid>, Vec<ConnectionNode>> = HashMap::new();
        for node in flat {
            by_parent.entry(node.parent_id).or_default().push(node);
        }

        for children in by_parent.values_mut() {
            children.sort_by(|a, b| {
                a.sort_order
                    .cmp(&b.sort_order)
                    .then_with(|| a.name.cmp(&b.name))
            });
        }

        let mut nodes = HashMap::new();
        for list in by_parent.values() {
            for n in list {
                let expanded = prior_expanded.get(&n.id).copied().unwrap_or(false);
                nodes.insert(
                    n.id,
                    TreeNode {
                        id: n.id,
                        parent_id: n.parent_id,
                        name: n.name.clone(),
                        kind: n.kind,
                        protocol: n.protocol,
                        host: n.host.clone(),
                        sort_order: n.sort_order,
                        children: Vec::new(),
                        is_expanded: expanded && n.kind == NodeKind::Folder,
                    },
                );
            }
        }

        let mut roots: Vec<Uuid> = by_parent
            .get(&None)
            .map(|top| top.iter().map(|n| n.id).collect())
            .unwrap_or_default();

        // Missing parents → promote orphans to roots with stable SortOrder, Name order
        // (HashMap iteration order is otherwise nondeterministic).
        let mut orphan_ids: Vec<Uuid> = Vec::new();
        for (parent_key, list) in &by_parent {
            let Some(pid) = parent_key else {
                continue;
            };
            if let Some(parent) = nodes.get_mut(pid) {
                parent.children = list.iter().map(|n| n.id).collect();
            } else {
                orphan_ids.extend(list.iter().map(|n| n.id));
            }
        }
        orphan_ids.sort_by(|a, b| {
            let na = &nodes[a];
            let nb = &nodes[b];
            na.sort_order
                .cmp(&nb.sort_order)
                .then_with(|| na.name.cmp(&nb.name))
                .then_with(|| a.cmp(b))
        });
        roots.extend(orphan_ids);

        self.nodes = nodes;
        self.roots = roots;
        // Keep search_expansion_overrides across reload so an active filter can still restore.
    }
}

/// One visible row after expand/search flattening.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlattenedRow {
    pub id: Uuid,
    pub depth: usize,
    pub name: String,
    pub kind: NodeKind,
    pub is_expanded: bool,
}

#[derive(Default)]
struct SearchProjection {
    roots: Vec<Uuid>,
    children_by_parent: HashMap<Uuid, Vec<Uuid>>,
    included: HashSet<Uuid>,
    ancestors_to_expand: Vec<Uuid>,
    ancestor_ids: HashSet<Uuid>,
    total_matches: usize,
    displayed_matches: usize,
}

struct SearchIndexEntry {
    id: Uuid,
    name_lower: String,
    host_lower: Option<String>,
    kind: NodeKind,
    parent_index: i32,
}

fn include_search_path(projection: &mut SearchProjection, index: &[SearchIndexEntry], match_index: usize) {
    let mut path = Vec::new();
    let mut current = match_index as i32;
    while current >= 0 {
        path.push(current as usize);
        current = index[current as usize].parent_index;
    }

    for path_index in (0..path.len()).rev() {
        let entry = &index[path[path_index]];
        let is_root = path_index + 1 == path.len();
        if projection.included.insert(entry.id) {
            if is_root {
                projection.roots.push(entry.id);
            } else {
                let parent = index[path[path_index + 1]].id;
                projection
                    .children_by_parent
                    .entry(parent)
                    .or_default()
                    .push(entry.id);
            }
        }

        // Ancestors on the path (not the match leaf itself unless it's a folder with deeper path).
        if path_index > 0 && entry.kind == NodeKind::Folder && projection.ancestor_ids.insert(entry.id)
        {
            projection.ancestors_to_expand.push(entry.id);
        }
    }
}

fn build_search_status_text(displayed_matches: usize, total_matches: usize) -> String {
    if total_matches == 0 {
        "No matches".to_string()
    } else if displayed_matches < total_matches {
        format!("Showing first {displayed_matches} of {total_matches} matches")
    } else {
        String::new()
    }
}

/// Case-insensitive substring on name or host (pre-lowercased query / haystacks).
fn entry_matches_query_lower(entry: &SearchIndexEntry, query_lower: &str) -> bool {
    super::filter::fields_match_query_lower(
        &entry.name_lower,
        entry.host_lower.as_deref(),
        query_lower,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::source::MemoryConnectionSource;
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
            host: Some("host".into()),
            ..Default::default()
        }
    }

    #[test]
    fn load_builds_roots_and_children() {
        let servers = Uuid::new_v4();
        let other = Uuid::new_v4();
        let prod = Uuid::new_v4();
        let source = MemoryConnectionSource::new(vec![
            folder(servers, None, "Servers", 0),
            folder(other, None, "Other", 1),
            conn(prod, Some(servers), "prod-web", 0),
        ]);

        let mut model = ConnectionTreeModel::new();
        model.load_from(&source).unwrap();

        assert_eq!(model.roots(), &[servers, other]);
        assert_eq!(model.display_children(servers), &[prod]);
        assert!(model.display_children(other).is_empty());
        assert!(!model.is_search_active());
    }

    #[test]
    fn search_matches_connection_only_that_branch() {
        let servers = Uuid::new_v4();
        let other = Uuid::new_v4();
        let prod = Uuid::new_v4();
        let leaf = Uuid::new_v4();
        let mut model = ConnectionTreeModel::new();
        model.load_nodes(vec![
            folder(servers, None, "Servers", 0),
            folder(other, None, "Other", 1),
            conn(prod, Some(servers), "prod-web", 0),
            conn(leaf, Some(other), "leaf", 0),
        ]);

        model.set_search_text("prod");

        assert!(model.is_search_active());
        assert_eq!(model.display_roots(), &[servers]);
        assert_eq!(model.display_children(servers), &[prod]);
        assert!(!model.display_roots().contains(&other));
    }

    #[test]
    fn search_nested_match_auto_expands_ancestor() {
        let parent = Uuid::new_v4();
        let prod = Uuid::new_v4();
        let mut model = ConnectionTreeModel::new();
        model.load_nodes(vec![
            folder(parent, None, "Parent", 0),
            conn(prod, Some(parent), "prod-web", 0),
        ]);
        assert!(!model.node(parent).unwrap().is_expanded);

        model.set_search_text("prod");
        assert!(model.node(parent).unwrap().is_expanded);
        assert_eq!(model.display_roots(), &[parent]);
        assert_eq!(model.display_children(parent), &[prod]);
    }

    #[test]
    fn search_folder_name_shows_folder_without_subtree() {
        let folder_id = Uuid::new_v4();
        let alpha = Uuid::new_v4();
        let beta = Uuid::new_v4();
        let mut model = ConnectionTreeModel::new();
        model.load_nodes(vec![
            folder(folder_id, None, "Linux", 0),
            conn(alpha, Some(folder_id), "alpha", 0),
            conn(beta, Some(folder_id), "beta", 1),
        ]);

        model.set_search_text("Lin");
        assert_eq!(model.display_roots(), &[folder_id]);
        assert!(model.display_children(folder_id).is_empty());
        assert!(!model.node(folder_id).unwrap().is_expanded);
        assert_eq!(model.node(folder_id).unwrap().children.len(), 2);
    }

    #[test]
    fn clearing_search_restores_prior_expanded_state() {
        let parent = Uuid::new_v4();
        let leaf = Uuid::new_v4();
        let mut model = ConnectionTreeModel::new();
        model.load_nodes(vec![
            folder(parent, None, "Parent", 0),
            conn(leaf, Some(parent), "leaf", 0),
        ]);
        assert!(!model.node(parent).unwrap().is_expanded);

        model.set_search_text("leaf");
        assert!(model.node(parent).unwrap().is_expanded);

        model.set_search_text("");
        assert!(!model.is_search_active());
        assert!(!model.node(parent).unwrap().is_expanded);
        assert_eq!(model.display_roots(), model.roots());
    }

    #[test]
    fn search_case_insensitive() {
        let linux = Uuid::new_v4();
        let mut model = ConnectionTreeModel::new();
        model.load_nodes(vec![folder(linux, None, "Linux", 0)]);
        model.set_search_text("LINUX");
        assert_eq!(model.display_roots(), &[linux]);
    }

    #[test]
    fn search_no_matches_reports_status() {
        let parent = Uuid::new_v4();
        let leaf = Uuid::new_v4();
        let mut model = ConnectionTreeModel::new();
        model.load_nodes(vec![
            folder(parent, None, "Parent", 0),
            conn(leaf, Some(parent), "leaf", 0),
        ]);
        model.set_search_text("zzz-no-match-zzz");
        assert!(model.is_search_active());
        assert!(model.display_roots().is_empty());
        assert_eq!(model.search_status_text(), "No matches");
    }

    #[test]
    fn whitespace_only_search_is_empty() {
        let parent = Uuid::new_v4();
        let mut model = ConnectionTreeModel::new();
        model.load_nodes(vec![folder(parent, None, "Parent", 0)]);
        model.set_search_text("   ");
        assert!(!model.is_search_active());
        assert_eq!(model.display_roots(), &[parent]);
    }

    #[test]
    fn expand_collapse_all() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let mut model = ConnectionTreeModel::new();
        model.load_nodes(vec![
            folder(a, None, "A", 0),
            folder(b, Some(a), "B", 0),
        ]);
        model.expand_all();
        assert!(model.node(a).unwrap().is_expanded);
        assert!(model.node(b).unwrap().is_expanded);
        model.collapse_all();
        assert!(!model.node(a).unwrap().is_expanded);
        assert!(!model.node(b).unwrap().is_expanded);
    }

    #[test]
    fn flatten_respects_expand_state() {
        let parent = Uuid::new_v4();
        let child = Uuid::new_v4();
        let mut model = ConnectionTreeModel::new();
        model.load_nodes(vec![
            folder(parent, None, "Parent", 0),
            conn(child, Some(parent), "child", 0),
        ]);

        let collapsed = model.flatten_visible();
        assert_eq!(collapsed.len(), 1);
        assert_eq!(collapsed[0].id, parent);

        model.set_expanded(parent, true);
        let expanded = model.flatten_visible();
        assert_eq!(expanded.len(), 2);
        assert_eq!(expanded[1].id, child);
        assert_eq!(expanded[1].depth, 1);
    }

    #[test]
    fn search_match_cap_reports_truncation() {
        let mut nodes = Vec::new();
        let root = Uuid::new_v4();
        nodes.push(folder(root, None, "Root", 0));
        for i in 0..(MAX_DISPLAYED_SEARCH_MATCHES + 10) {
            nodes.push(conn(
                Uuid::new_v4(),
                Some(root),
                &format!("match-{i:04}"),
                i as i32,
            ));
        }
        let mut model = ConnectionTreeModel::new();
        model.load_nodes(nodes);
        model.set_search_text("match-");
        assert!(model.search_status_text().contains("Showing first"));
        assert!(model.search_status_text().contains(&MAX_DISPLAYED_SEARCH_MATCHES.to_string()));
        // Root + capped matches under projection children.
        assert_eq!(
            model.display_children(root).len(),
            MAX_DISPLAYED_SEARCH_MATCHES
        );
    }

    #[test]
    fn user_collapse_during_search_reexpands_on_next_query() {
        let folder_id = Uuid::new_v4();
        let needle = Uuid::new_v4();
        let mut model = ConnectionTreeModel::new();
        model.load_nodes(vec![
            folder(folder_id, None, "Folder", 0),
            conn(needle, Some(folder_id), "needle", 0),
        ]);

        model.set_search_text("needle");
        assert!(model.node(folder_id).unwrap().is_expanded);
        model.set_expanded(folder_id, false);
        assert!(!model.node(folder_id).unwrap().is_expanded);

        model.set_search_text("needl");
        assert!(model.node(folder_id).unwrap().is_expanded);

        model.set_search_text("");
        assert!(!model.node(folder_id).unwrap().is_expanded);
    }

    #[test]
    fn load_preserves_expand_for_surviving_ids() {
        let parent = Uuid::new_v4();
        let leaf = Uuid::new_v4();
        let mut model = ConnectionTreeModel::new();
        model.load_nodes(vec![
            folder(parent, None, "Parent", 0),
            conn(leaf, Some(parent), "leaf", 0),
        ]);
        model.set_expanded(parent, true);

        model.load_nodes(vec![
            folder(parent, None, "Parent", 0),
            conn(leaf, Some(parent), "leaf", 0),
        ]);
        assert!(model.node(parent).unwrap().is_expanded);
    }

    #[test]
    fn search_matches_host_substring() {
        let parent = Uuid::new_v4();
        let hit = Uuid::new_v4();
        let miss = Uuid::new_v4();
        let mut model = ConnectionTreeModel::new();
        model.load_nodes(vec![
            folder(parent, None, "Lab", 0),
            ConnectionNode {
                id: hit,
                parent_id: Some(parent),
                name: "alpha".into(),
                kind: NodeKind::Connection,
                sort_order: 0,
                protocol: Some(ProtocolType::Ssh),
                host: Some("db.internal".into()),
                ..Default::default()
            },
            ConnectionNode {
                id: miss,
                parent_id: Some(parent),
                name: "beta".into(),
                kind: NodeKind::Connection,
                sort_order: 1,
                protocol: Some(ProtocolType::Ssh),
                host: Some("web.example".into()),
                ..Default::default()
            },
        ]);

        model.set_search_text("db.int");
        assert!(model.is_search_active());
        assert_eq!(model.display_roots(), &[parent]);
        assert_eq!(model.display_children(parent), &[hit]);
    }

    #[test]
    fn search_substring_case_insensitive_mixed() {
        let id = Uuid::new_v4();
        let mut model = ConnectionTreeModel::new();
        model.load_nodes(vec![conn(id, None, "Prod-Web-01", 0)]);
        model.set_search_text("od-we");
        assert_eq!(model.display_roots(), &[id]);
        model.set_search_text("OD-WE");
        assert_eq!(model.display_roots(), &[id]);
    }

    #[test]
    fn orphan_nodes_with_missing_parent_sort_stably_as_roots() {
        let missing = Uuid::new_v4();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let real_root = Uuid::new_v4();
        let mut model = ConnectionTreeModel::new();
        model.load_nodes(vec![
            folder(real_root, None, "Root", 0),
            conn(b, Some(missing), "bravo", 1),
            conn(a, Some(missing), "alpha", 0),
        ]);
        assert_eq!(model.roots(), &[real_root, a, b]);
    }

    #[test]
    fn clearing_search_restores_user_expanded_folder_not_in_last_projection() {
        let keep = Uuid::new_v4();
        let other = Uuid::new_v4();
        let needle = Uuid::new_v4();
        let mut model = ConnectionTreeModel::new();
        model.load_nodes(vec![
            folder(keep, None, "Keep", 0),
            folder(other, None, "Other", 1),
            conn(needle, Some(other), "needle", 0),
        ]);
        model.set_expanded(keep, true);
        model.set_search_text("needle");
        assert!(model.node(other).unwrap().is_expanded);
        assert!(model.node(keep).unwrap().is_expanded);
        model.set_search_text("");
        assert!(model.node(keep).unwrap().is_expanded);
        assert!(!model.node(other).unwrap().is_expanded);
    }

    #[test]
    fn search_cap_does_not_project_past_limit() {
        let mut nodes = Vec::new();
        let root = Uuid::new_v4();
        nodes.push(folder(root, None, "Root", 0));
        for i in 0..(MAX_DISPLAYED_SEARCH_MATCHES + 25) {
            nodes.push(conn(
                Uuid::new_v4(),
                Some(root),
                &format!("hit-{i:04}"),
                i as i32,
            ));
        }
        let mut model = ConnectionTreeModel::new();
        model.load_nodes(nodes);
        model.set_search_text("hit-");
        assert!(model.search_status_text().contains("Showing first"));
        assert_eq!(
            model.display_children(root).len(),
            MAX_DISPLAYED_SEARCH_MATCHES
        );
        model.set_expanded(root, true);
        let flat = model.flatten_visible();
        assert!(flat.len() <= MAX_DISPLAYED_SEARCH_MATCHES + 1);
    }
}
