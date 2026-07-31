//! Connection-tree row state (GPUI-independent).

use uuid::Uuid;
use wormhole_domain::{NodeKind, ProtocolType};

/// One folder or connection in the tree model.
#[derive(Debug, Clone)]
pub struct TreeNode {
    pub id: Uuid,
    pub parent_id: Option<Uuid>,
    pub name: String,
    pub kind: NodeKind,
    pub protocol: Option<ProtocolType>,
    /// Connection host (None for folders); used by search/filter glue.
    pub host: Option<String>,
    pub sort_order: i32,
    /// Full (unfiltered) child ids, ordered like storage `SortOrder, Name`.
    pub children: Vec<Uuid>,
    pub is_expanded: bool,
}

impl TreeNode {
    pub fn is_folder(&self) -> bool {
        self.kind == NodeKind::Folder
    }

    pub fn is_connection(&self) -> bool {
        self.kind == NodeKind::Connection
    }
}
