//! Connection-tree view-model (load / search / expand) — GPUI-independent.
//!
//! Open / double-click → session glue lives in [`open`] behind `--features session`
//! (default). Thin filter query → visible ids lives in [`filter`].

mod error;
mod filter;
mod model;
mod node;
mod source;

#[cfg(feature = "session")]
mod open;

pub use error::TreeError;
pub use filter::{
    fields_match_query_lower, node_matches_query, visible_connection_ids,
    visible_connection_ids_from,
};
pub use model::{ConnectionTreeModel, FlattenedRow, MAX_DISPLAYED_SEARCH_MATCHES};
pub use node::TreeNode;
pub use source::{ConnectionNodeSource, MemoryConnectionSource};

#[cfg(feature = "storage")]
pub use source::StorageConnectionSource;

#[cfg(feature = "session")]
pub use open::{
    connect, connect_from_selection, connect_from_tree, connect_prepared,
    fake_orchestrator_for_tests, fake_orchestrator_with_credentials, options_with_password,
    prepare_connect_request, prepare_tree_connect, prepare_tree_connect_from_selection,
    ConnectRequest, TreeConnectRequest, TreeOpenError,
};
