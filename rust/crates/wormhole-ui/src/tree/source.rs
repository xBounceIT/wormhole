//! Read path for connection-tree nodes.
//!
//! Concrete writers land with the storage-writes agent; this trait is enough for
//! load / search / expand view-model work.

use wormhole_domain::ConnectionNode;

use crate::tree::TreeError;

/// Loads a flat node list (same shape as `ConnectionRepository::list_all`).
pub trait ConnectionNodeSource {
    fn list_all(&self) -> Result<Vec<ConnectionNode>, TreeError>;
}

/// In-memory source for unit tests and headless demos.
#[derive(Debug, Clone, Default)]
pub struct MemoryConnectionSource {
    nodes: Vec<ConnectionNode>,
}

impl MemoryConnectionSource {
    pub fn new(nodes: Vec<ConnectionNode>) -> Self {
        Self { nodes }
    }

    pub fn nodes(&self) -> &[ConnectionNode] {
        &self.nodes
    }

    pub fn set_nodes(&mut self, nodes: Vec<ConnectionNode>) {
        self.nodes = nodes;
    }
}

impl ConnectionNodeSource for MemoryConnectionSource {
    fn list_all(&self) -> Result<Vec<ConnectionNode>, TreeError> {
        Ok(self.nodes.clone())
    }
}

impl ConnectionNodeSource for &MemoryConnectionSource {
    fn list_all(&self) -> Result<Vec<ConnectionNode>, TreeError> {
        (*self).list_all()
    }
}

/// Adapts [`wormhole_storage::ConnectionRepository`] read API.
#[cfg(feature = "storage")]
pub struct StorageConnectionSource {
    factory: wormhole_storage::SqliteConnectionFactory,
}

#[cfg(feature = "storage")]
impl StorageConnectionSource {
    pub fn new(factory: wormhole_storage::SqliteConnectionFactory) -> Self {
        Self { factory }
    }

    pub fn factory(&self) -> &wormhole_storage::SqliteConnectionFactory {
        &self.factory
    }
}

#[cfg(feature = "storage")]
impl ConnectionNodeSource for StorageConnectionSource {
    fn list_all(&self) -> Result<Vec<ConnectionNode>, TreeError> {
        let repo = wormhole_storage::ConnectionRepository::new(&self.factory);
        let rows = repo.list_all().map_err(|e| TreeError::Load(e.to_string()))?;
        Ok(rows.into_iter().map(|row| row.node).collect())
    }
}

#[cfg(all(test, feature = "storage"))]
mod storage_tests {
    use super::*;
    use uuid::Uuid;
    use wormhole_domain::{NodeKind, ProtocolType};
    use wormhole_storage::{ConnectionRepository, MigrationRunner, SqliteConnectionFactory};

    #[test]
    fn storage_source_lists_inserted_nodes() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("wormhole.db");
        let factory = SqliteConnectionFactory::new(&db);
        MigrationRunner::embedded().run(&factory).unwrap();

        let folder_id = Uuid::new_v4();
        let conn_id = Uuid::new_v4();
        let repo = ConnectionRepository::new(&factory);
        repo.insert(&ConnectionNode {
            id: folder_id,
            parent_id: None,
            name: "Servers".into(),
            kind: NodeKind::Folder,
            sort_order: 0,
            ..Default::default()
        })
        .unwrap();
        repo.insert(&ConnectionNode {
            id: conn_id,
            parent_id: Some(folder_id),
            name: "prod".into(),
            kind: NodeKind::Connection,
            sort_order: 0,
            protocol: Some(ProtocolType::Ssh),
            host: Some("h".into()),
            ..Default::default()
        })
        .unwrap();

        let source = StorageConnectionSource::new(factory);
        let mut model = super::super::ConnectionTreeModel::new();
        model.load_from(&source).unwrap();
        assert_eq!(model.roots(), &[folder_id]);
        assert_eq!(model.display_children(folder_id), &[conn_id]);
    }
}
