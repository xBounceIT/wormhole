use thiserror::Error;

/// Connection-tree load / projection errors.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TreeError {
    #[error("failed to load connection nodes: {0}")]
    Load(String),
}
