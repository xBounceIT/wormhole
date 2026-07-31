use thiserror::Error;
use uuid::Uuid;

use crate::enums::NodeKind;

/// Errors from [`crate::InheritanceResolver::resolve`], matching C# `InvalidOperationException` cases.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ResolveError {
    #[error(
        "InheritanceResolver can only resolve a connection node, but '{name}' is a {kind}."
    )]
    NotAConnection { name: String, kind: NodeKind },

    #[error("Detected a cycle in the node tree at '{name}' ({id}).")]
    Cycle { name: String, id: Uuid },

    #[error("Connection '{name}' has no protocol set on itself or any ancestor folder.")]
    MissingProtocol { name: String },

    #[error("Connection '{name}' has no host set on itself or any ancestor folder.")]
    MissingHost { name: String },
}

/// Rejected SQLite / wire discriminant that does not map to a domain enum variant.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("invalid {enum_name} discriminant: {value}")]
pub struct InvalidEnumValue {
    pub enum_name: &'static str,
    pub value: i32,
}
