use thiserror::Error;

/// UI shell errors (state machine only — no rendering failures yet).
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum UiError {
    #[error("workspace already has the maximum of {0} panes")]
    PaneLimitReached(usize),

    #[error("pane {0} is not in the workspace")]
    UnknownPane(u8),

    #[error("pane {0} is already present in the layout")]
    DuplicatePane(u8),

    #[error("cannot remove the last pane")]
    LastPane,

    #[error("split ratio must be a finite number")]
    InvalidSplitRatio,

    #[error("pane {0} has no parent split to adjust")]
    NoSplitForPane(u8),

    #[error("tab {0} is not in the strip")]
    UnknownTab(uuid::Uuid),

    #[error("session {0} is not in the tab bar")]
    UnknownSession(uuid::Uuid),

    #[error("session {0} is already open in the tab bar")]
    DuplicateSession(uuid::Uuid),

    #[error("invalid sidebar region")]
    InvalidSidebarRegion,
}
