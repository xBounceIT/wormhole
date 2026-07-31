use thiserror::Error;

/// Errors from terminal session I/O or bridge message framing.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TerminalError {
    #[error("terminal session is closing or disposed")]
    Closing,
    #[error("invalid terminal bridge message: {0}")]
    InvalidMessage(String),
    #[error("empty terminal payload")]
    EmptyPayload,
    #[error("terminal bridge message exceeds size limit ({kind}: {actual} > {limit})")]
    MessageTooLarge {
        kind: &'static str,
        actual: usize,
        limit: usize,
    },
    #[error("channel closed")]
    ChannelClosed,
    #[error("{0}")]
    Other(String),
}
