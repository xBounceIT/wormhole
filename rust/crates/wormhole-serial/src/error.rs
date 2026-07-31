use thiserror::Error;

/// Serial open / I/O errors.
#[derive(Debug, Error)]
pub enum SerialError {
    #[error("serial session is closing or disposed")]
    Closing,
    #[error("serial port error: {0}")]
    Port(#[from] tokio_serial::Error),
    #[error("serial I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid serial settings: {0}")]
    InvalidSettings(String),
    #[error("{0}")]
    Other(String),
}
