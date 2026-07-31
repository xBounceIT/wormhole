use thiserror::Error;

/// VNC / RFB spike errors.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum VncError {
    #[error("unsupported RFB security type {0}")]
    UnsupportedSecurityType(u8),

    #[error("VNC password required for classic VncAuth")]
    PasswordRequired,

    #[error("VNC password longer than {0} bytes (classic DES truncates at 8)")]
    PasswordTooLong(usize),

    #[error("authentication cancelled")]
    AuthCancelled,

    /// Server requested username+password auth (C# `CredentialsAuthenticationInput`).
    /// Wormhole v1 is password-only; username/domain are ignored / hidden in the editor.
    #[error(
        "VNC server requested username/password authentication, which Wormhole v1 does not support"
    )]
    UnsupportedCredentialsAuth,

    #[error("session is not connected")]
    NotConnected,

    #[error("input event queue full (capacity {capacity})")]
    InputQueueFull { capacity: usize },

    #[error("invalid framebuffer update (bounds or raw pixel length)")]
    InvalidFramebufferUpdate,

    /// Empty ClientCutText / ServerCutText rejected (fail-closed; no send / no buffer write).
    #[error("clipboard text is empty")]
    ClipboardEmpty,

    /// Cut-text exceeds soft UTF-8 byte cap (parity with terminal paste 1 MiB).
    /// Display / Debug carry sizes only — never the body.
    #[error("clipboard text exceeds limit ({actual} > {limit})")]
    ClipboardTooLarge { actual: usize, limit: usize },

    #[error("engine feature not enabled")]
    EngineNotEnabled,

    /// Empty / whitespace / NUL host rejected before dial or forwarder bind.
    #[error("VNC host is required")]
    InvalidHost,

    /// Remote RFB port must be non-zero.
    #[error("invalid VNC port {0}")]
    InvalidPort(u16),

    /// Loopback forwarder listen port must be non-zero.
    #[error("invalid local forwarder port {0}")]
    InvalidForwarderPort(u16),

    /// Tunnel `BindLocalForwarder` failed (no live socket in the stub path).
    #[error("VNC local forwarder bind failed: {0}")]
    ForwarderBindFailed(String),

    #[error("{0}")]
    Message(String),
}
