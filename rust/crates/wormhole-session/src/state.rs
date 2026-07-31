//! Session state machine + connected session payloads.

use wormhole_http::HttpConnectionTarget;
use wormhole_serial::SerialSession;

/// Lifecycle states for a session handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionState {
    Connecting,
    Connected,
    Failed,
    Closed,
}

/// Successful protocol payload after connect.
pub enum ConnectedSession {
    Serial(SerialSession),
    Ssh(SshConnected),
    Http(HttpConnectionTarget),
}

impl std::fmt::Debug for ConnectedSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Serial(_) => f.write_str("ConnectedSession::Serial(..)"),
            Self::Ssh(s) => f.debug_tuple("ConnectedSession::Ssh").field(s).finish(),
            Self::Http(t) => f.debug_tuple("ConnectedSession::Http").field(t).finish(),
        }
    }
}

/// SSH password-path result — live russh handles or a test double.
pub enum SshConnected {
    /// Real russh session (only when the `ssh-client` feature is on and a live connector is used).
    #[cfg(feature = "ssh-client")]
    Live {
        session: wormhole_ssh::SshClientSession,
        shell: wormhole_ssh::ShellChannelStub,
    },
    /// Unit-test / stub connect — no network.
    Fake {
        host: String,
        port: u16,
        via_socks: bool,
    },
}

impl std::fmt::Debug for SshConnected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(feature = "ssh-client")]
            Self::Live { .. } => f.write_str("SshConnected::Live { .. }"),
            Self::Fake {
                host,
                port,
                via_socks,
            } => f
                .debug_struct("SshConnected::Fake")
                .field("host", host)
                .field("port", port)
                .field("via_socks", via_socks)
                .finish(),
        }
    }
}
