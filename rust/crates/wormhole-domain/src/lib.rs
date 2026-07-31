//! Pure Wormhole domain types and folder-level inheritance.
//!
//! Ported from the C# models under `Models/` and `Data/InheritanceResolver.cs`.
//! See `docs/migration/02-domain.md` for the C# → Rust field/enum map.

mod connection_node;
mod connection_node_change;
mod connection_profile;
mod enums;
mod error;
mod inheritance;
mod rdp_screen_sizes;
mod serial;

pub use connection_node::ConnectionNode;
pub use connection_node_change::{
    ConnectionNodeChangeCallback, ConnectionNodeChangeEvent, ConnectionNodeChangeKind,
    ConnectionNodeChangeNotifier, ConnectionNodeChangePublisher, ConnectionNodeChangeSubscription,
    FakeConnectionNodeChangeNotifier, NopConnectionNodeChangeNotifier, RecordingRefreshListener,
    SharedConnectionNodeChangeNotifier,
};
pub use connection_profile::ConnectionProfile;
pub use enums::{
    CredentialBindingMode, CredentialBindingSentinelIds, CredentialKind, CredentialSecretProvider,
    NodeKind, ProtocolType, SerialFlowControlMode, SerialParityMode, SerialStopBitsMode,
    TunnelKind, BITWARDEN_PASSWORD_FIELD_PATH,
};
pub use error::{InvalidEnumValue, ResolveError};
pub use inheritance::InheritanceResolver;
pub use rdp_screen_sizes::RdpScreenSizes;
pub use serial::SerialDefaults;

/// Format a GUID in .NET format `"D"`: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` (lowercase).
pub fn format_guid_d(id: &uuid::Uuid) -> String {
    id.hyphenated().to_string()
}
