//! Session orchestrator for Wormhole protocol connects.
//!
//! Takes a resolved [`wormhole_domain::ConnectionProfile`] (or a sufficiently
//! populated [`wormhole_domain::ConnectionNode`]), optionally establishes a
//! [`wormhole_tunnels::TunnelLease`], then dispatches:
//!
//! - Serial → [`wormhole_serial`]
//! - SSH → [`wormhole_ssh`] password path (+ known_hosts verify-on-connect + host-key prompt gate stub
//!   + Fake reconnect loop glue over [`wormhole_ssh::reconnect`])
//! - Per-connect tunnel route prompt Fake glue ([`tunnel_route_prompt`])
//! - HTTP/HTTPS → [`wormhole_http`] target types (WebView2 hosting stays elsewhere)
//!
//! RDP / VNC prepare typed [`RdpConnectRequest`] / [`VncConnectRequest`] stubs, then
//! fail closed with [`SessionError::UnsupportedProtocol`] (structured reason) **before**
//! any tunnel establish — no OLE / VNC engine. See `docs/migration/16-session-orchestrator.md`.

mod connection_progress;
mod connectors;
mod error;
mod fake_port;
mod host_key;
mod id;
mod orchestrator;
mod profile;
mod rdp_vnc;
mod ssh_reconnect;
mod state;
mod tunnel_route_prompt;

pub use connection_progress::{
    describe_tunnel_phase, ConnectProgressPlan, ConnectionProgress, ConnectionProgressPhase,
    ConnectionStep, ConnectionStepState, FakeConnectOutcome, FakeConnectionProgressGlue,
    FakePhaseOutcome, TunnelProgressReport, TunnelSubPhase,
};
pub use connectors::{
    CredentialResolver, EmptyCredentialResolver, FakeCredentialResolver, FakeSerialConnector,
    FakeSshConnector, FakeTunnelBroker, LiveSerialConnector, LiveSshConnector, ManagerTunnelBroker,
    SerialConnector, SshConnector, TunnelBroker,
};
pub use error::{Result, SessionError};
pub use host_key::{
    gate_ssh_host_key, gate_ssh_host_key_fake, verify_ssh_host_key, verify_ssh_host_key_fake,
};
pub use id::SessionId;
pub use orchestrator::{
    ConnectOptions, SessionHandle, SessionOrchestrator, TunnelConnectArgs,
};
pub use profile::profile_from_node;
pub use rdp_vnc::{
    RdpConnectRequest, SessionKind, StubRdpConnector, StubVncConnector, UnsupportedProtocolReason,
    VncConnectRequest,
};
pub use ssh_reconnect::{
    apply_fake_reconnect_result, FakeSshReconnectGlue, FakeSshReconnectResult,
};
pub use tunnel_route_prompt::{
    apply_tunnel_route_choice, resolve_tunnel_route, FakeTunnelRoutePromptUi,
    MemoryTunnelConfigNames, TunnelConfigNameLookup, TunnelRouteChoice, TunnelRoutePrompt,
    TunnelRoutePromptRequest, FALLBACK_TUNNEL_NAME,
};
pub use state::{ConnectedSession, SessionState, SshConnected};

/// Re-export for callers that cancel connects.
pub use tokio_util::sync::CancellationToken;
