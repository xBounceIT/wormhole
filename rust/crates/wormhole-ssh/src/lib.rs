//! SSH protocol spike for Wormhole (russh).
//!
//! See `docs/migration/06-ssh-spike.md` for russh vs alternatives and SOCKS5
//! hook-point design. Password / private-key connect + interactive shell live
//! behind the `client` feature (on by default). Host-key known_hosts store,
//! verify-on-connect decision + accept/reject prompt glue, auto-sudo prompt
//! detector + session glue stub (Fake terminal), SSH reconnect / backoff policy
//! stub (Fake schedule), SSH agent **availability** probe, and agent ↔ auth
//! method select glue are always on. Agent and keyboard-interactive **wire**
//! auth are stubs (`AuthNotImplemented`).

mod agent;
mod agent_auth_select;
mod auto_sudo;
mod auto_sudo_glue;
mod error;
mod host_key_prompt;
mod host_key_verify;
mod known_hosts;
mod reconnect;
#[cfg(feature = "client")]
mod auth;
#[cfg(feature = "client")]
mod client;
#[cfg(feature = "client")]
mod transport;

pub use agent::{
    is_agent_available, probe_agent, AgentAvailability, FakeAgent, PlatformAgentProbe,
    SshAgentProbe,
};
pub use agent_auth_select::{
    agent_auth_allowed, select_auth_methods_for_connect, AgentAuthSelectError, AuthMethodKind,
    FakeFallibleAgent, FallibleAgentProbe,
};
#[cfg(feature = "client")]
pub use agent_auth_select::filter_ssh_auth_methods_for_connect;
#[cfg(windows)]
pub use agent::OPENSSH_AGENT_PIPE;
pub use auto_sudo::{
    classify_sudo_line, classify_sudo_output, SudoOutputClass, SudoPromptTail, ELEVATION_COMMAND,
    PROMPT_TIMEOUT_SECS, TAIL_CAPACITY,
};
pub use auto_sudo_glue::{
    AutoSudoPassword, AutoSudoPhase, AutoSudoSessionGlue, AutoSudoStep, AutoSudoTerminal,
    AutoSudoWriteError, LINE_TERMINATOR,
};
pub use error::SshError;
pub use reconnect::{
    decide_after_connect_attempt, decide_after_disconnect, plan_next_attempt,
    reconnect_exhausted_note, should_continue_auto_reconnect, BackoffSchedule,
    FakeBackoffSchedule, FixedBackoffSchedule, ReconnectConnectOutcome, ReconnectPolicyError,
    ReconnectStopReason, ReconnectVerdict, SshDisconnectCause, SshReconnectBudget,
    SshReconnectPolicy, AUTO_RECONNECT_DELAY, AUTO_RECONNECT_STABILITY_WINDOW,
    MAX_AUTO_RECONNECT_ATTEMPTS,
};
pub use host_key_prompt::{
    resolve_host_key_prompted, FakeHostKeyPrompt, FakeKnownHosts, HostKeyPinStore,
    HostKeyPrompt, HostKeyPromptReason, HostKeyPromptRequest, HostKeyPromptResponse,
    NullHostKeyPrompt,
};
pub use host_key_verify::{
    verify_host_key_on_connect, HostKeyConnectVerdict, HostKeyMismatchPolicy,
    HostKeyRejectReason,
};
pub use known_hosts::{
    compute_fingerprint, decide, host_identity, HostKeyDecision, HostKeyPolicy, KnownHostsStore,
};

#[cfg(feature = "client")]
pub use auth::{
    authenticate_with, ensure_auth_method_supported, load_private_key, validate_private_key_path,
    AuthAttempt, FakeAuthenticator, PasswordAuth, PrivateKeySource, RusshAuthenticator,
    SshAuthMethod, SshAuthenticator,
};
#[cfg(feature = "client")]
pub use client::{
    accept_server_host_key, connect_password_shell, fingerprint_public_key, validate_shell_resize,
    ShellChannelStub, SshClientSession, SshConnectOptions,
};
#[cfg(feature = "client")]
pub use transport::{
    connect_direct, connect_via_socks5, open_transport, DirectTcpTransport, Socks5Endpoint,
    Socks5TransportHook, SshTransport, TcpStreamTransport,
};

/// Crate-level result alias.
pub type Result<T> = std::result::Result<T, SshError>;
