//! Quick Connect → [`wormhole_session`] connect glue (pure; no GPUI).
//!
//! Maps an accepted [`QuickConnectResult`] (or an already-resolved ephemeral
//! [`ConnectionProfile`] + out-of-band password) into orchestrator inputs, then
//! optionally calls [`SessionOrchestrator::connect`]. Password stays only on
//! [`ConnectOptions`] — never on the node/profile, and never in `Debug`/`Display`.
//!
//! **Call-site contract:** [`prepare_connect`] always runs [`InheritanceResolver`]
//! on the solo ephemeral node **before** packing [`ConnectOptions`]. QC has no
//! folder ancestry (solo map) — tunnel/cred come from the ephemeral editor write,
//! not a persisted parent. Still never skip the resolver (defaults / validation).
//! [`prepare_connect_ephemeral`] trusts an already-resolved profile.
//!
//! Tunnel **flags** live on the ephemeral profile (`tunnel_enabled` /
//! `tunnel_config_id`). [`ConnectOptions::tunnel`] args (secret blob / snapshot)
//! stay caller-owned: set them on [`QuickConnectConnectRequest::options`] before
//! [`connect_prepared`] when the profile has a tunnel. [`connect_quick_connect`]
//! does not load DPAPI tunnel secrets.
//!
//! RDP / VNC: orchestrator still fail-closes with [`SessionError::UnsupportedProtocol`].
//! Callers that need the out-of-band password for a future surface host should
//! [`prepare_connect`] and branch **before** `connect_*` (connect drops options).

use std::collections::HashMap;
use std::fmt;

use wormhole_domain::{ConnectionProfile, InheritanceResolver};
use wormhole_session::{ConnectOptions, SessionHandle, SessionOrchestrator};

use super::state::PASSWORD_REDACTED;
use super::{BuildError, QuickConnectResult};

/// Prepared orchestrator inputs from a Quick Connect accept.
///
/// The profile is ephemeral (`is_ephemeral = true`). The session password, when
/// present, lives **only** on [`ConnectOptions::password`] (out-of-band).
pub struct QuickConnectConnectRequest {
    pub profile: ConnectionProfile,
    pub options: ConnectOptions,
}

impl QuickConnectConnectRequest {
    /// Profile + out-of-band password (no node resolve). Forces `is_ephemeral = true`.
    pub fn from_ephemeral(mut profile: ConnectionProfile, password: Option<String>) -> Self {
        profile.is_ephemeral = true;
        Self {
            profile,
            options: options_with_password(password),
        }
    }
}

/// Build [`ConnectOptions`] with an out-of-band password (profile untouched).
fn options_with_password(password: Option<String>) -> ConnectOptions {
    ConnectOptions {
        password,
        ..ConnectOptions::default()
    }
}

impl fmt::Debug for QuickConnectConnectRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Always `<redacted>` (parity with QuickConnectResult) — do not reveal
        // Some/None via ConnectOptions::Debug.
        f.debug_struct("QuickConnectConnectRequest")
            .field("profile_node_id", &self.profile.node_id)
            .field("protocol", &self.profile.protocol)
            .field("is_ephemeral", &self.profile.is_ephemeral)
            .field("host", &self.profile.host)
            .field("port", &self.profile.port)
            .field("tunnel_enabled", &self.profile.tunnel_enabled)
            .field("tunnel_config_id", &self.profile.tunnel_config_id)
            .field("options_password", &PASSWORD_REDACTED)
            .field("options_tunnel", &self.options.tunnel)
            .field(
                "options_cancel_is_cancelled",
                &self.options.cancel.is_cancelled(),
            )
            .finish()
    }
}

impl fmt::Display for QuickConnectConnectRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "QuickConnectConnectRequest {{ NodeId = {}, Protocol = {}, Password = {PASSWORD_REDACTED} }}",
            self.profile.node_id, self.profile.protocol
        )
    }
}

/// Resolve a solo ephemeral profile from [`QuickConnectResult`] and attach the
/// out-of-band password onto [`ConnectOptions`] (never onto the profile).
pub fn prepare_connect(result: QuickConnectResult) -> Result<QuickConnectConnectRequest, BuildError> {
    let QuickConnectResult { node, password } = result;
    let node_id = node.id;
    let mut nodes = HashMap::new();
    nodes.insert(node_id, node);
    let profile = InheritanceResolver
        .resolve(&nodes[&node_id], &nodes)
        .map_err(BuildError::Resolve)?;
    Ok(QuickConnectConnectRequest::from_ephemeral(profile, password))
}

/// Build connect inputs from an already-resolved ephemeral profile + password.
pub fn prepare_connect_ephemeral(
    profile: ConnectionProfile,
    password: Option<String>,
) -> QuickConnectConnectRequest {
    QuickConnectConnectRequest::from_ephemeral(profile, password)
}

/// Call the session orchestrator with a prepared Quick Connect request.
pub async fn connect_prepared(
    orch: &SessionOrchestrator,
    request: QuickConnectConnectRequest,
) -> SessionHandle {
    orch.connect(request.profile, request.options).await
}

/// Accept path convenience: [`QuickConnectResult`] → prepare → orchestrator connect.
///
/// Does not inject [`ConnectOptions::tunnel`]. When `profile.tunnel_enabled`, prefer
/// [`prepare_connect`] + set `options.tunnel` + [`connect_prepared`].
pub async fn connect_quick_connect(
    orch: &SessionOrchestrator,
    result: QuickConnectResult,
) -> Result<SessionHandle, BuildError> {
    let request = prepare_connect(result)?;
    Ok(connect_prepared(orch, request).await)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use uuid::Uuid;
    use wormhole_domain::{ConnectionProfile, ProtocolType};
    use wormhole_session::{
        ConnectedSession, FakeSerialConnector, FakeSshConnector, SessionError, SessionOrchestrator,
        SessionState, SshConnected,
    };

    use super::*;
    use crate::connection_editor::TunnelUiSelection;
    use crate::quick_connect::QuickConnectState;

    fn orch() -> SessionOrchestrator {
        SessionOrchestrator::for_tests(
            Arc::new(FakeSerialConnector::new()),
            Arc::new(FakeSshConnector::new()),
            None,
        )
    }

    #[test]
    fn prepare_connect_keeps_password_out_of_band_and_debug() {
        let mut qc = QuickConnectState::new();
        qc.set_host("ssh.example");
        qc.set_username("alice");
        qc.set_use_saved_credentials(false);
        qc.set_inline_password("s3cret-never-log");
        let result = qc.try_build().expect("valid");
        assert_eq!(result.password.as_deref(), Some("s3cret-never-log"));

        let request = prepare_connect(result).expect("resolve");
        assert!(request.profile.is_ephemeral);
        assert_eq!(request.profile.protocol, ProtocolType::Ssh);
        assert_eq!(request.profile.host, "ssh.example");
        assert_eq!(request.profile.port, 22);
        assert_eq!(request.options.password.as_deref(), Some("s3cret-never-log"));
        // SSH QC accept sets use_inline_password on the node (VNC does not); the secret
        // itself stays only on ConnectOptions / QuickConnectResult.password.
        assert!(request.profile.use_inline_password);
        assert!(!format!("{:?}", request.profile).contains("s3cret-never-log"));

        let dbg = format!("{request:?}");
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains("s3cret-never-log"));
        let disp = format!("{request}");
        assert!(disp.contains("<redacted>"));
        assert!(!disp.contains("s3cret-never-log"));
        let opts_dbg = format!("{:?}", request.options);
        assert!(opts_dbg.contains("<redacted>"));
        assert!(!opts_dbg.contains("s3cret-never-log"));
    }

    #[test]
    fn debug_and_display_always_redact_password_field_even_when_none() {
        let mut qc = QuickConnectState::new();
        qc.set_protocol(ProtocolType::Serial);
        qc.set_host("COM1");
        let request = prepare_connect(qc.try_build().unwrap()).unwrap();
        assert!(request.options.password.is_none());
        let dbg = format!("{request:?}");
        let disp = format!("{request}");
        assert!(dbg.contains("<redacted>"), "{dbg}");
        assert!(disp.contains("<redacted>"), "{disp}");
        // Must not echo ConnectOptions' `password: None` presence leak via nested options Debug.
        assert!(!dbg.contains("password: None"), "{dbg}");
    }

    #[test]
    fn tunnel_flags_survive_prepare_options_tunnel_stays_none() {
        let tunnel_id = Uuid::new_v4();
        let mut qc = QuickConnectState::new();
        qc.set_host("behind.vpn");
        qc.set_username("alice");
        qc.set_use_saved_credentials(false);
        qc.set_inline_password("pw");
        qc.set_tunnel_selection(TunnelUiSelection::Config(tunnel_id));
        let request = prepare_connect(qc.try_build().unwrap()).unwrap();
        assert!(request.profile.is_ephemeral);
        assert!(request.profile.tunnel_enabled);
        assert_eq!(request.profile.tunnel_config_id, Some(tunnel_id));
        assert!(request.options.tunnel.is_none());
        assert_eq!(request.options.password.as_deref(), Some("pw"));
    }

    #[test]
    fn prepare_connect_runs_resolver_before_options_solo_map() {
        // Solo ephemeral node: InheritanceResolver still applies protocol defaults
        // (port) before ConnectOptions are packed. A dangling parent_id must not
        // invent folder tunnel/cred (parent absent from the solo map).
        let mut qc = QuickConnectState::new();
        qc.set_host("solo.example");
        qc.set_username("alice");
        qc.set_use_saved_credentials(false);
        qc.set_inline_password("pw");
        let mut result = qc.try_build().unwrap();
        result.node.parent_id = Some(Uuid::new_v4());
        result.node.port = None;
        result.node.tunnel_enabled = Some(false);
        result.node.tunnel_config_id = None;
        result.node.credential_id = None;

        let request = prepare_connect(result).expect("solo resolve");
        assert!(request.profile.is_ephemeral);
        assert_eq!(request.profile.port, 22); // resolver default, not raw node
        assert!(!request.profile.tunnel_enabled);
        assert!(request.profile.tunnel_config_id.is_none());
        assert!(request.profile.credential_id.is_none());
        assert_eq!(request.options.password.as_deref(), Some("pw"));
        assert!(request.options.tunnel.is_none());
    }

    #[test]
    fn prepare_connect_and_ephemeral_path_agree_on_fields() {
        let mut qc = QuickConnectState::new();
        qc.set_host("box");
        qc.set_username("u");
        qc.set_use_saved_credentials(false);
        qc.set_inline_password("pw");
        let mut qc_ephemeral = qc.clone();
        let via_result = prepare_connect(qc.try_build().unwrap()).unwrap();
        let (profile, password) = qc_ephemeral.try_build_ephemeral_profile().unwrap();
        let via_ephemeral = prepare_connect_ephemeral(profile, password);

        assert_eq!(via_result.profile.node_id, via_ephemeral.profile.node_id);
        assert_eq!(via_result.profile.protocol, via_ephemeral.profile.protocol);
        assert_eq!(via_result.profile.host, via_ephemeral.profile.host);
        assert_eq!(via_result.profile.port, via_ephemeral.profile.port);
        assert!(via_result.profile.is_ephemeral && via_ephemeral.profile.is_ephemeral);
        assert_eq!(via_result.options.password, via_ephemeral.options.password);
        assert_eq!(
            via_result.profile.tunnel_enabled,
            via_ephemeral.profile.tunnel_enabled
        );
        assert_eq!(
            via_result.profile.tunnel_config_id,
            via_ephemeral.profile.tunnel_config_id
        );
    }

    #[tokio::test]
    async fn ssh_happy_path_via_fake() {
        let mut qc = QuickConnectState::new();
        qc.set_host("10.0.0.5");
        qc.set_username("alice");
        qc.set_use_saved_credentials(false);
        qc.set_inline_password("pw");
        let handle = connect_quick_connect(&orch(), qc.try_build().unwrap())
            .await
            .expect("prepare");
        assert_eq!(handle.state(), SessionState::Connected);
        assert!(handle.profile().is_ephemeral);
        match handle.connected() {
            Some(ConnectedSession::Ssh(SshConnected::Fake { host, port, .. })) => {
                assert_eq!(host, "10.0.0.5");
                assert_eq!(*port, 22);
            }
            other => panic!("expected Fake SSH, got {other:?}"),
        }
        handle.close().await;
    }

    #[tokio::test]
    async fn serial_happy_path_via_fake() {
        let mut qc = QuickConnectState::new();
        qc.set_protocol(ProtocolType::Serial);
        qc.set_host("COM3");
        let handle = connect_quick_connect(&orch(), qc.try_build().unwrap())
            .await
            .expect("prepare");
        assert_eq!(handle.state(), SessionState::Connected);
        assert!(handle.profile().is_ephemeral);
        assert!(matches!(
            handle.connected(),
            Some(ConnectedSession::Serial(_))
        ));
        handle.close().await;
    }

    #[tokio::test]
    async fn http_happy_path_via_fake() {
        let mut qc = QuickConnectState::new();
        qc.set_protocol(ProtocolType::Http);
        qc.set_host("fw.local");
        let handle = connect_quick_connect(&orch(), qc.try_build().unwrap())
            .await
            .expect("prepare");
        assert_eq!(handle.state(), SessionState::Connected);
        assert!(handle.profile().is_ephemeral);
        match handle.connected() {
            Some(ConnectedSession::Http(target)) => {
                assert!(target.navigate_uri.contains("fw.local"));
            }
            other => panic!("expected HTTP target, got {other:?}"),
        }
        handle.close().await;
    }

    #[tokio::test]
    async fn https_happy_path_via_fake() {
        let mut qc = QuickConnectState::new();
        qc.set_protocol(ProtocolType::Https);
        qc.set_host("fw.local:8443");
        let handle = connect_quick_connect(&orch(), qc.try_build().unwrap())
            .await
            .expect("prepare");
        assert_eq!(handle.state(), SessionState::Connected);
        assert!(handle.profile().is_ephemeral);
        match handle.connected() {
            Some(ConnectedSession::Http(target)) => {
                assert!(target.navigate_uri.starts_with("https://"));
                assert!(target.navigate_uri.contains("fw.local"));
            }
            other => panic!("expected HTTPS target, got {other:?}"),
        }
        handle.close().await;
    }

    #[tokio::test]
    async fn rdp_still_unsupported_protocol() {
        let mut qc = QuickConnectState::new();
        qc.set_protocol(ProtocolType::Rdp);
        qc.set_host("dc.local");
        qc.set_use_saved_credentials(false);
        qc.set_inline_password("rdp-secret");
        let result = qc.try_build().unwrap();
        let secret = result.password.clone();
        assert_eq!(secret.as_deref(), Some("rdp-secret"));

        let handle = connect_quick_connect(&orch(), result)
            .await
            .expect("prepare");
        assert_eq!(handle.state(), SessionState::Failed);
        match handle.last_error() {
            Some(SessionError::UnsupportedProtocol { protocol, reason }) => {
                assert_eq!(*protocol, ProtocolType::Rdp);
                let req = reason.as_rdp_request().expect("prepared");
                assert_eq!(req.host, "dc.local");
                assert_eq!(req.port, 3389);
                assert!(!req.tunnel_enabled);
            }
            other => panic!("expected UnsupportedProtocol Rdp, got {other:?}"),
        }
        let err_dbg = format!("{:?}", handle.last_error());
        let err_disp = handle.last_error().unwrap().to_string();
        assert!(!err_dbg.contains("rdp-secret"));
        assert!(!err_disp.contains("rdp-secret"));
    }

    #[tokio::test]
    async fn rdp_with_tunnel_still_fail_closed_before_tunnel_args() {
        let tunnel_id = Uuid::new_v4();
        let mut qc = QuickConnectState::new();
        qc.set_protocol(ProtocolType::Rdp);
        qc.set_host("dc.local");
        qc.set_use_saved_credentials(false);
        qc.set_inline_password("rdp-tunnel-secret");
        qc.set_tunnel_selection(TunnelUiSelection::Config(tunnel_id));
        let handle = connect_quick_connect(&orch(), qc.try_build().unwrap())
            .await
            .expect("prepare");
        assert_eq!(handle.state(), SessionState::Failed);
        // Must be UnsupportedProtocol (fail before tunnel), not TunnelArgsMissing.
        match handle.last_error() {
            Some(SessionError::UnsupportedProtocol { protocol, reason }) => {
                assert_eq!(*protocol, ProtocolType::Rdp);
                let req = reason.as_rdp_request().expect("prepared");
                assert!(req.tunnel_enabled);
                assert_eq!(req.tunnel_config_id, Some(tunnel_id));
            }
            other => panic!("expected UnsupportedProtocol Rdp, got {other:?}"),
        }
        let err_text = format!("{:?} / {}", handle.last_error(), handle.last_error().unwrap());
        assert!(!err_text.contains("rdp-tunnel-secret"));
    }

    #[tokio::test]
    async fn vnc_still_unsupported_protocol() {
        let mut qc = QuickConnectState::new();
        qc.set_protocol(ProtocolType::Vnc);
        qc.set_host("vnc.local");
        qc.set_use_saved_credentials(false);
        qc.set_inline_password("vnc-secret");
        let result = qc.try_build().unwrap();
        assert_eq!(result.password.as_deref(), Some("vnc-secret"));

        let handle = connect_quick_connect(&orch(), result)
            .await
            .expect("prepare");
        assert_eq!(handle.state(), SessionState::Failed);
        match handle.last_error() {
            Some(SessionError::UnsupportedProtocol { protocol, reason }) => {
                assert_eq!(*protocol, ProtocolType::Vnc);
                let req = reason.as_vnc_request().expect("prepared");
                assert_eq!(req.host, "vnc.local");
                assert_eq!(req.port, 5900);
            }
            other => panic!("expected UnsupportedProtocol Vnc, got {other:?}"),
        }
        let err_dbg = format!("{:?}", handle.last_error());
        let err_disp = handle.last_error().unwrap().to_string();
        assert!(!err_dbg.contains("vnc-secret"));
        assert!(!err_disp.contains("vnc-secret"));
    }

    #[tokio::test]
    async fn ssh_tunnel_without_args_fails_closed() {
        let tunnel_id = Uuid::new_v4();
        let mut qc = QuickConnectState::new();
        qc.set_host("behind.vpn");
        qc.set_username("alice");
        qc.set_use_saved_credentials(false);
        qc.set_inline_password("pw");
        qc.set_tunnel_selection(TunnelUiSelection::Config(tunnel_id));
        let handle = connect_quick_connect(&orch(), qc.try_build().unwrap())
            .await
            .expect("prepare");
        assert_eq!(handle.state(), SessionState::Failed);
        assert!(matches!(
            handle.last_error(),
            Some(SessionError::TunnelArgsMissing)
        ));
        assert!(handle.tunnel_lease().is_none());
    }

    #[tokio::test]
    async fn empty_host_rdp_ephemeral_fails_before_unsupported_reason() {
        let profile = ConnectionProfile {
            protocol: ProtocolType::Rdp,
            host: "   ".into(),
            port: 3389,
            is_ephemeral: false,
            ..ConnectionProfile::default()
        };
        let request = prepare_connect_ephemeral(profile, Some("rdp-secret".into()));
        assert!(request.profile.is_ephemeral);
        assert_eq!(request.options.password.as_deref(), Some("rdp-secret"));
        let handle = connect_prepared(&orch(), request).await;
        assert_eq!(handle.state(), SessionState::Failed);
        assert!(matches!(
            handle.last_error(),
            Some(SessionError::IncompleteNode)
        ));
        let err_text = format!("{:?} / {}", handle.last_error(), handle.last_error().unwrap());
        assert!(!err_text.contains("rdp-secret"));
    }

    #[tokio::test]
    async fn double_connect_independent_sessions() {
        let mut qc = QuickConnectState::new();
        qc.set_host("10.0.0.8");
        qc.set_username("alice");
        qc.set_use_saved_credentials(false);
        qc.set_inline_password("pw");
        let result = qc.try_build().unwrap();
        let orch = orch();
        let h1 = connect_quick_connect(&orch, result.clone())
            .await
            .expect("first");
        let h2 = connect_quick_connect(&orch, result).await.expect("second");
        assert_eq!(h1.state(), SessionState::Connected);
        assert_eq!(h2.state(), SessionState::Connected);
        assert_ne!(h1.id(), h2.id());
        h1.close().await;
        h2.close().await;
    }

    #[tokio::test]
    async fn ephemeral_profile_path_matches_result_path() {
        let mut qc = QuickConnectState::new();
        qc.set_host("box");
        qc.set_username("u");
        qc.set_use_saved_credentials(false);
        qc.set_inline_password("pw");
        let (profile, password) = qc.try_build_ephemeral_profile().unwrap();
        let request = prepare_connect_ephemeral(profile, password);
        let handle = connect_prepared(&orch(), request).await;
        assert_eq!(handle.state(), SessionState::Connected);
        handle.close().await;
    }
}
