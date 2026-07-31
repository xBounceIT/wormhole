//! Tree double-click / Open → session connect glue (pure state).
//!
//! Mirrors C# `ConnectionTreeViewModel.OpenConnectionAsync` for **persisted** tree
//! nodes: load a flat snapshot from [`ConnectionNodeSource`], resolve via
//! [`InheritanceResolver`], then either return a [`ConnectRequest`] /
//! [`TreeConnectRequest`] or call [`SessionOrchestrator::connect`]. Folders fail closed.
//!
//! **Call-site contract:** folder inheritance (host / credentials / tunnel tri-state /
//! config id) is always applied in [`prepare_connect_request`] **before** any
//! [`ConnectOptions`] are attached (`with_password` / `with_options` / connect helpers).
//! Never build orchestrator inputs from a raw leaf [`ConnectionNode`] alone.
//!
//! Passwords stay on [`ConnectOptions`] only (out-of-band stub) — never on the
//! resolved profile. Distinct from ephemeral [`crate::quick_connect::session_connect`].
//!
//! No GPUI. Gated behind `--features session` (default).

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use thiserror::Error;
use uuid::Uuid;
use wormhole_domain::{
    ConnectionNode, ConnectionProfile, InheritanceResolver, NodeKind, ResolveError,
};
use wormhole_session::{
    ConnectOptions, CredentialResolver, FakeSerialConnector, FakeSshConnector, SessionHandle,
    SessionOrchestrator,
};

use super::node::TreeNode;
use super::source::ConnectionNodeSource;
use super::TreeError;

/// Resolved profile from a tree Open / double-click (before protocol dispatch).
///
/// Hosts that open a session tab first can stash this and call [`connect`] later
/// with caller-owned [`ConnectOptions`]. Prefer [`TreeConnectRequest`] when the
/// out-of-band password is already known at prepare time.
#[derive(Clone)]
pub struct ConnectRequest {
    pub profile: ConnectionProfile,
}

impl ConnectRequest {
    pub fn profile(&self) -> &ConnectionProfile {
        &self.profile
    }

    pub fn into_profile(self) -> ConnectionProfile {
        self.profile
    }

    /// Attach an out-of-band password → [`TreeConnectRequest`].
    /// Forces `is_ephemeral = false` (persisted tree); password stays on options only.
    pub fn with_password(self, password: Option<String>) -> TreeConnectRequest {
        self.with_options(options_with_password(password))
    }

    /// Attach full [`ConnectOptions`] (password / tunnel / cancel) without mutating
    /// credential material onto the profile. Forces `is_ephemeral = false` (persisted tree).
    pub fn with_options(self, options: ConnectOptions) -> TreeConnectRequest {
        let mut profile = self.profile;
        profile.is_ephemeral = false;
        TreeConnectRequest { profile, options }
    }
}

impl fmt::Debug for ConnectRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectRequest")
            .field("profile_node_id", &self.profile.node_id)
            .field("name", &self.profile.name)
            .field("protocol", &self.profile.protocol)
            .field("host", &self.profile.host)
            .field("port", &self.profile.port)
            .field("is_ephemeral", &self.profile.is_ephemeral)
            .finish()
    }
}

/// Persisted-tree connect inputs: resolved profile + out-of-band [`ConnectOptions`].
///
/// Unlike Quick Connect, `profile.is_ephemeral` stays `false`. The session password
/// lives **only** on [`ConnectOptions::password`] (never on the profile / node).
pub struct TreeConnectRequest {
    pub profile: ConnectionProfile,
    pub options: ConnectOptions,
}

impl TreeConnectRequest {
    /// Profile + optional out-of-band password. Forces `is_ephemeral = false`.
    pub fn from_profile(profile: ConnectionProfile, password: Option<String>) -> Self {
        ConnectRequest { profile }.with_password(password)
    }
}

impl fmt::Debug for TreeConnectRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Delegate password redaction to ConnectOptions::Debug (`<redacted>`).
        f.debug_struct("TreeConnectRequest")
            .field("profile_node_id", &self.profile.node_id)
            .field("name", &self.profile.name)
            .field("protocol", &self.profile.protocol)
            .field("is_ephemeral", &self.profile.is_ephemeral)
            .field("host", &self.profile.host)
            .field("port", &self.profile.port)
            .field("options", &self.options)
            .finish()
    }
}

/// Build [`ConnectOptions`] with an out-of-band password stub (CredMgr/host resolves later).
///
/// Does not touch any [`ConnectionProfile`]. Blank / whitespace-only → `password: None`
/// so callers can pass through an empty field without forcing a failed SSH password auth.
pub fn options_with_password(password: Option<String>) -> ConnectOptions {
    let password = password.and_then(|p| {
        let trimmed = p.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    });
    ConnectOptions {
        password,
        ..ConnectOptions::default()
    }
}

/// Errors from tree → resolve → (optional) connect.
#[derive(Debug, Error)]
pub enum TreeOpenError {
    #[error("connection node {0} was not found in the node source")]
    NotFound(Uuid),

    /// Folders (and any non-connection kind) must not start a session.
    #[error("cannot open '{name}' because it is a {kind} (only connections can connect)")]
    NotAConnection { name: String, kind: NodeKind },

    #[error(transparent)]
    Source(#[from] TreeError),

    #[error(transparent)]
    Resolve(#[from] ResolveError),
}

/// Look up `node_id` in `source`, fail closed on folders, resolve inheritance → [`ConnectRequest`].
///
/// Does **not** start a protocol session (no orchestrator required). Profile is persisted
/// (`is_ephemeral = false`).
pub fn prepare_connect_request(
    node_id: Uuid,
    source: &dyn ConnectionNodeSource,
) -> Result<ConnectRequest, TreeOpenError> {
    let nodes = source.list_all()?;
    let map: HashMap<Uuid, ConnectionNode> = nodes.into_iter().map(|n| (n.id, n)).collect();

    let node = map.get(&node_id).ok_or(TreeOpenError::NotFound(node_id))?;

    if node.kind != NodeKind::Connection {
        return Err(TreeOpenError::NotAConnection {
            name: node.name.clone(),
            kind: node.kind,
        });
    }

    let mut profile = InheritanceResolver.resolve(node, &map)?;
    profile.is_ephemeral = false;
    Ok(ConnectRequest { profile })
}

/// Resolve a persisted tree node and attach an out-of-band password onto [`ConnectOptions`].
pub fn prepare_tree_connect(
    node_id: Uuid,
    source: &dyn ConnectionNodeSource,
    password: Option<String>,
) -> Result<TreeConnectRequest, TreeOpenError> {
    Ok(prepare_connect_request(node_id, source)?.with_password(password))
}

/// Same as [`prepare_tree_connect`], but takes the VM's selected [`TreeNode`].
///
/// Folders fail closed before any source round-trip when `selected.kind` is not a connection.
pub fn prepare_tree_connect_from_selection(
    selected: &TreeNode,
    source: &dyn ConnectionNodeSource,
    password: Option<String>,
) -> Result<TreeConnectRequest, TreeOpenError> {
    if selected.kind != NodeKind::Connection {
        return Err(TreeOpenError::NotAConnection {
            name: selected.name.clone(),
            kind: selected.kind,
        });
    }
    prepare_tree_connect(selected.id, source, password)
}

/// Call the session orchestrator with a prepared tree [`ConnectRequest`] + options.
pub async fn connect(
    orch: &SessionOrchestrator,
    request: ConnectRequest,
    options: ConnectOptions,
) -> SessionHandle {
    connect_prepared(orch, request.with_options(options)).await
}

/// Call the orchestrator with a bundled [`TreeConnectRequest`] (profile + options).
pub async fn connect_prepared(
    orch: &SessionOrchestrator,
    request: TreeConnectRequest,
) -> SessionHandle {
    orch.connect(request.profile, request.options).await
}

/// Resolve via [`prepare_connect_request`], attach `options`, then [`connect_prepared`].
///
/// Returns the live [`SessionHandle`] (Connected or Failed). Use
/// [`SessionHandle::into_result`] when you prefer `Result`.
pub async fn connect_from_tree(
    node_id: Uuid,
    source: &dyn ConnectionNodeSource,
    orch: &SessionOrchestrator,
    options: ConnectOptions,
) -> Result<SessionHandle, TreeOpenError> {
    let request = prepare_connect_request(node_id, source)?.with_options(options);
    Ok(connect_prepared(orch, request).await)
}

/// Selection convenience: [`prepare_tree_connect_from_selection`] → [`connect_prepared`].
pub async fn connect_from_selection(
    selected: &TreeNode,
    source: &dyn ConnectionNodeSource,
    orch: &SessionOrchestrator,
    password: Option<String>,
) -> Result<SessionHandle, TreeOpenError> {
    let request = prepare_tree_connect_from_selection(selected, source, password)?;
    Ok(connect_prepared(orch, request).await)
}

/// Test helper: orchestrator with fake serial + SSH, empty credential resolver, no tunnel broker.
pub fn fake_orchestrator_for_tests() -> (
    SessionOrchestrator,
    Arc<FakeSerialConnector>,
    Arc<FakeSshConnector>,
) {
    use wormhole_session::FakeCredentialResolver;
    fake_orchestrator_with_credentials(Arc::new(FakeCredentialResolver::new()))
}

/// Test helper: fake serial + SSH plus an injected credential resolver
/// (e.g. [`wormhole_session::FakeCredentialResolver`] preloaded with a `credential_id` password).
pub fn fake_orchestrator_with_credentials(
    credentials: Arc<dyn CredentialResolver>,
) -> (
    SessionOrchestrator,
    Arc<FakeSerialConnector>,
    Arc<FakeSshConnector>,
) {
    let serial = Arc::new(FakeSerialConnector::new());
    let ssh = Arc::new(FakeSshConnector::new());
    let orch = SessionOrchestrator::new(
        Arc::clone(&serial) as _,
        Arc::clone(&ssh) as _,
        None,
        credentials,
    );
    (orch, serial, ssh)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wormhole_domain::{ProtocolType, ResolveError};
    use wormhole_session::{
        ConnectedSession, FakeCredentialResolver, SessionError, SessionState,
    };

    use crate::tree::source::MemoryConnectionSource;

    /// Source that always fails `list_all` (source-error fail-closed probes).
    struct FailingConnectionSource;

    impl ConnectionNodeSource for FailingConnectionSource {
        fn list_all(&self) -> Result<Vec<ConnectionNode>, TreeError> {
            Err(TreeError::Load("injected source failure".into()))
        }
    }

    fn folder(id: Uuid, name: &str) -> ConnectionNode {
        ConnectionNode {
            id,
            name: name.into(),
            kind: NodeKind::Folder,
            ..ConnectionNode::default()
        }
    }

    fn conn(
        id: Uuid,
        parent: Option<Uuid>,
        name: &str,
        protocol: ProtocolType,
        host: &str,
    ) -> ConnectionNode {
        ConnectionNode {
            id,
            parent_id: parent,
            name: name.into(),
            kind: NodeKind::Connection,
            protocol: Some(protocol),
            host: Some(host.into()),
            use_inline_password: Some(matches!(protocol, ProtocolType::Ssh)),
            username: matches!(protocol, ProtocolType::Ssh).then(|| "alice".into()),
            ..ConnectionNode::default()
        }
    }

    fn tree_node_from(n: &ConnectionNode) -> TreeNode {
        TreeNode {
            id: n.id,
            parent_id: n.parent_id,
            name: n.name.clone(),
            kind: n.kind,
            protocol: n.protocol,
            host: n.host.clone(),
            sort_order: n.sort_order,
            children: Vec::new(),
            is_expanded: false,
        }
    }

    #[test]
    fn options_with_password_blank_becomes_none() {
        assert!(options_with_password(None).password.is_none());
        assert!(options_with_password(Some(String::new())).password.is_none());
        assert!(options_with_password(Some("   ".into())).password.is_none());
        assert_eq!(
            options_with_password(Some("  secret  ".into())).password.as_deref(),
            Some("secret")
        );
    }

    #[test]
    fn with_options_forces_persisted_ephemeral_flag() {
        let id = Uuid::new_v4();
        let source =
            MemoryConnectionSource::new(vec![conn(id, None, "box", ProtocolType::Ssh, "10.0.0.1")]);
        let mut req = prepare_connect_request(id, &source).unwrap();
        req.profile.is_ephemeral = true; // hostile / mistaken host mutation
        let bundled = req.with_options(ConnectOptions::default());
        assert!(!bundled.profile.is_ephemeral);
        let via_password = prepare_connect_request(id, &source)
            .unwrap()
            .with_password(None);
        assert!(!via_password.profile.is_ephemeral);
    }

    #[test]
    fn prepare_resolves_inherited_host_from_folder() {
        let folder_id = Uuid::new_v4();
        let leaf_id = Uuid::new_v4();
        let source = MemoryConnectionSource::new(vec![
            ConnectionNode {
                protocol: Some(ProtocolType::Ssh),
                host: Some("inherit.example".into()),
                ..folder(folder_id, "Servers")
            },
            ConnectionNode {
                id: leaf_id,
                parent_id: Some(folder_id),
                name: "leaf".into(),
                kind: NodeKind::Connection,
                use_inline_password: Some(true),
                username: Some("bob".into()),
                ..ConnectionNode::default()
            },
        ]);

        let req = prepare_connect_request(leaf_id, &source).unwrap();
        assert_eq!(req.profile.host, "inherit.example");
        assert_eq!(req.profile.protocol, ProtocolType::Ssh);
        assert_eq!(req.profile.username.as_deref(), Some("bob"));
        assert_eq!(req.profile.node_id, leaf_id);
        assert!(!req.profile.is_ephemeral);
    }

    #[test]
    fn prepare_inherits_folder_tunnel_before_options() {
        let folder_id = Uuid::new_v4();
        let leaf_id = Uuid::new_v4();
        let tunnel_id = Uuid::new_v4();
        let source = MemoryConnectionSource::new(vec![
            ConnectionNode {
                protocol: Some(ProtocolType::Ssh),
                host: Some("edge.prod".into()),
                tunnel_enabled: Some(true),
                tunnel_config_id: Some(tunnel_id),
                ..folder(folder_id, "Prod")
            },
            ConnectionNode {
                id: leaf_id,
                parent_id: Some(folder_id),
                name: "edge".into(),
                kind: NodeKind::Connection,
                // Leaf omits tunnel fields → inherit folder on/true + config id.
                use_inline_password: Some(true),
                username: Some("alice".into()),
                ..ConnectionNode::default()
            },
        ]);

        // Resolve-only prepare: inherited tunnel must already be on the profile
        // before any ConnectOptions exist.
        let req = prepare_connect_request(leaf_id, &source).unwrap();
        assert!(req.profile.tunnel_enabled);
        assert_eq!(req.profile.tunnel_config_id, Some(tunnel_id));
        assert_eq!(req.profile.host, "edge.prod");

        let bundled = req.with_password(Some("oob".into()));
        assert!(bundled.profile.tunnel_enabled);
        assert_eq!(bundled.profile.tunnel_config_id, Some(tunnel_id));
        assert_eq!(bundled.options.password.as_deref(), Some("oob"));
        assert!(bundled.options.tunnel.is_none());
    }

    #[test]
    fn prepare_inherits_folder_credential_before_options() {
        use wormhole_domain::CredentialBindingMode;

        let folder_id = Uuid::new_v4();
        let leaf_id = Uuid::new_v4();
        let cred_id = Uuid::new_v4();
        let source = MemoryConnectionSource::new(vec![
            ConnectionNode {
                protocol: Some(ProtocolType::Ssh),
                host: Some("app.prod".into()),
                username: Some("deploy".into()),
                credential_mode: Some(CredentialBindingMode::Saved),
                credential_id: Some(cred_id),
                ..folder(folder_id, "Prod")
            },
            ConnectionNode {
                id: leaf_id,
                parent_id: Some(folder_id),
                name: "app".into(),
                kind: NodeKind::Connection,
                credential_mode: Some(CredentialBindingMode::Inherit),
                ..ConnectionNode::default()
            },
        ]);

        let req = prepare_connect_request(leaf_id, &source).unwrap();
        assert_eq!(req.profile.credential_id, Some(cred_id));
        assert_eq!(req.profile.username.as_deref(), Some("deploy"));
        assert!(!req.profile.use_inline_password);

        // Options attach after resolve; inherited cred identity stays on the profile.
        let bundled = req.with_options(ConnectOptions::default());
        assert_eq!(bundled.profile.credential_id, Some(cred_id));
        assert!(bundled.options.password.is_none());
    }

    #[test]
    fn prepare_credential_none_stops_folder_credential() {
        use wormhole_domain::CredentialBindingMode;

        let folder_id = Uuid::new_v4();
        let leaf_id = Uuid::new_v4();
        let source = MemoryConnectionSource::new(vec![
            ConnectionNode {
                protocol: Some(ProtocolType::Ssh),
                host: Some("app.prod".into()),
                credential_mode: Some(CredentialBindingMode::Saved),
                credential_id: Some(Uuid::new_v4()),
                ..folder(folder_id, "Prod")
            },
            ConnectionNode {
                id: leaf_id,
                parent_id: Some(folder_id),
                name: "app".into(),
                kind: NodeKind::Connection,
                credential_mode: Some(CredentialBindingMode::None),
                username: Some("prompt-me".into()),
                ..ConnectionNode::default()
            },
        ]);

        let req = prepare_connect_request(leaf_id, &source).unwrap();
        assert!(req.profile.credential_id.is_none());
        assert_eq!(req.profile.username.as_deref(), Some("prompt-me"));
    }

    #[test]
    fn folder_fails_closed() {
        let folder_id = Uuid::new_v4();
        let source = MemoryConnectionSource::new(vec![folder(folder_id, "Docs")]);
        let err = prepare_connect_request(folder_id, &source).unwrap_err();
        match err {
            TreeOpenError::NotAConnection { name, kind } => {
                assert_eq!(name, "Docs");
                assert_eq!(kind, NodeKind::Folder);
            }
            other => panic!("expected NotAConnection, got {other:?}"),
        }
    }

    #[test]
    fn missing_node_fails_closed() {
        let source = MemoryConnectionSource::new(vec![]);
        let missing = Uuid::new_v4();
        match prepare_connect_request(missing, &source).unwrap_err() {
            TreeOpenError::NotFound(id) => assert_eq!(id, missing),
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn prepare_tree_connect_keeps_password_out_of_band_and_debug() {
        let id = Uuid::new_v4();
        let source =
            MemoryConnectionSource::new(vec![conn(id, None, "box", ProtocolType::Ssh, "10.0.0.1")]);
        let request = prepare_tree_connect(id, &source, Some("s3cret-never-log".into())).unwrap();
        assert!(!request.profile.is_ephemeral);
        assert_eq!(
            request.options.password.as_deref(),
            Some("s3cret-never-log")
        );
        // Password must not appear on the profile fields we surface in Debug.
        let dbg = format!("{request:?}");
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains("s3cret-never-log"));
        assert!(!request.profile.is_ephemeral);

        let bare = prepare_connect_request(id, &source).unwrap();
        let bare_dbg = format!("{bare:?}");
        assert!(!bare_dbg.to_lowercase().contains("password"));
        assert!(!bare_dbg.contains("credential"));
    }

    #[test]
    fn leaf_host_and_tunnel_off_skip_folder_inheritance() {
        let folder_id = Uuid::new_v4();
        let leaf_id = Uuid::new_v4();
        let tunnel_id = Uuid::new_v4();
        let source = MemoryConnectionSource::new(vec![
            ConnectionNode {
                protocol: Some(ProtocolType::Ssh),
                host: Some("folder.example".into()),
                tunnel_enabled: Some(true),
                tunnel_config_id: Some(tunnel_id),
                ..folder(folder_id, "Servers")
            },
            ConnectionNode {
                id: leaf_id,
                parent_id: Some(folder_id),
                name: "leaf".into(),
                kind: NodeKind::Connection,
                host: Some("leaf.example".into()),
                // Explicit override off — must not inherit folder tunnel.
                tunnel_enabled: Some(false),
                use_inline_password: Some(true),
                username: Some("bob".into()),
                ..ConnectionNode::default()
            },
        ]);

        let req = prepare_connect_request(leaf_id, &source).unwrap();
        assert_eq!(req.profile.host, "leaf.example");
        assert!(!req.profile.tunnel_enabled);
        // ConfigId still inherits — TunnelEnabled gates the launch (domain parity).
        assert_eq!(req.profile.tunnel_config_id, Some(tunnel_id));
    }

    #[test]
    fn missing_host_fails_closed_as_resolve() {
        let id = Uuid::new_v4();
        let source = MemoryConnectionSource::new(vec![ConnectionNode {
            id,
            name: "orphan".into(),
            kind: NodeKind::Connection,
            protocol: Some(ProtocolType::Ssh),
            host: None,
            use_inline_password: Some(true),
            username: Some("alice".into()),
            ..ConnectionNode::default()
        }]);
        match prepare_connect_request(id, &source).unwrap_err() {
            TreeOpenError::Resolve(ResolveError::MissingHost { name }) => {
                assert_eq!(name, "orphan");
            }
            other => panic!("expected MissingHost, got {other:?}"),
        }
    }

    #[test]
    fn missing_protocol_fails_closed_as_resolve() {
        let id = Uuid::new_v4();
        let source = MemoryConnectionSource::new(vec![ConnectionNode {
            id,
            name: "noproto".into(),
            kind: NodeKind::Connection,
            protocol: None,
            host: Some("h.example".into()),
            ..ConnectionNode::default()
        }]);
        match prepare_connect_request(id, &source).unwrap_err() {
            TreeOpenError::Resolve(ResolveError::MissingProtocol { name }) => {
                assert_eq!(name, "noproto");
            }
            other => panic!("expected MissingProtocol, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn source_error_never_reaches_orchestrator() {
        let (orch, serial, ssh) = fake_orchestrator_for_tests();
        let err = connect_from_tree(
            Uuid::new_v4(),
            &FailingConnectionSource,
            &orch,
            ConnectOptions::default(),
        )
        .await
        .unwrap_err();
        match err {
            TreeOpenError::Source(TreeError::Load(msg)) => {
                assert!(msg.contains("injected source failure"));
            }
            other => panic!("expected Source, got {other:?}"),
        }
        assert_eq!(serial.open_count(), 0);
        assert_eq!(ssh.connect_count(), 0);
    }

    #[tokio::test]
    async fn double_open_yields_two_independent_sessions() {
        let id = Uuid::new_v4();
        let source =
            MemoryConnectionSource::new(vec![conn(id, None, "com3", ProtocolType::Serial, "COM3")]);
        let (orch, serial, _) = fake_orchestrator_for_tests();

        let first = connect_from_tree(id, &source, &orch, ConnectOptions::default())
            .await
            .unwrap();
        let second = connect_from_tree(id, &source, &orch, ConnectOptions::default())
            .await
            .unwrap();
        assert_eq!(first.state(), SessionState::Connected);
        assert_eq!(second.state(), SessionState::Connected);
        assert_ne!(first.id(), second.id());
        assert_eq!(serial.open_count(), 2);
        first.close().await;
        second.close().await;
    }

    #[test]
    fn selection_folder_fails_closed_without_source_hit() {
        let folder_id = Uuid::new_v4();
        let selected = TreeNode {
            id: folder_id,
            parent_id: None,
            name: "NoOpen".into(),
            kind: NodeKind::Folder,
            protocol: None,
            host: None,
            sort_order: 0,
            children: Vec::new(),
            is_expanded: false,
        };
        // Empty source: if we incorrectly fell through to prepare_connect_request we'd get NotFound.
        let source = MemoryConnectionSource::new(vec![]);
        let err =
            prepare_tree_connect_from_selection(&selected, &source, None).unwrap_err();
        assert!(matches!(err, TreeOpenError::NotAConnection { .. }));
    }

    #[tokio::test]
    async fn connect_serial_via_fake() {
        let id = Uuid::new_v4();
        let source =
            MemoryConnectionSource::new(vec![conn(id, None, "com3", ProtocolType::Serial, "COM3")]);
        let (orch, serial, _) = fake_orchestrator_for_tests();

        let handle = connect_from_tree(id, &source, &orch, ConnectOptions::default())
            .await
            .unwrap();
        assert_eq!(handle.state(), SessionState::Connected);
        assert!(matches!(
            handle.connected(),
            Some(ConnectedSession::Serial(_))
        ));
        assert_eq!(serial.open_count(), 1);
        assert!(!handle.profile().is_ephemeral);
        handle.close().await;
    }

    #[tokio::test]
    async fn connect_ssh_via_fake_out_of_band_password() {
        let id = Uuid::new_v4();
        let source =
            MemoryConnectionSource::new(vec![conn(id, None, "box", ProtocolType::Ssh, "10.0.0.1")]);
        let (orch, _, ssh) = fake_orchestrator_for_tests();

        let handle = connect_prepared(
            &orch,
            prepare_tree_connect(id, &source, Some("secret".into())).unwrap(),
        )
        .await;
        assert_eq!(handle.state(), SessionState::Connected);
        assert!(matches!(handle.connected(), Some(ConnectedSession::Ssh(_))));
        assert_eq!(ssh.connect_count(), 1);
        let dbg = format!("{:?}", handle);
        assert!(!dbg.contains("secret"));
        handle.close().await;
    }

    #[tokio::test]
    async fn connect_ssh_via_credential_resolver_stub() {
        let id = Uuid::new_v4();
        let cred = Uuid::new_v4();
        let source = MemoryConnectionSource::new(vec![ConnectionNode {
            credential_id: Some(cred),
            use_inline_password: Some(false),
            ..conn(id, None, "box", ProtocolType::Ssh, "10.0.0.2")
        }]);
        let credentials = Arc::new(FakeCredentialResolver::new().with_password(cred, "from-store"));
        let (orch, _, ssh) = fake_orchestrator_with_credentials(credentials);

        // No password on ConnectOptions — orchestrator resolves via CredentialResolver stub.
        let handle = connect_from_tree(id, &source, &orch, ConnectOptions::default())
            .await
            .unwrap();
        assert_eq!(handle.state(), SessionState::Connected);
        assert_eq!(ssh.connect_count(), 1);
        let err_dbg = format!("{:?}", handle);
        assert!(!err_dbg.contains("from-store"));
        handle.close().await;
    }

    #[tokio::test]
    async fn connect_http_via_fake_orchestrator() {
        let id = Uuid::new_v4();
        let source = MemoryConnectionSource::new(vec![conn(
            id,
            None,
            "fw",
            ProtocolType::Http,
            "fw.local",
        )]);
        let (orch, serial, ssh) = fake_orchestrator_for_tests();

        let handle = connect_from_tree(id, &source, &orch, ConnectOptions::default())
            .await
            .unwrap();
        assert_eq!(handle.state(), SessionState::Connected);
        assert!(matches!(
            handle.connected(),
            Some(ConnectedSession::Http(_))
        ));
        assert_eq!(serial.open_count(), 0);
        assert_eq!(ssh.connect_count(), 0);
        handle.close().await;
    }

    #[tokio::test]
    async fn folder_never_reaches_orchestrator() {
        let folder_id = Uuid::new_v4();
        let source = MemoryConnectionSource::new(vec![folder(folder_id, "NoOpen")]);
        let (orch, serial, ssh) = fake_orchestrator_for_tests();

        let err = connect_from_tree(folder_id, &source, &orch, ConnectOptions::default())
            .await
            .unwrap_err();
        assert!(matches!(err, TreeOpenError::NotAConnection { .. }));
        assert_eq!(serial.open_count(), 0);
        assert_eq!(ssh.connect_count(), 0);

        let selected = TreeNode {
            id: folder_id,
            parent_id: None,
            name: "NoOpen".into(),
            kind: NodeKind::Folder,
            protocol: None,
            host: None,
            sort_order: 0,
            children: Vec::new(),
            is_expanded: false,
        };
        let err = connect_from_selection(&selected, &source, &orch, Some("pw".into()))
            .await
            .unwrap_err();
        assert!(matches!(err, TreeOpenError::NotAConnection { .. }));
        assert_eq!(serial.open_count(), 0);
        assert_eq!(ssh.connect_count(), 0);
    }

    #[tokio::test]
    async fn connect_from_selection_serial() {
        let id = Uuid::new_v4();
        let node = conn(id, None, "com5", ProtocolType::Serial, "COM5");
        let selected = tree_node_from(&node);
        let source = MemoryConnectionSource::new(vec![node]);
        let (orch, serial, _) = fake_orchestrator_for_tests();

        let handle = connect_from_selection(&selected, &source, &orch, None)
            .await
            .unwrap();
        assert_eq!(handle.state(), SessionState::Connected);
        assert_eq!(serial.open_count(), 1);
        handle.close().await;
    }

    #[tokio::test]
    async fn prepare_then_connect_matches_connect_from_tree() {
        let id = Uuid::new_v4();
        let source =
            MemoryConnectionSource::new(vec![conn(id, None, "web", ProtocolType::Https, "a.b")]);
        let req = prepare_connect_request(id, &source).unwrap();
        assert_eq!(req.profile().protocol, ProtocolType::Https);
        assert_eq!(req.profile().host, "a.b");
        assert_eq!(req.profile().port, 443);

        let (orch, _, _) = fake_orchestrator_for_tests();
        let handle = connect(&orch, req, ConnectOptions::default()).await;
        assert_eq!(handle.state(), SessionState::Connected);
        handle.close().await;
    }

    #[tokio::test]
    async fn rdp_still_unsupported_protocol() {
        let id = Uuid::new_v4();
        let source =
            MemoryConnectionSource::new(vec![conn(id, None, "dc", ProtocolType::Rdp, "dc.local")]);
        let (orch, serial, ssh) = fake_orchestrator_for_tests();

        let handle = connect_prepared(
            &orch,
            prepare_tree_connect(id, &source, Some("rdp-secret".into())).unwrap(),
        )
        .await;
        assert_eq!(handle.state(), SessionState::Failed);
        assert_eq!(serial.open_count(), 0);
        assert_eq!(ssh.connect_count(), 0);
        match handle.last_error() {
            Some(SessionError::UnsupportedProtocol { protocol, reason }) => {
                assert_eq!(*protocol, ProtocolType::Rdp);
                let req = reason.as_rdp_request().expect("prepared");
                assert_eq!(req.host, "dc.local");
                assert_eq!(req.port, 3389);
            }
            other => panic!("expected UnsupportedProtocol Rdp, got {other:?}"),
        }
        let err_dbg = format!("{:?}", handle.last_error());
        let err_disp = handle.last_error().unwrap().to_string();
        assert!(!err_dbg.contains("rdp-secret"));
        assert!(!err_disp.contains("rdp-secret"));
    }

    #[tokio::test]
    async fn vnc_still_unsupported_protocol() {
        let id = Uuid::new_v4();
        let source = MemoryConnectionSource::new(vec![conn(
            id,
            None,
            "desk",
            ProtocolType::Vnc,
            "vnc.local",
        )]);
        let (orch, _, _) = fake_orchestrator_for_tests();

        let handle = connect_prepared(
            &orch,
            prepare_tree_connect(id, &source, Some("vnc-secret".into())).unwrap(),
        )
        .await;
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
        assert!(!err_dbg.contains("vnc-secret"));
    }
}
