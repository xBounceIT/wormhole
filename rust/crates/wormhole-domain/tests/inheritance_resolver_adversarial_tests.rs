//! Adversarial / fuzz-style edge cases for [`InheritanceResolver`].
//!
//! Complements the C# parity ports: deep folder chains, null tunnel tri-state
//! through mid folders, credential inherit vs stop/override mid-chain, and
//! longer / protocol-lookup cycle shapes.

use std::collections::HashMap;

use uuid::Uuid;
use wormhole_domain::{
    ConnectionNode, CredentialBindingMode, InheritanceResolver, NodeKind, ProtocolType,
    ResolveError,
};

fn nodes(entries: &[ConnectionNode]) -> HashMap<Uuid, ConnectionNode> {
    entries.iter().map(|n| (n.id, n.clone())).collect()
}

fn folder(name: &str) -> ConnectionNode {
    ConnectionNode {
        id: Uuid::new_v4(),
        name: name.to_string(),
        kind: NodeKind::Folder,
        ..Default::default()
    }
}

fn connection(name: &str, protocol: ProtocolType, host: &str) -> ConnectionNode {
    ConnectionNode {
        id: Uuid::new_v4(),
        name: name.to_string(),
        kind: NodeKind::Connection,
        protocol: Some(protocol),
        host: Some(host.to_string()),
        ..Default::default()
    }
}

/// Build `depth` folders above a leaf: leaf → f0 → f1 → … → f{depth-1} (root).
/// Returns (leaf, all nodes including leaf). Folders are `Inherit`-neutral.
fn deep_chain(depth: usize, leaf: ConnectionNode) -> (ConnectionNode, Vec<ConnectionNode>) {
    assert!(depth >= 1);
    let mut folders: Vec<ConnectionNode> = (0..depth)
        .map(|i| folder(&format!("f{i}")))
        .collect();
    for i in 0..depth.saturating_sub(1) {
        folders[i].parent_id = Some(folders[i + 1].id);
    }
    let mut leaf = leaf;
    leaf.parent_id = Some(folders[0].id);
    let mut all = folders;
    all.push(leaf.clone());
    (leaf, all)
}

// --- Deep folder chains -------------------------------------------------------

#[test]
fn resolve_deep_chain_inherits_root_only_fields() {
    const DEPTH: usize = 48;
    let root_cred = Uuid::new_v4();
    let tunnel_id = Uuid::new_v4();

    let mut leaf = connection("deep-leaf", ProtocolType::Ssh, "leaf.example");
    leaf.credential_mode = Some(CredentialBindingMode::Inherit);

    let (leaf, mut all) = deep_chain(DEPTH, leaf);
    let root = all
        .iter_mut()
        .find(|n| n.name == format!("f{}", DEPTH - 1))
        .expect("root folder");
    root.username = Some("root-user".into());
    root.port = Some(2222);
    root.credential_mode = Some(CredentialBindingMode::Saved);
    root.credential_id = Some(root_cred);
    root.tunnel_enabled = Some(true);
    root.tunnel_config_id = Some(tunnel_id);

    let map = nodes(&all);
    let profile = InheritanceResolver::new().resolve(&leaf, &map).unwrap();
    assert_eq!(profile.username.as_deref(), Some("root-user"));
    assert_eq!(profile.port, 2222);
    assert_eq!(profile.credential_id, Some(root_cred));
    assert!(profile.tunnel_enabled);
    assert_eq!(profile.tunnel_config_id, Some(tunnel_id));
    assert_eq!(profile.parent_folder_name.as_deref(), Some("f0"));
}

#[test]
fn resolve_deep_chain_nearest_override_beats_distant_root() {
    const DEPTH: usize = 32;
    let root_cred = Uuid::new_v4();
    let near_cred = Uuid::new_v4();

    let mut leaf = connection("deep-leaf", ProtocolType::Ssh, "leaf.example");
    leaf.credential_mode = Some(CredentialBindingMode::Inherit);

    let (leaf, mut all) = deep_chain(DEPTH, leaf);
    {
        let root = all
            .iter_mut()
            .find(|n| n.name == format!("f{}", DEPTH - 1))
            .unwrap();
        root.username = Some("root-user".into());
        root.credential_mode = Some(CredentialBindingMode::Saved);
        root.credential_id = Some(root_cred);
        root.tunnel_enabled = Some(true);
        root.tunnel_config_id = Some(Uuid::new_v4());
    }
    {
        // Immediate parent of the leaf overrides credential + tunnel off.
        let near = all.iter_mut().find(|n| n.name == "f0").unwrap();
        near.username = Some("near-user".into());
        near.credential_mode = Some(CredentialBindingMode::Saved);
        near.credential_id = Some(near_cred);
        near.tunnel_enabled = Some(false);
    }

    let map = nodes(&all);
    let profile = InheritanceResolver::new().resolve(&leaf, &map).unwrap();
    assert_eq!(profile.username.as_deref(), Some("near-user"));
    assert_eq!(profile.credential_id, Some(near_cred));
    assert!(!profile.tunnel_enabled);
}

// --- Null tri-state tunnel (`None` = inherit) ---------------------------------

#[test]
fn resolve_null_tunnel_mid_folder_passes_root_true() {
    let tunnel_id = Uuid::new_v4();
    let mut root = folder("root");
    root.tunnel_enabled = Some(true);
    root.tunnel_config_id = Some(tunnel_id);
    let mut mid = folder("mid");
    mid.parent_id = Some(root.id);
    mid.tunnel_enabled = None; // explicit inherit
    mid.tunnel_config_id = None;
    let mut leaf = connection("edge", ProtocolType::Ssh, "edge.prod");
    leaf.parent_id = Some(mid.id);
    leaf.tunnel_enabled = None;
    let map = nodes(&[root, mid, leaf.clone()]);
    let profile = InheritanceResolver::new().resolve(&leaf, &map).unwrap();
    assert!(profile.tunnel_enabled);
    assert_eq!(profile.tunnel_config_id, Some(tunnel_id));
}

#[test]
fn resolve_null_tunnel_mid_folder_passes_root_false() {
    let mut root = folder("root");
    root.tunnel_enabled = Some(false);
    root.tunnel_config_id = Some(Uuid::new_v4());
    let mut mid = folder("mid");
    mid.parent_id = Some(root.id);
    mid.tunnel_enabled = None;
    let mut leaf = connection("edge", ProtocolType::Ssh, "edge.prod");
    leaf.parent_id = Some(mid.id);
    leaf.tunnel_enabled = None;
    let map = nodes(&[root, mid, leaf.clone()]);
    let profile = InheritanceResolver::new().resolve(&leaf, &map).unwrap();
    assert!(!profile.tunnel_enabled);
    // Config id still first-wins independently of the enabled flag.
    assert!(profile.tunnel_config_id.is_some());
}

#[test]
fn resolve_null_leaf_tunnel_stopped_by_mid_explicit_false() {
    let tunnel_id = Uuid::new_v4();
    let mut root = folder("root");
    root.tunnel_enabled = Some(true);
    root.tunnel_config_id = Some(tunnel_id);
    let mut mid = folder("mid");
    mid.parent_id = Some(root.id);
    mid.tunnel_enabled = Some(false);
    let mut leaf = connection("edge", ProtocolType::Ssh, "edge.prod");
    leaf.parent_id = Some(mid.id);
    leaf.tunnel_enabled = None;
    let map = nodes(&[root, mid, leaf.clone()]);
    let profile = InheritanceResolver::new().resolve(&leaf, &map).unwrap();
    assert!(!profile.tunnel_enabled);
    assert_eq!(profile.tunnel_config_id, Some(tunnel_id));
}

#[test]
fn resolve_null_leaf_tunnel_takes_mid_true_over_root_false() {
    let mid_tunnel = Uuid::new_v4();
    let mut root = folder("root");
    root.tunnel_enabled = Some(false);
    root.tunnel_config_id = Some(Uuid::new_v4());
    let mut mid = folder("mid");
    mid.parent_id = Some(root.id);
    mid.tunnel_enabled = Some(true);
    mid.tunnel_config_id = Some(mid_tunnel);
    let mut leaf = connection("edge", ProtocolType::Ssh, "edge.prod");
    leaf.parent_id = Some(mid.id);
    leaf.tunnel_enabled = None;
    let map = nodes(&[root, mid, leaf.clone()]);
    let profile = InheritanceResolver::new().resolve(&leaf, &map).unwrap();
    assert!(profile.tunnel_enabled);
    assert_eq!(profile.tunnel_config_id, Some(mid_tunnel));
}

#[test]
fn resolve_null_tunnel_enabled_still_inherits_config_id_alone() {
    // Enabled never set anywhere → defaults false; config id still walks up.
    let tunnel_id = Uuid::new_v4();
    let mut root = folder("root");
    root.tunnel_enabled = None;
    root.tunnel_config_id = Some(tunnel_id);
    let mut mid = folder("mid");
    mid.parent_id = Some(root.id);
    mid.tunnel_enabled = None;
    let mut leaf = connection("edge", ProtocolType::Ssh, "edge.prod");
    leaf.parent_id = Some(mid.id);
    leaf.tunnel_enabled = None;
    let map = nodes(&[root, mid, leaf.clone()]);
    let profile = InheritanceResolver::new().resolve(&leaf, &map).unwrap();
    assert!(!profile.tunnel_enabled);
    assert_eq!(profile.tunnel_config_id, Some(tunnel_id));
}

// --- Credential inherit vs override / stop ------------------------------------

#[test]
fn resolve_credential_inherit_chain_reaches_root_saved() {
    let root_cred = Uuid::new_v4();
    let mut root = folder("root");
    root.credential_mode = Some(CredentialBindingMode::Saved);
    root.credential_id = Some(root_cred);
    root.username = Some("root-user".into());
    let mut mid = folder("mid");
    mid.parent_id = Some(root.id);
    mid.credential_mode = Some(CredentialBindingMode::Inherit);
    let mut leaf = connection("web-1", ProtocolType::Ssh, "web-1.prod");
    leaf.parent_id = Some(mid.id);
    leaf.credential_mode = Some(CredentialBindingMode::Inherit);
    let map = nodes(&[root, mid, leaf.clone()]);
    let profile = InheritanceResolver::new().resolve(&leaf, &map).unwrap();
    assert_eq!(profile.credential_id, Some(root_cred));
    assert_eq!(profile.username.as_deref(), Some("root-user"));
}

#[test]
fn resolve_credential_mid_none_stops_root_saved_for_inheriting_leaf() {
    let mut root = folder("root");
    root.credential_mode = Some(CredentialBindingMode::Saved);
    root.credential_id = Some(Uuid::new_v4());
    root.username = Some("root-user".into());
    let mut mid = folder("mid");
    mid.parent_id = Some(root.id);
    mid.credential_mode = Some(CredentialBindingMode::None);
    let mut leaf = connection("web-1", ProtocolType::Ssh, "web-1.prod");
    leaf.parent_id = Some(mid.id);
    leaf.credential_mode = Some(CredentialBindingMode::Inherit);
    let map = nodes(&[root, mid, leaf.clone()]);
    let profile = InheritanceResolver::new().resolve(&leaf, &map).unwrap();
    assert!(profile.credential_id.is_none());
    // None is not a saved-credential identity boundary — username still walks.
    assert_eq!(profile.username.as_deref(), Some("root-user"));
}

#[test]
fn resolve_credential_leaf_saved_overrides_deep_inherit_chain() {
    let leaf_cred = Uuid::new_v4();
    let root_cred = Uuid::new_v4();
    let mut leaf = connection("web-1", ProtocolType::Ssh, "web-1.prod");
    leaf.credential_mode = Some(CredentialBindingMode::Saved);
    leaf.credential_id = Some(leaf_cred);
    leaf.username = Some("leaf-user".into());

    let (leaf, mut all) = deep_chain(16, leaf);
    let root = all.iter_mut().find(|n| n.name == "f15").unwrap();
    root.credential_mode = Some(CredentialBindingMode::Saved);
    root.credential_id = Some(root_cred);
    root.username = Some("root-user".into());
    for n in all.iter_mut().filter(|n| n.kind == NodeKind::Folder && n.name != "f15") {
        n.credential_mode = Some(CredentialBindingMode::Inherit);
    }

    let map = nodes(&all);
    let profile = InheritanceResolver::new().resolve(&leaf, &map).unwrap();
    assert_eq!(profile.credential_id, Some(leaf_cred));
    assert_eq!(profile.username.as_deref(), Some("leaf-user"));
}

#[test]
fn resolve_credential_mid_saved_null_id_stops_cred_but_not_username() {
    // Saved + null credential_id stops the credential walk (resolved, id=None) but
    // is NOT an identity boundary — username/rdp_domain may still come from farther up.
    let mut root = folder("root");
    root.credential_mode = Some(CredentialBindingMode::Saved);
    root.credential_id = Some(Uuid::new_v4());
    root.username = Some("root-user".into());
    let mut mid = folder("mid");
    mid.parent_id = Some(root.id);
    mid.credential_mode = Some(CredentialBindingMode::Saved);
    mid.credential_id = None;
    let mut leaf = connection("web-1", ProtocolType::Ssh, "web-1.prod");
    leaf.parent_id = Some(mid.id);
    leaf.credential_mode = Some(CredentialBindingMode::Inherit);
    let map = nodes(&[root, mid, leaf.clone()]);
    let profile = InheritanceResolver::new().resolve(&leaf, &map).unwrap();
    assert!(profile.credential_id.is_none());
    assert_eq!(profile.username.as_deref(), Some("root-user"));
}

// --- Cycle detection shapes ---------------------------------------------------

#[test]
fn resolve_throws_on_three_folder_cycle() {
    let mut a = folder("a");
    let mut b = folder("b");
    let mut c = folder("c");
    a.parent_id = Some(b.id);
    b.parent_id = Some(c.id);
    c.parent_id = Some(a.id);
    let mut leaf = connection("leaf", ProtocolType::Ssh, "host");
    leaf.parent_id = Some(a.id);
    let map = nodes(&[a, b, c, leaf.clone()]);
    assert!(matches!(
        InheritanceResolver::new().resolve(&leaf, &map),
        Err(ResolveError::Cycle { .. })
    ));
}

#[test]
fn resolve_throws_on_cycle_reached_only_via_protocol_lookup() {
    // `find_resolved_protocol` runs when the leaf opts into inline password and
    // has no protocol of its own — cycle must still surface as ResolveError::Cycle.
    let mut a = folder("a");
    let mut b = folder("b");
    a.parent_id = Some(b.id);
    b.parent_id = Some(a.id);
    let leaf = ConnectionNode {
        id: Uuid::new_v4(),
        parent_id: Some(a.id),
        name: "leaf".into(),
        kind: NodeKind::Connection,
        host: Some("host".into()),
        protocol: None,
        use_inline_password: Some(true),
        ..Default::default()
    };
    let map = nodes(&[a, b, leaf.clone()]);
    assert!(matches!(
        InheritanceResolver::new().resolve(&leaf, &map),
        Err(ResolveError::Cycle { .. })
    ));
}

#[test]
fn resolve_throws_on_cycle_after_long_linear_prefix() {
    const DEPTH: usize = 24;
    let leaf = connection("leaf", ProtocolType::Ssh, "host");
    let (leaf, mut all) = deep_chain(DEPTH, leaf);

    // Tie the root back into an earlier folder → cycle after a long walk.
    let early_id = all.iter().find(|n| n.name == "f3").unwrap().id;
    let root = all
        .iter_mut()
        .find(|n| n.name == format!("f{}", DEPTH - 1))
        .unwrap();
    root.parent_id = Some(early_id);

    let map = nodes(&all);
    assert!(matches!(
        InheritanceResolver::new().resolve(&leaf, &map),
        Err(ResolveError::Cycle { .. })
    ));
}

#[test]
fn resolve_cycle_error_names_a_node_in_the_loop() {
    let mut a = folder("cycle-a");
    let mut b = folder("cycle-b");
    a.parent_id = Some(b.id);
    b.parent_id = Some(a.id);
    let mut leaf = connection("leaf", ProtocolType::Ssh, "host");
    leaf.parent_id = Some(a.id);
    let map = nodes(&[a.clone(), b.clone(), leaf.clone()]);
    match InheritanceResolver::new().resolve(&leaf, &map) {
        Err(ResolveError::Cycle { name, id }) => {
            assert!(
                (name == "cycle-a" && id == a.id) || (name == "cycle-b" && id == b.id),
                "unexpected cycle node {name} ({id})"
            );
        }
        other => panic!("expected Cycle, got {other:?}"),
    }
}
