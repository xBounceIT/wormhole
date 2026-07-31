//! Port of `Wormhole.Tests.Data.InheritanceResolverTunnelTests`.

use std::collections::HashMap;

use uuid::Uuid;
use wormhole_domain::{ConnectionNode, InheritanceResolver, NodeKind, ProtocolType};

fn nodes(entries: &[ConnectionNode]) -> HashMap<Uuid, ConnectionNode> {
    entries.iter().map(|n| (n.id, n.clone())).collect()
}

fn connection_node(host: &str, protocol: ProtocolType) -> ConnectionNode {
    ConnectionNode {
        id: Uuid::new_v4(),
        name: "n".into(),
        kind: NodeKind::Connection,
        host: Some(host.to_string()),
        protocol: Some(protocol),
        ..Default::default()
    }
}

#[test]
fn resolve_tunnel_defaults_to_disabled_when_nothing_set() {
    let node = connection_node("h.example", ProtocolType::Ssh);
    let map = nodes(&[node.clone()]);
    let profile = InheritanceResolver::new().resolve(&node, &map).unwrap();
    assert!(!profile.tunnel_enabled);
    assert!(profile.tunnel_config_id.is_none());
}

#[test]
fn resolve_inherits_tunnel_enabled_and_config_id_from_ancestor() {
    let tunnel_id = Uuid::new_v4();
    let folder = ConnectionNode {
        id: Uuid::new_v4(),
        name: "prod".into(),
        kind: NodeKind::Folder,
        tunnel_enabled: Some(true),
        tunnel_config_id: Some(tunnel_id),
        ..Default::default()
    };
    let mut leaf = connection_node("edge.prod", ProtocolType::Ssh);
    leaf.parent_id = Some(folder.id);
    leaf.name = "edge".into();
    let map = nodes(&[folder, leaf.clone()]);
    let profile = InheritanceResolver::new().resolve(&leaf, &map).unwrap();
    assert!(profile.tunnel_enabled);
    assert_eq!(profile.tunnel_config_id, Some(tunnel_id));
}

#[test]
fn resolve_child_explicitly_disables_inherited_tunnel() {
    let tunnel_id = Uuid::new_v4();
    let folder = ConnectionNode {
        id: Uuid::new_v4(),
        name: "prod".into(),
        kind: NodeKind::Folder,
        tunnel_enabled: Some(true),
        tunnel_config_id: Some(tunnel_id),
        ..Default::default()
    };
    let mut leaf = connection_node("edge.prod", ProtocolType::Ssh);
    leaf.parent_id = Some(folder.id);
    leaf.name = "edge".into();
    leaf.tunnel_enabled = Some(false);
    let map = nodes(&[folder, leaf.clone()]);
    let profile = InheritanceResolver::new().resolve(&leaf, &map).unwrap();
    assert!(!profile.tunnel_enabled);
    // ConfigId still inherits — TunnelEnabled gates the launch.
    assert_eq!(profile.tunnel_config_id, Some(tunnel_id));
}

#[test]
fn resolve_child_overrides_ancestor_tunnel_config_id() {
    let folder = ConnectionNode {
        id: Uuid::new_v4(),
        name: "prod".into(),
        kind: NodeKind::Folder,
        tunnel_enabled: Some(true),
        tunnel_config_id: Some(Uuid::new_v4()),
        ..Default::default()
    };
    let own_config = Uuid::new_v4();
    let mut leaf = connection_node("edge.prod", ProtocolType::Ssh);
    leaf.parent_id = Some(folder.id);
    leaf.name = "edge".into();
    leaf.tunnel_config_id = Some(own_config);
    let map = nodes(&[folder, leaf.clone()]);
    let profile = InheritanceResolver::new().resolve(&leaf, &map).unwrap();
    assert!(profile.tunnel_enabled);
    assert_eq!(profile.tunnel_config_id, Some(own_config));
}

#[test]
fn resolve_leaf_true_overrides_ancestor_explicit_false() {
    let folder = ConnectionNode {
        id: Uuid::new_v4(),
        name: "prod".into(),
        kind: NodeKind::Folder,
        tunnel_enabled: Some(false),
        tunnel_config_id: Some(Uuid::new_v4()),
        ..Default::default()
    };
    let mut leaf = connection_node("edge.prod", ProtocolType::Ssh);
    leaf.parent_id = Some(folder.id);
    leaf.name = "edge".into();
    leaf.tunnel_enabled = Some(true);
    let map = nodes(&[folder.clone(), leaf.clone()]);
    let profile = InheritanceResolver::new().resolve(&leaf, &map).unwrap();
    assert!(profile.tunnel_enabled);
    assert_eq!(profile.tunnel_config_id, folder.tunnel_config_id);
}
