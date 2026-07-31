//! Port of `Wormhole.Tests.Data.InheritanceResolverTests`.

use std::collections::HashMap;

use uuid::Uuid;
use wormhole_domain::{
    ConnectionNode, CredentialBindingMode, InheritanceResolver, NodeKind, ProtocolType,
    RdpScreenSizes, ResolveError, SerialDefaults, SerialFlowControlMode, SerialParityMode,
    SerialStopBitsMode,
};

fn nodes(entries: &[ConnectionNode]) -> HashMap<Uuid, ConnectionNode> {
    entries.iter().map(|n| (n.id, n.clone())).collect()
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

fn folder(name: &str) -> ConnectionNode {
    ConnectionNode {
        id: Uuid::new_v4(),
        name: name.to_string(),
        kind: NodeKind::Folder,
        ..Default::default()
    }
}

#[test]
fn resolve_own_fields_only_returns_exact_values() {
    let node = connection("prod-db", ProtocolType::Ssh, "db.example.com");
    let mut node = node;
    node.port = Some(2222);
    node.username = Some("alice".into());
    let map = nodes(&[node.clone()]);
    let profile = InheritanceResolver::new().resolve(&node, &map).unwrap();
    assert_eq!(profile.protocol, ProtocolType::Ssh);
    assert_eq!(profile.host, "db.example.com");
    assert_eq!(profile.port, 2222);
    assert_eq!(profile.username.as_deref(), Some("alice"));
}

#[test]
fn resolve_inherits_username_and_port_from_parent_folder() {
    let mut folder = folder("prod");
    folder.username = Some("deploy".into());
    folder.port = Some(2222);
    let mut node = connection("web-1", ProtocolType::Ssh, "web-1.prod");
    node.parent_id = Some(folder.id);
    let map = nodes(&[folder, node.clone()]);
    let profile = InheritanceResolver::new().resolve(&node, &map).unwrap();
    assert_eq!(profile.username.as_deref(), Some("deploy"));
    assert_eq!(profile.port, 2222);
    assert_eq!(profile.host, "web-1.prod");
}

#[test]
fn resolve_child_overrides_parent() {
    let mut folder = folder("prod");
    folder.username = Some("deploy".into());
    folder.port = Some(22);
    let mut node = connection("bastion", ProtocolType::Ssh, "bastion.prod");
    node.parent_id = Some(folder.id);
    node.username = Some("alice".into());
    node.port = Some(2222);
    let map = nodes(&[folder, node.clone()]);
    let profile = InheritanceResolver::new().resolve(&node, &map).unwrap();
    assert_eq!(profile.username.as_deref(), Some("alice"));
    assert_eq!(profile.port, 2222);
}

#[test]
fn resolve_walks_multiple_ancestors_for_missing_fields() {
    let mut root = folder("all");
    root.username = Some("root-user".into());
    root.credential_id = Some(Uuid::new_v4());
    let mut mid = folder("prod");
    mid.parent_id = Some(root.id);
    mid.port = Some(22);
    let mut leaf = connection("edge", ProtocolType::Ssh, "edge.prod");
    leaf.parent_id = Some(mid.id);
    let root_cred = root.credential_id;
    let map = nodes(&[root, mid, leaf.clone()]);
    let profile = InheritanceResolver::new().resolve(&leaf, &map).unwrap();
    assert_eq!(profile.username.as_deref(), Some("root-user"));
    assert_eq!(profile.credential_id, root_cred);
    assert_eq!(profile.port, 22);
}

#[test]
fn resolve_parent_folder_name_uses_immediate_parent_only() {
    let root = folder("root");
    let mut mid = folder("prod");
    mid.parent_id = Some(root.id);
    let mut leaf = connection("edge", ProtocolType::Ssh, "edge.prod");
    leaf.parent_id = Some(mid.id);
    let map = nodes(&[root, mid, leaf.clone()]);
    let profile = InheritanceResolver::new().resolve(&leaf, &map).unwrap();
    assert_eq!(profile.parent_folder_name.as_deref(), Some("prod"));
}

#[test]
fn resolve_credential_mode_saved_inherits_from_parent_folder() {
    let cred_id = Uuid::new_v4();
    let mut folder = folder("prod");
    folder.username = Some("deploy".into());
    folder.credential_mode = Some(CredentialBindingMode::Saved);
    folder.credential_id = Some(cred_id);
    let mut node = connection("web-1", ProtocolType::Ssh, "web-1.prod");
    node.parent_id = Some(folder.id);
    node.credential_mode = Some(CredentialBindingMode::Inherit);
    let map = nodes(&[folder, node.clone()]);
    let profile = InheritanceResolver::new().resolve(&node, &map).unwrap();
    assert_eq!(profile.credential_id, Some(cred_id));
    assert_eq!(profile.username.as_deref(), Some("deploy"));
}

#[test]
fn resolve_credential_mode_none_on_child_stops_inherited_folder_credential() {
    let mut folder = folder("prod");
    folder.credential_mode = Some(CredentialBindingMode::Saved);
    folder.credential_id = Some(Uuid::new_v4());
    let mut node = connection("web-1", ProtocolType::Ssh, "web-1.prod");
    node.parent_id = Some(folder.id);
    node.credential_mode = Some(CredentialBindingMode::None);
    let map = nodes(&[folder, node.clone()]);
    let profile = InheritanceResolver::new().resolve(&node, &map).unwrap();
    assert!(profile.credential_id.is_none());
}

#[test]
fn resolve_credential_mode_saved_on_child_overrides_parent_folder() {
    let parent_cred = Uuid::new_v4();
    let child_cred = Uuid::new_v4();
    let mut folder = folder("prod");
    folder.credential_mode = Some(CredentialBindingMode::Saved);
    folder.credential_id = Some(parent_cred);
    let mut node = connection("web-1", ProtocolType::Ssh, "web-1.prod");
    node.parent_id = Some(folder.id);
    node.credential_mode = Some(CredentialBindingMode::Saved);
    node.credential_id = Some(child_cred);
    let map = nodes(&[folder, node.clone()]);
    let profile = InheritanceResolver::new().resolve(&node, &map).unwrap();
    assert_eq!(profile.credential_id, Some(child_cred));
}

#[test]
fn resolve_multiple_folder_credentials_closest_folder_credential_wins() {
    let root_cred = Uuid::new_v4();
    let closest_cred = Uuid::new_v4();
    let mut root = folder("all");
    root.credential_mode = Some(CredentialBindingMode::Saved);
    root.credential_id = Some(root_cred);
    root.username = Some("root-user".into());
    let mut closest = folder("prod");
    closest.parent_id = Some(root.id);
    closest.credential_mode = Some(CredentialBindingMode::Saved);
    closest.credential_id = Some(closest_cred);
    closest.username = Some("prod-user".into());
    let mut leaf = connection("web-1", ProtocolType::Ssh, "web-1.prod");
    leaf.parent_id = Some(closest.id);
    leaf.credential_mode = Some(CredentialBindingMode::Inherit);
    let map = nodes(&[root, closest, leaf.clone()]);
    let profile = InheritanceResolver::new().resolve(&leaf, &map).unwrap();
    assert_eq!(profile.credential_id, Some(closest_cred));
    assert_eq!(profile.username.as_deref(), Some("prod-user"));
}

#[test]
fn resolve_closest_saved_credential_without_identity_does_not_inherit_distant_identity() {
    let mut root = folder("all");
    root.credential_mode = Some(CredentialBindingMode::Saved);
    root.credential_id = Some(Uuid::new_v4());
    root.username = Some("root-user".into());
    root.rdp_domain = Some("ROOT".into());
    let mut closest = folder("prod");
    closest.parent_id = Some(root.id);
    closest.credential_mode = Some(CredentialBindingMode::Saved);
    closest.credential_id = Some(Uuid::new_v4());
    let closest_cred = closest.credential_id;
    let mut leaf = connection("vm", ProtocolType::Rdp, "vm.prod");
    leaf.parent_id = Some(closest.id);
    leaf.credential_mode = Some(CredentialBindingMode::Inherit);
    let map = nodes(&[root, closest, leaf.clone()]);
    let profile = InheritanceResolver::new().resolve(&leaf, &map).unwrap();
    assert_eq!(profile.credential_id, closest_cred);
    assert!(profile.username.is_none());
    assert!(profile.rdp_domain.is_none());
}

#[test]
fn resolve_legacy_closest_credential_without_identity_does_not_inherit_distant_username() {
    let mut root = folder("all");
    root.credential_mode = Some(CredentialBindingMode::Saved);
    root.credential_id = Some(Uuid::new_v4());
    root.username = Some("root-user".into());
    let mut closest = folder("imported-prod");
    closest.parent_id = Some(root.id);
    closest.credential_mode = None;
    closest.credential_id = Some(Uuid::new_v4());
    let closest_cred = closest.credential_id;
    let mut leaf = connection("web-1", ProtocolType::Ssh, "web-1.prod");
    leaf.parent_id = Some(closest.id);
    let map = nodes(&[root, closest, leaf.clone()]);
    let profile = InheritanceResolver::new().resolve(&leaf, &map).unwrap();
    assert_eq!(profile.credential_id, closest_cred);
    assert!(profile.username.is_none());
}

#[test]
fn resolve_leaf_username_overrides_closest_folder_credential_identity() {
    let mut root = folder("all");
    root.credential_mode = Some(CredentialBindingMode::Saved);
    root.credential_id = Some(Uuid::new_v4());
    root.username = Some("root-user".into());
    let mut closest = folder("prod");
    closest.parent_id = Some(root.id);
    closest.credential_mode = Some(CredentialBindingMode::Saved);
    closest.credential_id = Some(Uuid::new_v4());
    let closest_cred = closest.credential_id;
    let mut leaf = connection("web-1", ProtocolType::Ssh, "web-1.prod");
    leaf.parent_id = Some(closest.id);
    leaf.username = Some("leaf-user".into());
    leaf.credential_mode = Some(CredentialBindingMode::Inherit);
    let map = nodes(&[root, closest, leaf.clone()]);
    let profile = InheritanceResolver::new().resolve(&leaf, &map).unwrap();
    assert_eq!(profile.credential_id, closest_cred);
    assert_eq!(profile.username.as_deref(), Some("leaf-user"));
}

#[test]
fn resolve_credential_mode_none_still_inherits_username_for_prompt() {
    let mut folder = folder("prod");
    folder.credential_mode = Some(CredentialBindingMode::Saved);
    folder.credential_id = Some(Uuid::new_v4());
    folder.username = Some("deploy".into());
    let mut node = connection("web-1", ProtocolType::Ssh, "web-1.prod");
    node.parent_id = Some(folder.id);
    node.credential_mode = Some(CredentialBindingMode::None);
    let map = nodes(&[folder, node.clone()]);
    let profile = InheritanceResolver::new().resolve(&node, &map).unwrap();
    assert!(profile.credential_id.is_none());
    assert_eq!(profile.username.as_deref(), Some("deploy"));
}

#[test]
fn resolve_legacy_null_mode_with_credential_id_treats_node_as_saved_credential() {
    let child_cred = Uuid::new_v4();
    let mut folder = folder("prod");
    folder.credential_mode = Some(CredentialBindingMode::Saved);
    folder.credential_id = Some(Uuid::new_v4());
    let mut node = connection("web-1", ProtocolType::Ssh, "web-1.prod");
    node.parent_id = Some(folder.id);
    node.credential_mode = None;
    node.credential_id = Some(child_cred);
    let map = nodes(&[folder, node.clone()]);
    let profile = InheritanceResolver::new().resolve(&node, &map).unwrap();
    assert_eq!(profile.credential_id, Some(child_cred));
}

fn assert_inline_password_suppresses(protocol: ProtocolType) {
    let mut folder = folder("prod");
    folder.credential_mode = Some(CredentialBindingMode::Saved);
    folder.credential_id = Some(Uuid::new_v4());
    let mut node = connection("web-1", protocol, "web-1.prod");
    node.parent_id = Some(folder.id);
    node.use_inline_password = Some(true);
    let map = nodes(&[folder, node.clone()]);
    let profile = InheritanceResolver::new().resolve(&node, &map).unwrap();
    assert!(profile.use_inline_password);
    assert!(profile.credential_id.is_none());
}

#[test]
fn resolve_inline_password_on_child_suppresses_inherited_saved_credential_ssh() {
    assert_inline_password_suppresses(ProtocolType::Ssh);
}

#[test]
fn resolve_inline_password_on_child_suppresses_inherited_saved_credential_rdp() {
    assert_inline_password_suppresses(ProtocolType::Rdp);
}

#[test]
fn resolve_defaults_port_from_protocol_when_none_inherited() {
    let node = connection("rdp-target", ProtocolType::Rdp, "vm.example.com");
    let map = nodes(&[node.clone()]);
    let profile = InheritanceResolver::new().resolve(&node, &map).unwrap();
    assert_eq!(profile.port, 3389);
}

#[test]
fn resolve_defaults_port_from_protocol_http() {
    let node = connection("fw-gui", ProtocolType::Http, "fw.example.com");
    let map = nodes(&[node.clone()]);
    assert_eq!(
        InheritanceResolver::new().resolve(&node, &map).unwrap().port,
        80
    );
}

#[test]
fn resolve_defaults_port_from_protocol_https() {
    let node = connection("fw-gui", ProtocolType::Https, "fw.example.com");
    let map = nodes(&[node.clone()]);
    assert_eq!(
        InheritanceResolver::new().resolve(&node, &map).unwrap().port,
        443
    );
}

#[test]
fn resolve_defaults_port_from_protocol_vnc() {
    let node = connection("fw-gui", ProtocolType::Vnc, "fw.example.com");
    let map = nodes(&[node.clone()]);
    assert_eq!(
        InheritanceResolver::new().resolve(&node, &map).unwrap().port,
        5900
    );
}

#[test]
fn resolve_serial_defaults_to_putty_serial_settings() {
    let node = connection("console", ProtocolType::Serial, "COM3");
    let map = nodes(&[node.clone()]);
    let profile = InheritanceResolver::new().resolve(&node, &map).unwrap();
    assert_eq!(profile.protocol, ProtocolType::Serial);
    assert_eq!(profile.host, "COM3");
    assert_eq!(profile.port, 0);
    assert_eq!(profile.serial_baud_rate, SerialDefaults::BAUD_RATE);
    assert_eq!(profile.serial_data_bits, SerialDefaults::DATA_BITS);
    assert_eq!(profile.serial_stop_bits, SerialDefaults::STOP_BITS);
    assert_eq!(profile.serial_parity, SerialDefaults::PARITY);
    assert_eq!(profile.serial_flow_control, SerialDefaults::FLOW_CONTROL);
}

#[test]
fn resolve_serial_inherits_serial_settings_and_drops_credentials() {
    let credential_id = Uuid::new_v4();
    let mut folder = folder("serial-folder");
    folder.protocol = Some(ProtocolType::Serial);
    folder.tunnel_enabled = Some(true);
    folder.tunnel_config_id = Some(Uuid::new_v4());
    folder.serial_baud_rate = Some(115200);
    folder.serial_data_bits = Some(7);
    folder.serial_stop_bits = Some(SerialStopBitsMode::Two);
    folder.serial_parity = Some(SerialParityMode::Even);
    folder.serial_flow_control = Some(SerialFlowControlMode::RtsCts);
    folder.credential_id = Some(credential_id);
    folder.username = Some("ignored".into());
    folder.ssh_key_file_name = Some("key.pem".into());
    folder.ssh_known_host_fingerprint = Some("SHA256:ignored".into());
    folder.ssh_auto_sudo = Some(true);
    let node = ConnectionNode {
        id: Uuid::new_v4(),
        parent_id: Some(folder.id),
        name: "switch-console".into(),
        kind: NodeKind::Connection,
        host: Some("COM7".into()),
        ..Default::default()
    };
    let map = nodes(&[folder, node.clone()]);
    let profile = InheritanceResolver::new().resolve(&node, &map).unwrap();
    assert_eq!(profile.protocol, ProtocolType::Serial);
    assert_eq!(profile.serial_baud_rate, 115200);
    assert_eq!(profile.serial_data_bits, 7);
    assert_eq!(profile.serial_stop_bits, SerialStopBitsMode::Two);
    assert_eq!(profile.serial_parity, SerialParityMode::Even);
    assert_eq!(profile.serial_flow_control, SerialFlowControlMode::RtsCts);
    assert!(profile.username.is_none());
    assert!(profile.credential_id.is_none());
    assert!(profile.ssh_key_file_name.is_none());
    assert!(profile.ssh_known_host_fingerprint.is_none());
    assert!(!profile.ssh_auto_sudo);
    assert!(!profile.tunnel_enabled);
    assert!(profile.tunnel_config_id.is_none());
}

fn assert_web_does_not_inherit_rdp_port(protocol: ProtocolType, expected: i32) {
    let mut folder = folder("imported-rdp-folder");
    folder.protocol = Some(ProtocolType::Rdp);
    folder.port = Some(3389);
    let mut node = connection("wazuh-gui", protocol, "10.1.2.59");
    node.parent_id = Some(folder.id);
    let map = nodes(&[folder, node.clone()]);
    assert_eq!(
        InheritanceResolver::new().resolve(&node, &map).unwrap().port,
        expected
    );
}

#[test]
fn resolve_web_connection_does_not_inherit_ancestor_folder_port_http() {
    assert_web_does_not_inherit_rdp_port(ProtocolType::Http, 80);
}

#[test]
fn resolve_web_connection_does_not_inherit_ancestor_folder_port_https() {
    assert_web_does_not_inherit_rdp_port(ProtocolType::Https, 443);
}

#[test]
fn resolve_web_connection_honors_own_explicit_port() {
    let mut folder = folder("imported-rdp-folder");
    folder.protocol = Some(ProtocolType::Rdp);
    folder.port = Some(3389);
    let mut node = connection("appliance-gui", ProtocolType::Https, "10.1.2.59");
    node.parent_id = Some(folder.id);
    node.port = Some(8443);
    let map = nodes(&[folder, node.clone()]);
    assert_eq!(
        InheritanceResolver::new().resolve(&node, &map).unwrap().port,
        8443
    );
}

#[test]
fn resolve_does_not_inherit_port_configured_for_a_different_protocol() {
    let cases = [
        (ProtocolType::Ssh, ProtocolType::Rdp, 3389, 22),
        (ProtocolType::Rdp, ProtocolType::Ssh, 22, 3389),
        (ProtocolType::Vnc, ProtocolType::Rdp, 3389, 5900),
        (ProtocolType::Vnc, ProtocolType::Ssh, 22, 5900),
    ];
    for (leaf_protocol, folder_protocol, folder_port, expected) in cases {
        let mut folder = folder("imported-folder");
        folder.protocol = Some(folder_protocol);
        folder.port = Some(folder_port);
        let mut node = connection("host", leaf_protocol, "10.1.2.59");
        node.parent_id = Some(folder.id);
        let map = nodes(&[folder, node.clone()]);
        assert_eq!(
            InheritanceResolver::new().resolve(&node, &map).unwrap().port,
            expected,
            "{leaf_protocol:?} in {folder_protocol:?} folder"
        );
    }
}

#[test]
fn resolve_does_not_inherit_port_when_port_owner_inherits_a_different_protocol() {
    let mut root = folder("rdp-root");
    root.protocol = Some(ProtocolType::Rdp);
    let mut mid = folder("pins-port-inherits-protocol");
    mid.parent_id = Some(root.id);
    mid.port = Some(3389);
    let mut leaf = connection("ssh-host", ProtocolType::Ssh, "10.1.2.59");
    leaf.parent_id = Some(mid.id);
    let map = nodes(&[root, mid, leaf.clone()]);
    assert_eq!(
        InheritanceResolver::new().resolve(&leaf, &map).unwrap().port,
        22
    );
}

#[test]
fn resolve_inherits_custom_port_from_same_protocol_folder() {
    let mut folder = folder("rdp-farm");
    folder.protocol = Some(ProtocolType::Rdp);
    folder.port = Some(3390);
    let mut node = connection("vm", ProtocolType::Rdp, "vm.example.com");
    node.parent_id = Some(folder.id);
    let map = nodes(&[folder, node.clone()]);
    assert_eq!(
        InheritanceResolver::new().resolve(&node, &map).unwrap().port,
        3390
    );
}

#[test]
fn resolve_inherits_port_when_protocol_is_also_inherited() {
    let mut folder = folder("https-appliances");
    folder.protocol = Some(ProtocolType::Https);
    folder.port = Some(8443);
    let node = ConnectionNode {
        id: Uuid::new_v4(),
        parent_id: Some(folder.id),
        name: "fw".into(),
        kind: NodeKind::Connection,
        host: Some("fw.example.com".into()),
        ..Default::default()
    };
    let map = nodes(&[folder, node.clone()]);
    let profile = InheritanceResolver::new().resolve(&node, &map).unwrap();
    assert_eq!(profile.protocol, ProtocolType::Https);
    assert_eq!(profile.port, 8443);
}

#[test]
fn resolve_http_ignore_cert_errors_defaults_false_when_unset() {
    let node = connection("fw-gui", ProtocolType::Https, "fw.example.com");
    let map = nodes(&[node.clone()]);
    assert!(
        !InheritanceResolver::new()
            .resolve(&node, &map)
            .unwrap()
            .http_ignore_cert_errors
    );
}

#[test]
fn resolve_http_ignore_cert_errors_is_leaf_only_not_inherited_from_parent_folder() {
    let mut folder = folder("appliances");
    folder.http_ignore_cert_errors = Some(true);
    let mut node = connection("fw-gui", ProtocolType::Https, "fw.example.com");
    node.parent_id = Some(folder.id);
    let map = nodes(&[folder, node.clone()]);
    assert!(
        !InheritanceResolver::new()
            .resolve(&node, &map)
            .unwrap()
            .http_ignore_cert_errors
    );
}

#[test]
fn resolve_http_ignore_cert_errors_uses_own_leaf_value() {
    let mut node = connection("fw-gui", ProtocolType::Https, "fw.example.com");
    node.http_ignore_cert_errors = Some(true);
    let map = nodes(&[node.clone()]);
    assert!(
        InheritanceResolver::new()
            .resolve(&node, &map)
            .unwrap()
            .http_ignore_cert_errors
    );
}

fn assert_web_drops_inherited_auth(web_protocol: ProtocolType) {
    let mut folder = folder("appliances");
    folder.credential_id = Some(Uuid::new_v4());
    folder.credential_mode = Some(CredentialBindingMode::Saved);
    folder.username = Some("admin".into());
    folder.ssh_key_file_name = Some("shared-admin-key".into());
    folder.ssh_known_host_fingerprint = Some("SHA256:inherited-pin".into());
    folder.ssh_auto_sudo = Some(true);
    let mut node = connection("fw-gui", web_protocol, "fw.example.com");
    node.parent_id = Some(folder.id);
    let map = nodes(&[folder, node.clone()]);
    let profile = InheritanceResolver::new().resolve(&node, &map).unwrap();
    assert!(profile.credential_id.is_none());
    assert!(profile.username.is_none());
    assert!(profile.ssh_key_file_name.is_none());
    assert!(profile.ssh_known_host_fingerprint.is_none());
    assert!(!profile.ssh_auto_sudo);
    assert!(!profile.use_inline_password);
}

#[test]
fn resolve_web_protocol_drops_inherited_auth_material_http() {
    assert_web_drops_inherited_auth(ProtocolType::Http);
}

#[test]
fn resolve_web_protocol_drops_inherited_auth_material_https() {
    assert_web_drops_inherited_auth(ProtocolType::Https);
}

#[test]
fn resolve_vnc_connection_inherits_password_credential_but_drops_auth_identity_material() {
    let credential_id = Uuid::new_v4();
    let mut folder = folder("kvm");
    folder.credential_id = Some(credential_id);
    folder.credential_mode = Some(CredentialBindingMode::Saved);
    folder.username = Some("admin".into());
    folder.ssh_key_file_name = Some("shared-admin-key".into());
    folder.ssh_known_host_fingerprint = Some("SHA256:inherited-pin".into());
    let mut node = connection("console", ProtocolType::Vnc, "kvm.example.com");
    node.parent_id = Some(folder.id);
    node.use_inline_password = Some(true);
    let map = nodes(&[folder, node.clone()]);
    let profile = InheritanceResolver::new().resolve(&node, &map).unwrap();
    assert_eq!(profile.credential_id, Some(credential_id));
    assert!(profile.username.is_none());
    assert!(profile.ssh_key_file_name.is_none());
    assert!(profile.ssh_known_host_fingerprint.is_none());
    assert!(!profile.use_inline_password);
}

#[test]
fn resolve_vnc_connection_drops_credential_inherited_from_non_vnc_protocol() {
    let mut folder = folder("ssh-folder");
    folder.protocol = Some(ProtocolType::Ssh);
    folder.credential_mode = Some(CredentialBindingMode::Saved);
    folder.credential_id = Some(Uuid::new_v4());
    let mut node = connection("console", ProtocolType::Vnc, "kvm.example.com");
    node.parent_id = Some(folder.id);
    let map = nodes(&[folder, node.clone()]);
    let profile = InheritanceResolver::new().resolve(&node, &map).unwrap();
    assert!(profile.credential_id.is_none());
    assert!(profile.username.is_none());
}

#[test]
fn resolve_vnc_connection_drops_untyped_credential_governed_by_ancestor_ssh_protocol() {
    let mut root = folder("ssh-root");
    root.protocol = Some(ProtocolType::Ssh);
    let mut credential_folder = folder("shared-credentials");
    credential_folder.parent_id = Some(root.id);
    credential_folder.credential_mode = Some(CredentialBindingMode::Saved);
    credential_folder.credential_id = Some(Uuid::new_v4());
    let mut node = connection("console", ProtocolType::Vnc, "kvm.example.com");
    node.parent_id = Some(credential_folder.id);
    let map = nodes(&[root, credential_folder, node.clone()]);
    let profile = InheritanceResolver::new().resolve(&node, &map).unwrap();
    assert!(profile.credential_id.is_none());
    assert!(profile.username.is_none());
}

#[test]
fn resolve_non_vnc_connection_drops_credential_inherited_from_vnc_protocol() {
    for protocol in [ProtocolType::Ssh, ProtocolType::Rdp] {
        let mut folder = folder("vnc-folder");
        folder.protocol = Some(ProtocolType::Vnc);
        folder.credential_mode = Some(CredentialBindingMode::Saved);
        folder.credential_id = Some(Uuid::new_v4());
        let mut node = connection("server", protocol, "server.example.com");
        node.parent_id = Some(folder.id);
        let map = nodes(&[folder, node.clone()]);
        assert!(
            InheritanceResolver::new()
                .resolve(&node, &map)
                .unwrap()
                .credential_id
                .is_none()
        );
    }
}

fn assert_web_drops_own_auth(web_protocol: ProtocolType) {
    let mut node = connection("fw-gui", web_protocol, "fw.example.com");
    node.credential_id = Some(Uuid::new_v4());
    node.credential_mode = Some(CredentialBindingMode::Saved);
    node.username = Some("admin".into());
    node.use_inline_password = Some(true);
    node.ssh_key_file_name = Some("stale-admin-key".into());
    node.ssh_known_host_fingerprint = Some("SHA256:stale-pin".into());
    node.ssh_auto_sudo = Some(true);
    let map = nodes(&[node.clone()]);
    let profile = InheritanceResolver::new().resolve(&node, &map).unwrap();
    assert!(profile.credential_id.is_none());
    assert!(profile.username.is_none());
    assert!(profile.ssh_key_file_name.is_none());
    assert!(profile.ssh_known_host_fingerprint.is_none());
    assert!(!profile.ssh_auto_sudo);
    assert!(!profile.use_inline_password);
}

#[test]
fn resolve_web_protocol_drops_own_auth_material_http() {
    assert_web_drops_own_auth(ProtocolType::Http);
}

#[test]
fn resolve_web_protocol_drops_own_auth_material_https() {
    assert_web_drops_own_auth(ProtocolType::Https);
}

#[test]
fn resolve_throws_when_protocol_missing() {
    let node = ConnectionNode {
        id: Uuid::new_v4(),
        name: "broken".into(),
        kind: NodeKind::Connection,
        host: Some("host".into()),
        ..Default::default()
    };
    let map = nodes(&[node.clone()]);
    assert!(matches!(
        InheritanceResolver::new().resolve(&node, &map),
        Err(ResolveError::MissingProtocol { .. })
    ));
}

#[test]
fn resolve_throws_when_host_missing() {
    let node = ConnectionNode {
        id: Uuid::new_v4(),
        name: "broken".into(),
        kind: NodeKind::Connection,
        protocol: Some(ProtocolType::Ssh),
        ..Default::default()
    };
    let map = nodes(&[node.clone()]);
    assert!(matches!(
        InheritanceResolver::new().resolve(&node, &map),
        Err(ResolveError::MissingHost { .. })
    ));
}

#[test]
fn resolve_throws_on_cycle() {
    let mut a = folder("a");
    let mut b = folder("b");
    b.parent_id = Some(a.id);
    a.parent_id = Some(b.id);
    let mut leaf = connection("leaf", ProtocolType::Ssh, "host");
    leaf.parent_id = Some(a.id);
    let map = nodes(&[a, b, leaf.clone()]);
    assert!(matches!(
        InheritanceResolver::new().resolve(&leaf, &map),
        Err(ResolveError::Cycle { .. })
    ));
}

#[test]
fn resolve_throws_when_node_is_a_folder() {
    let folder = folder("folder");
    let map = nodes(&[folder.clone()]);
    assert!(matches!(
        InheritanceResolver::new().resolve(&folder, &map),
        Err(ResolveError::NotAConnection { .. })
    ));
}

#[test]
fn resolve_rdp_color_depth_inherits_from_parent_folder() {
    let mut folder = folder("rdp-folder");
    folder.protocol = Some(ProtocolType::Rdp);
    folder.rdp_color_depth = Some(24);
    let node = ConnectionNode {
        id: Uuid::new_v4(),
        parent_id: Some(folder.id),
        name: "vm".into(),
        kind: NodeKind::Connection,
        host: Some("vm.example.com".into()),
        ..Default::default()
    };
    let map = nodes(&[folder, node.clone()]);
    assert_eq!(
        InheritanceResolver::new()
            .resolve(&node, &map)
            .unwrap()
            .rdp_color_depth,
        24
    );
}

#[test]
fn resolve_rdp_defaults_applied_when_nothing_set_in_chain() {
    let node = connection("bare-rdp", ProtocolType::Rdp, "host");
    let map = nodes(&[node.clone()]);
    let profile = InheritanceResolver::new().resolve(&node, &map).unwrap();
    assert_eq!(profile.rdp_color_depth, 32);
    assert!(profile.rdp_redirect_clipboard);
    assert!(profile.rdp_auto_reconnect);
    assert_eq!(profile.rdp_connection_speed, 7);
    assert_eq!(profile.rdp_gateway_usage_method, 0);
    assert_eq!(profile.rdp_server_authentication, 2);
    assert_eq!(profile.rdp_keyboard_hook_mode, 2);
    assert!(profile.rdp_desktop_background);
    assert!(profile.rdp_visual_styles);
    assert!(profile.rdp_bitmap_caching);
    assert!(profile.rdp_gateway_bypass_local);
    assert_eq!(profile.rdp_redirect_drives, "");
    assert!(!profile.rdp_use_external_client);
}

#[test]
fn resolve_rdp_full_screen_true_overrides_inherited_fixed_screen_size() {
    let mut folder = folder("rdp-folder");
    folder.protocol = Some(ProtocolType::Rdp);
    folder.rdp_screen_size = Some("1024x768".into());
    let node = ConnectionNode {
        id: Uuid::new_v4(),
        parent_id: Some(folder.id),
        name: "vm".into(),
        kind: NodeKind::Connection,
        host: Some("vm.example.com".into()),
        rdp_full_screen: Some(true),
        ..Default::default()
    };
    let map = nodes(&[folder, node.clone()]);
    assert_eq!(
        InheritanceResolver::new()
            .resolve(&node, &map)
            .unwrap()
            .rdp_screen_size
            .as_deref(),
        Some(RdpScreenSizes::FULL_CONNECTION_CONTENT)
    );
}

#[test]
fn resolve_rdp_screen_size_overrides_same_node_legacy_full_screen_flag() {
    let mut node = connection("vm", ProtocolType::Rdp, "vm.example.com");
    node.rdp_screen_size = Some("1024x768".into());
    node.rdp_full_screen = Some(true);
    let map = nodes(&[node.clone()]);
    assert_eq!(
        InheritanceResolver::new()
            .resolve(&node, &map)
            .unwrap()
            .rdp_screen_size
            .as_deref(),
        Some("1024x768")
    );
}

#[test]
fn resolve_rdp_redirect_clipboard_false_on_child_overrides_parent_true() {
    let mut folder = folder("rdp-folder");
    folder.protocol = Some(ProtocolType::Rdp);
    folder.rdp_redirect_clipboard = Some(true);
    let node = ConnectionNode {
        id: Uuid::new_v4(),
        parent_id: Some(folder.id),
        name: "no-clipboard".into(),
        kind: NodeKind::Connection,
        host: Some("host".into()),
        rdp_redirect_clipboard: Some(false),
        ..Default::default()
    };
    let map = nodes(&[folder, node.clone()]);
    assert!(
        !InheritanceResolver::new()
            .resolve(&node, &map)
            .unwrap()
            .rdp_redirect_clipboard
    );
}

#[test]
fn resolve_rdp_gateway_credential_id_inherits_from_ancestor() {
    let cred_id = Uuid::new_v4();
    let mut folder = folder("behind-gw");
    folder.protocol = Some(ProtocolType::Rdp);
    folder.rdp_gateway_usage_method = Some(1);
    folder.rdp_gateway_hostname = Some("gw.example.com".into());
    folder.rdp_gateway_credential_id = Some(cred_id);
    let node = ConnectionNode {
        id: Uuid::new_v4(),
        parent_id: Some(folder.id),
        name: "behind-gw-vm".into(),
        kind: NodeKind::Connection,
        host: Some("vm".into()),
        ..Default::default()
    };
    let map = nodes(&[folder, node.clone()]);
    let profile = InheritanceResolver::new().resolve(&node, &map).unwrap();
    assert_eq!(profile.rdp_gateway_usage_method, 1);
    assert_eq!(profile.rdp_gateway_hostname.as_deref(), Some("gw.example.com"));
    assert_eq!(profile.rdp_gateway_credential_id, Some(cred_id));
}

#[test]
fn resolve_ssh_auto_sudo_defaults_false_when_unset() {
    let node = connection("plain-ssh", ProtocolType::Ssh, "host");
    let map = nodes(&[node.clone()]);
    assert!(
        !InheritanceResolver::new()
            .resolve(&node, &map)
            .unwrap()
            .ssh_auto_sudo
    );
}

#[test]
fn resolve_ssh_auto_sudo_inherits_from_parent_folder() {
    let mut folder = folder("elevated");
    folder.protocol = Some(ProtocolType::Ssh);
    folder.ssh_auto_sudo = Some(true);
    let node = ConnectionNode {
        id: Uuid::new_v4(),
        parent_id: Some(folder.id),
        name: "box".into(),
        kind: NodeKind::Connection,
        host: Some("box.example.com".into()),
        ..Default::default()
    };
    let map = nodes(&[folder, node.clone()]);
    assert!(
        InheritanceResolver::new()
            .resolve(&node, &map)
            .unwrap()
            .ssh_auto_sudo
    );
}

#[test]
fn resolve_ssh_auto_sudo_false_on_child_overrides_parent_true() {
    let mut folder = folder("elevated");
    folder.protocol = Some(ProtocolType::Ssh);
    folder.ssh_auto_sudo = Some(true);
    let node = ConnectionNode {
        id: Uuid::new_v4(),
        parent_id: Some(folder.id),
        name: "no-sudo".into(),
        kind: NodeKind::Connection,
        host: Some("host".into()),
        ssh_auto_sudo: Some(false),
        ..Default::default()
    };
    let map = nodes(&[folder, node.clone()]);
    assert!(
        !InheritanceResolver::new()
            .resolve(&node, &map)
            .unwrap()
            .ssh_auto_sudo
    );
}

#[test]
fn resolve_whitespace_only_host_is_missing_even_when_ancestor_has_host() {
    let mut folder = folder("prod");
    folder.host = Some("real.example".into());
    let mut node = connection("broken", ProtocolType::Ssh, "   ");
    node.parent_id = Some(folder.id);
    let map = nodes(&[folder, node.clone()]);
    assert!(matches!(
        InheritanceResolver::new().resolve(&node, &map),
        Err(ResolveError::MissingHost { .. })
    ));
}

#[test]
fn resolve_missing_parent_still_uses_leaf_fields() {
    let mut node = connection("orphan", ProtocolType::Ssh, "h.example");
    node.parent_id = Some(Uuid::new_v4());
    node.port = Some(2222);
    let map = nodes(&[node.clone()]);
    let profile = InheritanceResolver::new().resolve(&node, &map).unwrap();
    assert_eq!(profile.port, 2222);
    assert!(profile.parent_folder_name.is_none());
}

#[test]
fn resolve_empty_nodes_map_allows_self_contained_leaf() {
    let node = connection("solo", ProtocolType::Rdp, "vm.example");
    let profile = InheritanceResolver::new()
        .resolve(&node, &HashMap::new())
        .unwrap();
    assert_eq!(profile.port, 3389);
}

#[test]
fn resolve_throws_on_self_parent_cycle() {
    let id = Uuid::new_v4();
    let node = ConnectionNode {
        id,
        parent_id: Some(id),
        name: "self".into(),
        kind: NodeKind::Connection,
        protocol: Some(ProtocolType::Ssh),
        host: Some("host".into()),
        ..Default::default()
    };
    let map = nodes(&[node.clone()]);
    assert!(matches!(
        InheritanceResolver::new().resolve(&node, &map),
        Err(ResolveError::Cycle { .. })
    ));
}

#[test]
fn resolve_preserves_unicode_name_in_errors_and_profile() {
    let name = "сервер-🌐";
    let folder = folder("папка");
    let map = nodes(&[folder.clone()]);
    let err = InheritanceResolver::new()
        .resolve(&folder, &map)
        .unwrap_err()
        .to_string();
    assert!(err.contains("папка"), "{err}");

    let node = connection(name, ProtocolType::Ssh, "host");
    let map = nodes(&[node.clone()]);
    let profile = InheritanceResolver::new().resolve(&node, &map).unwrap();
    assert_eq!(profile.name, name);
}

#[test]
fn resolve_keeps_protocol_agnostic_inherited_port() {
    let mut folder = folder("shared-port");
    folder.port = Some(9999);
    let mut node = connection("host", ProtocolType::Ssh, "10.1.2.59");
    node.parent_id = Some(folder.id);
    let map = nodes(&[folder, node.clone()]);
    assert_eq!(
        InheritanceResolver::new().resolve(&node, &map).unwrap().port,
        9999
    );
}

#[test]
fn resolve_credential_mode_inherit_ignores_own_credential_id() {
    let distant = Uuid::new_v4();
    let own = Uuid::new_v4();
    let mut folder = folder("prod");
    folder.credential_mode = Some(CredentialBindingMode::Saved);
    folder.credential_id = Some(distant);
    let mut node = connection("web-1", ProtocolType::Ssh, "web-1.prod");
    node.parent_id = Some(folder.id);
    node.credential_mode = Some(CredentialBindingMode::Inherit);
    node.credential_id = Some(own);
    let map = nodes(&[folder, node.clone()]);
    assert_eq!(
        InheritanceResolver::new()
            .resolve(&node, &map)
            .unwrap()
            .credential_id,
        Some(distant)
    );
}

#[test]
fn resolve_saved_mode_with_null_credential_id_stops_parent_credential() {
    let parent_cred = Uuid::new_v4();
    let mut folder = folder("prod");
    folder.credential_mode = Some(CredentialBindingMode::Saved);
    folder.credential_id = Some(parent_cred);
    let mut node = connection("web-1", ProtocolType::Ssh, "web-1.prod");
    node.parent_id = Some(folder.id);
    node.credential_mode = Some(CredentialBindingMode::Saved);
    node.credential_id = None;
    let map = nodes(&[folder, node.clone()]);
    assert!(
        InheritanceResolver::new()
            .resolve(&node, &map)
            .unwrap()
            .credential_id
            .is_none()
    );
}
