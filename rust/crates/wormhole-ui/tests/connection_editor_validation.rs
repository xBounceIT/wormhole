//! Validation matrix + round-trip coverage for `ConnectionEditorState`.

use uuid::Uuid;
use wormhole_domain::{
    ConnectionNode, ConnectionProfile, CredentialBindingMode, NodeKind, ProtocolType,
    SerialDefaults, SerialStopBitsMode,
};
use wormhole_ui::{
    ConnectionEditorMode, ConnectionEditorState, CredentialUiMode, TunnelUiSelection,
    ValidationError,
};

fn base_valid(protocol: ProtocolType) -> ConnectionEditorState {
    let mut s = ConnectionEditorState::new(ConnectionEditorMode::Persistent);
    s.name = "n".into();
    s.protocol = protocol;
    s.host = match protocol {
        ProtocolType::Serial => "COM1".into(),
        ProtocolType::Http | ProtocolType::Https => "10.0.0.1".into(),
        _ => "h".into(),
    };
    s
}

#[test]
fn validation_matrix_ssh_rdp_vnc_require_name_host_and_port_range() {
    for protocol in [ProtocolType::Ssh, ProtocolType::Rdp, ProtocolType::Vnc] {
        let mut s = ConnectionEditorState::new(ConnectionEditorMode::Persistent);
        s.protocol = protocol;
        assert!(
            s.validate()
                .errors
                .contains(&ValidationError::NameRequired)
        );
        assert!(
            s.validate()
                .errors
                .contains(&ValidationError::HostRequired)
        );

        s.name = "n".into();
        s.host = "h".into();
        assert!(s.is_valid(), "{protocol:?} should be valid with name+host");

        s.port = Some(0);
        assert!(
            s.validate()
                .errors
                .contains(&ValidationError::PortOutOfRange),
            "{protocol:?}"
        );
        s.port = Some(65536);
        assert!(
            s.validate()
                .errors
                .contains(&ValidationError::PortOutOfRange)
        );
        s.port = None; // protocol default — allowed
        assert!(s.is_valid());
        s.port = Some(22);
        assert!(s.is_valid());
    }
}

#[test]
fn validation_matrix_http_rejects_malformed_address() {
    let mut s = base_valid(ProtocolType::Http);
    assert!(s.is_valid());

    s.host = ":8443".into();
    assert!(
        s.validate()
            .errors
            .contains(&ValidationError::HttpAddressInvalid)
    );

    s.host = "fw.local:8443".into();
    assert!(s.is_valid());

    let mut https = base_valid(ProtocolType::Https);
    https.host = "https://fw.local/login".into();
    assert!(https.is_valid());
    let vis = https.visible_fields();
    assert!(vis.show_http_ignore_cert);
    assert!(!vis.show_port_box);
    assert!(!vis.show_credential_section);

    // Out-of-range / zero port residues must not validate as hosts.
    for bad in ["10.0.0.1:0", "10.0.0.1:65536", "fw.local:99999"] {
        s.host = bad.into();
        assert!(
            s.validate()
                .errors
                .contains(&ValidationError::HttpAddressInvalid),
            "{bad}"
        );
    }

    // Vestigial Port box still validated (C# `IsValid` uses `!IsSerial` only).
    s.host = "10.0.0.1".into();
    s.port = Some(0);
    assert!(
        s.validate()
            .errors
            .contains(&ValidationError::PortOutOfRange)
    );
    s.port = None;
    assert!(s.is_valid());
}

#[test]
fn validation_matrix_serial_com_line_and_baud() {
    let mut s = base_valid(ProtocolType::Serial);
    let vis = s.visible_fields();
    assert!(vis.is_serial);
    assert!(!vis.show_port_box);
    assert!(!vis.show_credential_section);
    assert!(!vis.show_tunnel_section);
    assert_eq!(vis.host_header, "Serial line");
    // Network Port box is ignored — even 0 does not fail serial validity.
    s.port = Some(0);
    assert!(s.is_valid());

    s.host.clear();
    assert!(
        s.validate()
            .errors
            .contains(&ValidationError::HostRequired)
    );
    s.host = "COM4".into();

    s.serial_baud_rate_inherits = false;
    s.serial_baud_rate = 0;
    assert!(
        s.validate()
            .errors
            .contains(&ValidationError::SerialBaudInvalid)
    );
    s.serial_baud_rate = 115200;
    assert!(s.is_valid());

    s.serial_data_bits_inherits = false;
    s.serial_data_bits = 4;
    assert!(
        s.validate()
            .errors
            .contains(&ValidationError::SerialDataBitsInvalid)
    );
    s.serial_data_bits = 8;
    assert!(s.is_valid());

    // Win32 DCB: 1.5 stop bits illegal with 8 data bits — fail closed.
    s.serial_stop_bits = SerialStopBitsMode::OnePointFive;
    assert!(
        s.validate()
            .errors
            .contains(&ValidationError::SerialStopDataComboInvalid)
    );
    s.serial_data_bits = 5;
    assert!(s.is_valid());
    // 2 stop bits illegal with 5 data bits.
    s.serial_stop_bits = SerialStopBitsMode::Two;
    assert!(
        s.validate()
            .errors
            .contains(&ValidationError::SerialStopDataComboInvalid)
    );
    s.serial_stop_bits = SerialStopBitsMode::One;
    s.serial_data_bits = 8;
    assert!(s.is_valid());

    // All-inherit skips DCB (folder resolves later) — even if display is illegal.
    s.serial_baud_rate_inherits = true;
    s.serial_data_bits_inherits = true;
    s.serial_stop_bits_inherits = true;
    s.serial_parity_inherits = true;
    s.serial_flow_control_inherits = true;
    s.serial_data_bits = 8;
    s.serial_stop_bits = SerialStopBitsMode::OnePointFive;
    assert!(s.is_valid());
}

#[test]
fn validation_matrix_rdp_gateway_and_drives() {
    let mut s = base_valid(ProtocolType::Rdp);
    assert!(s.visible_fields().show_rdp_tabs);

    s.rdp_gateway_usage_method = 1;
    s.rdp_gateway_hostname.clear();
    assert!(
        s.validate()
            .errors
            .contains(&ValidationError::GatewayHostnameRequired)
    );
    s.rdp_gateway_hostname = "gw.example.com".into();
    assert!(s.is_valid());

    s.rdp_drive_redirect_mode = wormhole_ui::RdpDriveRedirectMode::Custom;
    s.rdp_custom_drive_list.clear();
    assert!(
        s.validate()
            .errors
            .contains(&ValidationError::CustomDriveListInvalid)
    );
    s.rdp_custom_drive_list = "C,D".into();
    assert!(s.is_valid());
}

#[test]
fn quick_connect_allows_blank_name() {
    let mut s = ConnectionEditorState::new(ConnectionEditorMode::QuickConnect);
    s.host = "h".into();
    assert!(s.is_valid());
    assert!(!s.supports_inheritance());
    assert_eq!(s.tunnel_selection(), TunnelUiSelection::NoTunnel);
}

#[test]
fn visible_fields_per_protocol() {
    let cases = [
        (
            ProtocolType::Ssh,
            true,  // creds
            true,  // tunnel
            true,  // port
            false, // rdp tabs
            false, // https cert
            "Host",
        ),
        (
            ProtocolType::Rdp,
            true,
            true,
            true,
            true,
            false,
            "Host",
        ),
        (
            ProtocolType::Vnc,
            true,
            true,
            true,
            false,
            false,
            "Host",
        ),
        (
            ProtocolType::Http,
            false,
            true, // tunnel applies to network web sessions
            false,
            false,
            false,
            "Address",
        ),
        (
            ProtocolType::Https,
            false,
            true,
            false,
            false,
            true,
            "Address",
        ),
        (
            ProtocolType::Serial,
            false,
            false,
            false,
            false,
            false,
            "Serial line",
        ),
    ];
    for (protocol, creds, tunnel, port, rdp, https_cert, header) in cases {
        let mut s = ConnectionEditorState::new(ConnectionEditorMode::Persistent);
        s.protocol = protocol;
        let v = s.visible_fields();
        assert_eq!(v.show_credential_section, creds, "{protocol:?}");
        assert_eq!(v.show_tunnel_section, tunnel, "{protocol:?}");
        assert_eq!(v.show_port_box, port, "{protocol:?}");
        assert_eq!(v.show_rdp_tabs, rdp, "{protocol:?}");
        assert_eq!(v.show_http_ignore_cert, https_cert, "{protocol:?}");
        assert_eq!(v.host_header, header, "{protocol:?}");
    }
}

#[test]
fn tunnel_tri_state_round_trip() {
    let mut s = ConnectionEditorState::new(ConnectionEditorMode::Persistent);
    s.name = "n".into();
    s.host = "h".into();

    s.set_tunnel_selection(TunnelUiSelection::Inherit);
    let (node, _) = s.to_connection_node();
    assert_eq!(node.tunnel_enabled, None);
    assert_eq!(node.tunnel_config_id, None);

    s.set_tunnel_selection(TunnelUiSelection::NoTunnel);
    let (node, _) = s.to_connection_node();
    assert_eq!(node.tunnel_enabled, Some(false));
    assert_eq!(node.tunnel_config_id, None);

    let id = Uuid::new_v4();
    s.set_tunnel_selection(TunnelUiSelection::Config(id));
    let (node, _) = s.to_connection_node();
    assert_eq!(node.tunnel_enabled, Some(true));
    assert_eq!(node.tunnel_config_id, Some(id));

    // Serial forces tunnel off.
    s.protocol = ProtocolType::Serial;
    s.host = "COM1".into();
    let (node, _) = s.to_connection_node();
    assert_eq!(node.tunnel_enabled, Some(false));
    assert_eq!(node.tunnel_config_id, None);
}

#[test]
fn credential_mode_saved_vs_inline() {
    let mut s = base_valid(ProtocolType::Ssh);
    let cred = Uuid::new_v4();
    s.credential_ui = CredentialUiMode::Saved;
    s.credential_mode = Some(CredentialBindingMode::Saved);
    s.credential_id = Some(cred);
    let (node, pending) = s.to_connection_node();
    assert_eq!(node.credential_mode, Some(CredentialBindingMode::Saved));
    assert_eq!(node.credential_id, Some(cred));
    assert_eq!(node.use_inline_password, Some(false));
    assert!(pending.is_none());

    s.set_use_saved_credentials(false);
    s.inline_password = "secret".into();
    let (node, pending) = s.to_connection_node();
    assert_eq!(node.credential_mode, Some(CredentialBindingMode::None));
    assert_eq!(node.credential_id, None);
    assert_eq!(node.use_inline_password, Some(true));
    assert_eq!(pending.as_deref(), Some("secret"));

    // VNC inline clears credential but does not set use_inline_password.
    s.protocol = ProtocolType::Vnc;
    let (node, pending) = s.to_connection_node();
    assert_eq!(node.use_inline_password, Some(false));
    assert!(pending.is_none());
}

#[test]
fn quick_connect_inherit_credential_collapses_to_none() {
    let mut s = ConnectionEditorState::new(ConnectionEditorMode::QuickConnect);
    s.host = "h".into();
    s.credential_ui = CredentialUiMode::Saved;
    s.credential_mode = Some(CredentialBindingMode::Inherit);
    s.credential_id = None;
    assert_eq!(
        s.effective_credential_mode(),
        CredentialBindingMode::None
    );
    let (node, _) = s.to_connection_node();
    assert_eq!(node.credential_mode, Some(CredentialBindingMode::None));
    assert_eq!(node.credential_id, None);
}

#[test]
fn load_from_then_to_connection_node_is_lossless_for_core_fields() {
    let cred = Uuid::new_v4();
    let source = ConnectionNode {
        id: Uuid::new_v4(),
        kind: NodeKind::Connection,
        name: "rdp-rich".into(),
        protocol: Some(ProtocolType::Rdp),
        host: Some("vm.example.com".into()),
        port: Some(3389),
        username: Some("alice".into()),
        credential_id: Some(cred),
        credential_mode: Some(CredentialBindingMode::Saved),
        rdp_domain: Some("CORP".into()),
        rdp_server_authentication: Some(2),
        rdp_gateway_usage_method: Some(1),
        rdp_gateway_hostname: Some("gw.example.com".into()),
        tunnel_enabled: Some(true),
        tunnel_config_id: Some(Uuid::new_v4()),
        ..ConnectionNode::default()
    };

    let mut s = ConnectionEditorState::new(ConnectionEditorMode::Persistent);
    s.load_from(&source, ConnectionEditorMode::Persistent);
    // Distinct domain under saved creds must stay visible for write-back.
    s.show_rdp_domain_override = true;
    let (sink, _) = s.to_connection_node();

    assert_eq!(sink.name, source.name);
    assert_eq!(sink.protocol, source.protocol);
    assert_eq!(sink.host, source.host);
    assert_eq!(sink.port, source.port);
    assert_eq!(sink.username, source.username);
    assert_eq!(sink.credential_id, source.credential_id);
    assert_eq!(sink.rdp_domain, source.rdp_domain);
    assert_eq!(sink.rdp_gateway_hostname, source.rdp_gateway_hostname);
    assert_eq!(sink.tunnel_enabled, source.tunnel_enabled);
    assert_eq!(sink.tunnel_config_id, source.tunnel_config_id);
}

#[test]
fn serial_write_clears_network_only_fields() {
    let mut s = base_valid(ProtocolType::Serial);
    s.serial_baud_rate_inherits = false;
    s.serial_baud_rate = 57600;
    s.username = "should-clear".into();
    s.set_tunnel_selection(TunnelUiSelection::Config(Uuid::new_v4()));
    let (node, _) = s.to_connection_node();
    assert_eq!(node.host.as_deref(), Some("COM1"));
    assert_eq!(node.port, None);
    assert_eq!(node.username, None);
    assert_eq!(node.credential_id, None);
    assert_eq!(node.serial_baud_rate, Some(57600));
    assert_eq!(node.tunnel_enabled, Some(false));
    assert_eq!(node.tunnel_config_id, None);
}

#[test]
fn apply_resolved_profile_seeds_quick_connect() {
    let mut profile = ConnectionProfile::default();
    profile.node_id = Uuid::new_v4();
    profile.name = "resolved".into();
    profile.protocol = ProtocolType::Ssh;
    profile.host = "prod.example".into();
    profile.port = 2222;
    profile.username = Some("ops".into());
    profile.tunnel_enabled = true;
    profile.tunnel_config_id = Some(Uuid::new_v4());
    profile.serial_baud_rate = SerialDefaults::BAUD_RATE;

    let mut s = ConnectionEditorState::new(ConnectionEditorMode::Persistent);
    s.apply_resolved_profile(&profile);
    assert!(s.is_quick_connect());
    assert_eq!(s.host, "prod.example");
    assert_eq!(s.port, Some(2222));
    assert_eq!(s.username, "ops");
    assert_eq!(s.tunnel_selection(), TunnelUiSelection::Config(profile.tunnel_config_id.unwrap()));
    assert!(s.is_valid()); // Quick Connect: blank name ok
}

#[test]
fn inline_password_redacted_in_debug() {
    let mut s = base_valid(ProtocolType::Ssh);
    s.set_use_saved_credentials(false);
    s.inline_password = "super-secret-password".into();
    let dbg = format!("{s:?}");
    assert!(
        !dbg.contains("super-secret-password"),
        "Debug must not leak inline password: {dbg}"
    );
    assert!(dbg.contains("[redacted]"));
}

#[test]
fn http_ipv6_port_fold_does_not_double_bracket() {
    let source = ConnectionNode {
        id: Uuid::new_v4(),
        kind: NodeKind::Connection,
        name: "https-v6".into(),
        protocol: Some(ProtocolType::Https),
        host: Some("[fd00::1]".into()),
        port: Some(8443),
        ..ConnectionNode::default()
    };
    let mut s = ConnectionEditorState::new(ConnectionEditorMode::Persistent);
    s.load_from(&source, ConnectionEditorMode::Persistent);
    assert_eq!(s.host, "[fd00::1]:8443");
    assert_eq!(s.port, None);
    let (node, _) = s.to_connection_node();
    assert_eq!(node.host.as_deref(), Some("fd00::1"));
    assert_eq!(node.port, Some(8443));

    // Bare IPv6 still gets a single bracket wrap.
    let bare = ConnectionNode {
        host: Some("fd00::2".into()),
        port: Some(8443),
        ..source
    };
    s.load_from(&bare, ConnectionEditorMode::Persistent);
    assert_eq!(s.host, "[fd00::2]:8443");
}

#[test]
fn tunnel_no_tunnel_write_clears_vestigial_config_id() {
    let mut s = base_valid(ProtocolType::Ssh);
    let id = Uuid::new_v4();
    // Hostile: enable=false with a leftover config id (should not persist).
    s.tunnel.enabled = Some(false);
    s.tunnel.config_id = Some(id);
    assert_eq!(s.tunnel_selection(), TunnelUiSelection::NoTunnel);
    let (node, _) = s.to_connection_node();
    assert_eq!(node.tunnel_enabled, Some(false));
    assert_eq!(node.tunnel_config_id, None);
}

#[test]
fn tunnel_inherit_null_is_not_false() {
    let mut s = base_valid(ProtocolType::Ssh);
    s.set_tunnel_selection(TunnelUiSelection::Inherit);
    assert_eq!(s.tunnel.enabled, None);
    let (node, _) = s.to_connection_node();
    assert_eq!(node.tunnel_enabled, None);
    assert_ne!(node.tunnel_enabled, Some(false));

    // Inherit-enable + override config id is a legitimate domain shape.
    let cfg = Uuid::new_v4();
    s.tunnel.enabled = None;
    s.tunnel.config_id = Some(cfg);
    assert_eq!(s.tunnel_selection(), TunnelUiSelection::Config(cfg));
    let (node, _) = s.to_connection_node();
    assert_eq!(node.tunnel_enabled, None);
    assert_eq!(node.tunnel_config_id, Some(cfg));
}

#[test]
fn serial_inherit_checkboxes_write_none_not_defaults() {
    let mut s = base_valid(ProtocolType::Serial);
    s.serial_baud_rate_inherits = true;
    s.serial_data_bits_inherits = true;
    s.serial_stop_bits_inherits = true;
    s.serial_parity_inherits = true;
    s.serial_flow_control_inherits = true;
    // Concrete UI values must not overwrite inheritance when checkboxes say inherit.
    s.serial_baud_rate = 9600;
    s.serial_data_bits = 7;
    let (node, _) = s.to_connection_node();
    assert_eq!(node.serial_baud_rate, None);
    assert_eq!(node.serial_data_bits, None);
    assert_eq!(node.serial_stop_bits, None);
    assert_eq!(node.serial_parity, None);
    assert_eq!(node.serial_flow_control, None);
}
