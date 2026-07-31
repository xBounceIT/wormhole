//! Map a sufficiently-populated [`ConnectionNode`] into a [`ConnectionProfile`].

use wormhole_domain::{
    ConnectionNode, ConnectionProfile, NodeKind, ProtocolType, SerialDefaults,
};

use crate::error::{Result, SessionError};

/// Build a profile from a connection node that already carries concrete values
/// (post-inheritance, or an ephemeral editor node).
///
/// Folders and nodes missing `protocol` / `host` fail with [`SessionError::IncompleteNode`].
pub fn profile_from_node(node: &ConnectionNode) -> Result<ConnectionProfile> {
    if node.kind != NodeKind::Connection {
        return Err(SessionError::IncompleteNode);
    }
    let protocol = node.protocol.ok_or(SessionError::IncompleteNode)?;
    let host = node
        .host
        .as_ref()
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
        .ok_or(SessionError::IncompleteNode)?;

    let default_port = match protocol {
        ProtocolType::Ssh => 22,
        ProtocolType::Rdp => 3389,
        ProtocolType::Http => 80,
        ProtocolType::Https => 443,
        ProtocolType::Serial => 0,
        ProtocolType::Vnc => 5900,
    };

    Ok(ConnectionProfile {
        node_id: node.id,
        name: node.name.clone(),
        parent_folder_name: None,
        protocol,
        host,
        port: node.port.unwrap_or(default_port),
        username: node.username.clone(),
        credential_id: node.credential_id,
        is_ephemeral: false,
        use_inline_password: node.use_inline_password.unwrap_or(false),
        rdp_domain: node.rdp_domain.clone(),
        rdp_screen_size: node.rdp_screen_size.clone(),
        rdp_full_screen: node.rdp_full_screen.unwrap_or(false),
        rdp_color_depth: node.rdp_color_depth.unwrap_or(32),
        rdp_use_all_monitors: node.rdp_use_all_monitors.unwrap_or(false),
        rdp_audio_mode: node.rdp_audio_mode.unwrap_or(0),
        rdp_audio_capture_mode: node.rdp_audio_capture_mode.unwrap_or(0),
        rdp_keyboard_hook_mode: node.rdp_keyboard_hook_mode.unwrap_or(2),
        rdp_redirect_clipboard: node.rdp_redirect_clipboard.unwrap_or(true),
        rdp_redirect_printers: node.rdp_redirect_printers.unwrap_or(false),
        rdp_redirect_smart_cards: node.rdp_redirect_smart_cards.unwrap_or(false),
        rdp_redirect_ports: node.rdp_redirect_ports.unwrap_or(false),
        rdp_redirect_devices: node.rdp_redirect_devices.unwrap_or(false),
        rdp_redirect_drives: node.rdp_redirect_drives.clone().unwrap_or_default(),
        rdp_connection_speed: node.rdp_connection_speed.unwrap_or(7),
        rdp_desktop_background: node.rdp_desktop_background.unwrap_or(true),
        rdp_font_smoothing: node.rdp_font_smoothing.unwrap_or(true),
        rdp_desktop_composition: node.rdp_desktop_composition.unwrap_or(true),
        rdp_window_drag: node.rdp_window_drag.unwrap_or(true),
        rdp_menu_animation: node.rdp_menu_animation.unwrap_or(true),
        rdp_visual_styles: node.rdp_visual_styles.unwrap_or(true),
        rdp_bitmap_caching: node.rdp_bitmap_caching.unwrap_or(true),
        rdp_auto_reconnect: node.rdp_auto_reconnect.unwrap_or(true),
        rdp_server_authentication: node.rdp_server_authentication.unwrap_or(2),
        rdp_gateway_usage_method: node.rdp_gateway_usage_method.unwrap_or(0),
        rdp_gateway_hostname: node.rdp_gateway_hostname.clone(),
        rdp_gateway_credential_id: node.rdp_gateway_credential_id,
        rdp_gateway_bypass_local: node.rdp_gateway_bypass_local.unwrap_or(true),
        rdp_gateway_use_same_creds: node.rdp_gateway_use_same_creds.unwrap_or(false),
        rdp_use_external_client: node.rdp_use_external_client.unwrap_or(false),
        ssh_key_file_name: node.ssh_key_file_name.clone(),
        ssh_known_host_fingerprint: node.ssh_known_host_fingerprint.clone(),
        ssh_auto_sudo: node.ssh_auto_sudo.unwrap_or(false),
        serial_baud_rate: node
            .serial_baud_rate
            .unwrap_or(SerialDefaults::BAUD_RATE),
        serial_data_bits: node
            .serial_data_bits
            .unwrap_or(SerialDefaults::DATA_BITS),
        serial_stop_bits: node
            .serial_stop_bits
            .unwrap_or(SerialDefaults::STOP_BITS),
        serial_parity: node.serial_parity.unwrap_or(SerialDefaults::PARITY),
        serial_flow_control: node
            .serial_flow_control
            .unwrap_or(SerialDefaults::FLOW_CONTROL),
        http_ignore_cert_errors: node.http_ignore_cert_errors.unwrap_or(false),
        // Resolved profile uses a concrete bool; inherit/`None` → false (off) here.
        tunnel_enabled: node.tunnel_enabled.unwrap_or(false),
        tunnel_config_id: node.tunnel_config_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    use wormhole_domain::NodeKind;

    #[test]
    fn maps_ssh_node() {
        let mut node = ConnectionNode::default();
        node.id = Uuid::new_v4();
        node.kind = NodeKind::Connection;
        node.name = "box".into();
        node.protocol = Some(ProtocolType::Ssh);
        node.host = Some("10.0.0.1".into());
        node.port = Some(2222);
        let p = profile_from_node(&node).unwrap();
        assert_eq!(p.host, "10.0.0.1");
        assert_eq!(p.port, 2222);
        assert_eq!(p.protocol, ProtocolType::Ssh);
    }

    #[test]
    fn rejects_folder() {
        let mut node = ConnectionNode::default();
        node.kind = NodeKind::Folder;
        node.protocol = Some(ProtocolType::Ssh);
        node.host = Some("x".into());
        assert!(matches!(
            profile_from_node(&node),
            Err(SessionError::IncompleteNode)
        ));
    }
}
