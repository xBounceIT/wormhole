use uuid::Uuid;

use crate::enums::{
    CredentialBindingMode, NodeKind, ProtocolType, SerialFlowControlMode, SerialParityMode,
    SerialStopBitsMode,
};

/// Tree node / connection row (`Wormhole.Models.ConnectionNode`).
///
/// Field names are snake_case Rust mirrors of the C# PascalCase properties (see
/// `docs/migration/02-domain.md`). GUIDs use format D when stringified.
#[derive(Debug, Clone)]
pub struct ConnectionNode {
    pub id: Uuid,
    pub parent_id: Option<Uuid>,
    pub name: String,
    pub kind: NodeKind,
    pub sort_order: i32,

    pub protocol: Option<ProtocolType>,
    pub host: Option<String>,
    pub port: Option<i32>,
    pub username: Option<String>,
    pub credential_id: Option<Uuid>,
    pub credential_mode: Option<CredentialBindingMode>,
    pub use_inline_password: Option<bool>,

    pub rdp_domain: Option<String>,
    pub rdp_screen_size: Option<String>,
    pub rdp_full_screen: Option<bool>,
    pub rdp_color_depth: Option<i32>,
    pub rdp_use_all_monitors: Option<bool>,
    pub rdp_audio_mode: Option<i32>,
    pub rdp_audio_capture_mode: Option<i32>,
    pub rdp_keyboard_hook_mode: Option<i32>,
    pub rdp_redirect_clipboard: Option<bool>,
    pub rdp_redirect_printers: Option<bool>,
    pub rdp_redirect_smart_cards: Option<bool>,
    pub rdp_redirect_ports: Option<bool>,
    pub rdp_redirect_devices: Option<bool>,
    pub rdp_redirect_drives: Option<String>,
    pub rdp_connection_speed: Option<i32>,
    pub rdp_desktop_background: Option<bool>,
    pub rdp_font_smoothing: Option<bool>,
    pub rdp_desktop_composition: Option<bool>,
    pub rdp_window_drag: Option<bool>,
    pub rdp_menu_animation: Option<bool>,
    pub rdp_visual_styles: Option<bool>,
    pub rdp_bitmap_caching: Option<bool>,
    pub rdp_auto_reconnect: Option<bool>,
    pub rdp_server_authentication: Option<i32>,
    pub rdp_gateway_usage_method: Option<i32>,
    pub rdp_gateway_hostname: Option<String>,
    pub rdp_gateway_credential_id: Option<Uuid>,
    pub rdp_gateway_bypass_local: Option<bool>,
    pub rdp_gateway_use_same_creds: Option<bool>,
    pub rdp_use_external_client: Option<bool>,

    pub ssh_key_file_name: Option<String>,
    pub ssh_known_host_fingerprint: Option<String>,
    pub ssh_auto_sudo: Option<bool>,

    pub serial_baud_rate: Option<i32>,
    pub serial_data_bits: Option<i32>,
    pub serial_stop_bits: Option<SerialStopBitsMode>,
    pub serial_parity: Option<SerialParityMode>,
    pub serial_flow_control: Option<SerialFlowControlMode>,

    pub http_ignore_cert_errors: Option<bool>,

    /// Tri-state: `None` = inherit, `Some(false)` = override off, `Some(true)` = on.
    pub tunnel_enabled: Option<bool>,
    pub tunnel_config_id: Option<Uuid>,
}

impl Default for ConnectionNode {
    fn default() -> Self {
        Self {
            id: Uuid::nil(),
            parent_id: None,
            name: String::new(),
            kind: NodeKind::Folder,
            sort_order: 0,
            protocol: None,
            host: None,
            port: None,
            username: None,
            credential_id: None,
            credential_mode: None,
            use_inline_password: None,
            rdp_domain: None,
            rdp_screen_size: None,
            rdp_full_screen: None,
            rdp_color_depth: None,
            rdp_use_all_monitors: None,
            rdp_audio_mode: None,
            rdp_audio_capture_mode: None,
            rdp_keyboard_hook_mode: None,
            rdp_redirect_clipboard: None,
            rdp_redirect_printers: None,
            rdp_redirect_smart_cards: None,
            rdp_redirect_ports: None,
            rdp_redirect_devices: None,
            rdp_redirect_drives: None,
            rdp_connection_speed: None,
            rdp_desktop_background: None,
            rdp_font_smoothing: None,
            rdp_desktop_composition: None,
            rdp_window_drag: None,
            rdp_menu_animation: None,
            rdp_visual_styles: None,
            rdp_bitmap_caching: None,
            rdp_auto_reconnect: None,
            rdp_server_authentication: None,
            rdp_gateway_usage_method: None,
            rdp_gateway_hostname: None,
            rdp_gateway_credential_id: None,
            rdp_gateway_bypass_local: None,
            rdp_gateway_use_same_creds: None,
            rdp_use_external_client: None,
            ssh_key_file_name: None,
            ssh_known_host_fingerprint: None,
            ssh_auto_sudo: None,
            serial_baud_rate: None,
            serial_data_bits: None,
            serial_stop_bits: None,
            serial_parity: None,
            serial_flow_control: None,
            http_ignore_cert_errors: None,
            tunnel_enabled: None,
            tunnel_config_id: None,
        }
    }
}

impl ConnectionNode {
    /// Full field copy with a fresh [`Id`] and no per-host / identity-scoped state.
    ///
    /// Mirrors C# `ConnectionNode.CloneAsNewIdentity` (tree Duplicate). Placement
    /// (`Name`, `ParentId`, `SortOrder`) stays with the caller.
    ///
    /// Resets:
    /// - `ssh_known_host_fingerprint` — host-scoped TOFU pin must not follow a new identity
    /// - `use_inline_password` → `Some(false)` — CredMgr secrets are keyed by node Id; a
    ///   fresh Id has no stored secret (never copies password bodies into SQLite)
    ///
    /// Keeps shared-pool references (`credential_id`, `rdp_gateway_credential_id`,
    /// `tunnel_config_id`) by design — those are not secret material.
    pub fn clone_as_new_identity(&self) -> Self {
        let mut copy = self.clone();
        copy.id = Uuid::new_v4();
        copy.ssh_known_host_fingerprint = None;
        copy.use_inline_password = Some(false);
        copy
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProtocolType;

    #[test]
    fn clone_as_new_identity_resets_host_scoped_fields() {
        let cred = Uuid::new_v4();
        let tunnel = Uuid::new_v4();
        let source = ConnectionNode {
            id: Uuid::new_v4(),
            parent_id: Some(Uuid::new_v4()),
            name: "prod".into(),
            kind: NodeKind::Connection,
            sort_order: 3,
            protocol: Some(ProtocolType::Ssh),
            host: Some("h.example".into()),
            credential_id: Some(cred),
            use_inline_password: Some(true),
            ssh_known_host_fingerprint: Some("pinned".into()),
            tunnel_config_id: Some(tunnel),
            rdp_gateway_credential_id: Some(cred),
            ..Default::default()
        };
        let copy = source.clone_as_new_identity();
        assert_ne!(copy.id, source.id);
        assert_eq!(copy.parent_id, source.parent_id);
        assert_eq!(copy.name, source.name);
        assert_eq!(copy.sort_order, source.sort_order);
        assert_eq!(copy.host.as_deref(), Some("h.example"));
        assert_eq!(copy.credential_id, Some(cred));
        assert_eq!(copy.rdp_gateway_credential_id, Some(cred));
        assert_eq!(copy.tunnel_config_id, Some(tunnel));
        assert!(copy.ssh_known_host_fingerprint.is_none());
        assert_eq!(copy.use_inline_password, Some(false));
    }
}
