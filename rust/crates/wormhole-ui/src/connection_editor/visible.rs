//! Protocol-driven visibility for editor fields / tabs.

use wormhole_domain::ProtocolType;

use super::state::ConnectionEditorMode;

/// Which editor chrome sections are relevant for the current protocol/mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VisibleFields {
    pub is_ssh: bool,
    pub is_rdp: bool,
    pub is_vnc: bool,
    pub is_serial: bool,
    pub is_http: bool,
    pub is_https: bool,
    pub show_port_box: bool,
    pub show_credential_section: bool,
    pub show_tunnel_section: bool,
    pub show_inline_password: bool,
    pub show_connection_username: bool,
    pub show_rdp_domain: bool,
    pub show_rdp_tabs: bool,
    pub show_serial_settings: bool,
    pub show_http_ignore_cert: bool,
    pub show_ssh_auto_sudo: bool,
    pub host_header: &'static str,
    pub host_placeholder: &'static str,
}

impl VisibleFields {
    pub fn for_protocol(
        protocol: ProtocolType,
        mode: ConnectionEditorMode,
        use_saved_credentials: bool,
        // Distinct RDP domain override vs resolved credential domain — keep field visible.
        show_rdp_domain_override: bool,
        // Selected credential is an SSH key (hides auto-sudo).
        selected_credential_is_ssh_key: bool,
    ) -> Self {
        let is_ssh = protocol == ProtocolType::Ssh;
        let is_rdp = protocol == ProtocolType::Rdp;
        let is_vnc = protocol == ProtocolType::Vnc;
        let is_serial = protocol == ProtocolType::Serial;
        let is_http = matches!(protocol, ProtocolType::Http | ProtocolType::Https);
        let is_https = protocol == ProtocolType::Https;
        let is_quick = mode == ConnectionEditorMode::QuickConnect;

        let show_credential_section = is_ssh || is_rdp || is_vnc;
        let show_inline_password =
            (is_ssh || is_rdp || (is_quick && is_vnc)) && !use_saved_credentials;
        let show_connection_username = !use_saved_credentials && (is_ssh || is_rdp);
        let show_rdp_domain = is_rdp
            && (!use_saved_credentials || show_rdp_domain_override);
        let show_ssh_auto_sudo =
            is_ssh && (!use_saved_credentials || !selected_credential_is_ssh_key);

        Self {
            is_ssh,
            is_rdp,
            is_vnc,
            is_serial,
            is_http,
            is_https,
            show_port_box: !is_http && !is_serial,
            show_credential_section,
            show_tunnel_section: !is_serial,
            show_inline_password,
            show_connection_username,
            show_rdp_domain,
            show_rdp_tabs: is_rdp,
            show_serial_settings: is_serial,
            show_http_ignore_cert: is_https,
            show_ssh_auto_sudo,
            host_header: if is_serial {
                "Serial line"
            } else if is_http {
                "Address"
            } else {
                "Host"
            },
            host_placeholder: if is_serial {
                "COM1"
            } else if is_http {
                "10.0.0.1:8443"
            } else {
                "example.com"
            },
        }
    }
}
