use std::collections::{HashMap, HashSet};

use uuid::Uuid;

use crate::connection_node::ConnectionNode;
use crate::connection_profile::ConnectionProfile;
use crate::enums::{CredentialBindingMode, NodeKind, ProtocolType};
use crate::error::ResolveError;
use crate::rdp_screen_sizes::RdpScreenSizes;
use crate::serial::SerialDefaults;

/// Folder-level inheritance resolver (`Wormhole.Data.InheritanceResolver`).
#[derive(Debug, Default, Clone, Copy)]
pub struct InheritanceResolver;

impl InheritanceResolver {
    pub fn new() -> Self {
        Self
    }

    pub fn resolve(
        &self,
        node: &ConnectionNode,
        nodes_by_id: &HashMap<Uuid, ConnectionNode>,
    ) -> Result<ConnectionProfile, ResolveError> {
        if node.kind != NodeKind::Connection {
            return Err(ResolveError::NotAConnection {
                name: node.name.clone(),
                kind: node.kind,
            });
        }

        let mut protocol: Option<ProtocolType> = None;
        let mut host: Option<String> = None;
        let mut port: Option<i32> = None;
        let mut port_context_protocol: Option<ProtocolType> = None;
        let mut username: Option<String> = None;
        let mut credential_id: Option<Uuid> = None;
        let mut credential_context_protocol: Option<ProtocolType> = None;
        let mut credential_context_protocol_pending = false;
        let leaf_uses_inline_password = (node.use_inline_password.unwrap_or(false))
            && matches!(
                find_resolved_protocol(node, nodes_by_id)?,
                Some(ProtocolType::Ssh | ProtocolType::Rdp)
            );
        let mut credential_resolved = leaf_uses_inline_password;
        let mut credential_identity_boundary_reached = false;
        let mut rdp_domain: Option<String> = None;
        let mut rdp_screen_size: Option<String> = None;
        let mut rdp_full_screen: Option<bool> = None;
        let mut rdp_color_depth: Option<i32> = None;
        let mut rdp_use_all_monitors: Option<bool> = None;
        let mut rdp_audio_mode: Option<i32> = None;
        let mut rdp_audio_capture_mode: Option<i32> = None;
        let mut rdp_keyboard_hook_mode: Option<i32> = None;
        let mut rdp_redirect_clipboard: Option<bool> = None;
        let mut rdp_redirect_printers: Option<bool> = None;
        let mut rdp_redirect_smart_cards: Option<bool> = None;
        let mut rdp_redirect_ports: Option<bool> = None;
        let mut rdp_redirect_devices: Option<bool> = None;
        let mut rdp_redirect_drives: Option<String> = None;
        let mut rdp_connection_speed: Option<i32> = None;
        let mut rdp_desktop_background: Option<bool> = None;
        let mut rdp_font_smoothing: Option<bool> = None;
        let mut rdp_desktop_composition: Option<bool> = None;
        let mut rdp_window_drag: Option<bool> = None;
        let mut rdp_menu_animation: Option<bool> = None;
        let mut rdp_visual_styles: Option<bool> = None;
        let mut rdp_bitmap_caching: Option<bool> = None;
        let mut rdp_auto_reconnect: Option<bool> = None;
        let mut rdp_server_authentication: Option<i32> = None;
        let mut rdp_gateway_usage_method: Option<i32> = None;
        let mut rdp_gateway_hostname: Option<String> = None;
        let mut rdp_gateway_credential_id: Option<Uuid> = None;
        let mut rdp_gateway_bypass_local: Option<bool> = None;
        let mut rdp_gateway_use_same_creds: Option<bool> = None;
        let mut rdp_use_external_client: Option<bool> = None;
        let mut ssh_key_file_name: Option<String> = None;
        let mut ssh_known_host_fingerprint: Option<String> = None;
        let mut ssh_auto_sudo: Option<bool> = None;
        let mut serial_baud_rate: Option<i32> = None;
        let mut serial_data_bits: Option<i32> = None;
        let mut serial_stop_bits = None;
        let mut serial_parity = None;
        let mut serial_flow_control = None;
        let mut tunnel_enabled: Option<bool> = None;
        let mut tunnel_config_id: Option<Uuid> = None;

        let mut seen: Option<HashSet<Uuid>> = None;
        let mut current = node;

        loop {
            if let Some(ref mut seen_set) = seen {
                if !seen_set.insert(current.id) {
                    return Err(ResolveError::Cycle {
                        name: current.name.clone(),
                        id: current.id,
                    });
                }
            }

            protocol = protocol.or(current.protocol);
            host = host.or_else(|| current.host.clone());
            port = port.or(current.port);
            if port.is_some() {
                port_context_protocol = port_context_protocol.or(current.protocol);
            }
            if !credential_identity_boundary_reached {
                username = username.or_else(|| current.username.clone());
                rdp_domain = rdp_domain.or_else(|| current.rdp_domain.clone());
            }
            if !credential_resolved {
                let mut resolves_saved_credential = false;
                match current.credential_mode {
                    None => {
                        if let Some(legacy_credential_id) = current.credential_id {
                            credential_id = Some(legacy_credential_id);
                            credential_resolved = true;
                            resolves_saved_credential = true;
                        }
                    }
                    Some(CredentialBindingMode::Inherit) => {}
                    Some(mode) => {
                        credential_resolved = true;
                        credential_id = if mode == CredentialBindingMode::Saved {
                            current.credential_id
                        } else {
                            None
                        };
                        resolves_saved_credential =
                            mode == CredentialBindingMode::Saved && current.credential_id.is_some();
                    }
                }

                if resolves_saved_credential {
                    credential_context_protocol_pending = true;
                    credential_identity_boundary_reached = true;
                }
            }
            if credential_context_protocol_pending && credential_context_protocol.is_none() {
                credential_context_protocol = current.protocol;
            }

            rdp_screen_size = rdp_screen_size.or_else(|| {
                current.rdp_screen_size.clone().or_else(|| {
                    if current.rdp_full_screen == Some(true) {
                        Some(RdpScreenSizes::FULL_CONNECTION_CONTENT.to_string())
                    } else {
                        None
                    }
                })
            });
            rdp_full_screen = rdp_full_screen.or(current.rdp_full_screen);
            rdp_color_depth = rdp_color_depth.or(current.rdp_color_depth);
            rdp_use_all_monitors = rdp_use_all_monitors.or(current.rdp_use_all_monitors);
            rdp_audio_mode = rdp_audio_mode.or(current.rdp_audio_mode);
            rdp_audio_capture_mode = rdp_audio_capture_mode.or(current.rdp_audio_capture_mode);
            rdp_keyboard_hook_mode = rdp_keyboard_hook_mode.or(current.rdp_keyboard_hook_mode);
            rdp_redirect_clipboard = rdp_redirect_clipboard.or(current.rdp_redirect_clipboard);
            rdp_redirect_printers = rdp_redirect_printers.or(current.rdp_redirect_printers);
            rdp_redirect_smart_cards = rdp_redirect_smart_cards.or(current.rdp_redirect_smart_cards);
            rdp_redirect_ports = rdp_redirect_ports.or(current.rdp_redirect_ports);
            rdp_redirect_devices = rdp_redirect_devices.or(current.rdp_redirect_devices);
            rdp_redirect_drives =
                rdp_redirect_drives.or_else(|| current.rdp_redirect_drives.clone());
            rdp_connection_speed = rdp_connection_speed.or(current.rdp_connection_speed);
            rdp_desktop_background = rdp_desktop_background.or(current.rdp_desktop_background);
            rdp_font_smoothing = rdp_font_smoothing.or(current.rdp_font_smoothing);
            rdp_desktop_composition = rdp_desktop_composition.or(current.rdp_desktop_composition);
            rdp_window_drag = rdp_window_drag.or(current.rdp_window_drag);
            rdp_menu_animation = rdp_menu_animation.or(current.rdp_menu_animation);
            rdp_visual_styles = rdp_visual_styles.or(current.rdp_visual_styles);
            rdp_bitmap_caching = rdp_bitmap_caching.or(current.rdp_bitmap_caching);
            rdp_auto_reconnect = rdp_auto_reconnect.or(current.rdp_auto_reconnect);
            rdp_server_authentication =
                rdp_server_authentication.or(current.rdp_server_authentication);
            rdp_gateway_usage_method =
                rdp_gateway_usage_method.or(current.rdp_gateway_usage_method);
            rdp_gateway_hostname =
                rdp_gateway_hostname.or_else(|| current.rdp_gateway_hostname.clone());
            rdp_gateway_credential_id =
                rdp_gateway_credential_id.or(current.rdp_gateway_credential_id);
            rdp_gateway_bypass_local =
                rdp_gateway_bypass_local.or(current.rdp_gateway_bypass_local);
            rdp_gateway_use_same_creds =
                rdp_gateway_use_same_creds.or(current.rdp_gateway_use_same_creds);
            rdp_use_external_client = rdp_use_external_client.or(current.rdp_use_external_client);
            ssh_key_file_name = ssh_key_file_name.or_else(|| current.ssh_key_file_name.clone());
            ssh_known_host_fingerprint =
                ssh_known_host_fingerprint.or_else(|| current.ssh_known_host_fingerprint.clone());
            ssh_auto_sudo = ssh_auto_sudo.or(current.ssh_auto_sudo);
            serial_baud_rate = serial_baud_rate.or(current.serial_baud_rate);
            serial_data_bits = serial_data_bits.or(current.serial_data_bits);
            serial_stop_bits = serial_stop_bits.or(current.serial_stop_bits);
            serial_parity = serial_parity.or(current.serial_parity);
            serial_flow_control = serial_flow_control.or(current.serial_flow_control);
            tunnel_enabled = tunnel_enabled.or(current.tunnel_enabled);
            tunnel_config_id = tunnel_config_id.or(current.tunnel_config_id);

            let Some(parent_id) = current.parent_id else {
                break;
            };
            let Some(parent) = nodes_by_id.get(&parent_id) else {
                break;
            };
            if seen.is_none() {
                let mut set = HashSet::new();
                set.insert(current.id);
                seen = Some(set);
            }
            current = parent;
        }

        let protocol = protocol.ok_or_else(|| ResolveError::MissingProtocol {
            name: node.name.clone(),
        })?;
        let host = match host {
            Some(ref h) if !is_null_or_white_space(h) => h.clone(),
            _ => {
                return Err(ResolveError::MissingHost {
                    name: node.name.clone(),
                });
            }
        };

        let mut port = port;
        if let Some(port_context) = port_context_protocol {
            if port_context != protocol {
                port = None;
            }
        }

        let is_web = matches!(protocol, ProtocolType::Http | ProtocolType::Https);
        let is_serial = protocol == ProtocolType::Serial;
        let is_vnc = protocol == ProtocolType::Vnc;
        let is_credentialless = is_web || is_serial;
        let clears_ssh_identity = is_credentialless || is_vnc;
        let use_inline_password = leaf_uses_inline_password;
        let can_use_resolved_credential = !is_credentialless
            && !use_inline_password
            && (credential_context_protocol.is_none()
                || credential_context_protocol == Some(protocol));

        let parent_folder_name = node.parent_id.and_then(|parent_id| {
            nodes_by_id.get(&parent_id).and_then(|parent| {
                if parent.kind == NodeKind::Folder && !is_null_or_white_space(&parent.name) {
                    Some(parent.name.clone())
                } else {
                    None
                }
            })
        });

        Ok(ConnectionProfile {
            node_id: node.id,
            name: node.name.clone(),
            parent_folder_name,
            protocol,
            host,
            port: port.unwrap_or_else(|| default_port_for(protocol)),
            username: if clears_ssh_identity {
                None
            } else {
                username
            },
            credential_id: if can_use_resolved_credential {
                credential_id
            } else {
                None
            },
            is_ephemeral: false,
            use_inline_password,
            rdp_domain,
            rdp_screen_size,
            rdp_full_screen: rdp_full_screen.unwrap_or(false),
            rdp_color_depth: rdp_color_depth.unwrap_or(32),
            rdp_use_all_monitors: rdp_use_all_monitors.unwrap_or(false),
            rdp_audio_mode: rdp_audio_mode.unwrap_or(0),
            rdp_audio_capture_mode: rdp_audio_capture_mode.unwrap_or(0),
            rdp_keyboard_hook_mode: rdp_keyboard_hook_mode.unwrap_or(2),
            rdp_redirect_clipboard: rdp_redirect_clipboard.unwrap_or(true),
            rdp_redirect_printers: rdp_redirect_printers.unwrap_or(false),
            rdp_redirect_smart_cards: rdp_redirect_smart_cards.unwrap_or(false),
            rdp_redirect_ports: rdp_redirect_ports.unwrap_or(false),
            rdp_redirect_devices: rdp_redirect_devices.unwrap_or(false),
            rdp_redirect_drives: rdp_redirect_drives.unwrap_or_default(),
            rdp_connection_speed: rdp_connection_speed.unwrap_or(7),
            rdp_desktop_background: rdp_desktop_background.unwrap_or(true),
            rdp_font_smoothing: rdp_font_smoothing.unwrap_or(true),
            rdp_desktop_composition: rdp_desktop_composition.unwrap_or(true),
            rdp_window_drag: rdp_window_drag.unwrap_or(true),
            rdp_menu_animation: rdp_menu_animation.unwrap_or(true),
            rdp_visual_styles: rdp_visual_styles.unwrap_or(true),
            rdp_bitmap_caching: rdp_bitmap_caching.unwrap_or(true),
            rdp_auto_reconnect: rdp_auto_reconnect.unwrap_or(true),
            rdp_server_authentication: rdp_server_authentication.unwrap_or(2),
            rdp_gateway_usage_method: rdp_gateway_usage_method.unwrap_or(0),
            rdp_gateway_hostname,
            rdp_gateway_credential_id,
            rdp_gateway_bypass_local: rdp_gateway_bypass_local.unwrap_or(true),
            rdp_gateway_use_same_creds: rdp_gateway_use_same_creds.unwrap_or(false),
            rdp_use_external_client: rdp_use_external_client.unwrap_or(false),
            ssh_key_file_name: if clears_ssh_identity {
                None
            } else {
                ssh_key_file_name
            },
            ssh_known_host_fingerprint: if clears_ssh_identity {
                None
            } else {
                ssh_known_host_fingerprint
            },
            ssh_auto_sudo: if clears_ssh_identity {
                false
            } else {
                ssh_auto_sudo.unwrap_or(false)
            },
            serial_baud_rate: SerialDefaults::normalize_baud_rate(serial_baud_rate),
            serial_data_bits: SerialDefaults::normalize_data_bits(serial_data_bits),
            serial_stop_bits: SerialDefaults::normalize_stop_bits(serial_stop_bits),
            serial_parity: SerialDefaults::normalize_parity(serial_parity),
            serial_flow_control: SerialDefaults::normalize_flow_control(serial_flow_control),
            http_ignore_cert_errors: node.http_ignore_cert_errors.unwrap_or(false),
            tunnel_enabled: if protocol == ProtocolType::Serial {
                false
            } else {
                tunnel_enabled.unwrap_or(false)
            },
            tunnel_config_id: if protocol == ProtocolType::Serial {
                None
            } else {
                tunnel_config_id
            },
        })
    }
}

fn default_port_for(protocol: ProtocolType) -> i32 {
    match protocol {
        ProtocolType::Ssh => 22,
        ProtocolType::Rdp => 3389,
        ProtocolType::Http => 80,
        ProtocolType::Https => 443,
        ProtocolType::Vnc => 5900,
        ProtocolType::Serial => 0,
    }
}

fn find_resolved_protocol(
    node: &ConnectionNode,
    nodes_by_id: &HashMap<Uuid, ConnectionNode>,
) -> Result<Option<ProtocolType>, ResolveError> {
    let mut seen: Option<HashSet<Uuid>> = None;
    let mut current = node;
    loop {
        if let Some(protocol) = current.protocol {
            return Ok(Some(protocol));
        }
        let Some(parent_id) = current.parent_id else {
            return Ok(None);
        };
        let Some(parent) = nodes_by_id.get(&parent_id) else {
            return Ok(None);
        };
        if seen.is_none() {
            let mut set = HashSet::new();
            set.insert(current.id);
            seen = Some(set);
        }
        if let Some(ref mut seen_set) = seen {
            if !seen_set.insert(parent.id) {
                return Err(ResolveError::Cycle {
                    name: parent.name.clone(),
                    id: parent.id,
                });
            }
        }
        current = parent;
    }
}

fn is_null_or_white_space(s: &str) -> bool {
    s.trim().is_empty()
}
