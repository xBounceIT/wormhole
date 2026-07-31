//! `ConnectionEditorState` — LoadFrom / WriteTo / apply_resolved_profile.

use std::fmt;

use uuid::Uuid;
use wormhole_domain::{
    ConnectionNode, ConnectionProfile, CredentialBindingMode, NodeKind, ProtocolType,
    RdpScreenSizes, SerialDefaults, SerialFlowControlMode, SerialParityMode, SerialStopBitsMode,
};

use super::http_address::parse_http_address;
use super::rdp_drives::{self, ALL_SENTINEL};
use super::tunnel::{TunnelUiSelection, TunnelUiState};
use super::visible::VisibleFields;

const REDACTED: &str = "[redacted]";

/// Fold a non-default HTTP(S) port into the address field for the editor chrome.
///
/// Bare IPv6 literals are bracketed so `host:port` round-trips through [`parse_http_address`].
/// Hosts that are already bracketed (`[fd00::1]`) must not be wrapped again.
fn fold_http_address_port(host: &str, port: i32) -> String {
    let host = host.trim();
    if host.starts_with('[') {
        // Already bracketed (with or without a trailing :port from a prior fold).
        format!("{host}:{port}")
    } else if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn http_default_port(protocol: ProtocolType) -> i32 {
    if protocol == ProtocolType::Https {
        443
    } else {
        80
    }
}

/// Persistent tree edit vs ephemeral Quick Connect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectionEditorMode {
    Persistent,
    QuickConnect,
}

/// Credential chrome: saved-picker vs inline/prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CredentialUiMode {
    /// Saved-credential picker shown (`UseSavedCredentials = true`).
    Saved,
    /// Inline / connect-time prompt (`UseSavedCredentials = false`).
    Inline,
}

/// Tri-state Auto sudo (string radio in C#).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SshAutoSudoMode {
    Inherit,
    On,
    Off,
}

/// Drive redirect radio in the Local Resources tab.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RdpDriveRedirectMode {
    None,
    All,
    Custom,
}

/// Options for [`ConnectionEditorState::to_connection_node`] / `write_to`.
#[derive(Debug, Clone, Copy)]
pub struct WriteOptions {
    /// When false, omit pending inline password (Quick Connect accept path).
    pub include_pending_inline_password: bool,
}

impl Default for WriteOptions {
    fn default() -> Self {
        Self {
            include_pending_inline_password: true,
        }
    }
}

/// Pure dialog state for the multi-tab connection editor.
///
/// `Debug` redacts [`Self::inline_password`] — never log the plaintext.
#[derive(Clone)]
pub struct ConnectionEditorState {
    pub mode: ConnectionEditorMode,
    pub editing_node_id: Uuid,
    pub parent_id: Option<Uuid>,
    pub sort_order: i32,

    pub name: String,
    pub protocol: ProtocolType,
    pub host: String,
    /// Network port; `None` = protocol default / inherit. Ignored for HTTP/Serial.
    pub port: Option<i32>,
    pub username: String,
    pub rdp_domain: String,

    pub credential_ui: CredentialUiMode,
    pub credential_mode: Option<CredentialBindingMode>,
    pub credential_id: Option<Uuid>,
    /// Transient plaintext — never log. Written via pending path, not on the node model.
    pub inline_password: String,
    /// When true, selected saved credential is an SSH key (hides auto-sudo).
    pub selected_credential_is_ssh_key: bool,
    /// Show RDP domain even under a saved credential (distinct override / unresolved cred).
    pub show_rdp_domain_override: bool,

    pub ssh_auto_sudo_mode: SshAutoSudoMode,
    loaded_ssh_auto_sudo: Option<bool>,
    loaded_use_inline_password: bool,

    // RDP
    pub rdp_screen_size: String,
    pub rdp_full_screen: bool,
    pub rdp_color_depth: i32,
    pub rdp_use_all_monitors: bool,
    pub rdp_audio_mode: i32,
    pub rdp_audio_capture_mode: i32,
    pub rdp_keyboard_hook_mode: i32,
    pub rdp_redirect_clipboard: bool,
    pub rdp_redirect_printers: bool,
    pub rdp_redirect_smart_cards: bool,
    pub rdp_redirect_ports: bool,
    pub rdp_redirect_devices: bool,
    pub rdp_drive_redirect_mode: RdpDriveRedirectMode,
    pub rdp_custom_drive_list: String,
    pub rdp_connection_speed: i32,
    pub rdp_desktop_background: bool,
    pub rdp_font_smoothing: bool,
    pub rdp_desktop_composition: bool,
    pub rdp_window_drag: bool,
    pub rdp_menu_animation: bool,
    pub rdp_visual_styles: bool,
    pub rdp_bitmap_caching: bool,
    pub rdp_auto_reconnect: bool,
    pub rdp_server_authentication: i32,
    pub rdp_gateway_usage_method: i32,
    pub rdp_gateway_hostname: String,
    pub rdp_gateway_credential_id: Option<Uuid>,
    pub rdp_gateway_bypass_local: bool,
    pub rdp_gateway_use_same_creds: bool,
    pub rdp_use_external_client: bool,

    // Serial
    pub serial_baud_rate: i32,
    pub serial_baud_rate_inherits: bool,
    pub serial_data_bits: i32,
    pub serial_data_bits_inherits: bool,
    pub serial_stop_bits: SerialStopBitsMode,
    pub serial_stop_bits_inherits: bool,
    pub serial_parity: SerialParityMode,
    pub serial_parity_inherits: bool,
    pub serial_flow_control: SerialFlowControlMode,
    pub serial_flow_control_inherits: bool,

    pub http_ignore_cert_errors: bool,

    pub tunnel: TunnelUiState,

    /// Username of the currently selected saved credential (fallback on write).
    pub selected_credential_username: Option<String>,
}

impl fmt::Debug for ConnectionEditorState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Non-exhaustive on purpose: keep Debug useful without listing every RDP/serial
        // field, and never emit the inline password plaintext.
        f.debug_struct("ConnectionEditorState")
            .field("mode", &self.mode)
            .field("editing_node_id", &self.editing_node_id)
            .field("name", &self.name)
            .field("protocol", &self.protocol)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("credential_ui", &self.credential_ui)
            .field("credential_mode", &self.credential_mode)
            .field("credential_id", &self.credential_id)
            .field("inline_password", &REDACTED)
            .field("tunnel", &self.tunnel)
            .finish_non_exhaustive()
    }
}

impl Default for ConnectionEditorState {
    fn default() -> Self {
        Self::new(ConnectionEditorMode::Persistent)
    }
}

impl ConnectionEditorState {
    pub fn new(mode: ConnectionEditorMode) -> Self {
        let allow_inheritance = mode == ConnectionEditorMode::Persistent;
        Self {
            mode,
            editing_node_id: Uuid::nil(),
            parent_id: None,
            sort_order: 0,
            name: String::new(),
            protocol: ProtocolType::Ssh,
            host: String::new(),
            port: None,
            username: String::new(),
            rdp_domain: String::new(),
            credential_ui: CredentialUiMode::Saved,
            credential_mode: Some(if allow_inheritance {
                CredentialBindingMode::Inherit
            } else {
                CredentialBindingMode::None
            }),
            credential_id: None,
            inline_password: String::new(),
            selected_credential_is_ssh_key: false,
            show_rdp_domain_override: true,
            ssh_auto_sudo_mode: if allow_inheritance {
                SshAutoSudoMode::Inherit
            } else {
                SshAutoSudoMode::Off
            },
            loaded_ssh_auto_sudo: None,
            loaded_use_inline_password: false,
            rdp_screen_size: RdpScreenSizes::FULL_CONNECTION_CONTENT.to_string(),
            rdp_full_screen: false,
            rdp_color_depth: 32,
            rdp_use_all_monitors: false,
            rdp_audio_mode: 0,
            rdp_audio_capture_mode: 0,
            rdp_keyboard_hook_mode: 2,
            rdp_redirect_clipboard: true,
            rdp_redirect_printers: false,
            rdp_redirect_smart_cards: false,
            rdp_redirect_ports: false,
            rdp_redirect_devices: false,
            rdp_drive_redirect_mode: RdpDriveRedirectMode::None,
            rdp_custom_drive_list: String::new(),
            rdp_connection_speed: 7,
            rdp_desktop_background: true,
            rdp_font_smoothing: true,
            rdp_desktop_composition: true,
            rdp_window_drag: true,
            rdp_menu_animation: true,
            rdp_visual_styles: true,
            rdp_bitmap_caching: true,
            rdp_auto_reconnect: true,
            rdp_server_authentication: 2,
            rdp_gateway_usage_method: 0,
            rdp_gateway_hostname: String::new(),
            rdp_gateway_credential_id: None,
            rdp_gateway_bypass_local: true,
            rdp_gateway_use_same_creds: false,
            rdp_use_external_client: false,
            serial_baud_rate: SerialDefaults::BAUD_RATE,
            serial_baud_rate_inherits: allow_inheritance,
            serial_data_bits: SerialDefaults::DATA_BITS,
            serial_data_bits_inherits: allow_inheritance,
            serial_stop_bits: SerialDefaults::STOP_BITS,
            serial_stop_bits_inherits: allow_inheritance,
            serial_parity: SerialDefaults::PARITY,
            serial_parity_inherits: allow_inheritance,
            serial_flow_control: SerialDefaults::FLOW_CONTROL,
            serial_flow_control_inherits: allow_inheritance,
            http_ignore_cert_errors: false,
            tunnel: TunnelUiState {
                allow_inheritance,
                enabled: if allow_inheritance {
                    None
                } else {
                    Some(false)
                },
                config_id: None,
            },
            selected_credential_username: None,
        }
    }

    pub fn supports_inheritance(&self) -> bool {
        self.mode == ConnectionEditorMode::Persistent
    }

    pub fn is_quick_connect(&self) -> bool {
        self.mode == ConnectionEditorMode::QuickConnect
    }

    pub fn use_saved_credentials(&self) -> bool {
        self.credential_ui == CredentialUiMode::Saved
    }

    /// Whether the loaded node used an inline password (before editor edits).
    ///
    /// Used by storage `load_inline_secret` (C# `_loadedUseInlinePassword`).
    pub fn loaded_uses_inline_password(&self) -> bool {
        self.loaded_use_inline_password
    }

    pub fn set_use_saved_credentials(&mut self, use_saved: bool) {
        self.credential_ui = if use_saved {
            CredentialUiMode::Saved
        } else {
            CredentialUiMode::Inline
        };
    }

    pub fn visible_fields(&self) -> VisibleFields {
        VisibleFields::for_protocol(
            self.protocol,
            self.mode,
            self.use_saved_credentials(),
            self.show_rdp_domain_override,
            self.selected_credential_is_ssh_key,
        )
    }

    pub fn tunnel_selection(&self) -> TunnelUiSelection {
        self.tunnel.selection()
    }

    pub fn set_tunnel_selection(&mut self, selection: TunnelUiSelection) {
        self.tunnel.set_selection(selection);
    }

    /// Load editor fields from a persisted / draft [`ConnectionNode`].
    pub fn load_from(&mut self, node: &ConnectionNode, mode: ConnectionEditorMode) {
        self.mode = mode;
        let allow = mode == ConnectionEditorMode::Persistent;
        self.tunnel.allow_inheritance = allow;

        self.editing_node_id = node.id;
        self.parent_id = node.parent_id;
        self.sort_order = node.sort_order;
        self.name = node.name.clone();
        self.protocol = node.protocol.unwrap_or(ProtocolType::Ssh);
        self.host = node.host.clone().unwrap_or_default();
        self.port = node.port;

        if matches!(self.protocol, ProtocolType::Http | ProtocolType::Https) {
            let web_default = http_default_port(self.protocol);
            if let Some(web_port) = node.port
                && web_port != web_default
                && !self.host.trim().is_empty()
            {
                self.host = fold_http_address_port(&self.host, web_port);
            }
            self.port = None;
        }

        self.username = node.username.clone().unwrap_or_default();
        self.rdp_domain = node.rdp_domain.clone().unwrap_or_default();
        self.credential_id = node.credential_id;
        self.credential_mode = Some(node.credential_mode.unwrap_or_else(|| {
            if node.credential_id.is_none() {
                if self.is_quick_connect() {
                    CredentialBindingMode::None
                } else {
                    CredentialBindingMode::Inherit
                }
            } else {
                CredentialBindingMode::Saved
            }
        }));
        self.loaded_use_inline_password = node.use_inline_password.unwrap_or(false);
        self.set_use_saved_credentials(!self.loaded_use_inline_password);
        self.inline_password.clear();

        self.loaded_ssh_auto_sudo = if self.is_quick_connect() {
            Some(false)
        } else {
            node.ssh_auto_sudo
        };
        self.ssh_auto_sudo_mode = match node.ssh_auto_sudo {
            Some(true) => SshAutoSudoMode::On,
            Some(false) => SshAutoSudoMode::Off,
            None => {
                if self.is_quick_connect() {
                    SshAutoSudoMode::Off
                } else {
                    SshAutoSudoMode::Inherit
                }
            }
        };

        self.rdp_screen_size = RdpScreenSizes::normalize_for_picker(node.rdp_screen_size.as_deref())
            .unwrap_or_else(|| RdpScreenSizes::FULL_CONNECTION_CONTENT.to_string());
        self.rdp_full_screen = node.rdp_full_screen.unwrap_or(false);
        self.rdp_color_depth = node.rdp_color_depth.unwrap_or(32);
        self.rdp_use_all_monitors = node.rdp_use_all_monitors.unwrap_or(false);
        self.rdp_audio_mode = node.rdp_audio_mode.unwrap_or(0);
        self.rdp_audio_capture_mode = node.rdp_audio_capture_mode.unwrap_or(0);
        self.rdp_keyboard_hook_mode = node.rdp_keyboard_hook_mode.unwrap_or(2);
        self.rdp_redirect_clipboard = node.rdp_redirect_clipboard.unwrap_or(true);
        self.rdp_redirect_printers = node.rdp_redirect_printers.unwrap_or(false);
        self.rdp_redirect_smart_cards = node.rdp_redirect_smart_cards.unwrap_or(false);
        self.rdp_redirect_ports = node.rdp_redirect_ports.unwrap_or(false);
        self.rdp_redirect_devices = node.rdp_redirect_devices.unwrap_or(false);

        self.apply_rdp_drive_list(node.rdp_redirect_drives.as_deref().unwrap_or(""));

        self.rdp_connection_speed = node.rdp_connection_speed.unwrap_or(7);
        self.rdp_desktop_background = node.rdp_desktop_background.unwrap_or(true);
        self.rdp_font_smoothing = node.rdp_font_smoothing.unwrap_or(true);
        self.rdp_desktop_composition = node.rdp_desktop_composition.unwrap_or(true);
        self.rdp_window_drag = node.rdp_window_drag.unwrap_or(true);
        self.rdp_menu_animation = node.rdp_menu_animation.unwrap_or(true);
        self.rdp_visual_styles = node.rdp_visual_styles.unwrap_or(true);
        self.rdp_bitmap_caching = node.rdp_bitmap_caching.unwrap_or(true);
        self.rdp_auto_reconnect = node.rdp_auto_reconnect.unwrap_or(true);
        self.rdp_server_authentication = node.rdp_server_authentication.unwrap_or(2);
        self.rdp_gateway_usage_method = node.rdp_gateway_usage_method.unwrap_or(0);
        self.rdp_gateway_hostname = node.rdp_gateway_hostname.clone().unwrap_or_default();
        self.rdp_gateway_credential_id = node.rdp_gateway_credential_id;
        self.rdp_gateway_bypass_local = node.rdp_gateway_bypass_local.unwrap_or(true);
        self.rdp_gateway_use_same_creds = node.rdp_gateway_use_same_creds.unwrap_or(false);
        self.rdp_use_external_client = node.rdp_use_external_client.unwrap_or(false);

        self.serial_baud_rate_inherits = allow && node.serial_baud_rate.is_none();
        self.serial_data_bits_inherits = allow && node.serial_data_bits.is_none();
        self.serial_stop_bits_inherits = allow && node.serial_stop_bits.is_none();
        self.serial_parity_inherits = allow && node.serial_parity.is_none();
        self.serial_flow_control_inherits = allow && node.serial_flow_control.is_none();
        self.serial_baud_rate = SerialDefaults::normalize_baud_rate(node.serial_baud_rate);
        self.serial_data_bits = SerialDefaults::normalize_data_bits(node.serial_data_bits);
        self.serial_stop_bits = SerialDefaults::normalize_stop_bits(node.serial_stop_bits);
        self.serial_parity = SerialDefaults::normalize_parity(node.serial_parity);
        self.serial_flow_control = SerialDefaults::normalize_flow_control(node.serial_flow_control);

        self.http_ignore_cert_errors = node.http_ignore_cert_errors.unwrap_or(false);
        self.tunnel
            .load_from_node(node.tunnel_enabled, node.tunnel_config_id);
    }

    /// Seed the editor from a fully resolved [`ConnectionProfile`] (concrete values, no inherit).
    ///
    /// Useful for Quick Connect / ephemeral sessions where inheritance already ran.
    pub fn apply_resolved_profile(&mut self, profile: &ConnectionProfile) {
        let mode = ConnectionEditorMode::QuickConnect;
        self.mode = mode;
        self.tunnel.allow_inheritance = false;

        self.editing_node_id = profile.node_id;
        self.parent_id = None;
        self.name = profile.name.clone();
        self.protocol = profile.protocol;
        self.host = profile.host.clone();
        self.port = Some(profile.port);

        if matches!(self.protocol, ProtocolType::Http | ProtocolType::Https) {
            let web_default = http_default_port(self.protocol);
            if profile.port != web_default && !self.host.trim().is_empty() {
                self.host = fold_http_address_port(&self.host, profile.port);
            }
            self.port = None;
        }

        self.username = profile.username.clone().unwrap_or_default();
        self.rdp_domain = profile.rdp_domain.clone().unwrap_or_default();
        self.credential_id = profile.credential_id;
        self.credential_mode = if profile.use_inline_password {
            Some(CredentialBindingMode::None)
        } else if profile.credential_id.is_some() {
            Some(CredentialBindingMode::Saved)
        } else {
            Some(CredentialBindingMode::None)
        };
        self.set_use_saved_credentials(!profile.use_inline_password);
        self.inline_password.clear();
        self.loaded_use_inline_password = profile.use_inline_password;
        self.loaded_ssh_auto_sudo = Some(profile.ssh_auto_sudo);
        self.ssh_auto_sudo_mode = if profile.ssh_auto_sudo {
            SshAutoSudoMode::On
        } else {
            SshAutoSudoMode::Off
        };

        self.rdp_screen_size =
            RdpScreenSizes::normalize_for_picker(profile.rdp_screen_size.as_deref())
                .unwrap_or_else(|| RdpScreenSizes::FULL_CONNECTION_CONTENT.to_string());
        self.rdp_full_screen = profile.rdp_full_screen;
        self.rdp_color_depth = profile.rdp_color_depth;
        self.rdp_use_all_monitors = profile.rdp_use_all_monitors;
        self.rdp_audio_mode = profile.rdp_audio_mode;
        self.rdp_audio_capture_mode = profile.rdp_audio_capture_mode;
        self.rdp_keyboard_hook_mode = profile.rdp_keyboard_hook_mode;
        self.rdp_redirect_clipboard = profile.rdp_redirect_clipboard;
        self.rdp_redirect_printers = profile.rdp_redirect_printers;
        self.rdp_redirect_smart_cards = profile.rdp_redirect_smart_cards;
        self.rdp_redirect_ports = profile.rdp_redirect_ports;
        self.rdp_redirect_devices = profile.rdp_redirect_devices;
        self.apply_rdp_drive_list(profile.rdp_redirect_drives.as_str());
        self.rdp_connection_speed = profile.rdp_connection_speed;
        self.rdp_desktop_background = profile.rdp_desktop_background;
        self.rdp_font_smoothing = profile.rdp_font_smoothing;
        self.rdp_desktop_composition = profile.rdp_desktop_composition;
        self.rdp_window_drag = profile.rdp_window_drag;
        self.rdp_menu_animation = profile.rdp_menu_animation;
        self.rdp_visual_styles = profile.rdp_visual_styles;
        self.rdp_bitmap_caching = profile.rdp_bitmap_caching;
        self.rdp_auto_reconnect = profile.rdp_auto_reconnect;
        self.rdp_server_authentication = profile.rdp_server_authentication;
        self.rdp_gateway_usage_method = profile.rdp_gateway_usage_method;
        self.rdp_gateway_hostname = profile
            .rdp_gateway_hostname
            .clone()
            .unwrap_or_default();
        self.rdp_gateway_credential_id = profile.rdp_gateway_credential_id;
        self.rdp_gateway_bypass_local = profile.rdp_gateway_bypass_local;
        self.rdp_gateway_use_same_creds = profile.rdp_gateway_use_same_creds;
        self.rdp_use_external_client = profile.rdp_use_external_client;

        // Resolved serial values are concrete — no inherit checkboxes.
        self.serial_baud_rate_inherits = false;
        self.serial_data_bits_inherits = false;
        self.serial_stop_bits_inherits = false;
        self.serial_parity_inherits = false;
        self.serial_flow_control_inherits = false;
        self.serial_baud_rate = profile.serial_baud_rate;
        self.serial_data_bits = profile.serial_data_bits;
        self.serial_stop_bits = profile.serial_stop_bits;
        self.serial_parity = profile.serial_parity;
        self.serial_flow_control = profile.serial_flow_control;

        self.http_ignore_cert_errors = profile.http_ignore_cert_errors;

        if self.protocol == ProtocolType::Serial {
            self.tunnel.set_selection(TunnelUiSelection::NoTunnel);
        } else if profile.tunnel_enabled {
            match profile.tunnel_config_id {
                Some(id) => self.tunnel.set_selection(TunnelUiSelection::Config(id)),
                None => self.tunnel.set_selection(TunnelUiSelection::EnabledNoConfig),
            }
        } else {
            self.tunnel.set_selection(TunnelUiSelection::NoTunnel);
        }
    }

    fn apply_rdp_drive_list(&mut self, drives: &str) {
        if drives.is_empty() {
            self.rdp_drive_redirect_mode = RdpDriveRedirectMode::None;
            self.rdp_custom_drive_list.clear();
        } else if drives.eq_ignore_ascii_case(ALL_SENTINEL) {
            self.rdp_drive_redirect_mode = RdpDriveRedirectMode::All;
            self.rdp_custom_drive_list.clear();
        } else {
            self.rdp_drive_redirect_mode = RdpDriveRedirectMode::Custom;
            self.rdp_custom_drive_list = drives.to_string();
        }
    }

    /// Build a new [`ConnectionNode`] from the current editor fields.
    ///
    /// Returns `(node, pending_inline_password)` — the password is never stored on the node.
    pub fn to_connection_node(&self) -> (ConnectionNode, Option<String>) {
        let mut node = ConnectionNode {
            id: self.editing_node_id,
            parent_id: self.parent_id,
            name: String::new(),
            kind: NodeKind::Connection,
            sort_order: self.sort_order,
            ..ConnectionNode::default()
        };
        let pending = self.write_to(&mut node, WriteOptions::default());
        (node, pending)
    }

    /// Copy field values into `node` (caller owns Id / parent linkage).
    ///
    /// Returns the pending inline password when SSH/RDP inline mode is active.
    pub fn write_to(&self, node: &mut ConnectionNode, options: WriteOptions) -> Option<String> {
        let vis = self.visible_fields();
        node.name = self.name.trim().to_string();
        node.protocol = Some(self.protocol);

        if vis.is_http {
            let (http_host, http_port) = parse_http_address(&self.host);
            node.host = Some(http_host);
            node.port = http_port;
        } else if vis.is_serial {
            node.host = Some(self.host.trim().to_string());
            node.port = None;
        } else {
            node.host = Some(self.host.trim().to_string());
            node.port = self.port;
        }

        if vis.is_vnc || vis.is_http || vis.is_serial {
            node.username = None;
        } else if !self.username.trim().is_empty() {
            node.username = Some(self.username.trim().to_string());
        } else if let Some(cred_user) = self
            .selected_credential_username
            .as_deref()
            .map(str::trim)
            .filter(|u| !u.is_empty())
        {
            node.username = Some(cred_user.to_string());
        } else {
            node.username = None;
        }

        let mut pending = None;
        if !vis.show_credential_section {
            node.credential_id = None;
            node.credential_mode = None;
            node.use_inline_password = Some(false);
        } else if !self.use_saved_credentials() {
            let can_inline = vis.is_ssh || vis.is_rdp;
            node.credential_id = None;
            node.credential_mode = Some(CredentialBindingMode::None);
            node.use_inline_password = Some(can_inline);
            if can_inline && options.include_pending_inline_password {
                pending = Some(self.inline_password.clone());
            }
        } else {
            node.use_inline_password = Some(false);
            let effective = self.effective_credential_mode();
            node.credential_mode = Some(effective);
            node.credential_id = if effective == CredentialBindingMode::Saved {
                self.credential_id
            } else {
                None
            };
        }

        node.ssh_auto_sudo = if vis.is_ssh {
            if vis.show_ssh_auto_sudo {
                match self.ssh_auto_sudo_mode {
                    SshAutoSudoMode::On => Some(true),
                    SshAutoSudoMode::Off => Some(false),
                    SshAutoSudoMode::Inherit => None,
                }
            } else {
                self.loaded_ssh_auto_sudo
            }
        } else {
            None
        };

        if vis.is_rdp {
            node.rdp_domain = if vis.show_rdp_domain && !self.rdp_domain.trim().is_empty() {
                Some(self.rdp_domain.trim().to_string())
            } else {
                None
            };
            node.rdp_screen_size = if self.rdp_screen_size.trim().is_empty() {
                None
            } else {
                Some(self.rdp_screen_size.clone())
            };
            node.rdp_full_screen = Some(self.rdp_full_screen);
            node.rdp_color_depth = Some(self.rdp_color_depth);
            node.rdp_use_all_monitors = Some(self.rdp_use_all_monitors);
            node.rdp_audio_mode = Some(self.rdp_audio_mode);
            node.rdp_audio_capture_mode = Some(self.rdp_audio_capture_mode);
            node.rdp_keyboard_hook_mode = Some(self.rdp_keyboard_hook_mode);
            node.rdp_redirect_clipboard = Some(self.rdp_redirect_clipboard);
            node.rdp_redirect_printers = Some(self.rdp_redirect_printers);
            node.rdp_redirect_smart_cards = Some(self.rdp_redirect_smart_cards);
            node.rdp_redirect_ports = Some(self.rdp_redirect_ports);
            node.rdp_redirect_devices = Some(self.rdp_redirect_devices);
            node.rdp_redirect_drives = Some(match self.rdp_drive_redirect_mode {
                RdpDriveRedirectMode::All => ALL_SENTINEL.to_string(),
                RdpDriveRedirectMode::Custom => rdp_drives::normalise(&self.rdp_custom_drive_list),
                RdpDriveRedirectMode::None => String::new(),
            });
            node.rdp_connection_speed = Some(self.rdp_connection_speed);
            node.rdp_desktop_background = Some(self.rdp_desktop_background);
            node.rdp_font_smoothing = Some(self.rdp_font_smoothing);
            node.rdp_desktop_composition = Some(self.rdp_desktop_composition);
            node.rdp_window_drag = Some(self.rdp_window_drag);
            node.rdp_menu_animation = Some(self.rdp_menu_animation);
            node.rdp_visual_styles = Some(self.rdp_visual_styles);
            node.rdp_bitmap_caching = Some(self.rdp_bitmap_caching);
            node.rdp_auto_reconnect = Some(self.rdp_auto_reconnect);
            node.rdp_server_authentication = Some(self.rdp_server_authentication);
            node.rdp_gateway_usage_method = Some(self.rdp_gateway_usage_method);
            node.rdp_gateway_hostname = {
                let t = self.rdp_gateway_hostname.trim();
                if t.is_empty() {
                    None
                } else {
                    Some(t.to_string())
                }
            };
            node.rdp_gateway_credential_id = self.rdp_gateway_credential_id;
            node.rdp_gateway_bypass_local = Some(self.rdp_gateway_bypass_local);
            node.rdp_gateway_use_same_creds = Some(self.rdp_gateway_use_same_creds);
            node.rdp_use_external_client = Some(self.rdp_use_external_client);
        }

        node.http_ignore_cert_errors = if vis.is_https {
            Some(self.http_ignore_cert_errors)
        } else {
            None
        };

        if vis.is_serial {
            // Fail-closed DCB via preset glue. On illegal combo, clear serial_* so an
            // in-place `write_to` cannot leave stale prior values (fresh nodes stay None).
            // Persist callers gate on `is_valid()` first.
            if !crate::serial_presets::write_editor_serial_to_node(self, node) {
                node.serial_baud_rate = None;
                node.serial_data_bits = None;
                node.serial_stop_bits = None;
                node.serial_parity = None;
                node.serial_flow_control = None;
            }
        } else {
            node.serial_baud_rate = None;
            node.serial_data_bits = None;
            node.serial_stop_bits = None;
            node.serial_parity = None;
            node.serial_flow_control = None;
        }

        if vis.is_serial {
            node.tunnel_enabled = Some(false);
            node.tunnel_config_id = None;
        } else {
            let (enabled, config_id) = self.tunnel.to_node_fields();
            node.tunnel_enabled = enabled;
            node.tunnel_config_id = config_id;
        }

        pending
    }

    /// Effective binding when the saved-credentials toggle is on.
    ///
    /// Quick Connect has no folder inheritance — an `Inherit` selection collapses to
    /// [`CredentialBindingMode::None`] (C# `EffectiveCredentialMode` parity).
    pub fn effective_credential_mode(&self) -> CredentialBindingMode {
        let mode = match self.credential_mode {
            Some(CredentialBindingMode::Inherit) => CredentialBindingMode::Inherit,
            Some(CredentialBindingMode::None) => CredentialBindingMode::None,
            Some(CredentialBindingMode::Saved) | None => {
                if self.credential_id.is_some() {
                    CredentialBindingMode::Saved
                } else if self.is_quick_connect() {
                    CredentialBindingMode::None
                } else {
                    CredentialBindingMode::Inherit
                }
            }
        };
        if self.is_quick_connect() && mode == CredentialBindingMode::Inherit {
            CredentialBindingMode::None
        } else {
            mode
        }
    }

    /// Take Quick Connect inline password without attaching it to a node.
    pub fn take_quick_connect_password(&mut self) -> Option<String> {
        if !self.is_quick_connect()
            || self.use_saved_credentials()
            || !matches!(
                self.protocol,
                ProtocolType::Ssh | ProtocolType::Rdp | ProtocolType::Vnc
            )
        {
            return None;
        }
        let password = std::mem::take(&mut self.inline_password);
        if password.is_empty() {
            None
        } else {
            Some(password)
        }
    }
}
