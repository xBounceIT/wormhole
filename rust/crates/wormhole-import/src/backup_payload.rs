//! Typed backup payload rows (camelCase JSON parity with `Models/Backup/*`).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use wormhole_domain::{
    ConnectionNode, CredentialKind, CredentialSecretProvider, NodeKind, ProtocolType, TunnelKind,
};
use wormhole_storage::{CredentialProfile, TunnelConfig};

/// Inline plaintext payload matching C# `BackupPayload`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct BackupPayloadRows {
    #[serde(default)]
    pub nodes: Vec<BackupConnectionNode>,
    #[serde(default)]
    pub credentials: Vec<BackupCredentialProfile>,
    #[serde(default)]
    pub tunnels: Vec<BackupTunnelConfig>,
    #[serde(default)]
    pub bitwarden_credential_cache: Vec<serde_json::Value>,
    #[serde(default)]
    pub passwords: Vec<BackupPasswordEntry>,
    #[serde(default)]
    pub inline_passwords: Vec<BackupInlinePasswordEntry>,
    #[serde(default)]
    pub private_keys: Vec<BackupPrivateKeyEntry>,
    #[serde(default)]
    pub tunnel_payloads: Vec<BackupTunnelPayloadEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupPasswordEntry {
    pub credential_id: Uuid,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupInlinePasswordEntry {
    pub node_id: Uuid,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupPrivateKeyEntry {
    pub credential_id: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_file_name: Option<String>,
    pub data_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupTunnelPayloadEntry {
    pub tunnel_config_id: Uuid,
    pub data_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupCredentialProfile {
    pub id: Uuid,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    pub kind: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key_file_name: Option<String>,
    pub protocol: i32,
    pub secret_provider: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bitwarden_item_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bitwarden_item_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bitwarden_field_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupTunnelConfig {
    pub id: Uuid,
    pub name: String,
    pub kind: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}

/// Connection node row for backup JSON (no SQLite audit columns).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupConnectionNode {
    pub id: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<Uuid>,
    pub name: String,
    pub kind: i32,
    pub sort_order: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_mode: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub use_inline_password: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdp_domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdp_screen_size: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdp_full_screen: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdp_color_depth: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdp_use_all_monitors: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdp_audio_mode: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdp_audio_capture_mode: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdp_keyboard_hook_mode: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdp_redirect_clipboard: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdp_redirect_printers: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdp_redirect_smart_cards: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdp_redirect_ports: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdp_redirect_devices: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdp_redirect_drives: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdp_connection_speed: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdp_desktop_background: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdp_font_smoothing: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdp_desktop_composition: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdp_window_drag: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdp_menu_animation: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdp_visual_styles: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdp_bitmap_caching: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdp_auto_reconnect: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdp_server_authentication: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdp_gateway_usage_method: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdp_gateway_hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdp_gateway_credential_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdp_gateway_bypass_local: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdp_gateway_use_same_creds: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdp_use_external_client: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_key_file_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_known_host_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_auto_sudo: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial_baud_rate: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial_data_bits: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial_stop_bits: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial_parity: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial_flow_control: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_ignore_cert_errors: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel_config_id: Option<Uuid>,
}

impl From<&ConnectionNode> for BackupConnectionNode {
    fn from(node: &ConnectionNode) -> Self {
        Self {
            id: node.id,
            parent_id: node.parent_id,
            name: node.name.clone(),
            kind: node.kind.as_i32(),
            sort_order: node.sort_order,
            protocol: node.protocol.map(|p| p.as_i32()),
            host: node.host.clone(),
            port: node.port,
            username: node.username.clone(),
            credential_id: node.credential_id,
            credential_mode: node.credential_mode.map(|m| m.as_i32()),
            use_inline_password: node.use_inline_password,
            rdp_domain: node.rdp_domain.clone(),
            rdp_screen_size: node.rdp_screen_size.clone(),
            rdp_full_screen: node.rdp_full_screen,
            rdp_color_depth: node.rdp_color_depth,
            rdp_use_all_monitors: node.rdp_use_all_monitors,
            rdp_audio_mode: node.rdp_audio_mode,
            rdp_audio_capture_mode: node.rdp_audio_capture_mode,
            rdp_keyboard_hook_mode: node.rdp_keyboard_hook_mode,
            rdp_redirect_clipboard: node.rdp_redirect_clipboard,
            rdp_redirect_printers: node.rdp_redirect_printers,
            rdp_redirect_smart_cards: node.rdp_redirect_smart_cards,
            rdp_redirect_ports: node.rdp_redirect_ports,
            rdp_redirect_devices: node.rdp_redirect_devices,
            rdp_redirect_drives: node.rdp_redirect_drives.clone(),
            rdp_connection_speed: node.rdp_connection_speed,
            rdp_desktop_background: node.rdp_desktop_background,
            rdp_font_smoothing: node.rdp_font_smoothing,
            rdp_desktop_composition: node.rdp_desktop_composition,
            rdp_window_drag: node.rdp_window_drag,
            rdp_menu_animation: node.rdp_menu_animation,
            rdp_visual_styles: node.rdp_visual_styles,
            rdp_bitmap_caching: node.rdp_bitmap_caching,
            rdp_auto_reconnect: node.rdp_auto_reconnect,
            rdp_server_authentication: node.rdp_server_authentication,
            rdp_gateway_usage_method: node.rdp_gateway_usage_method,
            rdp_gateway_hostname: node.rdp_gateway_hostname.clone(),
            rdp_gateway_credential_id: node.rdp_gateway_credential_id,
            rdp_gateway_bypass_local: node.rdp_gateway_bypass_local,
            rdp_gateway_use_same_creds: node.rdp_gateway_use_same_creds,
            rdp_use_external_client: node.rdp_use_external_client,
            ssh_key_file_name: node.ssh_key_file_name.clone(),
            ssh_known_host_fingerprint: node.ssh_known_host_fingerprint.clone(),
            ssh_auto_sudo: node.ssh_auto_sudo,
            serial_baud_rate: node.serial_baud_rate,
            serial_data_bits: node.serial_data_bits,
            serial_stop_bits: node.serial_stop_bits.map(|v| v.as_i32()),
            serial_parity: node.serial_parity.map(|v| v.as_i32()),
            serial_flow_control: node.serial_flow_control.map(|v| v.as_i32()),
            http_ignore_cert_errors: node.http_ignore_cert_errors,
            tunnel_enabled: node.tunnel_enabled,
            tunnel_config_id: node.tunnel_config_id,
        }
    }
}

impl TryFrom<BackupConnectionNode> for ConnectionNode {
    type Error = crate::error::ImportError;

    fn try_from(row: BackupConnectionNode) -> Result<Self, Self::Error> {
        Ok(ConnectionNode {
            id: row.id,
            parent_id: row.parent_id,
            name: row.name,
            kind: NodeKind::try_from(row.kind).map_err(|e| crate::error::ImportError::InvalidData(e.to_string()))?,
            sort_order: row.sort_order,
            protocol: opt_enum(row.protocol, "ProtocolType")?,
            host: row.host,
            port: row.port,
            username: row.username,
            credential_id: row.credential_id,
            credential_mode: opt_enum(row.credential_mode, "CredentialBindingMode")?,
            use_inline_password: row.use_inline_password,
            rdp_domain: row.rdp_domain,
            rdp_screen_size: row.rdp_screen_size,
            rdp_full_screen: row.rdp_full_screen,
            rdp_color_depth: row.rdp_color_depth,
            rdp_use_all_monitors: row.rdp_use_all_monitors,
            rdp_audio_mode: row.rdp_audio_mode,
            rdp_audio_capture_mode: row.rdp_audio_capture_mode,
            rdp_keyboard_hook_mode: row.rdp_keyboard_hook_mode,
            rdp_redirect_clipboard: row.rdp_redirect_clipboard,
            rdp_redirect_printers: row.rdp_redirect_printers,
            rdp_redirect_smart_cards: row.rdp_redirect_smart_cards,
            rdp_redirect_ports: row.rdp_redirect_ports,
            rdp_redirect_devices: row.rdp_redirect_devices,
            rdp_redirect_drives: row.rdp_redirect_drives,
            rdp_connection_speed: row.rdp_connection_speed,
            rdp_desktop_background: row.rdp_desktop_background,
            rdp_font_smoothing: row.rdp_font_smoothing,
            rdp_desktop_composition: row.rdp_desktop_composition,
            rdp_window_drag: row.rdp_window_drag,
            rdp_menu_animation: row.rdp_menu_animation,
            rdp_visual_styles: row.rdp_visual_styles,
            rdp_bitmap_caching: row.rdp_bitmap_caching,
            rdp_auto_reconnect: row.rdp_auto_reconnect,
            rdp_server_authentication: row.rdp_server_authentication,
            rdp_gateway_usage_method: row.rdp_gateway_usage_method,
            rdp_gateway_hostname: row.rdp_gateway_hostname,
            rdp_gateway_credential_id: row.rdp_gateway_credential_id,
            rdp_gateway_bypass_local: row.rdp_gateway_bypass_local,
            rdp_gateway_use_same_creds: row.rdp_gateway_use_same_creds,
            rdp_use_external_client: row.rdp_use_external_client,
            ssh_key_file_name: row.ssh_key_file_name,
            ssh_known_host_fingerprint: row.ssh_known_host_fingerprint,
            ssh_auto_sudo: row.ssh_auto_sudo,
            serial_baud_rate: row.serial_baud_rate,
            serial_data_bits: row.serial_data_bits,
            serial_stop_bits: opt_enum(row.serial_stop_bits, "SerialStopBitsMode")?,
            serial_parity: opt_enum(row.serial_parity, "SerialParityMode")?,
            serial_flow_control: opt_enum(row.serial_flow_control, "SerialFlowControlMode")?,
            http_ignore_cert_errors: row.http_ignore_cert_errors,
            tunnel_enabled: row.tunnel_enabled,
            tunnel_config_id: row.tunnel_config_id,
        })
    }
}

impl From<&CredentialProfile> for BackupCredentialProfile {
    fn from(profile: &CredentialProfile) -> Self {
        Self {
            id: profile.id,
            name: profile.name.clone(),
            username: profile.username.clone(),
            domain: profile.domain.clone(),
            kind: profile.kind.as_i32(),
            private_key_file_name: profile.private_key_file_name.clone(),
            protocol: profile.protocol.as_i32(),
            secret_provider: profile.secret_provider.as_i32(),
            bitwarden_item_id: profile.bitwarden_item_id.clone(),
            bitwarden_item_name: profile.bitwarden_item_name.clone(),
            bitwarden_field_path: profile.bitwarden_field_path.clone(),
            created_at: Some(profile.created_at),
        }
    }
}

impl TryFrom<BackupCredentialProfile> for CredentialProfile {
    type Error = crate::error::ImportError;

    fn try_from(row: BackupCredentialProfile) -> Result<Self, Self::Error> {
        Ok(CredentialProfile {
            id: row.id,
            name: row.name,
            username: row.username,
            domain: row.domain,
            kind: CredentialKind::try_from(row.kind)
                .map_err(|e| crate::error::ImportError::InvalidData(e.to_string()))?,
            private_key_file_name: row.private_key_file_name,
            protocol: ProtocolType::try_from(row.protocol)
                .map_err(|e| crate::error::ImportError::InvalidData(e.to_string()))?,
            secret_provider: CredentialSecretProvider::try_from(row.secret_provider)
                .map_err(|e| crate::error::ImportError::InvalidData(e.to_string()))?,
            bitwarden_item_id: row.bitwarden_item_id,
            bitwarden_item_name: row.bitwarden_item_name,
            bitwarden_field_path: row.bitwarden_field_path,
            created_at: row.created_at.unwrap_or_else(Utc::now),
        })
    }
}

impl From<&TunnelConfig> for BackupTunnelConfig {
    fn from(config: &TunnelConfig) -> Self {
        Self {
            id: config.id,
            name: config.name.clone(),
            kind: config.kind.as_i32(),
            created_at: Some(config.created_at),
            updated_at: Some(config.updated_at),
        }
    }
}

impl TryFrom<BackupTunnelConfig> for TunnelConfig {
    type Error = crate::error::ImportError;

    fn try_from(row: BackupTunnelConfig) -> Result<Self, Self::Error> {
        let now = Utc::now();
        Ok(TunnelConfig {
            id: row.id,
            name: row.name,
            kind: TunnelKind::try_from(row.kind)
                .map_err(|e| crate::error::ImportError::InvalidData(e.to_string()))?,
            created_at: row.created_at.unwrap_or(now),
            updated_at: row.updated_at.unwrap_or(now),
        })
    }
}

fn opt_enum<T>(value: Option<i32>, name: &str) -> Result<Option<T>, crate::error::ImportError>
where
    T: TryFrom<i32, Error = wormhole_domain::InvalidEnumValue>,
{
    match value {
        None => Ok(None),
        Some(v) => T::try_from(v)
            .map(Some)
            .map_err(|e| crate::error::ImportError::InvalidData(format!("{name}: {e}"))),
    }
}
