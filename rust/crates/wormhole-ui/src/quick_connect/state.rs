//! `QuickConnectState` — ephemeral seed, protocol/host/port/serial, validate, build.

use std::collections::HashMap;

use uuid::Uuid;
use wormhole_domain::{
    ConnectionNode, ConnectionProfile, CredentialBindingMode, InheritanceResolver, NodeKind,
    ProtocolType, ResolveError, SerialDefaults, SerialFlowControlMode, SerialParityMode,
    SerialStopBitsMode,
};

use crate::connection_editor::{
    ConnectionEditorMode, ConnectionEditorState, SshAutoSudoMode, TunnelUiSelection,
    ValidationReport, VisibleFields, WriteOptions,
};

/// Protocols offered by the Quick Connect protocol picker (session protocols only).
pub const PROTOCOL_PICKER: &[ProtocolType] = &[
    ProtocolType::Ssh,
    ProtocolType::Rdp,
    ProtocolType::Http,
    ProtocolType::Https,
    ProtocolType::Serial,
    ProtocolType::Vnc,
];

/// Label / field mode for the primary target input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetField {
    /// SSH / RDP / VNC host name or IP.
    Host,
    /// HTTP / HTTPS address (`host[:port]`).
    Address,
    /// Serial COM line (`COM1`, `COM10`, `\\.\COM10`, …).
    SerialLine,
}

impl TargetField {
    pub fn for_protocol(protocol: ProtocolType) -> Self {
        match protocol {
            ProtocolType::Serial => Self::SerialLine,
            ProtocolType::Http | ProtocolType::Https => Self::Address,
            ProtocolType::Ssh | ProtocolType::Rdp | ProtocolType::Vnc => Self::Host,
        }
    }

    pub fn header(self) -> &'static str {
        match self {
            Self::Host => "Host",
            Self::Address => "Address",
            Self::SerialLine => "Serial line",
        }
    }

    pub fn placeholder(self) -> &'static str {
        match self {
            Self::Host => "example.com",
            Self::Address => "10.0.0.1:8443",
            Self::SerialLine => "COM1",
        }
    }
}

/// Accepted Quick Connect values. Password is deliberately out-of-band from the node/profile
/// (C# `QuickConnectResult` → transient credential store).
#[derive(Clone)]
pub struct QuickConnectResult {
    pub node: ConnectionNode,
    /// Process-local only — never log. Present for SSH/RDP/VNC inline-password path.
    pub password: Option<String>,
}

impl QuickConnectResult {
    pub fn new(node: ConnectionNode, password: Option<String>) -> Self {
        Self { node, password }
    }
}

pub(super) const PASSWORD_REDACTED: &str = "<redacted>";

impl std::fmt::Debug for QuickConnectResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Mirror C# `DebuggerBrowsable(Never)` — never dump the session password.
        f.debug_struct("QuickConnectResult")
            .field("node_id", &self.node.id)
            .field("password", &PASSWORD_REDACTED)
            .finish()
    }
}

impl std::fmt::Display for QuickConnectResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Mirror C# `QuickConnectResult.ToString()` — password never leaves redacted form.
        write!(
            f,
            "QuickConnectResult {{ NodeId = {}, Password = {PASSWORD_REDACTED} }}",
            self.node.id
        )
    }
}

/// Pure Quick Connect bar / dialog state.
///
/// Owns a [`ConnectionEditorState`] locked in [`ConnectionEditorMode::QuickConnect`] so the
/// full editor field matrix stays available, while exposing the bar-oriented surface:
/// protocol picker, host/port or serial line, validation, ephemeral node/profile builders.
#[derive(Debug, Clone)]
pub struct QuickConnectState {
    editor: ConnectionEditorState,
}

impl Default for QuickConnectState {
    fn default() -> Self {
        Self::new()
    }
}

impl QuickConnectState {
    /// Fresh Quick Connect session seeded like `DialogService.PromptQuickConnectCoreAsync`.
    pub fn new() -> Self {
        let seed = seed_connection_node();
        let mut editor = ConnectionEditorState::new(ConnectionEditorMode::QuickConnect);
        editor.load_from(&seed, ConnectionEditorMode::QuickConnect);
        // Seed has CredentialMode=None and no inline flag → "prompt every time" in the picker.
        editor.set_use_saved_credentials(true);
        editor.credential_mode = Some(CredentialBindingMode::None);
        Self { editor }
    }

    /// Session protocols for the picker control.
    pub fn protocol_picker(&self) -> &'static [ProtocolType] {
        PROTOCOL_PICKER
    }

    pub fn editor(&self) -> &ConnectionEditorState {
        &self.editor
    }

    pub fn editor_mut(&mut self) -> &mut ConnectionEditorState {
        &mut self.editor
    }

    pub fn protocol(&self) -> ProtocolType {
        self.editor.protocol
    }

    pub fn set_protocol(&mut self, protocol: ProtocolType) {
        if self.editor.protocol == protocol {
            return;
        }
        let was_serial = self.editor.protocol == ProtocolType::Serial;
        self.editor.protocol = protocol;
        // Leaving RDP clears gateway credential binding (C# OnProtocolChanged).
        if protocol != ProtocolType::Rdp {
            self.editor.rdp_gateway_credential_id = None;
        }
        if matches!(
            protocol,
            ProtocolType::Serial | ProtocolType::Http | ProtocolType::Https
        ) {
            // Port box is hidden — drop a stale SSH/RDP/VNC value so it cannot poison
            // validation or confuse later switches back to a network protocol.
            self.editor.port = None;
            // Credential-less protocols: keep UI consistent with "no cred section".
            self.editor.credential_mode = Some(CredentialBindingMode::None);
            self.editor.credential_id = None;
            self.editor.inline_password.clear();
        }
        if protocol == ProtocolType::Serial || was_serial {
            // Entering or leaving Serial: tunnel is forced off (Serial has no VPN; leaving
            // must not revive an editor_mut-planted Config the Serial chrome never showed).
            self.set_tunnel_selection(TunnelUiSelection::NoTunnel);
        }
    }

    pub fn name(&self) -> &str {
        &self.editor.name
    }

    pub fn set_name(&mut self, name: impl Into<String>) {
        self.editor.name = name.into();
    }

    /// Host, HTTP address, or serial COM line (shared `Host` field in C#).
    pub fn host(&self) -> &str {
        &self.editor.host
    }

    pub fn set_host(&mut self, host: impl Into<String>) {
        self.editor.host = host.into();
    }

    /// Network port; `None` = protocol default. Ignored for HTTP (parsed from address) and serial.
    pub fn port(&self) -> Option<i32> {
        self.editor.port
    }

    pub fn set_port(&mut self, port: Option<i32>) {
        if matches!(
            self.editor.protocol,
            ProtocolType::Serial | ProtocolType::Http | ProtocolType::Https
        ) {
            self.editor.port = None;
            return;
        }
        self.editor.port = port;
    }

    pub fn target_field(&self) -> TargetField {
        TargetField::for_protocol(self.editor.protocol)
    }

    pub fn shows_port_box(&self) -> bool {
        self.editor.visible_fields().show_port_box
    }

    pub fn visible_fields(&self) -> VisibleFields {
        self.editor.visible_fields()
    }

    pub fn username(&self) -> &str {
        &self.editor.username
    }

    pub fn set_username(&mut self, username: impl Into<String>) {
        self.editor.username = username.into();
    }

    pub fn inline_password(&self) -> &str {
        &self.editor.inline_password
    }

    /// UI-only password (SSH/RDP/VNC). Never written onto [`ConnectionNode`].
    pub fn set_inline_password(&mut self, password: impl Into<String>) {
        self.editor.inline_password = password.into();
    }

    pub fn use_saved_credentials(&self) -> bool {
        self.editor.use_saved_credentials()
    }

    pub fn set_use_saved_credentials(&mut self, use_saved: bool) {
        self.editor.set_use_saved_credentials(use_saved);
        if !use_saved {
            self.editor.credential_mode = Some(CredentialBindingMode::None);
            self.editor.credential_id = None;
        }
    }

    pub fn http_ignore_cert_errors(&self) -> bool {
        self.editor.http_ignore_cert_errors
    }

    pub fn set_http_ignore_cert_errors(&mut self, ignore: bool) {
        self.editor.http_ignore_cert_errors = ignore;
    }

    // --- Ephemeral editor chrome labels (C# ConnectionEditorViewModel QC strings) ---

    pub fn name_header(&self) -> &'static str {
        "Session name (optional)"
    }

    pub fn name_placeholder(&self) -> &'static str {
        "Defaults to target"
    }

    pub fn credential_placeholder(&self) -> &'static str {
        "Prompt every time"
    }

    pub fn tunnel_help_text(&self) -> &'static str {
        "Started before the target connection. Select a saved VPN configuration or leave No tunnel."
    }

    /// Auto-sudo picker choices for Quick Connect (no folder Inherit).
    pub fn ssh_auto_sudo_choices(&self) -> &'static [SshAutoSudoMode] {
        &[SshAutoSudoMode::On, SshAutoSudoMode::Off]
    }

    // --- Optional tunnel (no Inherit in Quick Connect) ---

    pub fn shows_tunnel_section(&self) -> bool {
        self.editor.visible_fields().show_tunnel_section
    }

    /// Tunnel picker value for Quick Connect chrome.
    ///
    /// Serial is always [`TunnelUiSelection::NoTunnel`]. [`TunnelUiSelection::Inherit`] is never
    /// surfaced (no folder parent) — even if `editor_mut()` flipped `allow_inheritance` or left
    /// a vestigial config id on an Inherit-shaped (`enabled = None`) tunnel.
    pub fn tunnel_selection(&self) -> TunnelUiSelection {
        if self.editor.protocol == ProtocolType::Serial || self.editor.tunnel.enabled.is_none() {
            return TunnelUiSelection::NoTunnel;
        }
        self.editor.tunnel_selection()
    }

    /// Set tunnel: `NoTunnel` / `Config(id)`. `Inherit` always collapses to No tunnel (Quick
    /// Connect has no folder inheritance). Serial ignores the request and stays No tunnel.
    pub fn set_tunnel_selection(&mut self, selection: TunnelUiSelection) {
        if self.editor.protocol == ProtocolType::Serial {
            self.editor.set_tunnel_selection(TunnelUiSelection::NoTunnel);
            return;
        }
        let selection = match selection {
            TunnelUiSelection::Inherit => TunnelUiSelection::NoTunnel,
            other => other,
        };
        self.editor.set_tunnel_selection(selection);
    }

    // --- Serial settings (always concrete in Quick Connect; no inherit) ---
    //
    // Baud / data / stop mutations fail closed on illegal Win32 DCB pairing
    // (same rules as `wormhole_ui::serial_presets`). Parity / flow are closed enums.

    pub fn serial_baud_rate(&self) -> i32 {
        self.editor.serial_baud_rate
    }

    /// Set baud. No-op when `baud <= 0` or the resulting DCB pairing is illegal.
    pub fn set_serial_baud_rate(&mut self, baud: i32) {
        let _ = crate::serial_presets::set_custom_baud(&mut self.editor, baud);
    }

    pub fn serial_data_bits(&self) -> i32 {
        self.editor.serial_data_bits
    }

    /// Set data bits. No-op when out of `5..=8` or illegal with current stop bits.
    pub fn set_serial_data_bits(&mut self, bits: i32) {
        let _ = crate::serial_presets::set_custom_data_bits(&mut self.editor, bits);
    }

    pub fn serial_stop_bits(&self) -> SerialStopBitsMode {
        self.editor.serial_stop_bits
    }

    /// Set stop bits. No-op when illegal with current data bits.
    pub fn set_serial_stop_bits(&mut self, stop: SerialStopBitsMode) {
        let _ = crate::serial_presets::set_custom_stop_bits(&mut self.editor, stop);
    }

    pub fn serial_parity(&self) -> SerialParityMode {
        self.editor.serial_parity
    }

    pub fn set_serial_parity(&mut self, parity: SerialParityMode) {
        if self.editor.protocol != ProtocolType::Serial {
            return;
        }
        self.editor.serial_parity = parity;
        self.editor.serial_parity_inherits = false;
    }

    pub fn serial_flow_control(&self) -> SerialFlowControlMode {
        self.editor.serial_flow_control
    }

    pub fn set_serial_flow_control(&mut self, flow: SerialFlowControlMode) {
        if self.editor.protocol != ProtocolType::Serial {
            return;
        }
        self.editor.serial_flow_control = flow;
        self.editor.serial_flow_control_inherits = false;
    }

    pub fn validate(&self) -> ValidationReport {
        self.editor.validate()
    }

    pub fn is_valid(&self) -> bool {
        self.editor.is_valid()
    }

    /// Build an ephemeral [`ConnectionNode`] + optional session password (C# accept path).
    ///
    /// Blank name is filled from the trimmed host/address/COM line.
    /// Password is taken only for SSH/RDP/VNC when not using saved credentials.
    pub fn try_build(&mut self) -> Result<QuickConnectResult, ValidationReport> {
        // `editor_mut()` can flip `allow_inheritance` / leave Inherit-shaped fields; normalize
        // through the QC tunnel API before write so solo ephemeral nodes never persist Inherit.
        self.editor.tunnel.allow_inheritance = false;
        let tunnel = self.tunnel_selection();
        self.set_tunnel_selection(tunnel);

        let report = self.validate();
        if !report.is_valid() {
            return Err(report);
        }

        let mut node = ConnectionNode {
            id: self.editor.editing_node_id,
            parent_id: None,
            name: String::new(),
            kind: NodeKind::Connection,
            sort_order: self.editor.sort_order,
            ..ConnectionNode::default()
        };
        // Quick Connect accept never attaches pending inline password to the node.
        let _ = self.editor.write_to(
            &mut node,
            WriteOptions {
                include_pending_inline_password: false,
            },
        );
        let password = self.editor.take_quick_connect_password();

        if node.name.trim().is_empty() {
            node.name = node.host.as_deref().unwrap_or("").trim().to_string();
        }

        Ok(QuickConnectResult::new(node, password))
    }

    /// Resolve a fully-filled ephemeral [`ConnectionProfile`] (default ports, serial tunnel off).
    ///
    /// Mirrors `QuickConnectViewModel.OpenAsync` after dialog accept: solo-node inheritance
    /// resolve with `IsEphemeral = true`.
    pub fn try_build_ephemeral_profile(
        &mut self,
    ) -> Result<(ConnectionProfile, Option<String>), BuildError> {
        let QuickConnectResult { node, password } = self.try_build().map_err(BuildError::Validation)?;
        let node_id = node.id;
        let mut nodes = HashMap::new();
        nodes.insert(node_id, node);
        let mut profile = InheritanceResolver
            .resolve(&nodes[&node_id], &nodes)
            .map_err(BuildError::Resolve)?;
        profile.is_ephemeral = true;
        Ok((profile, password))
    }
}

/// Errors from [`QuickConnectState::try_build_ephemeral_profile`].
#[derive(Debug, PartialEq, Eq)]
pub enum BuildError {
    Validation(ValidationReport),
    Resolve(ResolveError),
}

/// Default port table (`InheritanceResolver.DefaultPortFor` / C# QC tests).
pub fn default_port(protocol: ProtocolType) -> i32 {
    match protocol {
        ProtocolType::Ssh => 22,
        ProtocolType::Rdp => 3389,
        ProtocolType::Http => 80,
        ProtocolType::Https => 443,
        ProtocolType::Vnc => 5900,
        ProtocolType::Serial => 0,
    }
}

/// Protocols offered by the Quick Connect picker.
pub fn protocol_picker() -> &'static [ProtocolType] {
    PROTOCOL_PICKER
}

/// Seed node matching `DialogService.PromptQuickConnectCoreAsync`.
pub fn seed_connection_node() -> ConnectionNode {
    ConnectionNode {
        id: Uuid::new_v4(),
        kind: NodeKind::Connection,
        protocol: Some(ProtocolType::Ssh),
        credential_mode: Some(CredentialBindingMode::None),
        ssh_auto_sudo: Some(false),
        serial_baud_rate: Some(SerialDefaults::BAUD_RATE),
        serial_data_bits: Some(SerialDefaults::DATA_BITS),
        serial_stop_bits: Some(SerialDefaults::STOP_BITS),
        serial_parity: Some(SerialDefaults::PARITY),
        serial_flow_control: Some(SerialDefaults::FLOW_CONTROL),
        tunnel_enabled: Some(false),
        ..ConnectionNode::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection_editor::{CredentialUiMode, SshAutoSudoMode, TunnelUiSelection, ValidationError};
    use wormhole_domain::SerialStopBitsMode;

    #[test]
    fn seed_defaults_match_dialog_service() {
        let qc = QuickConnectState::new();
        assert_eq!(qc.protocol(), ProtocolType::Ssh);
        assert!(qc.host().trim().is_empty());
        assert_eq!(qc.port(), None);
        assert!(qc.name().trim().is_empty());
        assert!(!qc.is_valid()); // host required
        assert_eq!(qc.serial_baud_rate(), SerialDefaults::BAUD_RATE);
        assert_eq!(qc.serial_data_bits(), SerialDefaults::DATA_BITS);
        assert_eq!(qc.serial_stop_bits(), SerialDefaults::STOP_BITS);
        assert_eq!(qc.editor().tunnel.enabled, Some(false));
        assert_eq!(
            qc.editor().credential_mode,
            Some(CredentialBindingMode::None)
        );
        assert!(qc.use_saved_credentials());
        assert_eq!(qc.editor().mode, ConnectionEditorMode::QuickConnect);
        assert!(!qc.editor().supports_inheritance());
    }

    #[test]
    fn protocol_picker_lists_all_session_protocols() {
        let picker = protocol_picker();
        assert_eq!(picker.len(), 6);
        assert!(picker.contains(&ProtocolType::Ssh));
        assert!(picker.contains(&ProtocolType::Rdp));
        assert!(picker.contains(&ProtocolType::Http));
        assert!(picker.contains(&ProtocolType::Https));
        assert!(picker.contains(&ProtocolType::Serial));
        assert!(picker.contains(&ProtocolType::Vnc));
        // Retired SFTP (2) must not appear.
        assert!(!picker.iter().any(|p| p.as_i32() == 2));
    }

    #[test]
    fn blank_name_allowed_when_host_present() {
        let mut qc = QuickConnectState::new();
        qc.set_host("target.example.com");
        assert!(qc.is_valid());
        let result = qc.try_build().expect("valid");
        assert_eq!(result.node.name, "target.example.com");
        assert_eq!(result.node.host.as_deref(), Some("target.example.com"));
        assert_eq!(result.node.protocol, Some(ProtocolType::Ssh));
        assert_eq!(
            result.node.credential_mode,
            Some(CredentialBindingMode::None)
        );
        assert!(result.password.is_none());
    }

    #[test]
    fn host_required() {
        let mut qc = QuickConnectState::new();
        qc.set_name("optional");
        let report = qc.validate();
        assert!(!report.is_valid());
        assert!(report.errors.contains(&ValidationError::HostRequired));
        assert!(!report.errors.contains(&ValidationError::NameRequired));
        assert!(qc.try_build().is_err());
    }

    #[test]
    fn port_out_of_range_rejected() {
        let mut qc = QuickConnectState::new();
        qc.set_host("h");
        qc.set_port(Some(0));
        assert!(qc
            .validate()
            .errors
            .contains(&ValidationError::PortOutOfRange));
        qc.set_port(Some(65536));
        assert!(qc
            .validate()
            .errors
            .contains(&ValidationError::PortOutOfRange));
        qc.set_port(None);
        assert!(qc.is_valid());
    }

    #[test]
    fn all_protocols_produce_ephemeral_profiles_with_default_ports() {
        let cases = [
            (ProtocolType::Ssh, "target.example.com", 22),
            (ProtocolType::Rdp, "target.example.com", 3389),
            (ProtocolType::Http, "target.example.com", 80),
            (ProtocolType::Https, "target.example.com", 443),
            (ProtocolType::Vnc, "target.example.com", 5900),
            (ProtocolType::Serial, "COM3", 0),
        ];
        for (protocol, host, expected_port) in cases {
            let mut qc = QuickConnectState::new();
            qc.set_protocol(protocol);
            qc.set_host(host);
            assert_eq!(default_port(protocol), expected_port);
            let (profile, password) = qc
                .try_build_ephemeral_profile()
                .unwrap_or_else(|e| panic!("{protocol:?}: {e:?}"));
            assert!(profile.is_ephemeral, "{protocol:?}");
            assert_eq!(profile.protocol, protocol);
            assert_eq!(profile.port, expected_port, "{protocol:?}");
            assert_eq!(profile.host, host);
            assert!(password.is_none());
            assert_eq!(TargetField::for_protocol(protocol).header(), match protocol {
                ProtocolType::Serial => "Serial line",
                ProtocolType::Http | ProtocolType::Https => "Address",
                _ => "Host",
            });
        }
    }

    #[test]
    fn https_preserves_custom_port_and_cert_policy() {
        let mut qc = QuickConnectState::new();
        qc.set_protocol(ProtocolType::Https);
        qc.set_host("fw.local:8443");
        qc.set_http_ignore_cert_errors(true);
        let (profile, _) = qc.try_build_ephemeral_profile().expect("https");
        assert_eq!(profile.port, 8443);
        assert!(profile.http_ignore_cert_errors);
        assert!(profile.is_ephemeral);
    }

    #[test]
    fn serial_preserves_settings_and_forces_tunnel_off() {
        let mut qc = QuickConnectState::new();
        qc.set_protocol(ProtocolType::Serial);
        qc.set_host("COM3");
        qc.set_serial_baud_rate(115_200);
        qc.set_serial_data_bits(7);
        qc.set_serial_stop_bits(SerialStopBitsMode::Two);
        qc.set_serial_parity(SerialParityMode::Even);
        qc.set_serial_flow_control(SerialFlowControlMode::DsrDtr);
        // Even if a caller left a tunnel on the editor, write path forces off.
        qc.editor_mut().tunnel.enabled = Some(true);
        qc.editor_mut().tunnel.config_id = Some(Uuid::new_v4());

        let (profile, _) = qc.try_build_ephemeral_profile().expect("serial");
        assert_eq!(profile.serial_baud_rate, 115_200);
        assert_eq!(profile.serial_data_bits, 7);
        assert_eq!(profile.serial_stop_bits, SerialStopBitsMode::Two);
        assert_eq!(profile.serial_parity, SerialParityMode::Even);
        assert_eq!(profile.serial_flow_control, SerialFlowControlMode::DsrDtr);
        assert!(!profile.tunnel_enabled);
        assert!(profile.tunnel_config_id.is_none());
        assert_eq!(profile.port, 0);
        assert!(!qc.shows_port_box());
    }

    #[test]
    fn serial_qc_setters_fail_closed_on_illegal_dcb() {
        let mut qc = QuickConnectState::new();
        qc.set_protocol(ProtocolType::Serial);
        qc.set_host("COM1");
        qc.set_serial_data_bits(8);
        qc.set_serial_stop_bits(SerialStopBitsMode::One);
        // 1.5 stop with 8 data — rejected; state unchanged.
        qc.set_serial_stop_bits(SerialStopBitsMode::OnePointFive);
        assert_eq!(qc.serial_stop_bits(), SerialStopBitsMode::One);
        qc.set_serial_data_bits(5);
        qc.set_serial_stop_bits(SerialStopBitsMode::OnePointFive);
        assert_eq!(qc.serial_stop_bits(), SerialStopBitsMode::OnePointFive);
        // Changing data bits to 8 while stop is 1.5 — rejected.
        qc.set_serial_data_bits(8);
        assert_eq!(qc.serial_data_bits(), 5);
        let baud_before = qc.serial_baud_rate();
        qc.set_serial_baud_rate(0);
        assert_eq!(qc.serial_baud_rate(), baud_before);
    }

    #[test]
    fn inline_password_stays_out_of_band_for_ssh() {
        let mut qc = QuickConnectState::new();
        qc.set_host("ssh.example");
        qc.set_username("alice");
        qc.set_use_saved_credentials(false);
        qc.set_inline_password("session-secret");
        assert_eq!(qc.editor().credential_ui, CredentialUiMode::Inline);

        let result = qc.try_build().expect("ssh");
        assert_eq!(result.password.as_deref(), Some("session-secret"));
        assert_eq!(result.node.use_inline_password, Some(true));
        // Password must not live on the node (no PendingInlinePassword field in Rust domain).
        assert!(qc.inline_password().is_empty()); // taken
    }

    #[test]
    fn vnc_inline_password_out_of_band_without_node_inline_flag() {
        let mut qc = QuickConnectState::new();
        qc.set_protocol(ProtocolType::Vnc);
        qc.set_host("vnc.example");
        qc.set_use_saved_credentials(false);
        qc.set_inline_password("vnc-secret");
        assert!(qc.visible_fields().show_inline_password);

        let result = qc.try_build().expect("vnc");
        assert_eq!(result.password.as_deref(), Some("vnc-secret"));
        // C# WriteQuickConnectTo uses includePendingInlinePassword: false and VNC does not
        // set UseInlinePassword on the node.
        assert_eq!(result.node.use_inline_password, Some(false));
        assert_eq!(
            result.node.credential_mode,
            Some(CredentialBindingMode::None)
        );
    }

    #[test]
    fn http_address_invalid_rejected() {
        let mut qc = QuickConnectState::new();
        qc.set_protocol(ProtocolType::Http);
        qc.set_host(":8443");
        assert!(qc
            .validate()
            .errors
            .contains(&ValidationError::HttpAddressInvalid));
    }

    #[test]
    fn serial_baud_invalid_rejected() {
        let mut qc = QuickConnectState::new();
        qc.set_protocol(ProtocolType::Serial);
        qc.set_host("COM1");
        // Setter fail-closes — baud stays at PuTTY default.
        qc.set_serial_baud_rate(0);
        assert_eq!(qc.serial_baud_rate(), SerialDefaults::BAUD_RATE);
        assert!(qc.is_valid());
        // Direct editor mutation still surfaces SerialBaudInvalid (validate path).
        qc.editor_mut().serial_baud_rate = 0;
        qc.editor_mut().serial_baud_rate_inherits = false;
        assert!(qc
            .validate()
            .errors
            .contains(&ValidationError::SerialBaudInvalid));
    }

    #[test]
    fn explicit_name_preserved() {
        let mut qc = QuickConnectState::new();
        qc.set_name("  my-session  ");
        qc.set_host("h.example");
        let result = qc.try_build().expect("named");
        assert_eq!(result.node.name, "my-session");
    }

    #[test]
    fn target_field_labels() {
        assert_eq!(TargetField::Host.placeholder(), "example.com");
        assert_eq!(TargetField::Address.placeholder(), "10.0.0.1:8443");
        assert_eq!(TargetField::SerialLine.placeholder(), "COM1");
    }

    #[test]
    fn ephemeral_chrome_labels_match_csharp() {
        let qc = QuickConnectState::new();
        assert_eq!(qc.name_header(), "Session name (optional)");
        assert_eq!(qc.name_placeholder(), "Defaults to target");
        assert_eq!(qc.credential_placeholder(), "Prompt every time");
        assert!(qc.tunnel_help_text().contains("No tunnel"));
        assert_eq!(
            qc.ssh_auto_sudo_choices(),
            &[SshAutoSudoMode::On, SshAutoSudoMode::Off]
        );
        assert!(!qc.ssh_auto_sudo_choices().contains(&SshAutoSudoMode::Inherit));
    }

    #[test]
    fn optional_tunnel_config_survives_ephemeral_build() {
        let tunnel_id = Uuid::new_v4();
        let mut qc = QuickConnectState::new();
        qc.set_host("ssh.example");
        assert!(qc.shows_tunnel_section());
        assert_eq!(qc.tunnel_selection(), TunnelUiSelection::NoTunnel);

        // Inherit is not offered; requesting it collapses to No tunnel.
        qc.set_tunnel_selection(TunnelUiSelection::Inherit);
        assert_eq!(qc.tunnel_selection(), TunnelUiSelection::NoTunnel);

        qc.set_tunnel_selection(TunnelUiSelection::Config(tunnel_id));
        let (profile, _) = qc.try_build_ephemeral_profile().expect("tunnel");
        assert!(profile.tunnel_enabled);
        assert_eq!(profile.tunnel_config_id, Some(tunnel_id));
        assert!(profile.is_ephemeral);
    }

    #[test]
    fn rdp_preserves_saved_credential_advanced_options_and_tunnel() {
        let credential_id = Uuid::new_v4();
        let tunnel_id = Uuid::new_v4();
        let mut qc = QuickConnectState::new();
        qc.set_protocol(ProtocolType::Rdp);
        qc.set_host("rdp.example");
        qc.set_port(Some(3390));
        qc.set_username(r"CORP\alice");
        qc.set_use_saved_credentials(true);
        {
            let ed = qc.editor_mut();
            ed.credential_mode = Some(CredentialBindingMode::Saved);
            ed.credential_id = Some(credential_id);
            ed.rdp_full_screen = true;
            ed.rdp_color_depth = 24;
            ed.rdp_redirect_clipboard = false;
            ed.rdp_server_authentication = 1;
        }
        qc.set_tunnel_selection(TunnelUiSelection::Config(tunnel_id));

        let (profile, password) = qc.try_build_ephemeral_profile().expect("rdp");
        assert!(password.is_none());
        assert_eq!(profile.port, 3390);
        assert_eq!(profile.credential_id, Some(credential_id));
        assert!(profile.rdp_full_screen);
        assert_eq!(profile.rdp_color_depth, 24);
        assert!(!profile.rdp_redirect_clipboard);
        assert_eq!(profile.rdp_server_authentication, 1);
        assert!(profile.tunnel_enabled);
        assert_eq!(profile.tunnel_config_id, Some(tunnel_id));
        assert!(profile.is_ephemeral);
    }

    #[test]
    fn quick_connect_result_debug_and_display_redact_password() {
        let mut qc = QuickConnectState::new();
        qc.set_host("ssh.example");
        qc.set_use_saved_credentials(false);
        qc.set_inline_password("session-secret");
        // Pre-accept editor Debug must also redact (ConnectionEditorState).
        let state_dbg = format!("{qc:?}");
        assert!(!state_dbg.contains("session-secret"), "{state_dbg}");
        let result = qc.try_build().expect("ssh");
        let dbg = format!("{result:?}");
        let display = format!("{result}");
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains("session-secret"));
        assert!(display.contains("<redacted>"));
        assert!(!display.contains("session-secret"));
        assert!(display.contains(&result.node.id.to_string()));
        assert_eq!(result.password.as_deref(), Some("session-secret"));
    }

    #[test]
    fn serial_hides_tunnel_and_forces_no_tunnel_selection() {
        let mut qc = QuickConnectState::new();
        qc.set_protocol(ProtocolType::Serial);
        qc.set_host("COM1");
        assert!(!qc.shows_tunnel_section());
        qc.set_tunnel_selection(TunnelUiSelection::Config(Uuid::new_v4()));
        assert_eq!(qc.tunnel_selection(), TunnelUiSelection::NoTunnel);

        // editor_mut bypass must not surface Config on the QC getter.
        qc.editor_mut()
            .set_tunnel_selection(TunnelUiSelection::Config(Uuid::new_v4()));
        assert_eq!(qc.tunnel_selection(), TunnelUiSelection::NoTunnel);

        // Leaving Serial must not revive a planted Config as an SSH tunnel.
        qc.set_protocol(ProtocolType::Ssh);
        assert_eq!(qc.tunnel_selection(), TunnelUiSelection::NoTunnel);
        assert!(!qc.editor().tunnel.enabled.unwrap_or(true));
        assert!(qc.editor().tunnel.config_id.is_none());
    }

    #[test]
    fn inherit_collapses_even_if_allow_inheritance_tampered() {
        let mut qc = QuickConnectState::new();
        qc.set_host("ssh.example");
        qc.editor_mut().tunnel.allow_inheritance = true;
        qc.editor_mut().tunnel.enabled = None;
        qc.editor_mut().tunnel.config_id = Some(Uuid::new_v4());
        // Getter must not advertise Inherit in Quick Connect.
        assert_eq!(qc.tunnel_selection(), TunnelUiSelection::NoTunnel);

        qc.set_tunnel_selection(TunnelUiSelection::Inherit);
        assert_eq!(qc.tunnel_selection(), TunnelUiSelection::NoTunnel);
        assert_eq!(qc.editor().tunnel.enabled, Some(false));
        assert!(qc.editor().tunnel.config_id.is_none());

        // Re-tamper Inherit+config, then accept — must not leave vestigial config on the node.
        let vestigial = Uuid::new_v4();
        qc.editor_mut().tunnel.allow_inheritance = true;
        qc.editor_mut().tunnel.enabled = None;
        qc.editor_mut().tunnel.config_id = Some(vestigial);
        let result = qc.try_build().expect("tampered inherit");
        assert_eq!(result.node.tunnel_enabled, Some(false));
        assert!(result.node.tunnel_config_id.is_none());
        assert!(!qc.editor().tunnel.allow_inheritance);
    }

    #[test]
    fn whitespace_name_defaults_to_host() {
        let mut qc = QuickConnectState::new();
        qc.set_name("   \t  ");
        qc.set_host("  target.example.com  ");
        let result = qc.try_build().expect("whitespace name");
        assert_eq!(result.node.name, "target.example.com");
        assert_eq!(result.node.host.as_deref(), Some("target.example.com"));
    }

    #[test]
    fn http_blank_name_uses_parsed_bare_host() {
        let mut qc = QuickConnectState::new();
        qc.set_protocol(ProtocolType::Https);
        qc.set_host("fw.local:8443");
        let result = qc.try_build().expect("https");
        assert_eq!(result.node.host.as_deref(), Some("fw.local"));
        assert_eq!(result.node.port, Some(8443));
        assert_eq!(result.node.name, "fw.local");
    }

    #[test]
    fn serial_extended_com_path_and_http_ip_host_rules() {
        // Serial: COM / \\.\COMn accepted; HTTP address usability is not applied.
        let mut serial = QuickConnectState::new();
        serial.set_protocol(ProtocolType::Serial);
        serial.set_host(r"\\.\COM10");
        let (profile, _) = serial.try_build_ephemeral_profile().expect("com10");
        assert_eq!(profile.host, r"\\.\COM10");
        assert_eq!(profile.port, 0);
        assert!(profile.is_ephemeral);

        // Serial also allows a non-COM string (no format gate — C# parity); still not HTTP rules.
        let mut serial_ip = QuickConnectState::new();
        serial_ip.set_protocol(ProtocolType::Serial);
        serial_ip.set_host("10.0.0.1");
        assert!(serial_ip.is_valid());

        // HTTP: IPv4 address is usable; port-only form is not.
        let mut http_ip = QuickConnectState::new();
        http_ip.set_protocol(ProtocolType::Http);
        http_ip.set_host("10.0.0.1");
        assert!(http_ip.is_valid());
        let (http_profile, _) = http_ip.try_build_ephemeral_profile().expect("http ip");
        assert_eq!(http_profile.host, "10.0.0.1");
        assert_eq!(http_profile.port, 80);

        // SSH: host field has no HTTP usability check (IP or DNS both OK).
        let mut ssh = QuickConnectState::new();
        ssh.set_host("10.0.0.1");
        assert!(ssh.is_valid());
        assert_eq!(ssh.target_field(), TargetField::Host);
    }

    #[test]
    fn switching_to_http_clears_stale_invalid_port() {
        let mut qc = QuickConnectState::new();
        qc.set_host("h");
        qc.set_port(Some(0));
        assert!(qc
            .validate()
            .errors
            .contains(&ValidationError::PortOutOfRange));

        qc.set_protocol(ProtocolType::Http);
        qc.set_host("10.0.0.1");
        assert_eq!(qc.port(), None);
        assert!(qc.is_valid());
    }

    #[test]
    fn vnc_ephemeral_profile_keeps_password_out_of_band() {
        let mut qc = QuickConnectState::new();
        qc.set_protocol(ProtocolType::Vnc);
        qc.set_host("vnc.example");
        qc.set_use_saved_credentials(false);
        qc.set_inline_password("vnc-secret");
        let (profile, password) = qc.try_build_ephemeral_profile().expect("vnc");
        assert!(profile.is_ephemeral);
        assert!(!profile.use_inline_password);
        assert_eq!(password.as_deref(), Some("vnc-secret"));
    }
}
