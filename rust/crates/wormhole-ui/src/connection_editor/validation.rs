//! Validation matrix for the connection editor.

use wormhole_domain::ProtocolType;
use wormhole_serial::validate_serial_combo;

use super::http_address::{is_usable_http_host, parse_http_address};
use super::rdp_drives;
use super::state::{ConnectionEditorMode, ConnectionEditorState, RdpDriveRedirectMode};

/// Individual validation failures (order is stable for tests / UI).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValidationError {
    NameRequired,
    /// Network host / HTTP address / serial COM line is blank.
    HostRequired,
    PortOutOfRange,
    HttpAddressInvalid,
    SerialBaudInvalid,
    SerialDataBitsInvalid,
    /// Win32 DCB: 1.5 stop only with 5 data bits; 2 stop invalid with 5 data bits.
    SerialStopDataComboInvalid,
    GatewayHostnameRequired,
    CustomDriveListInvalid,
}

impl ValidationError {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NameRequired => "Name is required.",
            Self::HostRequired => "Host is required.",
            Self::PortOutOfRange => "Port must be between 1 and 65535.",
            Self::HttpAddressInvalid => {
                "Enter a valid host or IP — optionally with a port, e.g. 10.0.0.1:8443."
            }
            Self::SerialBaudInvalid => "Baud rate must be greater than 0.",
            Self::SerialDataBitsInvalid => "Data bits must be between 5 and 8.",
            Self::SerialStopDataComboInvalid => {
                "Stop bits are not valid with the selected data bits."
            }
            Self::GatewayHostnameRequired => "RD Gateway hostname is required.",
            Self::CustomDriveListInvalid => "Custom drive list is invalid.",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ValidationReport {
    pub errors: Vec<ValidationError>,
}

impl ValidationReport {
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

impl ConnectionEditorState {
    pub fn validate(&self) -> ValidationReport {
        let mut errors = Vec::new();
        let is_serial = self.protocol == ProtocolType::Serial;
        let is_http = matches!(
            self.protocol,
            ProtocolType::Http | ProtocolType::Https
        );
        let is_rdp = self.protocol == ProtocolType::Rdp;

        if self.mode == ConnectionEditorMode::Persistent && self.name.trim().is_empty() {
            errors.push(ValidationError::NameRequired);
        }

        // Host / address / COM line: always required (serial uses the Host field for COM*).
        if self.host.trim().is_empty() {
            errors.push(ValidationError::HostRequired);
        }

        if is_http && !self.host.trim().is_empty() {
            let (parsed_host, _) = parse_http_address(&self.host);
            if parsed_host.is_empty() || !is_usable_http_host(&parsed_host) {
                errors.push(ValidationError::HttpAddressInvalid);
            }
        }

        // Null port = protocol default / inherit — only reject an explicit out-of-range value.
        // Serial ignores the network Port box (COM line owns Host). HTTP(S) hides the Port box
        // but still validates a vestigial `port` value — C# `IsValid` uses `!IsSerial` only.
        if !is_serial
            && let Some(port) = self.port
            && !(1..=65535).contains(&port)
        {
            errors.push(ValidationError::PortOutOfRange);
        }

        if is_serial && !self.serial_baud_rate_inherits && self.serial_baud_rate <= 0 {
            errors.push(ValidationError::SerialBaudInvalid);
        }
        if is_serial
            && !self.serial_data_bits_inherits
            && !(5..=8).contains(&self.serial_data_bits)
        {
            errors.push(ValidationError::SerialDataBitsInvalid);
        }
        // Match write_editor_serial_to_node: all-inherit skips DCB; otherwise fail-closed
        // on illegal stop/data (and baud) pairing of the display values.
        if is_serial
            && !crate::serial_presets::editor_serial_all_inherit(self)
            && self.serial_baud_rate > 0
            && (5..=8).contains(&self.serial_data_bits)
            && validate_serial_combo(
                self.serial_baud_rate,
                self.serial_data_bits,
                self.serial_stop_bits,
            )
            .is_err()
        {
            errors.push(ValidationError::SerialStopDataComboInvalid);
        }

        if is_rdp {
            if self.rdp_gateway_usage_method == 1 && self.rdp_gateway_hostname.trim().is_empty()
            {
                errors.push(ValidationError::GatewayHostnameRequired);
            }
            if self.rdp_drive_redirect_mode == RdpDriveRedirectMode::Custom
                && rdp_drives::validate(&self.rdp_custom_drive_list).is_some()
            {
                errors.push(ValidationError::CustomDriveListInvalid);
            }
        }

        ValidationReport { errors }
    }

    pub fn is_valid(&self) -> bool {
        self.validate().is_valid()
    }
}
