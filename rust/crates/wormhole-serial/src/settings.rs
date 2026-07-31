//! PuTTY-style serial line settings and tokio-serial mapping.
//!
//! Domain enums live in `wormhole-domain` (mirroring C#). This module normalizes
//! optional node fields and maps them onto `tokio_serial` / `serialport` types.

use tokio_serial::{DataBits, FlowControl, Parity, SerialPortBuilder, StopBits};
use wormhole_domain::{
    ConnectionProfile, SerialDefaults, SerialFlowControlMode, SerialParityMode, SerialStopBitsMode,
};

use crate::enumerate::normalize_serial_port_name;
use crate::error::SerialError;
use crate::Result;

/// Resolved serial line settings used to open a port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerialLineSettings {
    pub port_name: String,
    pub baud_rate: u32,
    pub data_bits: u8,
    pub stop_bits: SerialStopBitsMode,
    pub parity: SerialParityMode,
    pub flow_control: SerialFlowControlMode,
}

/// Options that mirror C# `SerialSessionService` open knobs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SerialOpenOptions {
    /// Assert DTR on open (C# sets `DtrEnable = true`).
    pub dtr_on_open: bool,
    /// Assert RTS when flow control is not RTS/CTS (C# sets `RtsEnable = true`).
    pub rts_when_not_hardware: bool,
}

impl Default for SerialOpenOptions {
    fn default() -> Self {
        Self {
            dtr_on_open: true,
            rts_when_not_hardware: true,
        }
    }
}

/// How Wormhole flow-control maps onto tokio-serial handshake + manual DSR/DTR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowControlMapping {
    pub handshake: FlowControl,
    /// When true, writes wait for DSR and pause/resume toggles DTR (C# `DsrDtr` path).
    pub manual_dsr_dtr: bool,
}

impl SerialLineSettings {
    /// Build settings from a resolved [`ConnectionProfile`].
    ///
    /// After [`SerialDefaults`] normalization, Win32 DCB stop/data pairing is
    /// validated via [`crate::validate_serial_combo`] (fail closed).
    pub fn from_profile(profile: &ConnectionProfile) -> Result<Self> {
        Self::from_optional(
            profile.host.as_str(),
            Some(profile.serial_baud_rate),
            Some(profile.serial_data_bits),
            Some(profile.serial_stop_bits),
            Some(profile.serial_parity),
            Some(profile.serial_flow_control),
        )
    }

    /// Parse/normalize optional node-style fields (null = default), matching C# `SerialDefaults`.
    ///
    /// Fail-closed on illegal baud / data / stop pairing after normalize.
    pub fn from_optional(
        port_name: impl Into<String>,
        baud_rate: Option<i32>,
        data_bits: Option<i32>,
        stop_bits: Option<SerialStopBitsMode>,
        parity: Option<SerialParityMode>,
        flow_control: Option<SerialFlowControlMode>,
    ) -> Result<Self> {
        let port_name = normalize_serial_port_name(&port_name.into())?;
        let baud_rate = SerialDefaults::normalize_baud_rate(baud_rate);
        let data_bits = SerialDefaults::normalize_data_bits(data_bits);
        let stop_bits = SerialDefaults::normalize_stop_bits(stop_bits);
        let parity = SerialDefaults::normalize_parity(parity);
        let flow_control = SerialDefaults::normalize_flow_control(flow_control);
        crate::presets::validate_serial_combo(baud_rate, data_bits, stop_bits)?;
        Ok(Self {
            port_name,
            baud_rate: baud_rate as u32,
            data_bits: data_bits as u8,
            stop_bits,
            parity,
            flow_control,
        })
    }

    pub fn flow_control_mapping(&self) -> FlowControlMapping {
        map_flow_control(self.flow_control)
    }

    pub fn tokio_data_bits(&self) -> Result<DataBits> {
        match self.data_bits {
            5 => Ok(DataBits::Five),
            6 => Ok(DataBits::Six),
            7 => Ok(DataBits::Seven),
            8 => Ok(DataBits::Eight),
            other => Err(SerialError::InvalidSettings(format!(
                "unsupported data bits {other}"
            ))),
        }
    }

    pub fn tokio_stop_bits(&self) -> StopBits {
        // `serialport` 4.x only exposes One/Two. Preserve OnePointFive in domain
        // settings (C# numeric value 3); approximate as Two at the OS layer until
        // a Windows DCB path can set 1.5 stop bits explicitly.
        match self.stop_bits {
            SerialStopBitsMode::Two | SerialStopBitsMode::OnePointFive => StopBits::Two,
            SerialStopBitsMode::One => StopBits::One,
        }
    }

    pub fn tokio_parity(&self) -> Parity {
        // `serialport` 4.x only exposes None/Odd/Even. Preserve Mark/Space in
        // domain settings (C# numeric parity) but approximate at the OS layer:
        // Markâ†’Odd, Spaceâ†’Even until a Windows-specific parity path exists.
        match self.parity {
            SerialParityMode::Odd | SerialParityMode::Mark => Parity::Odd,
            SerialParityMode::Even | SerialParityMode::Space => Parity::Even,
            SerialParityMode::None => Parity::None,
        }
    }
}

/// Convenience wrapper used by tests / callers.
pub fn serial_settings_from_profile(profile: &ConnectionProfile) -> Result<SerialLineSettings> {
    SerialLineSettings::from_profile(profile)
}

pub fn map_flow_control(mode: SerialFlowControlMode) -> FlowControlMapping {
    match mode {
        SerialFlowControlMode::XonXoff => FlowControlMapping {
            handshake: FlowControl::Software,
            manual_dsr_dtr: false,
        },
        SerialFlowControlMode::RtsCts => FlowControlMapping {
            handshake: FlowControl::Hardware,
            manual_dsr_dtr: false,
        },
        // C#: Handshake.None + manual DSR wait / DTR pause (DsrDtr) or plain None.
        SerialFlowControlMode::DsrDtr => FlowControlMapping {
            handshake: FlowControl::None,
            manual_dsr_dtr: true,
        },
        SerialFlowControlMode::None => FlowControlMapping {
            handshake: FlowControl::None,
            manual_dsr_dtr: false,
        },
    }
}

/// Apply resolved settings onto a [`SerialPortBuilder`].
///
/// DTR-on-open is applied by [`crate::SerialSession::open`] via [`SerialOpenOptions`], not here.
pub fn apply_settings_to_builder(
    builder: SerialPortBuilder,
    settings: &SerialLineSettings,
) -> Result<SerialPortBuilder> {
    let mapping = settings.flow_control_mapping();
    Ok(builder
        .baud_rate(settings.baud_rate)
        .data_bits(settings.tokio_data_bits()?)
        .parity(settings.tokio_parity())
        .stop_bits(settings.tokio_stop_bits())
        .flow_control(mapping.handshake))
}

/// Build a configured [`SerialPortBuilder`] for `settings.port_name`.
///
/// Re-validates the port name so a hand-built [`SerialLineSettings`] cannot bypass
/// [`normalize_serial_port_name`] and inject a hostile CreateFile path.
pub fn open_builder(settings: &SerialLineSettings) -> Result<SerialPortBuilder> {
    let port_name = normalize_serial_port_name(&settings.port_name)?;
    apply_settings_to_builder(tokio_serial::new(&port_name, settings.baud_rate), settings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wormhole_domain::ProtocolType;

    #[test]
    fn defaults_when_optional_fields_missing() {
        let s = SerialLineSettings::from_optional(
            "COM3",
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(s.port_name, "COM3");
        assert_eq!(s.baud_rate, 9600);
        assert_eq!(s.data_bits, 8);
        assert_eq!(s.stop_bits, SerialStopBitsMode::One);
        assert_eq!(s.parity, SerialParityMode::None);
        assert_eq!(s.flow_control, SerialFlowControlMode::None);
    }

    #[test]
    fn normalizes_invalid_baud_and_data_bits() {
        let s = SerialLineSettings::from_optional(
            r"\\.\COM10",
            Some(0),
            Some(9),
            Some(SerialStopBitsMode::Two),
            Some(SerialParityMode::Even),
            Some(SerialFlowControlMode::RtsCts),
        )
        .unwrap();
        assert_eq!(s.port_name, r"\\.\COM10");
        assert_eq!(s.baud_rate, 9600);
        assert_eq!(s.data_bits, 8);
        assert_eq!(s.stop_bits, SerialStopBitsMode::Two);
        assert_eq!(s.parity, SerialParityMode::Even);
        assert_eq!(s.flow_control, SerialFlowControlMode::RtsCts);
    }

    #[test]
    fn preserves_valid_putty_style_settings() {
        // 1.5 stop bits require 5 data bits (Win32 DCB).
        let s = SerialLineSettings::from_optional(
            "COM1",
            Some(115200),
            Some(5),
            Some(SerialStopBitsMode::OnePointFive),
            Some(SerialParityMode::Mark),
            Some(SerialFlowControlMode::DsrDtr),
        )
        .unwrap();
        assert_eq!(s.baud_rate, 115200);
        assert_eq!(s.data_bits, 5);
        assert_eq!(s.stop_bits, SerialStopBitsMode::OnePointFive);
        assert_eq!(s.parity, SerialParityMode::Mark);
        assert_eq!(s.flow_control, SerialFlowControlMode::DsrDtr);
        let mapping = s.flow_control_mapping();
        assert_eq!(mapping.handshake, FlowControl::None);
        assert!(mapping.manual_dsr_dtr);
    }

    #[test]
    fn rejects_illegal_stop_data_combo_after_normalize() {
        let err = SerialLineSettings::from_optional(
            "COM1",
            Some(9600),
            Some(8),
            Some(SerialStopBitsMode::OnePointFive),
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, SerialError::InvalidSettings(_)));
    }

    #[test]
    fn numeric_enum_values_match_csharp() {
        assert_eq!(SerialParityMode::None.as_i32(), 0);
        assert_eq!(SerialParityMode::Odd.as_i32(), 1);
        assert_eq!(SerialParityMode::Even.as_i32(), 2);
        assert_eq!(SerialParityMode::Mark.as_i32(), 3);
        assert_eq!(SerialParityMode::Space.as_i32(), 4);
        assert_eq!(SerialStopBitsMode::One.as_i32(), 1);
        assert_eq!(SerialStopBitsMode::Two.as_i32(), 2);
        assert_eq!(SerialStopBitsMode::OnePointFive.as_i32(), 3);
        assert_eq!(SerialFlowControlMode::None.as_i32(), 0);
        assert_eq!(SerialFlowControlMode::XonXoff.as_i32(), 1);
        assert_eq!(SerialFlowControlMode::RtsCts.as_i32(), 2);
        assert_eq!(SerialFlowControlMode::DsrDtr.as_i32(), 3);
    }

    #[test]
    fn maps_to_tokio_serial_types() {
        let s = SerialLineSettings::from_optional(
            "COM1",
            Some(57600),
            Some(8),
            Some(SerialStopBitsMode::One),
            Some(SerialParityMode::None),
            Some(SerialFlowControlMode::XonXoff),
        )
        .unwrap();
        assert_eq!(s.tokio_data_bits().unwrap(), DataBits::Eight);
        assert_eq!(s.tokio_stop_bits(), StopBits::One);
        assert_eq!(s.tokio_parity(), Parity::None);
        assert_eq!(s.flow_control_mapping().handshake, FlowControl::Software);

        let builder = open_builder(&s).unwrap();
        // Builder is opaque; constructing it without error is the compile/runtime check.
        let _ = builder;
    }

    #[test]
    fn approximates_mark_space_and_one_point_five_at_os_layer() {
        let s = SerialLineSettings::from_optional(
            "COM1",
            Some(9600),
            Some(5),
            Some(SerialStopBitsMode::OnePointFive),
            Some(SerialParityMode::Mark),
            Some(SerialFlowControlMode::None),
        )
        .unwrap();
        assert_eq!(s.tokio_stop_bits(), StopBits::Two);
        assert_eq!(s.tokio_parity(), Parity::Odd);

        let s2 = SerialLineSettings::from_optional(
            "COM1",
            Some(9600),
            Some(8),
            Some(SerialStopBitsMode::One),
            Some(SerialParityMode::Space),
            None,
        )
        .unwrap();
        assert_eq!(s2.tokio_parity(), Parity::Even);
    }

    #[test]
    fn from_profile_trims_host() {
        let mut profile = ConnectionProfile::default();
        profile.protocol = ProtocolType::Serial;
        profile.host = "  COM4  ".into();
        profile.serial_baud_rate = 19200;
        profile.serial_data_bits = 8;
        profile.serial_stop_bits = SerialStopBitsMode::One;
        profile.serial_parity = SerialParityMode::Odd;
        profile.serial_flow_control = SerialFlowControlMode::XonXoff;
        let s = serial_settings_from_profile(&profile).unwrap();
        assert_eq!(s.port_name, "COM4");
        assert_eq!(s.baud_rate, 19200);
        assert_eq!(s.parity, SerialParityMode::Odd);
    }

    #[test]
    fn rejects_empty_port_name() {
        let err = SerialLineSettings::from_optional("  ", None, None, None, None, None).unwrap_err();
        assert!(matches!(err, SerialError::InvalidSettings(_)));
    }

    #[test]
    fn rejects_hostile_port_name_before_open() {
        let err = SerialLineSettings::from_optional(
            r"\\.\pipe\not-a-com",
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, SerialError::InvalidSettings(_)));

        let mut hostile = SerialLineSettings::from_optional(
            "COM1",
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        hostile.port_name = r"C:\Windows\win.ini".into();
        let err = open_builder(&hostile).unwrap_err();
        assert!(matches!(err, SerialError::InvalidSettings(_)));
    }
}
