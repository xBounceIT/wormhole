//! PuTTY-style serial line presets and combo validation.
//!
//! Catalogs mirror the connection-editor Serial tab choices in
//! `ViewModels/ConnectionEditorViewModel.cs` (data / stop / parity / flow) plus a
//! PuTTY Speed dropdown subset for baud. Defaults match [`SerialDefaults`]
//! (`Models/SerialSettings.cs`): **9600 8N1, no flow control**.
//!
//! Win32 DCB rules enforced here (fail closed — never coerce):
//! - baud rate must be `> 0`
//! - data bits must be `5..=8`
//! - 1.5 stop bits only with 5 data bits
//! - 2 stop bits only with 6/7/8 data bits
//!
//! No live port open — pure value mapping for UI / node glue.

use wormhole_domain::{
    ConnectionNode, SerialDefaults, SerialFlowControlMode, SerialParityMode, SerialStopBitsMode,
};

use crate::error::SerialError;
use crate::Result;

/// PuTTY Serial config Speed dropdown rates (common subset). Custom baud outside
/// this list remains valid when set numerically (C# NumberBox path).
pub const BAUD_RATE_PRESETS: &[i32] = &[
    110, 300, 600, 1200, 2400, 4800, 9600, 14400, 19200, 38400, 57600, 115200, 230400, 460800,
    921600,
];

/// Editor data-bits combo (`SerialDataBitChoices`).
pub const DATA_BIT_PRESETS: &[i32] = &[5, 6, 7, 8];

/// Labeled stop-bits choice for combo chrome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StopBitPreset {
    pub mode: SerialStopBitsMode,
    pub label: &'static str,
}

/// Editor stop-bits combo (`SerialStopBitChoices`).
pub const STOP_BIT_PRESETS: &[StopBitPreset] = &[
    StopBitPreset {
        mode: SerialStopBitsMode::One,
        label: "1",
    },
    StopBitPreset {
        mode: SerialStopBitsMode::OnePointFive,
        label: "1.5",
    },
    StopBitPreset {
        mode: SerialStopBitsMode::Two,
        label: "2",
    },
];

/// Labeled parity choice for combo chrome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParityPreset {
    pub mode: SerialParityMode,
    pub label: &'static str,
}

/// Editor parity combo (`SerialParityChoices`).
pub const PARITY_PRESETS: &[ParityPreset] = &[
    ParityPreset {
        mode: SerialParityMode::None,
        label: "None",
    },
    ParityPreset {
        mode: SerialParityMode::Odd,
        label: "Odd",
    },
    ParityPreset {
        mode: SerialParityMode::Even,
        label: "Even",
    },
    ParityPreset {
        mode: SerialParityMode::Mark,
        label: "Mark",
    },
    ParityPreset {
        mode: SerialParityMode::Space,
        label: "Space",
    },
];

/// Labeled flow-control choice for combo chrome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowControlPreset {
    pub mode: SerialFlowControlMode,
    pub label: &'static str,
}

/// Editor flow-control combo (`SerialFlowControlChoices`).
pub const FLOW_CONTROL_PRESETS: &[FlowControlPreset] = &[
    FlowControlPreset {
        mode: SerialFlowControlMode::None,
        label: "None",
    },
    FlowControlPreset {
        mode: SerialFlowControlMode::XonXoff,
        label: "XON/XOFF",
    },
    FlowControlPreset {
        mode: SerialFlowControlMode::RtsCts,
        label: "RTS/CTS",
    },
    FlowControlPreset {
        mode: SerialFlowControlMode::DsrDtr,
        label: "DSR/DTR",
    },
];

/// Concrete serial line combo (resolved values, no inherit flags).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SerialLineCombo {
    pub baud_rate: i32,
    pub data_bits: i32,
    pub stop_bits: SerialStopBitsMode,
    pub parity: SerialParityMode,
    pub flow_control: SerialFlowControlMode,
}

impl SerialLineCombo {
    /// PuTTY / Wormhole defaults: 9600 8N1, flow None.
    pub const fn putty_defaults() -> Self {
        Self {
            baud_rate: SerialDefaults::BAUD_RATE,
            data_bits: SerialDefaults::DATA_BITS,
            stop_bits: SerialDefaults::STOP_BITS,
            parity: SerialDefaults::PARITY,
            flow_control: SerialDefaults::FLOW_CONTROL,
        }
    }

    /// Validate baud / data bits / stop-bits pairing (fail closed — no coerce).
    ///
    /// Parity / flow are closed enums and are not range-checked here.
    pub fn validate(self) -> Result<Self> {
        validate_serial_combo(self.baud_rate, self.data_bits, self.stop_bits)?;
        Ok(self)
    }

    /// Index into [`BAUD_RATE_PRESETS`], or `None` when baud is a custom rate.
    pub fn baud_preset_index(self) -> Option<usize> {
        BAUD_RATE_PRESETS.iter().position(|&b| b == self.baud_rate)
    }

    pub fn data_bits_preset_index(self) -> Option<usize> {
        DATA_BIT_PRESETS.iter().position(|&b| b == self.data_bits)
    }

    pub fn stop_bits_preset_index(self) -> Option<usize> {
        STOP_BIT_PRESETS
            .iter()
            .position(|p| p.mode == self.stop_bits)
    }

    pub fn parity_preset_index(self) -> Option<usize> {
        PARITY_PRESETS.iter().position(|p| p.mode == self.parity)
    }

    pub fn flow_control_preset_index(self) -> Option<usize> {
        FLOW_CONTROL_PRESETS
            .iter()
            .position(|p| p.mode == self.flow_control)
    }
}

/// Fail closed when baud / data / stop pairing is illegal for Win32 DCB.
pub fn validate_serial_combo(
    baud_rate: i32,
    data_bits: i32,
    stop_bits: SerialStopBitsMode,
) -> Result<()> {
    if baud_rate <= 0 {
        return Err(SerialError::InvalidSettings(format!(
            "baud rate must be > 0 (got {baud_rate})"
        )));
    }
    if !(5..=8).contains(&data_bits) {
        return Err(SerialError::InvalidSettings(format!(
            "data bits must be 5..=8 (got {data_bits})"
        )));
    }
    match stop_bits {
        SerialStopBitsMode::OnePointFive if data_bits != 5 => {
            Err(SerialError::InvalidSettings(
                "1.5 stop bits require 5 data bits".into(),
            ))
        }
        SerialStopBitsMode::Two if data_bits == 5 => Err(SerialError::InvalidSettings(
            "2 stop bits are invalid with 5 data bits (use 1.5)".into(),
        )),
        SerialStopBitsMode::One | SerialStopBitsMode::OnePointFive | SerialStopBitsMode::Two => {
            Ok(())
        }
    }
}

/// Lookup helpers — OOB / unknown → `None` (caller fail-closes).
pub fn baud_preset_at(index: usize) -> Option<i32> {
    BAUD_RATE_PRESETS.get(index).copied()
}

pub fn data_bits_preset_at(index: usize) -> Option<i32> {
    DATA_BIT_PRESETS.get(index).copied()
}

pub fn stop_bits_preset_at(index: usize) -> Option<SerialStopBitsMode> {
    STOP_BIT_PRESETS.get(index).map(|p| p.mode)
}

pub fn parity_preset_at(index: usize) -> Option<SerialParityMode> {
    PARITY_PRESETS.get(index).map(|p| p.mode)
}

pub fn flow_control_preset_at(index: usize) -> Option<SerialFlowControlMode> {
    FLOW_CONTROL_PRESETS.get(index).map(|p| p.mode)
}

/// Build a combo from optional node fields, applying [`SerialDefaults`] normalizers,
/// then **validate** (fail closed — normalized-but-illegal stop/data pairs still Err).
pub fn combo_from_optional_node_fields(
    baud_rate: Option<i32>,
    data_bits: Option<i32>,
    stop_bits: Option<SerialStopBitsMode>,
    parity: Option<SerialParityMode>,
    flow_control: Option<SerialFlowControlMode>,
) -> Result<SerialLineCombo> {
    let combo = SerialLineCombo {
        baud_rate: SerialDefaults::normalize_baud_rate(baud_rate),
        data_bits: SerialDefaults::normalize_data_bits(data_bits),
        stop_bits: SerialDefaults::normalize_stop_bits(stop_bits),
        parity: SerialDefaults::normalize_parity(parity),
        flow_control: SerialDefaults::normalize_flow_control(flow_control),
    };
    combo.validate()
}

/// Read serial fields from a [`ConnectionNode`] (null → PuTTY defaults via normalizers).
pub fn combo_from_connection_node(node: &ConnectionNode) -> Result<SerialLineCombo> {
    combo_from_optional_node_fields(
        node.serial_baud_rate,
        node.serial_data_bits,
        node.serial_stop_bits,
        node.serial_parity,
        node.serial_flow_control,
    )
}

/// Inherit flags for writing optional node fields (`None` = inherit).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SerialFieldInheritFlags {
    pub baud_rate: bool,
    pub data_bits: bool,
    pub stop_bits: bool,
    pub parity: bool,
    pub flow_control: bool,
}

impl SerialFieldInheritFlags {
    pub const fn all_inherit() -> Self {
        Self {
            baud_rate: true,
            data_bits: true,
            stop_bits: true,
            parity: true,
            flow_control: true,
        }
    }

    pub const fn none_inherit() -> Self {
        Self {
            baud_rate: false,
            data_bits: false,
            stop_bits: false,
            parity: false,
            flow_control: false,
        }
    }
}

/// Write a **validated** combo onto a node's serial_* fields.
///
/// Returns `Err` without mutating when the combo is illegal. Inherit `true` → `None`
/// on that field (folder inheritance); otherwise stores the concrete value.
pub fn apply_combo_to_connection_node(
    node: &mut ConnectionNode,
    combo: SerialLineCombo,
    inherits: SerialFieldInheritFlags,
) -> Result<()> {
    let combo = combo.validate()?;
    node.serial_baud_rate = (!inherits.baud_rate).then_some(combo.baud_rate);
    node.serial_data_bits = (!inherits.data_bits).then_some(combo.data_bits);
    node.serial_stop_bits = (!inherits.stop_bits).then_some(combo.stop_bits);
    node.serial_parity = (!inherits.parity).then_some(combo.parity);
    node.serial_flow_control = (!inherits.flow_control).then_some(combo.flow_control);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wormhole_domain::ProtocolType;

    #[test]
    fn putty_defaults_are_9600_8n1_no_flow() {
        let d = SerialLineCombo::putty_defaults();
        assert_eq!(d.baud_rate, 9600);
        assert_eq!(d.data_bits, 8);
        assert_eq!(d.stop_bits, SerialStopBitsMode::One);
        assert_eq!(d.parity, SerialParityMode::None);
        assert_eq!(d.flow_control, SerialFlowControlMode::None);
        assert!(d.validate().is_ok());
    }

    #[test]
    fn baud_presets_include_putty_default() {
        assert!(BAUD_RATE_PRESETS.contains(&SerialDefaults::BAUD_RATE));
        assert_eq!(baud_preset_at(6), Some(9600));
        assert!(baud_preset_at(99).is_none());
    }

    #[test]
    fn labeled_presets_match_csharp_editor_choices() {
        assert_eq!(DATA_BIT_PRESETS, &[5, 6, 7, 8]);
        assert_eq!(STOP_BIT_PRESETS[0].label, "1");
        assert_eq!(STOP_BIT_PRESETS[1].label, "1.5");
        assert_eq!(STOP_BIT_PRESETS[2].label, "2");
        assert_eq!(PARITY_PRESETS[0].label, "None");
        assert_eq!(PARITY_PRESETS[3].mode, SerialParityMode::Mark);
        assert_eq!(FLOW_CONTROL_PRESETS[1].label, "XON/XOFF");
        assert_eq!(FLOW_CONTROL_PRESETS[3].mode, SerialFlowControlMode::DsrDtr);
    }

    #[test]
    fn rejects_invalid_baud_and_data_bits() {
        assert!(validate_serial_combo(0, 8, SerialStopBitsMode::One).is_err());
        assert!(validate_serial_combo(-1, 8, SerialStopBitsMode::One).is_err());
        assert!(validate_serial_combo(9600, 4, SerialStopBitsMode::One).is_err());
        assert!(validate_serial_combo(9600, 9, SerialStopBitsMode::One).is_err());
    }

    #[test]
    fn fail_closed_on_illegal_stop_data_combos() {
        // 1.5 only with 5 data bits
        assert!(validate_serial_combo(9600, 8, SerialStopBitsMode::OnePointFive).is_err());
        assert!(validate_serial_combo(9600, 5, SerialStopBitsMode::OnePointFive).is_ok());
        // 2 stop bits invalid with 5 data bits
        assert!(validate_serial_combo(9600, 5, SerialStopBitsMode::Two).is_err());
        assert!(validate_serial_combo(9600, 8, SerialStopBitsMode::Two).is_ok());
    }

    #[test]
    fn normalize_then_validate_rejects_stored_illegal_pair() {
        // Normalizers alone would accept these enums; combo validate fail-closes.
        let err = combo_from_optional_node_fields(
            Some(9600),
            Some(8),
            Some(SerialStopBitsMode::OnePointFive),
            Some(SerialParityMode::None),
            Some(SerialFlowControlMode::None),
        )
        .unwrap_err();
        assert!(matches!(err, SerialError::InvalidSettings(_)));
    }

    #[test]
    fn node_round_trip_concrete_and_inherit() {
        let mut node = ConnectionNode::default();
        node.protocol = Some(ProtocolType::Serial);
        let combo = SerialLineCombo {
            baud_rate: 115200,
            data_bits: 7,
            stop_bits: SerialStopBitsMode::One,
            parity: SerialParityMode::Even,
            flow_control: SerialFlowControlMode::XonXoff,
        };
        apply_combo_to_connection_node(&mut node, combo, SerialFieldInheritFlags::none_inherit())
            .unwrap();
        assert_eq!(node.serial_baud_rate, Some(115200));
        assert_eq!(node.serial_data_bits, Some(7));
        assert_eq!(node.serial_stop_bits, Some(SerialStopBitsMode::One));
        assert_eq!(node.serial_parity, Some(SerialParityMode::Even));
        assert_eq!(
            node.serial_flow_control,
            Some(SerialFlowControlMode::XonXoff)
        );

        let loaded = combo_from_connection_node(&node).unwrap();
        assert_eq!(loaded, combo);

        apply_combo_to_connection_node(&mut node, combo, SerialFieldInheritFlags::all_inherit())
            .unwrap();
        assert_eq!(node.serial_baud_rate, None);
        assert_eq!(node.serial_data_bits, None);
        assert_eq!(node.serial_stop_bits, None);
        assert_eq!(node.serial_parity, None);
        assert_eq!(node.serial_flow_control, None);

        // Null fields → PuTTY defaults after normalize.
        let defaults = combo_from_connection_node(&node).unwrap();
        assert_eq!(defaults, SerialLineCombo::putty_defaults());
    }

    #[test]
    fn apply_combo_does_not_mutate_on_invalid() {
        let mut node = ConnectionNode::default();
        node.serial_baud_rate = Some(19200);
        let bad = SerialLineCombo {
            baud_rate: 9600,
            data_bits: 8,
            stop_bits: SerialStopBitsMode::OnePointFive,
            parity: SerialParityMode::None,
            flow_control: SerialFlowControlMode::None,
        };
        assert!(
            apply_combo_to_connection_node(&mut node, bad, SerialFieldInheritFlags::none_inherit())
                .is_err()
        );
        assert_eq!(node.serial_baud_rate, Some(19200));
    }

    #[test]
    fn custom_baud_outside_presets_is_allowed() {
        let combo = SerialLineCombo {
            baud_rate: 1000000,
            data_bits: 8,
            stop_bits: SerialStopBitsMode::One,
            parity: SerialParityMode::None,
            flow_control: SerialFlowControlMode::None,
        };
        assert!(combo.validate().is_ok());
        assert!(combo.baud_preset_index().is_none());
    }
}
