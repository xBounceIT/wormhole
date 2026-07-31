use crate::enums::{SerialFlowControlMode, SerialParityMode, SerialStopBitsMode};

/// PuTTY-style serial defaults and normalizers (`Wormhole.Models.SerialDefaults`).
pub struct SerialDefaults;

impl SerialDefaults {
    pub const BAUD_RATE: i32 = 9600;
    pub const DATA_BITS: i32 = 8;
    pub const STOP_BITS: SerialStopBitsMode = SerialStopBitsMode::One;
    pub const PARITY: SerialParityMode = SerialParityMode::None;
    pub const FLOW_CONTROL: SerialFlowControlMode = SerialFlowControlMode::None;

    pub fn normalize_baud_rate(value: Option<i32>) -> i32 {
        match value {
            Some(v) if v > 0 => v,
            _ => Self::BAUD_RATE,
        }
    }

    pub fn normalize_data_bits(value: Option<i32>) -> i32 {
        match value {
            Some(v) if (5..=8).contains(&v) => v,
            _ => Self::DATA_BITS,
        }
    }

    /// C# also rejects out-of-range cast values; Rust enums cannot hold those, so `None` is the
    /// only fallback path here (invalid wire values are rejected by `TryFrom<i32>` first).
    pub fn normalize_stop_bits(value: Option<SerialStopBitsMode>) -> SerialStopBitsMode {
        value.unwrap_or(Self::STOP_BITS)
    }

    pub fn normalize_parity(value: Option<SerialParityMode>) -> SerialParityMode {
        value.unwrap_or(Self::PARITY)
    }

    pub fn normalize_flow_control(value: Option<SerialFlowControlMode>) -> SerialFlowControlMode {
        value.unwrap_or(Self::FLOW_CONTROL)
    }
}
