//! Tokio-based serial (COM) session for Wormhole.
//!
//! Settings map from [`wormhole_domain`] PuTTY-style enums (same numeric values
//! as C# `SerialParityMode` / `SerialStopBitsMode` / `SerialFlowControlMode`).
//! Session behavior mirrors `Services/Serial/SerialSession.cs`.
//! Port listing: [`list_serial_ports`] / [`SerialPortEnumerator`] (fakeable for tests).
//! Line presets: [`SerialLineCombo`] / [`BAUD_RATE_PRESETS`] (PuTTY 9600 8N1 defaults;
//! Win32 DCB stop/data pairing fail-closed — see `presets`).

mod enumerate;
mod error;
mod port;
mod presets;
mod session;
mod settings;

pub use enumerate::{
    is_valid_windows_com_port_name, list_serial_ports, list_serial_ports_with,
    normalize_serial_port_name, FakeSerialPortEnumerator, MemorySerialPortEnumerator,
    SerialPortEnumerator, SystemSerialPortEnumerator,
};
pub use error::SerialError;
pub use port::{SerialPortHandle, TokioSerialPort};
pub use presets::{
    apply_combo_to_connection_node, baud_preset_at, combo_from_connection_node,
    combo_from_optional_node_fields, data_bits_preset_at, flow_control_preset_at, parity_preset_at,
    stop_bits_preset_at, validate_serial_combo, FlowControlPreset, ParityPreset,
    SerialFieldInheritFlags, SerialLineCombo, StopBitPreset, BAUD_RATE_PRESETS, DATA_BIT_PRESETS,
    FLOW_CONTROL_PRESETS, PARITY_PRESETS, STOP_BIT_PRESETS,
};
pub use session::SerialSession;
pub use settings::{
    apply_settings_to_builder, open_builder, serial_settings_from_profile, FlowControlMapping,
    SerialLineSettings, SerialOpenOptions,
};

/// Crate-level result alias.
pub type Result<T> = std::result::Result<T, SerialError>;
