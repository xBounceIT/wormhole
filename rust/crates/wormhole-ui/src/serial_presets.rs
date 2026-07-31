//! Serial baud / data / stop / parity / flow preset → editor / node glue.
//!
//! Thin pure-Rust bridge over [`wormhole_serial`] preset catalogs. Maps combo
//! selections into [`ConnectionEditorState`] serial fields (and optional
//! [`ConnectionNode`] writes). No GPUI chrome and no live `SerialPort` open.
//!
//! Fail-closed rules:
//! - non-Serial protocol → no mutation
//! - out-of-range preset index → no mutation
//! - resulting baud/data/stop combo illegal (Win32 DCB) → no mutation
//!
//! PuTTY-style defaults (9600 8N1, flow None) live in
//! [`wormhole_serial::SerialLineCombo::putty_defaults`].

use wormhole_domain::{ConnectionNode, ProtocolType};
use wormhole_serial::{
    apply_combo_to_connection_node, baud_preset_at, combo_from_optional_node_fields,
    data_bits_preset_at, flow_control_preset_at, parity_preset_at, stop_bits_preset_at,
    validate_serial_combo, SerialFieldInheritFlags, SerialLineCombo, BAUD_RATE_PRESETS,
    DATA_BIT_PRESETS, FLOW_CONTROL_PRESETS, PARITY_PRESETS, STOP_BIT_PRESETS,
};

use crate::connection_editor::ConnectionEditorState;
use crate::quick_connect::QuickConnectState;

/// Re-export catalogs for editor chrome bindings (no GPUI required).
pub use wormhole_serial::{
    FlowControlPreset, ParityPreset, StopBitPreset, BAUD_RATE_PRESETS as SERIAL_BAUD_PRESETS,
    DATA_BIT_PRESETS as SERIAL_DATA_BIT_PRESETS, FLOW_CONTROL_PRESETS as SERIAL_FLOW_PRESETS,
    PARITY_PRESETS as SERIAL_PARITY_PRESETS, STOP_BIT_PRESETS as SERIAL_STOP_BIT_PRESETS,
};

fn require_serial(editor: &ConnectionEditorState) -> bool {
    editor.protocol == ProtocolType::Serial
}

fn inherits_from_editor(editor: &ConnectionEditorState) -> SerialFieldInheritFlags {
    SerialFieldInheritFlags {
        baud_rate: editor.serial_baud_rate_inherits,
        data_bits: editor.serial_data_bits_inherits,
        stop_bits: editor.serial_stop_bits_inherits,
        parity: editor.serial_parity_inherits,
        flow_control: editor.serial_flow_control_inherits,
    }
}

/// Snapshot editor serial fields into a validated combo.
///
/// Returns `None` when the current baud/data/stop pairing is illegal (fail closed
/// for chrome that needs a coherent display value).
pub fn combo_from_editor(editor: &ConnectionEditorState) -> Option<SerialLineCombo> {
    SerialLineCombo {
        baud_rate: editor.serial_baud_rate,
        data_bits: editor.serial_data_bits,
        stop_bits: editor.serial_stop_bits,
        parity: editor.serial_parity,
        flow_control: editor.serial_flow_control,
    }
    .validate()
    .ok()
}

/// Apply a full validated combo to the editor (clears inherit flags for each field).
///
/// Fail-closed when protocol is not Serial or the combo is illegal (editor unchanged).
pub fn apply_combo_to_editor(editor: &mut ConnectionEditorState, combo: SerialLineCombo) -> bool {
    if !require_serial(editor) {
        return false;
    }
    let Ok(combo) = combo.validate() else {
        return false;
    };
    editor.serial_baud_rate = combo.baud_rate;
    editor.serial_baud_rate_inherits = false;
    editor.serial_data_bits = combo.data_bits;
    editor.serial_data_bits_inherits = false;
    editor.serial_stop_bits = combo.stop_bits;
    editor.serial_stop_bits_inherits = false;
    editor.serial_parity = combo.parity;
    editor.serial_parity_inherits = false;
    editor.serial_flow_control = combo.flow_control;
    editor.serial_flow_control_inherits = false;
    true
}

/// Seed editor serial fields from PuTTY defaults (9600 8N1, flow None).
pub fn apply_putty_defaults_to_editor(editor: &mut ConnectionEditorState) -> bool {
    apply_combo_to_editor(editor, SerialLineCombo::putty_defaults())
}

/// Set a custom baud (C# NumberBox path). Fail-closed when `baud <= 0` or non-Serial.
pub fn set_custom_baud(editor: &mut ConnectionEditorState, baud: i32) -> bool {
    if !require_serial(editor) {
        return false;
    }
    if validate_serial_combo(baud, editor.serial_data_bits, editor.serial_stop_bits).is_err() {
        return false;
    }
    editor.serial_baud_rate = baud;
    editor.serial_baud_rate_inherits = false;
    true
}

/// Set concrete data bits. Fail-closed when out of range / illegal with current stop bits.
pub fn set_custom_data_bits(editor: &mut ConnectionEditorState, data_bits: i32) -> bool {
    if !require_serial(editor) {
        return false;
    }
    if validate_serial_combo(editor.serial_baud_rate, data_bits, editor.serial_stop_bits).is_err()
    {
        return false;
    }
    editor.serial_data_bits = data_bits;
    editor.serial_data_bits_inherits = false;
    true
}

/// Set concrete stop bits. Fail-closed when illegal with current data bits.
pub fn set_custom_stop_bits(
    editor: &mut ConnectionEditorState,
    stop_bits: wormhole_domain::SerialStopBitsMode,
) -> bool {
    if !require_serial(editor) {
        return false;
    }
    if validate_serial_combo(editor.serial_baud_rate, editor.serial_data_bits, stop_bits).is_err() {
        return false;
    }
    editor.serial_stop_bits = stop_bits;
    editor.serial_stop_bits_inherits = false;
    true
}

/// True when every serial inherit checkbox is set (DCB display validate is skipped on write).
pub fn editor_serial_all_inherit(editor: &ConnectionEditorState) -> bool {
    editor.serial_baud_rate_inherits
        && editor.serial_data_bits_inherits
        && editor.serial_stop_bits_inherits
        && editor.serial_parity_inherits
        && editor.serial_flow_control_inherits
}

/// Select a baud preset by index. Fail-closed on OOB / non-Serial.
///
/// Does not change data/stop/parity/flow. Clears baud inherit.
pub fn select_baud_preset(editor: &mut ConnectionEditorState, index: usize) -> bool {
    let Some(baud) = baud_preset_at(index) else {
        return false;
    };
    set_custom_baud(editor, baud)
}

/// Select data-bits preset by index. Fail-closed when OOB, non-Serial, or the new
/// data bits would make the current stop-bits illegal.
pub fn select_data_bits_preset(editor: &mut ConnectionEditorState, index: usize) -> bool {
    let Some(data_bits) = data_bits_preset_at(index) else {
        return false;
    };
    set_custom_data_bits(editor, data_bits)
}

/// Select stop-bits preset by index. Fail-closed when OOB / non-Serial / illegal with current data bits.
pub fn select_stop_bits_preset(editor: &mut ConnectionEditorState, index: usize) -> bool {
    let Some(stop_bits) = stop_bits_preset_at(index) else {
        return false;
    };
    set_custom_stop_bits(editor, stop_bits)
}

/// Select parity preset by index. Fail-closed on OOB / non-Serial.
pub fn select_parity_preset(editor: &mut ConnectionEditorState, index: usize) -> bool {
    if !require_serial(editor) {
        return false;
    }
    let Some(parity) = parity_preset_at(index) else {
        return false;
    };
    editor.serial_parity = parity;
    editor.serial_parity_inherits = false;
    true
}

/// Select flow-control preset by index. Fail-closed on OOB / non-Serial.
pub fn select_flow_control_preset(editor: &mut ConnectionEditorState, index: usize) -> bool {
    if !require_serial(editor) {
        return false;
    }
    let Some(flow) = flow_control_preset_at(index) else {
        return false;
    };
    editor.serial_flow_control = flow;
    editor.serial_flow_control_inherits = false;
    true
}

/// Quick Connect: same fail-closed rules via the embedded editor.
pub fn select_baud_preset_qc(qc: &mut QuickConnectState, index: usize) -> bool {
    select_baud_preset(qc.editor_mut(), index)
}

pub fn select_data_bits_preset_qc(qc: &mut QuickConnectState, index: usize) -> bool {
    select_data_bits_preset(qc.editor_mut(), index)
}

pub fn select_stop_bits_preset_qc(qc: &mut QuickConnectState, index: usize) -> bool {
    select_stop_bits_preset(qc.editor_mut(), index)
}

pub fn select_parity_preset_qc(qc: &mut QuickConnectState, index: usize) -> bool {
    select_parity_preset(qc.editor_mut(), index)
}

pub fn select_flow_control_preset_qc(qc: &mut QuickConnectState, index: usize) -> bool {
    select_flow_control_preset(qc.editor_mut(), index)
}

/// Write editor serial fields onto a node using current inherit checkboxes.
///
/// Fail-closed when protocol is not Serial or the concrete (non-inheriting) combo
/// is illegal — node serial fields unchanged on `false`.
pub fn write_editor_serial_to_node(
    editor: &ConnectionEditorState,
    node: &mut ConnectionNode,
) -> bool {
    if !require_serial(editor) {
        return false;
    }
    let inherits = inherits_from_editor(editor);
    // When every field inherits, skip validate of display values — node gets all None.
    if editor_serial_all_inherit(editor) {
        node.serial_baud_rate = None;
        node.serial_data_bits = None;
        node.serial_stop_bits = None;
        node.serial_parity = None;
        node.serial_flow_control = None;
        return true;
    }
    // Validate the concrete values that will be stored (and display values for
    // inheriting slots — still must form a legal DCB if mixed inherit).
    let combo = SerialLineCombo {
        baud_rate: editor.serial_baud_rate,
        data_bits: editor.serial_data_bits,
        stop_bits: editor.serial_stop_bits,
        parity: editor.serial_parity,
        flow_control: editor.serial_flow_control,
    };
    apply_combo_to_connection_node(node, combo, inherits).is_ok()
}

/// Load node serial fields into the editor (normalize via domain defaults).
///
/// Fail-closed when the stored combo is illegal after normalize (editor unchanged).
/// Sets inherit flags from nullability when `supports_inheritance`.
pub fn load_node_serial_into_editor(
    node: &ConnectionNode,
    editor: &mut ConnectionEditorState,
) -> bool {
    if !require_serial(editor) {
        return false;
    }
    let Ok(combo) = combo_from_optional_node_fields(
        node.serial_baud_rate,
        node.serial_data_bits,
        node.serial_stop_bits,
        node.serial_parity,
        node.serial_flow_control,
    ) else {
        return false;
    };
    let allow = editor.supports_inheritance();
    editor.serial_baud_rate = combo.baud_rate;
    editor.serial_baud_rate_inherits = allow && node.serial_baud_rate.is_none();
    editor.serial_data_bits = combo.data_bits;
    editor.serial_data_bits_inherits = allow && node.serial_data_bits.is_none();
    editor.serial_stop_bits = combo.stop_bits;
    editor.serial_stop_bits_inherits = allow && node.serial_stop_bits.is_none();
    editor.serial_parity = combo.parity;
    editor.serial_parity_inherits = allow && node.serial_parity.is_none();
    editor.serial_flow_control = combo.flow_control;
    editor.serial_flow_control_inherits = allow && node.serial_flow_control.is_none();
    true
}

/// Catalog lengths for tests / chrome bounds checks.
pub fn preset_catalog_lens() -> (usize, usize, usize, usize, usize) {
    (
        BAUD_RATE_PRESETS.len(),
        DATA_BIT_PRESETS.len(),
        STOP_BIT_PRESETS.len(),
        PARITY_PRESETS.len(),
        FLOW_CONTROL_PRESETS.len(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use wormhole_domain::{
        SerialDefaults, SerialFlowControlMode, SerialParityMode, SerialStopBitsMode,
    };

    use crate::connection_editor::{ConnectionEditorMode, ConnectionEditorState};
    use crate::quick_connect::QuickConnectState;

    fn serial_editor() -> ConnectionEditorState {
        let mut e = ConnectionEditorState::new(ConnectionEditorMode::Persistent);
        e.protocol = ProtocolType::Serial;
        e.host = "COM1".into();
        e
    }

    #[test]
    fn putty_defaults_apply_and_catalogs_stable() {
        let mut e = serial_editor();
        e.serial_baud_rate = 115200;
        e.serial_data_bits = 7;
        assert!(apply_putty_defaults_to_editor(&mut e));
        assert_eq!(e.serial_baud_rate, SerialDefaults::BAUD_RATE);
        assert_eq!(e.serial_data_bits, SerialDefaults::DATA_BITS);
        assert_eq!(e.serial_stop_bits, SerialStopBitsMode::One);
        assert_eq!(e.serial_parity, SerialParityMode::None);
        assert_eq!(e.serial_flow_control, SerialFlowControlMode::None);
        assert!(!e.serial_baud_rate_inherits);

        let (b, d, s, p, f) = preset_catalog_lens();
        assert!(b >= 10);
        assert_eq!(d, 4);
        assert_eq!(s, 3);
        assert_eq!(p, 5);
        assert_eq!(f, 4);
        assert_eq!(SERIAL_STOP_BIT_PRESETS[1].label, "1.5");
        assert_eq!(SERIAL_FLOW_PRESETS[1].label, "XON/XOFF");
    }

    #[test]
    fn select_presets_into_editor() {
        let mut e = serial_editor();
        // 9600 is index 6 in BAUD_RATE_PRESETS
        assert!(select_baud_preset(&mut e, 6));
        assert_eq!(e.serial_baud_rate, 9600);
        assert!(select_baud_preset(&mut e, 11)); // 115200
        assert_eq!(e.serial_baud_rate, 115200);

        assert!(select_data_bits_preset(&mut e, 2)); // 7
        assert_eq!(e.serial_data_bits, 7);
        assert!(select_parity_preset(&mut e, 2)); // Even
        assert_eq!(e.serial_parity, SerialParityMode::Even);
        assert!(select_flow_control_preset(&mut e, 2)); // RtsCts
        assert_eq!(e.serial_flow_control, SerialFlowControlMode::RtsCts);
        assert!(select_stop_bits_preset(&mut e, 0)); // 1
        assert_eq!(e.serial_stop_bits, SerialStopBitsMode::One);
    }

    #[test]
    fn oob_and_non_serial_fail_closed() {
        let mut e = serial_editor();
        e.serial_baud_rate = 19200;
        assert!(!select_baud_preset(&mut e, 99));
        assert_eq!(e.serial_baud_rate, 19200);

        e.protocol = ProtocolType::Ssh;
        assert!(!select_baud_preset(&mut e, 6));
        assert!(!select_parity_preset(&mut e, 0));
        assert!(!set_custom_baud(&mut e, 57600));
        assert_eq!(e.serial_baud_rate, 19200);
    }

    #[test]
    fn illegal_stop_data_combo_fail_closed() {
        let mut e = serial_editor();
        e.serial_data_bits = 8;
        e.serial_stop_bits = SerialStopBitsMode::One;
        // 1.5 stop bits with 8 data bits — rejected
        assert!(!select_stop_bits_preset(&mut e, 1));
        assert_eq!(e.serial_stop_bits, SerialStopBitsMode::One);

        // Switch to 5 data bits, then 1.5 is ok
        assert!(select_data_bits_preset(&mut e, 0)); // 5
        assert!(select_stop_bits_preset(&mut e, 1)); // 1.5
        assert_eq!(e.serial_stop_bits, SerialStopBitsMode::OnePointFive);

        // Changing data bits to 8 while stop is 1.5 — rejected
        assert!(!select_data_bits_preset(&mut e, 3)); // 8
        assert_eq!(e.serial_data_bits, 5);
        assert_eq!(e.serial_stop_bits, SerialStopBitsMode::OnePointFive);

        // 2 stop bits with 5 data bits — rejected
        assert!(!select_stop_bits_preset(&mut e, 2));
        assert_eq!(e.serial_stop_bits, SerialStopBitsMode::OnePointFive);
    }

    #[test]
    fn custom_baud_and_zero_fail_closed() {
        let mut e = serial_editor();
        assert!(set_custom_baud(&mut e, 1000000));
        assert_eq!(e.serial_baud_rate, 1000000);
        assert!(!set_custom_baud(&mut e, 0));
        assert!(!set_custom_baud(&mut e, -9600));
        assert_eq!(e.serial_baud_rate, 1000000);
    }

    #[test]
    fn node_round_trip_via_glue() {
        let mut e = serial_editor();
        assert!(select_baud_preset(&mut e, 11)); // 115200
        assert!(select_data_bits_preset(&mut e, 3)); // 8
        assert!(select_parity_preset(&mut e, 1)); // Odd
        assert!(select_flow_control_preset(&mut e, 1)); // XonXoff

        let mut node = ConnectionNode::default();
        assert!(write_editor_serial_to_node(&e, &mut node));
        assert_eq!(node.serial_baud_rate, Some(115200));
        assert_eq!(node.serial_parity, Some(SerialParityMode::Odd));

        let mut e2 = serial_editor();
        assert!(load_node_serial_into_editor(&node, &mut e2));
        assert_eq!(e2.serial_baud_rate, 115200);
        assert!(!e2.serial_baud_rate_inherits);
        assert_eq!(e2.serial_parity, SerialParityMode::Odd);
        assert_eq!(combo_from_editor(&e2).unwrap().baud_rate, 115200);
    }

    #[test]
    fn inherit_all_writes_none_fields() {
        let mut e = serial_editor();
        e.serial_baud_rate_inherits = true;
        e.serial_data_bits_inherits = true;
        e.serial_stop_bits_inherits = true;
        e.serial_parity_inherits = true;
        e.serial_flow_control_inherits = true;
        e.serial_baud_rate = 9600;
        let mut node = ConnectionNode::default();
        node.serial_baud_rate = Some(57600);
        assert!(write_editor_serial_to_node(&e, &mut node));
        assert_eq!(node.serial_baud_rate, None);
        assert_eq!(node.serial_data_bits, None);
    }

    #[test]
    fn load_illegal_stored_combo_fail_closed() {
        let mut e = serial_editor();
        e.serial_baud_rate = 19200;
        let mut node = ConnectionNode::default();
        node.serial_baud_rate = Some(9600);
        node.serial_data_bits = Some(8);
        node.serial_stop_bits = Some(SerialStopBitsMode::OnePointFive);
        assert!(!load_node_serial_into_editor(&node, &mut e));
        assert_eq!(e.serial_baud_rate, 19200);
    }

    #[test]
    fn quick_connect_preset_select_requires_serial() {
        let mut qc = QuickConnectState::new();
        qc.set_host("ssh.example");
        assert!(!select_baud_preset_qc(&mut qc, 6));
        qc.set_protocol(ProtocolType::Serial);
        assert!(select_baud_preset_qc(&mut qc, 6));
        assert_eq!(qc.editor().serial_baud_rate, 9600);
        assert!(select_parity_preset_qc(&mut qc, 2));
        assert_eq!(qc.editor().serial_parity, SerialParityMode::Even);
    }

    #[test]
    fn write_illegal_concrete_combo_fail_closed() {
        let mut e = serial_editor();
        e.serial_baud_rate = 9600;
        e.serial_data_bits = 8;
        e.serial_stop_bits = SerialStopBitsMode::OnePointFive;
        e.serial_baud_rate_inherits = false;
        e.serial_data_bits_inherits = false;
        e.serial_stop_bits_inherits = false;
        e.serial_parity_inherits = false;
        e.serial_flow_control_inherits = false;
        let mut node = ConnectionNode::default();
        node.serial_baud_rate = Some(19200);
        assert!(!write_editor_serial_to_node(&e, &mut node));
        assert_eq!(node.serial_baud_rate, Some(19200));
    }

    #[test]
    fn to_connection_node_uses_fail_closed_serial_write() {
        let mut e = serial_editor();
        e.name = "s".into();
        e.serial_data_bits = 8;
        e.serial_stop_bits = SerialStopBitsMode::OnePointFive;
        e.serial_baud_rate_inherits = false;
        e.serial_data_bits_inherits = false;
        e.serial_stop_bits_inherits = false;
        e.serial_parity_inherits = false;
        e.serial_flow_control_inherits = false;
        assert!(!e.is_valid());
        let (node, _) = e.to_connection_node();
        // Illegal combo must not be persisted onto the node.
        assert_eq!(node.serial_baud_rate, None);
        assert_eq!(node.serial_data_bits, None);
        assert_eq!(node.serial_stop_bits, None);
    }

    #[test]
    fn write_to_clears_stale_serial_on_illegal_combo() {
        let mut e = serial_editor();
        e.name = "s".into();
        e.serial_baud_rate_inherits = false;
        e.serial_data_bits_inherits = false;
        e.serial_stop_bits_inherits = false;
        e.serial_parity_inherits = false;
        e.serial_flow_control_inherits = false;
        let mut node = ConnectionNode::default();
        node.serial_baud_rate = Some(19200);
        node.serial_data_bits = Some(8);
        node.serial_stop_bits = Some(SerialStopBitsMode::One);
        e.serial_data_bits = 8;
        e.serial_stop_bits = SerialStopBitsMode::OnePointFive;
        e.write_to(&mut node, crate::connection_editor::WriteOptions::default());
        assert_eq!(node.serial_baud_rate, None);
        assert_eq!(node.serial_data_bits, None);
        assert_eq!(node.serial_stop_bits, None);
    }

    #[test]
    fn apply_combo_rejects_bad_and_wrong_protocol() {
        let mut e = serial_editor();
        let bad = SerialLineCombo {
            baud_rate: 9600,
            data_bits: 8,
            stop_bits: SerialStopBitsMode::OnePointFive,
            parity: SerialParityMode::None,
            flow_control: SerialFlowControlMode::None,
        };
        assert!(!apply_combo_to_editor(&mut e, bad));
        assert_eq!(e.serial_stop_bits, SerialStopBitsMode::One);

        e.protocol = ProtocolType::Vnc;
        assert!(!apply_combo_to_editor(&mut e, SerialLineCombo::putty_defaults()));
    }
}
