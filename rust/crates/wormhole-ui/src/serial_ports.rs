//! Serial port enumerate → connection editor / Quick Connect host-field glue.
//!
//! Thin pure-Rust bridge over [`wormhole_serial::SerialPortEnumerator`]: refresh a COM
//! list, then select a line into the shared Host / Serial-line field. No GPUI chrome
//! and no live `SerialPort` open — list only.
//!
//! Refresh fail-closes to an empty list when the enumerator returns `Err` (e.g.
//! [`FakeSerialPortEnumerator::failing`](wormhole_serial::FakeSerialPortEnumerator::failing)).
//! Empty `Ok` lists are valid and do **not** set [`SerialPortPickerState::refresh_failed`].
//! [`SystemSerialPortEnumerator`](wormhole_serial::SystemSerialPortEnumerator) soft-fails OS
//! errors as `Ok([])` inside `wormhole-serial`, so product refreshes see an empty success
//! (not `refresh_failed`). Selection refuses out-of-range indices and non-Serial protocols.

use wormhole_domain::ProtocolType;
use wormhole_serial::{list_serial_ports_with, SerialPortEnumerator};

use crate::connection_editor::ConnectionEditorState;
use crate::quick_connect::QuickConnectState;

/// Cached COM list for the connection-editor / Quick Connect serial-line picker.
///
/// Does not open ports. Call [`refresh`](Self::refresh) with a
/// [`FakeSerialPortEnumerator`](wormhole_serial::FakeSerialPortEnumerator) in tests
/// or [`SystemSerialPortEnumerator`](wormhole_serial::SystemSerialPortEnumerator) in product code.
///
/// `refresh_failed` is set only when the enumerator trait returns `Err`. System enumeration
/// maps OS failures to `Ok([])` (see `wormhole-serial`), so an empty list after a system
/// refresh is indistinguishable from “no ports” at this layer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SerialPortPickerState {
    ports: Vec<String>,
    /// `true` when the last [`refresh`](Self::refresh) received enumerator `Err`.
    refresh_failed: bool,
}

impl SerialPortPickerState {
    /// Empty picker (no ports; last refresh treated as success).
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed from an already-listed snapshot (tests / previews). Marks refresh as succeeded.
    pub fn from_ports(ports: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            ports: ports.into_iter().map(Into::into).collect(),
            refresh_failed: false,
        }
    }

    /// Re-list via `enumerator`. On `Err`, clear the list and set [`refresh_failed`](Self::refresh_failed)
    /// (fail closed — never panics, never leaves a stale list after a failed refresh).
    /// On `Ok` (including empty), replace the list and clear the fail flag.
    pub fn refresh(&mut self, enumerator: &dyn SerialPortEnumerator) {
        match list_serial_ports_with(enumerator) {
            Ok(ports) => {
                self.ports = ports;
                self.refresh_failed = false;
            }
            Err(_) => {
                self.ports.clear();
                self.refresh_failed = true;
            }
        }
    }

    /// Current COM names (order preserved from the enumerator / seed).
    pub fn ports(&self) -> &[String] {
        &self.ports
    }

    pub fn is_empty(&self) -> bool {
        self.ports.is_empty()
    }

    pub fn len(&self) -> usize {
        self.ports.len()
    }

    /// `true` when the last refresh returned an enumerator error (list is empty).
    pub fn refresh_failed(&self) -> bool {
        self.refresh_failed
    }

    /// Copy `ports[index]` into `host`. Fail-closed on out-of-range (host unchanged).
    pub fn select_into_host(&self, index: usize, host: &mut String) -> bool {
        let Some(name) = self.ports.get(index) else {
            return false;
        };
        *host = name.clone();
        true
    }

    /// Select by exact name only when present in the cached list (host unchanged otherwise).
    pub fn select_named_into_host(&self, name: &str, host: &mut String) -> bool {
        if !self.ports.iter().any(|p| p == name) {
            return false;
        }
        *host = name.to_string();
        true
    }

    /// Write the selected COM line into the editor Host field.
    ///
    /// Fail-closed when the protocol is not Serial or the index is out of range
    /// (editor host unchanged).
    pub fn select_into_editor(&self, index: usize, editor: &mut ConnectionEditorState) -> bool {
        if editor.protocol != ProtocolType::Serial {
            return false;
        }
        self.select_into_host(index, &mut editor.host)
    }

    /// Write the selected COM line into Quick Connect's Host / Serial-line field.
    ///
    /// Delegates to [`select_into_editor`](Self::select_into_editor) on the embedded
    /// editor so protocol / OOB fail-closed rules stay identical.
    pub fn select_into_quick_connect(
        &self,
        index: usize,
        qc: &mut QuickConnectState,
    ) -> bool {
        self.select_into_editor(index, qc.editor_mut())
    }
}

/// Soft-list helper: enumerator `Err` → empty `Vec` (fail-closed list clearing).
/// Does not expose a failure flag — use [`SerialPortPickerState::refresh`] when callers
/// need to distinguish `Err` from an empty `Ok` list.
pub fn list_ports_fail_closed(enumerator: &dyn SerialPortEnumerator) -> Vec<String> {
    list_serial_ports_with(enumerator).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use wormhole_domain::ProtocolType;
    use wormhole_serial::FakeSerialPortEnumerator;

    use crate::connection_editor::{ConnectionEditorMode, ConnectionEditorState};
    use crate::quick_connect::QuickConnectState;

    #[test]
    fn refresh_lists_fake_ports() {
        let fake = FakeSerialPortEnumerator::new(["COM1", "COM3", r"\\.\COM10"]);
        let mut picker = SerialPortPickerState::new();
        picker.refresh(&fake);
        assert_eq!(picker.ports(), &["COM1", "COM3", r"\\.\COM10"]);
        assert!(!picker.refresh_failed());
        assert_eq!(picker.len(), 3);
    }

    #[test]
    fn refresh_empty_list_is_ok() {
        let fake = FakeSerialPortEnumerator::empty();
        let mut picker = SerialPortPickerState::from_ports(["COM9"]);
        picker.refresh(&fake);
        assert!(picker.is_empty());
        assert!(!picker.refresh_failed());
    }

    #[test]
    fn refresh_enumerator_error_clears_and_flags_fail() {
        let fake = FakeSerialPortEnumerator::failing("registry denied");
        let mut picker = SerialPortPickerState::from_ports(["COM1", "COM2"]);
        picker.refresh(&fake);
        assert!(picker.is_empty());
        assert!(picker.refresh_failed());
    }

    #[test]
    fn list_ports_fail_closed_maps_err_to_empty() {
        let ok = FakeSerialPortEnumerator::new(["COM4"]);
        assert_eq!(list_ports_fail_closed(&ok), vec!["COM4"]);
        let bad = FakeSerialPortEnumerator::failing("boom");
        assert!(list_ports_fail_closed(&bad).is_empty());
    }

    #[test]
    fn select_into_host_by_index_and_name() {
        let picker = SerialPortPickerState::from_ports(["COM1", "COM7"]);
        let mut host = String::from("stale");
        assert!(picker.select_into_host(1, &mut host));
        assert_eq!(host, "COM7");

        assert!(picker.select_named_into_host("COM1", &mut host));
        assert_eq!(host, "COM1");

        assert!(!picker.select_into_host(99, &mut host));
        assert_eq!(host, "COM1");
        assert!(!picker.select_named_into_host("COM99", &mut host));
        assert_eq!(host, "COM1");
    }

    #[test]
    fn select_into_editor_requires_serial_protocol() {
        let picker = SerialPortPickerState::from_ports(["COM5"]);
        let mut editor = ConnectionEditorState::new(ConnectionEditorMode::Persistent);
        editor.protocol = ProtocolType::Ssh;
        editor.host = "ssh.example".into();
        assert!(!picker.select_into_editor(0, &mut editor));
        assert_eq!(editor.host, "ssh.example");

        editor.protocol = ProtocolType::Serial;
        assert!(picker.select_into_editor(0, &mut editor));
        assert_eq!(editor.host, "COM5");
    }

    #[test]
    fn select_into_quick_connect_requires_serial_protocol() {
        let picker = SerialPortPickerState::from_ports(["COM3", r"\\.\COM10"]);
        let mut qc = QuickConnectState::new();
        qc.set_host("ssh.example");
        assert!(!picker.select_into_quick_connect(0, &mut qc));
        assert_eq!(qc.host(), "ssh.example");

        qc.set_protocol(ProtocolType::Serial);
        assert!(picker.select_into_quick_connect(1, &mut qc));
        assert_eq!(qc.host(), r"\\.\COM10");

        assert!(!picker.select_into_quick_connect(9, &mut qc));
        assert_eq!(qc.host(), r"\\.\COM10");
    }

    #[test]
    fn empty_picker_select_fails_closed() {
        let picker = SerialPortPickerState::new();
        let mut host = String::from("COM1");
        assert!(!picker.select_into_host(0, &mut host));
        assert_eq!(host, "COM1");

        let mut editor = ConnectionEditorState::new(ConnectionEditorMode::QuickConnect);
        editor.protocol = ProtocolType::Serial;
        editor.host = "COM9".into();
        assert!(!picker.select_into_editor(0, &mut editor));
        assert_eq!(editor.host, "COM9");
    }

    #[test]
    fn refresh_ok_after_fail_clears_flag_and_list() {
        let mut picker = SerialPortPickerState::from_ports(["COM9"]);
        picker.refresh(&FakeSerialPortEnumerator::failing("registry denied"));
        assert!(picker.refresh_failed());
        assert!(picker.is_empty());

        picker.refresh(&FakeSerialPortEnumerator::new(["COM1", "COM2"]));
        assert!(!picker.refresh_failed());
        assert_eq!(picker.ports(), &["COM1", "COM2"]);
    }

    #[test]
    fn select_after_failed_refresh_and_oob_fail_closed() {
        let mut picker = SerialPortPickerState::from_ports(["COM1", "COM2"]);
        picker.refresh(&FakeSerialPortEnumerator::failing("boom"));

        let mut editor = ConnectionEditorState::new(ConnectionEditorMode::Persistent);
        editor.protocol = ProtocolType::Serial;
        editor.host = "kept".into();
        assert!(!picker.select_into_editor(0, &mut editor));
        assert_eq!(editor.host, "kept");

        let picker = SerialPortPickerState::from_ports(["COM1"]);
        editor.host = "kept".into();
        assert!(!picker.select_into_editor(1, &mut editor));
        assert_eq!(editor.host, "kept");
    }
}
