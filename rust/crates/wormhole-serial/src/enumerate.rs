//! Serial port enumeration (COM list for the Rust connection-editor / Quick Connect hooks).
//!
//! Live listing uses `tokio_serial::available_ports` (serialport) on Windows and soft-fails
//! to an empty list on OS/permission errors (never panics). Tests inject
//! [`MemorySerialPortEnumerator`] so CI never needs a real COM device.
//!
//! This crate exposes the enumerator API only; shipping a product UI COM picker is separate.

use crate::error::SerialError;
use crate::Result;

/// Pluggable COM enumerator so UI and tests can inject a fixed list.
pub trait SerialPortEnumerator: Send + Sync {
    /// Return available port names (`COM1`, `COM10`, `\\.\COM10`, …).
    fn list_ports(&self) -> Result<Vec<String>>;
}

/// Live OS enumeration.
///
/// On Windows this calls `tokio_serial::available_ports` (serialport Win32 path).
/// Enumeration errors soft-fail to an empty list. Surviving names are passed through
/// [`normalize_serial_port_name`] (invalid CreateFile shapes are dropped).
/// Non-Windows builds return an empty list (Wormhole ships Windows-only).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemSerialPortEnumerator;

impl SerialPortEnumerator for SystemSerialPortEnumerator {
    fn list_ports(&self) -> Result<Vec<String>> {
        list_serial_ports_system()
    }
}

/// In-memory / fake enumerator for unit tests and UI previews.
///
/// Deterministic: returns a clone of the configured list (or the configured error) on every call.
/// Does **not** sanitize names — callers that open ports must validate via
/// [`normalize_serial_port_name`].
#[derive(Debug, Clone, Default)]
pub struct MemorySerialPortEnumerator {
    ports: Vec<String>,
    fail: Option<String>,
}

/// Alias preferred in tests (`Fake` = memory list).
pub type FakeSerialPortEnumerator = MemorySerialPortEnumerator;

impl MemorySerialPortEnumerator {
    /// Fixed list of port names (order preserved).
    pub fn new(ports: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            ports: ports.into_iter().map(Into::into).collect(),
            fail: None,
        }
    }

    /// Empty list (no ports present).
    pub fn empty() -> Self {
        Self::default()
    }

    /// Always fail listing with the given message (error-path tests).
    pub fn failing(message: impl Into<String>) -> Self {
        Self {
            ports: Vec::new(),
            fail: Some(message.into()),
        }
    }
}

impl SerialPortEnumerator for MemorySerialPortEnumerator {
    fn list_ports(&self) -> Result<Vec<String>> {
        if let Some(msg) = &self.fail {
            return Err(SerialError::Other(msg.clone()));
        }
        Ok(self.ports.clone())
    }
}

/// List serial port names using the system enumerator.
///
/// Prefer injecting [`MemorySerialPortEnumerator`] in tests instead of calling this.
pub fn list_serial_ports() -> Result<Vec<String>> {
    SystemSerialPortEnumerator.list_ports()
}

/// List port names through an arbitrary enumerator (UI / DI hook).
pub fn list_serial_ports_with(enumerator: &dyn SerialPortEnumerator) -> Result<Vec<String>> {
    enumerator.list_ports()
}

/// True when `name` is a Windows COM device name safe to pass to CreateFile as a serial port.
///
/// Accepts `COMn`, `COMn:`, and `\\.\COMn` (ASCII, case-insensitive) with `n` in `1..=256`.
/// Rejects pipes, drive paths, relative segments, NULs, and other CreateFile injection shapes.
pub fn is_valid_windows_com_port_name(name: &str) -> bool {
    normalize_serial_port_name(name).is_ok()
}

/// Trim and normalize a Windows COM port name, or reject hostile / non-COM strings.
///
/// Normalization: trim whitespace, strip a single trailing `:`, preserve an existing
/// `\\.\` prefix, and uppercase the `COM` prefix while keeping the digits.
pub fn normalize_serial_port_name(name: &str) -> Result<String> {
    if name.as_bytes().contains(&0) {
        return Err(SerialError::InvalidSettings(
            "serial port name must not contain NUL".into(),
        ));
    }

    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(SerialError::InvalidSettings(
            "serial line (Host) must be non-empty".into(),
        ));
    }
    // `\\.\COM256` is 10 chars; reject absurd Host / Fake payloads before parsing.
    if trimmed.len() > 32 {
        return Err(SerialError::InvalidSettings(
            "serial port name is too long".into(),
        ));
    }

    let without_colon = trimmed.strip_suffix(':').unwrap_or(trimmed);
    let (prefix, digits) = if let Some(rest) = strip_com_device_prefix(without_colon) {
        rest
    } else {
        return Err(SerialError::InvalidSettings(format!(
            "serial port name must be COMn or \\\\.\\COMn (got {trimmed:?})"
        )));
    };

    if digits.is_empty() || digits.len() > 3 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(SerialError::InvalidSettings(format!(
            "serial port name must end with digits 1..=256 (got {trimmed:?})"
        )));
    }
    // Keep the digit spelling from the input (`COM01` stays `COM01`); only the COM prefix is
    // canonicalized. Range-check the parsed number (Windows COM1..=COM256).
    let n: u32 = digits.parse().unwrap_or(0);
    if !(1..=256).contains(&n) {
        return Err(SerialError::InvalidSettings(format!(
            "serial port number must be 1..=256 (got {trimmed:?})"
        )));
    }

    Ok(format!("{prefix}{digits}"))
}

/// Returns `Some(("COM"|"\\\\.\\COM", digits))` when `s` matches a COM device shape.
fn strip_com_device_prefix(s: &str) -> Option<(&'static str, &str)> {
    const EXTENDED: &str = r"\\.\";
    if let Some(rest) = s.strip_prefix(EXTENDED) {
        return strip_com_token(rest).map(|digits| (r"\\.\COM", digits));
    }
    // Reject any other backslash / slash path forms (pipes, drive letters, `..\`).
    if s.as_bytes().iter().any(|&b| b == b'\\' || b == b'/') {
        return None;
    }
    strip_com_token(s).map(|digits| ("COM", digits))
}

fn strip_com_token(s: &str) -> Option<&str> {
    let bytes = s.as_bytes();
    if bytes.len() < 4 {
        return None;
    }
    if !bytes[..3].eq_ignore_ascii_case(b"COM") {
        return None;
    }
    Some(&s[3..])
}

#[cfg(windows)]
fn list_serial_ports_system() -> Result<Vec<String>> {
    Ok(soft_fail_system_port_names(tokio_serial::available_ports().map(
        |infos| infos.into_iter().map(|info| info.port_name).collect(),
    )))
}

#[cfg(not(windows))]
fn list_serial_ports_system() -> Result<Vec<String>> {
    // Workspace targets are Windows-only; keep a stub so `cfg(not(windows))` still type-checks.
    Ok(Vec::new())
}

/// Map a system enumeration result to a filtered, normalized list. Errors become `[]` (soft-fail).
fn soft_fail_system_port_names(result: std::result::Result<Vec<String>, tokio_serial::Error>) -> Vec<String> {
    match result {
        Ok(names) => names
            .into_iter()
            .filter_map(|name| normalize_serial_port_name(&name).ok())
            .collect(),
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_list_returns_configured_names() {
        let fake = FakeSerialPortEnumerator::new(["COM1", "COM3", r"\\.\COM10"]);
        let ports = list_serial_ports_with(&fake).unwrap();
        assert_eq!(ports, vec!["COM1", "COM3", r"\\.\COM10"]);
    }

    #[test]
    fn memory_empty_returns_no_ports() {
        let mem = MemorySerialPortEnumerator::empty();
        let ports = mem.list_ports().unwrap();
        assert!(ports.is_empty());
    }

    #[test]
    fn memory_failing_surfaces_error() {
        let mem = MemorySerialPortEnumerator::failing("registry read failed");
        let err = mem.list_ports().unwrap_err();
        assert!(matches!(err, SerialError::Other(ref m) if m.contains("registry")));
    }

    #[test]
    fn memory_list_is_deterministic_across_calls() {
        let mem = MemorySerialPortEnumerator::new(["COM2", "COM4"]);
        let a = mem.list_ports().unwrap();
        let b = mem.list_ports().unwrap();
        assert_eq!(a, b);
        assert_eq!(a, vec!["COM2", "COM4"]);
    }

    #[test]
    fn memory_preserves_hostile_configured_names_without_opening() {
        // Enumerator must stay deterministic for tests; open path validates separately.
        let hostile = MemorySerialPortEnumerator::new([r"\\.\pipe\evil", r"C:\Windows\system.ini"]);
        let ports = hostile.list_ports().unwrap();
        assert_eq!(ports, vec![r"\\.\pipe\evil", r"C:\Windows\system.ini"]);
        assert!(normalize_serial_port_name(&ports[0]).is_err());
        assert!(normalize_serial_port_name(&ports[1]).is_err());
    }

    #[test]
    fn system_list_soft_fails_without_panic() {
        // Must not panic; soft-fail yields Ok (possibly empty) even with zero COM ports.
        let ports = list_serial_ports().expect("system list soft-fails to Ok");
        for name in &ports {
            assert!(
                is_valid_windows_com_port_name(name),
                "system list leaked invalid name {name:?}"
            );
        }
    }

    #[test]
    fn soft_fail_maps_os_error_to_empty_list() {
        let err = tokio_serial::Error::new(
            tokio_serial::ErrorKind::Unknown,
            "simulated permission / setupdi failure",
        );
        let ports = soft_fail_system_port_names(Err(err));
        assert!(ports.is_empty());
    }

    #[test]
    fn soft_fail_filters_hostile_os_names() {
        let ports = soft_fail_system_port_names(Ok(vec![
            "COM1".into(),
            r"\\.\pipe\x".into(),
            r"\\.\COM12".into(),
            r"C:\evil".into(),
            "LPT1".into(),
            "COM999".into(),
            "  com7: ".into(),
        ]));
        assert_eq!(ports, vec!["COM1", r"\\.\COM12", "COM7"]);
    }

    #[test]
    fn normalize_accepts_common_com_shapes() {
        assert_eq!(normalize_serial_port_name("COM1").unwrap(), "COM1");
        assert_eq!(normalize_serial_port_name("  com3:  ").unwrap(), "COM3");
        assert_eq!(
            normalize_serial_port_name(r"\\.\COM10").unwrap(),
            r"\\.\COM10"
        );
        assert_eq!(
            normalize_serial_port_name(r"\\.\com256").unwrap(),
            r"\\.\COM256"
        );
    }

    #[test]
    fn normalize_rejects_injection_shapes() {
        for hostile in [
            "",
            "   ",
            "COM0",
            "COM257",
            "COM",
            "COM 1",
            "LPT1",
            r"\\.\pipe\wormhole",
            r"C:\Windows\System32\drivers\etc\hosts",
            r"COM1\..\COM2",
            r"\\.\COM1\..\COM2",
            "COM1\0evil",
            "/dev/ttyS0",
            "COM0001",
            &format!("COM1{}", "x".repeat(40)),
        ] {
            assert!(
                normalize_serial_port_name(hostile).is_err(),
                "expected reject for {hostile:?}"
            );
        }
    }

    #[test]
    fn normalize_accepts_three_digit_com() {
        assert_eq!(normalize_serial_port_name("COM256").unwrap(), "COM256");
        assert_eq!(normalize_serial_port_name("COM01").unwrap(), "COM01");
    }

    #[test]
    fn fake_alias_is_memory_enumerator() {
        let fake: FakeSerialPortEnumerator = MemorySerialPortEnumerator::new(["COM5"]);
        assert_eq!(fake.list_ports().unwrap(), vec!["COM5"]);
    }
}
