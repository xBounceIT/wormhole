//! Crash sentinel for in-flight embedded RDP connects (`rdp-in-flight.json`).
//!
//! Mirrors C# `RdpCrashSentinelService` at a high level:
//! - single JSON file under `%LOCALAPPDATA%\Wormhole\` (or an explicit test path)
//! - Mark = tmp + atomic replace (Windows `MoveFileEx` with overwrite)
//! - Clear = delete (idempotent)
//! - TryReadOrphan = read without delete; malformed payloads are deleted

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Sentinel file name (matches C#).
pub const SENTINEL_FILE_NAME: &str = "rdp-in-flight.json";

/// Payload written while an embedded RDP connect is in flight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RdpCrashRecord {
    /// Connection node id (GUID string, same shape as C# `Guid`).
    pub node_id: String,
    /// Target host (never a secret; password is not stored).
    pub host: String,
    /// UTC start instant as unix-epoch seconds with a `Z` suffix (breadcrumb only).
    pub started_at_utc: String,
}

/// File-backed RDP crash sentinel (Mark / Clear / TryReadOrphan).
#[derive(Debug)]
pub struct RdpCrashSentinel {
    path: PathBuf,
    gate: Mutex<()>,
}

impl RdpCrashSentinel {
    /// Production path: `%LOCALAPPDATA%\Wormhole\rdp-in-flight.json`.
    pub fn default_path() -> io::Result<PathBuf> {
        let local = std::env::var_os("LOCALAPPDATA").ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "LOCALAPPDATA is not set")
        })?;
        Ok(PathBuf::from(local)
            .join("Wormhole")
            .join(SENTINEL_FILE_NAME))
    }

    /// Create a sentinel at the production default path.
    pub fn production() -> io::Result<Self> {
        Ok(Self::at_path(Self::default_path()?))
    }

    /// Create a sentinel at an explicit path (tests / lab).
    pub fn at_path(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            gate: Mutex::new(()),
        }
    }

    /// Path of the sentinel file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Atomically write an in-flight record (tmp + replace). Overwrites any prior sentinel.
    pub fn mark_connect_in_flight(&self, node_id: &str, host: &str) -> io::Result<()> {
        if node_id.trim().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "node_id must be non-empty",
            ));
        }
        let _guard = self.gate.lock().unwrap_or_else(|e| e.into_inner());
        let started = unix_secs_z_now();
        let payload = format!(
            "{{\"nodeId\":{},\"host\":{},\"startedAtUtc\":{}}}",
            json_string(node_id),
            json_string(host),
            json_string(&started)
        );

        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        // Match C#: path + ".tmp" (not Path::with_extension).
        let tmp = tmp_path_for(&self.path);
        fs::write(&tmp, payload.as_bytes())?;
        match replace_file(&tmp, &self.path) {
            Ok(()) => Ok(()),
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                Err(e)
            }
        }
    }

    /// Delete the sentinel if present. Idempotent.
    pub fn clear(&self) -> io::Result<()> {
        let _guard = self.gate.lock().unwrap_or_else(|e| e.into_inner());
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Read orphan sentinel without deleting. Malformed JSON is deleted and yields `Ok(None)`.
    pub fn try_read_orphan(&self) -> io::Result<Option<RdpCrashRecord>> {
        let _guard = self.gate.lock().unwrap_or_else(|e| e.into_inner());
        if !self.path.exists() {
            return Ok(None);
        }
        let bytes = match fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        match parse_record(&bytes) {
            Some(record) => Ok(Some(record)),
            None => {
                let _ = fs::remove_file(&self.path);
                Ok(None)
            }
        }
    }
}

fn tmp_path_for(path: &Path) -> PathBuf {
    let mut os = path.as_os_str().to_owned();
    os.push(".tmp");
    PathBuf::from(os)
}

/// Atomic replace matching C# `File.Move(tmp, dest, overwrite: true)` on NTFS.
#[cfg(windows)]
fn replace_file(from: &Path, to: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    fn wide(p: &Path) -> Vec<u16> {
        p.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
    }

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
        fn GetLastError() -> u32;
    }

    let from_w = wide(from);
    let to_w = wide(to);
    let ok = unsafe { MoveFileExW(from_w.as_ptr(), to_w.as_ptr(), MOVEFILE_REPLACE_EXISTING) };
    if ok == 0 {
        Err(io::Error::from_raw_os_error(unsafe { GetLastError() } as i32))
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn replace_file(from: &Path, to: &Path) -> io::Result<()> {
    if to.exists() {
        let _ = fs::remove_file(to);
    }
    fs::rename(from, to)
}

fn unix_secs_z_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Breadcrumb stamp (not full RFC3339 calendar form). Sufficient for orphan recovery.
    format!("{secs}Z")
}

fn json_string(s: &str) -> String {
    let mut out = String::from('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn parse_record(bytes: &[u8]) -> Option<RdpCrashRecord> {
    let text = std::str::from_utf8(bytes).ok()?;
    let node_id = extract_json_string(text, "nodeId")?;
    if node_id.trim().is_empty() {
        return None;
    }
    let host = extract_json_string(text, "host").unwrap_or_default();
    let started_at_utc = extract_json_string(text, "startedAtUtc").unwrap_or_default();
    Some(RdpCrashRecord {
        node_id,
        host,
        started_at_utc,
    })
}

fn extract_json_string(text: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{key}\"");
    let idx = text.find(&pattern)?;
    let after_key = &text[idx + pattern.len()..];
    let colon = after_key.find(':')?;
    let mut rest = after_key[colon + 1..].trim_start();
    if !rest.starts_with('"') {
        return None;
    }
    rest = &rest[1..];
    let mut out = String::new();
    let mut chars = rest.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Some(out),
            '\\' => match chars.next()? {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                'u' => {
                    let mut hex = String::new();
                    for _ in 0..4 {
                        hex.push(chars.next()?);
                    }
                    let code = u32::from_str_radix(&hex, 16).ok()?;
                    out.push(char::from_u32(code)?);
                }
                other => out.push(other),
            },
            c => out.push(c),
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_sentinel() -> (PathBuf, RdpCrashSentinel) {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("wormhole-rdp-sentinel-{nanos}"));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(SENTINEL_FILE_NAME);
        (dir, RdpCrashSentinel::at_path(&path))
    }

    #[test]
    fn mark_clear_orphan_roundtrip() {
        let (dir, sentinel) = temp_sentinel();

        sentinel
            .mark_connect_in_flight("11111111-2222-3333-4444-555555555555", "rdp.example")
            .unwrap();
        let orphan = sentinel.try_read_orphan().unwrap().expect("orphan");
        assert_eq!(orphan.node_id, "11111111-2222-3333-4444-555555555555");
        assert_eq!(orphan.host, "rdp.example");
        assert!(orphan.started_at_utc.ends_with('Z'));

        sentinel.clear().unwrap();
        assert!(sentinel.try_read_orphan().unwrap().is_none());
        sentinel.clear().unwrap();

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn try_read_orphan_keeps_file_until_clear() {
        let (dir, sentinel) = temp_sentinel();
        sentinel
            .mark_connect_in_flight("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "keep.example")
            .unwrap();

        let first = sentinel.try_read_orphan().unwrap().expect("first");
        let second = sentinel.try_read_orphan().unwrap().expect("second");
        assert_eq!(first, second);
        assert!(sentinel.path().exists());

        sentinel.clear().unwrap();
        assert!(!sentinel.path().exists());
        assert!(sentinel.try_read_orphan().unwrap().is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn mark_overwrites_previous_and_leaves_no_tmp() {
        let (dir, sentinel) = temp_sentinel();
        sentinel
            .mark_connect_in_flight("11111111-1111-1111-1111-111111111111", "host-a")
            .unwrap();
        sentinel
            .mark_connect_in_flight("22222222-2222-2222-2222-222222222222", "host-b")
            .unwrap();

        let orphan = sentinel.try_read_orphan().unwrap().expect("orphan");
        assert_eq!(orphan.node_id, "22222222-2222-2222-2222-222222222222");
        assert_eq!(orphan.host, "host-b");
        assert!(!tmp_path_for(sentinel.path()).exists());

        sentinel.clear().unwrap();
        assert!(!tmp_path_for(sentinel.path()).exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn malformed_json_is_deleted_and_yields_none() {
        let (dir, sentinel) = temp_sentinel();
        fs::write(sentinel.path(), b"{ this is not valid json").unwrap();

        assert!(sentinel.try_read_orphan().unwrap().is_none());
        assert!(!sentinel.path().exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_object_and_empty_node_id_are_malformed() {
        let (dir, sentinel) = temp_sentinel();
        fs::write(sentinel.path(), b"{}").unwrap();
        assert!(sentinel.try_read_orphan().unwrap().is_none());

        fs::write(
            sentinel.path(),
            br#"{"nodeId":"","host":"x","startedAtUtc":"1Z"}"#,
        )
        .unwrap();
        assert!(sentinel.try_read_orphan().unwrap().is_none());

        fs::write(
            sentinel.path(),
            br#"{"nodeId":"  ","host":"x","startedAtUtc":"1Z"}"#,
        )
        .unwrap();
        assert!(sentinel.try_read_orphan().unwrap().is_none());
        assert!(!sentinel.path().exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn mark_rejects_empty_node_id() {
        let (dir, sentinel) = temp_sentinel();
        let err = sentinel.mark_connect_in_flight("", "host").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        let err = sentinel.mark_connect_in_flight("   ", "host").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(!sentinel.path().exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn json_escape_roundtrip_for_hostile_host() {
        let (dir, sentinel) = temp_sentinel();
        let host = "a\"b\\c\n\t\u{1}host";
        sentinel
            .mark_connect_in_flight("33333333-3333-3333-3333-333333333333", host)
            .unwrap();
        let orphan = sentinel.try_read_orphan().unwrap().expect("orphan");
        assert_eq!(orphan.host, host);
        sentinel.clear().unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn default_path_uses_localappdata_wormhole() {
        let path = RdpCrashSentinel::default_path().expect("LOCALAPPDATA");
        assert_eq!(
            path.file_name().and_then(|s| s.to_str()),
            Some(SENTINEL_FILE_NAME)
        );
        assert!(
            path.components()
                .any(|c| c.as_os_str() == std::ffi::OsStr::new("Wormhole")),
            "path must include Wormhole dir: {}",
            path.display()
        );
        let local = std::env::var_os("LOCALAPPDATA").unwrap();
        assert!(path.starts_with(local));
    }

    #[test]
    fn concurrent_marks_and_clears_do_not_panic_or_leave_half_written() {
        let (dir, sentinel) = temp_sentinel();
        let sentinel = Arc::new(sentinel);
        let mut handles = Vec::new();
        for i in 0..40 {
            let s = Arc::clone(&sentinel);
            handles.push(std::thread::spawn(move || {
                let id = format!("00000000-0000-0000-0000-{i:012}");
                let _ = s.mark_connect_in_flight(&id, &format!("host-{i}"));
                let _ = s.clear();
            }));
        }
        for h in handles {
            h.join().expect("thread");
        }
        // Final state may be present or absent; must parse cleanly and leave no .tmp.
        let _ = sentinel.try_read_orphan().unwrap();
        assert!(!tmp_path_for(sentinel.path()).exists());
        let _ = fs::remove_dir_all(&dir);
    }
}
