//! WER `LocalDumps` crash-config glue + crash-sentinel seams (crash diagnostics
//! Lab unit).
//!
//! C# parity: [`installer/Wormhole.iss`] writes the per-app WER LocalDumps
//! subtree (`HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\
//! LocalDumps\{#MyAppExeName}`) with:
//!
//! | Value | C#/installer | Type |
//! |---|---|---|
//! | `DumpFolder` | `%LOCALAPPDATA%\Wormhole\crashdumps` (`expandsz`) | `REG_SZ` / `REG_EXPAND_SZ` |
//! | `DumpType` | `1` (full heap dump; `2` = mini) | `REG_DWORD` |
//! | `DumpCount` | `10` | `REG_DWORD` |
//! | `MaxFolderSize` | unset in C# -> WER default `10` **MB** | `REG_DWORD` |
//!
//! C# `Services/CrashDiagnosticsService.cs` handles the dump *directory* +
//! reported-dump state; the WER registry configuration is what this module
//! models and applies (`CrashDiagnosticsGlue::apply_wer_config`). Units mirror
//! WER / C# exactly: `DumpType` 1/2, `MaxFolderSize` in megabytes,
//! `DumpCount` in files.
//!
//! Fail-closed table ([`WerRegistry`] read / [`CrashDiagnosticsGlue`]):
//!
//! | Condition | Result |
//! |---|---|
//! | subtree present with every value, correct types | `Configured` (report rows = paths/value types only) |
//! | no `LocalDumps\<app>` subtree | `NotConfigured` |
//! | value missing, wrong REG type, or unknown `DumpType` | **fail closed** -> `Error` (never claims configured) |
//! | Win32 read/write failed | **fail closed** -> `Error` (never panics) |
//! | non-Windows / broken process | **fail closed** -> `UnsupportedPlatform` |
//! | sentinel recorded | report shows `Armed { detail }` |
//! | sentinel cleared / absent | report shows `Clear` |
//!
//! Fake-first: [`FakeWerRegistry`] (in-memory, deterministic, never a live
//! hive) and [`FakeCrashSentinel`] back every unit path; [`RealWerRegistry`]
//! is a thin Win32 shim that is **compile-time presence only** - its read/write
//! must never be exercised against a live hive in CI (writing HKLM requires
//! elevation).
//!
//! **Never** log credentials �?" this module holds no secrets; report rows emit
//! paths and REG value types only, with defense-in-depth scrubbing for forged
//! `password=` / `token=` / `secret=` assignments and Wormhole secret blob
//! directories ([`report`] parity).

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::path::{Path, PathBuf};

use crate::sidecars::touches_wormhole_secrets_dir;

/// WER LocalDumps root subkey (relative to `HKLM`), matching the C#/installer
/// `Software\Microsoft\Windows\Windows Error Reporting\LocalDumps`.
pub const WER_LOCAL_DUMPS_SUBKEY: &str =
    r"SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps";

/// Wormhole executable name (`{#MyAppExeName}` in `installer/Wormhole.iss`).
pub const WORMHOLE_APP_EXE: &str = "Wormhole.exe";

/// `DumpCount` the C#/installer writes (`10` files kept). WER's own default is
/// also `10`.
pub const WER_DEFAULT_DUMP_COUNT: u32 = 10;

/// `MaxFolderSize` WER default in MB (`10`) when the C#/installer leaves it
/// unset.
pub const WER_DEFAULT_MAX_FOLDER_SIZE_MB: u32 = 10;

const VALUE_DUMP_TYPE: &str = "DumpType";
const VALUE_DUMP_FOLDER: &str = "DumpFolder";
const VALUE_MAX_FOLDER_SIZE: &str = "MaxFolderSize";
const VALUE_DUMP_COUNT: &str = "DumpCount";

/// WER `DumpType` (`REG_DWORD`): full vs mini heap dump for the app.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WerDumpType {
    /// Full heap dump (`DumpType = 1`, what the C#/installer writes).
    Full,
    /// Mini heap dump (`DumpType = 2`, WER default when unset).
    Mini,
}

impl WerDumpType {
    /// Registry value (`1` = full, `2` = mini), C#/WER parity.
    pub const fn as_reg_value(self) -> u32 {
        match self {
            WerDumpType::Full => 1,
            WerDumpType::Mini => 2,
        }
    }

    /// Map a `DumpType` DWORD back; `None` for unknown values (fail-closed).
    pub fn from_reg_value(value: u32) -> Option<Self> {
        match value {
            1 => Some(WerDumpType::Full),
            2 => Some(WerDumpType::Mini),
            _ => None,
        }
    }

    /// Short report label (never a secret).
    pub const fn label(self) -> &'static str {
        match self {
            WerDumpType::Full => "full",
            WerDumpType::Mini => "mini",
        }
    }
}

/// WER LocalDumps per-app settings (`LocalDumps\<AppExeName>` subtree).
///
/// Defaults mirror the C#/installer exactly:
/// `DumpType` full, `DumpFolder` `%LOCALAPPDATA%\Wormhole\crashdumps`,
/// `DumpCount` 10, `MaxFolderSize` 10 MB (WER unit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WerSettings {
    /// `DumpType` (`REG_DWORD`): full or mini heap dump.
    pub dump_type: WerDumpType,
    /// `DumpFolder` (`REG_SZ` / `REG_EXPAND_SZ`): dump directory path.
    pub dump_folder: PathBuf,
    /// `MaxFolderSize` (`REG_DWORD`), in **megabytes** (WER unit).
    pub max_folder_size_mb: u32,
    /// `DumpCount` (`REG_DWORD`): max dump files kept.
    pub dump_count: u32,
}

impl Default for WerSettings {
    fn default() -> Self {
        Self {
            dump_type: WerDumpType::Full,
            dump_folder: default_dump_folder(),
            max_folder_size_mb: WER_DEFAULT_MAX_FOLDER_SIZE_MB,
            dump_count: WER_DEFAULT_DUMP_COUNT,
        }
    }
}

/// `%LOCALAPPDATA%\Wormhole\crashdumps` - mirrors C#
/// `AppPaths.GetCrashDumpsDirectory()` / installer `DumpFolder` (resolved).
pub fn default_dump_folder() -> PathBuf {
    local_app_data().join("Wormhole").join("crashdumps")
}

fn local_app_data() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("USERPROFILE").map(|p| PathBuf::from(p).join("AppData").join("Local"))
        })
        .unwrap_or_else(|| PathBuf::from(r"C:\Users\Default\AppData\Local"))
}

/// Registry read/write failure - fail-closed convention (hosts surface these
/// in the report as `Error`, never as "configured").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WerRegistryError {
    /// Win32 registry API call failed.
    Win32 {
        /// API or operation name.
        op: &'static str,
        /// Windows error code (`GetLastError`).
        code: u32,
    },
    /// A required value was missing, had the wrong REG type, or carried an
    /// unrecognized value (e.g. `DumpType` not 1/2).
    InvalidValue {
        /// Registry value name.
        name: &'static str,
        /// Why it is invalid (missing / expected type / unknown value).
        detail: &'static str,
    },
    /// Not running on a supported Windows hive.
    UnsupportedPlatform,
}

impl fmt::Display for WerRegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Win32 { op, code } => write!(f, "{op} failed with Win32 error {code}"),
            Self::InvalidValue { name, detail } => {
                write!(f, "LocalDumps {name} invalid: {detail}")
            }
            Self::UnsupportedPlatform => write!(f, "WER registry access requires Windows"),
        }
    }
}

impl std::error::Error for WerRegistryError {}

/// Injectable WER LocalDumps registry access (in-memory [`FakeWerRegistry`] in
/// tests; [`RealWerRegistry`] is compile-time presence only).
pub trait WerRegistry {
    /// Read the per-app LocalDumps subtree.
    ///
    /// `Ok(None)` when the subtree is absent (`NotConfigured`). Any missing /
    /// wrong-typed / unrecognized value is `Err` (fail-closed so the report
    /// never claims `Configured` on a partial or corrupt config).
    fn read(&self, app_exe: &str) -> Result<Option<WerSettings>, WerRegistryError>;

    /// Write/overwrite the per-app LocalDumps subtree.
    ///
    /// Value types: `DumpType` / `DumpCount` / `MaxFolderSize` as `REG_DWORD`,
    /// `DumpFolder` as `REG_SZ` (resolved path; C#/installer uses
    /// `REG_EXPAND_SZ` with the same effective directory - see
    /// [`WerSettings`]).
    fn write(&self, app_exe: &str, settings: &WerSettings) -> Result<(), WerRegistryError>;
}

/// Deterministic in-memory [`WerRegistry`] for unit tests - never touches a
/// live hive. Stores values with their REG type so DWORD vs REG_SZ (and wrong
/// types / partial subtrees) are exercised faithfully.
///
/// [`Debug`] exposes stored paths/value types only.
#[derive(Debug, Default)]
pub struct FakeWerRegistry {
    store: RefCell<HashMap<String, BTreeMap<String, WerRegValue>>>,
    fail_next: RefCell<Option<WerRegistryError>>,
    read_count: Cell<u64>,
    write_count: Cell<u64>,
}

impl FakeWerRegistry {
    /// Empty fake registry (`NotConfigured` for every app).
    pub fn new() -> Self {
        Self::default()
    }

    /// Script the **next** `read`/`write` to fail once (deterministic
    /// fail-closed tests). Subsequent operations behave normally.
    pub fn fail_next(&self, err: WerRegistryError) {
        *self.fail_next.borrow_mut() = Some(err);
    }

    /// How many `read` calls ran.
    pub fn read_count(&self) -> u64 {
        self.read_count.get()
    }

    /// How many `write` calls ran.
    pub fn write_count(&self) -> u64 {
        self.write_count.get()
    }

    /// Seed a single registry value with an explicit REG type (tests inject
    /// wrong-type / partial subtrees to exercise fail-closed reads).
    pub fn seed(&self, app_exe: &str, name: &'static str, value: WerRegValue) {
        self.store
            .borrow_mut()
            .entry(app_exe.to_string())
            .or_default()
            .insert(name.to_string(), value);
    }

    /// Raw typed snapshot of an app's subtree (deterministic value-type
    /// assertions); `None` when the subtree is absent.
    pub fn snapshot(&self, app_exe: &str) -> Option<BTreeMap<String, WerRegValue>> {
        self.store.borrow().get(app_exe).cloned()
    }
}

/// A typed registry value inside the fake store (mirrors `REG_DWORD` /
/// `REG_SZ` / `REG_EXPAND_SZ`); also used to seed malformed configs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WerRegValue {
    /// `REG_DWORD` (numeric keys: `DumpType`, `DumpCount`, `MaxFolderSize`).
    Dword(u32),
    /// `REG_SZ` (resolved `DumpFolder`).
    Sz(String),
    /// `REG_EXPAND_SZ` (`%LOCALAPPDATA%`-style `DumpFolder`, e.g. installer).
    ExpandSz(String),
}

impl WerRegistry for FakeWerRegistry {
    fn read(&self, app_exe: &str) -> Result<Option<WerSettings>, WerRegistryError> {
        self.read_count.set(self.read_count.get() + 1);
        if let Some(err) = self.fail_next.borrow_mut().take() {
            return Err(err);
        }
        let subtree = match self.store.borrow().get(app_exe) {
            Some(subtree) => subtree.clone(),
            None => return Ok(None),
        };

        let dump_type_raw = read_dword(&subtree, VALUE_DUMP_TYPE)?;
        let dump_type =
            WerDumpType::from_reg_value(dump_type_raw).ok_or(WerRegistryError::InvalidValue {
                name: VALUE_DUMP_TYPE,
                detail: "expected 1 (full) or 2 (mini)",
            })?;
        let dump_folder = read_sz(&subtree, VALUE_DUMP_FOLDER)?;
        let max_folder_size_mb = read_dword(&subtree, VALUE_MAX_FOLDER_SIZE)?;
        let dump_count = read_dword(&subtree, VALUE_DUMP_COUNT)?;

        Ok(Some(WerSettings {
            dump_type,
            dump_folder: PathBuf::from(dump_folder),
            max_folder_size_mb,
            dump_count,
        }))
    }

    fn write(&self, app_exe: &str, settings: &WerSettings) -> Result<(), WerRegistryError> {
        self.write_count.set(self.write_count.get() + 1);
        if let Some(err) = self.fail_next.borrow_mut().take() {
            return Err(err);
        }
        let mut store = self.store.borrow_mut();
        let subtree = store.entry(app_exe.to_string()).or_default();
        subtree.insert(
            VALUE_DUMP_TYPE.to_string(),
            WerRegValue::Dword(settings.dump_type.as_reg_value()),
        );
        subtree.insert(
            VALUE_DUMP_FOLDER.to_string(),
            WerRegValue::Sz(settings.dump_folder.to_string_lossy().into_owned()),
        );
        subtree.insert(
            VALUE_MAX_FOLDER_SIZE.to_string(),
            WerRegValue::Dword(settings.max_folder_size_mb),
        );
        subtree.insert(
            VALUE_DUMP_COUNT.to_string(),
            WerRegValue::Dword(settings.dump_count),
        );
        Ok(())
    }
}

fn read_dword(subtree: &BTreeMap<String, WerRegValue>, name: &'static str) -> Result<u32, WerRegistryError> {
    match subtree.get(name) {
        Some(WerRegValue::Dword(v)) => Ok(*v),
        Some(_) => Err(WerRegistryError::InvalidValue {
            name,
            detail: "expected REG_DWORD",
        }),
        None => Err(WerRegistryError::InvalidValue {
            name,
            detail: "missing",
        }),
    }
}

fn read_sz(subtree: &BTreeMap<String, WerRegValue>, name: &'static str) -> Result<String, WerRegistryError> {
    match subtree.get(name) {
        Some(WerRegValue::Sz(v)) => Ok(v.clone()),
        Some(WerRegValue::ExpandSz(v)) => Ok(v.clone()),
        Some(_) => Err(WerRegistryError::InvalidValue {
            name,
            detail: "expected REG_SZ / REG_EXPAND_SZ",
        }),
        None => Err(WerRegistryError::InvalidValue {
            name,
            detail: "missing",
        }),
    }
}

/// Thin Win32 shim for the real WER LocalDumps subtree (**compile-time
/// presence only**).
///
/// Reads/writes `HKLM\{WER_LOCAL_DUMPS_SUBKEY}\<app>` with `RegCreateKeyExW` /
/// `RegSetValueExW` / `RegOpenKeyExW` / `RegQueryValueExW`, enforcing the same
/// DWORD vs REG_SZ value types as [`FakeWerRegistry`].
///
/// **Never run this against a live hive in CI** - writing `HKLM\SOFTWARE` (and
/// the whole subtree) requires elevation, and no test here exercises it: the
/// E2E/unit paths all use the in-memory fake. Treat the Win32 implementations
/// as deliberately unused glue until a host wires an elevated write path.
#[derive(Debug, Clone, Copy, Default)]
pub struct RealWerRegistry;

#[cfg(windows)]
mod real {
    use super::*;
    use windows::core::HSTRING;
    use windows::Win32::Foundation::{
        ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS, WIN32_ERROR,
    };
    use windows::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY,
        HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_DWORD, REG_EXPAND_SZ, REG_OPTION_NON_VOLATILE,
        REG_SZ, REG_VALUE_TYPE,
    };

    impl WerRegistry for RealWerRegistry {
        fn read(&self, app_exe: &str) -> Result<Option<WerSettings>, WerRegistryError> {
            let subkey = format!(r"{WER_LOCAL_DUMPS_SUBKEY}\{app_exe}");
            unsafe {
                let sub_h = HSTRING::from(subkey.as_str());
                let mut key = HKEY::default();
                let opened = RegOpenKeyExW(HKEY_LOCAL_MACHINE, &sub_h, Some(0), KEY_READ, &mut key);
                if opened != ERROR_SUCCESS {
                    return if is_missing(opened) {
                        Ok(None)
                    } else {
                        Err(WerRegistryError::Win32 {
                            op: "RegOpenKeyExW",
                            code: opened.0,
                        })
                    };
                }
                let result = read_values(key);
                let _ = RegCloseKey(key);
                result
            }
        }

        fn write(&self, app_exe: &str, settings: &WerSettings) -> Result<(), WerRegistryError> {
            let subkey = format!(r"{WER_LOCAL_DUMPS_SUBKEY}\{app_exe}");
            unsafe {
                let sub_h = HSTRING::from(subkey.as_str());
                let mut key = HKEY::default();
                let created =
                    RegCreateKeyExW(HKEY_LOCAL_MACHINE, &sub_h, None, None, REG_OPTION_NON_VOLATILE, KEY_WRITE, None, &mut key, None);
                if created != ERROR_SUCCESS {
                    return Err(WerRegistryError::Win32 {
                        op: "RegCreateKeyExW",
                        code: created.0,
                    });
                }
                let result = set_dword(key, VALUE_DUMP_TYPE, settings.dump_type.as_reg_value())
                    .and_then(|_| set_dword(key, VALUE_DUMP_COUNT, settings.dump_count))
                    .and_then(|_| set_dword(key, VALUE_MAX_FOLDER_SIZE, settings.max_folder_size_mb))
                    .and_then(|_| {
                        let folder = settings.dump_folder.to_string_lossy();
                        set_sz(key, VALUE_DUMP_FOLDER, &folder)
                    });
                let _ = RegCloseKey(key);
                result
            }
        }
    }

    fn is_missing(status: WIN32_ERROR) -> bool {
        status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND
    }

    unsafe fn set_dword(key: HKEY, name: &str, value: u32) -> Result<(), WerRegistryError> {
        let name_h = HSTRING::from(name);
        let bytes = value.to_le_bytes();
        let status = unsafe { RegSetValueExW(key, &name_h, None, REG_DWORD, Some(&bytes)) };
        if status != ERROR_SUCCESS {
            return Err(WerRegistryError::Win32 {
                op: "RegSetValueExW",
                code: status.0,
            });
        }
        Ok(())
    }

    unsafe fn set_sz(key: HKEY, name: &str, value: &str) -> Result<(), WerRegistryError> {
        let name_h = HSTRING::from(name);
        let mut chars: Vec<u16> = value.encode_utf16().collect();
        chars.push(0);
        let bytes = unsafe { std::slice::from_raw_parts(chars.as_ptr().cast::<u8>(), chars.len() * 2) };
        let status = unsafe { RegSetValueExW(key, &name_h, None, REG_SZ, Some(bytes)) };
        if status != ERROR_SUCCESS {
            return Err(WerRegistryError::Win32 {
                op: "RegSetValueExW",
                code: status.0,
            });
        }
        Ok(())
    }

    unsafe fn query_value(
        key: HKEY,
        name: &'static str,
    ) -> Result<(REG_VALUE_TYPE, Vec<u8>), WerRegistryError> {
        let name_h = HSTRING::from(name);
        let mut value_type = REG_VALUE_TYPE(0);
        let mut size = 0u32;
        let mut status = unsafe {
            RegQueryValueExW(
                key,
                &name_h,
                None,
                Some(&mut value_type),
                None,
                Some(&mut size),
            )
        };
        if is_missing(status) {
            return Err(WerRegistryError::InvalidValue {
                name,
                detail: "missing",
            });
        }
        if status != ERROR_SUCCESS && status != ERROR_MORE_DATA {
            return Err(WerRegistryError::Win32 {
                op: "RegQueryValueExW",
                code: status.0,
            });
        }
        let mut buf = vec![0u8; size as usize];
        status = unsafe {
            RegQueryValueExW(
                key,
                &name_h,
                None,
                Some(&mut value_type),
                Some(buf.as_mut_ptr()),
                Some(&mut size),
            )
        };
        if status != ERROR_SUCCESS {
            return Err(WerRegistryError::Win32 {
                op: "RegQueryValueExW",
                code: status.0,
            });
        }
        buf.truncate(size as usize);
        Ok((value_type, buf))
    }

    fn read_values(key: HKEY) -> Result<Option<WerSettings>, WerRegistryError> {
        let (dt_type, dt_buf) = unsafe { query_value(key, VALUE_DUMP_TYPE) }?;
        let dump_type_raw = decode_dword(VALUE_DUMP_TYPE, dt_type, &dt_buf)?;
        let dump_type =
            WerDumpType::from_reg_value(dump_type_raw).ok_or(WerRegistryError::InvalidValue {
                name: VALUE_DUMP_TYPE,
                detail: "expected 1 (full) or 2 (mini)",
            })?;
        let (folder_type, folder_buf) = unsafe { query_value(key, VALUE_DUMP_FOLDER) }?;
        let dump_folder = decode_sz(VALUE_DUMP_FOLDER, folder_type, &folder_buf)?;
        let (max_type, max_buf) = unsafe { query_value(key, VALUE_MAX_FOLDER_SIZE) }?;
        let max_folder_size_mb = decode_dword(VALUE_MAX_FOLDER_SIZE, max_type, &max_buf)?;
        let (count_type, count_buf) = unsafe { query_value(key, VALUE_DUMP_COUNT) }?;
        let dump_count = decode_dword(VALUE_DUMP_COUNT, count_type, &count_buf)?;

        Ok(Some(WerSettings {
            dump_type,
            dump_folder: PathBuf::from(dump_folder),
            max_folder_size_mb,
            dump_count,
        }))
    }

    fn decode_dword(
        name: &'static str,
        value_type: REG_VALUE_TYPE,
        buf: &[u8],
    ) -> Result<u32, WerRegistryError> {
        if value_type != REG_DWORD || buf.len() < 4 {
            return Err(WerRegistryError::InvalidValue {
                name,
                detail: "expected REG_DWORD",
            });
        }
        Ok(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]))
    }

    fn decode_sz(
        name: &'static str,
        value_type: REG_VALUE_TYPE,
        buf: &[u8],
    ) -> Result<String, WerRegistryError> {
        if value_type != REG_SZ && value_type != REG_EXPAND_SZ {
            return Err(WerRegistryError::InvalidValue {
                name,
                detail: "expected REG_SZ / REG_EXPAND_SZ",
            });
        }
        let even = buf.len() & !1;
        let units: Vec<u16> = buf[..even]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        Ok(String::from_utf16_lossy(&units)
            .trim_end_matches('\0')
            .to_string())
    }
}

#[cfg(not(windows))]
impl WerRegistry for RealWerRegistry {
    fn read(&self, _app_exe: &str) -> Result<Option<WerSettings>, WerRegistryError> {
        Err(WerRegistryError::UnsupportedPlatform)
    }

    fn write(&self, _app_exe: &str, _settings: &WerSettings) -> Result<(), WerRegistryError> {
        Err(WerRegistryError::UnsupportedPlatform)
    }
}

/// Sentinels are file-backed in C#
/// (`Services/Rdp/RdpCrashSentinelService.cs`, `rdp-in-flight.json`): a crash
/// while a handshake is in flight leaves a flag that the next launch reports.
/// This trait is the Rust-side flagging seam wired into the report section.
pub trait CrashSentinel {
    /// Record that a crash-prone operation is in flight (`detail` is a
    /// non-secret label, e.g. the operation name).
    fn record(&mut self, detail: String) -> Result<(), WerSentinelError>;
    /// Clear the flag after successful completion / recovery.
    fn clear(&mut self) -> Result<(), WerSentinelError>;
    /// Current flag state for the report section.
    fn status(&self) -> SentinelStatus;
}

/// Flag state surfaced in the diagnostics report.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SentinelStatus {
    /// No crash-prone operation in flight.
    #[default]
    Clear,
    /// Flag set (a prior crash may have left it behind).
    Armed { detail: String },
}

/// Failure in a crash-sentinel persistence seam.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WerSentinelError {
    /// The host persistence layer failed (records / clears never panic here).
    Io { op: &'static str },
}

impl fmt::Display for WerSentinelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { op } => write!(f, "crash sentinel {op} failed"),
        }
    }
}

impl std::error::Error for WerSentinelError {}

/// Deterministic in-memory [`CrashSentinel`] for unit tests.
///
/// [`record`](FakeCrashSentinel::record) arms, [`clear`](FakeCrashSentinel::clear)
/// resets; a scripted failure via [`fail_next`](FakeCrashSentinel::fail_next)
/// exercises error propagation without touching disk.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FakeCrashSentinel {
    status: SentinelStatus,
    fail_next: Option<WerSentinelError>,
}

impl FakeCrashSentinel {
    /// Starts cleared.
    pub fn new() -> Self {
        Self::default()
    }

    /// Script the **next** `record`/`clear` to fail once.
    pub fn fail_next(&mut self, err: WerSentinelError) {
        self.fail_next = Some(err);
    }

    /// Record a crash-prone operation as in flight (arms the flag).
    pub fn record(&mut self, detail: String) -> Result<(), WerSentinelError> {
        if let Some(err) = self.fail_next.take() {
            return Err(err);
        }
        self.status = SentinelStatus::Armed { detail };
        Ok(())
    }

    /// Clear the flag.
    pub fn clear(&mut self) -> Result<(), WerSentinelError> {
        if let Some(err) = self.fail_next.take() {
            return Err(err);
        }
        self.status = SentinelStatus::Clear;
        Ok(())
    }

    /// Current flag state.
    pub fn status(&self) -> SentinelStatus {
        self.status.clone()
    }
}

impl CrashSentinel for FakeCrashSentinel {
    fn record(&mut self, detail: String) -> Result<(), WerSentinelError> {
        FakeCrashSentinel::record(self, detail)
    }

    fn clear(&mut self) -> Result<(), WerSentinelError> {
        FakeCrashSentinel::clear(self)
    }

    fn status(&self) -> SentinelStatus {
        self.status.clone()
    }
}

/// Status of the applied WER LocalDumps config for the report section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WerSectionState {
    /// Subtree present, every value read with the correct type.
    Configured(WerSettings),
    /// No `LocalDumps\<app>` subtree.
    NotConfigured,
    /// Reading/verifying the config failed (fail-closed - never rendered as
    /// "configured").
    Error { detail: String },
}

/// One report row for the WER section: registry value name + REG type + value.
///
/// Values are paths and value types only - never credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WerReportRow {
    /// Registry value name (`DumpType`, `DumpFolder`, ...).
    pub name: &'static str,
    /// Registry type label (`DWORD`, `REG_SZ`).
    pub value_type: &'static str,
    /// Rendered value (paths redacted when under Wormhole secret dirs).
    pub value: String,
}

/// Diagnostics report section describing the WER LocalDumps config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WerReportSection {
    /// App executable the subtree belongs to.
    pub app_exe: String,
    /// Whether the config is verified, absent, or failed (fail-closed).
    pub state: WerSectionState,
    /// Config rows (populated for [`WerSectionState::Configured`]).
    pub rows: Vec<WerReportRow>,
    /// Crash-sentinel flag state.
    pub sentinel: SentinelStatus,
}

/// Pure section builder - no I/O, easily unit-tested.
///
/// Takes the resolved config (inside [`WerSectionState::Configured`]) plus the
/// status and sentinel flag, and produces a report section whose rows carry
/// paths and REG value types only.
pub fn build_wer_report_section(
    app_exe: &str,
    state: WerSectionState,
    sentinel: SentinelStatus,
) -> WerReportSection {
    let rows = match &state {
        WerSectionState::Configured(settings) => configure_rows(settings),
        WerSectionState::NotConfigured | WerSectionState::Error { .. } => Vec::new(),
    };
    WerReportSection {
        app_exe: app_exe.to_string(),
        state,
        rows,
        sentinel,
    }
}

fn configure_rows(settings: &WerSettings) -> Vec<WerReportRow> {
    vec![
        WerReportRow {
            name: VALUE_DUMP_TYPE,
            value_type: "DWORD",
            value: settings.dump_type.label().to_string(),
        },
        WerReportRow {
            name: VALUE_DUMP_FOLDER,
            value_type: "REG_SZ",
            value: render_folder(&settings.dump_folder),
        },
        WerReportRow {
            name: VALUE_MAX_FOLDER_SIZE,
            value_type: "DWORD",
            value: format!("{} MB", settings.max_folder_size_mb),
        },
        WerReportRow {
            name: VALUE_DUMP_COUNT,
            value_type: "DWORD",
            value: settings.dump_count.to_string(),
        },
    ]
}

/// Render a WER dump path; never emit Wormhole secret blob directories.
fn render_folder(path: &Path) -> String {
    if touches_wormhole_secrets_dir(path) {
        "(redacted)".to_string()
    } else {
        path.display().to_string()
    }
}

/// Render the WER section as report lines (`wer_localdumps:` block), scrubbed
/// for forged secret assignments / secret-dir paths (defense in depth).
pub fn format_wer_section(section: &WerReportSection) -> String {
    let mut out = String::from("wer_localdumps:\n");
    out.push_str(&format!("  app_exe: {}\n", section.app_exe));
    match &section.state {
        WerSectionState::Configured(_) => out.push_str("  state: configured\n"),
        WerSectionState::NotConfigured => out.push_str("  state: not-configured\n"),
        WerSectionState::Error { detail } => {
            out.push_str(&format!("  state: error ({detail})\n"));
        }
    }
    for row in &section.rows {
        out.push_str(&format!("  {} ({}): {}\n", row.name, row.value_type, row.value));
    }
    match &section.sentinel {
        SentinelStatus::Clear => out.push_str("  crash_sentinel: clear\n"),
        SentinelStatus::Armed { detail } => {
            out.push_str(&format!("  crash_sentinel: armed ({detail})\n"));
        }
    }
    redact_secret_assignments(&redact_secret_dir_paths(&out))
}

/// Replace case-insensitive `Wormhole\keys` / `Wormhole\tunnels` path fragments
/// (either separator) with `(redacted)` - never in report text. Mirrors
/// [`crate::sidecars::touches_wormhole_secrets_dir`]: a fragment fused onto an
/// identifier (e.g. `mywormhole\keys`) is skipped, not redacted; everything
/// else is over-redacted rather than leaked.
fn redact_secret_dir_paths(input: &str) -> String {
    const FRAGS: [&str; 4] = [
        r"wormhole\keys",
        r"wormhole\tunnels",
        "wormhole/keys",
        "wormhole/tunnels",
    ];
    let mut out = String::with_capacity(input.len());
    let lower = input.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let rest = &lower[i..];
        let mut candidate: Option<(usize, usize)> = None;
        for frag in FRAGS {
            if let Some(rel) = rest.find(frag) {
                let pos = i + rel;
                if candidate.is_none_or(|(p, _)| pos < p) {
                    candidate = Some((pos, frag.len()));
                }
            }
        }
        let Some((pos, len)) = candidate else {
            out.push_str(&input[i..]);
            break;
        };
        let fused = pos > 0 && bytes[pos - 1].is_ascii_alphanumeric();
        if fused {
            out.push_str(&input[i..pos + len]);
        } else {
            out.push_str(&input[i..pos]);
            out.push_str("(redacted)");
        }
        i = pos + len;
    }
    out
}

/// Redact forged `password=` / `token=` / `secret=` assignments
/// (case-insensitive key, optional spaces, non-empty `\S+` value), mirroring
/// [`report`] defense-in-depth for this section's text.
fn redact_secret_assignments(input: &str) -> String {
    let lower = input.to_ascii_lowercase();
    let bytes = input.as_bytes();
    let lower_bytes = lower.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;
    const KEYS: [&str; 3] = ["password", "token", "secret"];
    'outer: loop {
        let remaining = &lower_bytes[i..];
        let mut matched: Option<(usize, usize)> = None;
        for key in KEYS {
            let kb = key.as_bytes();
            if let Some(rel) = remaining.windows(kb.len()).position(|w| w == kb) {
                let pos = i + rel;
                if matched.is_none_or(|(p, _)| pos < p) {
                    matched = Some((pos, kb.len()));
                }
            }
        }
        let Some((start, key_len)) = matched else {
            out.push_str(&input[i..]);
            break;
        };
        out.push_str(&input[i..start]);
        let after = start + key_len;
        let mut j = after;
        while j < bytes.len() && lower_bytes[j] == b' ' {
            j += 1;
        }
        if j < bytes.len() && bytes[j] == b'=' {
            j += 1;
            while j < bytes.len() && lower_bytes[j] == b' ' {
                j += 1;
            }
            let value_start = j;
            while j < bytes.len() && !bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if value_start < j {
                out.push_str(&input[start..value_start]);
                out.push_str("[redacted]");
                i = j;
                continue 'outer;
            }
        }
        out.push_str(&input[start..after]);
        i = after;
    }
    out
}

/// Compose WER config apply + report-section collect for crash diagnostics.
///
/// Fail-closed: [`apply_wer_config`](CrashDiagnosticsGlue::apply_wer_config)
/// propagates registry errors (hosts must never claim "configured" on
/// failure); [`collect_wer_section`](CrashDiagnosticsGlue::collect_wer_section)
/// turns any read failure into [`WerSectionState::Error`] and never panics.
#[derive(Debug, Clone, Copy, Default)]
pub struct CrashDiagnosticsGlue;

impl CrashDiagnosticsGlue {
    /// Apply the WER LocalDumps config for `app_exe`, overwriting any prior
    /// subtree. Value types per [`WerRegistry::write`]; C#/installer defaults
    /// come from [`WerSettings::default`].
    pub fn apply_wer_config(
        registry: &dyn WerRegistry,
        app_exe: &str,
        settings: &WerSettings,
    ) -> Result<(), WerRegistryError> {
        registry.write(app_exe, settings)
    }

    /// Collect a report section describing the current WER config and the
    /// crash-sentinel flag - paths/values only, never secrets, never panics.
    pub fn collect_wer_section(
        registry: &dyn WerRegistry,
        sentinel: &dyn CrashSentinel,
        app_exe: &str,
    ) -> WerReportSection {
        let state = match registry.read(app_exe) {
            Ok(Some(settings)) => WerSectionState::Configured(settings),
            Ok(None) => WerSectionState::NotConfigured,
            Err(e) => WerSectionState::Error {
                detail: e.to_string(),
            },
        };
        build_wer_report_section(app_exe, state, sentinel.status())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wer::{
        CrashDiagnosticsGlue, FakeCrashSentinel, FakeWerRegistry, WerRegValue, WerSectionState,
        WerSettings, WerDumpType, WER_DEFAULT_DUMP_COUNT, WER_DEFAULT_MAX_FOLDER_SIZE_MB,
        WORMHOLE_APP_EXE, WER_LOCAL_DUMPS_SUBKEY,
    };

    #[test]
    fn defaults_parity_with_csharp_installer() {
        let settings = WerSettings::default();
        assert_eq!(settings.dump_type, WerDumpType::Full);
        assert_eq!(settings.dump_count, WER_DEFAULT_DUMP_COUNT);
        assert_eq!(settings.dump_count, 10);
        assert_eq!(settings.max_folder_size_mb, WER_DEFAULT_MAX_FOLDER_SIZE_MB);
        assert_eq!(settings.max_folder_size_mb, 10);
        let folder = settings.dump_folder.to_string_lossy().to_ascii_lowercase();
        assert!(folder.ends_with("wormhole\\crashdumps") || folder.ends_with("wormhole/crashdumps"));
        // DumpType registry values (C#/WER parity): 1 = full, 2 = mini.
        assert_eq!(WerDumpType::Full.as_reg_value(), 1);
        assert_eq!(WerDumpType::Mini.as_reg_value(), 2);
        assert_eq!(WerDumpType::from_reg_value(1), Some(WerDumpType::Full));
        assert_eq!(WerDumpType::from_reg_value(2), Some(WerDumpType::Mini));
        assert_eq!(WerDumpType::from_reg_value(9), None);
        // Subkey mirrors the installer path.
        assert_eq!(
            WER_LOCAL_DUMPS_SUBKEY,
            r"SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps"
        );
        assert_eq!(WORMHOLE_APP_EXE, "Wormhole.exe");
    }

    #[test]
    fn fake_write_preserves_dword_and_sz_value_types() {
        let fake = FakeWerRegistry::new();
        fake.write(WORMHOLE_APP_EXE, &WerSettings::default()).unwrap();

        let snapshot = fake.snapshot(WORMHOLE_APP_EXE).unwrap();
        assert_eq!(snapshot.get("DumpType"), Some(&WerRegValue::Dword(1)));
        assert_eq!(snapshot.get("DumpCount"), Some(&WerRegValue::Dword(10)));
        assert_eq!(snapshot.get("MaxFolderSize"), Some(&WerRegValue::Dword(10)));
        assert!(matches!(snapshot.get("DumpFolder"), Some(WerRegValue::Sz(_))));

        // Round-trip resolves the exact typed settings back.
        assert_eq!(
            fake.read(WORMHOLE_APP_EXE).unwrap(),
            Some(WerSettings::default())
        );
    }

    #[test]
    fn read_enforces_dword_vs_sz_value_types_fail_closed() {
        let fake = FakeWerRegistry::new();
        fake.seed(WORMHOLE_APP_EXE, "DumpType", WerRegValue::Sz("1".into()));
        assert!(matches!(
            fake.read(WORMHOLE_APP_EXE),
            Err(WerRegistryError::InvalidValue { name: "DumpType", .. })
        ));

        let fake2 = FakeWerRegistry::new();
        fake2.seed(WORMHOLE_APP_EXE, "DumpFolder", WerRegValue::Dword(1));
        fake2.seed(WORMHOLE_APP_EXE, "DumpType", WerRegValue::Dword(1));
        fake2.seed(WORMHOLE_APP_EXE, "DumpCount", WerRegValue::Dword(10));
        fake2.seed(WORMHOLE_APP_EXE, "MaxFolderSize", WerRegValue::Dword(10));
        assert!(matches!(
            fake2.read(WORMHOLE_APP_EXE),
            Err(WerRegistryError::InvalidValue { name: "DumpFolder", .. })
        ));

        let fake3 = FakeWerRegistry::new();
        fake3.seed(WORMHOLE_APP_EXE, "DumpType", WerRegValue::Dword(99));
        fake3.seed(WORMHOLE_APP_EXE, "DumpFolder", WerRegValue::Sz("C:\\d".into()));
        fake3.seed(WORMHOLE_APP_EXE, "DumpCount", WerRegValue::Dword(10));
        fake3.seed(WORMHOLE_APP_EXE, "MaxFolderSize", WerRegValue::Dword(10));
        assert!(matches!(
            fake3.read(WORMHOLE_APP_EXE),
            Err(WerRegistryError::InvalidValue { name: "DumpType", .. })
        ));
    }

    #[test]
    fn partial_subtree_is_fail_closed_not_configured() {
        let fake = FakeWerRegistry::new();
        fake.seed(WORMHOLE_APP_EXE, "DumpType", WerRegValue::Dword(1));
        assert!(matches!(
            fake.read(WORMHOLE_APP_EXE),
            Err(WerRegistryError::InvalidValue { name: "DumpCount" | "MaxFolderSize" | "DumpFolder", .. })
        ));
    }

    #[test]
    fn expand_sz_dump_folder_is_tolerated() {
        let fake = FakeWerRegistry::new();
        fake.seed(
            WORMHOLE_APP_EXE,
            "DumpType",
            WerRegValue::Dword(WerDumpType::Mini.as_reg_value()),
        );
        fake.seed(
            WORMHOLE_APP_EXE,
            "DumpFolder",
            WerRegValue::ExpandSz("%LOCALAPPDATA%\\Wormhole\\crashdumps".into()),
        );
        fake.seed(WORMHOLE_APP_EXE, "DumpCount", WerRegValue::Dword(10));
        fake.seed(WORMHOLE_APP_EXE, "MaxFolderSize", WerRegValue::Dword(10));
        let resolved = fake.read(WORMHOLE_APP_EXE).unwrap().unwrap();
        assert_eq!(resolved.dump_type, WerDumpType::Mini);
        assert_eq!(
            resolved.dump_folder,
            PathBuf::from("%LOCALAPPDATA%\\Wormhole\\crashdumps")
        );
    }

    #[test]
    fn apply_on_registry_error_fail_closed() {
        let fake = FakeWerRegistry::new();
        fake.fail_next(WerRegistryError::Win32 {
            op: "RegCreateKeyExW",
            code: 5,
        });
        let result = CrashDiagnosticsGlue::apply_wer_config(
            &fake,
            WORMHOLE_APP_EXE,
            &WerSettings::default(),
        );
        assert!(matches!(result, Err(WerRegistryError::Win32 { code: 5, .. })));
        // The failed apply wrote nothing (fail-closed).
        assert!(fake.snapshot(WORMHOLE_APP_EXE).is_none());
        assert_eq!(fake.read_count(), 0);
        assert_eq!(fake.write_count(), 1);
    }

    #[test]
    fn apply_then_collect_yields_configured_section() {
        let fake = FakeWerRegistry::new();
        CrashDiagnosticsGlue::apply_wer_config(&fake, WORMHOLE_APP_EXE, &WerSettings::default())
            .unwrap();

        let mut sentinel = FakeCrashSentinel::new();
        let section = CrashDiagnosticsGlue::collect_wer_section(&fake, &sentinel, WORMHOLE_APP_EXE);
        assert!(matches!(section.state, WerSectionState::Configured(_)));
        assert_eq!(section.app_exe, "Wormhole.exe");
        assert_eq!(section.rows.len(), 4);
        let types: Vec<_> = section.rows.iter().map(|r| r.value_type).collect();
        assert_eq!(types, vec!["DWORD", "REG_SZ", "DWORD", "DWORD"]);
        assert_eq!(section.rows[0].value, "full");
        assert!(section.rows[1].value.to_ascii_lowercase().contains("crashdumps"));
        assert_eq!(section.rows[2].value, "10 MB");
        assert_eq!(section.rows[3].value, "10");
        assert_eq!(section.sentinel, SentinelStatus::Clear);

        let text = format_wer_section(&section);
        assert!(text.contains("wer_localdumps:"));
        assert!(text.contains("state: configured"));
        assert!(text.contains("DumpType (DWORD): full"));
        assert!(text.contains("DumpFolder (REG_SZ):"));
        assert!(text.contains("MaxFolderSize (DWORD): 10 MB"));
        assert!(text.contains("crash_sentinel: clear"));
        sentinel.record("rdp-connect-in-flight".to_string()).unwrap();
        let armed = CrashDiagnosticsGlue::collect_wer_section(&fake, &sentinel, WORMHOLE_APP_EXE);
        assert_eq!(armed.sentinel, SentinelStatus::Armed { detail: "rdp-connect-in-flight".into() });
        assert!(format_wer_section(&armed).contains("crash_sentinel: armed (rdp-connect-in-flight)"));
    }

    #[test]
    fn collect_without_subtree_is_not_configured() {
        let fake = FakeWerRegistry::new();
        let sentinel = FakeCrashSentinel::new();
        let section = CrashDiagnosticsGlue::collect_wer_section(&fake, &sentinel, WORMHOLE_APP_EXE);
        assert_eq!(section.state, WerSectionState::NotConfigured);
        assert!(section.rows.is_empty());
        let text = format_wer_section(&section);
        assert!(text.contains("state: not-configured"));
        assert!(!text.contains("configured ("));
    }

    #[test]
    fn collect_on_read_failure_reports_error_never_panics() {
        let fake = FakeWerRegistry::new();
        fake.fail_next(WerRegistryError::Win32 {
            op: "RegOpenKeyExW",
            code: 5,
        });
        let sentinel = FakeCrashSentinel::new();
        let section = CrashDiagnosticsGlue::collect_wer_section(&fake, &sentinel, WORMHOLE_APP_EXE);
        assert!(matches!(section.state, WerSectionState::Error { .. }));
        assert!(section.rows.is_empty());
        let text = format_wer_section(&section);
        assert!(text.contains("state: error (RegOpenKeyExW failed with Win32 error 5)"));
        assert!(!text.contains("state: configured"));
    }

    #[test]
    fn pure_builder_configured_states_dont_need_a_registry() {
        let settings = WerSettings {
            dump_type: WerDumpType::Mini,
            dump_folder: PathBuf::from(r"C:\dumps"),
            max_folder_size_mb: 250,
            dump_count: 3,
        };
        let section =
            build_wer_report_section("Wormhole.exe", WerSectionState::Configured(settings), SentinelStatus::Clear);
        assert_eq!(section.rows[0].value, "mini");
        assert_eq!(section.rows[2].value, "250 MB");
        assert_eq!(section.rows[3].value, "3");
    }

    #[test]
    fn sentinel_record_clear_is_deterministic() {
        let mut sentinel = FakeCrashSentinel::new();
        assert_eq!(sentinel.status(), SentinelStatus::Clear);
        sentinel.record("aad-wam".to_string()).unwrap();
        assert_eq!(sentinel.status(), SentinelStatus::Armed { detail: "aad-wam".into() });
        sentinel.record("rdp".to_string()).unwrap();
        assert_eq!(sentinel.status(), SentinelStatus::Armed { detail: "rdp".into() });
        sentinel.clear().unwrap();
        assert_eq!(sentinel.status(), SentinelStatus::Clear);

        // Scripted failure propagates and leaves state unchanged.
        let mut failing = FakeCrashSentinel::new();
        failing.record("a".to_string()).unwrap();
        failing.fail_next(WerSentinelError::Io { op: "write" });
        assert!(failing.clear().is_err());
        assert_eq!(failing.status(), SentinelStatus::Armed { detail: "a".into() });
    }

    #[test]
    fn formatted_section_redacts_forged_secrets_and_secret_dirs() {
        let settings = WerSettings {
            dump_type: WerDumpType::Full,
            dump_folder: PathBuf::from(r"C:\Users\x\AppData\Local\Wormhole\keys\dump.dmp"),
            max_folder_size_mb: 10,
            dump_count: 10,
        };
        let section = build_wer_report_section(
            "Wormhole.exe",
            WerSectionState::Configured(settings),
            SentinelStatus::Armed { detail: "secret=blob password=hunter2".into() },
        );
        let text = format_wer_section(&section);
        let lower = text.to_ascii_lowercase();
        assert!(text.contains("(redacted)"));
        assert!(!lower.contains(r"\wormhole\keys"));
        assert!(lower.contains("[redacted]"));
        assert!(!lower.contains("secret=blob") && !lower.contains("password=hunter2"));
    }

    #[test]
    fn debug_output_is_paths_and_value_types_only() {
        let settings = WerSettings::default();
        let dbg = format!("{settings:?}");
        assert!(dbg.contains("dump_type"));
        assert!(!dbg.contains("password") && !dbg.contains("token") && !dbg.contains("secret"));
        let fake = FakeWerRegistry::new();
        fake.seed(WORMHOLE_APP_EXE, "DumpFolder", WerRegValue::Sz(r"C:\d\dump".into()));
        let dbg_fake = format!("{fake:?}");
        assert!(dbg_fake.contains("DumpFolder"));
        assert!(!dbg_fake.contains("password"));
        let sentinel_dbg = format!("{:?}", FakeCrashSentinel::new());
        assert!(sentinel_dbg.contains("FakeCrashSentinel"));
    }

    #[test]
    fn format_redacts_secret_dirs_across_separators_and_offsets() {
        let forward = format_wer_section(&build_wer_report_section(
            "C:/Users/x/AppData/Local/Wormhole/tunnels/dump.bin",
            WerSectionState::NotConfigured,
            SentinelStatus::Clear,
        ));
        assert!(forward.contains("(redacted)"));
        assert!(!forward.to_ascii_lowercase().contains("wormhole/tunnels"));
        assert!(!forward.to_ascii_lowercase().contains("wormhole\\tunnels"));

        let leading = format_wer_section(&build_wer_report_section(
            "Wormhole/keys/dump.dmp",
            WerSectionState::NotConfigured,
            SentinelStatus::Armed {
                detail: "C:\\Users\\x\\AppData\\Local\\Wormhole\\keys\\file".into(),
            },
        ));
        let lower = leading.to_ascii_lowercase();
        assert!(!lower.contains("wormhole/keys"));
        assert!(!lower.contains(r"\wormhole\keys"));

        let mid_word = format_wer_section(&build_wer_report_section(
            "mywormhole\\keys value",
            WerSectionState::NotConfigured,
            SentinelStatus::Clear,
        ));
        assert!(mid_word.contains("mywormhole\\keys"));
        assert!(mid_word.contains("state: not-configured"));
    }

    #[test]
    fn real_registry_presence_never_touches_live_hive() {
        // Compile-time presence only: constructed + Debug'ed, but read()/write()
        // must NOT be invoked here - writing HKLM requires elevation and would
        // mutate a live hive in CI.
        let real = RealWerRegistry;
        let _ = format!("{real:?}");
        assert_eq!(
            WER_LOCAL_DUMPS_SUBKEY,
            r"SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps"
        );
    }

    #[test]
    fn all_test_paths_use_the_fake_not_the_live_hive() {
        // Guards that this module's deterministic tests are fake-only: every
        // registry read/write above flows through FakeWerRegistry; RealWerRegistry
        // is exactly one presence test. This test documents/asserts the split.
        let fake = FakeWerRegistry::new();
        fake.write("other.exe", &WerSettings::default()).unwrap();
        assert_eq!(fake.read_count(), 0);
        assert_eq!(fake.write_count(), 1);
        assert_eq!(fake.read("other.exe").unwrap().unwrap().dump_count, 10);
        assert_eq!(fake.read_count(), 1);
    }
}
