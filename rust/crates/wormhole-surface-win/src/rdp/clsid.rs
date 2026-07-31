//! MsRdpClient CLSID selection (newest registered of 11 → 10 → 9).

use windows::core::GUID;
use windows::Win32::System::Registry::{RegCloseKey, RegOpenKeyExW, HKEY_CLASSES_ROOT, KEY_READ};

/// A preferred MsRdpClient*NotSafeForScripting class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RdpActiveXClass {
    /// Prog-friendly name (e.g. `MsRdpClient9NotSafeForScripting`).
    pub name: &'static str,
    /// CLSID string without braces.
    pub clsid_string: &'static str,
    /// Parsed CLSID.
    pub guid: GUID,
}

/// Preference order matching C# `AxMsRdpClient9NotSafeForScripting`.
pub const PREFERRED_CLASSES: &[RdpActiveXClass] = &[
    RdpActiveXClass {
        name: "MsRdpClient11NotSafeForScripting",
        clsid_string: "1DF7C823-B2D4-4B54-975A-F2AC5D7CF8B8",
        guid: GUID::from_u128(0x1DF7_C823_B2D4_4B54_975A_F2AC_5D7C_F8B8),
    },
    RdpActiveXClass {
        name: "MsRdpClient10NotSafeForScripting",
        clsid_string: "A0C63C30-F08D-4AB4-907C-34905D770C7D",
        guid: GUID::from_u128(0xA0C6_3C30_F08D_4AB4_907C_3490_5D77_0C7D),
    },
    RdpActiveXClass {
        name: "MsRdpClient9NotSafeForScripting",
        clsid_string: "8B918B82-7985-4C24-89DF-C33AD2BBFBCD",
        guid: GUID::from_u128(0x8B91_8B82_7985_4C24_89DF_C33A_D2BB_FBCD),
    },
];

/// Probe `HKCR\CLSID\{…}` for preferred classes (best-effort).
///
/// If none are registered, returns the v9 fallback so CoCreate can surface the real COM error.
pub fn probe_registered_classes() -> Vec<RdpActiveXClass> {
    let mut registered = Vec::new();
    for candidate in PREFERRED_CLASSES {
        if clsid_key_exists(candidate.clsid_string) {
            registered.push(*candidate);
        }
    }
    if registered.is_empty() {
        registered.push(PREFERRED_CLASSES[PREFERRED_CLASSES.len() - 1]);
    }
    registered
}

/// Newest registered preferred class (v9 fallback always present in the probe list).
pub fn select_best_rdp_class() -> RdpActiveXClass {
    probe_registered_classes()[0]
}

fn clsid_key_exists(clsid: &str) -> bool {
    let sub = windows::core::HSTRING::from(format!("CLSID\\{{{clsid}}}"));
    unsafe {
        let mut key = Default::default();
        let opened = RegOpenKeyExW(HKEY_CLASSES_ROOT, &sub, Some(0), KEY_READ, &mut key);
        if opened.is_ok() {
            let _ = RegCloseKey(key);
            true
        } else {
            false
        }
    }
}
