//! Shared Win32 HRESULT helpers (CredMgr / DPAPI / file replace).

use crate::SecretsError;

pub(crate) fn win32_err(op: &'static str, err: windows::core::Error) -> SecretsError {
    let hr = err.code().0 as u32;
    // Prefer the WIN32 code when the HRESULT is `HRESULT_FROM_WIN32`.
    let code = if (hr & 0xFFFF_0000) == 0x8007_0000 {
        hr & 0xFFFF
    } else {
        hr
    };
    SecretsError::Win32 { op, code }
}
