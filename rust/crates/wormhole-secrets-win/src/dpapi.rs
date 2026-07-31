//! DPAPI `CryptProtectData` / `CryptUnprotectData` — CurrentUser scope.
//!
//! Matches `ProtectedData.Protect(..., DataProtectionScope.CurrentUser)`.

use std::path::{Path, PathBuf};

use crate::{Result, SecretsError};

/// Protect `plaintext` with optional entropy (CurrentUser scope).
pub fn protect(plaintext: &[u8], entropy: Option<&[u8]>) -> Result<Vec<u8>> {
    #[cfg(windows)]
    {
        protect_windows(plaintext, entropy)
    }
    #[cfg(not(windows))]
    {
        let _ = (plaintext, entropy);
        Err(SecretsError::UnsupportedPlatform)
    }
}

/// Unprotect a DPAPI blob. Wrong entropy / corrupt data → [`SecretsError::DpapiUnprotect`].
pub fn unprotect(blob: &[u8], entropy: Option<&[u8]>) -> Result<Vec<u8>> {
    #[cfg(windows)]
    {
        unprotect_windows(blob, entropy)
    }
    #[cfg(not(windows))]
    {
        let _ = (blob, entropy);
        Err(SecretsError::UnsupportedPlatform)
    }
}

/// Protect and write to `path`, creating parent directories.
pub fn write_protected_file(
    path: &Path,
    plaintext: &[u8],
    entropy: Option<&[u8]>,
) -> Result<()> {
    ensure_parent(path)?;
    let blob = protect(plaintext, entropy)?;
    std::fs::write(path, blob)?;
    Ok(())
}

/// Atomic write: temp sibling + replace (mirrors Azure/WatchGuard/Stormshield caches).
///
/// Temp name matches C#: `{path}.{guid:N}.tmp`. On Windows the replace uses
/// `MoveFileExW(MOVEFILE_REPLACE_EXISTING)` so an existing destination is overwritten
/// without a delete gap. On failure the temp file is best-effort deleted.
pub fn write_protected_file_atomic(
    path: &Path,
    plaintext: &[u8],
    entropy: Option<&[u8]>,
) -> Result<()> {
    ensure_parent(path)?;
    let blob = protect(plaintext, entropy)?;

    // C#: `path + "." + Guid.NewGuid().ToString("N") + ".tmp"`
    let mut tmp_os = path.as_os_str().to_os_string();
    tmp_os.push(".");
    tmp_os.push(uuid::Uuid::new_v4().simple().to_string());
    tmp_os.push(".tmp");
    let tmp_path = PathBuf::from(tmp_os);

    let result = (|| -> Result<()> {
        std::fs::write(&tmp_path, &blob)?;
        replace_file(&tmp_path, path)?;
        Ok(())
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    result
}

/// Read + unprotect. Missing file → `Ok(None)`. Corrupt / wrong entropy → error.
pub fn read_protected_file(path: &Path, entropy: Option<&[u8]>) -> Result<Option<Vec<u8>>> {
    let blob = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    Ok(Some(unprotect(&blob, entropy)?))
}

/// Delete a protected file if present. Missing file/dir → `Ok(())` (C# `DeleteFileIfExistsAsync`).
///
/// Does **not** unprotect or read plaintext. Callers must confine `path` first.
pub fn delete_protected_file_if_exists(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn replace_file(src: &Path, dest: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        replace_file_windows(src, dest)
    }
    #[cfg(not(windows))]
    {
        std::fs::rename(src, dest)?;
        Ok(())
    }
}

#[cfg(windows)]
fn replace_file_windows(src: &Path, dest: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_REPLACE_EXISTING};

    let src_w: Vec<u16> = src.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let dest_w: Vec<u16> = dest.as_os_str().encode_wide().chain(std::iter::once(0)).collect();

    unsafe {
        MoveFileExW(
            PCWSTR(src_w.as_ptr()),
            PCWSTR(dest_w.as_ptr()),
            MOVEFILE_REPLACE_EXISTING,
        )
    }
    .map_err(|e| crate::win32::win32_err("MoveFileExW", e))?;
    Ok(())
}

#[cfg(windows)]
fn protect_windows(plaintext: &[u8], entropy: Option<&[u8]>) -> Result<Vec<u8>> {
    use windows::core::PCWSTR;
    use windows::Win32::Security::Cryptography::{
        CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    with_optional_entropy(entropy, |p_entropy| {
        let data_in = CRYPT_INTEGER_BLOB {
            cbData: plaintext.len() as u32,
            pbData: plaintext.as_ptr() as *mut u8,
        };
        let mut data_out = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };

        unsafe {
            CryptProtectData(
                &data_in,
                PCWSTR::null(),
                p_entropy,
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut data_out,
            )
        }
        .map_err(|e| crate::win32::win32_err("CryptProtectData", e))?;

        Ok(unsafe { take_blob(&mut data_out) })
    })
}

#[cfg(windows)]
fn unprotect_windows(blob: &[u8], entropy: Option<&[u8]>) -> Result<Vec<u8>> {
    use windows::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    with_optional_entropy(entropy, |p_entropy| {
        let data_in = CRYPT_INTEGER_BLOB {
            cbData: blob.len() as u32,
            pbData: blob.as_ptr() as *mut u8,
        };
        let mut data_out = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };

        let result = unsafe {
            CryptUnprotectData(
                &data_in,
                None,
                p_entropy,
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut data_out,
            )
        };

        if result.is_err() {
            return Err(SecretsError::DpapiUnprotect);
        }

        Ok(unsafe { take_blob(&mut data_out) })
    })
}

/// Keep the entropy `CRYPT_INTEGER_BLOB` alive for the duration of `f`.
#[cfg(windows)]
fn with_optional_entropy<T>(
    entropy: Option<&[u8]>,
    f: impl FnOnce(
        Option<*const windows::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB>,
    ) -> Result<T>,
) -> Result<T> {
    use windows::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB;

    match entropy {
        Some(e) if !e.is_empty() => {
            let blob = CRYPT_INTEGER_BLOB {
                cbData: e.len() as u32,
                pbData: e.as_ptr() as *mut u8,
            };
            f(Some(&blob as *const _))
        }
        _ => f(None),
    }
}

#[cfg(windows)]
unsafe fn take_blob(
    blob: &mut windows::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB,
) -> Vec<u8> {
    use windows::Win32::Foundation::{LocalFree, HLOCAL};

    if blob.pbData.is_null() || blob.cbData == 0 {
        return Vec::new();
    }
    let slice = unsafe { std::slice::from_raw_parts(blob.pbData, blob.cbData as usize) };
    let v = slice.to_vec();
    unsafe {
        let _ = LocalFree(Some(HLOCAL(blob.pbData as *mut _)));
    }
    blob.pbData = std::ptr::null_mut();
    blob.cbData = 0;
    v
}
