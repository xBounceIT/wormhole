//! Download-to-temp + SHA-256 verify hooks (no live HTTP / no installer launch).

use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::error::{Result, UpdateError};
use crate::github::{normalize_sha256_token, parse_sha_sidecar};

/// Fail-closed upper bound for in-memory installer payloads (512 MiB).
///
/// Live streaming downloads can be larger; this crate accepts pre-buffered bytes only.
pub const MAX_INSTALLER_BYTES: usize = 512 * 1024 * 1024;

/// Compute lowercase hex SHA-256 of `data`.
pub fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    hex::encode(digest)
}

/// Verify `data` against an expected lowercase/uppercase hex digest (64 chars).
pub fn verify_sha256(data: &[u8], expected_hex: &str) -> Result<()> {
    let expected = normalize_sha256_token(expected_hex.trim()).ok_or_else(|| {
        UpdateError::InvalidSha256(UpdateError::clip_ctx(expected_hex.trim()))
    })?;
    let computed = sha256_hex(data);
    if computed != expected {
        return Err(UpdateError::Sha256Mismatch { expected, computed });
    }
    Ok(())
}

/// Verify using a `.sha256` sidecar body (same rules as C# `ParseShaSidecar`).
pub fn verify_sha256_sidecar(data: &[u8], sidecar_body: &str) -> Result<()> {
    let expected = parse_sha_sidecar(sidecar_body).ok_or_else(|| {
        UpdateError::InvalidSha256("(unparseable sidecar)".into())
    })?;
    verify_sha256(data, &expected)
}

/// Write installer bytes to a temp `.part` then rename, optionally verifying SHA-256.
///
/// Mirrors the C# download path shape (`*.part` → final) without HTTP. When `expected_sha256`
/// is `None`, the bytes are still written (host should log a warning — same as C#).
///
/// Fail-closed:
/// - path traversal / multi-component file names → [`UpdateError::UnsafeFileName`]
/// - hash mismatch → no file written
/// - payload larger than [`MAX_INSTALLER_BYTES`] → [`UpdateError::InstallerTooLarge`]
///
/// # Non-goals
///
/// - Live `HttpClient` download
/// - Mark-of-the-Web strip
/// - Cache rotation / `Process.Start` installer launch (`/SILENT /RESTARTAPP`)
pub fn download_bytes_to_temp(
    bytes: &[u8],
    file_name: &str,
    expected_sha256: Option<&str>,
    dest_dir: Option<&Path>,
) -> Result<PathBuf> {
    download_bytes_to_temp_limited(bytes, file_name, expected_sha256, dest_dir, MAX_INSTALLER_BYTES)
}

/// Same as [`download_bytes_to_temp`] with an explicit size cap (tests / specialized hosts).
pub fn download_bytes_to_temp_limited(
    bytes: &[u8],
    file_name: &str,
    expected_sha256: Option<&str>,
    dest_dir: Option<&Path>,
    max_bytes: usize,
) -> Result<PathBuf> {
    validate_installer_file_name(file_name)?;
    if bytes.len() > max_bytes {
        return Err(UpdateError::InstallerTooLarge {
            size: bytes.len(),
            max: max_bytes,
        });
    }
    // Verify before any filesystem write so mismatch never leaves a `.part` / final.
    if let Some(expected) = expected_sha256 {
        verify_sha256(bytes, expected)?;
    }

    let dir = match dest_dir {
        Some(d) => {
            fs::create_dir_all(d)?;
            d.to_path_buf()
        }
        None => {
            let tmp = tempfile::tempdir()?;
            let path = tmp.path().to_path_buf();
            // Persist the directory beyond this function (caller owns cleanup).
            let _ = tmp.keep();
            path
        }
    };

    let final_path = dir.join(file_name);
    // Defense in depth: joined path must stay a direct child of `dir`.
    if final_path.parent() != Some(dir.as_path()) {
        return Err(UpdateError::UnsafeFileName(UpdateError::clip_ctx(file_name)));
    }

    let part_path = with_part_suffix(&final_path);
    let _ = fs::remove_file(&part_path);
    {
        let mut file = fs::File::create(&part_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    // Prefer overwrite rename; on Windows replace existing final if present.
    if final_path.exists() {
        let _ = fs::remove_file(&final_path);
    }
    fs::rename(&part_path, &final_path)?;
    Ok(final_path)
}

/// Live HTTP download stub — always fails with [`UpdateError::DownloadStub`].
pub fn download_installer_live_stub(_url: &str, _file_name: &str) -> Result<PathBuf> {
    Err(UpdateError::DownloadStub)
}

/// `%LOCALAPPDATA%\Wormhole\cache\updates` (mirrors `AppPaths.GetUpdateCacheDirectory`).
pub fn update_cache_dir() -> PathBuf {
    local_app_data().join("Wormhole").join("cache").join("updates")
}

fn local_app_data() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("USERPROFILE").map(|p| PathBuf::from(p).join("AppData").join("Local"))
        })
        .unwrap_or_else(|| PathBuf::from(r"C:\Users\Default\AppData\Local"))
}

fn with_part_suffix(path: &Path) -> PathBuf {
    let mut os: OsString = path.as_os_str().to_owned();
    os.push(".part");
    PathBuf::from(os)
}

/// Whether `file_name` is a single safe path component suitable for cache joins.
pub fn is_safe_installer_file_name(file_name: &str) -> bool {
    validate_installer_file_name(file_name).is_ok()
}

fn validate_installer_file_name(file_name: &str) -> Result<()> {
    if file_name.is_empty() || file_name.contains('\0') {
        return Err(UpdateError::UnsafeFileName(UpdateError::clip_ctx(file_name)));
    }
    // Exactly one Normal path component — rejects separators, `.`, `..`, prefixes.
    let path = Path::new(file_name);
    let mut components = path.components();
    match components.next() {
        Some(Component::Normal(name))
            if components.next().is_none()
                && name.to_str() == Some(file_name)
                && !file_name.contains('/')
                && !file_name.contains('\\') => {}
        _ => {
            return Err(UpdateError::UnsafeFileName(UpdateError::clip_ctx(
                file_name,
            )))
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_accepts_matching_digest() {
        let data = b"wormhole-installer-bytes";
        let hex = sha256_hex(data);
        verify_sha256(data, &hex).unwrap();
        verify_sha256(data, &hex.to_ascii_uppercase()).unwrap();
    }

    #[test]
    fn verify_rejects_mismatch() {
        let data = b"wormhole-installer-bytes";
        let bad = "0000000000000000000000000000000000000000000000000000000000000000";
        match verify_sha256(data, bad) {
            Err(UpdateError::Sha256Mismatch { .. }) => {}
            other => panic!("expected mismatch, got {other:?}"),
        }
    }

    #[test]
    fn download_bytes_writes_and_verifies() {
        let data = b"payload";
        let hex = sha256_hex(data);
        let dir = tempfile::tempdir().unwrap();
        let path = download_bytes_to_temp(
            data,
            "Wormhole-0.1.0-win-x64-setup.exe",
            Some(&hex),
            Some(dir.path()),
        )
        .unwrap();
        assert!(path.is_file());
        assert_eq!(fs::read(&path).unwrap(), data);
        assert!(!dir.path().join("Wormhole-0.1.0-win-x64-setup.exe.part").exists());
    }

    #[test]
    fn download_rejects_path_traversal_name() {
        let dir = tempfile::tempdir().unwrap();
        for name in [
            "../evil.exe",
            "..\\evil.exe",
            "foo/bar.exe",
            "foo\\bar.exe",
            "..",
            ".",
            "",
            "evil\0.exe",
        ] {
            let err = download_bytes_to_temp(b"x", name, None, Some(dir.path())).unwrap_err();
            assert!(
                matches!(err, UpdateError::UnsafeFileName(_)),
                "name={name:?} err={err:?}"
            );
            assert!(dir.path().read_dir().unwrap().next().is_none());
        }
    }

    #[test]
    fn hash_mismatch_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let bad = "0000000000000000000000000000000000000000000000000000000000000000";
        let err = download_bytes_to_temp(
            b"payload",
            "Wormhole-0.1.0-win-x64-setup.exe",
            Some(bad),
            Some(dir.path()),
        )
        .unwrap_err();
        assert!(matches!(err, UpdateError::Sha256Mismatch { .. }));
        assert!(dir.path().read_dir().unwrap().next().is_none());
    }

    #[test]
    fn download_rejects_bytes_over_cap_before_write() {
        let dir = tempfile::tempdir().unwrap();
        let data = b"twelve-bytes"; // 12 bytes
        let err = download_bytes_to_temp_limited(
            data,
            "Wormhole-0.1.0-win-x64-setup.exe",
            None,
            Some(dir.path()),
            8,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            UpdateError::InstallerTooLarge { size: 12, max: 8 }
        ));
        assert!(dir.path().read_dir().unwrap().next().is_none());
    }

    #[test]
    fn download_accepts_bytes_at_cap() {
        let dir = tempfile::tempdir().unwrap();
        let data = b"twelve-bytes"; // 12 bytes
        let path = download_bytes_to_temp_limited(
            data,
            "Wormhole-0.1.0-win-x64-setup.exe",
            None,
            Some(dir.path()),
            12,
        )
        .unwrap();
        assert_eq!(fs::read(&path).unwrap(), data);
    }

    #[test]
    fn live_stub_errors() {
        assert!(matches!(
            download_installer_live_stub("https://example", "a.exe"),
            Err(UpdateError::DownloadStub)
        ));
    }
}
