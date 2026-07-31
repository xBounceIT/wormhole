//! `%LOCALAPPDATA%\Wormhole\…` path helpers matching `Helpers/AppPaths.cs`.
//!
//! Key and tunnel DPAPI filenames are always `{guid:N}.dpapi`; Azure VPN Entra
//! refresh-token files are `{guid:N}.tokencache` under `azurevpn-cache\`. Callers
//! that inject an alternate root (tests) must go through [`key_path_under`] /
//! [`tunnel_path_under`] / [`azure_vpn_token_cache_path_under`] /
//! [`ensure_confined_under`] so `..` and absolute escapes cannot leave the
//! allowed root.

use std::path::{Component, Path, PathBuf};

use uuid::Uuid;

use crate::{Result, SecretsError};

fn local_app_data() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| {
            // Fallback for odd shells: `%USERPROFILE%\AppData\Local`
            std::env::var_os("USERPROFILE").map(|p| PathBuf::from(p).join("AppData").join("Local"))
        })
        .unwrap_or_else(|| PathBuf::from(r"C:\Users\Default\AppData\Local"))
}

fn has_parent_dir(path: &Path) -> bool {
    path.components().any(|c| matches!(c, Component::ParentDir))
}

/// Reject empty / `.` / `..` / separators / absolute / multi-component segments.
///
/// Keeps WebView2 profile and extension paths under `%LOCALAPPDATA%\Wormhole\…`
/// even if a caller passes a hostile folder or version string.
pub(crate) fn require_single_path_segment(segment: &str, op: &'static str) -> Result<()> {
    if segment.is_empty()
        || segment.contains('\0')
        || segment.contains('/')
        || segment.contains('\\')
        || Path::new(segment).is_absolute()
    {
        return Err(SecretsError::InvalidPathSegment { op });
    }

    let mut components = Path::new(segment).components();
    match components.next() {
        Some(Component::Normal(name)) if name.to_str() == Some(segment) => {}
        _ => return Err(SecretsError::InvalidPathSegment { op }),
    }
    if components.next().is_some() {
        return Err(SecretsError::InvalidPathSegment { op });
    }
    Ok(())
}

/// Lexically ensure `path` stays under `root` (no `..`, no absolute escape).
///
/// Does **not** follow symlinks (same class as other Wormhole lexical guards).
/// Error variants never embed the candidate path string.
///
/// Empty `root` is rejected up front: on Windows/Unix, `path.starts_with("")`
/// is vacuously true for every `path`, which would disable confinement.
pub fn ensure_confined_under(root: &Path, path: &Path, op: &'static str) -> Result<()> {
    if root.as_os_str().is_empty() {
        return Err(SecretsError::PathNotConfined { op });
    }
    if has_parent_dir(root) || has_parent_dir(path) {
        return Err(SecretsError::PathNotConfined { op });
    }
    // Component-wise prefix: `C:\foo` does not match `C:\foobar`.
    if !path.starts_with(root) {
        return Err(SecretsError::PathNotConfined { op });
    }
    Ok(())
}

/// Join a single relative `file_name` under `root`, rejecting traversal / absolute escapes.
///
/// `root` itself must not contain `..`. `file_name` must be a single relative segment
/// (see [`require_single_path_segment`]).
pub fn confined_file_under(root: &Path, file_name: &str, op: &'static str) -> Result<PathBuf> {
    if root.as_os_str().is_empty() || has_parent_dir(root) {
        return Err(SecretsError::PathNotConfined { op });
    }
    require_single_path_segment(file_name, op)?;
    let path = root.join(file_name);
    ensure_confined_under(root, &path, op)?;
    Ok(path)
}

/// `%LOCALAPPDATA%\Wormhole`
pub fn wormhole_app_data_dir() -> PathBuf {
    local_app_data().join("Wormhole")
}

/// `%LOCALAPPDATA%\Wormhole\keys`
pub fn keys_dir() -> PathBuf {
    wormhole_app_data_dir().join("keys")
}

/// `%LOCALAPPDATA%\Wormhole\tunnels`
pub fn tunnels_dir() -> PathBuf {
    wormhole_app_data_dir().join("tunnels")
}

/// `keys\<guid:N>.dpapi` under the default profile root.
///
/// Returns [`SecretsError::PathNotConfined`] when `LOCALAPPDATA` / the resolved
/// keys root contains `..` (hostile environment). Prefer [`key_path_under`] in
/// tests with a temp directory.
pub fn key_path(credential_id: &Uuid) -> Result<PathBuf> {
    key_path_under(&keys_dir(), credential_id)
}

/// `tunnels\<guid:N>.dpapi` under the default profile root.
///
/// See [`key_path`] for confinement / hostile-env behavior.
pub fn tunnel_path(tunnel_config_id: &Uuid) -> Result<PathBuf> {
    tunnel_path_under(&tunnels_dir(), tunnel_config_id)
}

/// `{keys_root}\<guid:N>.dpapi` — confined under `keys_root` (tests inject temp dirs).
pub fn key_path_under(keys_root: &Path, credential_id: &Uuid) -> Result<PathBuf> {
    confined_file_under(
        keys_root,
        &format!("{}.dpapi", guid_n(credential_id)),
        "key_path_under",
    )
}

/// `{tunnels_root}\<guid:N>.dpapi` — confined under `tunnels_root` (tests inject temp dirs).
pub fn tunnel_path_under(tunnels_root: &Path, tunnel_config_id: &Uuid) -> Result<PathBuf> {
    confined_file_under(
        tunnels_root,
        &format!("{}.dpapi", guid_n(tunnel_config_id)),
        "tunnel_path_under",
    )
}

/// `%LOCALAPPDATA%\Wormhole\app-auth.dpapi`
pub fn app_authentication_path() -> PathBuf {
    wormhole_app_data_dir().join("app-auth.dpapi")
}

/// `%LOCALAPPDATA%\Wormhole\bitwarden-browser-storage.dpapi`
pub fn bitwarden_browser_shared_storage_path() -> PathBuf {
    wormhole_app_data_dir().join("bitwarden-browser-storage.dpapi")
}

/// `%LOCALAPPDATA%\Wormhole\bitwarden-browser-webview2` — persistent profile root
/// for HTTPS tabs that load the Bitwarden extension (`AppPaths.GetBitwardenBrowserExtensionWebView2UserDataRoot`).
pub fn bitwarden_browser_webview2_root() -> PathBuf {
    wormhole_app_data_dir().join("bitwarden-browser-webview2")
}

/// `bitwarden-browser-webview2\<contextFolderName>` — one WebView2 user-data folder.
///
/// `context_folder_name` must be a single relative segment (typically `profile-` + 16 hex).
/// Traversal / separators / absolute paths → [`SecretsError::InvalidPathSegment`].
pub fn bitwarden_browser_webview2_user_data(context_folder_name: &str) -> Result<PathBuf> {
    require_single_path_segment(context_folder_name, "bitwarden_browser_webview2_user_data")?;
    Ok(bitwarden_browser_webview2_root().join(context_folder_name))
}

/// `%LOCALAPPDATA%\Wormhole\extensions\bitwarden` — unpacked extension installs.
pub fn bitwarden_extension_root() -> PathBuf {
    wormhole_app_data_dir()
        .join("extensions")
        .join("bitwarden")
}

/// `extensions\bitwarden\<version>` — install directory for a specific extension build.
///
/// `version` must be a single relative segment (e.g. `2026.1.0`). Traversal → error.
pub fn bitwarden_extension_install_dir(version: &str) -> Result<PathBuf> {
    require_single_path_segment(version, "bitwarden_extension_install_dir")?;
    Ok(bitwarden_extension_root().join(version))
}

/// `%LOCALAPPDATA%\Wormhole\cache\bitwarden-browser-extension` — download cache
/// (path helper only; this crate does **not** download the extension).
pub fn bitwarden_extension_download_cache_dir() -> PathBuf {
    wormhole_app_data_dir()
        .join("cache")
        .join("bitwarden-browser-extension")
}

/// `%LOCALAPPDATA%\Wormhole\stormshield-cache`
pub fn stormshield_cache_dir() -> PathBuf {
    wormhole_app_data_dir().join("stormshield-cache")
}

/// `stormshield-cache\<guid:N>.ovpncache`
pub fn stormshield_ovpn_cache_path(tunnel_config_id: &Uuid) -> PathBuf {
    stormshield_cache_dir().join(format!("{}.ovpncache", guid_n(tunnel_config_id)))
}

/// `%LOCALAPPDATA%\Wormhole\watchguard-cache`
pub fn watchguard_cache_dir() -> PathBuf {
    wormhole_app_data_dir().join("watchguard-cache")
}

/// `watchguard-cache\<guid:N>.ovpncache`
pub fn watchguard_ovpn_cache_path(tunnel_config_id: &Uuid) -> PathBuf {
    watchguard_cache_dir().join(format!("{}.ovpncache", guid_n(tunnel_config_id)))
}

/// `%LOCALAPPDATA%\Wormhole\azurevpn-cache`
pub fn azure_vpn_cache_dir() -> PathBuf {
    wormhole_app_data_dir().join("azurevpn-cache")
}

/// `azurevpn-cache\<guid:N>.tokencache` under the default profile (unchecked join).
///
/// Prefer [`azure_vpn_token_cache_path_under`] before any I/O — that helper
/// fail-closes on `..` / absolute escapes. This PathBuf form remains for
/// display / parity with C# `AppPaths.GetAzureVpnCacheDirectory` joins.
pub fn azure_vpn_token_cache_path(tunnel_config_id: &Uuid) -> PathBuf {
    azure_vpn_cache_dir().join(format!("{}.tokencache", guid_n(tunnel_config_id)))
}

/// `{cache_root}\<guid:N>.tokencache` — confined under `cache_root` (tests inject temp dirs).
///
/// Same lexical guards as [`key_path_under`] / [`tunnel_path_under`]. Distinct from
/// `keys\` / `tunnels\` stores — Entra refresh tokens live only under `azurevpn-cache`.
pub fn azure_vpn_token_cache_path_under(
    cache_root: &Path,
    tunnel_config_id: &Uuid,
) -> Result<PathBuf> {
    confined_file_under(
        cache_root,
        &format!("{}.tokencache", guid_n(tunnel_config_id)),
        "azure_vpn_token_cache_path_under",
    )
}

fn guid_n(id: &Uuid) -> String {
    // .NET Guid.ToString("N") — 32 lowercase hex digits, no hyphens.
    format!("{}", id.simple())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecretsError;

    #[test]
    fn single_segment_accepts_profile_and_version() {
        require_single_path_segment("profile-b7ab518aadff9ca3", "t").unwrap();
        require_single_path_segment("2026.1.0", "t").unwrap();
    }

    #[test]
    fn single_segment_rejects_traversal() {
        for bad in [
            "",
            ".",
            "..",
            "../evil",
            "..\\evil",
            "a/b",
            "a\\b",
            r"\Windows\evil", // RootDir form; is_absolute() is false on Windows
            "D:evil",         // drive-relative — Path::join would replace the root
            "profile-\0x",
            r"C:\Windows",
            r"\\?\C:\Windows",
        ] {
            assert!(
                matches!(
                    require_single_path_segment(bad, "t"),
                    Err(SecretsError::InvalidPathSegment { op: "t" })
                ),
                "expected reject for {bad:?}"
            );
        }
    }

    #[test]
    fn user_data_and_extension_dir_reject_traversal() {
        let err = bitwarden_browser_webview2_user_data(r"..\..\keys").unwrap_err();
        assert!(matches!(err, SecretsError::InvalidPathSegment { .. }));
        assert!(!format!("{err}").contains("keys"));
        assert!(!format!("{err:?}").contains(".."));

        let err = bitwarden_extension_install_dir(r"..\..\..\Windows").unwrap_err();
        assert!(matches!(err, SecretsError::InvalidPathSegment { .. }));

        let ok = bitwarden_browser_webview2_user_data("profile-abc").unwrap();
        assert!(ok.starts_with(bitwarden_browser_webview2_root()));
        assert_eq!(ok.file_name().and_then(|n| n.to_str()), Some("profile-abc"));
    }

    #[test]
    fn wormhole_paths_live_under_local_app_data() {
        let root = wormhole_app_data_dir();
        let local = local_app_data();
        assert!(
            root.starts_with(&local),
            "wormhole dir {root:?} must be under LOCALAPPDATA {local:?}"
        );
        assert_eq!(root.file_name().and_then(|n| n.to_str()), Some("Wormhole"));
        assert!(app_authentication_path().starts_with(&root));
        assert!(bitwarden_browser_shared_storage_path().starts_with(&root));
        assert!(bitwarden_browser_webview2_root().starts_with(&root));
    }

    #[test]
    fn ensure_confined_under_rejects_parent_and_absolute_escape() {
        let root = Path::new(r"C:\Users\me\AppData\Local\Wormhole\keys");
        ensure_confined_under(root, &root.join("a.dpapi"), "t").unwrap();

        let err = ensure_confined_under(root, Path::new(r"C:\Windows\evil.dpapi"), "t").unwrap_err();
        assert!(matches!(err, SecretsError::PathNotConfined { op: "t" }));
        assert!(!format!("{err}").contains("Windows"));
        assert!(!format!("{err:?}").contains("evil"));

        let err = ensure_confined_under(
            root,
            &root.join("..").join("tunnels").join("x.dpapi"),
            "t",
        )
        .unwrap_err();
        assert!(matches!(err, SecretsError::PathNotConfined { op: "t" }));

        // Prefix confusion: `keys` must not match `keys_extra`.
        let err = ensure_confined_under(
            root,
            Path::new(r"C:\Users\me\AppData\Local\Wormhole\keys_extra\a.dpapi"),
            "t",
        )
        .unwrap_err();
        assert!(matches!(err, SecretsError::PathNotConfined { op: "t" }));
        assert!(!format!("{err} / {err:?}").contains("keys_extra"));
    }

    #[test]
    fn ensure_confined_under_rejects_empty_root() {
        // Load-bearing: `any_path.starts_with("")` is true — empty root must not pass.
        let err =
            ensure_confined_under(Path::new(""), Path::new(r"C:\Windows\evil.dpapi"), "t").unwrap_err();
        assert!(matches!(err, SecretsError::PathNotConfined { op: "t" }));
        let text = format!("{err} / {err:?}");
        assert!(!text.contains("Windows"));
        assert!(!text.contains("evil"));
        assert!(!text.contains(r"C:\"));
    }

    #[test]
    fn confined_file_under_rejects_hostile_root_and_name() {
        let id_name = "00000000000000000000000000000000.dpapi";
        let err = confined_file_under(Path::new(r"C:\temp\..\Windows"), id_name, "t").unwrap_err();
        assert!(matches!(err, SecretsError::PathNotConfined { op: "t" }));

        let err = confined_file_under(Path::new(""), id_name, "t").unwrap_err();
        assert!(matches!(err, SecretsError::PathNotConfined { op: "t" }));

        let err = confined_file_under(Path::new(r"C:\temp\keys"), r"..\evil.dpapi", "t").unwrap_err();
        assert!(matches!(err, SecretsError::InvalidPathSegment { op: "t" }));

        let err = confined_file_under(Path::new(r"C:\temp\keys"), r"C:\Windows\x.dpapi", "t")
            .unwrap_err();
        assert!(matches!(err, SecretsError::InvalidPathSegment { op: "t" }));

        // Drive-relative / RootDir forms — join would replace or escape the root.
        let err = confined_file_under(Path::new(r"C:\temp\keys"), "D:evil.dpapi", "t").unwrap_err();
        assert!(matches!(err, SecretsError::InvalidPathSegment { op: "t" }));
        let err =
            confined_file_under(Path::new(r"C:\temp\keys"), r"\Windows\evil.dpapi", "t").unwrap_err();
        assert!(matches!(err, SecretsError::InvalidPathSegment { op: "t" }));
    }

    #[test]
    fn key_and_tunnel_path_under_temp_dir() {
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        let tunnels = dir.path().join("tunnels");
        let id = Uuid::parse_str("a7f3c1e2-9b6d-4e8a-bf21-7c0d2e5a4b91").unwrap();

        let key = key_path_under(&keys, &id).unwrap();
        let tunnel = tunnel_path_under(&tunnels, &id).unwrap();
        assert!(key.starts_with(&keys));
        assert!(tunnel.starts_with(&tunnels));
        assert_eq!(
            key.file_name().and_then(|n| n.to_str()),
            Some("a7f3c1e29b6d4e8abf217c0d2e5a4b91.dpapi")
        );
        assert_eq!(
            tunnel.file_name().and_then(|n| n.to_str()),
            Some("a7f3c1e29b6d4e8abf217c0d2e5a4b91.dpapi")
        );

        let err = key_path_under(Path::new(r"C:\a\..\b"), &id).unwrap_err();
        assert!(matches!(
            err,
            SecretsError::PathNotConfined {
                op: "key_path_under"
            }
        ));
        let err = tunnel_path_under(Path::new(r"C:\a\..\b"), &id).unwrap_err();
        assert!(matches!(
            err,
            SecretsError::PathNotConfined {
                op: "tunnel_path_under"
            }
        ));
    }

    #[test]
    fn default_key_tunnel_paths_confined_under_profile() {
        let id = Uuid::nil();
        let key = key_path(&id).unwrap();
        let tunnel = tunnel_path(&id).unwrap();
        assert!(key.starts_with(keys_dir()));
        assert!(tunnel.starts_with(tunnels_dir()));
        assert!(keys_dir().starts_with(wormhole_app_data_dir()));
        assert!(tunnels_dir().starts_with(wormhole_app_data_dir()));
        ensure_confined_under(&keys_dir(), &key, "t").unwrap();
        ensure_confined_under(&tunnels_dir(), &tunnel, "t").unwrap();
    }

    #[test]
    fn azure_vpn_token_cache_path_under_confines_and_rejects_hostile_root() {
        let id = Uuid::parse_str("a7f3c1e2-9b6d-4e8a-bf21-7c0d2e5a4b91").unwrap();
        let root = Path::new(r"C:\Wormhole\azurevpn-cache");
        let path = azure_vpn_token_cache_path_under(root, &id).unwrap();
        assert_eq!(
            path.file_name().and_then(|n| n.to_str()),
            Some("a7f3c1e29b6d4e8abf217c0d2e5a4b91.tokencache")
        );
        ensure_confined_under(root, &path, "t").unwrap();

        let err = azure_vpn_token_cache_path_under(Path::new(r"C:\a\..\b"), &id).unwrap_err();
        assert!(matches!(
            err,
            SecretsError::PathNotConfined {
                op: "azure_vpn_token_cache_path_under"
            }
        ));
        assert!(!format!("{err}").contains(r"C:\"));
    }
}
