//! Locate Go sidecar binaries under `tools/`, `bin/`, or next to the running app.

use std::env;
use std::path::{Component, Path, PathBuf};

use super::SidecarBinary;
use crate::{TunnelError, TunnelKind};

/// Environment variable: directory that contains staged sidecar `.exe` files.
///
/// Trust boundary: the value must name a directory (no `..` components, no NUL).
/// When set and valid it is searched first; when set but invalid it is ignored
/// (with a warn) so a malicious/misconfigured relative override cannot walk the tree.
pub const SIDECAR_DIR_ENV: &str = "WORMHOLE_SIDECAR_DIR";

/// Resolve the absolute path to a sidecar binary, or return a clear [`TunnelError::BinaryNotFound`].
pub fn locate_sidecar(binary: SidecarBinary) -> Result<PathBuf, TunnelError> {
    locate_among(binary, candidate_paths(binary))
}

pub fn locate_sidecar_for_kind(kind: TunnelKind) -> Result<PathBuf, TunnelError> {
    let Some(binary) = SidecarBinary::for_kind(kind) else {
        return Err(TunnelError::Establish(format!(
            "no sidecar binary mapping for {kind:?}"
        )));
    };
    locate_sidecar(binary)
}

/// First existing file among `candidates`, else [`TunnelError::BinaryNotFound`].
///
/// Candidates whose final component is not the expected exe name are skipped
/// (defense in depth against path-injection mistakes at call sites).
pub fn locate_among(
    binary: SidecarBinary,
    candidates: impl IntoIterator<Item = PathBuf>,
) -> Result<PathBuf, TunnelError> {
    let expected = binary.exe_name();
    let searched: Vec<PathBuf> = candidates.into_iter().collect();
    for path in &searched {
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_none_or(|n| !n.eq_ignore_ascii_case(expected))
        {
            continue;
        }
        if path.is_file() {
            return Ok(path.clone());
        }
    }
    Err(TunnelError::BinaryNotFound {
        binary: expected.to_string(),
        searched: searched
            .into_iter()
            .map(|p| p.display().to_string())
            .collect(),
    })
}

/// Ordered search paths (first existing file wins).
pub fn candidate_paths(binary: SidecarBinary) -> Vec<PathBuf> {
    let exe = binary.exe_name();
    let mut out = Vec::new();

    if let Some(dir) = sidecar_dir_from_env() {
        out.push(dir.join(exe));
    }

    // App-relative (mirrors C# `AppContext.BaseDirectory` / `AppPaths.Get*ProxyExecutablePath`).
    if let Ok(current) = env::current_exe()
        && let Some(dir) = current.parent()
    {
        out.push(dir.join(exe));
    }

    // CWD + common staging layouts from Fetch-*.ps1 / local builds.
    if let Ok(cwd) = env::current_dir() {
        push_repo_relative(&mut out, &cwd, binary);
        for ancestor in cwd.ancestors().take(8) {
            push_repo_relative(&mut out, ancestor, binary);
        }
    }

    // Walk up from the running binary looking for a repo checkout.
    if let Ok(current) = env::current_exe() {
        for ancestor in current.ancestors().take(10) {
            push_repo_relative(&mut out, ancestor, binary);
        }
    }

    dedupe_paths(out)
}

/// Parse / validate `WORMHOLE_SIDECAR_DIR`. Returns `None` when unset, empty, or unsafe.
pub fn sidecar_dir_from_env() -> Option<PathBuf> {
    let Ok(dir) = env::var(SIDECAR_DIR_ENV) else {
        return None;
    };
    validate_sidecar_dir(&dir)
}

/// Validate an operator-supplied sidecar directory string (NUL / `..` rejected).
pub fn validate_sidecar_dir(dir: &str) -> Option<PathBuf> {
    let trimmed = dir.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.as_bytes().contains(&0) {
        tracing::warn!(
            env = SIDECAR_DIR_ENV,
            "ignoring sidecar dir: contains NUL byte"
        );
        return None;
    }
    let path = PathBuf::from(trimmed);
    if path
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        tracing::warn!(
            env = SIDECAR_DIR_ENV,
            path = %path.display(),
            "ignoring sidecar dir: parent-directory components (`..`) are not allowed"
        );
        return None;
    }
    Some(path)
}

fn push_repo_relative(out: &mut Vec<PathBuf>, root: &Path, binary: SidecarBinary) {
    let exe = binary.exe_name();
    let dir = binary.directory_name();
    // Staged next to app / under bin/ (README build output).
    out.push(root.join("bin").join(exe));
    // Source tree: tools/<name>/<exe> (dev builds that drop the exe in-tree).
    out.push(root.join("tools").join(dir).join(exe));
    // Fetch-WgProxy stages under obj/wgproxy/<arch>/.
    out.push(root.join("obj").join("wgproxy").join("x64").join(exe));
    out.push(root.join("obj").join("wgproxy").join("arm64").join(exe));
}

fn dedupe_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for p in paths {
        let key = p.display().to_string().to_lowercase();
        if seen.insert(key) {
            out.push(p);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_among_empty_candidates_is_binary_not_found() {
        let err = locate_among(SidecarBinary::WgProxy, Vec::new()).unwrap_err();
        match err {
            TunnelError::BinaryNotFound { binary, searched } => {
                assert_eq!(binary, "wormhole-wgproxy.exe");
                assert!(searched.is_empty());
            }
            other => panic!("expected BinaryNotFound, got {other:?}"),
        }
    }

    #[test]
    fn locate_among_picks_first_existing_file() {
        let dir = std::env::temp_dir().join(format!(
            "wormhole-sidecar-locate-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(SidecarBinary::WgProxy.exe_name());
        std::fs::write(&path, b"not-a-real-exe").unwrap();

        let missing = dir.join("nope.exe");
        let found = locate_among(
            SidecarBinary::WgProxy,
            vec![missing, path.clone()],
        )
        .unwrap();
        assert_eq!(found, path);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn locate_among_skips_wrong_file_name() {
        let dir = std::env::temp_dir().join(format!(
            "wormhole-sidecar-wrong-name-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let evil = dir.join("evil.exe");
        std::fs::write(&evil, b"x").unwrap();
        let err = locate_among(SidecarBinary::WgProxy, vec![evil]).unwrap_err();
        assert!(matches!(err, TunnelError::BinaryNotFound { .. }));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn candidate_paths_include_tools_and_bin_layouts() {
        let paths = candidate_paths(SidecarBinary::WgProxy);
        assert!(
            paths.iter().any(|p| {
                let s = p.to_string_lossy();
                s.contains("wormhole-wgproxy.exe")
            }),
            "{paths:?}"
        );
    }

    #[test]
    fn validate_sidecar_dir_rejects_parent_and_nul() {
        assert!(validate_sidecar_dir("").is_none());
        assert!(validate_sidecar_dir("   ").is_none());
        assert!(validate_sidecar_dir("C:\\sidecars\\..\\Windows").is_none());
        assert!(validate_sidecar_dir("foo/../bar").is_none());
        assert!(validate_sidecar_dir("good\0bad").is_none());
        assert_eq!(
            validate_sidecar_dir("C:\\Wormhole\\sidecars").map(|p| p.display().to_string()),
            Some("C:\\Wormhole\\sidecars".into())
        );
        assert_eq!(
            validate_sidecar_dir("./sidecars").map(|p| p.display().to_string()),
            Some("./sidecars".into())
        );
    }
}
