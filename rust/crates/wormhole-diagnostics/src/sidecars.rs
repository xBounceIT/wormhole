//! Sidecar binary presence matrix (paths only — never spawn or read stdin JSON).

use std::path::{Component, Path, PathBuf};

use wormhole_tunnels::sidecar::{candidate_paths, locate_among, SidecarBinary};

/// Whether a known sidecar `.exe` was found on the standard search path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SidecarStatus {
    /// File exists at `path` (not validated as a runnable PE).
    Present { path: PathBuf },
    /// No candidate file existed; `searched` lists paths that were checked.
    Missing { searched: Vec<PathBuf> },
}

/// One row of the sidecar presence matrix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidecarPresence {
    /// Expected file name (e.g. `wormhole-wgproxy.exe`).
    pub name: &'static str,
    pub status: SidecarStatus,
}

/// Probe all known tunnel sidecars (WireGuard / OpenVPN / Fortinet / Cisco).
pub fn collect_sidecar_matrix() -> Vec<SidecarPresence> {
    [
        SidecarBinary::WgProxy,
        SidecarBinary::OvpnProxy,
        SidecarBinary::FortiProxy,
        SidecarBinary::CiscoProxy,
    ]
    .into_iter()
    .map(probe_one)
    .collect()
}

fn probe_one(binary: SidecarBinary) -> SidecarPresence {
    let name = binary.exe_name();
    // Never traverse / report under `%LOCALAPPDATA%\Wormhole\{keys,tunnels}`.
    let candidates = filter_secret_dir_candidates(candidate_paths(binary));
    match locate_among(binary, candidates.clone()) {
        Ok(path) if !touches_wormhole_secrets_dir(&path) => SidecarPresence {
            name,
            status: SidecarStatus::Present { path },
        },
        Ok(_) | Err(_) => SidecarPresence {
            name,
            status: SidecarStatus::Missing {
                searched: candidates,
            },
        },
    }
}

/// Drop candidates that would walk into Wormhole credential blob directories.
fn filter_secret_dir_candidates(candidates: Vec<PathBuf>) -> Vec<PathBuf> {
    candidates
        .into_iter()
        .filter(|p| !touches_wormhole_secrets_dir(p))
        .collect()
}

/// True when `path` includes `Wormhole/keys` or `Wormhole/tunnels` (case-insensitive).
///
/// Those directories hold DPAPI private keys and tunnel secret payloads — diagnostics
/// must never search or print them.
pub(crate) fn touches_wormhole_secrets_dir(path: &Path) -> bool {
    let comps: Vec<String> = path
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_string_lossy().to_ascii_lowercase()),
            _ => None,
        })
        .collect();
    comps.windows(2).any(|w| {
        w[0] == "wormhole" && (w[1] == "keys" || w[1] == "tunnels")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matrix_covers_four_sidecars() {
        let rows = collect_sidecar_matrix();
        assert_eq!(rows.len(), 4);
        let names: Vec<_> = rows.iter().map(|r| r.name).collect();
        assert!(names.contains(&"wormhole-wgproxy.exe"));
        assert!(names.contains(&"wormhole-ovpnproxy.exe"));
        assert!(names.contains(&"wormhole-fortiproxy.exe"));
        assert!(names.contains(&"wormhole-ciscoproxy.exe"));
    }

    #[test]
    fn matrix_never_searches_or_reports_secrets_dirs() {
        let rows = collect_sidecar_matrix();
        for row in &rows {
            match &row.status {
                SidecarStatus::Present { path } => {
                    assert!(
                        !touches_wormhole_secrets_dir(path),
                        "present path must not be under secrets dirs: {}",
                        path.display()
                    );
                }
                SidecarStatus::Missing { searched } => {
                    for p in searched {
                        assert!(
                            !touches_wormhole_secrets_dir(p),
                            "searched candidate under secrets dir: {}",
                            p.display()
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn touches_wormhole_secrets_dir_detects_keys_and_tunnels() {
        assert!(touches_wormhole_secrets_dir(Path::new(
            r"C:\Users\x\AppData\Local\Wormhole\keys\id_rsa.dpapi"
        )));
        assert!(touches_wormhole_secrets_dir(Path::new(
            r"C:\Users\x\AppData\Local\Wormhole\tunnels\cfg.bin"
        )));
        assert!(touches_wormhole_secrets_dir(Path::new(
            r"c:\users\x\appdata\local\wormhole\KEYS\foo"
        )));
        // Staging / tools layouts must not false-positive.
        assert!(!touches_wormhole_secrets_dir(Path::new(
            r"C:\src\wormhole\tools\wormhole-wgproxy\wormhole-wgproxy.exe"
        )));
        assert!(!touches_wormhole_secrets_dir(Path::new(
            r"C:\Users\x\AppData\Local\Wormhole\logs"
        )));
        assert!(!touches_wormhole_secrets_dir(Path::new(
            r"C:\Program Files\Wormhole\wormhole-wgproxy.exe"
        )));
    }

    #[test]
    fn filter_drops_secret_dir_candidates() {
        let kept = PathBuf::from(r"C:\app\bin\wormhole-wgproxy.exe");
        let drop_keys = PathBuf::from(r"C:\Users\x\AppData\Local\Wormhole\keys\wormhole-wgproxy.exe");
        let drop_tunnels =
            PathBuf::from(r"C:\Users\x\AppData\Local\Wormhole\tunnels\wormhole-wgproxy.exe");
        let out = filter_secret_dir_candidates(vec![kept.clone(), drop_keys, drop_tunnels]);
        assert_eq!(out, vec![kept]);
    }

}
