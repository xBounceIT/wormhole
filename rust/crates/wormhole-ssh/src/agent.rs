//! SSH agent availability probe (Pageant / OpenSSH agent).
//!
//! This module only answers "**is an agent endpoint reachable?**". It never
//! lists identities, signs challenges, or authenticates to a remote host.
//! Wire auth for [`crate::SshAuthMethod::Agent`] remains
//! [`crate::SshError::AuthNotImplemented`] until a russh agent client lands.
//!
//! # Platform probe
//!
//! On Windows (`cfg(windows)`), [`PlatformAgentProbe`] / [`is_agent_available`]
//! check the OpenSSH agent named pipe (`\\.\pipe\openssh-ssh-agent`, or a
//! **bounded named-pipe** `SSH_AUTH_SOCK` when set). The probe opens the pipe
//! and **immediately drops** the handle — no SSH agent protocol bytes are
//! written or read, so private keys never leave the agent.
//!
//! Hostile / unbounded `SSH_AUTH_SOCK` values (UNC shares, filesystem paths,
//! `\\.\` devices other than named pipes, overlong paths, empty / unsafe pipe
//! names) are ignored and the probe falls through to the default OpenSSH pipe.
//! Windows does **not** treat arbitrary absolute filesystem paths as agent
//! endpoints (avoids false positives on directories / ordinary files).
//!
//! Pageant (shared-memory / WM_COPYDATA) is **not** probed yet; availability
//! is OpenSSH named-pipe only on Windows. Non-Windows builds probe
//! `SSH_AUTH_SOCK` as a length-bounded filesystem path when set; otherwise
//! report unavailable.
//!
//! Unit tests inject [`FakeAgent`] (no network, no pipes).

use std::ffi::OsStr;
use std::fmt;
use std::path::Path;

/// Default Windows OpenSSH Authentication Agent named pipe.
#[cfg(windows)]
pub const OPENSSH_AGENT_PIPE: &str = r"\\.\pipe\openssh-ssh-agent";

/// Upper bound on `SSH_AUTH_SOCK` / pipe path bytes (rejects hostile overlong env).
const MAX_AGENT_ENDPOINT_LEN: usize = 256;

/// Result of an availability probe (no secrets).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentAvailability {
    /// Whether an agent endpoint appears present.
    pub available: bool,
    /// Short, non-secret label for logs/UI (`openssh-pipe`, `ssh-auth-sock`, `none`, …).
    pub source: &'static str,
}

impl AgentAvailability {
    pub const fn unavailable() -> Self {
        Self {
            available: false,
            source: "none",
        }
    }
}

/// Probe whether an SSH agent endpoint appears reachable.
///
/// Implementations must not speak the SSH agent wire protocol and must never
/// log key material (this API has none).
pub trait SshAgentProbe: Send + Sync {
    /// True when an agent endpoint looks present.
    fn is_agent_available(&self) -> bool {
        self.probe().available
    }

    /// Detailed availability (source label is never a secret).
    fn probe(&self) -> AgentAvailability;
}

/// In-memory probe for unit tests (no network, no named pipes).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FakeAgent {
    pub available: bool,
    pub source: &'static str,
}

impl FakeAgent {
    pub const fn available() -> Self {
        Self {
            available: true,
            source: "fake",
        }
    }

    pub const fn unavailable() -> Self {
        Self {
            available: false,
            source: "fake",
        }
    }
}

impl Default for FakeAgent {
    fn default() -> Self {
        Self::unavailable()
    }
}

impl fmt::Debug for FakeAgent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeAgent")
            .field("available", &self.available)
            .field("source", &self.source)
            .finish()
    }
}

impl SshAgentProbe for FakeAgent {
    fn probe(&self) -> AgentAvailability {
        AgentAvailability {
            available: self.available,
            source: self.source,
        }
    }
}

/// Best-effort platform probe (Windows OpenSSH named pipe / `SSH_AUTH_SOCK`).
///
/// Does not implement Pageant detection. Does not authenticate.
#[derive(Debug, Default, Clone, Copy)]
pub struct PlatformAgentProbe;

impl SshAgentProbe for PlatformAgentProbe {
    fn probe(&self) -> AgentAvailability {
        probe_platform()
    }
}

/// Convenience: platform agent availability (no protocol I/O beyond open/stat).
pub fn is_agent_available() -> bool {
    PlatformAgentProbe.is_agent_available()
}

/// Convenience: platform probe with source label.
pub fn probe_agent() -> AgentAvailability {
    PlatformAgentProbe.probe()
}

fn probe_platform() -> AgentAvailability {
    if let Some(sock) = std::env::var_os("SSH_AUTH_SOCK") {
        if let Some(availability) = probe_ssh_auth_sock(&sock) {
            return availability;
        }
        // Env unset-equivalent / hostile / missing → fall through to platform default.
    }

    #[cfg(windows)]
    {
        if probe_windows_named_pipe(Path::new(OPENSSH_AGENT_PIPE)) {
            return AgentAvailability {
                available: true,
                source: "openssh-pipe",
            };
        }
    }

    AgentAvailability::unavailable()
}

/// Probe a caller-supplied `SSH_AUTH_SOCK` value (bounded; never puts the path in `source`).
fn probe_ssh_auth_sock(sock: &OsStr) -> Option<AgentAvailability> {
    if sock.is_empty() || os_str_len(sock) > MAX_AGENT_ENDPOINT_LEN {
        return None;
    }

    #[cfg(windows)]
    {
        let path = classify_windows_agent_pipe(sock)?;
        if probe_windows_named_pipe(path) {
            return Some(AgentAvailability {
                available: true,
                source: "ssh-auth-sock",
            });
        }
        // Valid pipe shape but absent → fall through so default pipe can still match.
        return None;
    }

    #[cfg(not(windows))]
    {
        use std::path::Component;
        let path = Path::new(sock);
        // Avoid CWD-relative / traversal footguns from a hostile env.
        if !path.is_absolute()
            || path.components().any(|c| matches!(c, Component::ParentDir))
        {
            return None;
        }
        if path.exists() {
            return Some(AgentAvailability {
                available: true,
                source: "ssh-auth-sock",
            });
        }
        None
    }
}

fn os_str_len(s: &OsStr) -> usize {
    s.as_encoded_bytes().len()
}

/// Parse/validate a Windows named-pipe agent endpoint from env (or reject as hostile).
///
/// Only `\\.\pipe\NAME` / `//./pipe/NAME` with a safe NAME are accepted. Filesystem
/// paths, UNC shares, and other device namespaces are rejected so a hostile env
/// cannot point the probe at arbitrary files or remote paths.
#[cfg(windows)]
fn classify_windows_agent_pipe(sock: &OsStr) -> Option<&Path> {
    if sock.is_empty() || os_str_len(sock) > MAX_AGENT_ENDPOINT_LEN {
        return None;
    }
    let text = sock.to_str()?;
    let name = strip_windows_named_pipe_prefix(text)?;
    if !windows_pipe_name_ok(name) {
        return None;
    }
    Some(Path::new(sock))
}

/// Accept `\\.\pipe\NAME` / `//./pipe/NAME` (case-insensitive prefix); return NAME.
#[cfg(windows)]
fn strip_windows_named_pipe_prefix(text: &str) -> Option<&str> {
    const PREFIXES: [&str; 2] = [r"\\.\pipe\", "//./pipe/"];
    for prefix in PREFIXES {
        if text.len() >= prefix.len() && text[..prefix.len()].eq_ignore_ascii_case(prefix) {
            return Some(&text[prefix.len()..]);
        }
    }
    None
}

#[cfg(windows)]
fn windows_pipe_name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_AGENT_ENDPOINT_LEN.saturating_sub(r"\\.\pipe\".len())
        && !name.contains(['\\', '/', '\0'])
        && name != "."
        && name != ".."
}

/// Open a Windows named pipe and drop the handle — **no** agent protocol traffic.
#[cfg(windows)]
fn probe_windows_named_pipe(path: &Path) -> bool {
    match std::fs::OpenOptions::new().read(true).write(true).open(path) {
        Ok(_handle) => true, // drop closes immediately
        Err(e) => classify_windows_pipe_probe_error(&e),
    }
}

/// Map Windows named-pipe open errors to availability.
///
/// Only used after the path is known to be a named-pipe form — so
/// `PermissionDenied` / busy / sharing-violation mean "endpoint present".
#[cfg(windows)]
fn classify_windows_pipe_probe_error(err: &std::io::Error) -> bool {
    match err.raw_os_error() {
        // ERROR_ACCESS_DENIED (5), ERROR_SHARING_VIOLATION (32), ERROR_PIPE_BUSY (231).
        Some(5) | Some(32) | Some(231) => true,
        // ERROR_FILE_NOT_FOUND (2), ERROR_PATH_NOT_FOUND (3): absent.
        Some(2) | Some(3) => false,
        // Prefer PermissionDenied kind when raw code is missing (still "present").
        _ if matches!(err.kind(), std::io::ErrorKind::PermissionDenied) => true,
        // Unknown: fail closed (report unavailable) — safer than false positive.
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_agent_available_true() {
        let fake = FakeAgent::available();
        assert!(fake.is_agent_available());
        assert_eq!(
            fake.probe(),
            AgentAvailability {
                available: true,
                source: "fake",
            }
        );
        assert_eq!(fake, FakeAgent::available());
    }

    #[test]
    fn fake_agent_available_false() {
        let fake = FakeAgent::unavailable();
        assert!(!fake.is_agent_available());
        assert_eq!(
            fake.probe(),
            AgentAvailability {
                available: false,
                source: "fake",
            }
        );
        assert_eq!(fake, FakeAgent::default());
    }

    #[test]
    fn fake_agent_is_deterministic() {
        // Same constructors always yield the same availability — no I/O, no env.
        for _ in 0..8 {
            assert!(FakeAgent::available().is_agent_available());
            assert!(!FakeAgent::unavailable().is_agent_available());
            assert_eq!(FakeAgent::available().probe().source, "fake");
        }
    }

    #[test]
    fn fake_agent_debug_has_no_secret_fields() {
        let fake = FakeAgent {
            available: true,
            source: "fake",
        };
        let rendered = format!("{fake:?}");
        assert!(rendered.contains("FakeAgent"));
        assert!(rendered.contains("available"));
        // Probe API carries no keys/passwords; assert the Debug shape stays lean.
        assert!(!rendered.to_lowercase().contains("password"));
        assert!(!rendered.to_lowercase().contains("private"));
        assert!(!rendered.contains("BEGIN"));
    }

    #[test]
    fn agent_availability_source_never_embeds_path() {
        let labels = ["none", "fake", "openssh-pipe", "ssh-auth-sock"];
        for label in labels {
            let a = AgentAvailability {
                available: label != "none",
                source: label,
            };
            let rendered = format!("{a:?}");
            assert!(!rendered.contains(r"\\.\pipe"));
            assert!(!rendered.contains("SSH_AUTH_SOCK"));
            assert!(!rendered.contains("BEGIN"));
        }
    }

    #[test]
    fn trait_object_works_with_fake() {
        let probe: &dyn SshAgentProbe = &FakeAgent::available();
        assert!(probe.is_agent_available());
        let probe: &dyn SshAgentProbe = &FakeAgent::default();
        assert!(!probe.is_agent_available());
    }

    #[test]
    fn platform_probe_does_not_panic() {
        // May be true or false depending on the host; must not hang or panic.
        let availability = PlatformAgentProbe.probe();
        let _ = is_agent_available();
        let _ = probe_agent();
        assert!(
            availability.source == "none"
                || availability.source == "openssh-pipe"
                || availability.source == "ssh-auth-sock"
        );
        if !availability.available {
            assert_eq!(availability.source, "none");
        }
        // Source is a static label only — never the raw env path.
        assert!(availability.source.len() < 32);
    }

    #[test]
    fn agent_availability_unavailable_constant() {
        assert_eq!(
            AgentAvailability::unavailable(),
            AgentAvailability {
                available: false,
                source: "none",
            }
        );
    }

    #[test]
    fn overlong_ssh_auth_sock_rejected() {
        let overlong = "a".repeat(MAX_AGENT_ENDPOINT_LEN + 1);
        assert!(probe_ssh_auth_sock(OsStr::new(&overlong)).is_none());
    }

    #[test]
    fn empty_ssh_auth_sock_rejected() {
        assert!(probe_ssh_auth_sock(OsStr::new("")).is_none());
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_ssh_auth_sock_rejects_relative_and_parent() {
        assert!(probe_ssh_auth_sock(OsStr::new("relative.sock")).is_none());
        assert!(probe_ssh_auth_sock(OsStr::new("/tmp/../etc/passwd")).is_none());
    }

    #[cfg(windows)]
    #[test]
    fn openssh_pipe_constant_is_well_formed() {
        assert!(OPENSSH_AGENT_PIPE.starts_with(r"\\.\pipe\"));
        assert!(OPENSSH_AGENT_PIPE.contains("openssh-ssh-agent"));
        assert!(os_str_len(OsStr::new(OPENSSH_AGENT_PIPE)) <= MAX_AGENT_ENDPOINT_LEN);
        assert!(classify_windows_agent_pipe(OsStr::new(OPENSSH_AGENT_PIPE)).is_some());
    }

    #[cfg(windows)]
    #[test]
    fn classify_pipe_busy_as_available() {
        let busy = std::io::Error::from_raw_os_error(231);
        assert!(classify_windows_pipe_probe_error(&busy));
        let sharing = std::io::Error::from_raw_os_error(32);
        assert!(classify_windows_pipe_probe_error(&sharing));
        let missing = std::io::Error::from_raw_os_error(2);
        assert!(!classify_windows_pipe_probe_error(&missing));
        let path_missing = std::io::Error::from_raw_os_error(3);
        assert!(!classify_windows_pipe_probe_error(&path_missing));
        let access_denied = std::io::Error::from_raw_os_error(5);
        assert!(classify_windows_pipe_probe_error(&access_denied));
    }

    #[cfg(windows)]
    #[test]
    fn windows_ssh_auth_sock_accepts_named_pipe() {
        let sock = OsStr::new(r"\\.\pipe\openssh-ssh-agent");
        assert!(classify_windows_agent_pipe(sock).is_some());
        let alt = OsStr::new("//./pipe/openssh-ssh-agent");
        assert!(classify_windows_agent_pipe(alt).is_some());
    }

    #[cfg(windows)]
    #[test]
    fn windows_ssh_auth_sock_rejects_unc_devices_and_fs_paths() {
        let hostile = [
            r"\\evil-server\share\agent.sock",
            r"\\.\PhysicalDrive0",
            r"\\.\C:",
            r"\\?\C:\Windows\System32\config\SAM",
            r"\\.\pipe\",        // empty name
            r"\\.\pipe\..\x",    // separator in name
            r"\\.\pipe\foo/bar", // slash in name
            r"relative\agent.sock",
            r"C:\Users\..\Windows\agent.sock",
            r"C:\Windows", // absolute FS — not a named pipe (no false positive)
            r"C:\Users\Public\wormhole-agent.sock",
        ];
        for h in hostile {
            assert!(
                classify_windows_agent_pipe(OsStr::new(h)).is_none(),
                "expected reject: {h}"
            );
            assert!(
                probe_ssh_auth_sock(OsStr::new(h)).is_none(),
                "probe must ignore hostile: {h}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_pipe_name_rejects_dot_dot() {
        assert!(!windows_pipe_name_ok(".."));
        assert!(!windows_pipe_name_ok("."));
        assert!(!windows_pipe_name_ok(""));
        assert!(windows_pipe_name_ok("openssh-ssh-agent"));
    }
}
