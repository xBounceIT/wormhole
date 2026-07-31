//! Tracing bootstrap: daily file under `%LOCALAPPDATA%\Wormhole\logs\` + stderr.
//!
//! File naming matches C# Serilog / `Helpers/LogFiles.cs`: `wormhole-yyyyMMdd.log`.
//! Redaction runs through a writer hook that calls `wormhole-secrets-win` when the
//! `secrets` feature is enabled, then always strips case-insensitive assignment
//! patterns: `password=` / `token=` / `secret=` / `SVPNCOOKIE=` / `BW_SESSION=`.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use chrono::{Datelike, Local, NaiveDate};
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

/// Default retention hint (mirrors `LogFiles.DefaultRetentionDays`); deletion is host-owned.
pub const DEFAULT_LOG_RETENTION_DAYS: u32 = 14;

/// Guard returned by [`init_tracing`] — marker so callers keep the init side-effect obvious.
#[derive(Debug, Default)]
pub struct TracingGuard {
    _private: (),
}

/// `%LOCALAPPDATA%\Wormhole\logs` (AGENTS.md / `AppPaths.GetLogsDirectory`).
pub fn logs_dir() -> PathBuf {
    local_app_data().join("Wormhole").join("logs")
}

/// Daily sink path for `local_date` (`wormhole-yyyyMMdd.log`).
pub fn log_file_path_for_date(local_date: NaiveDate) -> PathBuf {
    logs_dir().join(format!(
        "wormhole-{:04}{:02}{:02}.log",
        local_date.year(),
        local_date.month(),
        local_date.day()
    ))
}

/// Today's log file path (local calendar date).
pub fn current_day_log_file_path() -> PathBuf {
    log_file_path_for_date(Local::now().date_naive())
}

/// Assignment keys always stripped after the Bitwarden / secrets pass.
///
/// Case-insensitive; optional whitespace around `=`. Values are non-empty `\S+`.
/// Substring match is intentional (`WORMHOLE_BW_PASSWORD=`, `api_token=`).
const SENSITIVE_ASSIGNMENT_KEYS: &[&str] =
    &["password", "token", "secret", "SVPNCOOKIE", "BW_SESSION"];

const REDACTED: &str = "[redacted]";

/// Redact a free-form log line before it hits a sink.
///
/// When the `secrets` feature is on, delegates to
/// [`wormhole_secrets_win::redact_env_and_cli_secrets`]. Otherwise applies a built-in
/// fallback with the same Bitwarden-style patterns. Always also redacts case-insensitive
/// [`SENSITIVE_ASSIGNMENT_KEYS`] assignments (optional spaces around `=`):
/// `password=` / `token=` / `secret=` / `SVPNCOOKIE=` / `BW_SESSION=`.
///
/// This is **best-effort assignment scrubbing**, not full secret detection of free-form
/// text (e.g. `the password is hunter2` is left unchanged).
///
/// Trailing CR/LF runes (`\n`, `\r\n`, bare `\r`, or multiples) are preserved exactly so
/// fmt writers that emit one line per `write` keep their record separators.
pub fn redact_log_text(value: &str) -> String {
    let core = value.trim_end_matches(['\r', '\n']);
    let trailing = &value[core.len()..];

    #[cfg(feature = "secrets")]
    let mut out = wormhole_secrets_win::redact_env_and_cli_secrets(core);
    #[cfg(not(feature = "secrets"))]
    let mut out = fallback_redact_env_and_cli_secrets(core);

    out = redact_assignment_keys(&out, SENSITIVE_ASSIGNMENT_KEYS);
    out.push_str(trailing);
    out
}

/// Initialize tracing: stderr + daily file under [`logs_dir`].
///
/// Safe to call once; subsequent calls are no-ops (`try_init`). Honors `RUST_LOG`, else `info`.
/// Creates the logs directory if missing.
pub fn init_tracing() -> TracingGuard {
    init_tracing_with_dirs(None, true)
}

/// Test / custom-root variant of [`init_tracing`].
///
/// `logs_root` overrides [`logs_dir`]. `also_stderr` toggles the stderr layer.
pub fn init_tracing_with_dirs(logs_root: Option<PathBuf>, also_stderr: bool) -> TracingGuard {
    let dir = logs_root.unwrap_or_else(logs_dir);
    let _ = fs::create_dir_all(&dir);

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let file_layer = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_target(false)
        .with_span_events(FmtSpan::NONE)
        .with_writer(RedactingMakeWriter::file(dir));

    let registry = tracing_subscriber::registry().with(filter).with(file_layer);

    if also_stderr {
        let stderr_layer = tracing_subscriber::fmt::layer()
            .with_ansi(true)
            .with_target(false)
            .with_writer(RedactingMakeWriter::stderr());
        let _ = registry.with(stderr_layer).try_init();
    } else {
        let _ = registry.try_init();
    }

    TracingGuard { _private: () }
}

fn local_app_data() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("USERPROFILE").map(|p| PathBuf::from(p).join("AppData").join("Local"))
        })
        .unwrap_or_else(|| PathBuf::from(r"C:\Users\Default\AppData\Local"))
}

/// MakeWriter that redacts UTF-8 lines then writes to stderr or a daily file.
#[derive(Clone, Debug)]
struct RedactingMakeWriter {
    kind: WriterKind,
}

#[derive(Clone, Debug)]
enum WriterKind {
    Stderr,
    File(PathBuf),
}

impl RedactingMakeWriter {
    fn stderr() -> Self {
        Self {
            kind: WriterKind::Stderr,
        }
    }

    fn file(dir: PathBuf) -> Self {
        Self {
            kind: WriterKind::File(dir),
        }
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for RedactingMakeWriter {
    type Writer = RedactingWriter;

    fn make_writer(&'a self) -> Self::Writer {
        match &self.kind {
            WriterKind::Stderr => RedactingWriter {
                inner: InnerWriter::Stderr,
            },
            WriterKind::File(dir) => RedactingWriter {
                inner: InnerWriter::File(dir.clone()),
            },
        }
    }
}

struct RedactingWriter {
    inner: InnerWriter,
}

enum InnerWriter {
    Stderr,
    File(PathBuf),
}

impl Write for RedactingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Lossy UTF-8 so malformed bytes still pass through assignment redaction.
        let text = String::from_utf8_lossy(buf);
        let redacted = redact_log_text(&text).into_bytes();
        match &self.inner {
            InnerWriter::Stderr => {
                let mut out = io::stderr().lock();
                out.write_all(&redacted)?;
            }
            InnerWriter::File(dir) => {
                write_daily_file(dir, &redacted)?;
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        match &self.inner {
            InnerWriter::Stderr => io::stderr().flush(),
            InnerWriter::File(_) => Ok(()),
        }
    }
}

fn write_daily_file(dir: &Path, bytes: &[u8]) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    let now = Local::now().date_naive();
    let path = dir.join(format!(
        "wormhole-{:04}{:02}{:02}.log",
        now.year(),
        now.month(),
        now.day()
    ));
    // Cache open handle per path string to avoid reopening every line.
    static FILE: OnceLock<Mutex<Option<(PathBuf, File)>>> = OnceLock::new();
    let slot = FILE.get_or_init(|| Mutex::new(None));
    let mut guard = slot.lock().unwrap_or_else(|e| e.into_inner());
    let needs_open = match guard.as_ref() {
        Some((p, _)) => p != &path,
        None => true,
    };
    if needs_open {
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        *guard = Some((path, file));
    }
    if let Some((_, file)) = guard.as_mut() {
        file.write_all(bytes)?;
        file.flush()?;
    }
    Ok(())
}

/// Case-insensitive `key=` / `key =` value redaction (non-empty `\S+` values).
fn redact_assignment_keys(input: &str, keys: &[&str]) -> String {
    let mut out = input.to_string();
    for key in keys {
        out = redact_assignment_key(&out, key);
    }
    out
}

fn redact_assignment_key(input: &str, key: &str) -> String {
    let lower = input.to_ascii_lowercase();
    let key_lower = key.to_ascii_lowercase();
    let mut result = String::with_capacity(input.len());
    let mut cursor = 0;

    while let Some(rel) = lower[cursor..].find(&key_lower) {
        let idx = cursor + rel;
        // Substring match is intentional (e.g. `WORMHOLE_BW_PASSWORD=` / `my_password=`).
        result.push_str(&input[cursor..idx]);
        result.push_str(&input[idx..idx + key.len()]);

        let after_name = idx + key.len();
        let rest = &input[after_name..];

        let mut pos = 0;
        let ws1: usize = rest[pos..]
            .chars()
            .take_while(|c| c.is_whitespace())
            .map(char::len_utf8)
            .sum();
        pos += ws1;
        if rest.get(pos..).is_none_or(|s| !s.starts_with('=')) {
            cursor = after_name;
            continue;
        }
        pos += 1; // '='
        let ws2: usize = rest[pos..]
            .chars()
            .take_while(|c| c.is_whitespace())
            .map(char::len_utf8)
            .sum();
        pos += ws2;

        let after_eq = after_name + pos;
        let value = &input[after_eq..];
        let value_end = value
            .find(|c: char| c.is_whitespace())
            .unwrap_or(value.len());
        if value_end == 0 {
            cursor = after_name;
            continue;
        }

        result.push_str(&input[after_name..after_eq]);
        result.push_str(REDACTED);
        cursor = after_eq + value_end;
    }
    result.push_str(&input[cursor..]);
    result
}

#[cfg(not(feature = "secrets"))]
fn fallback_redact_env_and_cli_secrets(value: &str) -> String {
    let trimmed = value.trim();
    let mut out = trimmed.to_string();
    for flag in ["--session", "--code"] {
        out = fallback_redact_flag(&out, flag);
    }
    for name in ["BW_SESSION", "WORMHOLE_BW_PASSWORD"] {
        out = redact_assignment_key(&out, name);
    }
    if out.chars().count() > 500 {
        out = out.chars().take(500).collect();
    }
    out
}

#[cfg(not(feature = "secrets"))]
fn fallback_redact_flag(input: &str, flag: &str) -> String {
    let lower = input.to_ascii_lowercase();
    let flag_lower = flag.to_ascii_lowercase();
    let mut result = String::with_capacity(input.len());
    let mut cursor = 0;

    while let Some(rel) = lower[cursor..].find(&flag_lower) {
        let idx = cursor + rel;
        result.push_str(&input[cursor..idx]);
        result.push_str(&input[idx..idx + flag.len()]);

        let after = idx + flag.len();
        let rest = &input[after..];
        let delim = if rest.starts_with('=') {
            1
        } else if rest.starts_with(|c: char| c.is_whitespace()) {
            rest.chars()
                .take_while(|c| c.is_whitespace())
                .map(char::len_utf8)
                .sum()
        } else {
            cursor = after;
            continue;
        };
        let value_start = after + delim;
        let value = &input[value_start..];
        let value_end = value.find(|c: char| c.is_whitespace()).unwrap_or(value.len());
        if value_end == 0 {
            cursor = after;
            continue;
        }
        result.push_str(&input[after..value_start]);
        result.push_str(REDACTED);
        cursor = value_start + value_end;
    }
    result.push_str(&input[cursor..]);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_path_uses_serilog_daily_name() {
        let d = NaiveDate::from_ymd_opt(2026, 6, 16).unwrap();
        let path = log_file_path_for_date(d);
        assert_eq!(
            path.file_name().and_then(|s| s.to_str()),
            Some("wormhole-20260616.log")
        );
        assert_eq!(
            path.parent().and_then(|p| p.file_name()).and_then(|s| s.to_str()),
            Some("logs")
        );
        // Path must not embed obvious secret material — only LocalAppData/Wormhole/logs.
        let rendered = path.to_string_lossy();
        assert!(!rendered.to_ascii_lowercase().contains("password="));
        assert!(!rendered.to_ascii_lowercase().contains("token="));
    }

    #[test]
    fn redact_log_text_strips_secrets() {
        let s = "err --session abc BW_SESSION=xyz --code 12 WORMHOLE_BW_PASSWORD=pw done";
        let out = redact_log_text(s);
        assert_eq!(
            out,
            "err --session [redacted] BW_SESSION=[redacted] --code [redacted] WORMHOLE_BW_PASSWORD=[redacted] done"
        );
    }

    #[test]
    fn redact_password_and_token_assignments() {
        let out = redact_log_text("connect password=s3cret token = abc123 done");
        assert_eq!(
            out,
            "connect password=[redacted] token = [redacted] done"
        );

        let out2 = redact_log_text("Password=X TOKEN=y");
        assert_eq!(out2, "Password=[redacted] TOKEN=[redacted]");
    }

    #[test]
    fn redact_secret_svpncookie_bw_session_assignments() {
        let out = redact_log_text(
            "x secret=s3cr3t SVPNCOOKIE=cookieval BW_SESSION=sess done",
        );
        assert_eq!(
            out,
            "x secret=[redacted] SVPNCOOKIE=[redacted] BW_SESSION=[redacted] done"
        );

        let mixed = redact_log_text("SeCrEt = a SvPnCoOkIe=b bw_session = c");
        assert_eq!(
            mixed,
            "SeCrEt = [redacted] SvPnCoOkIe=[redacted] bw_session = [redacted]"
        );
    }

    #[test]
    fn redact_hostile_secret_patterns_never_leak() {
        // Mixed case, spaced `=`, Fortinet cookie, Bitwarden session, and nested-looking values.
        let hostile = concat!(
            "AUTH Password=p@ss/Word Token = t0k3n ",
            "SECRET=s3cr3t! svpncookie=SVPN_COOKIE_VAL ",
            "BW_SESSION=bw-sess-uuid leak ",
            "password=token=nested"
        );
        let out = redact_log_text(hostile);
        for leak in [
            "p@ss/Word",
            "t0k3n",
            "s3cr3t!",
            "SVPN_COOKIE_VAL",
            "bw-sess-uuid",
            "token=nested",
        ] {
            assert!(
                !out.contains(leak),
                "hostile value leaked through redaction: {leak:?} in {out:?}"
            );
        }
        assert!(!out.to_ascii_lowercase().contains("p@ss"));
        assert_eq!(out.matches("[redacted]").count(), 6);

        // Bare `key=` (no `\S+` value) must stay intact — do not invent redaction.
        assert_eq!(redact_log_text("secret="), "secret=");
        assert_eq!(redact_log_text("SVPNCOOKIE="), "SVPNCOOKIE=");
        assert_eq!(redact_log_text("BW_SESSION="), "BW_SESSION=");
        assert_eq!(redact_log_text("password="), "password=");
        assert_eq!(redact_log_text("token="), "token=");
    }

    #[test]
    fn redact_hostile_crlf_and_urlish_payloads() {
        let crlf = redact_log_text("pre secret=one\r\nmid SVPNCOOKIE=two token=three\r\n");
        assert!(crlf.ends_with("\r\n"), "{crlf:?}");
        assert!(!crlf.contains("one"));
        assert!(!crlf.contains("two"));
        assert!(!crlf.contains("three"));
        assert!(crlf.contains("secret=[redacted]"));
        assert!(crlf.contains("SVPNCOOKIE=[redacted]"));
        assert!(crlf.contains("token=[redacted]"));

        // Query-string style: `\S+` consumes through `&…` until whitespace (same as Bitwarden `\S+`).
        let qs = redact_log_text(
            "GET /cb?password=pw1&token=tk1 secret=sec2 password=pw2 BW_SESSION=s",
        );
        for leak in ["pw1", "tk1", "sec2", "pw2"] {
            assert!(!qs.contains(leak), "leaked {leak} in {qs}");
        }
        assert!(qs.contains("password=[redacted]"));
        assert!(qs.contains("secret=[redacted]"));
        assert!(qs.contains("BW_SESSION=[redacted]"));
    }

    #[test]
    fn redact_preserves_trailing_newline() {
        let out = redact_log_text("hello --session secret\n");
        assert!(out.ends_with('\n'), "{out:?}");
        assert!(!out.contains("secret"));
    }

    #[test]
    fn redact_preserves_exact_trailing_line_endings() {
        assert_eq!(redact_log_text("password=x\n\n"), "password=[redacted]\n\n");
        assert_eq!(
            redact_log_text("password=x\r\n\r\n"),
            "password=[redacted]\r\n\r\n"
        );
        assert_eq!(redact_log_text("password=x\r"), "password=[redacted]\r");
        assert_eq!(redact_log_text("token=y\r\n"), "token=[redacted]\r\n");
    }

    #[test]
    fn redact_does_not_claim_freeform_secret_scrubbing() {
        // Assignment scrubbing only — prose mentioning secrets must stay intact.
        let prose = "user said the password is hunter2 and the token was abc123";
        assert_eq!(redact_log_text(prose), prose);

        let jsonish = r#""password":"hunter2" "token":"abc""#;
        assert_eq!(redact_log_text(jsonish), jsonish);

        // Bare key= (no \S+ value) left alone.
        assert_eq!(redact_log_text("secret="), "secret=");
        // Secrets/Bitwarden pass trims the line, so spaces-only after `=` become bare key=.
        assert_eq!(redact_log_text("password=   "), "password=");
        // Mid-line spaces after `=` are optional padding before a `\S+` value.
        assert_eq!(
            redact_log_text("x password=   y"),
            "x password=   [redacted]"
        );

        // Substring match is intentional for `token` / `password`; `secret` requires `=`
        // immediately after optional spaces (so `secret_key=` is not an assignment hit).
        assert_eq!(redact_log_text("api_token=xyz"), "api_token=[redacted]");
        assert_eq!(redact_log_text("secret_key=abc"), "secret_key=abc");
    }

    #[test]
    fn redact_nested_and_query_string_assignments() {
        assert_eq!(
            redact_log_text("password=token=nested"),
            "password=[redacted]"
        );
        assert_eq!(
            redact_log_text("secret=password=token=x"),
            "secret=[redacted]"
        );

        // token before password in a query string — both secret values stripped.
        // Note: `\S+` for `token=` consumes through `&password=…` until whitespace, so the
        // password assignment may be swallowed as part of the token value (still no leak).
        let qs = redact_log_text("GET /x?foo=1&token=tk1&password=pw1 SVPNCOOKIE=cook1");
        for leak in ["tk1", "pw1", "cook1"] {
            assert!(!qs.contains(leak), "leaked {leak} in {qs}");
        }
        assert!(qs.contains("token=[redacted]"));
        assert!(qs.contains("SVPNCOOKIE=[redacted]"));
    }

    #[test]
    fn init_tracing_creates_logs_dir() {
        let root = tempfile::tempdir().unwrap();
        let logs = root.path().join("Wormhole").join("logs");
        assert!(!logs.exists());
        let _ = init_tracing_with_dirs(Some(logs.clone()), false);
        assert!(logs.is_dir());
    }
}
