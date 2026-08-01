//! Installer-launch state glue — C# `UpdateViewModel.InstallAsync` /
//! `UpdateService.LaunchInstallerAndExitAsync` parity, Fake-first.
//!
//! The download + SHA-256 verify **leg stays in [`crate::download`]**; hosts keep
//! using [`crate::download_bytes_to_temp`] / [`crate::verify_sha256`] as today.
//! This module owns the **prepared → launching → launched → done** tail of the
//! flow plus a fail-closed Bitwarden-flush-before-launch ordering hook:
//!
//! | Phase | Trigger | Launch? |
//! |---|---|---|
//! | [`InstallerPhase::Ready`] | [`UpdateInstallerGlue::stage`] | — |
//! | [`InstallerPhase::Prepared`] | [`UpdateInstallerGlue::verify`] passes (existing [`crate::verify_sha256`]) | — |
//! | [`InstallerPhase::VerifyFailed`] | verify fails (bad `expected_sha256`, unreadable file) | **never** |
//! | [`InstallerPhase::PrepareFailed`] | [`PrepareForInstallSink`] (Bitwarden flush / session close) fails | **never** |
//! | [`InstallerPhase::Launching`] → [`InstallerPhase::Launched`] | [`InstallerLauncher`] returns `Ok` | yes |
//! | [`InstallerPhase::Done`] | flow complete (C# `ExitApp` next) | yes |
//! | [`InstallerPhase::LaunchFailed`] | [`InstallerLauncher`] returns `Err` | attempted, **never reports success** |
//!
//! Ordering is recorded per step ([`InstallerOrderStep::PrepareForInstall`] before
//! [`InstallerOrderStep::Launch`], mirroring C# flush-before-launch) and validated
//! by [`validate_installer_order`] / [`UpdateInstallerGlue::validate_order`] (same
//! recorder style as `wormhole-mcp::shutdown_order`).
//!
//! **No live HTTP, no real process spawn in this crate.** Tests inject
//! [`FakeInstallerLauncher`] (records launches, never spawns) and
//! [`FakePrepareForInstallSink`]; the product host supplies a
//! [`InstallerLauncher`] wrapping `Process::Start` with `/SILENT /RESTARTAPP`.
//!
//! **Never log API tokens.** The optional [`UpdateCheckRequest`] payload carries a
//! PAT whose `Debug` is redacted ([`crate::UpdateApiToken`]); this module never
//! formats a token value. SHA digests are only ever sampled for presence.
//!
//! Skip-version stamping (C# `Dismiss` → `SkippedUpdateVersion`) is preserved as
//! [`skipped_update_version`], reusing the same version formatting as
//! [`crate::notify_status_from_result`].

use std::collections::VecDeque;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::channel::UpdateCheckRequest;
use crate::check::UpdateCheckResult;
use crate::download::verify_sha256;
use crate::error::{Result, UpdateError};

/// Injectable installer launch boundary (product host wraps `Process::Start`).
///
/// Implementations must **never** echo credentials and must return
/// [`UpdateError::InstallerLaunchFailed`] on failure so the glue can fail closed.
pub trait InstallerLauncher: Send + Sync {
    /// Launch the installer at `path` (product: `Process.Start` with
    /// `/SILENT /RESTARTAPP`). `Ok(())` means the process **spawned**, not that
    /// the install succeeded.
    fn launch(&self, path: &Path) -> Result<()>;
}

/// Shared handle for DI / trait-object use.
pub type SharedInstallerLauncher = Arc<dyn InstallerLauncher>;

/// Records installer launches **without spawning anything** (deterministic tests).
///
/// Outcomes can be scripted: by default every launch succeeds; push `false` to
/// make the next launch return [`UpdateError::InstallerLaunchFailed`]. This fake
/// never opens a process — no real installer is ever started in this crate.
#[derive(Clone, Default)]
pub struct FakeInstallerLauncher {
    inner: Arc<FakeInstallerLauncherInner>,
}

#[derive(Default)]
struct FakeInstallerLauncherInner {
    launched: Mutex<Vec<PathBuf>>,
    outcomes: Mutex<VecDeque<bool>>,
}

impl FakeInstallerLauncher {
    /// All launches succeed.
    pub fn new() -> Self {
        Self::default()
    }

    /// Script the *next* `failures` launches to fail.
    pub fn with_failures(failures: usize) -> Self {
        Self::new().with_outcome_script((0..failures).map(|_| false))
    }

    /// Script launch outcomes in order (`true` = succeed, `false` = fail).
    pub fn with_outcome_script(
        self,
        outcomes: impl IntoIterator<Item = bool>,
    ) -> Self {
        self.inner
            .outcomes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .extend(outcomes);
        self
    }

    /// Queued launch paths (every [`InstallerLauncher::launch`] attempt, success or fail).
    pub fn launches(&self) -> Vec<PathBuf> {
        self.inner
            .launched
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// Number of launch attempts recorded.
    pub fn launch_count(&self) -> usize {
        self.inner
            .launched
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len()
    }
}

impl InstallerLauncher for FakeInstallerLauncher {
    fn launch(&self, path: &Path) -> Result<()> {
        let mut launched = self.inner.launched.lock().unwrap_or_else(|p| p.into_inner());
        launched.push(path.to_path_buf());
        let success = {
            let mut outcomes = self.inner.outcomes.lock().unwrap_or_else(|p| p.into_inner());
            outcomes.pop_front().unwrap_or(true)
        };
        if success {
            Ok(())
        } else {
            Err(UpdateError::InstallerLaunchFailed(
                "scripted fake launch failure".into(),
            ))
        }
    }
}

impl fmt::Debug for FakeInstallerLauncher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let launched = self.inner.launched.lock().unwrap_or_else(|p| p.into_inner());
        let outcomes = self.inner.outcomes.lock().unwrap_or_else(|p| p.into_inner());
        f.debug_struct("FakeInstallerLauncher")
            .field("launch_count", &launched.len())
            .field("launched_paths", &launched)
            .field("remaining_outcomes", &outcomes.len())
            .finish()
    }
}

/// Bitwarden-flush / session-close hook that must run **before** launching the
/// installer (C# `MainWindow.PrepareForProcessExitAsync` →
/// `UpdateViewModel.PrepareForInstallAsync`).
///
/// Failures abort the flow at [`InstallerPhase::PrepareFailed`] — the installer
/// is **never** launched. Tests inject [`FakePrepareForInstallSink`].
pub trait PrepareForInstallSink {
    /// Flush Bitwarden extension storage / close live sessions before the
    /// installer takes over the machine.
    fn prepare_for_install(&mut self) -> Result<()>;
}

/// Scriptable sink: records flush calls and can fail on demand (never touches
/// WebView2 / Bitwarden).
#[derive(Clone, Default)]
pub struct FakePrepareForInstallSink {
    inner: Arc<FakePrepareForInstallSinkInner>,
}

#[derive(Default)]
struct FakePrepareForInstallSinkInner {
    prepares: AtomicUsize,
    fail_next: AtomicBool,
    ok_calls: AtomicUsize,
}

impl FakePrepareForInstallSink {
    /// Never fails.
    pub fn new() -> Self {
        Self::default()
    }

    /// Make the next [`Self::prepare_for_install`] fail (then reset to success).
    pub fn set_fail_next(&self, fail: bool) {
        self.inner.fail_next.store(fail, Ordering::SeqCst);
    }

    /// Successful (non-failed) flush calls — the Bitwarden-flush record count.
    pub fn ok_prepares(&self) -> usize {
        self.inner.ok_calls.load(Ordering::SeqCst)
    }

    /// Total flush calls (successful + failed).
    pub fn prepares(&self) -> usize {
        self.inner.prepares.load(Ordering::SeqCst)
    }
}

impl PrepareForInstallSink for FakePrepareForInstallSink {
    fn prepare_for_install(&mut self) -> Result<()> {
        self.inner.prepares.fetch_add(1, Ordering::SeqCst);
        if self.inner.fail_next.swap(false, Ordering::SeqCst) {
            return Err(UpdateError::PrepareForInstallFailed(
                "scripted fake prepare failure".into(),
            ));
        }
        self.inner.ok_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

impl fmt::Debug for FakePrepareForInstallSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakePrepareForInstallSink")
            .field("prepares", &self.prepares())
            .field("ok_prepares", &self.ok_prepares())
            .field(
                "fail_next",
                &self.inner.fail_next.load(Ordering::SeqCst),
            )
            .finish()
    }
}

/// Ordered step in the installer flow (fail-closed ordering validation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallerOrderStep {
    /// Bitwarden storage flush / session close before launching (C#
    /// `PrepareForInstallAsync`).
    PrepareForInstall,
    /// Installer process launch attempt (`Process.Start`).
    Launch,
}

impl InstallerOrderStep {
    /// Stable string form for logs / tests.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PrepareForInstall => "PrepareForInstall",
            Self::Launch => "Launch",
        }
    }
}

impl fmt::Display for InstallerOrderStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Canonical C# parity ordering: Bitwarden flush **before** installer launch.
pub const INSTALLER_PARITY_ORDER: &[InstallerOrderStep] = &[
    InstallerOrderStep::PrepareForInstall,
    InstallerOrderStep::Launch,
];

/// Violation when recorded installer steps are out of canonical order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallerOrderError {
    /// Human-readable reason.
    pub message: String,
    /// Steps recorded so far.
    pub recorded: Vec<InstallerOrderStep>,
    /// Step that should have come next.
    pub expected_before: InstallerOrderStep,
    /// Step that actually appeared.
    pub found_at: InstallerOrderStep,
}

impl fmt::Display for InstallerOrderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for InstallerOrderError {}

/// Fail closed when `recorded` deviates from [`INSTALLER_PARITY_ORDER`]
/// (strict next-step match; duplicates / trailing steps rejected).
///
/// Mirrors `wormhole-mcp::shutdown_order::validate_shutdown_order`: an empty or
/// prefix sequence is valid; a flush after launch, a duplicate, or an unexpected
/// extra step is a violation.
pub fn validate_installer_order(recorded: &[InstallerOrderStep]) -> std::result::Result<(), InstallerOrderError> {
    for (canon, &step) in recorded.iter().enumerate() {
        let Some(&expected) = INSTALLER_PARITY_ORDER.get(canon) else {
            return Err(InstallerOrderError {
                message: format!("unexpected extra installer step {step}"),
                recorded: recorded.to_vec(),
                expected_before: InstallerOrderStep::Launch,
                found_at: step,
            });
        };
        if step != expected {
            return Err(InstallerOrderError {
                message: format!(
                    "installer step {step} is out of order (expected {expected} next)"
                ),
                recorded: recorded.to_vec(),
                expected_before: expected,
                found_at: step,
            });
        }
    }
    Ok(())
}

/// Installer-flow phase (C# `UpdateViewModel.InstallAsync` lifecycle).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallerPhase {
    /// Nothing staged / staged and awaiting verification.
    Ready,
    /// Verify passed (existing [`crate::verify_sha256`]); launch not started.
    Prepared,
    /// Launch attempt in progress.
    Launching,
    /// Installer process spawned (`Ok` from the launcher).
    Launched,
    /// Flow complete (host's next step is C# `ExitApp`).
    Done,
    /// Verify failed — **never** launches.
    VerifyFailed,
    /// Bitwarden flush / session close failed — **never** launches.
    PrepareFailed,
    /// Launch failed — **never** reports success.
    LaunchFailed,
}

impl InstallerPhase {
    /// Stable string form for logs / tests.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "Ready",
            Self::Prepared => "Prepared",
            Self::Launching => "Launching",
            Self::Launched => "Launched",
            Self::Done => "Done",
            Self::VerifyFailed => "VerifyFailed",
            Self::PrepareFailed => "PrepareFailed",
            Self::LaunchFailed => "LaunchFailed",
        }
    }

    /// `true` for failure terminals (never launch / never report success).
    pub fn is_failed(self) -> bool {
        matches!(
            self,
            Self::VerifyFailed | Self::PrepareFailed | Self::LaunchFailed
        )
    }

    /// `true` only when the whole install flow succeeded.
    pub fn is_success(self) -> bool {
        matches!(self, Self::Done)
    }
}

impl fmt::Display for InstallerPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Staged installer input (path + optional expected SHA-256).
#[derive(Clone)]
struct StagedInstaller {
    path: PathBuf,
    expected_sha256: Option<String>,
}

/// State machine + injectable hooks for the installer-launch tail.
///
/// Type-alias [`UpdateInstallerVm`] keeps the VM naming while [`UpdateInstallerGlue`]
/// is the canonical struct name. `Debug` never leaks tokens or SHA digests.
pub struct UpdateInstallerGlue {
    launcher: SharedInstallerLauncher,
    prepare_sink: Box<dyn PrepareForInstallSink>,
    phase: InstallerPhase,
    staged: Option<StagedInstaller>,
    order: Vec<InstallerOrderStep>,
    launched_path: Option<PathBuf>,
    request: Option<UpdateCheckRequest>,
    update: Option<UpdateCheckResult>,
}

/// VM-style alias for [`UpdateInstallerGlue`].
pub type UpdateInstallerVm = UpdateInstallerGlue;

impl fmt::Debug for UpdateInstallerGlue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpdateInstallerGlue")
            .field("phase", &self.phase)
            // Delegate to UpdateCheckRequest's redacting Debug (never expose token).
            .field("request", &self.request)
            .field("update_present", &self.update.is_some())
            .field("skip_version", &self.skip_version())
            .field("staged_path", &self.staged.as_ref().map(|s| &s.path))
            // SHA digest presence only — never the digest itself.
            .field(
                "expected_sha256_present",
                &self.staged.as_ref().map(|s| s.expected_sha256.is_some()),
            )
            .field("order_steps", &self.order)
            .field("launcher", &"<InstallerLauncher>")
            .field("prepare_sink", &"<PrepareForInstallSink>")
            .finish()
    }
}

impl UpdateInstallerGlue {
    /// Glue over an injected launcher + Bitwarden-flush sink.
    pub fn new(launcher: SharedInstallerLauncher, prepare_sink: Box<dyn PrepareForInstallSink>) -> Self {
        Self {
            launcher,
            prepare_sink,
            phase: InstallerPhase::Ready,
            staged: None,
            order: Vec::new(),
            launched_path: None,
            request: None,
            update: None,
        }
    }

    /// Attach the token-carrying check request as context. Never logged; `Debug`
    /// redacts the token via [`UpdateCheckRequest`].
    pub fn with_request(mut self, request: UpdateCheckRequest) -> Self {
        self.request = Some(request);
        self
    }

    /// Record the advertised update (C# `LatestKnown` equivalent) so
    /// [`Self::skip_version`] can preserve `SkippedUpdateVersion` stamping.
    pub fn with_update(mut self, update: UpdateCheckResult) -> Self {
        self.update = Some(update);
        self
    }

    /// Current phase of the state machine.
    pub fn phase(&self) -> InstallerPhase {
        self.phase
    }

    /// Staged installer path, if any.
    pub fn staged_path(&self) -> Option<&Path> {
        self.staged.as_ref().map(|s| s.path.as_path())
    }

    /// Path of the installer that was actually launched (`Ok` from the launcher).
    pub fn launched_path(&self) -> Option<&Path> {
        self.launched_path.as_deref()
    }

    /// Recorded ordering steps (flush-before-launch determinism).
    pub fn order_steps(&self) -> &[InstallerOrderStep] {
        &self.order
    }

    /// Fail-closed ordering check against [`INSTALLER_PARITY_ORDER`].
    pub fn validate_order(&self) -> std::result::Result<(), InstallerOrderError> {
        validate_installer_order(&self.order)
    }

    /// Preserved `SkippedUpdateVersion` stamp (C# `Dismiss`) derived from the
    /// recorded update — `None` when nothing was advertised (nothing to skip).
    pub fn skip_version(&self) -> Option<String> {
        self.update.as_ref().and_then(skipped_update_version)
    }

    /// Start a new install flow: stage `installer_path` (optionally with the
    /// expected SHA-256) and reset to [`InstallerPhase::Ready`].
    ///
    /// Re-staging resets the ordering recorder and any prior `launched_path`.
    pub fn stage(&mut self, installer_path: PathBuf, expected_sha256: Option<String>) -> Result<()> {
        self.staged = Some(StagedInstaller {
            path: installer_path,
            expected_sha256,
        });
        self.phase = InstallerPhase::Ready;
        self.order.clear();
        self.launched_path = None;
        Ok(())
    }

    /// Verify the staged installer against `expected_sha256` using the existing
    /// [`verify_sha256`] helper. Fail-closed:
    /// - nothing staged / wrong stage → [`UpdateError::InstallerNotStaged`]
    /// - unreadable file or digest mismatch → [`InstallerPhase::VerifyFailed`], no launch
    /// - `expected_sha256 == None` → proceed unverified (C# warns and continues)
    pub fn verify(&mut self) -> Result<()> {
        if self.phase == InstallerPhase::Prepared {
            // Idempotent: already verified for the current staging.
            return Ok(());
        }
        let Some(staged) = self.staged.as_ref() else {
            return Err(UpdateError::InstallerNotStaged);
        };
        if self.phase != InstallerPhase::Ready {
            return Err(UpdateError::InstallerNotStaged);
        }
        let bytes = match fs::read(&staged.path) {
            Ok(bytes) => bytes,
            Err(e) => {
                self.phase = InstallerPhase::VerifyFailed;
                return Err(UpdateError::Io(e));
            }
        };
        if let Some(expected) = staged.expected_sha256.as_deref() {
            if let Err(e) = verify_sha256(&bytes, expected) {
                self.phase = InstallerPhase::VerifyFailed;
                return Err(e);
            }
        }
        self.phase = InstallerPhase::Prepared;
        Ok(())
    }

    /// Bitwarden flush (prepare) then launch — must be called from
    /// [`InstallerPhase::Prepared`], else fail closed ([`UpdateError::InstallerNotStaged`]).
    ///
    /// Ordering recorder: [`InstallerOrderStep::PrepareForInstall`] is recorded
    /// before the sink; [`InstallerOrderStep::Launch`] before the launcher attempt.
    pub fn prepare_and_launch(&mut self) -> Result<()> {
        if self.phase != InstallerPhase::Prepared {
            return Err(UpdateError::InstallerNotStaged);
        }
        let Some(staged) = self.staged.clone() else {
            return Err(UpdateError::InstallerNotStaged);
        };

        // Bitwarden flush / session close MUST precede the launch (C# parity).
        self.order.push(InstallerOrderStep::PrepareForInstall);
        if let Err(e) = self.prepare_sink.prepare_for_install() {
            self.phase = InstallerPhase::PrepareFailed;
            return Err(e);
        }

        self.phase = InstallerPhase::Launching;
        self.order.push(InstallerOrderStep::Launch);
        match self.launcher.launch(&staged.path) {
            Ok(()) => {
                self.launched_path = Some(staged.path);
                self.phase = InstallerPhase::Launched;
                self.phase = InstallerPhase::Done;
                Ok(())
            }
            Err(e) => {
                self.phase = InstallerPhase::LaunchFailed;
                Err(e)
            }
        }
    }

    /// Canonical full flow: [`Self::verify`] → [`Self::prepare_and_launch`].
    ///
    /// Fail-closed: verify failure / prepare failure never reach the launcher;
    /// launcher failure leaves [`InstallerPhase::LaunchFailed`] (never success).
    pub fn install(&mut self) -> Result<()> {
        self.verify()?;
        self.prepare_and_launch()
    }
}

/// Preserve C# `UpdateViewModel.Dismiss` → `SkippedUpdateVersion` stamping.
///
/// Mirrors [`crate::notify_status_from_result`]'s fail-closed availability rule:
/// only an advertised update (`!check_failed && is_update_available`) with a
/// usable latest version yields a skip stamp, formatted via
/// [`crate::AppVersion::to_string`] — identical to the version printed in the
/// notify status line. Hosts write the returned string into their settings
/// `SkippedUpdateVersion` (as `wormhole-ui`'s `UpdateNotifyGlue::dismiss` does).
pub fn skipped_update_version(result: &UpdateCheckResult) -> Option<String> {
    if result.check_failed || !result.is_update_available {
        return None;
    }
    result.latest_version.map(|v| v.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::UpdateApiToken;
    use crate::download::sha256_hex;
    use crate::notify::notify_status_from_result;
    use crate::version::AppVersion;

    fn write_temp_installer() -> (tempfile::TempDir, PathBuf, Vec<u8>) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Wormhole-9.9.9-win-x64-setup.exe");
        let data = b"installer-bytes-for-verify-test";
        fs::write(&path, data).unwrap();
        (dir, path, data.to_vec())
    }

    fn available_update() -> UpdateCheckResult {
        UpdateCheckResult {
            current_version: AppVersion::new(0, 1),
            latest_version: Some(AppVersion::with_build(9, 9, 9)),
            is_update_available: true,
            check_failed: false,
            release_tag: Some("v9.9.9".into()),
            release_name: Some("Release v9.9.9".into()),
            release_url: Some("https://example/release".into()),
            release_notes: Some("## Notes".into()),
            installer_url: Some("https://example.invalid/setup.exe".into()),
            installer_file_name: Some("setup.exe".into()),
            installer_size: Some(1),
            installer_sha256: None,
        }
    }

    #[test]
    fn success_flow_records_prepare_before_launch_and_reaches_done() {
        let launcher = FakeInstallerLauncher::new();
        let sink = FakePrepareForInstallSink::new();
        let mut glue = UpdateInstallerGlue::new(Arc::new(launcher), Box::new(sink.clone()));
        let (_dir, path, data) = write_temp_installer();
        glue.stage(path.clone(), Some(sha256_hex(&data))).unwrap();

        glue.install().unwrap();

        assert_eq!(glue.phase(), InstallerPhase::Done);
        assert!(glue.phase().is_success());
        assert_eq!(glue.launched_path(), Some(path.as_path()));
        assert_eq!(glue.order_steps(), INSTALLER_PARITY_ORDER);
        glue.validate_order().expect("flush before launch");
        assert_eq!(sink.ok_prepares(), 1);
    }

    #[test]
    fn verify_fail_aborts_before_launch() {
        let launcher = FakeInstallerLauncher::new();
        let sink = FakePrepareForInstallSink::new();
        let mut glue = UpdateInstallerGlue::new(Arc::new(launcher), Box::new(sink.clone()));
        let (_dir, path, _data) = write_temp_installer();
        let bad = "0000000000000000000000000000000000000000000000000000000000000000";
        glue.stage(path, Some(bad.into())).unwrap();

        let err = glue.install().unwrap_err();
        assert!(matches!(err, UpdateError::Sha256Mismatch { .. }));
        assert_eq!(glue.phase(), InstallerPhase::VerifyFailed);
        assert!(glue.phase().is_failed());
        assert!(!glue.phase().is_success());
        assert_eq!(sink.prepares(), 0, "flush must not run when verify fails");
        assert!(glue.order_steps().is_empty(), "no steps recorded on verify failure");
        assert!(glue.launched_path().is_none());
    }

    #[test]
    fn missing_expected_sha_proceeds_unverified_like_csharp() {
        let launcher = FakeInstallerLauncher::new();
        let sink = FakePrepareForInstallSink::new();
        let mut glue = UpdateInstallerGlue::new(Arc::new(launcher), Box::new(sink));
        let (_dir, path, _data) = write_temp_installer();
        glue.stage(path.clone(), None).unwrap();

        glue.install().unwrap();

        assert_eq!(glue.phase(), InstallerPhase::Done);
        assert_eq!(glue.launched_path(), Some(path.as_path()));
    }

    #[test]
    fn unreadable_installer_verify_fail_closed() {
        let launcher = FakeInstallerLauncher::new();
        let sink = FakePrepareForInstallSink::new();
        let mut glue = UpdateInstallerGlue::new(Arc::new(launcher.clone()), Box::new(sink));
        let missing = PathBuf::from("Z:/definitely/not/a/real/installer.exe");
        glue.stage(missing, None).unwrap();

        let err = glue.install().unwrap_err();
        assert!(matches!(err, UpdateError::Io(_)));
        assert_eq!(glue.phase(), InstallerPhase::VerifyFailed);
        assert_eq!(launcher.launch_count(), 0, "unverifiable file must never launch");
    }

    #[test]
    fn launcher_error_fail_closed_never_reports_success() {
        let launcher = FakeInstallerLauncher::with_failures(1);
        let sink = FakePrepareForInstallSink::new();
        let mut glue = UpdateInstallerGlue::new(Arc::new(launcher), Box::new(sink));
        let (_dir, path, data) = write_temp_installer();
        glue.stage(path, Some(sha256_hex(&data))).unwrap();

        let err = glue.install().unwrap_err();
        assert!(matches!(err, UpdateError::InstallerLaunchFailed(_)));
        assert_eq!(glue.phase(), InstallerPhase::LaunchFailed);
        assert!(glue.phase().is_failed());
        assert!(!glue.phase().is_success());
        // Prepare ran before the launch attempt (order still canonical).
        assert_eq!(glue.order_steps(), INSTALLER_PARITY_ORDER);
        glue.validate_order().expect("prepare before launch attempt");
        assert!(glue.launched_path().is_none(), "failed launch is not a success");
    }

    #[test]
    fn prepare_failure_fail_closed_never_launches() {
        let launcher = FakeInstallerLauncher::new();
        let sink = FakePrepareForInstallSink::new();
        sink.set_fail_next(true);
        let mut glue = UpdateInstallerGlue::new(Arc::new(launcher), Box::new(sink.clone()));
        let (_dir, path, data) = write_temp_installer();
        glue.stage(path, Some(sha256_hex(&data))).unwrap();

        let err = glue.install().unwrap_err();
        assert!(matches!(err, UpdateError::PrepareForInstallFailed(_)));
        assert_eq!(glue.phase(), InstallerPhase::PrepareFailed);
        assert_eq!(sink.prepares(), 1, "flush attempted once");
        assert_eq!(
            glue.order_steps(),
            &[InstallerOrderStep::PrepareForInstall],
            "Launch must not be recorded when prepare fails"
        );
        assert!(glue.launched_path().is_none());
    }

    #[test]
    fn granular_verify_then_prepare_and_launch() {
        let launcher = FakeInstallerLauncher::new();
        let sink = FakePrepareForInstallSink::new();
        let mut glue = UpdateInstallerGlue::new(Arc::new(launcher), Box::new(sink.clone()));
        let (_dir, path, data) = write_temp_installer();
        glue.stage(path, Some(sha256_hex(&data))).unwrap();

        glue.verify().unwrap();
        assert_eq!(glue.phase(), InstallerPhase::Prepared);
        // Idempotent re-verify is a no-op.
        glue.verify().unwrap();
        assert_eq!(glue.phase(), InstallerPhase::Prepared);

        glue.prepare_and_launch().unwrap();
        assert_eq!(glue.phase(), InstallerPhase::Done);
        assert_eq!(sink.ok_prepares(), 1);
        glue.validate_order().unwrap();
    }

    #[test]
    fn prepare_and_launch_wrong_stage_fail_closed() {
        let launcher = FakeInstallerLauncher::new();
        let sink = FakePrepareForInstallSink::new();
        let mut glue = UpdateInstallerGlue::new(Arc::new(launcher.clone()), Box::new(sink.clone()));
        let (_dir, path, _data) = write_temp_installer();
        glue.stage(path, None).unwrap();

        // Never verified -> must not launch.
        let err = glue.prepare_and_launch().unwrap_err();
        assert!(matches!(err, UpdateError::InstallerNotStaged));
        assert_eq!(glue.phase(), InstallerPhase::Ready);
        assert_eq!(sink.prepares(), 0);
        assert_eq!(launcher.launch_count(), 0);
    }

    #[test]
    fn install_without_stage_fail_closed() {
        let launcher = FakeInstallerLauncher::new();
        let sink = FakePrepareForInstallSink::new();
        let mut glue = UpdateInstallerGlue::new(Arc::new(launcher.clone()), Box::new(sink));
        let err = glue.install().unwrap_err();
        assert!(matches!(err, UpdateError::InstallerNotStaged));
        assert_eq!(glue.phase(), InstallerPhase::Ready);
        assert_eq!(launcher.launch_count(), 0);
    }

    #[test]
    fn verify_failed_terminal_rejects_all_further_steps() {
        let launcher = FakeInstallerLauncher::new();
        let sink = FakePrepareForInstallSink::new();
        let mut glue = UpdateInstallerGlue::new(Arc::new(launcher.clone()), Box::new(sink.clone()));
        let (_dir, path, _data) = write_temp_installer();
        let bad = "0000000000000000000000000000000000000000000000000000000000000000";
        glue.stage(path, Some(bad.into())).unwrap();
        assert!(matches!(glue.install(), Err(UpdateError::Sha256Mismatch { .. })));
        assert_eq!(glue.phase(), InstallerPhase::VerifyFailed);

        assert!(matches!(glue.verify(), Err(UpdateError::InstallerNotStaged)));
        assert!(matches!(glue.prepare_and_launch(), Err(UpdateError::InstallerNotStaged)));
        assert!(matches!(glue.install(), Err(UpdateError::InstallerNotStaged)));
        assert_eq!(sink.prepares(), 0, "flush must never run from VerifyFailed");
        assert_eq!(launcher.launch_count(), 0, "nothing may launch from VerifyFailed");
    }

    #[test]
    fn launch_failed_terminal_rejects_retry_without_relaunch() {
        let launcher = FakeInstallerLauncher::with_failures(1);
        let sink = FakePrepareForInstallSink::new();
        let mut glue = UpdateInstallerGlue::new(Arc::new(launcher.clone()), Box::new(sink.clone()));
        let (_dir, path, data) = write_temp_installer();
        glue.stage(path, Some(sha256_hex(&data))).unwrap();
        assert!(matches!(
            glue.install(),
            Err(UpdateError::InstallerLaunchFailed(_))
        ));
        assert_eq!(glue.phase(), InstallerPhase::LaunchFailed);
        assert_eq!(launcher.launch_count(), 1);

        assert!(matches!(glue.prepare_and_launch(), Err(UpdateError::InstallerNotStaged)));
        assert!(matches!(glue.install(), Err(UpdateError::InstallerNotStaged)));
        assert_eq!(launcher.launch_count(), 1, "no second launch attempt");
        assert_eq!(sink.prepares(), 1, "flush must not re-run from LaunchFailed");
    }

    #[test]
    fn prepare_failed_terminal_rejects_retry_without_launch() {
        let launcher = FakeInstallerLauncher::new();
        let sink = FakePrepareForInstallSink::new();
        sink.set_fail_next(true);
        let mut glue = UpdateInstallerGlue::new(Arc::new(launcher.clone()), Box::new(sink.clone()));
        let (_dir, path, data) = write_temp_installer();
        glue.stage(path, Some(sha256_hex(&data))).unwrap();
        assert!(matches!(
            glue.install(),
            Err(UpdateError::PrepareForInstallFailed(_))
        ));
        assert_eq!(glue.phase(), InstallerPhase::PrepareFailed);
        assert_eq!(sink.prepares(), 1);

        assert!(matches!(glue.install(), Err(UpdateError::InstallerNotStaged)));
        assert!(matches!(glue.prepare_and_launch(), Err(UpdateError::InstallerNotStaged)));
        assert_eq!(launcher.launch_count(), 0, "prepare failure must never launch");
        assert_eq!(sink.prepares(), 1, "flush must not re-run from PrepareFailed");
    }

    #[test]
    fn done_terminal_rejects_further_steps_without_relaunch() {
        let launcher = FakeInstallerLauncher::new();
        let sink = FakePrepareForInstallSink::new();
        let mut glue = UpdateInstallerGlue::new(Arc::new(launcher.clone()), Box::new(sink.clone()));
        let (_dir, path, data) = write_temp_installer();
        glue.stage(path.clone(), Some(sha256_hex(&data))).unwrap();
        glue.install().unwrap();
        assert_eq!(glue.phase(), InstallerPhase::Done);

        assert!(matches!(glue.verify(), Err(UpdateError::InstallerNotStaged)));
        assert!(matches!(glue.prepare_and_launch(), Err(UpdateError::InstallerNotStaged)));
        assert!(matches!(glue.install(), Err(UpdateError::InstallerNotStaged)));
        assert_eq!(launcher.launch_count(), 1, "no second launch");
        assert_eq!(sink.prepares(), 1, "no second flush");
        assert_eq!(glue.launched_path(), Some(path.as_path()));
    }

    #[test]
    fn restaging_starts_a_fresh_flow_and_resets_recorder() {
        let launcher = FakeInstallerLauncher::new();
        let sink = FakePrepareForInstallSink::new();
        let mut glue = UpdateInstallerGlue::new(Arc::new(launcher.clone()), Box::new(sink.clone()));
        let (dir, first, data) = write_temp_installer();
        let second = dir.path().join("second.exe");
        fs::write(&second, &data).unwrap();

        glue.stage(first, Some(sha256_hex(&data))).unwrap();
        glue.install().unwrap();
        assert_eq!(glue.order_steps(), INSTALLER_PARITY_ORDER);

        // Re-staging clears phase, ordering recorder, and the previous launched path.
        glue.stage(second.clone(), Some(sha256_hex(&data))).unwrap();
        assert_eq!(glue.phase(), InstallerPhase::Ready);
        assert!(glue.order_steps().is_empty(), "restage clears the order recorder");
        assert!(glue.launched_path().is_none(), "restage clears launched_path");

        glue.install().unwrap();
        assert_eq!(glue.launched_path(), Some(second.as_path()));
        assert_eq!(glue.order_steps(), INSTALLER_PARITY_ORDER);
        assert_eq!(launcher.launch_count(), 2);
    }

    #[test]
    fn order_validation_rejects_wrong_order_duplicates_extra() {
        assert!(validate_installer_order(&[]).is_ok());
        assert!(validate_installer_order(&[InstallerOrderStep::PrepareForInstall]).is_ok());
        assert!(validate_installer_order(INSTALLER_PARITY_ORDER).is_ok());

        let launch_first = vec![InstallerOrderStep::Launch, InstallerOrderStep::PrepareForInstall];
        let err = validate_installer_order(&launch_first).expect_err("launch before flush fails");
        assert_eq!(err.expected_before, InstallerOrderStep::PrepareForInstall);
        assert_eq!(err.found_at, InstallerOrderStep::Launch);

        let duplicate = vec![
            InstallerOrderStep::PrepareForInstall,
            InstallerOrderStep::PrepareForInstall,
        ];
        validate_installer_order(&duplicate).expect_err("duplicate flush fails");

        let extra = INSTALLER_PARITY_ORDER
            .iter()
            .copied()
            .chain([InstallerOrderStep::PrepareForInstall])
            .collect::<Vec<_>>();
        validate_installer_order(&extra).expect_err("trailing extra step fails");
    }

    #[test]
    fn debug_redacts_api_token_and_omits_sensitive_wording() {
        let secret = "ghp_installer_glue_secret_must_never_leak";
        let request = UpdateCheckRequest::new("o", "r", AppVersion::new(0, 1), "x64")
            .with_api_token(UpdateApiToken::new(secret));
        let sink = FakePrepareForInstallSink::new();
        let glue = UpdateInstallerGlue::new(Arc::new(FakeInstallerLauncher::new()), Box::new(sink))
            .with_request(request)
            .with_update(available_update());
        let dbg = format!("{glue:?}");
        assert!(dbg.contains("UpdateInstallerGlue"), "{dbg}");
        assert!(!dbg.contains(secret), "{dbg}");
        assert!(!dbg.contains("ghp_"), "{dbg}");
        assert!(dbg.contains("[REDACTED"), "{dbg}");

        // SHA digest values must never surface; presence only.
        let sha = "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234";
        let mut glue2 = UpdateInstallerGlue::new(
            Arc::new(FakeInstallerLauncher::new()),
            Box::new(FakePrepareForInstallSink::new()),
        );
        glue2.stage(PathBuf::from("C:/Wormhole/setup.exe"), Some(sha.into())).unwrap();
        let dbg2 = format!("{glue2:?}");
        assert!(!dbg2.contains(sha), "{dbg2}");
        assert!(dbg2.contains("expected_sha256_present: Some(true)"), "{dbg2}");
    }

    #[test]
    fn skipped_version_stamp_preserved_and_matches_notify() {
        let update = available_update();
        // Same formatting the notify status line uses (failed update checks never stamp).
        let status = notify_status_from_result(&update);
        assert_eq!(skipped_update_version(&update).as_deref(), Some("9.9.9"));
        assert!(status.status_text().ends_with("9.9.9"));

        let sink = FakePrepareForInstallSink::new();
        let glue = UpdateInstallerGlue::new(
            Arc::new(FakeInstallerLauncher::new()),
            Box::new(sink),
        )
        .with_update(update);
        assert_eq!(glue.skip_version().as_deref(), Some("9.9.9"));
    }

    #[test]
    fn skipped_version_none_when_nothing_usable() {
        let failed = UpdateCheckResult::failed(AppVersion::new(0, 1));
        assert_eq!(skipped_update_version(&failed), None);

        let mut hostile = available_update();
        hostile.latest_version = None;
        assert_eq!(skipped_update_version(&hostile), None, "no version -> nothing to skip");

        let mut check_failed_available = available_update();
        check_failed_available.check_failed = true;
        assert_eq!(
            skipped_update_version(&check_failed_available),
            None,
            "failed check must not stamp a skip"
        );
    }

    #[test]
    fn skipped_version_none_for_no_update_even_with_version() {
        // C# `Dismiss` stamps any known LatestVersion; Rust parity mirrors notify,
        // which only advertises an *available* update — an old-but-known release
        // must never produce a skip stamp (nothing is shown to dismiss).
        let no_update = UpdateCheckResult::no_update(
            AppVersion::new(0, 1),
            Some(AppVersion::with_build(9, 9, 9)),
        );
        let status = notify_status_from_result(&no_update);
        assert!(!status.is_update_available(), "notify never advertises a no-update");
        assert_eq!(
            skipped_update_version(&no_update),
            None,
            "not advertised -> nothing to skip"
        );
    }

    #[test]
    fn fake_launcher_records_launches_and_scripted_failures() {
        let launcher = FakeInstallerLauncher::new().with_outcome_script([true, false]);
        let a = PathBuf::from("C:/Wormhole/a.exe");
        let b = PathBuf::from("C:/Wormhole/b.exe");
        assert!(launcher.launch(&a).is_ok());
        assert!(matches!(
            launcher.launch(&b),
            Err(UpdateError::InstallerLaunchFailed(_))
        ));
        assert_eq!(launcher.launches(), vec![a, b]);
        assert_eq!(launcher.launch_count(), 2);
        let dbg = format!("{launcher:?}");
        assert!(dbg.contains("launch_count"), "{dbg}");
        assert!(!dbg.contains("bearer"), "{dbg}");
        assert!(!dbg.contains("token"), "{dbg}");
    }
}
