//! CredSSP password wipe ↔ connect-attempt lifecycle glue (Fake; no OCX).
//!
//! Pins that the caller's [`RdpConfigureOptions::password`] buffer is wiped on
//! **every** connect-attempt exit — success, hard fail, cancel, or bare Drop —
//! using the existing [`WipePasswordOnDrop`] helper from [`super::configure`]. Does **not**
//! rewrite OLE / CredSSP configure core or touch live `mstscax`.
//!
//! Live `RdpOcx::configure` already wipes on configure exits; this glue covers the
//! session-shaped attempt that may be abandoned (cancel) before Connect, or fail
//! after a Fake configure, without holding a password across the lifecycle.

use std::fmt;

use zeroize::Zeroize;

use super::configure::{
    validate_configure_inputs, ConfigureReport, RdpConfigureOptions, WipePasswordOnDrop,
    CREDSSP_SOFT_MISS_NLA_RISK,
};

/// Errors from Fake CredSSP connect-attempt glue — **never** carry password bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct CredSspConnectGlueError {
    message: String,
}

impl CredSspConnectGlueError {
    /// Build from a diagnostic message (must not include secrets).
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// User-facing / diagnostic text (never the password).
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Debug for CredSspConnectGlueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredSspConnectGlueError")
            .field("message", &self.message)
            .finish()
    }
}

impl fmt::Display for CredSspConnectGlueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CredSspConnectGlueError {}

impl From<windows::core::Error> for CredSspConnectGlueError {
    fn from(value: windows::core::Error) -> Self {
        Self::new(value.message())
    }
}

/// Stand-in for configure + `Connect` without COM / `mstscax`.
///
/// Records counts and last non-secret dial fields only — **never** stores the
/// password string (only whether a `ClearTextPassword`-shaped put occurred).
#[derive(Default, Clone, PartialEq, Eq)]
pub struct FakeRdpCredSspSurface {
    configure_count: usize,
    connect_count: usize,
    cancel_count: usize,
    /// Number of Fake `ClearTextPassword` puts (secret not retained).
    password_put_count: usize,
    last_server: Option<String>,
    last_port: Option<u16>,
    /// When set, Fake configure fails before password put (leftover must still wipe).
    fail_configure_with: Option<&'static str>,
    /// When set, Fake connect fails after configure (password already wiped).
    fail_connect_with: Option<&'static str>,
    /// Script a soft CredSSP miss on Fake configure (NLA-risk flag on report).
    soft_miss_cred_ssp: bool,
}

impl fmt::Debug for FakeRdpCredSspSurface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeRdpCredSspSurface")
            .field("configure_count", &self.configure_count)
            .field("connect_count", &self.connect_count)
            .field("cancel_count", &self.cancel_count)
            .field("password_put_count", &self.password_put_count)
            .field("last_server", &self.last_server)
            .field("last_port", &self.last_port)
            .field("fail_configure_with", &self.fail_configure_with)
            .field("fail_connect_with", &self.fail_connect_with)
            .field("soft_miss_cred_ssp", &self.soft_miss_cred_ssp)
            .finish()
    }
}

impl FakeRdpCredSspSurface {
    /// Empty Fake (no attempts yet).
    pub const fn new() -> Self {
        Self {
            configure_count: 0,
            connect_count: 0,
            cancel_count: 0,
            password_put_count: 0,
            last_server: None,
            last_port: None,
            fail_configure_with: None,
            fail_connect_with: None,
            soft_miss_cred_ssp: false,
        }
    }

    /// Script Fake configure to fail with `message` (before password put).
    pub fn fail_configure(&mut self, message: &'static str) -> &mut Self {
        self.fail_configure_with = Some(message);
        self
    }

    /// Script Fake connect to fail with `message` (after configure).
    pub fn fail_connect(&mut self, message: &'static str) -> &mut Self {
        self.fail_connect_with = Some(message);
        self
    }

    /// Script soft CredSSP miss on Fake configure (sticky until cleared with `false`).
    pub fn with_cred_ssp_soft_miss(&mut self, miss: bool) -> &mut Self {
        self.soft_miss_cred_ssp = miss;
        self
    }

    /// Configure invocations recorded.
    pub fn configure_count(&self) -> usize {
        self.configure_count
    }

    /// Connect invocations recorded.
    pub fn connect_count(&self) -> usize {
        self.connect_count
    }

    /// Explicit cancel invocations recorded ([`RdpCredSspConnectAttempt::cancel`]).
    /// Bare Drop without `cancel` does not increment this.
    pub fn cancel_count(&self) -> usize {
        self.cancel_count
    }

    /// How many times a password was put (count only).
    pub fn password_put_count(&self) -> usize {
        self.password_put_count
    }

    /// Last Fake configure server (non-secret).
    pub fn last_server(&self) -> Option<&str> {
        self.last_server.as_deref()
    }

    /// Last Fake configure port.
    pub fn last_port(&self) -> Option<u16> {
        self.last_port
    }

    fn record_cancel(&mut self) {
        self.cancel_count = self.cancel_count.saturating_add(1);
    }
}

/// In-flight connect attempt that owns the password slot until success / fail / cancel.
///
/// Construct with [`Self::begin`] (takes `opts.password` immediately). Dropping
/// without [`Self::run`] still wipes via [`WipePasswordOnDrop`] (abandon path).
/// Explicit [`Self::cancel`] also wipes and bumps the Fake `cancel_count`.
pub struct RdpCredSspConnectAttempt {
    server: String,
    port: u16,
    username: Option<String>,
    domain: Option<String>,
    desktop_width: i32,
    desktop_height: i32,
    enable_cred_ssp: bool,
    password_slot: Option<zeroize::Zeroizing<String>>,
}

impl fmt::Debug for RdpCredSspConnectAttempt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RdpCredSspConnectAttempt")
            .field("server", &self.server)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("domain", &self.domain)
            .field("desktop_width", &self.desktop_width)
            .field("desktop_height", &self.desktop_height)
            .field("enable_cred_ssp", &self.enable_cred_ssp)
            .field(
                "password",
                &self.password_slot.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl Drop for RdpCredSspConnectAttempt {
    fn drop(&mut self) {
        // Cancel / panic / early-return without run: same wipe helper as configure.
        let _wipe = WipePasswordOnDrop::new(&mut self.password_slot);
    }
}

impl RdpCredSspConnectAttempt {
    /// Take the password out of `opts` and begin an attempt (wipe on Drop / run exit).
    pub fn begin(opts: &mut RdpConfigureOptions) -> Self {
        Self {
            server: opts.server.clone(),
            port: opts.port,
            username: opts.username.clone(),
            domain: opts.domain.clone(),
            desktop_width: opts.desktop_width,
            desktop_height: opts.desktop_height,
            enable_cred_ssp: opts.enable_cred_ssp,
            password_slot: opts.password.take(),
        }
    }

    /// True while the attempt still holds a password buffer (before put / wipe).
    pub fn holds_password(&self) -> bool {
        self.password_slot.is_some()
    }

    /// Cancel without Connect — bumps `cancel_count`; wipe happens on Drop.
    ///
    /// Bare Drop without [`Self::cancel`] still wipes, but does **not** bump
    /// `cancel_count` (abandon vs explicit cancel).
    pub fn cancel(self, surface: &mut FakeRdpCredSspSurface) {
        surface.record_cancel();
        // Drop → WipePasswordOnDrop
    }

    /// Fake configure + Connect under [`WipePasswordOnDrop`].
    ///
    /// Password is wiped on Ok, configure Err, connect Err, and if this value is
    /// dropped without calling `run` (cancel / abandon).
    ///
    /// Does **not** refuse Fake Connect when [`ConfigureReport::cred_ssp_soft_missed`]
    /// is set (parity with [`super::ocx::RdpOcx::configure_and_connect`]); session
    /// callers must inspect [`ConfigureReport::has_cred_ssp_risk`] before treating
    /// the attempt as safe to proceed.
    pub fn run(
        mut self,
        surface: &mut FakeRdpCredSspSurface,
    ) -> Result<ConfigureReport, CredSspConnectGlueError> {
        // Same order as `RdpOcx::configure`: validate while we still hold the slot,
        // then install WipePasswordOnDrop so every exit (including validation Err) wipes.
        let validated = validate_configure_inputs(
            &self.server,
            self.port,
            self.username.as_deref(),
            self.domain.as_deref(),
            self.password_slot.as_ref().map(|p| p.as_str()),
            self.desktop_width,
            self.desktop_height,
        );
        let mut wipe = WipePasswordOnDrop::new(&mut self.password_slot);
        validated?;

        surface.configure_count = surface.configure_count.saturating_add(1);
        surface.last_server = Some(self.server.trim().to_string());
        surface.last_port = Some(self.port);

        if let Some(msg) = surface.fail_configure_with {
            return Err(CredSspConnectGlueError::new(msg));
        }

        let mut report = ConfigureReport::default();
        if self.enable_cred_ssp {
            if surface.soft_miss_cred_ssp {
                report.cred_ssp_applied = false;
                report.cred_ssp_soft_missed = true;
                report.push_missing(format!(
                    "EnableCredSspSupport Fake soft miss. {CREDSSP_SOFT_MISS_NLA_RISK}"
                ));
            } else {
                report.cred_ssp_applied = true;
            }
        }

        if let Some(mut password) = wipe.take_for_put() {
            surface.password_put_count = surface.password_put_count.saturating_add(1);
            // Never retain the secret on the Fake — put is count-only.
            password.zeroize();
            drop(password);
        }

        if let Some(msg) = surface.fail_connect_with {
            return Err(CredSspConnectGlueError::new(msg));
        }

        surface.connect_count = surface.connect_count.saturating_add(1);
        // Attempt Drop still runs; password_slot is already empty after wipe / take.
        Ok(report)
    }
}

/// Thin glue: Fake surface + attempt helpers for unit tests / session wiring.
#[derive(Debug, Default)]
pub struct RdpCredSspConnectGlue {
    surface: FakeRdpCredSspSurface,
}

impl RdpCredSspConnectGlue {
    /// Glue with an empty Fake surface (no OCX).
    pub fn with_fake() -> Self {
        Self::default()
    }

    /// Borrow the Fake surface (tests / diagnostics).
    pub fn surface(&self) -> &FakeRdpCredSspSurface {
        &self.surface
    }

    /// Mutable Fake surface (script failures / soft miss).
    pub fn surface_mut(&mut self) -> &mut FakeRdpCredSspSurface {
        &mut self.surface
    }

    /// Begin → run Fake configure+Connect; password wiped on every exit.
    ///
    /// Soft CredSSP miss still Fake-Connects — inspect the report (see [`RdpCredSspConnectAttempt::run`]).
    pub fn attempt_connect(
        &mut self,
        opts: &mut RdpConfigureOptions,
    ) -> Result<ConfigureReport, CredSspConnectGlueError> {
        RdpCredSspConnectAttempt::begin(opts).run(&mut self.surface)
    }

    /// Begin → explicit cancel (no Connect); bumps `cancel_count`; password wiped on Drop.
    pub fn cancel_attempt(&mut self, opts: &mut RdpConfigureOptions) {
        RdpCredSspConnectAttempt::begin(opts).cancel(&mut self.surface);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::configure::MAX_PASSWORD_CHARS;

    #[test]
    fn success_wipes_password_and_records_put() {
        let mut glue = RdpCredSspConnectGlue::with_fake();
        let mut opts = RdpConfigureOptions::new("dc.local", 3389).with_password("s3cret-ok");
        let report = glue.attempt_connect(&mut opts).expect("ok");
        assert!(opts.password.is_none());
        assert!(report.cred_ssp_applied);
        assert_eq!(glue.surface().configure_count(), 1);
        assert_eq!(glue.surface().connect_count(), 1);
        assert_eq!(glue.surface().password_put_count(), 1);
        assert_eq!(glue.surface().last_server(), Some("dc.local"));
        assert_eq!(glue.surface().last_port(), Some(3389));
        let dbg = format!("{opts:?}");
        assert!(!dbg.contains("s3cret-ok"));
    }

    #[test]
    fn configure_fail_before_put_still_wipes() {
        let mut glue = RdpCredSspConnectGlue::with_fake();
        glue.surface_mut().fail_configure("fake configure boom");
        let mut opts = RdpConfigureOptions::new("host", 3389).with_password("must-wipe-cfg");
        let err = glue.attempt_connect(&mut opts).expect_err("cfg fail");
        assert!(opts.password.is_none());
        assert_eq!(err.message(), "fake configure boom");
        assert!(!format!("{err:?}").contains("must-wipe-cfg"));
        assert_eq!(glue.surface().configure_count(), 1);
        assert_eq!(glue.surface().connect_count(), 0);
        assert_eq!(glue.surface().password_put_count(), 0);
        assert!(!format!("{opts:?}").contains("must-wipe-cfg"));
    }

    #[test]
    fn connect_fail_after_put_still_wipes() {
        let mut glue = RdpCredSspConnectGlue::with_fake();
        glue.surface_mut().fail_connect("fake connect boom");
        let mut opts = RdpConfigureOptions::new("host", 3389).with_password("must-wipe-conn");
        let err = glue.attempt_connect(&mut opts).expect_err("conn fail");
        assert!(opts.password.is_none());
        assert_eq!(err.message(), "fake connect boom");
        assert!(!format!("{err:?}").contains("must-wipe-conn"));
        assert_eq!(glue.surface().password_put_count(), 1);
        assert_eq!(glue.surface().connect_count(), 0);
    }

    #[test]
    fn validation_fail_still_wipes_and_debug_redacts() {
        let mut glue = RdpCredSspConnectGlue::with_fake();
        let mut opts = RdpConfigureOptions::new("   ", 3389).with_password("must-wipe-val");
        let err = glue.attempt_connect(&mut opts).expect_err("validation");
        assert!(opts.password.is_none());
        assert!(err.message().contains("server"));
        assert!(!err.message().contains("must-wipe-val"));
        assert!(!format!("{opts:?}").contains("must-wipe-val"));
        assert_eq!(glue.surface().configure_count(), 0);
        assert_eq!(glue.surface().password_put_count(), 0);
    }

    #[test]
    fn cancel_wipes_without_connect() {
        let mut glue = RdpCredSspConnectGlue::with_fake();
        let mut opts = RdpConfigureOptions::new("host", 3389).with_password("must-wipe-cancel");
        glue.cancel_attempt(&mut opts);
        assert!(opts.password.is_none());
        assert_eq!(glue.surface().cancel_count(), 1);
        assert_eq!(glue.surface().configure_count(), 0);
        assert_eq!(glue.surface().connect_count(), 0);
        assert_eq!(glue.surface().password_put_count(), 0);
        assert!(!format!("{opts:?}").contains("must-wipe-cancel"));
    }

    #[test]
    fn drop_without_run_is_cancel_wipe() {
        let mut opts = RdpConfigureOptions::new("host", 3389).with_password("abandon-secret");
        {
            let attempt = RdpCredSspConnectAttempt::begin(&mut opts);
            assert!(opts.password.is_none());
            assert!(attempt.holds_password());
            let dbg = format!("{attempt:?}");
            assert!(dbg.contains("<redacted>"));
            assert!(!dbg.contains("abandon-secret"));
            // drop without run
        }
        assert!(opts.password.is_none());
        assert!(!format!("{opts:?}").contains("abandon-secret"));
    }

    #[test]
    fn fake_surface_debug_never_echoes_password() {
        let mut surface = FakeRdpCredSspSurface::new();
        let mut opts = RdpConfigureOptions::new("h", 3389).with_password("not-in-fake-debug");
        RdpCredSspConnectAttempt::begin(&mut opts)
            .run(&mut surface)
            .expect("ok");
        let dbg = format!("{surface:?}");
        assert!(!dbg.contains("not-in-fake-debug"));
        assert_eq!(surface.password_put_count(), 1);
    }

    #[test]
    fn soft_cred_ssp_miss_still_wipes_on_success_path() {
        let mut glue = RdpCredSspConnectGlue::with_fake();
        glue.surface_mut().with_cred_ssp_soft_miss(true);
        let mut opts = RdpConfigureOptions::new("host", 3389).with_password("soft-miss-secret");
        let report = glue.attempt_connect(&mut opts).expect("ok");
        assert!(opts.password.is_none());
        assert!(report.cred_ssp_soft_missed);
        assert!(report.has_cred_ssp_risk());
        // Lab/Fake parity with configure_and_connect: soft miss still Fake-Connects.
        assert_eq!(glue.surface().connect_count(), 1);
        assert!(!format!("{opts:?}").contains("soft-miss-secret"));
    }

    #[test]
    fn requested_off_cred_ssp_ignores_soft_miss() {
        let mut glue = RdpCredSspConnectGlue::with_fake();
        glue.surface_mut().with_cred_ssp_soft_miss(true);
        let mut opts = RdpConfigureOptions::new("host", 3389).with_password("off-cred-secret");
        opts.enable_cred_ssp = false;
        let report = glue.attempt_connect(&mut opts).expect("ok");
        assert!(opts.password.is_none());
        assert!(!report.cred_ssp_applied);
        assert!(!report.cred_ssp_soft_missed);
        assert!(!report.has_cred_ssp_risk());
        assert!(report.soft_failures.is_empty());
        assert!(!format!("{opts:?}").contains("off-cred-secret"));
    }

    #[test]
    fn oversized_and_nul_password_validation_still_wipes() {
        let mut glue = RdpCredSspConnectGlue::with_fake();
        let oversized: String = "X".repeat(MAX_PASSWORD_CHARS + 1);
        let mut opts = RdpConfigureOptions::new("host", 3389).with_password(oversized.clone());
        let err = glue.attempt_connect(&mut opts).expect_err("oversize");
        assert!(opts.password.is_none());
        assert!(err.message().contains("password"));
        assert!(!err.message().contains('X'));
        assert!(!format!("{err:?}").contains(&oversized));
        assert_eq!(glue.surface().configure_count(), 0);

        let mut glue = RdpCredSspConnectGlue::with_fake();
        let mut opts = RdpConfigureOptions::new("host", 3389).with_password("nul\0secret");
        let err = glue.attempt_connect(&mut opts).expect_err("nul");
        assert!(opts.password.is_none());
        assert!(err.message().contains("password"));
        assert!(!err.message().contains("nul"));
        assert!(!format!("{opts:?}").contains("nul\0secret"));
        assert_eq!(glue.surface().password_put_count(), 0);
    }

    #[test]
    fn no_password_connect_wipes_none_and_skips_put() {
        let mut glue = RdpCredSspConnectGlue::with_fake();
        let mut opts = RdpConfigureOptions::new("host", 3389);
        assert!(opts.password.is_none());
        let report = glue.attempt_connect(&mut opts).expect("ok");
        assert!(opts.password.is_none());
        assert!(report.cred_ssp_applied);
        assert_eq!(glue.surface().password_put_count(), 0);
        assert_eq!(glue.surface().connect_count(), 1);
    }

    #[test]
    fn bare_drop_wipes_without_bumping_cancel_count() {
        let surface = FakeRdpCredSspSurface::new();
        let mut opts = RdpConfigureOptions::new("host", 3389).with_password("bare-drop-secret");
        let attempt = RdpCredSspConnectAttempt::begin(&mut opts);
        drop(attempt);
        assert!(opts.password.is_none());
        assert_eq!(surface.cancel_count(), 0);
        assert!(!format!("{opts:?}").contains("bare-drop-secret"));
    }
}
