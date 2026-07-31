//! ConnectionProfile RDP display + common redirects → Fake configure (no OCX).
//!
//! Thin glue mirroring the display / redirection subset of C# `RdpHostForm.Configure`:
//! - **Loud** (fail-closed): `DesktopWidth` / `DesktopHeight` / `ColorDepth`
//!   after [`resolve_connect_desktop_size`] + existing [`MAX_DESKTOP_AXIS`] /
//!   positive-axis checks (same bounds as [`super::configure::validate_configure_inputs`]).
//! - **Soft** (TrySet-style skip): `SmartSizing`, `UseMultimon`, redirect toggles,
//!   `RedirectDrives` master, and `DriveCollection` per-letter filter when the Fake
//!   (or a future live OCX tier) does not expose the property name.
//!
//! Does **not** touch CredSSP / password wipe, gateway transport, audio, performance
//! flags, or live `mstscax`. Soft skips are recorded on [`DisplayRedirectReport`] —
//! never hard-`Err`.

use std::collections::BTreeSet;
use std::fmt;

use wormhole_domain::{ConnectionProfile, RdpScreenSizes};

use super::configure::{normalise_color_depth, MAX_DESKTOP_AXIS};

/// C# `RdpDesktopSizeResolver.MinimumWidth` — connect-time logon UI floor.
pub const DESKTOP_MIN_WIDTH: i32 = 640;
/// C# `RdpDesktopSizeResolver.MinimumHeight`.
pub const DESKTOP_MIN_HEIGHT: i32 = 480;
/// C# `RdpDesktopSizeResolver.DefaultWidth` — fixed-size parse fallback.
pub const DESKTOP_DEFAULT_WIDTH: i32 = 1280;
/// C# `RdpDesktopSizeResolver.DefaultHeight`.
pub const DESKTOP_DEFAULT_HEIGHT: i32 = 800;

/// Drive-redirect `"all"` sentinel (`RdpDriveList.AllSentinel`).
pub const REDIRECT_DRIVES_ALL: &str = "all";

/// Soft / TrySet-style property names applied by this glue (documented skip set).
pub const SOFT_DISPLAY_REDIRECT_PROPS: &[&str] = &[
    "SmartSizing",
    "UseMultimon",
    "RedirectClipboard",
    "RedirectPrinters",
    "RedirectSmartCards",
    "RedirectPorts",
    "RedirectDevices",
    "RedirectDrives",
    "DriveCollection",
];

/// Loud display property names (validation / Fake hard-fail → `Err`).
pub const LOUD_DISPLAY_PROPS: &[&str] = &["DesktopWidth", "DesktopHeight", "ColorDepth"];

/// Outcome of one Fake property put.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FakePropPut {
    /// Property was recorded on the Fake.
    Applied,
    /// Name unknown / scripted missing — TrySet-style soft skip.
    SoftSkipped {
        /// Property name that was soft-skipped.
        property: String,
        /// Human-readable miss detail (for [`DisplayRedirectReport::soft_skips`]).
        detail: String,
    },
}

/// Errors from display/redirect Fake glue — never carry secrets.
#[derive(Clone, PartialEq, Eq)]
pub struct DisplayRedirectGlueError {
    message: String,
}

impl DisplayRedirectGlueError {
    /// Build from a diagnostic message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// User-facing / diagnostic text.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Debug for DisplayRedirectGlueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DisplayRedirectGlueError")
            .field("message", &self.message)
            .finish()
    }
}

impl fmt::Display for DisplayRedirectGlueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for DisplayRedirectGlueError {}

impl From<windows::core::Error> for DisplayRedirectGlueError {
    fn from(value: windows::core::Error) -> Self {
        Self::new(value.message())
    }
}

/// Soft-skip + loud-apply summary for one Fake configure pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DisplayRedirectReport {
    /// Human-readable soft-skip details (missing optional props).
    pub soft_skips: Vec<String>,
    /// Loud puts that applied (`DesktopWidth` / `DesktopHeight` / `ColorDepth`).
    pub loud_applied: Vec<String>,
    /// Soft puts that applied.
    pub soft_applied: Vec<String>,
    /// Resolved desktop axes after policy + validation (loud puts).
    pub desktop_width: i32,
    /// See [`Self::desktop_width`].
    pub desktop_height: i32,
    /// Colour depth after [`normalise_color_depth`].
    pub color_depth: i32,
    /// Parsed drive-redirect intent (may differ from effective master after soft-miss /
    /// least-privilege force-off).
    pub redirect_drives: RedirectDrivesIntent,
    /// Final `RedirectDrives` master enable on the Fake (`true` only when last applied
    /// value is `true` — false after `None`, soft-miss, or DriveCollection least-privilege off).
    pub redirect_drives_master: bool,
}

impl DisplayRedirectReport {
    /// True when every soft setter applied (or was not attempted).
    pub fn all_soft_applied(&self) -> bool {
        self.soft_skips.is_empty()
    }
}

/// Parsed `RdpRedirectDrives` intent (C# `RdpDriveList.ParseLetters` shape).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedirectDrivesIntent {
    /// `""` / whitespace → master off.
    None,
    /// `"all"` → master on, no per-letter filter.
    All,
    /// Explicit letter list → master on + DriveCollection filter (soft).
    Letters(BTreeSet<char>),
}

impl Default for RedirectDrivesIntent {
    fn default() -> Self {
        Self::None
    }
}

/// Pure connect-time desktop size policy (`RdpDesktopSizeResolver.Resolve`).
///
/// Does not call Win32; callers supply the monitor / surface fallback axes.
pub fn resolve_connect_desktop_size(
    screen_size: Option<&str>,
    initial_surface_width: i32,
    initial_surface_height: i32,
    fallback_width: i32,
    fallback_height: i32,
) -> (i32, i32) {
    if RdpScreenSizes::is_full_connection_content(screen_size) {
        if initial_surface_width > 0 && initial_surface_height > 0 {
            return (
                initial_surface_width.max(DESKTOP_MIN_WIDTH),
                initial_surface_height.max(DESKTOP_MIN_HEIGHT),
            );
        }
        return (
            fallback_width.max(DESKTOP_MIN_WIDTH),
            fallback_height.max(DESKTOP_MIN_HEIGHT),
        );
    }

    if let Some(raw) = screen_size {
        if let Some((w, h)) = parse_fixed_screen_size(raw) {
            if w >= DESKTOP_MIN_WIDTH && h >= DESKTOP_MIN_HEIGHT {
                return (w, h);
            }
        }
    }

    (DESKTOP_DEFAULT_WIDTH, DESKTOP_DEFAULT_HEIGHT)
}

fn parse_fixed_screen_size(raw: &str) -> Option<(i32, i32)> {
    let trimmed = raw.trim();
    let sep = trimmed.find(['x', 'X'])?;
    // Reject a second separator (C# `IndexOfAny` on the suffix < 0).
    if trimmed[sep + 1..].find(['x', 'X']).is_some() {
        return None;
    }
    let w: i32 = trimmed[..sep].trim().parse().ok()?;
    let h: i32 = trimmed[sep + 1..].trim().parse().ok()?;
    Some((w, h))
}

/// Validate desktop axes with the same fail-closed bounds as configure inputs.
pub fn validate_desktop_axes(width: i32, height: i32) -> Result<(), DisplayRedirectGlueError> {
    if width <= 0 || height <= 0 {
        return Err(DisplayRedirectGlueError::new(
            "RDP desktop width and height must be positive",
        ));
    }
    if width > MAX_DESKTOP_AXIS || height > MAX_DESKTOP_AXIS {
        return Err(DisplayRedirectGlueError::new(format!(
            "RDP desktop axis exceeds maximum ({MAX_DESKTOP_AXIS})"
        )));
    }
    Ok(())
}

/// Parse persisted drive-redirect string (`RdpDriveList.ParseLetters`).
///
/// - whitespace / `""` → [`RedirectDrivesIntent::None`]
/// - `"all"` (case-insensitive) → [`RedirectDrivesIntent::All`]
/// - otherwise → letter set (invalid tokens dropped silently)
pub fn parse_redirect_drives(raw: &str) -> RedirectDrivesIntent {
    if raw.trim().is_empty() {
        return RedirectDrivesIntent::None;
    }
    if raw.eq_ignore_ascii_case(REDIRECT_DRIVES_ALL) {
        return RedirectDrivesIntent::All;
    }
    let mut letters = BTreeSet::new();
    for token in raw
        .split(|c| c == ',' || c == ';' || c == ' ')
        .map(str::trim)
        .filter(|t| !t.is_empty())
    {
        if token.len() != 1 {
            continue;
        }
        let ch = token.chars().next().unwrap().to_ascii_uppercase();
        if ch.is_ascii_uppercase() {
            letters.insert(ch);
        }
    }
    if letters.is_empty() {
        RedirectDrivesIntent::None
    } else {
        RedirectDrivesIntent::Letters(letters)
    }
}

/// One Fake IDispatch-shaped put record (tests / diagnostics).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakePropRecord {
    /// Property name (`DesktopWidth`, `RedirectClipboard`, …).
    pub property: String,
    /// Stringified value (bool / i32 / drive intent) — never a password.
    pub value: String,
    /// Whether the put applied or soft-skipped.
    pub outcome: FakePropOutcome,
}

/// Applied vs soft-skipped (mirrors TrySetOptional swallow).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FakePropOutcome {
    /// Recorded on the Fake.
    Applied,
    /// Unknown / scripted missing.
    SoftSkipped,
}

/// Stand-in for MsRdpClient display/redirect configure puts (no COM / `mstscax`).
///
/// Scripted soft-miss names TrySet-skip; other names record as Applied. Loud display
/// props can be scripted to hard-fail. Does **not** retain credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeRdpPropertySurface {
    records: Vec<FakePropRecord>,
    /// Property names that soft-skip (TrySet miss). Default: empty (all known apply).
    soft_miss: BTreeSet<String>,
    /// When set, loud put of this property hard-fails.
    fail_loud_with: Option<(String, &'static str)>,
}

impl Default for FakeRdpPropertySurface {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeRdpPropertySurface {
    /// Empty Fake (no puts yet).
    pub const fn new() -> Self {
        Self {
            records: Vec::new(),
            soft_miss: BTreeSet::new(),
            fail_loud_with: None,
        }
    }

    /// Script a soft miss for `property` (sticky until cleared).
    pub fn soft_miss_prop(&mut self, property: impl Into<String>) -> &mut Self {
        self.soft_miss.insert(property.into());
        self
    }

    /// Clear all scripted soft misses.
    pub fn clear_soft_misses(&mut self) -> &mut Self {
        self.soft_miss.clear();
        self
    }

    /// Script a loud property put to hard-fail with `message`.
    pub fn fail_loud(&mut self, property: impl Into<String>, message: &'static str) -> &mut Self {
        self.fail_loud_with = Some((property.into(), message));
        self
    }

    /// All put records in order.
    pub fn records(&self) -> &[FakePropRecord] {
        &self.records
    }

    /// Number of applied puts.
    pub fn applied_count(&self) -> usize {
        self.records
            .iter()
            .filter(|r| r.outcome == FakePropOutcome::Applied)
            .count()
    }

    /// Number of soft-skipped puts.
    pub fn soft_skip_count(&self) -> usize {
        self.records
            .iter()
            .filter(|r| r.outcome == FakePropOutcome::SoftSkipped)
            .count()
    }

    /// Last recorded value for `property` (applied only).
    pub fn last_applied_value(&self, property: &str) -> Option<&str> {
        self.records
            .iter()
            .rev()
            .find(|r| r.property == property && r.outcome == FakePropOutcome::Applied)
            .map(|r| r.value.as_str())
    }

    /// Clear recorded puts (keeps miss / fail scripts).
    pub fn clear_records(&mut self) {
        self.records.clear();
    }

    fn put_loud_i4(&mut self, property: &str, value: i32) -> Result<FakePropPut, DisplayRedirectGlueError> {
        if let Some((ref fail_prop, msg)) = self.fail_loud_with {
            if fail_prop == property {
                return Err(DisplayRedirectGlueError::new(msg));
            }
        }
        self.records.push(FakePropRecord {
            property: property.to_string(),
            value: value.to_string(),
            outcome: FakePropOutcome::Applied,
        });
        Ok(FakePropPut::Applied)
    }

    fn try_put_bool(&mut self, property: &str, value: bool) -> FakePropPut {
        if self.soft_miss.contains(property) {
            let detail = format!("{property}: missing on Fake tier (TrySet soft skip)");
            self.records.push(FakePropRecord {
                property: property.to_string(),
                value: value.to_string(),
                outcome: FakePropOutcome::SoftSkipped,
            });
            return FakePropPut::SoftSkipped {
                property: property.to_string(),
                detail,
            };
        }
        self.records.push(FakePropRecord {
            property: property.to_string(),
            value: value.to_string(),
            outcome: FakePropOutcome::Applied,
        });
        FakePropPut::Applied
    }

    fn try_put_drives(
        &mut self,
        intent: &RedirectDrivesIntent,
    ) -> (FakePropPut, Option<FakePropPut>) {
        let master = match intent {
            RedirectDrivesIntent::None => false,
            RedirectDrivesIntent::All | RedirectDrivesIntent::Letters(_) => true,
        };
        let master_put = self.try_put_bool("RedirectDrives", master);
        match intent {
            RedirectDrivesIntent::Letters(letters) => {
                // Custom letters require an applied master before DriveCollection.
                // Soft-missed master → skip collection (no filter without enable).
                if matches!(master_put, FakePropPut::SoftSkipped { .. }) {
                    return (master_put, None);
                }
                let value = letters.iter().collect::<String>();
                let collection_put = self.try_put_collection("DriveCollection", &value);
                // Least-privilege: DriveCollection soft-miss → force master off
                // (parity with C# ApplyDriveRedirection catch path). Return the *final*
                // master put so DisplayRedirectReport soft_applied matches last_applied.
                if matches!(collection_put, FakePropPut::SoftSkipped { .. }) {
                    let final_master = self.try_put_bool("RedirectDrives", false);
                    return (final_master, Some(collection_put));
                }
                (master_put, Some(collection_put))
            }
            RedirectDrivesIntent::None | RedirectDrivesIntent::All => (master_put, None),
        }
    }

    fn try_put_collection(&mut self, property: &str, value: &str) -> FakePropPut {
        if self.soft_miss.contains(property) {
            let detail = format!("{property}: missing on Fake tier (TrySet soft skip)");
            self.records.push(FakePropRecord {
                property: property.to_string(),
                value: value.to_string(),
                outcome: FakePropOutcome::SoftSkipped,
            });
            return FakePropPut::SoftSkipped {
                property: property.to_string(),
                detail,
            };
        }
        self.records.push(FakePropRecord {
            property: property.to_string(),
            value: value.to_string(),
            outcome: FakePropOutcome::Applied,
        });
        FakePropPut::Applied
    }
}

/// Layout / monitor fallbacks for [`resolve_connect_desktop_size`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DesktopSizeContext {
    /// Embedded surface width in physical px (0 = unknown / seed).
    pub initial_surface_width: i32,
    /// Embedded surface height in physical px (0 = unknown / seed).
    pub initial_surface_height: i32,
    /// Owner-monitor working-area width fallback.
    pub fallback_width: i32,
    /// Owner-monitor working-area height fallback.
    pub fallback_height: i32,
}

impl Default for DesktopSizeContext {
    fn default() -> Self {
        Self {
            initial_surface_width: 0,
            initial_surface_height: 0,
            fallback_width: 1920,
            fallback_height: 1080,
        }
    }
}

impl DesktopSizeContext {
    /// Surface already measured; use as full-connection-content size.
    pub const fn with_surface(width: i32, height: i32) -> Self {
        Self {
            initial_surface_width: width,
            initial_surface_height: height,
            fallback_width: 1920,
            fallback_height: 1080,
        }
    }
}

/// Maps [`ConnectionProfile`] RDP display + common redirects onto a Fake configure surface.
#[derive(Debug, Default)]
pub struct RdpDisplayRedirectGlue {
    surface: FakeRdpPropertySurface,
}

impl RdpDisplayRedirectGlue {
    /// Glue with an empty Fake surface.
    pub fn with_fake() -> Self {
        Self {
            surface: FakeRdpPropertySurface::new(),
        }
    }

    /// Wrap an existing Fake (tests / scripted misses).
    pub fn new(surface: FakeRdpPropertySurface) -> Self {
        Self { surface }
    }

    /// Borrow the Fake surface.
    pub fn surface(&self) -> &FakeRdpPropertySurface {
        &self.surface
    }

    /// Mutably borrow the Fake surface.
    pub fn surface_mut(&mut self) -> &mut FakeRdpPropertySurface {
        &mut self.surface
    }

    /// Apply display + common redirect properties from `profile` (no OCX / no CredSSP).
    ///
    /// Loud desktop axes are resolved via [`resolve_connect_desktop_size`] then
    /// fail-closed by [`validate_desktop_axes`]. Soft props soft-skip when the Fake
    /// scripts a miss (TrySetOptional parity).
    pub fn apply_from_profile(
        &mut self,
        profile: &ConnectionProfile,
        ctx: DesktopSizeContext,
    ) -> Result<DisplayRedirectReport, DisplayRedirectGlueError> {
        let (width, height) = resolve_connect_desktop_size(
            profile.rdp_screen_size.as_deref(),
            ctx.initial_surface_width,
            ctx.initial_surface_height,
            ctx.fallback_width,
            ctx.fallback_height,
        );
        validate_desktop_axes(width, height)?;

        let color = normalise_color_depth(profile.rdp_color_depth);
        let mut report = DisplayRedirectReport {
            desktop_width: width,
            desktop_height: height,
            color_depth: color,
            redirect_drives: parse_redirect_drives(&profile.rdp_redirect_drives),
            ..DisplayRedirectReport::default()
        };

        // --- Loud display ---
        self.record_loud(&mut report, "DesktopWidth", width)?;
        self.record_loud(&mut report, "DesktopHeight", height)?;
        self.record_loud(&mut report, "ColorDepth", color)?;

        // --- Soft display ---
        self.record_soft(&mut report, "SmartSizing", true);
        self.record_soft(&mut report, "UseMultimon", profile.rdp_use_all_monitors);

        // --- Soft common redirects ---
        self.record_soft(
            &mut report,
            "RedirectClipboard",
            profile.rdp_redirect_clipboard,
        );
        self.record_soft(
            &mut report,
            "RedirectPrinters",
            profile.rdp_redirect_printers,
        );
        self.record_soft(
            &mut report,
            "RedirectSmartCards",
            profile.rdp_redirect_smart_cards,
        );
        self.record_soft(&mut report, "RedirectPorts", profile.rdp_redirect_ports);
        self.record_soft(
            &mut report,
            "RedirectDevices",
            profile.rdp_redirect_devices,
        );

        let (master, collection) = self.surface.try_put_drives(&report.redirect_drives);
        push_soft_outcome(&mut report, "RedirectDrives", master);
        if let Some(c) = collection {
            push_soft_outcome(&mut report, "DriveCollection", c);
        }
        // Effective master after soft-miss / least-privilege force-off (not raw intent).
        report.redirect_drives_master =
            self.surface.last_applied_value("RedirectDrives") == Some("true");

        Ok(report)
    }

    fn record_loud(
        &mut self,
        report: &mut DisplayRedirectReport,
        property: &str,
        value: i32,
    ) -> Result<(), DisplayRedirectGlueError> {
        self.surface.put_loud_i4(property, value)?;
        report.loud_applied.push(property.to_string());
        Ok(())
    }

    fn record_soft(&mut self, report: &mut DisplayRedirectReport, property: &str, value: bool) {
        let outcome = self.surface.try_put_bool(property, value);
        push_soft_outcome(report, property, outcome);
    }
}

fn push_soft_outcome(report: &mut DisplayRedirectReport, property: &str, outcome: FakePropPut) {
    match outcome {
        FakePropPut::Applied => report.soft_applied.push(property.to_string()),
        FakePropPut::SoftSkipped { detail, .. } => report.soft_skips.push(detail),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rdp_profile() -> ConnectionProfile {
        let mut p = ConnectionProfile::default();
        p.protocol = wormhole_domain::ProtocolType::Rdp;
        p.host = "dc.local".into();
        p.port = 3389;
        p.rdp_screen_size = Some("1024x768".into());
        p.rdp_color_depth = 32;
        p.rdp_use_all_monitors = true;
        p.rdp_redirect_clipboard = true;
        p.rdp_redirect_printers = true;
        p.rdp_redirect_smart_cards = false;
        p.rdp_redirect_ports = false;
        p.rdp_redirect_devices = true;
        p.rdp_redirect_drives = "C,D".into();
        p
    }

    #[test]
    fn resolve_fixed_size_and_defaults() {
        assert_eq!(
            resolve_connect_desktop_size(Some("1024x768"), 0, 0, 1920, 1080),
            (1024, 768)
        );
        assert_eq!(
            resolve_connect_desktop_size(Some("50x50"), 0, 0, 1920, 1080),
            (DESKTOP_DEFAULT_WIDTH, DESKTOP_DEFAULT_HEIGHT)
        );
        assert_eq!(
            resolve_connect_desktop_size(Some("bogus"), 0, 0, 1920, 1080),
            (DESKTOP_DEFAULT_WIDTH, DESKTOP_DEFAULT_HEIGHT)
        );
        assert_eq!(
            resolve_connect_desktop_size(Some("1024x768x32"), 0, 0, 1920, 1080),
            (DESKTOP_DEFAULT_WIDTH, DESKTOP_DEFAULT_HEIGHT)
        );
    }

    #[test]
    fn resolve_full_connection_content_uses_surface_or_fallback() {
        assert_eq!(
            resolve_connect_desktop_size(None, 900, 700, 1920, 1080),
            (900, 700)
        );
        // Below minimum → clamp up.
        assert_eq!(
            resolve_connect_desktop_size(
                Some(RdpScreenSizes::FULL_CONNECTION_CONTENT),
                100,
                100,
                1920,
                1080
            ),
            (DESKTOP_MIN_WIDTH, DESKTOP_MIN_HEIGHT)
        );
        // Unknown surface → fallback (clamped).
        assert_eq!(
            resolve_connect_desktop_size(Some(""), 0, 0, 800, 600),
            (800, 600)
        );
        assert_eq!(
            resolve_connect_desktop_size(
                Some(RdpScreenSizes::LEGACY_FULL_SCREEN_SENTINEL),
                0,
                0,
                100,
                100
            ),
            (DESKTOP_MIN_WIDTH, DESKTOP_MIN_HEIGHT)
        );
        // mRemoteNG FitToWindow alias; one non-positive axis → fallback (C# both > 0).
        assert_eq!(
            resolve_connect_desktop_size(
                Some(RdpScreenSizes::M_REMOTE_NG_FIT_TO_WINDOW_SENTINEL),
                900,
                0,
                1280,
                1024
            ),
            (1280, 1024)
        );
    }

    #[test]
    fn validate_desktop_axes_fail_closed() {
        assert!(validate_desktop_axes(1024, 768).is_ok());
        assert!(validate_desktop_axes(0, 768).is_err());
        assert!(validate_desktop_axes(1024, -1).is_err());
        let err = validate_desktop_axes(MAX_DESKTOP_AXIS + 1, 768).expect_err("max");
        assert!(err.message().contains("maximum"));
        assert!(validate_desktop_axes(MAX_DESKTOP_AXIS, MAX_DESKTOP_AXIS).is_ok());
    }

    #[test]
    fn hostile_fixed_size_over_max_axis_fail_closed() {
        let mut p = rdp_profile();
        p.rdp_screen_size = Some(format!("{}x{}", MAX_DESKTOP_AXIS + 1, 768));
        let mut glue = RdpDisplayRedirectGlue::with_fake();
        let err = glue
            .apply_from_profile(&p, DesktopSizeContext::default())
            .expect_err("hostile size");
        assert!(err.message().contains("maximum"));
        assert_eq!(glue.surface().applied_count(), 0);
    }

    #[test]
    fn hostile_full_content_surface_or_fallback_over_max_fail_closed() {
        let mut p = rdp_profile();
        p.rdp_screen_size = Some(RdpScreenSizes::FULL_CONNECTION_CONTENT.into());
        let mut glue = RdpDisplayRedirectGlue::with_fake();
        let err = glue
            .apply_from_profile(
                &p,
                DesktopSizeContext {
                    initial_surface_width: MAX_DESKTOP_AXIS + 1,
                    initial_surface_height: 768,
                    fallback_width: 1920,
                    fallback_height: 1080,
                },
            )
            .expect_err("hostile surface");
        assert!(err.message().contains("maximum"));
        assert_eq!(glue.surface().applied_count(), 0);

        glue.surface_mut().clear_records();
        let err = glue
            .apply_from_profile(
                &p,
                DesktopSizeContext {
                    initial_surface_width: 0,
                    initial_surface_height: 0,
                    fallback_width: MAX_DESKTOP_AXIS + 1,
                    fallback_height: 1080,
                },
            )
            .expect_err("hostile fallback");
        assert!(err.message().contains("maximum"));
        assert_eq!(glue.surface().applied_count(), 0);
    }

    #[test]
    fn apply_maps_display_and_redirects() {
        let mut glue = RdpDisplayRedirectGlue::with_fake();
        let report = glue
            .apply_from_profile(&rdp_profile(), DesktopSizeContext::default())
            .expect("apply");
        assert_eq!(report.desktop_width, 1024);
        assert_eq!(report.desktop_height, 768);
        assert_eq!(report.color_depth, 32);
        assert!(report.redirect_drives_master);
        assert_eq!(
            glue.surface().last_applied_value("DesktopWidth"),
            Some("1024")
        );
        assert_eq!(
            glue.surface().last_applied_value("UseMultimon"),
            Some("true")
        );
        assert_eq!(
            glue.surface().last_applied_value("RedirectClipboard"),
            Some("true")
        );
        assert_eq!(
            glue.surface().last_applied_value("RedirectDevices"),
            Some("true")
        );
        assert_eq!(
            glue.surface().last_applied_value("RedirectDrives"),
            Some("true")
        );
        assert_eq!(
            glue.surface().last_applied_value("DriveCollection"),
            Some("CD")
        );
        assert!(report.all_soft_applied());
        assert_eq!(report.loud_applied, LOUD_DISPLAY_PROPS);
        // Every soft catalog name is attempted for a custom-letter profile.
        for name in SOFT_DISPLAY_REDIRECT_PROPS {
            assert!(
                report.soft_applied.iter().any(|p| p == name),
                "soft catalog prop {name} not applied"
            );
        }
    }

    #[test]
    fn color_depth_normalised_via_existing_helper() {
        let mut p = rdp_profile();
        p.rdp_color_depth = 99; // → 32
        let mut glue = RdpDisplayRedirectGlue::with_fake();
        let report = glue
            .apply_from_profile(&p, DesktopSizeContext::default())
            .expect("apply");
        assert_eq!(report.color_depth, 32);
        assert_eq!(
            glue.surface().last_applied_value("ColorDepth"),
            Some("32")
        );
    }

    #[test]
    fn soft_miss_tryset_skips_without_err() {
        let mut surface = FakeRdpPropertySurface::new();
        surface.soft_miss_prop("RedirectDevices");
        surface.soft_miss_prop("UseMultimon");
        let mut glue = RdpDisplayRedirectGlue::new(surface);
        let report = glue
            .apply_from_profile(&rdp_profile(), DesktopSizeContext::default())
            .expect("soft miss is Ok");
        assert!(!report.all_soft_applied());
        assert!(report
            .soft_skips
            .iter()
            .any(|s| s.contains("RedirectDevices")));
        assert!(report.soft_skips.iter().any(|s| s.contains("UseMultimon")));
        // Loud props still applied.
        assert_eq!(
            glue.surface().last_applied_value("DesktopWidth"),
            Some("1024")
        );
        assert!(glue.surface().soft_skip_count() >= 2);
        assert!(report.redirect_drives_master);
    }

    #[test]
    fn drive_collection_soft_miss_forces_master_off() {
        let mut surface = FakeRdpPropertySurface::new();
        surface.soft_miss_prop("DriveCollection");
        let mut glue = RdpDisplayRedirectGlue::new(surface);
        let report = glue
            .apply_from_profile(&rdp_profile(), DesktopSizeContext::default())
            .expect("ok");
        assert!(report
            .soft_skips
            .iter()
            .any(|s| s.starts_with("DriveCollection:")));
        assert_eq!(
            glue.surface().last_applied_value("RedirectDrives"),
            Some("false"),
            "least-privilege: custom letters without DriveCollection → master off"
        );
        assert!(
            !report.redirect_drives_master,
            "report must reflect final master=false, not initial true put"
        );
        // Final master put (false) still counts as soft-applied; value is false.
        assert!(report.soft_applied.iter().any(|p| p == "RedirectDrives"));
        assert!(matches!(
            report.redirect_drives,
            RedirectDrivesIntent::Letters(_)
        ));
    }

    #[test]
    fn redirect_drives_master_soft_miss_skips_drive_collection() {
        let mut surface = FakeRdpPropertySurface::new();
        surface.soft_miss_prop("RedirectDrives");
        let mut glue = RdpDisplayRedirectGlue::new(surface);
        let report = glue
            .apply_from_profile(&rdp_profile(), DesktopSizeContext::default())
            .expect("ok");
        assert!(report
            .soft_skips
            .iter()
            .any(|s| s.starts_with("RedirectDrives:")));
        assert!(
            glue.surface()
                .last_applied_value("DriveCollection")
                .is_none(),
            "no DriveCollection filter without an applied RedirectDrives master"
        );
        assert!(!report.redirect_drives_master);
        assert!(!report.soft_applied.iter().any(|p| p == "DriveCollection"));
    }

    #[test]
    fn redirect_drives_all_and_none() {
        let mut p = rdp_profile();
        p.rdp_redirect_drives = "all".into();
        let mut glue = RdpDisplayRedirectGlue::with_fake();
        let report = glue
            .apply_from_profile(&p, DesktopSizeContext::default())
            .expect("all");
        assert_eq!(report.redirect_drives, RedirectDrivesIntent::All);
        assert!(report.redirect_drives_master);
        assert_eq!(
            glue.surface().last_applied_value("RedirectDrives"),
            Some("true")
        );
        assert!(glue
            .surface()
            .last_applied_value("DriveCollection")
            .is_none());

        p.rdp_redirect_drives = String::new();
        glue.surface_mut().clear_records();
        let report = glue
            .apply_from_profile(&p, DesktopSizeContext::default())
            .expect("none");
        assert_eq!(report.redirect_drives, RedirectDrivesIntent::None);
        assert!(!report.redirect_drives_master);
        assert_eq!(
            glue.surface().last_applied_value("RedirectDrives"),
            Some("false")
        );
    }

    #[test]
    fn loud_fake_fail_stops_before_soft() {
        let mut surface = FakeRdpPropertySurface::new();
        surface.fail_loud("ColorDepth", "scripted ColorDepth failure");
        let mut glue = RdpDisplayRedirectGlue::new(surface);
        let err = glue
            .apply_from_profile(&rdp_profile(), DesktopSizeContext::default())
            .expect_err("loud");
        assert!(err.message().contains("ColorDepth"));
        // DesktopWidth/Height applied before ColorDepth; no soft redirects.
        assert!(glue
            .surface()
            .last_applied_value("RedirectClipboard")
            .is_none());
        assert_eq!(
            glue.surface().last_applied_value("DesktopWidth"),
            Some("1024")
        );
    }

    #[test]
    fn soft_prop_catalog_documents_tryset_set() {
        for name in SOFT_DISPLAY_REDIRECT_PROPS {
            assert!(!name.is_empty());
        }
        for name in LOUD_DISPLAY_PROPS {
            assert!(!SOFT_DISPLAY_REDIRECT_PROPS.contains(name));
        }
    }

    #[test]
    fn parse_redirect_drives_drops_junk_tokens() {
        assert_eq!(
            parse_redirect_drives("C, xx, D, 1"),
            RedirectDrivesIntent::Letters(BTreeSet::from(['C', 'D']))
        );
        assert_eq!(
            parse_redirect_drives("c;d"),
            RedirectDrivesIntent::Letters(BTreeSet::from(['C', 'D']))
        );
        assert_eq!(parse_redirect_drives("  "), RedirectDrivesIntent::None);
        assert_eq!(parse_redirect_drives("ALL"), RedirectDrivesIntent::All);
        // Whitespace around sentinel is not "all" (C# OrdinalIgnoreCase on raw) → junk → None.
        assert_eq!(parse_redirect_drives(" all "), RedirectDrivesIntent::None);
    }
}
