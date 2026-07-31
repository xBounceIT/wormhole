//! ConnectionProfile RDP performance flags + bitmap cache → Fake configure (no OCX).
//!
//! Thin glue mirroring the experience subset of C# `RdpHostForm.Configure`:
//! - **Soft** (TrySet-style skip): `PerformanceFlags` (from [`build_performance_flags`]),
//!   `BitmapCachePersistEnable`, and legacy typo `BitmapPeristence` (0/1).
//! - **Loud / fail-closed:** none in this subset — C# applies these via
//!   `TrySetOptional` only. Existing configure validators (`validate_desktop_axes`,
//!   CredSSP input checks, tunnel policy) live elsewhere and are not invoked here.
//!
//! Does **not** touch CredSSP / password wipe, display/redirect Fake glue, audio,
//! keyboard-hook, gateway, `NetworkConnectionType`, or live `mstscax`. Soft skips
//! are recorded on [`PerformanceFlagsReport`] — never hard-`Err`.

use std::collections::BTreeSet;
use std::fmt;

use wormhole_domain::ConnectionProfile;

/// Soft / TrySet-style property names applied by this glue (documented skip set).
pub const SOFT_PERFORMANCE_PROPS: &[&str] = &[
    "PerformanceFlags",
    "BitmapCachePersistEnable",
    "BitmapPeristence",
];

/// TS_PERF_DISABLE_WALLPAPER (`IMsRdpClientAdvancedSettings`).
pub const TS_PERF_DISABLE_WALLPAPER: u32 = 0x01;
/// TS_PERF_DISABLE_FULLWINDOWDRAG.
pub const TS_PERF_DISABLE_FULLWINDOWDRAG: u32 = 0x02;
/// TS_PERF_DISABLE_MENUANIMATIONS.
pub const TS_PERF_DISABLE_MENUANIMATIONS: u32 = 0x04;
/// TS_PERF_DISABLE_THEMING.
pub const TS_PERF_DISABLE_THEMING: u32 = 0x08;
/// TS_PERF_DISABLE_CURSOR_SHADOW.
pub const TS_PERF_DISABLE_CURSOR_SHADOW: u32 = 0x20;
/// TS_PERF_DISABLE_CURSORSETTINGS.
pub const TS_PERF_DISABLE_CURSORSETTINGS: u32 = 0x40;
/// TS_PERF_ENABLE_FONT_SMOOTHING.
pub const TS_PERF_ENABLE_FONT_SMOOTHING: u32 = 0x80;
/// TS_PERF_ENABLE_DESKTOP_COMPOSITION.
pub const TS_PERF_ENABLE_DESKTOP_COMPOSITION: u32 = 0x100;

/// Visual-styles off also disables cursor shadow + cursor settings (C# packing).
pub const TS_PERF_VISUAL_STYLES_OFF_MASK: u32 =
    TS_PERF_DISABLE_THEMING | TS_PERF_DISABLE_CURSOR_SHADOW | TS_PERF_DISABLE_CURSORSETTINGS;

/// Outcome of one Fake property put.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FakePerfPropPut {
    /// Property was recorded on the Fake.
    Applied,
    /// Name unknown / scripted missing — TrySet-style soft skip.
    SoftSkipped {
        /// Property name that was soft-skipped.
        property: String,
        /// Human-readable miss detail (for [`PerformanceFlagsReport::soft_skips`]).
        detail: String,
    },
}

/// Errors from performance Fake glue — never carry secrets.
///
/// This module currently never returns `Err` (all puts are soft). The type exists
/// for API parity with sister Fake glues and for future fail-closed hooks that
/// reuse existing validators.
#[derive(Clone, PartialEq, Eq)]
pub struct PerformanceFlagsGlueError {
    message: String,
}

impl PerformanceFlagsGlueError {
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

impl fmt::Debug for PerformanceFlagsGlueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PerformanceFlagsGlueError")
            .field("message", &self.message)
            .finish()
    }
}

impl fmt::Display for PerformanceFlagsGlueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for PerformanceFlagsGlueError {}

impl From<windows::core::Error> for PerformanceFlagsGlueError {
    fn from(value: windows::core::Error) -> Self {
        Self::new(value.message())
    }
}

/// Soft-apply summary for one Fake performance configure pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PerformanceFlagsReport {
    /// Human-readable soft-skip details (missing optional props).
    pub soft_skips: Vec<String>,
    /// Soft puts that applied.
    pub soft_applied: Vec<String>,
    /// Bitmask from [`build_performance_flags`] (attempted value, even if soft-skipped).
    pub performance_flags: u32,
    /// Profile `rdp_bitmap_caching` (attempted value).
    pub bitmap_caching: bool,
}

impl PerformanceFlagsReport {
    /// True when every soft setter applied (or was not attempted).
    pub fn all_soft_applied(&self) -> bool {
        self.soft_skips.is_empty()
    }
}

/// Pure C# `RdpHostForm.BuildPerformanceFlags` — disable bits when features are off;
/// enable bits when font smoothing / desktop composition are on.
pub fn build_performance_flags(profile: &ConnectionProfile) -> u32 {
    let mut flags = 0u32;
    if !profile.rdp_desktop_background {
        flags |= TS_PERF_DISABLE_WALLPAPER;
    }
    if !profile.rdp_window_drag {
        flags |= TS_PERF_DISABLE_FULLWINDOWDRAG;
    }
    if !profile.rdp_menu_animation {
        flags |= TS_PERF_DISABLE_MENUANIMATIONS;
    }
    if !profile.rdp_visual_styles {
        flags |= TS_PERF_VISUAL_STYLES_OFF_MASK;
    }
    if profile.rdp_font_smoothing {
        flags |= TS_PERF_ENABLE_FONT_SMOOTHING;
    }
    if profile.rdp_desktop_composition {
        flags |= TS_PERF_ENABLE_DESKTOP_COMPOSITION;
    }
    flags
}

/// One Fake IDispatch-shaped put record (tests / diagnostics).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakePerfPropRecord {
    /// Property name (`PerformanceFlags`, `BitmapCachePersistEnable`, …).
    pub property: String,
    /// Stringified value (u32 / bool / 0|1) — never a password.
    pub value: String,
    /// Whether the put applied or soft-skipped.
    pub outcome: FakePerfPropOutcome,
}

/// Applied vs soft-skipped (mirrors TrySetOptional swallow).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FakePerfPropOutcome {
    /// Recorded on the Fake.
    Applied,
    /// Unknown / scripted missing.
    SoftSkipped,
}

/// Stand-in for MsRdpClient performance / bitmap-cache configure puts (no COM / `mstscax`).
///
/// Scripted soft-miss names TrySet-skip; other names record as Applied. Does **not**
/// retain credentials. Does **not** share state with display/redirect or CredSSP Fakes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeRdpPerformanceSurface {
    records: Vec<FakePerfPropRecord>,
    /// Property names that soft-skip (TrySet miss). Default: empty (all known apply).
    soft_miss: BTreeSet<String>,
}

impl Default for FakeRdpPerformanceSurface {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeRdpPerformanceSurface {
    /// Empty Fake (no puts yet).
    pub const fn new() -> Self {
        Self {
            records: Vec::new(),
            soft_miss: BTreeSet::new(),
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

    /// All put records in order.
    pub fn records(&self) -> &[FakePerfPropRecord] {
        &self.records
    }

    /// Number of applied puts.
    pub fn applied_count(&self) -> usize {
        self.records
            .iter()
            .filter(|r| r.outcome == FakePerfPropOutcome::Applied)
            .count()
    }

    /// Number of soft-skipped puts.
    pub fn soft_skip_count(&self) -> usize {
        self.records
            .iter()
            .filter(|r| r.outcome == FakePerfPropOutcome::SoftSkipped)
            .count()
    }

    /// Last recorded value for `property` (applied only).
    pub fn last_applied_value(&self, property: &str) -> Option<&str> {
        self.records
            .iter()
            .rev()
            .find(|r| r.property == property && r.outcome == FakePerfPropOutcome::Applied)
            .map(|r| r.value.as_str())
    }

    /// Clear recorded puts (keeps miss scripts).
    pub fn clear_records(&mut self) {
        self.records.clear();
    }

    fn try_put(&mut self, property: &str, value: String) -> FakePerfPropPut {
        if self.soft_miss.contains(property) {
            let detail = format!("{property}: missing on Fake tier (TrySet soft skip)");
            self.records.push(FakePerfPropRecord {
                property: property.to_string(),
                value,
                outcome: FakePerfPropOutcome::SoftSkipped,
            });
            return FakePerfPropPut::SoftSkipped {
                property: property.to_string(),
                detail,
            };
        }
        self.records.push(FakePerfPropRecord {
            property: property.to_string(),
            value,
            outcome: FakePerfPropOutcome::Applied,
        });
        FakePerfPropPut::Applied
    }
}

/// Maps [`ConnectionProfile`] RDP performance + bitmap-cache flags onto a Fake surface.
#[derive(Debug, Default)]
pub struct RdpPerformanceFlagsGlue {
    surface: FakeRdpPerformanceSurface,
}

impl RdpPerformanceFlagsGlue {
    /// Glue with an empty Fake surface.
    pub fn with_fake() -> Self {
        Self {
            surface: FakeRdpPerformanceSurface::new(),
        }
    }

    /// Wrap an existing Fake (tests / scripted misses).
    pub fn new(surface: FakeRdpPerformanceSurface) -> Self {
        Self { surface }
    }

    /// Borrow the Fake surface.
    pub fn surface(&self) -> &FakeRdpPerformanceSurface {
        &self.surface
    }

    /// Mutably borrow the Fake surface.
    pub fn surface_mut(&mut self) -> &mut FakeRdpPerformanceSurface {
        &mut self.surface
    }

    /// Apply performance + bitmap-cache properties from `profile` (no OCX / no CredSSP).
    ///
    /// Always `Ok` today — every property is soft TrySet. The `Result` mirrors sister
    /// Fake glues and reserves room for fail-closed hooks that reuse existing validators.
    pub fn apply_from_profile(
        &mut self,
        profile: &ConnectionProfile,
    ) -> Result<PerformanceFlagsReport, PerformanceFlagsGlueError> {
        let flags = build_performance_flags(profile);
        let bitmap = profile.rdp_bitmap_caching;
        let mut report = PerformanceFlagsReport {
            performance_flags: flags,
            bitmap_caching: bitmap,
            ..PerformanceFlagsReport::default()
        };

        // C# order: PerformanceFlags → BitmapCachePersistEnable → BitmapPeristence.
        self.record_soft(&mut report, "PerformanceFlags", flags.to_string());
        self.record_soft(
            &mut report,
            "BitmapCachePersistEnable",
            bitmap.to_string(),
        );
        // Legacy typo name (single 'r') — independent TrySet; still attempted after modern.
        self.record_soft(
            &mut report,
            "BitmapPeristence",
            if bitmap { "1" } else { "0" }.to_string(),
        );

        Ok(report)
    }

    fn record_soft(
        &mut self,
        report: &mut PerformanceFlagsReport,
        property: &str,
        value: String,
    ) {
        let outcome = self.surface.try_put(property, value);
        push_soft_outcome(report, property, outcome);
    }
}

fn push_soft_outcome(
    report: &mut PerformanceFlagsReport,
    property: &str,
    outcome: FakePerfPropPut,
) {
    match outcome {
        FakePerfPropPut::Applied => report.soft_applied.push(property.to_string()),
        FakePerfPropPut::SoftSkipped { detail, .. } => report.soft_skips.push(detail),
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
        // Defaults: experience features on → enable bits only.
        p.rdp_desktop_background = true;
        p.rdp_window_drag = true;
        p.rdp_menu_animation = true;
        p.rdp_visual_styles = true;
        p.rdp_font_smoothing = true;
        p.rdp_desktop_composition = true;
        p.rdp_bitmap_caching = true;
        p
    }

    #[test]
    fn build_flags_defaults_enable_bits_only() {
        let flags = build_performance_flags(&rdp_profile());
        assert_eq!(
            flags,
            TS_PERF_ENABLE_FONT_SMOOTHING | TS_PERF_ENABLE_DESKTOP_COMPOSITION
        );
        assert_eq!(flags, 0x180);
    }

    #[test]
    fn build_flags_all_experience_off() {
        let mut p = rdp_profile();
        p.rdp_desktop_background = false;
        p.rdp_window_drag = false;
        p.rdp_menu_animation = false;
        p.rdp_visual_styles = false;
        p.rdp_font_smoothing = false;
        p.rdp_desktop_composition = false;
        let flags = build_performance_flags(&p);
        assert_eq!(
            flags,
            TS_PERF_DISABLE_WALLPAPER
                | TS_PERF_DISABLE_FULLWINDOWDRAG
                | TS_PERF_DISABLE_MENUANIMATIONS
                | TS_PERF_VISUAL_STYLES_OFF_MASK
        );
        assert_eq!(flags, 0x6F);
        assert_eq!(
            flags & TS_PERF_VISUAL_STYLES_OFF_MASK,
            TS_PERF_VISUAL_STYLES_OFF_MASK
        );
        assert_eq!(flags & TS_PERF_ENABLE_FONT_SMOOTHING, 0);
        assert_eq!(flags & TS_PERF_ENABLE_DESKTOP_COMPOSITION, 0);
    }

    #[test]
    fn build_flags_visual_styles_packs_three_disable_bits() {
        let mut p = rdp_profile();
        p.rdp_visual_styles = false;
        let flags = build_performance_flags(&p);
        assert_eq!(
            flags & TS_PERF_VISUAL_STYLES_OFF_MASK,
            TS_PERF_VISUAL_STYLES_OFF_MASK
        );
        // Enable bits still present when font/composition stay on.
        assert_ne!(flags & TS_PERF_ENABLE_FONT_SMOOTHING, 0);
        assert_ne!(flags & TS_PERF_ENABLE_DESKTOP_COMPOSITION, 0);
    }

    #[test]
    fn build_flags_independent_toggle_bits() {
        let mut p = rdp_profile();
        p.rdp_desktop_background = false;
        assert_ne!(
            build_performance_flags(&p) & TS_PERF_DISABLE_WALLPAPER,
            0
        );
        p.rdp_desktop_background = true;
        p.rdp_window_drag = false;
        assert_ne!(
            build_performance_flags(&p) & TS_PERF_DISABLE_FULLWINDOWDRAG,
            0
        );
        p.rdp_window_drag = true;
        p.rdp_menu_animation = false;
        assert_ne!(
            build_performance_flags(&p) & TS_PERF_DISABLE_MENUANIMATIONS,
            0
        );
        p.rdp_menu_animation = true;
        p.rdp_font_smoothing = false;
        assert_eq!(
            build_performance_flags(&p) & TS_PERF_ENABLE_FONT_SMOOTHING,
            0
        );
        p.rdp_font_smoothing = true;
        p.rdp_desktop_composition = false;
        assert_eq!(
            build_performance_flags(&p) & TS_PERF_ENABLE_DESKTOP_COMPOSITION,
            0
        );
    }

    #[test]
    fn apply_maps_performance_and_bitmap_cache() {
        let mut glue = RdpPerformanceFlagsGlue::with_fake();
        let report = glue.apply_from_profile(&rdp_profile()).expect("apply");
        assert_eq!(report.performance_flags, 0x180);
        assert!(report.bitmap_caching);
        assert_eq!(
            glue.surface().last_applied_value("PerformanceFlags"),
            Some("384") // 0x180 decimal
        );
        assert_eq!(
            glue.surface()
                .last_applied_value("BitmapCachePersistEnable"),
            Some("true")
        );
        assert_eq!(
            glue.surface().last_applied_value("BitmapPeristence"),
            Some("1")
        );
        assert!(report.all_soft_applied());
        assert_eq!(report.soft_applied, SOFT_PERFORMANCE_PROPS);
        // C# order pinned.
        let names: Vec<_> = glue
            .surface()
            .records()
            .iter()
            .map(|r| r.property.as_str())
            .collect();
        assert_eq!(
            names,
            vec![
                "PerformanceFlags",
                "BitmapCachePersistEnable",
                "BitmapPeristence"
            ]
        );
    }

    #[test]
    fn apply_bitmap_caching_off_writes_zero_legacy() {
        let mut p = rdp_profile();
        p.rdp_bitmap_caching = false;
        let mut glue = RdpPerformanceFlagsGlue::with_fake();
        let report = glue.apply_from_profile(&p).expect("apply");
        assert!(!report.bitmap_caching);
        assert_eq!(
            glue.surface()
                .last_applied_value("BitmapCachePersistEnable"),
            Some("false")
        );
        assert_eq!(
            glue.surface().last_applied_value("BitmapPeristence"),
            Some("0")
        );
    }

    #[test]
    fn soft_miss_tryset_skips_without_err() {
        let mut surface = FakeRdpPerformanceSurface::new();
        surface.soft_miss_prop("PerformanceFlags");
        surface.soft_miss_prop("BitmapPeristence");
        let mut glue = RdpPerformanceFlagsGlue::new(surface);
        let report = glue
            .apply_from_profile(&rdp_profile())
            .expect("soft miss is Ok");
        assert!(!report.all_soft_applied());
        assert!(report
            .soft_skips
            .iter()
            .any(|s| s.contains("PerformanceFlags")));
        assert!(report
            .soft_skips
            .iter()
            .any(|s| s.contains("BitmapPeristence")));
        // Modern bitmap prop still applied; report still carries computed flags.
        assert_eq!(
            glue.surface()
                .last_applied_value("BitmapCachePersistEnable"),
            Some("true")
        );
        assert_eq!(report.performance_flags, 0x180);
        assert!(glue.surface().soft_skip_count() >= 2);
        assert_eq!(glue.surface().applied_count(), 1);
    }

    #[test]
    fn modern_bitmap_soft_miss_still_attempts_legacy() {
        // C# tries both independently — modern miss must not suppress legacy put.
        let mut surface = FakeRdpPerformanceSurface::new();
        surface.soft_miss_prop("BitmapCachePersistEnable");
        let mut glue = RdpPerformanceFlagsGlue::new(surface);
        let report = glue.apply_from_profile(&rdp_profile()).expect("ok");
        assert!(report
            .soft_skips
            .iter()
            .any(|s| s.starts_with("BitmapCachePersistEnable:")));
        assert_eq!(
            glue.surface().last_applied_value("BitmapPeristence"),
            Some("1")
        );
        assert!(report.soft_applied.iter().any(|p| p == "BitmapPeristence"));
        assert!(report
            .soft_applied
            .iter()
            .any(|p| p == "PerformanceFlags"));
    }

    #[test]
    fn all_soft_miss_still_ok_with_attempted_report_values() {
        // Attack: every TrySet miss — must remain Ok; report carries attempted bitmask/bool.
        let mut surface = FakeRdpPerformanceSurface::new();
        for name in SOFT_PERFORMANCE_PROPS {
            surface.soft_miss_prop(*name);
        }
        let mut glue = RdpPerformanceFlagsGlue::new(surface);
        let report = glue.apply_from_profile(&rdp_profile()).expect("all soft");
        assert!(!report.all_soft_applied());
        assert_eq!(report.soft_skips.len(), 3);
        assert!(report.soft_applied.is_empty());
        assert_eq!(report.performance_flags, 0x180);
        assert!(report.bitmap_caching);
        assert_eq!(glue.surface().applied_count(), 0);
        assert_eq!(glue.surface().soft_skip_count(), 3);
        assert!(glue
            .surface()
            .last_applied_value("PerformanceFlags")
            .is_none());
    }

    #[test]
    fn reapply_appends_records_unless_cleared() {
        // Sister Fake contract: apply does not auto-clear; callers clear_records.
        let mut glue = RdpPerformanceFlagsGlue::with_fake();
        let _ = glue.apply_from_profile(&rdp_profile()).expect("1");
        let _ = glue.apply_from_profile(&rdp_profile()).expect("2");
        assert_eq!(glue.surface().records().len(), 6);
        glue.surface_mut().clear_records();
        let report = glue.apply_from_profile(&rdp_profile()).expect("3");
        assert_eq!(glue.surface().records().len(), 3);
        assert!(report.all_soft_applied());
    }

    #[test]
    fn soft_prop_catalog_documents_tryset_set() {
        for name in SOFT_PERFORMANCE_PROPS {
            assert!(!name.is_empty());
        }
        assert_eq!(SOFT_PERFORMANCE_PROPS.len(), 3);
        // Typo name is intentional (C# AdvSettings5 fallback).
        assert!(SOFT_PERFORMANCE_PROPS.contains(&"BitmapPeristence"));
        assert!(!SOFT_PERFORMANCE_PROPS.contains(&"BitmapPersistence"));
    }

    #[test]
    fn apply_hostile_experience_combo_still_ok() {
        // No loud validator in this subset — extreme bool combos must soft-apply.
        let mut p = rdp_profile();
        p.rdp_desktop_background = false;
        p.rdp_visual_styles = false;
        p.rdp_font_smoothing = false;
        p.rdp_bitmap_caching = false;
        let mut glue = RdpPerformanceFlagsGlue::with_fake();
        let report = glue.apply_from_profile(&p).expect("no fail-closed");
        assert_eq!(
            report.performance_flags,
            TS_PERF_DISABLE_WALLPAPER
                | TS_PERF_VISUAL_STYLES_OFF_MASK
                | TS_PERF_ENABLE_DESKTOP_COMPOSITION
        );
        let flags_str = report.performance_flags.to_string();
        assert_eq!(
            glue.surface().last_applied_value("PerformanceFlags"),
            Some(flags_str.as_str())
        );
        assert_eq!(
            glue.surface().last_applied_value("BitmapPeristence"),
            Some("0")
        );
        assert!(report.all_soft_applied());
    }

    #[test]
    fn clear_records_keeps_soft_miss_scripts() {
        let mut surface = FakeRdpPerformanceSurface::new();
        surface.soft_miss_prop("PerformanceFlags");
        let mut glue = RdpPerformanceFlagsGlue::new(surface);
        let _ = glue.apply_from_profile(&rdp_profile()).expect("1");
        assert!(glue.surface().soft_skip_count() >= 1);
        glue.surface_mut().clear_records();
        assert_eq!(glue.surface().records().len(), 0);
        let report = glue.apply_from_profile(&rdp_profile()).expect("2");
        assert!(report
            .soft_skips
            .iter()
            .any(|s| s.contains("PerformanceFlags")));
    }

    #[test]
    fn error_display_and_debug_omit_secrets() {
        let err = PerformanceFlagsGlueError::new("perf put failed");
        assert_eq!(err.message(), "perf put failed");
        assert_eq!(format!("{err}"), "perf put failed");
        let dbg = format!("{err:?}");
        assert!(dbg.contains("PerformanceFlagsGlueError"));
        assert!(!dbg.contains("password"));
    }
}
