//! AppSettings font / size / auto-copy → terminal apply glue (Fake; no GPUI).
//!
//! Thin Lab stub: validate the settings-shaped display slice, emit typed apply
//! messages, and record them on [`FakeTerminalSettingsSurface`]. Empty /
//! whitespace-only font family (Unicode `trim` White_Space, including NBSP) and
//! non-positive font size **fail closed** (Fake unchanged). Auto-copy is a
//! host-side policy (C# `TerminalBridge` reads `AutoCopyOnSelect` on each `c:`
//! frame, skips empty / oversize selections) — recorded here for hosts / tests,
//! not pushed as a live WebView2 wire frame yet.
//!
//! **Not** product xterm `term.options` / `ExecuteScript` apply, and **not** on
//! the `d:`/`c:` codec. Defaults mirror C# `AppSettings` (`Cascadia Mono`, 12,
//! auto-copy on).

use std::fmt;

/// C# `AppSettings.DefaultSshFont` default.
pub const DEFAULT_SSH_FONT_FAMILY: &str = "Cascadia Mono";
/// C# `AppSettings.DefaultSshFontSize` default.
pub const DEFAULT_SSH_FONT_SIZE: u32 = 12;

/// Settings-shaped terminal display snapshot (slice of `AppSettings`).
///
/// Construct via [`TerminalSettingsConfig::default`], [`Self::from_parts`], or
/// UI helpers that map `AppSettings` fields. No GPUI / settings chrome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalSettingsConfig {
    pub font_family: String,
    pub font_size: i32,
    pub auto_copy_on_select: bool,
}

impl Default for TerminalSettingsConfig {
    fn default() -> Self {
        Self {
            font_family: DEFAULT_SSH_FONT_FAMILY.into(),
            font_size: DEFAULT_SSH_FONT_SIZE as i32,
            auto_copy_on_select: true,
        }
    }
}

impl TerminalSettingsConfig {
    /// Build from raw AppSettings-shaped fields (font / size / auto-copy).
    pub fn from_parts(
        font_family: impl Into<String>,
        font_size: i32,
        auto_copy_on_select: bool,
    ) -> Self {
        Self {
            font_family: font_family.into(),
            font_size,
            auto_copy_on_select,
        }
    }
}

/// Validated, applied terminal display settings.
///
/// Fields are private so callers cannot bypass [`apply_terminal_settings`].
#[derive(Clone, PartialEq, Eq)]
pub struct AppliedTerminalSettings {
    font_family: String,
    font_size: u32,
    auto_copy_on_select: bool,
}

impl AppliedTerminalSettings {
    pub fn font_family(&self) -> &str {
        &self.font_family
    }

    pub fn font_size(&self) -> u32 {
        self.font_size
    }

    pub fn auto_copy_on_select(&self) -> bool {
        self.auto_copy_on_select
    }
}

impl fmt::Debug for AppliedTerminalSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppliedTerminalSettings")
            .field("font_family", &self.font_family)
            .field("font_size", &self.font_size)
            .field("auto_copy_on_select", &self.auto_copy_on_select)
            .finish()
    }
}

/// Typed Lab apply messages produced by a successful apply.
///
/// Font family / size are host→page intent (future xterm options path). Auto-copy
/// is host policy only (mirrors C# reading settings on `c:` — never auto-sends
/// clipboard into the session).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminalSettingsApplyMessage {
    SetFontFamily { family: String },
    SetFontSize { size: u32 },
    SetAutoCopyOnSelect { enabled: bool },
}

/// Fail-closed validation errors (no Fake mutation).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TerminalSettingsApplyError {
    /// Font family empty or whitespace-only after trim.
    #[error("terminal font family is empty")]
    EmptyFontFamily,
    /// Font size ≤ 0.
    #[error("terminal font size must be positive")]
    NonPositiveFontSize,
}

/// Validate + normalize config → applied settings + apply messages.
///
/// | Input | Behaviour |
/// |---|---|
/// | blank / whitespace font | [`TerminalSettingsApplyError::EmptyFontFamily`] |
/// | `font_size <= 0` | [`TerminalSettingsApplyError::NonPositiveFontSize`] |
/// | ok | trim family; size as `u32`; three apply messages |
pub fn apply_terminal_settings(
    config: TerminalSettingsConfig,
) -> Result<(AppliedTerminalSettings, Vec<TerminalSettingsApplyMessage>), TerminalSettingsApplyError>
{
    let applied = validate_terminal_settings(&config)?;
    let messages = terminal_settings_apply_messages(&applied);
    Ok((applied, messages))
}

/// Validate without building messages (trim family; require positive size).
pub fn validate_terminal_settings(
    config: &TerminalSettingsConfig,
) -> Result<AppliedTerminalSettings, TerminalSettingsApplyError> {
    let font_family = config.font_family.trim();
    if font_family.is_empty() {
        return Err(TerminalSettingsApplyError::EmptyFontFamily);
    }
    if config.font_size <= 0 {
        return Err(TerminalSettingsApplyError::NonPositiveFontSize);
    }
    Ok(AppliedTerminalSettings {
        font_family: font_family.to_string(),
        font_size: config.font_size as u32,
        auto_copy_on_select: config.auto_copy_on_select,
    })
}

/// Build the three Lab apply messages for an already-validated snapshot.
pub fn terminal_settings_apply_messages(
    applied: &AppliedTerminalSettings,
) -> Vec<TerminalSettingsApplyMessage> {
    vec![
        TerminalSettingsApplyMessage::SetFontFamily {
            family: applied.font_family.clone(),
        },
        TerminalSettingsApplyMessage::SetFontSize {
            size: applied.font_size,
        },
        TerminalSettingsApplyMessage::SetAutoCopyOnSelect {
            enabled: applied.auto_copy_on_select,
        },
    ]
}

/// C# `TerminalBridge` auto-copy gate on decoded `c:` selection bytes.
///
/// Mirrors the host-side checks after wire decode: auto-copy enabled, non-empty
/// payload (C# `IsNullOrEmpty` skip), and ≤ [`crate::MAX_SELECTION_UTF8_BYTES`]
/// (C# `MaximumSelectionUtf8Bytes`). Does **not** write the clipboard — hosts /
/// Fake record acceptance only. Never treats selection bytes as a secret in
/// return values.
pub fn accept_selection_auto_copy(applied: &AppliedTerminalSettings, selection_utf8: &[u8]) -> bool {
    applied.auto_copy_on_select
        && !selection_utf8.is_empty()
        && selection_utf8.len() <= crate::MAX_SELECTION_UTF8_BYTES
}

/// In-memory terminal settings apply surface (no WebView2 / GPUI / xterm).
///
/// Failed applies leave prior state untouched. [`Debug`] shows counts / lengths
/// only for selection acceptance — never selection bodies.
#[derive(Clone, Default)]
pub struct FakeTerminalSettingsSurface {
    last: Option<AppliedTerminalSettings>,
    messages: Vec<TerminalSettingsApplyMessage>,
    apply_count: usize,
    /// Accepted auto-copy selection lengths (bodies never stored).
    accepted_selection_lens: Vec<usize>,
}

impl FakeTerminalSettingsSurface {
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply config: validate → record messages + last snapshot. Fail-closed.
    pub fn apply(
        &mut self,
        config: TerminalSettingsConfig,
    ) -> Result<&AppliedTerminalSettings, TerminalSettingsApplyError> {
        let (applied, messages) = apply_terminal_settings(config)?;
        self.messages.extend(messages);
        self.last = Some(applied);
        self.apply_count += 1;
        Ok(self.last.as_ref().expect("just set"))
    }

    /// Gate a page `c:` selection through the last applied auto-copy policy.
    ///
    /// No last apply → reject. Returns whether the selection would be copied.
    pub fn try_auto_copy_selection(&mut self, selection_utf8: &[u8]) -> bool {
        let Some(applied) = self.last.as_ref() else {
            return false;
        };
        if accept_selection_auto_copy(applied, selection_utf8) {
            self.accepted_selection_lens.push(selection_utf8.len());
            true
        } else {
            false
        }
    }

    pub fn last(&self) -> Option<&AppliedTerminalSettings> {
        self.last.as_ref()
    }

    pub fn messages(&self) -> &[TerminalSettingsApplyMessage] {
        &self.messages
    }

    pub fn apply_count(&self) -> usize {
        self.apply_count
    }

    pub fn accepted_selection_count(&self) -> usize {
        self.accepted_selection_lens.len()
    }

    pub fn accepted_selection_lens(&self) -> &[usize] {
        &self.accepted_selection_lens
    }

    pub fn clear(&mut self) {
        *self = Self::default();
    }
}

impl fmt::Debug for FakeTerminalSettingsSurface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeTerminalSettingsSurface")
            .field("apply_count", &self.apply_count)
            .field("message_count", &self.messages.len())
            .field("has_last", &self.last.is_some())
            .field("accepted_selection_count", &self.accepted_selection_lens.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_apply_cascadia_mono_12_auto_copy_on() {
        let (applied, messages) = apply_terminal_settings(TerminalSettingsConfig::default()).unwrap();
        assert_eq!(applied.font_family(), DEFAULT_SSH_FONT_FAMILY);
        assert_eq!(applied.font_size(), DEFAULT_SSH_FONT_SIZE);
        assert!(applied.auto_copy_on_select());
        assert_eq!(
            messages,
            vec![
                TerminalSettingsApplyMessage::SetFontFamily {
                    family: DEFAULT_SSH_FONT_FAMILY.into(),
                },
                TerminalSettingsApplyMessage::SetFontSize {
                    size: DEFAULT_SSH_FONT_SIZE,
                },
                TerminalSettingsApplyMessage::SetAutoCopyOnSelect { enabled: true },
            ]
        );
    }

    #[test]
    fn empty_and_whitespace_font_fail_closed() {
        for family in ["", "   ", "\t\n", "\u{00A0}", "\u{00A0}\u{00A0}"] {
            let err = apply_terminal_settings(TerminalSettingsConfig::from_parts(family, 12, true))
                .unwrap_err();
            assert_eq!(err, TerminalSettingsApplyError::EmptyFontFamily);
        }
    }

    #[test]
    fn non_positive_font_size_fail_closed() {
        for size in [0, -1, i32::MIN] {
            let err = apply_terminal_settings(TerminalSettingsConfig::from_parts(
                "Cascadia Mono",
                size,
                true,
            ))
            .unwrap_err();
            assert_eq!(err, TerminalSettingsApplyError::NonPositiveFontSize);
        }
    }

    #[test]
    fn trims_font_family_on_success() {
        let (applied, _) = apply_terminal_settings(TerminalSettingsConfig::from_parts(
            "  Consolas  ",
            14,
            false,
        ))
        .unwrap();
        assert_eq!(applied.font_family(), "Consolas");
        assert_eq!(applied.font_size(), 14);
        assert!(!applied.auto_copy_on_select());

        // Leading/trailing Unicode White_Space (NBSP) also trimmed.
        let (applied, _) = apply_terminal_settings(TerminalSettingsConfig::from_parts(
            "\u{00A0}Consolas\u{00A0}",
            14,
            true,
        ))
        .unwrap();
        assert_eq!(applied.font_family(), "Consolas");
    }

    #[test]
    fn fake_apply_records_messages_and_rejects_leave_prior() {
        let mut fake = FakeTerminalSettingsSurface::new();
        fake.apply(TerminalSettingsConfig::default()).unwrap();
        assert_eq!(fake.apply_count(), 1);
        assert_eq!(fake.messages().len(), 3);
        assert_eq!(fake.last().unwrap().font_size(), 12);

        let err = fake
            .apply(TerminalSettingsConfig::from_parts("", 99, false))
            .unwrap_err();
        assert_eq!(err, TerminalSettingsApplyError::EmptyFontFamily);
        assert_eq!(fake.apply_count(), 1);
        assert_eq!(fake.messages().len(), 3);
        assert_eq!(fake.last().unwrap().font_size(), 12);

        let err = fake
            .apply(TerminalSettingsConfig::from_parts("Consolas", 0, true))
            .unwrap_err();
        assert_eq!(err, TerminalSettingsApplyError::NonPositiveFontSize);
        assert_eq!(fake.apply_count(), 1);
        assert_eq!(fake.last().unwrap().font_family(), DEFAULT_SSH_FONT_FAMILY);
    }

    #[test]
    fn fake_reapply_updates_snapshot_and_appends_messages() {
        let mut fake = FakeTerminalSettingsSurface::new();
        fake.apply(TerminalSettingsConfig::default()).unwrap();
        fake.apply(TerminalSettingsConfig::from_parts("Consolas", 16, false))
            .unwrap();
        assert_eq!(fake.apply_count(), 2);
        assert_eq!(fake.messages().len(), 6);
        let last = fake.last().unwrap();
        assert_eq!(last.font_family(), "Consolas");
        assert_eq!(last.font_size(), 16);
        assert!(!last.auto_copy_on_select());
    }

    #[test]
    fn auto_copy_gate_matches_csharp_c_frame_policy() {
        let on = validate_terminal_settings(&TerminalSettingsConfig::from_parts(
            "Cascadia Mono",
            12,
            true,
        ))
        .unwrap();
        let off = validate_terminal_settings(&TerminalSettingsConfig::from_parts(
            "Cascadia Mono",
            12,
            false,
        ))
        .unwrap();
        assert!(accept_selection_auto_copy(&on, b"selected"));
        assert!(!accept_selection_auto_copy(&on, b""));
        assert!(!accept_selection_auto_copy(&off, b"selected"));
        // C# MaximumSelectionUtf8Bytes — oversized decoded payload is ignored.
        let over = vec![b'x'; crate::MAX_SELECTION_UTF8_BYTES + 1];
        assert!(!accept_selection_auto_copy(&on, &over));
        let at_cap = vec![b'x'; crate::MAX_SELECTION_UTF8_BYTES];
        assert!(accept_selection_auto_copy(&on, &at_cap));
    }

    #[test]
    fn fake_auto_copy_records_length_only_never_body() {
        let mut fake = FakeTerminalSettingsSurface::new();
        assert!(!fake.try_auto_copy_selection(b"early"));
        fake.apply(TerminalSettingsConfig::from_parts("Cascadia Mono", 12, true))
            .unwrap();
        assert!(fake.try_auto_copy_selection(b"hello"));
        assert!(!fake.try_auto_copy_selection(b""));
        let over = vec![b'z'; crate::MAX_SELECTION_UTF8_BYTES + 1];
        assert!(!fake.try_auto_copy_selection(&over));
        fake.apply(TerminalSettingsConfig::from_parts("Cascadia Mono", 12, false))
            .unwrap();
        assert!(!fake.try_auto_copy_selection(b"nope"));
        assert_eq!(fake.accepted_selection_count(), 1);
        assert_eq!(fake.accepted_selection_lens(), &[5]);
        let dbg = format!("{fake:?}");
        assert!(dbg.contains("FakeTerminalSettingsSurface"));
        assert!(!dbg.contains("hello"));
        assert!(!dbg.contains("nope"));
    }

    #[test]
    fn from_parts_round_trips_fields() {
        let cfg = TerminalSettingsConfig::from_parts("Fira Code", 18, false);
        assert_eq!(cfg.font_family, "Fira Code");
        assert_eq!(cfg.font_size, 18);
        assert!(!cfg.auto_copy_on_select);
    }

    #[test]
    fn fake_clear_resets_snapshot_messages_and_auto_copy() {
        let mut fake = FakeTerminalSettingsSurface::new();
        fake.apply(TerminalSettingsConfig::default()).unwrap();
        assert!(fake.try_auto_copy_selection(b"x"));
        fake.clear();
        assert_eq!(fake.apply_count(), 0);
        assert!(fake.messages().is_empty());
        assert!(fake.last().is_none());
        assert_eq!(fake.accepted_selection_count(), 0);
        assert!(!fake.try_auto_copy_selection(b"x"));
    }
}
