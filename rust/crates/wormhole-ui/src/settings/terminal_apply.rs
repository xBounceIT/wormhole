//! AppSettings → terminal font / size / auto-copy apply glue.
//!
//! Thin mapper over [`wormhole_terminal::settings_apply`]: copies
//! `DefaultSshFont` / `DefaultSshFontSize` / `AutoCopyOnSelect` into
//! [`TerminalSettingsConfig`], then validates + records on
//! [`FakeTerminalSettingsSurface`]. Empty / whitespace-only font (Unicode
//! `trim`, including NBSP) and non-positive size fail closed (Fake unchanged).
//! No GPUI / no live WebView2 xterm options push.

use wormhole_terminal::{
    apply_terminal_settings, AppliedTerminalSettings, FakeTerminalSettingsSurface,
    TerminalSettingsApplyError, TerminalSettingsApplyMessage, TerminalSettingsConfig,
};

use super::model::AppSettings;

/// Map UI [`AppSettings`] terminal fields into a [`TerminalSettingsConfig`].
pub fn terminal_settings_config_from_app(settings: &AppSettings) -> TerminalSettingsConfig {
    TerminalSettingsConfig::from_parts(
        settings.default_ssh_font.clone(),
        settings.default_ssh_font_size,
        settings.auto_copy_on_select,
    )
}

/// Validate + build apply messages from [`AppSettings`] (no Fake mutation).
pub fn apply_terminal_settings_from_app(
    settings: &AppSettings,
) -> Result<(AppliedTerminalSettings, Vec<TerminalSettingsApplyMessage>), TerminalSettingsApplyError>
{
    apply_terminal_settings(terminal_settings_config_from_app(settings))
}

/// Apply AppSettings terminal slice onto a Fake surface (fail-closed).
pub fn apply_terminal_settings_to_fake<'a>(
    settings: &AppSettings,
    surface: &'a mut FakeTerminalSettingsSurface,
) -> Result<&'a AppliedTerminalSettings, TerminalSettingsApplyError> {
    surface.apply(terminal_settings_config_from_app(settings))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wormhole_terminal::{DEFAULT_SSH_FONT_FAMILY, DEFAULT_SSH_FONT_SIZE};

    #[test]
    fn default_app_settings_apply_to_fake() {
        let settings = AppSettings::default();
        let mut fake = FakeTerminalSettingsSurface::new();
        let applied = apply_terminal_settings_to_fake(&settings, &mut fake).unwrap();
        assert_eq!(applied.font_family(), DEFAULT_SSH_FONT_FAMILY);
        assert_eq!(applied.font_size(), DEFAULT_SSH_FONT_SIZE);
        assert!(applied.auto_copy_on_select());
        assert_eq!(fake.messages().len(), 3);
        // AppSettings defaults must stay aligned with TerminalSettingsConfig::default.
        let cfg_default = TerminalSettingsConfig::default();
        assert_eq!(settings.default_ssh_font, cfg_default.font_family);
        assert_eq!(settings.default_ssh_font_size, cfg_default.font_size);
        assert_eq!(settings.auto_copy_on_select, cfg_default.auto_copy_on_select);
    }

    #[test]
    fn empty_font_from_app_fail_closed() {
        let mut settings = AppSettings::default();
        settings.default_ssh_font = "  ".into();
        let mut fake = FakeTerminalSettingsSurface::new();
        fake.apply(TerminalSettingsConfig::default()).unwrap();
        let err = apply_terminal_settings_to_fake(&settings, &mut fake).unwrap_err();
        assert_eq!(err, TerminalSettingsApplyError::EmptyFontFamily);
        assert_eq!(fake.apply_count(), 1);
        assert_eq!(fake.last().unwrap().font_family(), DEFAULT_SSH_FONT_FAMILY);

        // Unicode White_Space (NBSP) also fails closed — Fake unchanged.
        settings.default_ssh_font = "\u{00A0}".into();
        let err = apply_terminal_settings_to_fake(&settings, &mut fake).unwrap_err();
        assert_eq!(err, TerminalSettingsApplyError::EmptyFontFamily);
        assert_eq!(fake.apply_count(), 1);
    }

    #[test]
    fn non_positive_size_from_app_fail_closed() {
        let mut settings = AppSettings::default();
        settings.default_ssh_font_size = 0;
        let err_apply = apply_terminal_settings_from_app(&settings).unwrap_err();
        assert_eq!(err_apply, TerminalSettingsApplyError::NonPositiveFontSize);

        settings.default_ssh_font_size = -3;
        let mut fake = FakeTerminalSettingsSurface::new();
        let err = apply_terminal_settings_to_fake(&settings, &mut fake).unwrap_err();
        assert_eq!(err, TerminalSettingsApplyError::NonPositiveFontSize);
        assert_eq!(fake.apply_count(), 0);
        assert!(fake.last().is_none());
    }

    #[test]
    fn staged_font_size_and_auto_copy_round_trip() {
        let mut settings = AppSettings::default();
        settings.default_ssh_font = "Consolas".into();
        settings.default_ssh_font_size = 18;
        settings.auto_copy_on_select = false;
        let (applied, messages) = apply_terminal_settings_from_app(&settings).unwrap();
        assert_eq!(applied.font_family(), "Consolas");
        assert_eq!(applied.font_size(), 18);
        assert!(!applied.auto_copy_on_select());
        assert!(matches!(
            &messages[2],
            TerminalSettingsApplyMessage::SetAutoCopyOnSelect { enabled: false }
        ));
    }

    #[test]
    fn config_mapper_clones_fields() {
        let mut settings = AppSettings::default();
        settings.default_ssh_font = "JetBrains Mono".into();
        settings.default_ssh_font_size = 11;
        settings.auto_copy_on_select = false;
        let cfg = terminal_settings_config_from_app(&settings);
        assert_eq!(cfg.font_family, "JetBrains Mono");
        assert_eq!(cfg.font_size, 11);
        assert!(!cfg.auto_copy_on_select);
    }
}
