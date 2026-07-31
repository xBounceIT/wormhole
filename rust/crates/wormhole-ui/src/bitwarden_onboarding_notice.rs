//! Bitwarden onboarding notice versioning glue (C# `BitwardenOnboardingNoticeService`).
//!
//! Soft UX: show a one-time notice when settings migration marks a pending onboarding
//! version and the app is **0.7.x**. Persists seen/pending fields via an injected
//! [`SettingsStore`] only — no live `bw` CLI, no GPUI dialog chrome.
//!
//! Fail-closed: dialog errors do **not** mark seen or save; cancellation aborts without
//! mutation. Negative / zero notice versions never show.

use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::settings::{AppSettings, SettingsError, SettingsStore};

/// Current onboarding notice content version (C# `CurrentBitwardenOnboardingNoticeVersion`).
pub const CURRENT_BITWARDEN_ONBOARDING_NOTICE_VERSION: i32 = 1;

/// Dialog title (C# `BitwardenOnboardingNoticeService.Title`).
pub const BITWARDEN_ONBOARDING_NOTICE_TITLE: &str = "New Bitwarden integration";

/// Dialog body (C# `BitwardenOnboardingNoticeService.Message`).
pub const BITWARDEN_ONBOARDING_NOTICE_MESSAGE: &str =
    "Wormhole now supports Bitwarden as an optional vault for credentials and as a browser extension in HTTPS windows. Enable it from Settings > Extensions > Bitwarden.";

/// App release version gate — only **0.7.x** shows the notice (C# `Version.Major/Minor`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppReleaseVersion {
    pub major: u32,
    pub minor: u32,
}

impl AppReleaseVersion {
    pub const fn new(major: u32, minor: u32) -> Self {
        Self { major, minor }
    }
}

/// Outcome of [`BitwardenOnboardingNoticeGlue::show_if_needed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitwardenOnboardingShowOutcome {
    /// Preconditions not met — no dialog, no save.
    Skipped,
    /// Notice shown and settings persisted.
    Shown,
    /// Dialog surface failed — settings unchanged on disk.
    DialogFailed,
}

/// Errors from the glue (settings I/O or cooperative cancellation).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BitwardenOnboardingError {
    #[error(transparent)]
    Settings(#[from] SettingsError),
    #[error("Bitwarden onboarding notice cancelled")]
    Cancelled,
}

/// UI surface for the onboarding notice (tests: [`FakeBitwardenOnboardingNoticeUi`]).
pub trait BitwardenOnboardingNoticeUi: Send + Sync {
    /// Show the notice. Must use the Bitwarden-specific dialog in production; tests
    /// record title/message only.
    fn show(&self, title: &str, message: &str) -> Result<(), BitwardenOnboardingUiError>;
}

/// Dialog failure (never carries secrets).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("Bitwarden onboarding notice UI failed")]
pub struct BitwardenOnboardingUiError;

/// Whether the notice should display for the given settings + app version.
pub fn should_show_bitwarden_onboarding_notice(
    settings: &AppSettings,
    app_version: AppReleaseVersion,
) -> bool {
    settings.bitwarden_onboarding_notice_seen_version
        < CURRENT_BITWARDEN_ONBOARDING_NOTICE_VERSION
        && settings.bitwarden_onboarding_notice_pending_version
            >= CURRENT_BITWARDEN_ONBOARDING_NOTICE_VERSION
        && app_version.major == 0
        && app_version.minor == 7
}

/// Orchestrates load → maybe show → mark seen → save (Fake UI + settings store only).
pub struct BitwardenOnboardingNoticeGlue<U: BitwardenOnboardingNoticeUi> {
    ui: U,
    app_version: AppReleaseVersion,
}

impl<U: BitwardenOnboardingNoticeUi> fmt::Debug for BitwardenOnboardingNoticeGlue<U> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BitwardenOnboardingNoticeGlue")
            .field("app_version", &self.app_version)
            .field("ui", &"<BitwardenOnboardingNoticeUi>")
            .finish()
    }
}

impl<U: BitwardenOnboardingNoticeUi> BitwardenOnboardingNoticeGlue<U> {
    pub fn new(ui: U, app_version: AppReleaseVersion) -> Self {
        Self { ui, app_version }
    }

    pub fn app_version(&self) -> AppReleaseVersion {
        self.app_version
    }

    /// Load settings, show when needed, persist seen/pending on success.
    ///
    /// `cancelled` mirrors `CancellationToken` — when true, returns
    /// [`BitwardenOnboardingError::Cancelled`] before UI or save (no mutation).
    pub fn show_if_needed(
        &self,
        store: &dyn SettingsStore,
        cancelled: bool,
    ) -> Result<BitwardenOnboardingShowOutcome, BitwardenOnboardingError> {
        if cancelled {
            return Err(BitwardenOnboardingError::Cancelled);
        }

        let mut settings = store.load()?;
        if !should_show_bitwarden_onboarding_notice(&settings, self.app_version) {
            return Ok(BitwardenOnboardingShowOutcome::Skipped);
        }

        if cancelled {
            return Err(BitwardenOnboardingError::Cancelled);
        }

        match self
            .ui
            .show(BITWARDEN_ONBOARDING_NOTICE_TITLE, BITWARDEN_ONBOARDING_NOTICE_MESSAGE)
        {
            Ok(()) => {
                if cancelled {
                    return Err(BitwardenOnboardingError::Cancelled);
                }
                settings.bitwarden_onboarding_notice_seen_version =
                    CURRENT_BITWARDEN_ONBOARDING_NOTICE_VERSION;
                settings.bitwarden_onboarding_notice_pending_version = 0;
                store.save(&settings)?;
                Ok(BitwardenOnboardingShowOutcome::Shown)
            }
            Err(_) => Ok(BitwardenOnboardingShowOutcome::DialogFailed),
        }
    }
}

struct FakeUiState {
    last_title: Option<String>,
    last_message: Option<String>,
    fail_next: bool,
}

impl Default for FakeUiState {
    fn default() -> Self {
        Self {
            last_title: None,
            last_message: None,
            fail_next: false,
        }
    }
}

/// Scripted onboarding UI for unit tests (no GPUI).
#[derive(Default)]
pub struct FakeBitwardenOnboardingNoticeUi {
    state: Mutex<FakeUiState>,
    show_calls: AtomicUsize,
}

impl fmt::Debug for FakeBitwardenOnboardingNoticeUi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        f.debug_struct("FakeBitwardenOnboardingNoticeUi")
            .field("show_calls", &self.show_calls.load(Ordering::SeqCst))
            .field("fail_next", &state.fail_next)
            .field("last_title_len", &state.last_title.as_ref().map(|s| s.len()))
            .field(
                "last_message_len",
                &state.last_message.as_ref().map(|s| s.len()),
            )
            .finish()
    }
}

impl FakeBitwardenOnboardingNoticeUi {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn show_calls(&self) -> usize {
        self.show_calls.load(Ordering::SeqCst)
    }

    pub fn last_title(&self) -> Option<String> {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .last_title
            .clone()
    }

    pub fn last_message(&self) -> Option<String> {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .last_message
            .clone()
    }

    /// Next `show` returns [`BitwardenOnboardingUiError`].
    pub fn fail_next_show(&self) {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).fail_next = true;
    }
}

impl BitwardenOnboardingNoticeUi for FakeBitwardenOnboardingNoticeUi {
    fn show(&self, title: &str, message: &str) -> Result<(), BitwardenOnboardingUiError> {
        self.show_calls.fetch_add(1, Ordering::SeqCst);
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.fail_next {
            state.fail_next = false;
            return Err(BitwardenOnboardingUiError);
        }
        state.last_title = Some(title.to_string());
        state.last_message = Some(message.to_string());
        Ok(())
    }
}

impl BitwardenOnboardingNoticeUi for Arc<FakeBitwardenOnboardingNoticeUi> {
    fn show(&self, title: &str, message: &str) -> Result<(), BitwardenOnboardingUiError> {
        (**self).show(title, message)
    }
}

/// Test harness: glue + shared Fake UI handle.
pub fn with_fake_ui(
    app_version: AppReleaseVersion,
) -> (
    BitwardenOnboardingNoticeGlue<Arc<FakeBitwardenOnboardingNoticeUi>>,
    Arc<FakeBitwardenOnboardingNoticeUi>,
) {
    let ui = Arc::new(FakeBitwardenOnboardingNoticeUi::new());
    let glue = BitwardenOnboardingNoticeGlue::new(Arc::clone(&ui), app_version);
    (glue, ui)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::MemorySettingsStore;

    fn pending_settings() -> AppSettings {
        let mut s = AppSettings::default();
        s.bitwarden_onboarding_notice_pending_version =
            CURRENT_BITWARDEN_ONBOARDING_NOTICE_VERSION;
        s
    }

    fn glue_v07() -> (
        BitwardenOnboardingNoticeGlue<Arc<FakeBitwardenOnboardingNoticeUi>>,
        Arc<FakeBitwardenOnboardingNoticeUi>,
    ) {
        with_fake_ui(AppReleaseVersion::new(0, 7))
    }

    #[test]
    fn shows_notice_and_marks_seen_on_version_07() {
        let (glue, ui) = glue_v07();
        let store = MemorySettingsStore::new(pending_settings());

        assert_eq!(
            glue.show_if_needed(&store, false).unwrap(),
            BitwardenOnboardingShowOutcome::Shown
        );
        assert_eq!(ui.show_calls(), 1);
        assert_eq!(
            ui.last_title().as_deref(),
            Some(BITWARDEN_ONBOARDING_NOTICE_TITLE)
        );
        assert_eq!(
            ui.last_message().as_deref(),
            Some(BITWARDEN_ONBOARDING_NOTICE_MESSAGE)
        );

        let saved = store.snapshot();
        assert_eq!(
            saved.bitwarden_onboarding_notice_seen_version,
            CURRENT_BITWARDEN_ONBOARDING_NOTICE_VERSION
        );
        assert_eq!(saved.bitwarden_onboarding_notice_pending_version, 0);
    }

    #[test]
    fn does_nothing_on_version_08() {
        let (glue, ui) = with_fake_ui(AppReleaseVersion::new(0, 8));
        let store = MemorySettingsStore::new(pending_settings());

        assert_eq!(
            glue.show_if_needed(&store, false).unwrap(),
            BitwardenOnboardingShowOutcome::Skipped
        );
        assert_eq!(ui.show_calls(), 0);
        let saved = store.snapshot();
        assert_eq!(saved.bitwarden_onboarding_notice_seen_version, 0);
        assert_eq!(
            saved.bitwarden_onboarding_notice_pending_version,
            CURRENT_BITWARDEN_ONBOARDING_NOTICE_VERSION
        );
    }

    #[test]
    fn does_nothing_without_pending_notice() {
        let (glue, ui) = glue_v07();
        let store = MemorySettingsStore::new(AppSettings::default());

        assert_eq!(
            glue.show_if_needed(&store, false).unwrap(),
            BitwardenOnboardingShowOutcome::Skipped
        );
        assert_eq!(ui.show_calls(), 0);
        let saved = store.snapshot();
        assert_eq!(saved.bitwarden_onboarding_notice_seen_version, 0);
        assert_eq!(saved.bitwarden_onboarding_notice_pending_version, 0);
    }

    #[test]
    fn does_nothing_when_already_seen() {
        let (glue, ui) = glue_v07();
        let mut settings = pending_settings();
        settings.bitwarden_onboarding_notice_seen_version =
            CURRENT_BITWARDEN_ONBOARDING_NOTICE_VERSION;
        let store = MemorySettingsStore::new(settings);

        assert_eq!(
            glue.show_if_needed(&store, false).unwrap(),
            BitwardenOnboardingShowOutcome::Skipped
        );
        assert_eq!(ui.show_calls(), 0);
        assert_eq!(
            store.snapshot().bitwarden_onboarding_notice_pending_version,
            CURRENT_BITWARDEN_ONBOARDING_NOTICE_VERSION
        );
    }

    #[test]
    fn does_not_mark_seen_when_dialog_fails() {
        let (glue, ui) = glue_v07();
        ui.fail_next_show();
        let store = MemorySettingsStore::new(pending_settings());

        assert_eq!(
            glue.show_if_needed(&store, false).unwrap(),
            BitwardenOnboardingShowOutcome::DialogFailed
        );
        assert_eq!(ui.show_calls(), 1);
        let saved = store.snapshot();
        assert_eq!(saved.bitwarden_onboarding_notice_seen_version, 0);
        assert_eq!(
            saved.bitwarden_onboarding_notice_pending_version,
            CURRENT_BITWARDEN_ONBOARDING_NOTICE_VERSION
        );
    }

    #[test]
    fn cancelled_before_load_does_not_touch_store() {
        let (glue, ui) = glue_v07();
        let store = MemorySettingsStore::new(pending_settings());

        assert!(matches!(
            glue.show_if_needed(&store, true),
            Err(BitwardenOnboardingError::Cancelled)
        ));
        assert_eq!(ui.show_calls(), 0);
    }

    #[test]
    fn negative_notice_versions_never_show() {
        let (glue, ui) = glue_v07();
        let mut settings = AppSettings::default();
        settings.bitwarden_onboarding_notice_pending_version = -1;
        settings.bitwarden_onboarding_notice_seen_version = -1;
        let store = MemorySettingsStore::new(settings);

        assert_eq!(
            glue.show_if_needed(&store, false).unwrap(),
            BitwardenOnboardingShowOutcome::Skipped
        );
        assert_eq!(ui.show_calls(), 0);
    }

    #[test]
    fn does_not_show_on_version_06() {
        let (glue, ui) = with_fake_ui(AppReleaseVersion::new(0, 6));
        let store = MemorySettingsStore::new(pending_settings());
        assert_eq!(
            glue.show_if_needed(&store, false).unwrap(),
            BitwardenOnboardingShowOutcome::Skipped
        );
        assert_eq!(ui.show_calls(), 0);
    }

    #[test]
    fn does_not_show_when_major_nonzero() {
        let (glue, ui) = with_fake_ui(AppReleaseVersion::new(1, 7));
        let store = MemorySettingsStore::new(pending_settings());
        assert_eq!(
            glue.show_if_needed(&store, false).unwrap(),
            BitwardenOnboardingShowOutcome::Skipped
        );
        assert_eq!(ui.show_calls(), 0);
    }

    #[test]
    fn migrate_from_schema_before_v6_sets_pending_notice() {
        let mut settings = AppSettings::default();
        assert_eq!(settings.bitwarden_onboarding_notice_pending_version, 0);
        assert!(settings.migrate_from_schema(5));
        assert_eq!(settings.bitwarden_onboarding_notice_pending_version, 1);
        assert_eq!(settings.bitwarden_onboarding_notice_seen_version, 0);
    }

    #[test]
    fn save_failure_after_dialog_does_not_persist_seen() {
        struct FailSaveStore {
            inner: MemorySettingsStore,
        }

        impl SettingsStore for FailSaveStore {
            fn load(&self) -> Result<AppSettings, SettingsError> {
                self.inner.load()
            }

            fn save(&self, _settings: &AppSettings) -> Result<(), SettingsError> {
                Err(SettingsError::Io("injected save failure".into()))
            }
        }

        let (glue, ui) = glue_v07();
        let store = FailSaveStore {
            inner: MemorySettingsStore::new(pending_settings()),
        };

        let err = glue.show_if_needed(&store, false).unwrap_err();
        assert!(matches!(err, BitwardenOnboardingError::Settings(_)));
        assert_eq!(ui.show_calls(), 1);
        assert_eq!(store.inner.snapshot().bitwarden_onboarding_notice_seen_version, 0);
        assert_eq!(
            store.inner.snapshot().bitwarden_onboarding_notice_pending_version,
            CURRENT_BITWARDEN_ONBOARDING_NOTICE_VERSION
        );
    }

    #[test]
    fn pending_above_current_notice_version_still_shows_on_07() {
        let (glue, ui) = glue_v07();
        let mut settings = AppSettings::default();
        settings.bitwarden_onboarding_notice_pending_version = 2;
        let store = MemorySettingsStore::new(settings);

        assert_eq!(
            glue.show_if_needed(&store, false).unwrap(),
            BitwardenOnboardingShowOutcome::Shown
        );
        assert_eq!(ui.show_calls(), 1);
        assert_eq!(
            store.snapshot().bitwarden_onboarding_notice_seen_version,
            CURRENT_BITWARDEN_ONBOARDING_NOTICE_VERSION
        );
    }

    #[test]
    fn should_show_helper_matches_glue_gates() {
        let mut settings = pending_settings();
        assert!(should_show_bitwarden_onboarding_notice(
            &settings,
            AppReleaseVersion::new(0, 7)
        ));
        assert!(!should_show_bitwarden_onboarding_notice(
            &settings,
            AppReleaseVersion::new(0, 8)
        ));
        settings.bitwarden_onboarding_notice_seen_version =
            CURRENT_BITWARDEN_ONBOARDING_NOTICE_VERSION;
        assert!(!should_show_bitwarden_onboarding_notice(
            &settings,
            AppReleaseVersion::new(0, 7)
        ));
    }

    #[test]
    fn fake_debug_never_echoes_message_body() {
        let (glue, ui) = glue_v07();
        let store = MemorySettingsStore::new(pending_settings());
        glue.show_if_needed(&store, false).unwrap();
        let dbg = format!("{ui:?}");
        assert!(!dbg.contains(BITWARDEN_ONBOARDING_NOTICE_MESSAGE));
        assert!(dbg.contains("last_message_len"));
    }
}
