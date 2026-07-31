//! Settings view-model wrapping a [`SettingsStore`].

use std::sync::Arc;

use super::model::{
    AppAuthenticationFallbackMethod, AppAuthenticationMode, AppSettings, ApplicationTheme,
    CURRENT_SCHEMA_VERSION,
};
use super::store::{SettingsError, SettingsStore};

/// UI-facing settings state (subset of C# `SettingsViewModel` bindings).
///
/// Bitwarden / MCP / Hello side-effects stay out of scope — this layer owns
/// load / mutate / save of the JSON settings document via [`SettingsStore`].
///
/// Immediate-persist setters are atomic: on save failure the in-memory document
/// rolls back to the pre-setter snapshot and any prior `stage` dirty flag is kept.
pub struct SettingsViewModel {
    store: Arc<dyn SettingsStore>,
    current: AppSettings,
    dirty: bool,
}

impl std::fmt::Debug for SettingsViewModel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Intentionally omit the store handle and full AppSettings dump (paths,
        // URLs, install/sync error strings). Settings.json holds no passwords;
        // keep Debug free of secret-adjacent payloads anyway.
        f.debug_struct("SettingsViewModel")
            .field("dirty", &self.dirty)
            .field("schema_version", &self.current.settings_schema_version)
            .field("theme", &self.current.theme)
            .field("enable_mcp_server", &self.current.enable_mcp_server)
            .field(
                "app_authentication_mode",
                &self.current.app_authentication_mode,
            )
            .finish_non_exhaustive()
    }
}

impl SettingsViewModel {
    pub fn new(store: Arc<dyn SettingsStore>) -> Result<Self, SettingsError> {
        let current = store.load()?;
        Ok(Self {
            store,
            current,
            dirty: false,
        })
    }

    pub fn from_settings(store: Arc<dyn SettingsStore>, current: AppSettings) -> Self {
        Self {
            store,
            current,
            dirty: false,
        }
    }

    pub fn current(&self) -> &AppSettings {
        &self.current
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    pub fn reload(&mut self) -> Result<(), SettingsError> {
        self.current = self.store.load()?;
        self.dirty = false;
        Ok(())
    }

    pub fn save(&mut self) -> Result<(), SettingsError> {
        self.stamp_and_save()?;
        self.dirty = false;
        Ok(())
    }

    /// Mutate the in-memory document without writing. Marks the VM dirty.
    ///
    /// Use with [`Self::apply`] for batch edits (dirty → apply → reload).
    /// Immediate setters ([`Self::set_theme`], …) still persist on each change.
    pub fn stage(&mut self, apply: impl FnOnce(&mut AppSettings)) {
        apply(&mut self.current);
        self.dirty = true;
    }

    /// Persist dirty settings through the store. No-op when clean.
    ///
    /// On save failure the in-memory document and dirty flag are left unchanged
    /// so the caller can retry or [`Self::reload`] to discard.
    pub fn apply(&mut self) -> Result<(), SettingsError> {
        if !self.dirty {
            return Ok(());
        }
        self.stamp_and_save()?;
        self.dirty = false;
        Ok(())
    }

    pub fn set_theme(&mut self, theme: ApplicationTheme) -> Result<(), SettingsError> {
        if self.current.theme == theme {
            return Ok(());
        }
        self.commit(|s| s.theme = theme)
    }

    pub fn set_confirm_on_tab_close(&mut self, value: bool) -> Result<(), SettingsError> {
        self.set_bool(|s| &mut s.confirm_on_tab_close, value)
    }

    pub fn set_auto_check_for_updates(&mut self, value: bool) -> Result<(), SettingsError> {
        self.set_bool(|s| &mut s.auto_check_for_updates, value)
    }

    pub fn set_auto_copy_on_select(&mut self, value: bool) -> Result<(), SettingsError> {
        self.set_bool(|s| &mut s.auto_copy_on_select, value)
    }

    pub fn set_prompt_before_tunnel_connect(&mut self, value: bool) -> Result<(), SettingsError> {
        self.set_bool(|s| &mut s.prompt_before_tunnel_connect, value)
    }

    pub fn set_enable_mcp_server(&mut self, value: bool) -> Result<(), SettingsError> {
        self.set_bool(|s| &mut s.enable_mcp_server, value)
    }

    pub fn set_mcp_server_port(&mut self, port: i32) -> Result<(), SettingsError> {
        if !(1..=65535).contains(&port) {
            return Ok(());
        }
        if self.current.mcp_server_port == port {
            return Ok(());
        }
        self.commit(|s| s.mcp_server_port = port)
    }

    pub fn set_log_retention_days(&mut self, days: i32) -> Result<(), SettingsError> {
        let normalized = normalize_retention_days(days);
        if self.current.log_retention_days == normalized {
            return Ok(());
        }
        self.commit(|s| s.log_retention_days = normalized)
    }

    pub fn set_app_authentication_mode(
        &mut self,
        mode: AppAuthenticationMode,
    ) -> Result<(), SettingsError> {
        if self.current.app_authentication_mode == mode {
            return Ok(());
        }
        self.commit(|s| s.app_authentication_mode = mode)
    }

    pub fn set_app_authentication_hello_fallback(
        &mut self,
        fallback: AppAuthenticationFallbackMethod,
    ) -> Result<(), SettingsError> {
        if self.current.app_authentication_hello_fallback == fallback {
            return Ok(());
        }
        self.commit(|s| s.app_authentication_hello_fallback = fallback)
    }

    pub fn set_sidebar_width(&mut self, width: i32) -> Result<(), SettingsError> {
        let width = width.max(160);
        if self.current.sidebar_width == width {
            return Ok(());
        }
        self.commit(|s| s.sidebar_width = width)
    }

    /// Replace the whole document (import / tests) and persist.
    pub fn replace(&mut self, settings: AppSettings) -> Result<(), SettingsError> {
        self.commit(|s| *s = settings)
    }

    fn set_bool(
        &mut self,
        field: impl Fn(&mut AppSettings) -> &mut bool,
        value: bool,
    ) -> Result<(), SettingsError> {
        if *field(&mut self.current) == value {
            return Ok(());
        }
        self.commit(|s| {
            *field(s) = value;
        })
    }

    fn commit(
        &mut self,
        apply: impl FnOnce(&mut AppSettings),
    ) -> Result<(), SettingsError> {
        let before = self.current.clone();
        let was_dirty = self.dirty;
        apply(&mut self.current);
        self.persist_or_rollback(before, was_dirty)
    }

    /// Stamp schema + persist. Caller clears or restores `dirty` on success/failure.
    fn stamp_and_save(&mut self) -> Result<(), SettingsError> {
        self.current.settings_schema_version = CURRENT_SCHEMA_VERSION;
        self.store.save(&self.current)
    }

    fn persist_or_rollback(
        &mut self,
        before: AppSettings,
        was_dirty: bool,
    ) -> Result<(), SettingsError> {
        match self.stamp_and_save() {
            Ok(()) => {
                self.dirty = false;
                Ok(())
            }
            Err(e) => {
                self.current = before;
                // Preserve prior dirty so a failed immediate setter after `stage`
                // cannot leave memory≠disk with `is_dirty() == false`.
                self.dirty = was_dirty;
                Err(e)
            }
        }
    }
}

/// Clamp retention like C# `LogFiles.NormalizeRetentionDays` (1..=365, default 14).
pub fn normalize_retention_days(days: i32) -> i32 {
    if !(1..=365).contains(&days) {
        14
    } else {
        days
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::store::MemorySettingsStore;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn setters_persist_through_store() {
        let store = Arc::new(MemorySettingsStore::new(AppSettings::default()));
        let mut vm = SettingsViewModel::new(store.clone()).unwrap();

        vm.set_theme(ApplicationTheme::Dark).unwrap();
        vm.set_confirm_on_tab_close(false).unwrap();
        vm.set_prompt_before_tunnel_connect(false).unwrap();
        vm.set_mcp_server_port(9000).unwrap();

        let snap = store.snapshot();
        assert_eq!(snap.theme, ApplicationTheme::Dark);
        assert!(!snap.confirm_on_tab_close);
        assert!(!snap.prompt_before_tunnel_connect);
        assert_eq!(snap.mcp_server_port, 9000);
        assert!(!vm.is_dirty());
    }

    #[test]
    fn invalid_mcp_port_is_ignored() {
        let store = Arc::new(MemorySettingsStore::new(AppSettings::default()));
        let mut vm = SettingsViewModel::new(store.clone()).unwrap();
        vm.set_mcp_server_port(0).unwrap();
        assert_eq!(vm.current().mcp_server_port, 8765);
    }

    #[test]
    fn retention_days_normalize() {
        assert_eq!(normalize_retention_days(0), 14);
        assert_eq!(normalize_retention_days(400), 14);
        assert_eq!(normalize_retention_days(30), 30);
    }

    struct FailNTimesStore {
        inner: MemorySettingsStore,
        failures_left: AtomicUsize,
    }

    impl FailNTimesStore {
        fn new(settings: AppSettings, failures: usize) -> Self {
            Self {
                inner: MemorySettingsStore::new(settings),
                failures_left: AtomicUsize::new(failures),
            }
        }
    }

    impl SettingsStore for FailNTimesStore {
        fn load(&self) -> Result<AppSettings, SettingsError> {
            self.inner.load()
        }

        fn save(&self, settings: &AppSettings) -> Result<(), SettingsError> {
            let left = self.failures_left.load(Ordering::SeqCst);
            if left > 0 {
                self.failures_left.fetch_sub(1, Ordering::SeqCst);
                return Err(SettingsError::Io("injected save failure".into()));
            }
            self.inner.save(settings)
        }
    }

    #[test]
    fn persist_failure_rolls_back_in_memory_state() {
        let store = Arc::new(FailNTimesStore::new(AppSettings::default(), 1));
        let mut vm = SettingsViewModel::new(store.clone()).unwrap();
        assert_eq!(vm.current().theme, ApplicationTheme::System);

        let err = vm.set_theme(ApplicationTheme::Dark).unwrap_err();
        assert!(matches!(err, SettingsError::Io(_)));
        assert_eq!(vm.current().theme, ApplicationTheme::System);
        assert!(!vm.is_dirty());
        assert_eq!(store.inner.snapshot().theme, ApplicationTheme::System);

        vm.set_theme(ApplicationTheme::Dark).unwrap();
        assert_eq!(vm.current().theme, ApplicationTheme::Dark);
        assert_eq!(store.inner.snapshot().theme, ApplicationTheme::Dark);
    }

    #[test]
    fn debug_omits_full_settings_dump_and_paths() {
        let mut settings = AppSettings::default();
        settings.bitwarden_cli_path = r"C:\secret\bw.exe".into();
        settings.bitwarden_cli_install_error = Some("token=super-secret".into());
        settings.bitwarden_browser_extension_path =
            Some(r"C:\Users\x\vault-extension".into());
        let store = Arc::new(MemorySettingsStore::new(settings));
        let vm = SettingsViewModel::new(store).unwrap();
        let dbg = format!("{vm:?}");
        assert!(dbg.contains("SettingsViewModel"));
        assert!(dbg.contains("theme"));
        assert!(
            !dbg.contains(r"C:\secret"),
            "Debug must not dump Bitwarden paths: {dbg}"
        );
        assert!(
            !dbg.contains("super-secret"),
            "Debug must not dump install/sync error payloads: {dbg}"
        );
        assert!(
            !dbg.contains("vault-extension"),
            "Debug must not dump extension paths: {dbg}"
        );
    }

    #[test]
    fn stage_apply_reload_memory_round_trip() {
        let store = Arc::new(MemorySettingsStore::new(AppSettings::default()));
        let mut vm = SettingsViewModel::new(store.clone()).unwrap();

        vm.stage(|s| {
            s.theme = ApplicationTheme::Light;
            s.sidebar_width = 280;
        });
        assert!(vm.is_dirty());
        assert_eq!(store.snapshot().theme, ApplicationTheme::System);

        vm.apply().unwrap();
        assert!(!vm.is_dirty());
        assert_eq!(store.snapshot().theme, ApplicationTheme::Light);
        assert_eq!(store.snapshot().sidebar_width, 280);

        vm.reload().unwrap();
        assert_eq!(vm.current().theme, ApplicationTheme::Light);
        assert_eq!(vm.current().sidebar_width, 280);
        assert!(!vm.is_dirty());
    }

    #[test]
    fn apply_failure_keeps_dirty_for_retry() {
        let store = Arc::new(FailNTimesStore::new(AppSettings::default(), 1));
        let mut vm = SettingsViewModel::new(store.clone()).unwrap();
        vm.stage(|s| s.theme = ApplicationTheme::Dark);
        let err = vm.apply().unwrap_err();
        assert!(matches!(err, SettingsError::Io(_)));
        assert!(vm.is_dirty());
        assert_eq!(vm.current().theme, ApplicationTheme::Dark);

        vm.apply().unwrap();
        assert!(!vm.is_dirty());
        assert_eq!(store.inner.snapshot().theme, ApplicationTheme::Dark);
    }

    #[test]
    fn failed_setter_after_stage_preserves_dirty() {
        let store = Arc::new(FailNTimesStore::new(AppSettings::default(), 1));
        let mut vm = SettingsViewModel::new(store.clone()).unwrap();
        vm.stage(|s| s.sidebar_width = 280);
        assert!(vm.is_dirty());

        let err = vm.set_theme(ApplicationTheme::Dark).unwrap_err();
        assert!(matches!(err, SettingsError::Io(_)));
        assert!(
            vm.is_dirty(),
            "staged edits must stay dirty after failed immediate persist"
        );
        assert_eq!(vm.current().theme, ApplicationTheme::System);
        assert_eq!(vm.current().sidebar_width, 280);
        assert_eq!(store.inner.snapshot().sidebar_width, 320);

        vm.apply().unwrap();
        assert!(!vm.is_dirty());
        assert_eq!(store.inner.snapshot().sidebar_width, 280);
        assert_eq!(store.inner.snapshot().theme, ApplicationTheme::System);
    }

    #[test]
    fn reload_discards_unapplied_stage() {
        let store = Arc::new(MemorySettingsStore::new(AppSettings::default()));
        let mut vm = SettingsViewModel::new(store.clone()).unwrap();
        vm.stage(|s| s.theme = ApplicationTheme::Dark);
        assert!(vm.is_dirty());

        vm.reload().unwrap();
        assert!(!vm.is_dirty());
        assert_eq!(vm.current().theme, ApplicationTheme::System);
        assert_eq!(store.snapshot().theme, ApplicationTheme::System);
    }
}
