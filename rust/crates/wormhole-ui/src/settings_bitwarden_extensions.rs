//! Settings → Extensions: Bitwarden vault + browser Fake glue (C# `SettingsViewModel` subset).
//!
//! Composes [`wormhole_secrets_win`] session / catalog / CLI pin / extension install Fakes
//! with [`SettingsViewModel`] and [`bitwarden_onboarding_notice`] — **no** live `bw` HTTP,
//! **no** GPUI chrome. Exposes enable/disable toggles, unlock status, install summaries,
//! and virtual-credential visibility (fail-closed when the vault is locked).
//!
//! Master passwords and session keys are never retained or logged; [`Debug`] omits paths and
//! install/sync error payloads.

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use wormhole_secrets_win::{
    configured_install_from_settings, demo_bitwarden_cache_entries, BitwardenCatalogProfile,
    BitwardenCliInstall, BitwardenCliInstallError, BitwardenCliInstallGlue,
    BitwardenCliInstallSettings, FakeBitwardenCliInstallSettings,
    BitwardenCredentialCatalogGlue, BitwardenExtensionInstall, BitwardenExtensionInstallGlue,
    BitwardenExtensionSettingsSnapshot, BitwardenSession, BitwardenSessionStatus,
    BitwardenUnlockResult, FakeBitwardenCliReleaseSource, FakeBitwardenCredentialCache,
    FakeBitwardenExtensionSettingsStore, FakeBitwardenSession, FakeExtensionInstallFs,
    FakeLocalCredentialCatalog,
};

use crate::bitwarden_onboarding_notice::{
    should_show_bitwarden_onboarding_notice, AppReleaseVersion,
};
use crate::settings::{
    AppSettings, BitwardenBrowserExtensionSource, SettingsError, SettingsStore, SettingsViewModel,
};

/// Host-facing Settings → Extensions Bitwarden bindings (metadata only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitwardenSettingsUiState {
    /// `EnableBitwardenVault` toggle.
    pub vault_enabled: bool,
    /// `EnableBitwardenBrowserExtension` toggle.
    pub browser_extension_enabled: bool,
    /// In-process CLI session lock state.
    pub session_status: BitwardenSessionStatus,
    /// UI-safe session line (never contains secrets).
    pub session_status_text: String,
    /// Whether virtual Bitwarden rows would appear in pickers (false when locked).
    pub virtual_profiles_available: bool,
    /// Count of virtual picker rows when unlocked (0 when locked / disabled).
    pub virtual_profile_count: usize,
    /// Local + virtual picker row count (local always counted when load succeeds).
    pub picker_profile_count: usize,
    /// CLI version / install summary for the settings card.
    pub cli_summary: String,
    /// Whether `BitwardenCliInstallError` / install error string is present on disk.
    pub cli_install_error_present: bool,
    /// Browser extension version / path summary.
    pub extension_summary: String,
    /// Last extension update status line when present.
    pub extension_update_status_present: bool,
    /// Credential sync status line when present.
    pub credential_sync_status_present: bool,
    /// Cached available credential count from settings (metadata).
    pub credential_available_count: Option<i32>,
    /// Onboarding notice should show for app 0.7.x (computed; does not persist).
    pub onboarding_notice_visible: bool,
}

impl Default for BitwardenSettingsUiState {
    fn default() -> Self {
        Self {
            vault_enabled: false,
            browser_extension_enabled: false,
            session_status: BitwardenSessionStatus::Locked,
            session_status_text: session_status_label(BitwardenSessionStatus::Locked).into(),
            virtual_profiles_available: false,
            virtual_profile_count: 0,
            picker_profile_count: 0,
            cli_summary: "Bitwarden CLI not installed".into(),
            cli_install_error_present: false,
            extension_summary: "Bitwarden browser extension not installed".into(),
            extension_update_status_present: false,
            credential_sync_status_present: false,
            credential_available_count: None,
            onboarding_notice_visible: false,
        }
    }
}

/// Scripted lab harness returned by [`with_fake_harness`].
pub struct BitwardenSettingsFakeHarness {
    /// CLI pinned-release fake (shared for scripted install tests).
    pub cli_releases: Arc<FakeBitwardenCliReleaseSource>,
}

impl fmt::Debug for BitwardenSettingsFakeHarness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BitwardenSettingsFakeHarness")
            .field("cli_releases", &"<FakeBitwardenCliReleaseSource>")
            .finish()
    }
}

/// Settings Extensions orchestrator — Fake session/catalog/install + settings VM only.
pub struct BitwardenSettingsExtensionsGlue {
    settings: SettingsViewModel,
    session: FakeBitwardenSession,
    local: FakeLocalCredentialCatalog,
    cache: FakeBitwardenCredentialCache,
    cli_settings: FakeBitwardenCliInstallSettings,
    cli_releases: Arc<FakeBitwardenCliReleaseSource>,
    ext_settings: FakeBitwardenExtensionSettingsStore,
    ext_fs: FakeExtensionInstallFs,
    cli_install_root: PathBuf,
    cli_download_root: PathBuf,
    ext_install_root: PathBuf,
    app_version: AppReleaseVersion,
    ui: BitwardenSettingsUiState,
}

impl fmt::Debug for BitwardenSettingsExtensionsGlue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BitwardenSettingsExtensionsGlue")
            .field("ui", &self.ui)
            .field("app_version", &self.app_version)
            .field("session", &self.session)
            .field("cache", &self.cache)
            .finish_non_exhaustive()
    }
}

impl BitwardenSettingsExtensionsGlue {
    /// Construct glue over an existing settings VM + injectable Fakes.
    pub fn new(
        settings: SettingsViewModel,
        session: FakeBitwardenSession,
        cache: FakeBitwardenCredentialCache,
        cli_releases: Arc<FakeBitwardenCliReleaseSource>,
        cli_install_root: PathBuf,
        cli_download_root: PathBuf,
        ext_install_root: PathBuf,
        app_version: AppReleaseVersion,
    ) -> Self {
        let mut glue = Self {
            settings,
            session,
            local: FakeLocalCredentialCatalog::new(),
            cache,
            cli_settings: FakeBitwardenCliInstallSettings::new(),
            cli_releases,
            ext_settings: FakeBitwardenExtensionSettingsStore::new(),
            ext_fs: FakeExtensionInstallFs::new(),
            cli_install_root,
            cli_download_root,
            ext_install_root,
            app_version,
            ui: BitwardenSettingsUiState::default(),
        };
        glue.sync_install_stores_from_settings();
        glue.refresh_ui_state();
        glue
    }

    /// Lab harness: memory settings store + demo cache + lab CLI pin + unlockable session.
    pub fn with_fake_harness(
        store: Arc<dyn SettingsStore>,
        app_version: AppReleaseVersion,
        cli_install_root: PathBuf,
        cli_download_root: PathBuf,
        ext_install_root: PathBuf,
    ) -> Result<(Self, BitwardenSettingsFakeHarness), SettingsError> {
        let settings = SettingsViewModel::new(store)?;
        let session = FakeBitwardenSession::with_session_key("lab-session-token");
        let cache = FakeBitwardenCredentialCache::with_demo_entries();
        let cli_releases = Arc::new(FakeBitwardenCliReleaseSource::lab_default());
        let glue = Self::new(
            settings,
            session,
            cache,
            Arc::clone(&cli_releases),
            cli_install_root,
            cli_download_root,
            ext_install_root,
            app_version,
        );
        let harness = BitwardenSettingsFakeHarness { cli_releases };
        Ok((glue, harness))
    }

    /// Borrow current UI-facing state.
    pub fn ui_state(&self) -> &BitwardenSettingsUiState {
        &self.ui
    }

    /// Borrow the settings VM (persist toggles / install metadata).
    pub fn settings(&self) -> &SettingsViewModel {
        &self.settings
    }

    /// Mutable settings VM (advanced hosts).
    pub fn settings_mut(&mut self) -> &mut SettingsViewModel {
        &mut self.settings
    }

    /// Borrow the session fake (tests).
    pub fn session(&self) -> &FakeBitwardenSession {
        &self.session
    }

    /// Mutable session fake (tests).
    #[cfg(test)]
    pub fn session_mut(&mut self) -> &mut FakeBitwardenSession {
        &mut self.session
    }

    /// Replace local credential catalog seed (metadata only).
    pub fn set_local_profiles(&mut self, profiles: Vec<BitwardenCatalogProfile>) {
        self.local = FakeLocalCredentialCatalog::with_profiles(profiles);
        self.refresh_ui_state();
    }

    /// Recompute UI summaries from settings + session + catalog glue.
    pub fn refresh_ui_state(&mut self) {
        self.sync_install_stores_from_settings();
        let app = self.settings.current().clone();
        let session_status = self.session.status();
        let catalog = self.catalog_glue(app.enable_bitwarden_vault);
        let picker_count = catalog
            .picker_profiles()
            .map(|rows| rows.len())
            .unwrap_or(0);
        let virtual_count = if app.enable_bitwarden_vault
            && session_status == BitwardenSessionStatus::Unlocked
        {
            count_virtual_profiles(&catalog).unwrap_or(0)
        } else {
            0
        };
        let virtual_available =
            app.enable_bitwarden_vault && session_status == BitwardenSessionStatus::Unlocked;

        self.ui = BitwardenSettingsUiState {
            vault_enabled: app.enable_bitwarden_vault,
            browser_extension_enabled: app.enable_bitwarden_browser_extension,
            session_status,
            session_status_text: session_status_label(session_status).into(),
            virtual_profiles_available: virtual_available,
            virtual_profile_count: virtual_count,
            picker_profile_count: picker_count,
            cli_summary: cli_summary_from_settings(&app, &self.cli_settings),
            cli_install_error_present: app
                .bitwarden_cli_install_error
                .as_ref()
                .is_some_and(|s| !s.trim().is_empty()),
            extension_summary: extension_summary_from_settings(&app),
            extension_update_status_present: app
                .bitwarden_browser_extension_last_update_status
                .as_ref()
                .is_some_and(|s| !s.trim().is_empty()),
            credential_sync_status_present: app
                .bitwarden_credential_last_sync_status
                .as_ref()
                .is_some_and(|s| !s.trim().is_empty()),
            credential_available_count: app.bitwarden_credential_available_count,
            onboarding_notice_visible: should_show_bitwarden_onboarding_notice(
                &app,
                self.app_version,
            ),
        };
    }

    /// Enable or disable the Bitwarden vault toggle (persists immediately).
    pub fn set_vault_enabled(&mut self, enabled: bool) -> Result<(), SettingsError> {
        if self.settings.current().enable_bitwarden_vault == enabled {
            return Ok(());
        }
        self.settings.stage(|s| s.enable_bitwarden_vault = enabled);
        self.settings.apply()?;
        if !enabled {
            self.session.lock();
        }
        self.refresh_ui_state();
        Ok(())
    }

    /// Enable or disable the browser extension toggle (persists immediately).
    pub fn set_browser_extension_enabled(&mut self, enabled: bool) -> Result<(), SettingsError> {
        if self.settings.current().enable_bitwarden_browser_extension == enabled {
            return Ok(());
        }
        self.settings.stage(|s| s.enable_bitwarden_browser_extension = enabled);
        self.settings.apply()?;
        self.refresh_ui_state();
        Ok(())
    }

    /// Attempt vault unlock (memory-only session key; password never retained).
    pub fn unlock_vault(&mut self, master_password: &str) -> BitwardenUnlockResult {
        let result = self.session.unlock(master_password);
        self.refresh_ui_state();
        result
    }

    /// Clear any held session key.
    pub fn lock_vault(&mut self) {
        self.session.lock();
        self.refresh_ui_state();
    }

    /// Picker profiles via catalog glue (virtual rows omitted when locked — fail-closed).
    pub fn picker_profiles(
        &self,
    ) -> Result<Vec<BitwardenCatalogProfile>, wormhole_secrets_win::BitwardenCatalogError> {
        self.catalog_glue(self.settings.current().enable_bitwarden_vault)
            .picker_profiles()
    }

    /// Count virtual-only picker rows (0 when vault disabled or locked).
    pub fn virtual_profile_count(&self) -> usize {
        if !self.settings.current().enable_bitwarden_vault
            || self.session.status() != BitwardenSessionStatus::Unlocked
        {
            return 0;
        }
        count_virtual_profiles(&self.catalog_glue(true)).unwrap_or(0)
    }

    /// Install the lab-pinned CLI release (Fake digest + stage under injectable roots).
    pub fn install_cli_pinned(
        &mut self,
    ) -> Result<BitwardenCliInstall, BitwardenCliInstallError> {
        self.sync_install_stores_from_settings();
        let cli_settings =
            FakeBitwardenCliInstallSettings::with_settings(self.cli_settings.snapshot());
        let glue = BitwardenCliInstallGlue::with_roots(
            cli_settings,
            (*self.cli_releases).clone(),
            self.cli_install_root.clone(),
            self.cli_download_root.clone(),
        );
        let install = glue.install_pinned()?;
        self.apply_cli_install_to_settings(&install)?;
        self.refresh_ui_state();
        Ok(install)
    }

    /// Read configured CLI install row from current settings + disk check.
    pub fn configured_cli_install(&self) -> Option<BitwardenCliInstall> {
        let cli_settings =
            FakeBitwardenCliInstallSettings::with_settings(self.cli_settings.snapshot());
        let glue = BitwardenCliInstallGlue::with_roots(
            cli_settings,
            (*self.cli_releases).clone(),
            self.cli_install_root.clone(),
            self.cli_download_root.clone(),
        );
        glue.configured_install()
    }

    /// Extension install snapshot from settings-backed store + Fake FS.
    pub fn configured_extension_install(&self) -> Option<BitwardenExtensionInstall> {
        let store = FakeBitwardenExtensionSettingsStore::new();
        store.set_snapshot(extension_snapshot_from_app(self.settings.current()));
        let glue = BitwardenExtensionInstallGlue::new(
            store,
            self.ext_fs.clone(),
            self.ext_install_root.clone(),
        );
        glue.configured_install()
    }

    fn catalog_glue(
        &self,
        vault_enabled: bool,
    ) -> BitwardenCredentialCatalogGlue<
        &FakeLocalCredentialCatalog,
        &FakeBitwardenCredentialCache,
        &FakeBitwardenSession,
    > {
        BitwardenCredentialCatalogGlue::new(
            &self.local,
            &self.cache,
            &self.session,
            vault_enabled,
        )
    }

    fn sync_install_stores_from_settings(&mut self) {
        let app = self.settings.current();
        self.cli_settings = FakeBitwardenCliInstallSettings::with_settings(cli_settings_from_app(
            app,
        ));
        self.ext_settings
            .set_snapshot(extension_snapshot_from_app(app));
    }

    fn apply_cli_install_to_settings(
        &mut self,
        install: &BitwardenCliInstall,
    ) -> Result<(), BitwardenCliInstallError> {
        let snap = self.cli_settings.snapshot();
        let status = format!("Installed official Bitwarden CLI {}.", install.version);
        self.settings.stage(|s| {
            s.bitwarden_cli_path = install.executable_path.to_string_lossy().into_owned();
            s.bitwarden_cli_version = Some(install.version.clone());
            s.bitwarden_cli_sha256 = install.sha256.clone().or(snap.sha256.clone());
            s.bitwarden_cli_asset_name = install.asset_name.clone().or(snap.asset_name.clone());
            s.bitwarden_cli_download_url = install
                .download_url
                .clone()
                .or(snap.download_url.clone());
            s.bitwarden_cli_install_status = Some(status);
            s.bitwarden_cli_install_error = None;
        });
        self.settings
            .apply()
            .map_err(|_| BitwardenCliInstallError::SettingsPersist)?;
        self.cli_settings = FakeBitwardenCliInstallSettings::with_settings(
            BitwardenCliInstallSettings {
                cli_path: install.executable_path.to_string_lossy().into_owned(),
                version: Some(install.version.clone()),
                sha256: install.sha256.clone(),
                asset_name: install.asset_name.clone(),
                download_url: install.download_url.clone(),
            },
        );
        Ok(())
    }

    /// Override app release version gate (tests / host refresh).
    #[cfg(test)]
    pub fn set_app_version(&mut self, version: AppReleaseVersion) {
        self.app_version = version;
    }
}

fn session_status_label(status: BitwardenSessionStatus) -> &'static str {
    match status {
        BitwardenSessionStatus::Locked => "Vault locked",
        BitwardenSessionStatus::Unlocked => "Vault unlocked",
    }
}

fn cli_settings_from_app(app: &AppSettings) -> BitwardenCliInstallSettings {
    BitwardenCliInstallSettings {
        cli_path: app.bitwarden_cli_path.clone(),
        version: app.bitwarden_cli_version.clone(),
        sha256: app.bitwarden_cli_sha256.clone(),
        asset_name: app.bitwarden_cli_asset_name.clone(),
        download_url: app.bitwarden_cli_download_url.clone(),
    }
}

fn extension_snapshot_from_app(app: &AppSettings) -> BitwardenExtensionSettingsSnapshot {
    BitwardenExtensionSettingsSnapshot {
        enable_bitwarden_browser_extension: app.enable_bitwarden_browser_extension,
        source: extension_source_from_app(app.bitwarden_browser_extension_source),
        version: app.bitwarden_browser_extension_version.clone(),
        path: app
            .bitwarden_browser_extension_path
            .as_ref()
            .map(PathBuf::from),
        sha256: app.bitwarden_browser_extension_sha256.clone(),
        asset_name: app.bitwarden_browser_extension_asset_name.clone(),
        download_url: app.bitwarden_browser_extension_download_url.clone(),
        last_update_check_utc: app.bitwarden_browser_extension_last_update_check_utc.clone(),
        last_update_status: app.bitwarden_browser_extension_last_update_status.clone(),
        last_update_error: app.bitwarden_browser_extension_last_update_error.clone(),
        available_version: app.bitwarden_browser_extension_available_version.clone(),
    }
}

fn extension_source_from_app(
    source: BitwardenBrowserExtensionSource,
) -> wormhole_secrets_win::BitwardenBrowserExtensionSource {
    use wormhole_secrets_win::BitwardenBrowserExtensionSource as S;
    match source {
        BitwardenBrowserExtensionSource::OfficialGitHub => S::OfficialGitHub,
        BitwardenBrowserExtensionSource::ManualZip => S::ManualZip,
        BitwardenBrowserExtensionSource::ManualFolder => S::ManualFolder,
    }
}

fn cli_summary_from_settings(
    app: &AppSettings,
    cli_settings: &FakeBitwardenCliInstallSettings,
) -> String {
    if let Some(status) = app
        .bitwarden_cli_install_status
        .as_ref()
        .filter(|s| !s.trim().is_empty())
    {
        return status.clone();
    }
    if let Some(version) = app.bitwarden_cli_version.as_ref().filter(|v| !v.trim().is_empty()) {
        return format!("Bitwarden CLI {version}");
    }
    let snap = cli_settings.snapshot();
    if let Some(path) = wormhole_secrets_win::resolve_executable_path(&snap.cli_path) {
        let install = configured_install_from_settings(&snap, path);
        return format!("Bitwarden CLI {}", install.version);
    }
    "Bitwarden CLI not installed".into()
}

fn extension_summary_from_settings(app: &AppSettings) -> String {
    if let Some(status) = app
        .bitwarden_browser_extension_last_update_status
        .as_ref()
        .filter(|s| !s.trim().is_empty())
    {
        return status.clone();
    }
    if let Some(version) = app
        .bitwarden_browser_extension_version
        .as_ref()
        .filter(|v| !v.trim().is_empty())
    {
        return format!("Bitwarden extension {version}");
    }
    if app
        .bitwarden_browser_extension_path
        .as_ref()
        .is_some_and(|p| !p.trim().is_empty())
    {
        return "Bitwarden extension installed".into();
    }
    "Bitwarden browser extension not installed".into()
}

fn count_virtual_profiles(
    catalog: &BitwardenCredentialCatalogGlue<
        &FakeLocalCredentialCatalog,
        &FakeBitwardenCredentialCache,
        &FakeBitwardenSession,
    >,
) -> Result<usize, wormhole_secrets_win::BitwardenCatalogError> {
    Ok(catalog
        .picker_profiles()?
        .into_iter()
        .filter(|p| p.is_virtual_bitwarden)
        .count())
}

/// Test helper: demo cache entry count (metadata only).
pub fn demo_virtual_cache_entry_count() -> usize {
    demo_bitwarden_cache_entries().len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::MemorySettingsStore;
    use wormhole_domain::ProtocolType;
    use wormhole_secrets_win::BitwardenSession;
    use wormhole_secrets_win::BITWARDEN_CLI_SESSION_GAP;

    fn temp_roots() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let cli_install = dir.path().join("cli-install");
        let cli_download = dir.path().join("cli-download");
        let ext_install = dir.path().join("ext-install");
        (dir, cli_install, cli_download, ext_install)
    }

    fn harness_v07() -> (
        BitwardenSettingsExtensionsGlue,
        BitwardenSettingsFakeHarness,
        tempfile::TempDir,
    ) {
        let (dir, cli_install, cli_download, ext_install) = temp_roots();
        let (glue, harness) = BitwardenSettingsExtensionsGlue::with_fake_harness(
            Arc::new(MemorySettingsStore::new(AppSettings::default())),
            AppReleaseVersion::new(0, 7),
            cli_install,
            cli_download,
            ext_install,
        )
        .expect("harness");
        (glue, harness, dir)
    }

    #[test]
    fn enable_vault_and_unlock_exposes_virtual_profiles() {
        let (mut glue, _, _dir) = harness_v07();
        assert!(!glue.ui_state().vault_enabled);
        assert_eq!(glue.ui_state().virtual_profile_count, 0);

        glue.set_vault_enabled(true).unwrap();
        assert!(glue.ui_state().vault_enabled);
        // Locked — virtual rows still fail-closed.
        assert_eq!(glue.ui_state().virtual_profile_count, 0);
        assert!(!glue.ui_state().virtual_profiles_available);

        let unlock = glue.unlock_vault("lab-master-password");
        assert!(unlock.unlocked);
        assert_eq!(glue.ui_state().session_status, BitwardenSessionStatus::Unlocked);
        let expected_virtuals = demo_virtual_cache_entry_count() * 3; // SSH/RDP/VNC per entry
        assert_eq!(glue.ui_state().virtual_profile_count, expected_virtuals);
        assert!(glue.ui_state().virtual_profiles_available);
        assert_eq!(glue.session().unlock_calls(), 1);
    }

    #[test]
    fn locked_vault_omits_virtual_rows_but_keeps_local() {
        let (mut glue, _, _dir) = harness_v07();
        let local = BitwardenCatalogProfile::local_password(
            uuid::Uuid::new_v4(),
            "Local Only",
            ProtocolType::Ssh,
            Some("user".into()),
        );
        glue.set_local_profiles(vec![local]);
        glue.set_vault_enabled(true).unwrap();

        let rows = glue.picker_profiles().unwrap();
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].is_virtual_bitwarden);
        assert_eq!(glue.virtual_profile_count(), 0);
    }

    #[test]
    fn disable_vault_locks_session_and_clears_virtuals() {
        let (mut glue, _, _dir) = harness_v07();
        glue.set_vault_enabled(true).unwrap();
        glue.unlock_vault("pw");
        assert!(glue.ui_state().virtual_profile_count > 0);

        glue.set_vault_enabled(false).unwrap();
        assert_eq!(glue.ui_state().virtual_profile_count, 0);
        assert_eq!(glue.session().status(), BitwardenSessionStatus::Locked);
        assert!(glue.session().lock_calls() >= 1);
    }

    #[test]
    fn empty_master_password_unlock_fails_closed() {
        let (mut glue, _, _dir) = harness_v07();
        glue.set_vault_enabled(true).unwrap();
        let result = glue.unlock_vault("   ");
        assert!(!result.unlocked);
        assert_eq!(glue.ui_state().session_status, BitwardenSessionStatus::Locked);
    }

    #[test]
    fn install_cli_pinned_updates_settings_summary() {
        let (mut glue, _, _dir) = harness_v07();
        let install = glue.install_cli_pinned().unwrap();
        assert!(!install.version.is_empty());
        glue.refresh_ui_state();
        assert!(
            glue.ui_state()
                .cli_summary
                .to_ascii_lowercase()
                .contains("installed")
        );
        assert!(!glue.ui_state().cli_install_error_present);
        let app = glue.settings().current();
        assert!(app.bitwarden_cli_install_status.as_ref().is_some());
        assert!(app.bitwarden_cli_version.as_ref().is_some());
    }

    #[test]
    fn browser_extension_toggle_persists() {
        let (mut glue, _, _dir) = harness_v07();
        glue.set_browser_extension_enabled(true).unwrap();
        assert!(glue.ui_state().browser_extension_enabled);
        assert!(glue.settings().current().enable_bitwarden_browser_extension);
    }

    #[test]
    fn debug_omits_paths_and_install_errors() {
        let (mut glue, _, _dir) = harness_v07();
        glue.settings_mut().stage(|s| {
            s.bitwarden_cli_path = r"C:\secret\bw.exe".into();
            s.bitwarden_cli_install_error = Some("token=super-secret".into());
            s.bitwarden_browser_extension_path = Some(r"C:\ext\vault".into());
        });
        glue.refresh_ui_state();
        let dbg = format!("{glue:?}");
        assert!(!dbg.contains(r"C:\secret"));
        assert!(!dbg.contains("super-secret"));
        assert!(!dbg.contains(r"C:\ext"));
        assert!(glue.ui_state().cli_install_error_present);
    }

    #[test]
    fn onboarding_notice_visible_only_on_07_with_pending() {
        let (dir, cli_install, cli_download, ext_install) = temp_roots();
        let mut settings = AppSettings::default();
        settings.bitwarden_onboarding_notice_pending_version = 1;
        let (mut glue, _) = BitwardenSettingsExtensionsGlue::with_fake_harness(
            Arc::new(MemorySettingsStore::new(settings)),
            AppReleaseVersion::new(0, 7),
            cli_install,
            cli_download,
            ext_install,
        )
        .unwrap();
        glue.refresh_ui_state();
        assert!(glue.ui_state().onboarding_notice_visible);

        glue.set_app_version(AppReleaseVersion::new(0, 8));
        glue.refresh_ui_state();
        assert!(!glue.ui_state().onboarding_notice_visible);
        drop(dir);
    }

    #[test]
    fn lock_vault_clears_virtual_availability() {
        let (mut glue, _, _dir) = harness_v07();
        glue.set_vault_enabled(true).unwrap();
        glue.unlock_vault("pw");
        assert!(glue.ui_state().virtual_profiles_available);
        glue.lock_vault();
        assert!(!glue.ui_state().virtual_profiles_available);
        assert_eq!(glue.ui_state().virtual_profile_count, 0);
    }

    #[test]
    fn cli_gap_message_is_safe_ui_copy() {
        let (mut glue, _, _dir) = harness_v07();
        glue.session_mut().set_allow_unlock(false);
        glue.set_vault_enabled(true).unwrap();
        let result = glue.unlock_vault("pw");
        assert!(!result.unlocked);
        assert!(result.message.contains(BITWARDEN_CLI_SESSION_GAP));
        assert!(!result.message.contains("pw"));
    }
}
