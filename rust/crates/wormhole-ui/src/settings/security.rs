//! Settings → Security: app-lock mode / Hello fallback / idle-timeout VM glue.
//!
//! Lab scope: VM + Fake glue only. C# parity: `ViewModels/SettingsViewModel.cs`
//! Security section (`AppAuthenticationModeIndex` / `AppAuthenticationHelloFallback`
//! / `AppAuthenticationIdleTimeout` with the fixed `IdleTimeoutOptions` preset list
//! `[null, 1, 5, 15, 30, 60]`). There is **no** WinRT Hello consent and **no**
//! `GetLastInputInfo` here — Hello probing and OS idle sampling stay host
//! responsibilities (`wormhole-secrets-win::os_idle`).
//!
//! The idle-timeout policy mirrors the `AppIdleLockGlue::should_lock` fail-closed
//! table from `wormhole-secrets-win`:
//!
//! | Mode / timeout | Effective policy |
//! |---|---|
//! | [`AppAuthenticationMode::Disabled`] | never locks |
//! | `timeout == None` (UI "Never") | never locks |
//! | `timeout <= 0` (hostile / corrupt) | **fail closed** → lock when auth enabled |
//! | `timeout >= 1` | lock after `timeout` minutes idle |
//!
//! The VM restricts the idle timeout to the C# preset list ([`IDLE_TIMEOUT_PRESETS`]);
//! a hostile value (zero / negative / not in the preset set) is rejected, an error is
//! surfaced, and it is **not** persisted. A hostile value already on disk (corrupt
//! JSON) is clamped to `None` ("Never") at VM construction — never round-tripped.
//! Hello fallback only applies when the mode is [`AppAuthenticationMode::WindowsHello`]
//! (C# `ShowWindowsHelloFallback`), but the selection is persisted regardless of mode,
//! exactly like C#.
//!
//! No secrets live here: the mode / labels are not credential material, and `Debug`
//! shows mode-adjacent state only.

use std::fmt;
use std::sync::Arc;

use thiserror::Error;

use super::model::{AppAuthenticationFallbackMethod, AppAuthenticationMode, AppSettings};
use super::store::{MemorySettingsStore, SettingsError, SettingsStore};

/// Fixed idle-timeout preset list (C# `IdleTimeoutOptions`).
pub const IDLE_TIMEOUT_PRESETS: [Option<i32>; 6] =
    [None, Some(1), Some(5), Some(15), Some(30), Some(60)];

/// Effective idle-lock policy for a mode + timeout combination.
///
/// Mirrors `AppIdleLockGlue::should_lock` (fail-closed table in the module header).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdleLockPolicy {
    /// `Disabled` mode or "Never" timeout — never lock.
    NeverLock,
    /// Positive timeout — lock after that many minutes idle.
    LockAfterMinutes(i32),
    /// Hostile / corrupt non-positive timeout with auth enabled — fail-closed lock.
    FailClosedLock,
}

/// Fail-closed entry gate for idle-timeout changes.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SecuritySettingsError {
    /// Value not in [`IDLE_TIMEOUT_PRESETS`] (zero / negative / absurd).
    #[error("idle timeout must be one of the presets, \"Never\", 1, 5, 15, 30, 60 (got {0:?})")]
    IdleTimeout(Option<i32>),
    #[error("settings load error: {0}")]
    Load(SettingsError),
    #[error("settings persist error: {0}")]
    Persist(SettingsError),
}

/// Validate an idle timeout against the C# preset list (fail-closed).
///
/// `None` ("Never") and the positive presets pass; zero, negatives, and values
/// outside the preset set are rejected — they must never reach the store.
pub fn validate_idle_timeout(timeout: Option<i32>) -> Result<Option<i32>, SecuritySettingsError> {
    match timeout {
        None => Ok(None),
        Some(n) if IDLE_TIMEOUT_PRESETS.contains(&Some(n)) => Ok(Some(n)),
        Some(n) => Err(SecuritySettingsError::IdleTimeout(Some(n))),
    }
}

/// Effective lock policy (C# `AppIdleLockGlue` semantics; fail-closed on hostile data).
pub fn effective_idle_policy(
    mode: AppAuthenticationMode,
    timeout_minutes: Option<i32>,
) -> IdleLockPolicy {
    match mode {
        AppAuthenticationMode::Disabled => IdleLockPolicy::NeverLock,
        _ => match timeout_minutes {
            None => IdleLockPolicy::NeverLock,
            Some(n) if n <= 0 => IdleLockPolicy::FailClosedLock,
            Some(n) => IdleLockPolicy::LockAfterMinutes(n),
        },
    }
}

/// Whether the Hello fallback selection is visible / relevant (C# `ShowWindowsHelloFallback`).
pub fn fallback_relevant(mode: AppAuthenticationMode) -> bool {
    mode == AppAuthenticationMode::WindowsHello
}

/// UI-facing Security section state (subset of C# `SettingsViewModel` bindings).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecuritySettingsUiState {
    /// `AppAuthenticationMode` (0=Disabled).
    pub mode: AppAuthenticationMode,
    /// `AppAuthenticationHelloFallback` (shown only for WindowsHello).
    pub hello_fallback: AppAuthenticationFallbackMethod,
    /// `AppAuthenticationIdleTimeout` (`None` = "Never").
    pub idle_timeout_minutes: Option<i32>,
    /// `IsAppAuthenticationEnabled` (= mode != Disabled).
    pub is_enabled: bool,
    /// `ShowWindowsHelloFallback` (= mode == WindowsHello).
    pub show_hello_fallback: bool,
    /// Effective lock policy for the current selection.
    pub policy: IdleLockPolicy,
    /// Last error copy (UI-safe; never secret material).
    pub last_error: Option<String>,
}

impl Default for SecuritySettingsUiState {
    fn default() -> Self {
        Self {
            mode: AppAuthenticationMode::Disabled,
            hello_fallback: AppAuthenticationFallbackMethod::Pin,
            idle_timeout_minutes: None,
            is_enabled: false,
            show_hello_fallback: false,
            policy: IdleLockPolicy::NeverLock,
            last_error: None,
        }
    }
}

/// Settings → Security view-model: mode / Hello fallback / idle timeout over a
/// [`SettingsStore`], fail-closed at every gate.
pub struct SecuritySettingsVm {
    store: Arc<dyn SettingsStore>,
    mode: AppAuthenticationMode,
    hello_fallback: AppAuthenticationFallbackMethod,
    idle_timeout_minutes: Option<i32>,
    last_error: Option<String>,
}

impl fmt::Debug for SecuritySettingsVm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Mode / labels only — never secret material (this VM holds none).
        f.debug_struct("SecuritySettingsVm")
            .field("mode", &self.mode)
            .field("hello_fallback", &self.hello_fallback)
            .field("idle_timeout_minutes", &self.idle_timeout_minutes)
            .field("last_error", &self.last_error)
            .field("store", &"<SettingsStore>")
            .finish()
    }
}

impl SecuritySettingsVm {
    /// Load the current settings and build the VM.
    pub fn new(store: Arc<dyn SettingsStore>) -> Result<Self, SecuritySettingsError> {
        let current = store.load().map_err(SecuritySettingsError::Load)?;
        Ok(Self::from_settings(store, current))
    }

    /// Build over an explicit settings snapshot (skips the store read).
    ///
    /// A hostile idle timeout on disk is clamped to `None` ("Never") — never
    /// round-tripped. (C# `TimeoutMinutesToIndex` maps an unmatched value to
    /// index 3 = 15 minutes instead; this lab clamps fail-closed to `None` —
    /// see the module header table.)
    pub fn from_settings(store: Arc<dyn SettingsStore>, current: AppSettings) -> Self {
        let idle_timeout_minutes = validate_idle_timeout(current.app_authentication_idle_timeout_minutes)
            .unwrap_or(None);
        Self {
            store,
            mode: current.app_authentication_mode,
            hello_fallback: current.app_authentication_hello_fallback,
            idle_timeout_minutes,
            last_error: None,
        }
    }

    /// Current mode.
    pub fn mode(&self) -> AppAuthenticationMode {
        self.mode
    }

    /// Current Hello fallback selection.
    pub fn hello_fallback(&self) -> AppAuthenticationFallbackMethod {
        self.hello_fallback
    }

    /// Current idle timeout (`None` = "Never").
    pub fn idle_timeout_minutes(&self) -> Option<i32> {
        self.idle_timeout_minutes
    }

    /// `IsAppAuthenticationEnabled`.
    pub fn is_enabled(&self) -> bool {
        self.mode != AppAuthenticationMode::Disabled
    }

    /// `ShowWindowsHelloFallback`.
    pub fn show_hello_fallback(&self) -> bool {
        fallback_relevant(self.mode)
    }

    /// Effective lock policy for the current selection.
    pub fn policy(&self) -> IdleLockPolicy {
        effective_idle_policy(self.mode, self.idle_timeout_minutes)
    }

    /// Last error copy (UI-safe).
    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    /// Derived UI state.
    pub fn ui_state(&self) -> SecuritySettingsUiState {
        SecuritySettingsUiState {
            mode: self.mode,
            hello_fallback: self.hello_fallback,
            idle_timeout_minutes: self.idle_timeout_minutes,
            is_enabled: self.is_enabled(),
            show_hello_fallback: self.show_hello_fallback(),
            policy: self.policy(),
            last_error: self.last_error.clone(),
        }
    }

    /// Reload mode / fallback / timeout from the store (C# refresh paths).
    pub fn reload(&mut self) -> Result<(), SecuritySettingsError> {
        let current = self.store.load().map_err(SecuritySettingsError::Load)?;
        self.mode = current.app_authentication_mode;
        self.hello_fallback = current.app_authentication_hello_fallback;
        if let Ok(timeout) =
            validate_idle_timeout(current.app_authentication_idle_timeout_minutes)
        {
            self.idle_timeout_minutes = timeout;
        }
        Ok(())
    }

    /// Change the app-lock mode (C# `OnAppAuthenticationModeIndexChanged`).
    ///
    /// The idle timeout is preserved as-is (C# keeps the stored value; the policy
    /// ignores it while Disabled). Persist failure reverts the VM field.
    pub fn set_mode(&mut self, mode: AppAuthenticationMode) -> Result<(), SecuritySettingsError> {
        if self.mode == mode {
            return Ok(());
        }
        let before = self.mode;
        self.mode = mode;
        let result = self.save_doc();
        if result.is_err() {
            self.mode = before;
        }
        self.record_error(result.as_ref().err());
        result
    }

    /// Change the Hello fallback selection (C# `OnAppAuthenticationHelloFallbackIndexChanged`).
    ///
    /// Persisted regardless of mode (C# parity); only relevant for WindowsHello.
    pub fn set_hello_fallback(
        &mut self,
        fallback: AppAuthenticationFallbackMethod,
    ) -> Result<(), SecuritySettingsError> {
        if self.hello_fallback == fallback {
            return Ok(());
        }
        let before = self.hello_fallback;
        self.hello_fallback = fallback;
        let result = self.save_doc();
        if result.is_err() {
            self.hello_fallback = before;
        }
        self.record_error(result.as_ref().err());
        result
    }

    /// Change the idle timeout (C# `ChangeIdleTimeoutAsync`; admin-reauth is the
    /// host's job). Fail-closed: zero / negative / non-preset values are rejected
    /// and **not** persisted.
    pub fn set_idle_timeout(
        &mut self,
        timeout: Option<i32>,
    ) -> Result<(), SecuritySettingsError> {
        let validated = match validate_idle_timeout(timeout) {
            Ok(validated) => validated,
            Err(e) => {
                self.record_error(Some(&e));
                return Err(e);
            }
        };
        if self.idle_timeout_minutes == validated {
            return Ok(());
        }
        let before = self.idle_timeout_minutes;
        self.idle_timeout_minutes = validated;
        let result = self.save_doc();
        if result.is_err() {
            self.idle_timeout_minutes = before;
        }
        self.record_error(result.as_ref().err());
        result
    }

    fn save_doc(&mut self) -> Result<(), SecuritySettingsError> {
        let mut current = self.store.load().map_err(SecuritySettingsError::Load)?;
        current.app_authentication_mode = self.mode;
        current.app_authentication_hello_fallback = self.hello_fallback;
        current.app_authentication_idle_timeout_minutes = self.idle_timeout_minutes;
        self.store.save(&current).map_err(SecuritySettingsError::Persist)
    }

    fn record_error(&mut self, error: Option<&SecuritySettingsError>) {
        self.last_error = error.map(ToString::to_string);
    }
}

/// Lab harness: the memory settings store behind the VM (assertions).
pub struct SecuritySettingsFakeHarness {
    /// The memory settings store (assertions).
    pub store: Arc<MemorySettingsStore>,
}

impl fmt::Debug for SecuritySettingsFakeHarness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecuritySettingsFakeHarness")
            .field("store", &"<MemorySettingsStore>")
            .finish()
    }
}

/// Composed security settings glue: [`SecuritySettingsVm`] + cached UI state.
pub struct SecuritySettingsGlue {
    vm: SecuritySettingsVm,
    ui: SecuritySettingsUiState,
}

impl fmt::Debug for SecuritySettingsGlue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecuritySettingsGlue")
            .field("vm", &self.vm)
            .field("ui", &self.ui)
            .finish()
    }
}

impl SecuritySettingsGlue {
    /// Glue over an existing VM (cached UI state).
    pub fn new(vm: SecuritySettingsVm) -> Self {
        let ui = vm.ui_state();
        Self { vm, ui }
    }

    /// Lab harness over a seeded settings snapshot.
    pub fn with_fake_harness(seed: AppSettings) -> (Self, SecuritySettingsFakeHarness) {
        let store = Arc::new(MemorySettingsStore::new(seed));
        let harness = SecuritySettingsFakeHarness {
            store: Arc::clone(&store),
        };
        let vm = SecuritySettingsVm::from_settings(
            Arc::clone(&store) as Arc<dyn SettingsStore>,
            store.snapshot(),
        );
        (Self::new(vm), harness)
    }

    /// Borrow current UI state.
    pub fn ui_state(&self) -> &SecuritySettingsUiState {
        &self.ui
    }

    /// Borrow the view-model.
    pub fn vm(&self) -> &SecuritySettingsVm {
        &self.vm
    }

    /// Mutable view-model (advanced hosts / tests).
    pub fn vm_mut(&mut self) -> &mut SecuritySettingsVm {
        &mut self.vm
    }

    /// Refresh cached UI state after external mutations.
    pub fn refresh_ui_state(&mut self) {
        self.ui = self.vm.ui_state();
    }

    /// Set the mode (delegates; refreshes UI state).
    pub fn set_mode(&mut self, mode: AppAuthenticationMode) -> Result<(), SecuritySettingsError> {
        let result = self.vm.set_mode(mode);
        self.refresh_ui_state();
        result
    }

    /// Set the Hello fallback (delegates; refreshes UI state).
    pub fn set_hello_fallback(
        &mut self,
        fallback: AppAuthenticationFallbackMethod,
    ) -> Result<(), SecuritySettingsError> {
        let result = self.vm.set_hello_fallback(fallback);
        self.refresh_ui_state();
        result
    }

    /// Set the idle timeout (delegates; refreshes UI state).
    pub fn set_idle_timeout(
        &mut self,
        timeout: Option<i32>,
    ) -> Result<(), SecuritySettingsError> {
        let result = self.vm.set_idle_timeout(timeout);
        self.refresh_ui_state();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn harness() -> (SecuritySettingsGlue, SecuritySettingsFakeHarness) {
        SecuritySettingsGlue::with_fake_harness(AppSettings::default())
    }

    /// Store whose next `n` saves fail (persist-failure injection).
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
    fn defaults_are_disabled_with_default_timeout() {
        let (glue, _) = harness();
        assert_eq!(glue.vm().mode(), AppAuthenticationMode::Disabled);
        assert!(!glue.ui_state().is_enabled);
        // C# AppSettings default: 15-minute idle timeout (ignored while Disabled).
        assert_eq!(glue.vm().idle_timeout_minutes(), Some(15));
        assert_eq!(glue.vm().policy(), IdleLockPolicy::NeverLock);
        assert!(!glue.ui_state().show_hello_fallback);
    }

    #[test]
    fn presets_match_csharp_list() {
        assert_eq!(
            IDLE_TIMEOUT_PRESETS,
            [None, Some(1), Some(5), Some(15), Some(30), Some(60)]
        );
    }

    #[test]
    fn valid_timeouts_validate_and_persist() {
        let (mut glue, harness) = harness();
        for preset in [Some(1), Some(5), Some(15), Some(30), Some(60)] {
            glue.set_idle_timeout(preset).unwrap();
            assert_eq!(harness.store.snapshot().app_authentication_idle_timeout_minutes, preset);
            assert_eq!(glue.vm().idle_timeout_minutes(), preset);
        }
        glue.set_idle_timeout(None).unwrap();
        assert_eq!(harness.store.snapshot().app_authentication_idle_timeout_minutes, None);
    }

    #[test]
    fn hostile_timeouts_rejected_fail_closed_not_persisted() {
        // Default document carries 15 (C# default) — rejections must leave it intact.
        let (mut glue, harness) = harness();
        for hostile in [Some(0), Some(-1), Some(2), Some(90), Some(i32::MAX), Some(i32::MIN)] {
            let err = glue.set_idle_timeout(hostile).unwrap_err();
            assert!(matches!(err, SecuritySettingsError::IdleTimeout(_)));
            assert_eq!(harness.store.snapshot().app_authentication_idle_timeout_minutes, Some(15));
            assert_eq!(glue.vm().idle_timeout_minutes(), Some(15));
        }
        assert!(glue.vm().last_error().is_some());
    }

    #[test]
    fn hostile_stored_timeout_clamped_to_never() {
        for hostile in [Some(0), Some(-5), Some(2), Some(9999)] {
            let mut settings = AppSettings::default();
            settings.app_authentication_idle_timeout_minutes = hostile;
            let store = Arc::new(MemorySettingsStore::new(settings));
            let vm = SecuritySettingsVm::new(store).unwrap();
            assert_eq!(vm.idle_timeout_minutes(), None);
        }
    }

    #[test]
    fn reload_keeps_last_valid_timeout_when_disk_turns_hostile() {
        let (mut glue, harness) = harness();
        glue.set_idle_timeout(Some(30)).unwrap();
        // Corrupted out-of-band to a hostile value (zero).
        let mut external = harness.store.snapshot();
        external.app_authentication_idle_timeout_minutes = Some(0);
        harness.store.save(&external).unwrap();
        glue.vm_mut().reload().unwrap();
        // Fail-closed: hostile value never adopted; last valid timeout survives.
        assert_eq!(glue.vm().idle_timeout_minutes(), Some(30));
        // The next save repairs the document from the valid VM field.
        glue.set_mode(AppAuthenticationMode::Pin).unwrap();
        assert_eq!(
            harness.store.snapshot().app_authentication_idle_timeout_minutes,
            Some(30)
        );
    }

    #[test]
    fn mode_change_persists_and_reflects_in_state() {
        let (mut glue, harness) = harness();
        glue.set_mode(AppAuthenticationMode::Pin).unwrap();
        assert_eq!(harness.store.snapshot().app_authentication_mode, AppAuthenticationMode::Pin);
        assert!(glue.ui_state().is_enabled);
        assert!(!glue.ui_state().show_hello_fallback);
        glue.set_mode(AppAuthenticationMode::WindowsHello).unwrap();
        assert!(glue.ui_state().show_hello_fallback);
        glue.set_mode(AppAuthenticationMode::Disabled).unwrap();
        assert!(!glue.ui_state().is_enabled);
        assert!(!glue.ui_state().show_hello_fallback);
    }

    #[test]
    fn fallback_persisted_regardless_of_mode() {
        let (mut glue, harness) = harness();
        glue.set_hello_fallback(AppAuthenticationFallbackMethod::Password).unwrap();
        assert_eq!(
            harness.store.snapshot().app_authentication_hello_fallback,
            AppAuthenticationFallbackMethod::Password
        );
        assert_eq!(glue.vm().hello_fallback(), AppAuthenticationFallbackMethod::Password);
    }

    #[test]
    fn mode_persist_failure_reverts_field_and_surfaces_error() {
        let settings = AppSettings::default();
        let store = Arc::new(FailNTimesStore::new(settings, 1));
        let mut vm = SecuritySettingsVm::new(Arc::clone(&store) as Arc<dyn SettingsStore>).unwrap();
        let err = vm.set_mode(AppAuthenticationMode::Pin).unwrap_err();
        assert!(matches!(err, SecuritySettingsError::Persist(_)));
        assert_eq!(vm.mode(), AppAuthenticationMode::Disabled);
        assert_eq!(
            store.inner.snapshot().app_authentication_mode,
            AppAuthenticationMode::Disabled
        );
        assert!(vm.last_error().is_some());
        // Next attempt succeeds once the injected failure is consumed.
        vm.set_mode(AppAuthenticationMode::Pin).unwrap();
        assert_eq!(vm.mode(), AppAuthenticationMode::Pin);
        assert_eq!(
            store.inner.snapshot().app_authentication_mode,
            AppAuthenticationMode::Pin
        );
        assert!(vm.last_error().is_none());
    }

    #[test]
    fn fallback_persist_failure_reverts_field_and_surfaces_error() {
        let settings = AppSettings::default();
        let store = Arc::new(FailNTimesStore::new(settings, 1));
        let mut vm = SecuritySettingsVm::new(Arc::clone(&store) as Arc<dyn SettingsStore>).unwrap();
        let err = vm
            .set_hello_fallback(AppAuthenticationFallbackMethod::Password)
            .unwrap_err();
        assert!(matches!(err, SecuritySettingsError::Persist(_)));
        assert_eq!(vm.hello_fallback(), AppAuthenticationFallbackMethod::Pin);
        assert_eq!(
            store.inner.snapshot().app_authentication_hello_fallback,
            AppAuthenticationFallbackMethod::Pin
        );
        assert!(vm.last_error().is_some());
    }

    #[test]
    fn timeout_persist_failure_reverts_field_and_surfaces_error() {
        let settings = AppSettings::default();
        let store = Arc::new(FailNTimesStore::new(settings, 1));
        let mut vm = SecuritySettingsVm::new(Arc::clone(&store) as Arc<dyn SettingsStore>).unwrap();
        let err = vm.set_idle_timeout(Some(5)).unwrap_err();
        assert!(matches!(err, SecuritySettingsError::Persist(_)));
        assert_eq!(vm.idle_timeout_minutes(), Some(15));
        assert_eq!(
            store.inner.snapshot().app_authentication_idle_timeout_minutes,
            Some(15)
        );
        assert!(vm.last_error().is_some());
    }

    #[test]
    fn effective_policy_fail_closed_table() {
        assert_eq!(
            effective_idle_policy(AppAuthenticationMode::Disabled, Some(5)),
            IdleLockPolicy::NeverLock
        );
        assert_eq!(
            effective_idle_policy(AppAuthenticationMode::Disabled, Some(0)),
            IdleLockPolicy::NeverLock
        );
        assert_eq!(
            effective_idle_policy(AppAuthenticationMode::Pin, None),
            IdleLockPolicy::NeverLock
        );
        assert_eq!(
            effective_idle_policy(AppAuthenticationMode::Password, Some(0)),
            IdleLockPolicy::FailClosedLock
        );
        assert_eq!(
            effective_idle_policy(AppAuthenticationMode::WindowsHello, Some(-1)),
            IdleLockPolicy::FailClosedLock
        );
        assert_eq!(
            effective_idle_policy(AppAuthenticationMode::Pin, Some(15)),
            IdleLockPolicy::LockAfterMinutes(15)
        );
    }

    #[test]
    fn disabled_mode_keeps_stored_timeout_but_policy_is_never() {
        let mut settings = AppSettings::default();
        settings.app_authentication_mode = AppAuthenticationMode::Pin;
        settings.app_authentication_idle_timeout_minutes = Some(15);
        let (mut glue, harness) = harness();
        harness.store.save(&settings).unwrap();
        glue.vm_mut().reload().unwrap();
        glue.set_mode(AppAuthenticationMode::Disabled).unwrap();
        assert_eq!(harness.store.snapshot().app_authentication_idle_timeout_minutes, Some(15));
        assert_eq!(glue.vm().policy(), IdleLockPolicy::NeverLock);
    }

    #[test]
    fn debug_shows_mode_labels_and_errors_only() {
        let (mut glue, _) = harness();
        glue.set_mode(AppAuthenticationMode::Password).unwrap();
        let dbg = format!("{glue:?}");
        assert!(dbg.contains("Password"));
        assert!(!dbg.contains("hunter2"));
        assert!(!dbg.contains("PIN material"));
    }

    #[test]
    fn fail_closed_reject_leaves_error_copy() {
        let (mut glue, _) = harness();
        let err = glue.set_idle_timeout(Some(0)).unwrap_err();
        let _ = err;
        let error = glue.vm().last_error().unwrap_or_default();
        assert!(error.contains("idle timeout"));
    }
}