//! Integration tests for settings JSON store + schema migration.

use std::sync::Arc;

use wormhole_ui::{
    AppSettings, ApplicationTheme, JsonFileSettingsStore, MemorySettingsStore, SettingsStore,
    SettingsViewModel, CURRENT_SCHEMA_VERSION,
};

#[test]
fn json_file_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let store = JsonFileSettingsStore::in_directory(dir.path()).unwrap();

    let mut settings = AppSettings::default();
    settings.theme = ApplicationTheme::Dark;
    settings.confirm_on_tab_close = false;
    store.save(&settings).unwrap();

    let loaded = store.load().unwrap();
    assert_eq!(loaded.theme, ApplicationTheme::Dark);
    assert!(!loaded.confirm_on_tab_close);
    assert_eq!(loaded.settings_schema_version, CURRENT_SCHEMA_VERSION);
}

#[test]
fn legacy_json_migrates_prompt_before_tunnel() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    std::fs::write(
        &path,
        "{\n  \"PromptBeforeTunnelConnect\": false\n}",
    )
    .unwrap();

    let store = JsonFileSettingsStore::new(&path).unwrap();
    let loaded = store.load().unwrap();
    assert!(loaded.prompt_before_tunnel_connect);
    assert_eq!(loaded.settings_schema_version, CURRENT_SCHEMA_VERSION);
    assert_eq!(loaded.bitwarden_onboarding_notice_pending_version, 1);
}

#[test]
fn versioned_off_prompt_is_preserved() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    std::fs::write(
        &path,
        "{\n  \"SettingsSchemaVersion\": 1,\n  \"PromptBeforeTunnelConnect\": false\n}",
    )
    .unwrap();

    let store = JsonFileSettingsStore::new(&path).unwrap();
    let loaded = store.load().unwrap();
    assert!(!loaded.prompt_before_tunnel_connect);
    assert_eq!(loaded.settings_schema_version, CURRENT_SCHEMA_VERSION);
}

#[test]
fn settings_view_model_reload() {
    let store = Arc::new(MemorySettingsStore::new(AppSettings::default()));
    let mut vm = SettingsViewModel::new(store.clone()).unwrap();
    vm.set_theme(ApplicationTheme::Light).unwrap();

    let mut other = SettingsViewModel::new(store).unwrap();
    assert_eq!(other.current().theme, ApplicationTheme::Light);
    other.reload().unwrap();
    assert_eq!(other.current().theme, ApplicationTheme::Light);
}

#[test]
fn path_escape_via_parent_segments_is_rejected() {
    let err = JsonFileSettingsStore::in_directory(std::path::Path::new("a/../../evil")).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("..") || msg.contains("path"), "{msg}");
}