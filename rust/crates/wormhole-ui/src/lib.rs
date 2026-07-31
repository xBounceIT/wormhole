//! Wormhole GPUI shell skeleton + connection-tree / settings / connection-editor VMs.
//!
//! Pure UI state (sidebar regions, tab strip, session tab bar, ≤4-pane layout tree,
//! settings + terminal font/size/auto-copy apply glue, connection editor, Quick Connect
//! + recent-history MRU, credential picker search glue, serial COM picker + baud/parity
//! preset glue) compiles without GPUI.
//! Enable `--features gpui` for shell
//! chrome (`gpui_platform::application()`). Enable `--features storage` for the SQLite
//! connection-tree read adapter, `StorageSettingsStore`, editor save glue, and tree
//! connection reparent apply. Default features `session` / `tunnels` / `update` wire
//! tree Open / Quick Connect → `wormhole-session`, OTP / Fortinet SAML prompt UI glue →
//! `wormhole-tunnels` (`ChannelOtpPrompt` / `ChannelSamlAuthCallback` + Fake; no dialog /
//! WebView2 chrome), and update notify glue → `wormhole-update` (`check_now` +
//! Fake / NetworkStub; no live HTTP).
//!
//! See `docs/migration/08-ui.md`, `docs/migration/17-tree-settings-vm.md`,
//! `docs/migration/16-session-orchestrator.md`, `docs/migration/20-connection-editor.md`,
//! `docs/migration/21-quick-connect.md`, `docs/migration/07-tunnels-mcp.md`, and
//! `docs/migration/13-update-logging.md`.

mod connection_editor;
mod credential_picker;
mod error;
mod layout_sink;
mod pane_layout;
mod quick_connect;
mod serial_ports;
mod serial_presets;
mod session_tab_bar;
mod settings;
mod shell;
mod tabs;
mod theme;
mod tree;
mod workspace;

#[cfg(feature = "session")]
mod tunnel_route_prompt;

#[cfg(feature = "tunnels")]
mod otp_prompt;
#[cfg(feature = "tunnels")]
mod saml_prompt;

#[cfg(feature = "update")]
mod update_notify;

#[cfg(feature = "gpui")]
mod gpui_host;

pub use connection_editor::{
    ConnectionEditorMode, ConnectionEditorState, CredentialUiMode, RdpDriveRedirectMode,
    SshAutoSudoMode, TunnelUiSelection, TunnelUiState, ValidationError, ValidationReport,
    VisibleFields, WriteOptions,
};
pub use credential_picker::{
    filter_credential_profiles, filter_credential_profiles_from, profile_matches_query,
    CredentialPickerError, CredentialPickerSearchVm, CredentialProfileRow,
    CredentialProfileSource, FakeCredentialList,
};
#[cfg(feature = "storage")]
pub use connection_editor::{
    load_inline_secret, save_validated_editor, EditorSaveError, EditorSaveOp, EditorSaveResult,
};
pub use error::UiError;
pub use quick_connect::{
    default_port, protocol_picker, seed_connection_node, BuildError,
    FakeQuickConnectHistoryStore, QuickConnectHistoryEntry, QuickConnectHistoryError,
    QuickConnectHistoryKey, QuickConnectHistoryStore, QuickConnectHistoryVm, QuickConnectResult,
    QuickConnectState, TargetField, DEFAULT_HISTORY_CAPACITY, PROTOCOL_PICKER,
};
pub use serial_ports::{list_ports_fail_closed, SerialPortPickerState};
pub use serial_presets::{
    apply_combo_to_editor, apply_putty_defaults_to_editor, combo_from_editor,
    editor_serial_all_inherit, load_node_serial_into_editor, preset_catalog_lens, select_baud_preset,
    select_baud_preset_qc, select_data_bits_preset, select_data_bits_preset_qc,
    select_flow_control_preset, select_flow_control_preset_qc, select_parity_preset,
    select_parity_preset_qc, select_stop_bits_preset, select_stop_bits_preset_qc, set_custom_baud,
    set_custom_data_bits, set_custom_stop_bits, write_editor_serial_to_node, FlowControlPreset,
    ParityPreset, StopBitPreset, SERIAL_BAUD_PRESETS, SERIAL_DATA_BIT_PRESETS, SERIAL_FLOW_PRESETS,
    SERIAL_PARITY_PRESETS, SERIAL_STOP_BIT_PRESETS,
};
#[cfg(feature = "session")]
pub use quick_connect::{
    connect_prepared, connect_quick_connect, prepare_connect, prepare_connect_ephemeral,
    QuickConnectConnectRequest,
};
pub use layout_sink::{
    notify_workspace_layout, physical_updates_for_layout, physical_updates_for_workspace,
    NopPaneLayoutSink, PaneLayoutSink, PaneLayoutUpdate, PanePhysicalBounds, RecordingPaneLayoutSink,
};
pub use settings::{
    apply_terminal_settings_from_app, apply_terminal_settings_to_fake, confined_settings_path,
    normalize_retention_days, terminal_settings_config_from_app, AppAuthenticationFallbackMethod,
    AppAuthenticationMode, AppSettings, ApplicationTheme, BitwardenBrowserExtensionSource,
    BitwardenCliServerRegion, JsonFileSettingsStore, MemorySettingsStore, SettingsError,
    SettingsStore, SettingsViewModel, BITWARDEN_ONBOARDING_INTRODUCED_SCHEMA_VERSION,
    CURRENT_SCHEMA_VERSION,
};
// Re-export terminal settings apply types used by the AppSettings mapper.
pub use wormhole_terminal::{
    accept_selection_auto_copy, apply_terminal_settings, AppliedTerminalSettings,
    FakeTerminalSettingsSurface, TerminalSettingsApplyError, TerminalSettingsApplyMessage,
    TerminalSettingsConfig, DEFAULT_SSH_FONT_FAMILY, DEFAULT_SSH_FONT_SIZE,
};
pub use session_tab_bar::{
    sanitize_session_tab_title, ProtocolBadge, SessionId, SessionTabBarState, SessionTabModel,
};
pub use shell::{ShellState, SidebarRegion};
pub use tabs::{SessionTab, TabStrip};
pub use theme::{ThemeTokens, THEME};
pub use tree::{
    apply_duplicate_memory, apply_reparent_memory, build_duplicate, build_duplicate_from,
    duplicate_memory, fields_match_query_lower, node_matches_query, reparent_memory,
    should_reject_drag_selection, should_reject_drag_selection_from, validate_reparent,
    validate_reparent_from, visible_connection_ids, visible_connection_ids_from, BuiltDuplicate,
    ConnectionNodeSource, ConnectionTreeModel, DuplicateError, FlattenedRow,
    MemoryConnectionSource, ReparentError, ReparentOptions, TreeError, TreeNode, ValidatedReparent,
    DUPLICATE_NAME_SUFFIX, MAX_DISPLAYED_SEARCH_MATCHES,
};
#[cfg(feature = "session")]
pub use tree::{
    connect_from_selection, connect_from_tree, fake_orchestrator_for_tests,
    fake_orchestrator_with_credentials, options_with_password, prepare_connect_request,
    prepare_tree_connect, prepare_tree_connect_from_selection, ConnectRequest, TreeConnectRequest,
    TreeOpenError,
};
// Tree `connect` / `connect_prepared` stay aliased to avoid clashing with QC glue names.
#[cfg(feature = "session")]
pub use tunnel_route_prompt::resolve_tunnel_route_from_settings;
#[cfg(feature = "session")]
pub use wormhole_session::{
    apply_tunnel_route_choice, resolve_tunnel_route, FakeTunnelRoutePromptUi,
    MemoryTunnelConfigNames, TunnelConfigNameLookup, TunnelRouteChoice, TunnelRoutePrompt,
    TunnelRoutePromptRequest, FALLBACK_TUNNEL_NAME,
};
#[cfg(feature = "session")]
pub use tree::connect as connect_tree;
#[cfg(feature = "session")]
pub use tree::connect_prepared as connect_tree_prepared;
pub use pane_layout::{
    PaneArrangement, PaneLayout, SplitAxis, SPLIT_RATIO_DEFAULT, SPLIT_RATIO_MAX, SPLIT_RATIO_MIN,
};
pub use workspace::{PaneId, WorkspaceState, MAX_PANES};

#[cfg(feature = "storage")]
pub use settings::StorageSettingsStore;
#[cfg(feature = "storage")]
pub use tree::{
    duplicate_connection_storage, reparent_connection_storage, StorageConnectionSource,
};

#[cfg(feature = "tunnels")]
pub use otp_prompt::{
    cancel_pending, submit_pending, FakeOtpPromptUi, FakePrompt, OtpPromptChannel,
};
#[cfg(feature = "tunnels")]
pub use saml_prompt::{
    cancel_pending_saml, submit_auth_id, submit_saml_result, submit_svpn_cookie, FakeSamlPromptUi,
    SamlPromptChannel,
};
// Glue-facing tunnels types + hooks used by the OTP / SAML UI surfaces.
#[cfg(feature = "tunnels")]
pub use wormhole_tunnels::{
    authenticate_fortinet_saml, request_otp, request_second_factor, ChannelOtpPrompt,
    ChannelSamlAuthCallback, OtpCode, OtpPromptError, OtpPromptRequest, OtpPromptResponse,
    PendingOtpPrompt, PendingSamlPrompt, SamlAuthCallback, SamlAuthError, SamlAuthFlow,
    SamlAuthRequest, SamlAuthResult, SamlPromptResponse, SharedOtpPrompt, SharedSamlAuthCallback,
    TunnelError, DEFAULT_SAML_REDIRECT_PORT,
};

#[cfg(feature = "update")]
pub use update_notify::{
    format_last_check, test_request, UpdateNotifyGlue, UpdateNotifyUiState,
    UPDATE_NOTIFY_DEV_MODE_TEXT,
};
#[cfg(feature = "update")]
pub use wormhole_update::{
    AppVersion, FakeUpdateChecker, NetworkStubUpdateChecker, SharedUpdateChecker,
    UpdateApiToken, UpdateCheckRequest, UpdateNotifyKind, UpdateNotifyStatus,
    UPDATE_NOTIFY_ERROR_TEXT, UPDATE_NOTIFY_UP_TO_DATE_TEXT,
};

#[cfg(feature = "gpui")]
pub use gpui_host::{
    try_boot_shell, try_boot_shell_with_sink, GpuiShellMarker, LogicalRect, ShellChrome,
};

/// Crate-level result alias.
pub type Result<T> = std::result::Result<T, UiError>;
