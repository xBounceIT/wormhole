//! Per-connect tunnel-vs-direct route prompt glue (Fake / LabOnly).
//!
//! Mirrors C# `TunnelRoutePrompter` / `PromptBeforeTunnelConnect` without GPUI or
//! live dialogs. When prompting is off or the profile has no tunnel, the input profile
//! returns unchanged. When prompting is on and `tunnel_enabled`, a [`TunnelRoutePrompt`]
//! (typically [`FakeTunnelRoutePromptUi`]) supplies
//! [`TunnelRouteChoice::AllowTunnel`] / [`TunnelRouteChoice::PreferDirect`] /
//! [`TunnelRouteChoice::Cancel`]. Cancel is fail-closed (`Ok(None)` — do not connect).
//!
//! Tunnel config **names** are cosmetic for the prompt label; lookup failures use
//! [`FALLBACK_TUNNEL_NAME`] and never block the routing decision (C# parity).

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::Mutex;

use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use wormhole_domain::ConnectionProfile;

use crate::error::{Result, SessionError};

/// Generic label when tunnel metadata cannot be loaded (C# `FallbackTunnelName`).
pub const FALLBACK_TUNNEL_NAME: &str = "the configured VPN tunnel";

/// User answer to the per-connect route prompt (C# `TunnelRouteChoice`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelRouteChoice {
    /// Establish the configured tunnel for this attempt (`UseTunnel` in C#).
    AllowTunnel,
    /// Skip the tunnel and connect directly (`Direct` in C#).
    PreferDirect,
    /// Abort without connecting either way.
    Cancel,
}

/// Cosmetic metadata passed to the prompt (no secrets).
#[derive(Clone)]
pub struct TunnelRoutePromptRequest {
    pub connection_name: String,
    pub tunnel_name: String,
    pub tunnel_config_id: Option<Uuid>,
}

impl TunnelRoutePromptRequest {
    pub fn new(
        connection_name: impl Into<String>,
        tunnel_name: impl Into<String>,
        tunnel_config_id: Option<Uuid>,
    ) -> Self {
        Self {
            connection_name: connection_name.into(),
            tunnel_name: tunnel_name.into(),
            tunnel_config_id,
        }
    }
}

impl fmt::Debug for TunnelRoutePromptRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunnelRoutePromptRequest")
            .field("connection_name_len", &self.connection_name.len())
            .field("tunnel_name_len", &self.tunnel_name.len())
            .field("tunnel_config_id", &self.tunnel_config_id)
            .finish()
    }
}

/// UI / dialog surface for the route prompt (Fake in Lab; WinUI ContentDialog in C#).
pub trait TunnelRoutePrompt: Send + Sync {
    fn prompt(&self, request: &TunnelRoutePromptRequest) -> TunnelRouteChoice;
}

/// Resolve a display name for the configured tunnel (metadata only).
pub trait TunnelConfigNameLookup: Send + Sync {
    fn lookup_name(
        &self,
        config_id: Uuid,
        cancel: &CancellationToken,
    ) -> Result<Option<String>>;
}

/// In-memory tunnel name map for unit tests.
#[derive(Default)]
pub struct MemoryTunnelConfigNames {
    names: HashMap<Uuid, String>,
}

impl MemoryTunnelConfigNames {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, config_id: Uuid, name: impl Into<String>) {
        self.names.insert(config_id, name.into());
    }
}

impl fmt::Debug for MemoryTunnelConfigNames {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemoryTunnelConfigNames")
            .field("count", &self.names.len())
            .finish()
    }
}

impl TunnelConfigNameLookup for MemoryTunnelConfigNames {
    fn lookup_name(
        &self,
        config_id: Uuid,
        cancel: &CancellationToken,
    ) -> Result<Option<String>> {
        if cancel.is_cancelled() {
            return Err(SessionError::Cancelled);
        }
        Ok(self.names.get(&config_id).cloned())
    }
}

struct FakeTunnelRoutePromptState {
    script: VecDeque<TunnelRouteChoice>,
    prompted: usize,
    last_request: Option<TunnelRoutePromptRequest>,
}

/// Scripted Fake prompt UI (no GPUI).
pub struct FakeTunnelRoutePromptUi {
    state: Mutex<FakeTunnelRoutePromptState>,
}

impl Default for FakeTunnelRoutePromptUi {
    fn default() -> Self {
        Self {
            state: Mutex::new(FakeTunnelRoutePromptState {
                script: VecDeque::new(),
                prompted: 0,
                last_request: None,
            }),
        }
    }
}

impl fmt::Debug for FakeTunnelRoutePromptUi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state.lock().expect("fake prompt mutex");
        f.debug_struct("FakeTunnelRoutePromptUi")
            .field("script_len", &state.script.len())
            .field("prompted", &state.prompted)
            .field("last_request", &state.last_request)
            .finish()
    }
}

impl FakeTunnelRoutePromptUi {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_choices(choices: impl IntoIterator<Item = TunnelRouteChoice>) -> Self {
        let ui = Self::new();
        for choice in choices {
            ui.push(choice);
        }
        ui
    }

    pub fn push(&self, choice: TunnelRouteChoice) {
        self.state
            .lock()
            .expect("fake prompt mutex")
            .script
            .push_back(choice);
    }

    pub fn prompted_count(&self) -> usize {
        self.state.lock().expect("fake prompt mutex").prompted
    }

    pub fn last_request(&self) -> Option<TunnelRoutePromptRequest> {
        self.state
            .lock()
            .expect("fake prompt mutex")
            .last_request
            .clone()
    }
}

impl TunnelRoutePrompt for FakeTunnelRoutePromptUi {
    fn prompt(&self, request: &TunnelRoutePromptRequest) -> TunnelRouteChoice {
        let mut state = self.state.lock().expect("fake prompt mutex");
        state.last_request = Some(request.clone());
        state.prompted += 1;
        state
            .script
            .pop_front()
            .unwrap_or(TunnelRouteChoice::Cancel)
    }
}

/// Map a user choice onto a profile for this connect attempt.
pub fn apply_tunnel_route_choice(
    profile: ConnectionProfile,
    choice: TunnelRouteChoice,
) -> Option<ConnectionProfile> {
    match choice {
        TunnelRouteChoice::AllowTunnel => Some(profile),
        TunnelRouteChoice::PreferDirect => {
            let mut direct = profile;
            direct.tunnel_enabled = false;
            Some(direct)
        }
        TunnelRouteChoice::Cancel => None,
    }
}

fn resolve_tunnel_label(
    profile: &ConnectionProfile,
    cancel: &CancellationToken,
    names: Option<&dyn TunnelConfigNameLookup>,
) -> Result<String> {
    if cancel.is_cancelled() {
        return Err(SessionError::Cancelled);
    }

    let config_id = match profile.tunnel_config_id {
        Some(id) => id,
        None => return Ok(FALLBACK_TUNNEL_NAME.to_string()),
    };

    if names.is_none() {
        return Ok(FALLBACK_TUNNEL_NAME.to_string());
    }

    let lookup = names
        .expect("names.is_some()")
        .lookup_name(config_id, cancel);
    if cancel.is_cancelled() {
        return Err(SessionError::Cancelled);
    }

    match lookup {
        Err(SessionError::Cancelled) => Err(SessionError::Cancelled),
        Err(_) => Ok(FALLBACK_TUNNEL_NAME.to_string()),
        Ok(None) => Ok(FALLBACK_TUNNEL_NAME.to_string()),
        Ok(Some(name)) if name.trim().is_empty() => Ok(FALLBACK_TUNNEL_NAME.to_string()),
        Ok(Some(name)) => Ok(name),
    }
}

/// Resolve whether this connect uses the profile tunnel or direct routing.
///
/// | `prompt_before_tunnel_connect` | `tunnel_enabled` | Result |
/// |---|---|---|
/// | `false` | any | `Ok(Some(profile))` — auto route per resolved tunnel flag |
/// | `true` | `false` | `Ok(Some(profile))` — nothing to choose |
/// | `true` | `true` | prompt → choice mapped profile or `Ok(None)` on cancel |
///
/// Cooperative cancel on `cancel` → `Err(SessionError::Cancelled)` (never opens a stale prompt).
/// Missing prompt when prompting is required → fail-closed `Ok(None)`.
pub fn resolve_tunnel_route(
    profile: ConnectionProfile,
    prompt_before_tunnel_connect: bool,
    cancel: &CancellationToken,
    names: Option<&dyn TunnelConfigNameLookup>,
    prompt: Option<&dyn TunnelRoutePrompt>,
) -> Result<Option<ConnectionProfile>> {
    if !profile.tunnel_enabled {
        return Ok(Some(profile));
    }
    if !prompt_before_tunnel_connect {
        return Ok(Some(profile));
    }

    let tunnel_name = resolve_tunnel_label(&profile, cancel, names)?;
    if cancel.is_cancelled() {
        return Err(SessionError::Cancelled);
    }

    let request = TunnelRoutePromptRequest::new(
        profile.name.clone(),
        tunnel_name,
        profile.tunnel_config_id,
    );

    let choice = match prompt {
        Some(p) => p.prompt(&request),
        None => TunnelRouteChoice::Cancel,
    };

    if cancel.is_cancelled() {
        return Err(SessionError::Cancelled);
    }

    Ok(apply_tunnel_route_choice(profile, choice))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wormhole_domain::ProtocolType;

    struct ThrowingNameLookup;

    impl TunnelConfigNameLookup for ThrowingNameLookup {
        fn lookup_name(
            &self,
            _config_id: Uuid,
            _cancel: &CancellationToken,
        ) -> Result<Option<String>> {
            Err(SessionError::Other("repository unavailable".into()))
        }
    }

    struct CancellingNameLookup;

    impl TunnelConfigNameLookup for CancellingNameLookup {
        fn lookup_name(
            &self,
            _config_id: Uuid,
            cancel: &CancellationToken,
        ) -> Result<Option<String>> {
            if cancel.is_cancelled() {
                return Err(SessionError::Cancelled);
            }
            // Simulate async lookup observing cancellation mid-flight.
            cancel.cancel();
            Err(SessionError::Cancelled)
        }
    }

    fn profile(tunnel_enabled: bool, config_id: Option<Uuid>) -> ConnectionProfile {
        ConnectionProfile {
            node_id: Uuid::new_v4(),
            name: "conn".into(),
            protocol: ProtocolType::Ssh,
            host: "192.0.2.10".into(),
            port: 22,
            tunnel_enabled,
            tunnel_config_id: config_id,
            ..ConnectionProfile::default()
        }
    }

    #[test]
    fn tunnel_disabled_returns_without_prompting() {
        let cancel = CancellationToken::new();
        let ui = FakeTunnelRoutePromptUi::new();
        let result = resolve_tunnel_route(
            profile(false, None),
            true,
            &cancel,
            None,
            Some(&ui),
        )
        .unwrap();
        assert!(result.is_some());
        assert!(!result.unwrap().tunnel_enabled);
        assert_eq!(ui.prompted_count(), 0);
    }

    #[test]
    fn setting_off_returns_without_prompting() {
        let cancel = CancellationToken::new();
        let config_id = Uuid::new_v4();
        let ui = FakeTunnelRoutePromptUi::new();
        let input = profile(true, Some(config_id));
        let result = resolve_tunnel_route(input, false, &cancel, None, Some(&ui)).unwrap();
        let out = result.unwrap();
        assert!(out.tunnel_enabled);
        assert_eq!(out.tunnel_config_id, Some(config_id));
        assert_eq!(ui.prompted_count(), 0);
    }

    #[test]
    fn allow_tunnel_returns_profile_unchanged() {
        let cancel = CancellationToken::new();
        let config_id = Uuid::new_v4();
        let ui =
            FakeTunnelRoutePromptUi::from_choices([TunnelRouteChoice::AllowTunnel]);
        let result = resolve_tunnel_route(
            profile(true, Some(config_id)),
            true,
            &cancel,
            None,
            Some(&ui),
        )
        .unwrap()
        .unwrap();
        assert!(result.tunnel_enabled);
        assert_eq!(result.tunnel_config_id, Some(config_id));
        assert_eq!(ui.prompted_count(), 1);
    }

    #[test]
    fn prefer_direct_forces_tunnel_off_keeps_config_id() {
        let cancel = CancellationToken::new();
        let config_id = Uuid::new_v4();
        let ui =
            FakeTunnelRoutePromptUi::from_choices([TunnelRouteChoice::PreferDirect]);
        let result = resolve_tunnel_route(
            profile(true, Some(config_id)),
            true,
            &cancel,
            None,
            Some(&ui),
        )
        .unwrap()
        .unwrap();
        assert!(!result.tunnel_enabled);
        assert_eq!(result.tunnel_config_id, Some(config_id));
        assert_eq!(ui.prompted_count(), 1);
    }

    #[test]
    fn cancel_returns_none_fail_closed() {
        let cancel = CancellationToken::new();
        let ui = FakeTunnelRoutePromptUi::from_choices([TunnelRouteChoice::Cancel]);
        let result = resolve_tunnel_route(
            profile(true, Some(Uuid::new_v4())),
            true,
            &cancel,
            None,
            Some(&ui),
        )
        .unwrap();
        assert!(result.is_none());
        assert_eq!(ui.prompted_count(), 1);
    }

    #[test]
    fn missing_prompt_when_required_fail_closed() {
        let cancel = CancellationToken::new();
        let result = resolve_tunnel_route(
            profile(true, Some(Uuid::new_v4())),
            true,
            &cancel,
            None,
            None,
        )
        .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn passes_configured_tunnel_name_to_prompt() {
        let cancel = CancellationToken::new();
        let config_id = Uuid::new_v4();
        let mut names = MemoryTunnelConfigNames::new();
        names.insert(config_id, "corp-vpn");
        let ui =
            FakeTunnelRoutePromptUi::from_choices([TunnelRouteChoice::AllowTunnel]);

        resolve_tunnel_route(
            profile(true, Some(config_id)),
            true,
            &cancel,
            Some(&names),
            Some(&ui),
        )
        .unwrap();

        let req = ui.last_request().expect("last_request");
        assert_eq!(req.tunnel_name, "corp-vpn");
        assert_eq!(req.connection_name, "conn");
        assert_eq!(req.tunnel_config_id, Some(config_id));
    }

    #[test]
    fn lookup_error_still_prompts_with_generic_name() {
        let cancel = CancellationToken::new();
        let ui =
            FakeTunnelRoutePromptUi::from_choices([TunnelRouteChoice::AllowTunnel]);
        let lookup = ThrowingNameLookup;
        let result = resolve_tunnel_route(
            profile(true, Some(Uuid::new_v4())),
            true,
            &cancel,
            Some(&lookup),
            Some(&ui),
        )
        .unwrap()
        .unwrap();
        assert!(result.tunnel_enabled);
        assert_eq!(ui.prompted_count(), 1);
        assert_eq!(
            ui.last_request().expect("last_request").tunnel_name,
            FALLBACK_TUNNEL_NAME
        );
    }

    #[test]
    fn missing_config_uses_generic_name() {
        let cancel = CancellationToken::new();
        let names = MemoryTunnelConfigNames::new();
        let ui =
            FakeTunnelRoutePromptUi::from_choices([TunnelRouteChoice::AllowTunnel]);
        let missing = Uuid::new_v4();

        resolve_tunnel_route(
            profile(true, Some(missing)),
            true,
            &cancel,
            Some(&names),
            Some(&ui),
        )
        .unwrap();

        assert_eq!(
            ui.last_request().expect("last_request").tunnel_name,
            FALLBACK_TUNNEL_NAME
        );
    }

    #[test]
    fn lookup_cancelled_propagates_without_prompt() {
        let cancel = CancellationToken::new();
        let ui = FakeTunnelRoutePromptUi::new();
        let lookup = CancellingNameLookup;
        let err = resolve_tunnel_route(
            profile(true, Some(Uuid::new_v4())),
            true,
            &cancel,
            Some(&lookup),
            Some(&ui),
        )
        .unwrap_err();
        assert!(err.is_cancelled());
        assert_eq!(ui.prompted_count(), 0);
    }

    #[test]
    fn already_cancelled_aborts_before_prompt() {
        let cancel = CancellationToken::new();
        cancel.cancel();
        let ui = FakeTunnelRoutePromptUi::new();
        let err = resolve_tunnel_route(
            profile(true, Some(Uuid::new_v4())),
            true,
            &cancel,
            None,
            Some(&ui),
        )
        .unwrap_err();
        assert!(err.is_cancelled());
        assert_eq!(ui.prompted_count(), 0);
    }

    #[test]
    fn fake_ui_exhausted_script_cancels() {
        let cancel = CancellationToken::new();
        let ui = FakeTunnelRoutePromptUi::new();
        let result = resolve_tunnel_route(
            profile(true, Some(Uuid::new_v4())),
            true,
            &cancel,
            None,
            Some(&ui),
        )
        .unwrap();
        assert!(result.is_none());
        assert_eq!(ui.prompted_count(), 1);
    }

    #[test]
    fn request_debug_uses_lengths_not_names() {
        let req = TunnelRoutePromptRequest::new("conn-name", "tunnel-label", Some(Uuid::new_v4()));
        let dbg = format!("{req:?}");
        assert!(dbg.contains("connection_name_len"));
        assert!(!dbg.contains("conn-name"));
        assert!(!dbg.contains("tunnel-label"));
    }

    #[test]
    fn fake_ui_debug_omits_script_choices_content() {
        let ui = FakeTunnelRoutePromptUi::from_choices([
            TunnelRouteChoice::AllowTunnel,
            TunnelRouteChoice::PreferDirect,
        ]);
        let dbg = format!("{ui:?}");
        assert!(dbg.contains("script_len"));
        assert!(!dbg.contains("AllowTunnel"));
    }

    #[test]
    fn blank_tunnel_name_from_lookup_uses_fallback() {
        let cancel = CancellationToken::new();
        let config_id = Uuid::new_v4();
        let mut names = MemoryTunnelConfigNames::new();
        names.insert(config_id, "   ");
        let ui =
            FakeTunnelRoutePromptUi::from_choices([TunnelRouteChoice::AllowTunnel]);

        resolve_tunnel_route(
            profile(true, Some(config_id)),
            true,
            &cancel,
            Some(&names),
            Some(&ui),
        )
        .unwrap();

        assert_eq!(
            ui.last_request().expect("last_request").tunnel_name,
            FALLBACK_TUNNEL_NAME
        );
    }

    struct CancellingPrompt {
        cancel: CancellationToken,
    }

    impl TunnelRoutePrompt for CancellingPrompt {
        fn prompt(&self, _request: &TunnelRoutePromptRequest) -> TunnelRouteChoice {
            self.cancel.cancel();
            TunnelRouteChoice::AllowTunnel
        }
    }

    #[test]
    fn post_prompt_cancel_returns_cancelled_not_profile() {
        let cancel = CancellationToken::new();
        let prompt = CancellingPrompt {
            cancel: cancel.clone(),
        };
        let err = resolve_tunnel_route(
            profile(true, Some(Uuid::new_v4())),
            true,
            &cancel,
            None,
            Some(&prompt),
        )
        .unwrap_err();
        assert!(err.is_cancelled());
    }

    #[test]
    fn cancel_after_prompt_still_returns_none() {
        let cancel = CancellationToken::new();
        let ui = FakeTunnelRoutePromptUi::from_choices([TunnelRouteChoice::Cancel]);
        let result = resolve_tunnel_route(
            profile(true, Some(Uuid::new_v4())),
            true,
            &cancel,
            None,
            Some(&ui),
        )
        .unwrap();
        assert!(result.is_none());
        // Post-choice cancel is checked but Cancel already returned None.
        cancel.cancel();
    }

    #[test]
    fn apply_choice_maps_direct_and_cancel() {
        let config_id = Uuid::new_v4();
        let base = profile(true, Some(config_id));
        let direct = apply_tunnel_route_choice(base.clone(), TunnelRouteChoice::PreferDirect)
            .expect("direct");
        assert!(!direct.tunnel_enabled);
        assert_eq!(direct.tunnel_config_id, Some(config_id));

        assert!(apply_tunnel_route_choice(base, TunnelRouteChoice::Cancel).is_none());
    }
}
