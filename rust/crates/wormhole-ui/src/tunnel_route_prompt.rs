//! Settings-backed tunnel route prompt glue (no GPUI dialog).
//!
//! Maps [`AppSettings::prompt_before_tunnel_connect`] onto
//! [`wormhole_session::resolve_tunnel_route`] with optional Fake prompt UI.

use wormhole_domain::ConnectionProfile;
use wormhole_session::{
    resolve_tunnel_route, CancellationToken, TunnelConfigNameLookup, TunnelRoutePrompt,
};

use crate::settings::AppSettings;

/// Resolve per-connect tunnel routing using persisted settings.
pub fn resolve_tunnel_route_from_settings(
    profile: ConnectionProfile,
    settings: &AppSettings,
    cancel: &CancellationToken,
    names: Option<&dyn TunnelConfigNameLookup>,
    prompt: Option<&dyn TunnelRoutePrompt>,
) -> wormhole_session::Result<Option<ConnectionProfile>> {
    resolve_tunnel_route(
        profile,
        settings.prompt_before_tunnel_connect,
        cancel,
        names,
        prompt,
    )
}
