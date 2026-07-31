//! CredSSP / AdvancedSettings configure spike (C# `RdpHostForm.Configure` core subset).
//!
//! Applies connect-time MsRdpClient IDispatch properties. Password goes through
//! `ClearTextPassword` as a [`zeroize::Zeroizing`] buffer that is wiped after put —
//! never logged. CredSSP / NegotiateSecurityLayer setters fail soft when the
//! property is absent on the active CLSID tier.
//!
//! Tunnel + RD Gateway / external mstsc / strict server-auth combos are rejected by
//! [`validate_tunnel_rdp_policy`] (parity with `RdpSessionViewModel` + AGENTS.md).
//! Gateway-only checks use [`validate_rdp_gateway_tunnel_combo`].
//!
//! # Partial configure / soft CredSSP
//!
//! Loud property puts mutate the OCX as they succeed. A later hard `Err` (or a soft
//! CredSSP miss) can leave the control half-configured. Soft CredSSP miss leaves
//! `EnableCredSspSupport` at the OCX default (`false`) — NLA may be unavailable.
//! Callers must inspect [`ConfigureReport`] and must not `Connect` after a hard
//! configure failure or an unacked CredSSP soft miss when CredSSP was requested.

use std::fmt;

use zeroize::{Zeroize, Zeroizing};

/// Messages mirror C# `RdpSessionViewModel` constants (AGENTS.md VPN routing notes).
pub const TUNNEL_EXTERNAL_CLIENT_UNSUPPORTED: &str = "The external Remote Desktop client cannot be used with a per-connection VPN tunnel because mstsc.exe would connect from the host network. Use embedded RDP without Azure AD/external-client routing, or disable the tunnel.";

/// RD Gateway + tunnel rejection (loopback bridge cannot carry gateway HTTPS).
pub const TUNNEL_GATEWAY_UNSUPPORTED: &str = "RD Gateway cannot be used with a per-connection VPN tunnel yet because the ActiveX control would open gateway traffic from the host network. Disable RD Gateway for this connection, or disable the tunnel.";

/// Strict server auth (Require) + tunnel rejection (OCX validates loopback name).
pub const TUNNEL_STRICT_SERVER_AUTH_UNSUPPORTED: &str = "Strict RDP server authentication cannot be used with the current per-connection VPN tunnel because the embedded ActiveX control validates the loopback forwarder name instead of the original server name. Set server authentication to Warn, or disable the tunnel.";

/// Soft CredSSP miss note (OCX default `EnableCredSspSupport` is `false`).
pub const CREDSSP_SOFT_MISS_NLA_RISK: &str = "EnableCredSspSupport was not applied; the OCX default is false, so NLA/CredSSP may be unavailable. Do not Connect without an explicit policy decision.";

/// Soft NegotiateSecurityLayer miss note.
pub const NEGOTIATE_SOFT_MISS: &str = "NegotiateSecurityLayer was not applied; falling back to the OCX default for this CLSID tier.";

/// Max length for `Server` (host / IP / unusual lab names). Rejects oversized BSTR puts.
pub const MAX_SERVER_CHARS: usize = 1024;
/// Max length for `UserName`.
pub const MAX_USERNAME_CHARS: usize = 256;
/// Max length for `Domain`.
pub const MAX_DOMAIN_CHARS: usize = 256;
/// Max password length (parity with Credential Manager practical ceiling).
pub const MAX_PASSWORD_CHARS: usize = 2560;
/// Desktop axis upper bound (spike guard against absurd COM puts).
pub const MAX_DESKTOP_AXIS: i32 = 16_384;

/// Inputs for [`validate_tunnel_rdp_policy`] (session-layer, pre-Connect).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunnelRdpPolicy {
    /// Effective `TunnelEnabled` after inheritance / route prompt.
    pub tunnel_enabled: bool,
    /// External `mstsc.exe` hand-off (Azure AD / opt-in).
    pub use_external_client: bool,
    /// `RdpGatewayUsageMethod` — C# `ConnectionProfile`: `0=Direct`, `1=Always`,
    /// `2=Detect`, `3=DefaultRdg`. Any nonzero (incl. negatives / `i32::MAX`) means a
    /// gateway mode is selected and is rejected with a tunnel.
    pub gateway_usage_method: i32,
    /// `RdpServerAuthentication` — C# `ConnectionProfile`: `0=NoAuth`, `1=Require`
    /// (strict), `2=Warn/prompt` (product default). Only `1` is rejected with a
    /// tunnel; every other `i32` (incl. negatives / `i32::MAX`) is allowed.
    pub server_authentication: i32,
}

/// Why a tunnel + RDP combo is rejected (parity with C# connect guards).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelRdpConflict {
    /// External mstsc + tunnel.
    ExternalClient,
    /// RD Gateway + tunnel.
    Gateway,
    /// Strict server authentication + tunnel.
    StrictServerAuth,
}

impl TunnelRdpConflict {
    /// User-facing message (same text as C# overlays).
    pub fn message(&self) -> &'static str {
        match self {
            Self::ExternalClient => TUNNEL_EXTERNAL_CLIENT_UNSUPPORTED,
            Self::Gateway => TUNNEL_GATEWAY_UNSUPPORTED,
            Self::StrictServerAuth => TUNNEL_STRICT_SERVER_AUTH_UNSUPPORTED,
        }
    }
}

impl fmt::Display for TunnelRdpConflict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for TunnelRdpConflict {}

/// Reject RD Gateway when a per-connection VPN tunnel is enabled.
///
/// Parity with C# `RdpSessionViewModel`:
/// `if (profile.TunnelEnabled && profile.RdpGatewayUsageMethod != 0)`.
///
/// C# `RdpGatewayUsageMethod` values (`ConnectionProfile`): `0=Direct` (never),
/// `1=Always`, `2=Detect`, `3=DefaultRdg`. Any nonzero — including negatives and
/// `i32::MAX` / `i32::MIN` — means a gateway mode is selected and is rejected with
/// the tunnel; the loopback forwarder cannot carry gateway HTTPS. When the tunnel
/// is off, every gateway value is allowed.
///
/// Pure policy helper (no COM / hardware). Prefer this focused check for
/// gateway-only callers; the full three-combo guard is [`validate_tunnel_rdp_policy`].
pub fn validate_rdp_gateway_tunnel_combo(
    tunnel_enabled: bool,
    gateway_usage_method: i32,
) -> Result<(), TunnelRdpConflict> {
    if tunnel_enabled && gateway_usage_method != 0 {
        return Err(TunnelRdpConflict::Gateway);
    }
    Ok(())
}

/// Reject the three AGENTS.md / C# tunnel combos that the loopback bridge cannot handle.
///
/// Returns `Ok(())` when the combination is allowed (including when the tunnel is off).
/// When multiple conflicts apply, priority matches C# `RdpSessionViewModel` connect
/// guards: ExternalClient → Gateway → StrictServerAuth (first match wins; never a
/// false `Ok` for any of the three). Gateway is therefore checked **before** strict
/// server auth; External still wins when both External and Gateway apply.
/// Gateway rejection delegates to [`validate_rdp_gateway_tunnel_combo`] (same
/// `TunnelRdpConflict::Gateway` / `TUNNEL_GATEWAY_UNSUPPORTED` identity).
///
/// Pure policy helper (no COM / hardware).
pub fn validate_tunnel_rdp_policy(policy: TunnelRdpPolicy) -> Result<(), TunnelRdpConflict> {
    if !policy.tunnel_enabled {
        return Ok(());
    }
    if policy.use_external_client {
        return Err(TunnelRdpConflict::ExternalClient);
    }
    validate_rdp_gateway_tunnel_combo(policy.tunnel_enabled, policy.gateway_usage_method)?;
    if policy.server_authentication == 1 {
        return Err(TunnelRdpConflict::StrictServerAuth);
    }
    Ok(())
}

/// Connect-time settings applied via IDispatch (C# `RdpHostForm.Configure` core).
///
/// `Debug` redacts the password. After [`crate::rdp::RdpOcx::configure`] returns
/// (Ok or Err), `password` is taken and zeroized — never left in `opts` for retry.
pub struct RdpConfigureOptions {
    /// RDP server hostname or IP (`Server`).
    pub server: String,
    /// TCP port (`AdvancedSettings.RDPPort`). Must be non-zero.
    pub port: u16,
    /// Optional `UserName`.
    pub username: Option<String>,
    /// Optional `Domain`.
    pub domain: Option<String>,
    /// Desktop width in pixels.
    pub desktop_width: i32,
    /// Desktop height in pixels.
    pub desktop_height: i32,
    /// Color depth (normalised via [`normalise_color_depth`]).
    pub color_depth: i32,
    /// `AdvancedSettings.EnableCredSspSupport` (C# defaults to `true` for NLA parity).
    pub enable_cred_ssp: bool,
    /// Optional `NegotiateSecurityLayer` stub — soft-fail if absent on CLSID tier.
    pub negotiate_security_layer: Option<bool>,
    /// Optional clear-text password for `ClearTextPassword`. Wiped after put / on drop /
    /// on any configure exit. Never logged.
    pub password: Option<Zeroizing<String>>,
}

impl fmt::Debug for RdpConfigureOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RdpConfigureOptions")
            .field("server", &self.server)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("domain", &self.domain)
            .field("desktop_width", &self.desktop_width)
            .field("desktop_height", &self.desktop_height)
            .field("color_depth", &self.color_depth)
            .field("enable_cred_ssp", &self.enable_cred_ssp)
            .field("negotiate_security_layer", &self.negotiate_security_layer)
            .field(
                "password",
                &self.password.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl RdpConfigureOptions {
    /// Builder with CredSSP on and no password / Negotiate stub.
    pub fn new(server: impl Into<String>, port: u16) -> Self {
        Self {
            server: server.into(),
            port,
            username: None,
            domain: None,
            desktop_width: 1024,
            desktop_height: 768,
            color_depth: 32,
            enable_cred_ssp: true,
            negotiate_security_layer: None,
            password: None,
        }
    }

    /// Attach a password that will be zeroized after `ClearTextPassword` put / configure exit.
    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(Zeroizing::new(password.into()));
        self
    }
}

/// Soft failures + CredSSP/Negotiate apply status collected during configure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigureReport {
    /// Human-readable soft-fail messages (CredSSP / Negotiate / etc.).
    pub soft_failures: Vec<String>,
    /// True when `EnableCredSspSupport` was set successfully on the OCX.
    pub cred_ssp_applied: bool,
    /// `None` if Negotiate was not requested; `Some(true)` applied; `Some(false)` soft-missed.
    pub negotiate_applied: Option<bool>,
    /// True when caller requested CredSSP (`enable_cred_ssp`) but the soft put missed.
    /// Connect without an explicit ack is unsafe (NLA may be off).
    pub cred_ssp_soft_missed: bool,
}

impl Default for ConfigureReport {
    fn default() -> Self {
        Self {
            soft_failures: Vec::new(),
            cred_ssp_applied: false,
            negotiate_applied: None,
            cred_ssp_soft_missed: false,
        }
    }
}

impl ConfigureReport {
    /// True when every soft setter applied (or was skipped).
    pub fn all_soft_applied(&self) -> bool {
        self.soft_failures.is_empty()
    }

    /// True when CredSSP was requested but not applied — NLA risk if Connect proceeds.
    pub fn has_cred_ssp_risk(&self) -> bool {
        self.cred_ssp_soft_missed
    }

    pub(crate) fn push_missing(&mut self, detail: String) {
        self.soft_failures.push(detail);
    }
}

/// Match C# `RdpHostForm.NormaliseColorDepth` — allow 8/15/16/24/32, else 32.
pub fn normalise_color_depth(requested: i32) -> i32 {
    match requested {
        8 | 15 | 16 | 24 | 32 => requested,
        _ => 32,
    }
}

/// Validate server / port / identity / desktop bounds before any IDispatch put.
///
/// Error messages never include password contents. Rejects empty/whitespace server,
/// port `0`, embedded NUL, oversized strings, and non-positive / oversized desktop axes.
pub fn validate_rdp_configure_options(opts: &RdpConfigureOptions) -> windows::core::Result<()> {
    validate_configure_inputs(
        &opts.server,
        opts.port,
        opts.username.as_deref(),
        opts.domain.as_deref(),
        opts.password.as_ref().map(|p| p.as_str()),
        opts.desktop_width,
        opts.desktop_height,
    )
}

/// Shared field checks used by [`validate_rdp_configure_options`] and `RdpOcx::configure`
/// (password may already be taken into a wipe guard).
pub(crate) fn validate_configure_inputs(
    server: &str,
    port: u16,
    username: Option<&str>,
    domain: Option<&str>,
    password: Option<&str>,
    desktop_width: i32,
    desktop_height: i32,
) -> windows::core::Result<()> {
    if port == 0 {
        return Err(invalid_arg("RDP port must be non-zero"));
    }

    let server_trimmed = server.trim();
    if server_trimmed.is_empty() {
        return Err(invalid_arg("RDP server must be non-empty"));
    }
    if server.len() > MAX_SERVER_CHARS {
        return Err(invalid_arg(format!(
            "RDP server exceeds maximum length ({MAX_SERVER_CHARS})"
        )));
    }
    if server.contains('\0') {
        return Err(invalid_arg("RDP server must not contain NUL"));
    }

    if let Some(user) = username {
        if user.contains('\0') {
            return Err(invalid_arg("RDP username must not contain NUL"));
        }
        if user.len() > MAX_USERNAME_CHARS {
            return Err(invalid_arg(format!(
                "RDP username exceeds maximum length ({MAX_USERNAME_CHARS})"
            )));
        }
    }

    if let Some(domain) = domain {
        if domain.contains('\0') {
            return Err(invalid_arg("RDP domain must not contain NUL"));
        }
        if domain.len() > MAX_DOMAIN_CHARS {
            return Err(invalid_arg(format!(
                "RDP domain exceeds maximum length ({MAX_DOMAIN_CHARS})"
            )));
        }
    }

    if let Some(password) = password {
        if password.contains('\0') {
            return Err(invalid_arg("RDP password must not contain NUL"));
        }
        if password.len() > MAX_PASSWORD_CHARS {
            return Err(invalid_arg(format!(
                "RDP password exceeds maximum length ({MAX_PASSWORD_CHARS})"
            )));
        }
    }

    if desktop_width <= 0 || desktop_height <= 0 {
        return Err(invalid_arg("RDP desktop width and height must be positive"));
    }
    if desktop_width > MAX_DESKTOP_AXIS || desktop_height > MAX_DESKTOP_AXIS {
        return Err(invalid_arg(format!(
            "RDP desktop axis exceeds maximum ({MAX_DESKTOP_AXIS})"
        )));
    }

    Ok(())
}

pub(crate) fn invalid_arg(message: impl Into<String>) -> windows::core::Error {
    windows::core::Error::new(windows::Win32::Foundation::E_INVALIDARG, message.into())
}

/// Ensures `opts.password` is taken and zeroized when the guard drops (any configure exit).
pub(crate) struct WipePasswordOnDrop<'a> {
    password: &'a mut Option<Zeroizing<String>>,
}

impl<'a> WipePasswordOnDrop<'a> {
    pub(crate) fn new(password: &'a mut Option<Zeroizing<String>>) -> Self {
        Self { password }
    }

    /// Take the password for a `ClearTextPassword` put (caller must zeroize after put).
    pub(crate) fn take_for_put(&mut self) -> Option<Zeroizing<String>> {
        self.password.take()
    }
}

impl Drop for WipePasswordOnDrop<'_> {
    fn drop(&mut self) {
        if let Some(mut leftover) = self.password.take() {
            // Zeroizing Drop also wipes; explicit zeroize keeps the contract obvious.
            leftover.zeroize();
            drop(leftover);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroize;

    /// C# `RdpGatewayUsageMethod` product values `1..=3` plus hostile extremes.
    /// Shared so reject/allow loops cannot drift across tests.
    const NONZERO_GATEWAY_METHODS: [i32; 6] = [1, 2, 3, -1, i32::MAX, i32::MIN];
    /// Direct (`0`) plus every nonzero vector above.
    const ALL_GATEWAY_METHODS: [i32; 7] = [0, 1, 2, 3, -1, i32::MAX, i32::MIN];
    /// `RdpServerAuthentication` values that must **not** trip StrictServerAuth
    /// (only Require `== 1` rejects). Product: `0=NoAuth`, `2=Warn`; plus unknowns
    /// (`3` / `-1` / `MAX` / `MIN`) so a closed allow-list cannot false-reject.
    const NON_REQUIRE_SERVER_AUTH: [i32; 6] = [0, 2, 3, -1, i32::MAX, i32::MIN];
    /// C# `RdpSessionViewModel.TunnelExternalClientUnsupportedMessage` — pinned
    /// independently of the Rust const so an edit to either side fails the test.
    const CSHARP_TUNNEL_EXTERNAL_CLIENT_UNSUPPORTED: &str = "The external Remote Desktop client cannot be used with a per-connection VPN tunnel because mstsc.exe would connect from the host network. Use embedded RDP without Azure AD/external-client routing, or disable the tunnel.";
    /// C# `RdpSessionViewModel.TunnelStrictServerAuthUnsupportedMessage` — pinned
    /// independently of the Rust const so an edit to either side fails the test.
    const CSHARP_TUNNEL_STRICT_SERVER_AUTH_UNSUPPORTED: &str = "Strict RDP server authentication cannot be used with the current per-connection VPN tunnel because the embedded ActiveX control validates the loopback forwarder name instead of the original server name. Set server authentication to Warn, or disable the tunnel.";

    #[test]
    fn tunnel_off_allows_all_combos() {
        // Tunnel off: every gateway value + external + strict must still Ok
        // (C# only gates when TunnelEnabled).
        for method in ALL_GATEWAY_METHODS {
            assert!(
                validate_tunnel_rdp_policy(TunnelRdpPolicy {
                    tunnel_enabled: false,
                    use_external_client: true,
                    gateway_usage_method: method,
                    server_authentication: 1,
                })
                .is_ok(),
                "tunnel off must allow gateway_usage_method={method}"
            );
        }
    }

    #[test]
    fn gateway_combo_allows_when_tunnel_off() {
        // Tunnel off never rejects gateway (C# enum + hostile extremes).
        for method in ALL_GATEWAY_METHODS {
            assert!(
                validate_rdp_gateway_tunnel_combo(false, method).is_ok(),
                "tunnel off must allow gateway_usage_method={method}"
            );
        }
    }

    #[test]
    fn gateway_combo_allows_zero_usage_with_tunnel() {
        assert!(validate_rdp_gateway_tunnel_combo(true, 0).is_ok());
    }

    #[test]
    fn gateway_combo_rejects_nonzero_with_tunnel() {
        for method in NONZERO_GATEWAY_METHODS {
            let err = validate_rdp_gateway_tunnel_combo(true, method)
                .expect_err("gateway nonzero + tunnel");
            assert_eq!(err, TunnelRdpConflict::Gateway);
            assert_eq!(err.message(), TUNNEL_GATEWAY_UNSUPPORTED);
        }
    }

    #[test]
    fn tunnel_rejects_gateway() {
        let err = validate_tunnel_rdp_policy(TunnelRdpPolicy {
            tunnel_enabled: true,
            use_external_client: false,
            gateway_usage_method: 1,
            server_authentication: 0,
        })
        .expect_err("gateway");
        assert_eq!(err, TunnelRdpConflict::Gateway);
        assert!(err.message().contains("RD Gateway"));
        assert!(err.message().contains("tunnel"));
    }

    #[test]
    fn tunnel_rejects_gateway_any_nonzero_including_negative() {
        for method in NONZERO_GATEWAY_METHODS {
            let err = validate_tunnel_rdp_policy(TunnelRdpPolicy {
                tunnel_enabled: true,
                use_external_client: false,
                gateway_usage_method: method,
                server_authentication: 0,
            })
            .expect_err("gateway nonzero");
            assert_eq!(err, TunnelRdpConflict::Gateway);
        }
    }

    #[test]
    fn policy_gateway_err_matches_combo_helper_identity() {
        // Delegation contract: full policy Gateway path must be the same conflict +
        // message as the focused combo helper (no divergent inline check).
        for method in NONZERO_GATEWAY_METHODS {
            let combo = validate_rdp_gateway_tunnel_combo(true, method)
                .expect_err("combo");
            let policy = validate_tunnel_rdp_policy(TunnelRdpPolicy {
                tunnel_enabled: true,
                use_external_client: false,
                gateway_usage_method: method,
                server_authentication: 0,
            })
            .expect_err("policy");
            assert_eq!(combo, TunnelRdpConflict::Gateway);
            assert_eq!(policy, combo);
            assert_eq!(policy.message(), TUNNEL_GATEWAY_UNSUPPORTED);
            assert_eq!(format!("{policy}"), TUNNEL_GATEWAY_UNSUPPORTED);
        }
    }

    #[test]
    fn tunnel_rejects_external_client() {
        let err = validate_tunnel_rdp_policy(TunnelRdpPolicy {
            tunnel_enabled: true,
            use_external_client: true,
            gateway_usage_method: 0,
            server_authentication: 0,
        })
        .expect_err("external");
        assert_eq!(err, TunnelRdpConflict::ExternalClient);
        assert_eq!(err.message(), TUNNEL_EXTERNAL_CLIENT_UNSUPPORTED);
        assert_eq!(format!("{err}"), TUNNEL_EXTERNAL_CLIENT_UNSUPPORTED);
        assert_eq!(err.to_string(), CSHARP_TUNNEL_EXTERNAL_CLIENT_UNSUPPORTED);
        assert!(err.message().contains("mstsc.exe"));
        assert!(err.message().contains("tunnel"));
    }

    #[test]
    fn external_client_message_matches_csharp_constant() {
        // Attack: message identity with C# `TunnelExternalClientUnsupportedMessage`.
        assert_eq!(
            TUNNEL_EXTERNAL_CLIENT_UNSUPPORTED,
            CSHARP_TUNNEL_EXTERNAL_CLIENT_UNSUPPORTED
        );
        assert_eq!(
            TunnelRdpConflict::ExternalClient.message(),
            CSHARP_TUNNEL_EXTERNAL_CLIENT_UNSUPPORTED
        );
        assert_eq!(
            format!("{}", TunnelRdpConflict::ExternalClient),
            CSHARP_TUNNEL_EXTERNAL_CLIENT_UNSUPPORTED
        );
    }

    #[test]
    fn tunnel_rejects_strict_server_auth() {
        // C# `RdpServerAuthentication == 1` (Require) + tunnel → fail closed.
        let err = validate_tunnel_rdp_policy(TunnelRdpPolicy {
            tunnel_enabled: true,
            use_external_client: false,
            gateway_usage_method: 0,
            server_authentication: 1,
        })
        .expect_err("strict");
        assert_eq!(err, TunnelRdpConflict::StrictServerAuth);
        assert_eq!(err.message(), TUNNEL_STRICT_SERVER_AUTH_UNSUPPORTED);
        assert_eq!(format!("{err}"), TUNNEL_STRICT_SERVER_AUTH_UNSUPPORTED);
        assert_eq!(err.to_string(), CSHARP_TUNNEL_STRICT_SERVER_AUTH_UNSUPPORTED);
        assert!(err.message().contains("server authentication"));
        assert!(err.message().contains("tunnel"));
    }

    #[test]
    fn strict_server_auth_message_matches_csharp_constant() {
        // Attack: message identity with C# `TunnelStrictServerAuthUnsupportedMessage`.
        assert_eq!(
            TUNNEL_STRICT_SERVER_AUTH_UNSUPPORTED,
            CSHARP_TUNNEL_STRICT_SERVER_AUTH_UNSUPPORTED
        );
        assert_eq!(
            TunnelRdpConflict::StrictServerAuth.message(),
            CSHARP_TUNNEL_STRICT_SERVER_AUTH_UNSUPPORTED
        );
        assert_eq!(
            format!("{}", TunnelRdpConflict::StrictServerAuth),
            CSHARP_TUNNEL_STRICT_SERVER_AUTH_UNSUPPORTED
        );
    }

    #[test]
    fn tunnel_allows_non_require_server_auth() {
        // C# only rejects `== 1`; Warn(=2), NoAuth(=0), unknowns must Ok with tunnel.
        // Attack vectors: 0 / 2 / 3 / -1 / MAX / MIN (closed allow-lists must not false-reject).
        for auth in NON_REQUIRE_SERVER_AUTH {
            assert!(
                validate_tunnel_rdp_policy(TunnelRdpPolicy {
                    tunnel_enabled: true,
                    use_external_client: false,
                    gateway_usage_method: 0,
                    server_authentication: auth,
                })
                .is_ok(),
                "auth={auth} must allow (only Require=1 rejects with tunnel)"
            );
        }
        // Explicit Require control: same fixture with auth=1 must still reject.
        let err = validate_tunnel_rdp_policy(TunnelRdpPolicy {
            tunnel_enabled: true,
            use_external_client: false,
            gateway_usage_method: 0,
            server_authentication: 1,
        })
        .expect_err("Require=1 control");
        assert_eq!(err, TunnelRdpConflict::StrictServerAuth);
    }

    #[test]
    fn external_checked_before_gateway() {
        // When both conflict, external wins (same order as C# ShouldUseExternalClient
        // before the gateway guard). Priority: external → gateway → strict auth.
        let err = validate_tunnel_rdp_policy(TunnelRdpPolicy {
            tunnel_enabled: true,
            use_external_client: true,
            gateway_usage_method: 2,
            server_authentication: 1,
        })
        .expect_err("external first");
        assert_eq!(err, TunnelRdpConflict::ExternalClient);
    }

    #[test]
    fn external_checked_before_strict_auth() {
        // External must win over Strict when gateway is Direct (`0`) — otherwise a
        // reorder that checks Strict before External is invisible to the
        // gateway-also-conflict fixture.
        let err = validate_tunnel_rdp_policy(TunnelRdpPolicy {
            tunnel_enabled: true,
            use_external_client: true,
            gateway_usage_method: 0,
            server_authentication: 1,
        })
        .expect_err("external before strict");
        assert_eq!(err, TunnelRdpConflict::ExternalClient);
        assert_ne!(err, TunnelRdpConflict::StrictServerAuth);
    }

    #[test]
    fn gateway_checked_before_strict_auth() {
        // Gateway is prioritized before strict auth (C# order after external).
        for method in NONZERO_GATEWAY_METHODS {
            let err = validate_tunnel_rdp_policy(TunnelRdpPolicy {
                tunnel_enabled: true,
                use_external_client: false,
                gateway_usage_method: method,
                server_authentication: 1,
            })
            .expect_err("gateway before strict");
            assert_eq!(err, TunnelRdpConflict::Gateway);
            assert_ne!(err, TunnelRdpConflict::StrictServerAuth);
        }
    }

    #[test]
    fn colour_depth_normalises() {
        assert_eq!(normalise_color_depth(32), 32);
        assert_eq!(normalise_color_depth(16), 16);
        assert_eq!(normalise_color_depth(7), 32);
        assert_eq!(normalise_color_depth(0), 32);
    }

    #[test]
    fn debug_redacts_password() {
        let opts = RdpConfigureOptions::new("host.example", 3389).with_password("s3cret");
        let dbg = format!("{opts:?}");
        let pretty = format!("{opts:#?}");
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains("s3cret"));
        assert!(pretty.contains("<redacted>"));
        assert!(!pretty.contains("s3cret"));
    }

    #[test]
    fn password_zeroized_on_drop_of_options() {
        let mut opts = RdpConfigureOptions::new("h", 3389).with_password("wipe-me");
        assert!(opts.password.is_some());
        opts.password = None;
        assert!(opts.password.is_none());
    }

    #[test]
    fn wipe_password_on_drop_clears_leftover() {
        let mut opts = RdpConfigureOptions::new("h", 3389).with_password("leftover-secret");
        {
            let _guard = WipePasswordOnDrop::new(&mut opts.password);
            // Simulate early Err before take_for_put — guard must wipe on scope exit.
        }
        assert!(opts.password.is_none());
        let dbg = format!("{opts:?}");
        assert!(!dbg.contains("leftover-secret"));
    }

    #[test]
    fn wipe_password_take_for_put_then_manual_zeroize_leaves_none() {
        let mut opts = RdpConfigureOptions::new("h", 3389).with_password("put-path");
        {
            let mut guard = WipePasswordOnDrop::new(&mut opts.password);
            let mut pwd = guard.take_for_put().expect("pwd");
            assert_eq!(pwd.as_str(), "put-path");
            pwd.zeroize();
            drop(pwd);
            // Guard Drop finds None — no double-free / no leftover.
        }
        assert!(opts.password.is_none());
    }

    #[test]
    fn validate_rejects_empty_and_whitespace_server() {
        for server in ["", "   ", "\t\n"] {
            let opts = RdpConfigureOptions::new(server, 3389);
            let err = validate_rdp_configure_options(&opts).expect_err("server");
            assert_eq!(err.code(), windows::Win32::Foundation::E_INVALIDARG);
            assert!(err.message().contains("server"));
        }
    }

    #[test]
    fn validate_rejects_port_zero() {
        let opts = RdpConfigureOptions::new("host", 0);
        let err = validate_rdp_configure_options(&opts).expect_err("port");
        assert!(err.message().contains("port"));
    }

    #[test]
    fn validate_rejects_oversized_server_username_domain_password() {
        let big_server = "a".repeat(MAX_SERVER_CHARS + 1);
        let err = validate_rdp_configure_options(&RdpConfigureOptions::new(big_server, 3389))
            .expect_err("server len");
        assert!(err.message().contains("server"));
        assert!(!err.message().contains("aaa"));

        let mut opts = RdpConfigureOptions::new("host", 3389);
        opts.username = Some("u".repeat(MAX_USERNAME_CHARS + 1));
        let err = validate_rdp_configure_options(&opts).expect_err("user");
        assert!(err.message().contains("username"));

        opts.username = None;
        opts.domain = Some("d".repeat(MAX_DOMAIN_CHARS + 1));
        let err = validate_rdp_configure_options(&opts).expect_err("domain");
        assert!(err.message().contains("domain"));

        let secret = "p".repeat(MAX_PASSWORD_CHARS + 1);
        opts.domain = None;
        opts = opts.with_password(secret.clone());
        let err = validate_rdp_configure_options(&opts).expect_err("password");
        assert!(err.message().contains("password"));
        assert!(!err.message().contains(&secret));
        assert!(!format!("{err}").contains(&secret));
    }

    #[test]
    fn validate_rejects_nul_in_fields() {
        let opts = RdpConfigureOptions::new("host\0evil", 3389);
        assert!(validate_rdp_configure_options(&opts).is_err());

        let mut opts = RdpConfigureOptions::new("host", 3389);
        opts.username = Some("u\0".into());
        assert!(validate_rdp_configure_options(&opts).is_err());
        opts.username = None;
        opts.domain = Some("d\0".into());
        assert!(validate_rdp_configure_options(&opts).is_err());
        opts.domain = None;
        opts = opts.with_password("p\0");
        assert!(validate_rdp_configure_options(&opts).is_err());
    }

    #[test]
    fn validate_rejects_bad_desktop_axes() {
        let mut opts = RdpConfigureOptions::new("host", 3389);
        opts.desktop_width = 0;
        assert!(validate_rdp_configure_options(&opts).is_err());
        opts.desktop_width = 1024;
        opts.desktop_height = -1;
        assert!(validate_rdp_configure_options(&opts).is_err());
        opts.desktop_height = MAX_DESKTOP_AXIS + 1;
        assert!(validate_rdp_configure_options(&opts).is_err());
    }

    #[test]
    fn validate_accepts_sane_options() {
        let mut opts = RdpConfigureOptions::new("host.example", 3389).with_password("ok");
        opts.username = Some("lab".into());
        opts.domain = Some("CORP".into());
        assert!(validate_rdp_configure_options(&opts).is_ok());
    }

    #[test]
    fn configure_report_cred_ssp_risk_flag() {
        let mut report = ConfigureReport::default();
        assert!(!report.has_cred_ssp_risk());
        report.cred_ssp_soft_missed = true;
        report.push_missing(CREDSSP_SOFT_MISS_NLA_RISK.to_string());
        assert!(report.has_cred_ssp_risk());
        assert!(!report.all_soft_applied());
        assert!(report.soft_failures.iter().any(|m| m.contains("NLA")));
    }

    #[test]
    fn cred_ssp_soft_miss_constants_document_nla() {
        assert!(CREDSSP_SOFT_MISS_NLA_RISK.contains("NLA"));
        assert!(CREDSSP_SOFT_MISS_NLA_RISK.contains("Connect"));
        assert!(NEGOTIATE_SOFT_MISS.contains("NegotiateSecurityLayer"));
    }

    #[test]
    fn validate_trims_server_for_emptiness_but_rejects_oversize_on_raw_len() {
        let opts = RdpConfigureOptions::new("  host.example  ", 3389);
        assert!(validate_rdp_configure_options(&opts).is_ok());
        // Raw length (not trim) is what BSTR sizing cares about for the oversize cap.
        let padded = format!("{}{}", " ", "a".repeat(MAX_SERVER_CHARS));
        assert!(padded.len() > MAX_SERVER_CHARS);
        let opts = RdpConfigureOptions::new(padded, 3389);
        assert!(validate_rdp_configure_options(&opts).is_err());
    }
}
