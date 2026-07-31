//! Build [`OpenVpnSidecarConfig`] from already-resolved portal/cache materials.
//!
//! Interactive OTP / SAML / Entra WebView2 flows are **not** implemented here —
//! callers supply [`ResolvedOvpnMaterials`] after those steps complete.

use std::fmt;

use crate::{TunnelError, TunnelKind};

use super::sidecar_config::{OpenVpnSidecarConfig, OpenVpnTransportRemote};

/// Sentinel username Azure P2S gateways expect (`AzureVpnTunnelProvider.AadAuthUsername`).
pub const AZURE_AAD_USERNAME: &str = "AzureAD";

/// Resolved OpenVPN data-plane inputs (post-auth / post-cache).
///
/// [`Debug`] redacts profile / password / challenge so logs never print secrets.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct ResolvedOvpnMaterials {
    pub profile_ovpn: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub challenge_response: Option<String>,
    pub transport_adapter_ids: Option<Vec<String>>,
    pub transport_remotes: Option<Vec<OpenVpnTransportRemote>>,
    pub mock: bool,
}

impl fmt::Debug for ResolvedOvpnMaterials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolvedOvpnMaterials")
            .field("profile_ovpn", &super::redact_nonempty(&self.profile_ovpn))
            .field("username", &self.username)
            .field(
                "password",
                &self.password.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "challenge_response",
                &self.challenge_response.as_ref().map(|_| "[REDACTED]"),
            )
            .field("transport_adapter_ids", &self.transport_adapter_ids)
            .field("transport_remotes", &self.transport_remotes)
            .field("mock", &self.mock)
            .finish()
    }
}

/// Trait hook: transform resolved materials into OpenVPN sidecar stdin JSON.
pub trait OvpnAuthGlue {
    fn kind(&self) -> TunnelKind;

    /// Build [`OpenVpnSidecarConfig`] then serialize + shape-validate.
    fn to_sidecar_json(&self, materials: &ResolvedOvpnMaterials) -> Result<Vec<u8>, TunnelError> {
        self.to_sidecar_config(materials)?.to_stdin_json()
    }

    /// Kind-specific defaults (e.g. Azure forces username `AzureAD`).
    fn to_sidecar_config(
        &self,
        materials: &ResolvedOvpnMaterials,
    ) -> Result<OpenVpnSidecarConfig, TunnelError>;
}

fn require_profile(materials: &ResolvedOvpnMaterials) -> Result<(), TunnelError> {
    if materials.profile_ovpn.trim().is_empty() {
        return Err(TunnelError::Establish(
            "OpenVpnSidecarConfig requires non-empty profile_ovpn \
             (portal/cache auth glue must resolve a profile before spawn)"
                .into(),
        ));
    }
    Ok(())
}

fn empty_to_none(s: Option<&String>) -> Option<String> {
    s.map(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

/// Shared WatchGuard / Stormshield mapping (credentials + optional transport fields).
fn passthrough_sidecar_config(
    materials: &ResolvedOvpnMaterials,
) -> Result<OpenVpnSidecarConfig, TunnelError> {
    require_profile(materials)?;
    Ok(OpenVpnSidecarConfig {
        profile_ovpn: materials.profile_ovpn.clone(),
        username: empty_to_none(materials.username.as_ref()),
        password: empty_to_none(materials.password.as_ref()),
        challenge_response: empty_to_none(materials.challenge_response.as_ref()),
        transport_adapter_ids: materials.transport_adapter_ids.clone(),
        transport_remotes: materials.transport_remotes.clone(),
        mock: materials.mock,
    })
}

/// Generic builder used by WatchGuard / Stormshield / OpenVPN-shaped callers.
pub fn build_sidecar_json(materials: &ResolvedOvpnMaterials) -> Result<Vec<u8>, TunnelError> {
    WatchguardAuthGlue.to_sidecar_json(materials)
}

/// Materials for Azure: profile + Entra **access** token as password.
pub fn azure_materials_from_access_token(
    profile_ovpn: impl Into<String>,
    access_token: impl Into<String>,
) -> ResolvedOvpnMaterials {
    ResolvedOvpnMaterials {
        profile_ovpn: profile_ovpn.into(),
        username: Some(AZURE_AAD_USERNAME.to_string()),
        password: Some(access_token.into()),
        ..Default::default()
    }
}

/// Materials for WatchGuard after profile + credentials are known.
pub fn watchguard_materials(
    profile_ovpn: impl Into<String>,
    username: impl Into<String>,
    password: impl Into<String>,
    challenge_response: Option<String>,
) -> ResolvedOvpnMaterials {
    ResolvedOvpnMaterials {
        profile_ovpn: profile_ovpn.into(),
        username: Some(username.into()),
        password: Some(password.into()),
        challenge_response,
        ..Default::default()
    }
}

/// Materials for Stormshield (optional transport pinning).
pub fn stormshield_materials(
    profile_ovpn: impl Into<String>,
    username: Option<String>,
    password: Option<String>,
    transport_adapter_ids: Option<Vec<String>>,
    transport_remotes: Option<Vec<OpenVpnTransportRemote>>,
) -> ResolvedOvpnMaterials {
    ResolvedOvpnMaterials {
        profile_ovpn: profile_ovpn.into(),
        username,
        password,
        transport_adapter_ids,
        transport_remotes,
        ..Default::default()
    }
}

/// WatchGuard auth glue — passes username/password/challenge through as-is.
#[derive(Debug, Default, Clone, Copy)]
pub struct WatchguardAuthGlue;

impl OvpnAuthGlue for WatchguardAuthGlue {
    fn kind(&self) -> TunnelKind {
        TunnelKind::Watchguard
    }

    fn to_sidecar_config(
        &self,
        materials: &ResolvedOvpnMaterials,
    ) -> Result<OpenVpnSidecarConfig, TunnelError> {
        passthrough_sidecar_config(materials)
    }
}

/// Stormshield auth glue — same OpenVPN shape; transport fields optional.
#[derive(Debug, Default, Clone, Copy)]
pub struct StormshieldAuthGlue;

impl OvpnAuthGlue for StormshieldAuthGlue {
    fn kind(&self) -> TunnelKind {
        TunnelKind::Stormshield
    }

    fn to_sidecar_config(
        &self,
        materials: &ResolvedOvpnMaterials,
    ) -> Result<OpenVpnSidecarConfig, TunnelError> {
        passthrough_sidecar_config(materials)
    }
}

/// Azure VPN auth glue — forces username [`AZURE_AAD_USERNAME`].
#[derive(Debug, Default, Clone, Copy)]
pub struct AzureVpnAuthGlue;

impl OvpnAuthGlue for AzureVpnAuthGlue {
    fn kind(&self) -> TunnelKind {
        TunnelKind::AzureVpn
    }

    fn to_sidecar_config(
        &self,
        materials: &ResolvedOvpnMaterials,
    ) -> Result<OpenVpnSidecarConfig, TunnelError> {
        require_profile(materials)?;
        let password = empty_to_none(materials.password.as_ref()).ok_or_else(|| {
            TunnelError::Establish(
                "Azure VPN OpenVpnSidecarConfig requires a non-empty access token password".into(),
            )
        })?;
        Ok(OpenVpnSidecarConfig {
            profile_ovpn: materials.profile_ovpn.clone(),
            username: Some(AZURE_AAD_USERNAME.to_string()),
            password: Some(password),
            challenge_response: None,
            transport_adapter_ids: materials.transport_adapter_ids.clone(),
            transport_remotes: materials.transport_remotes.clone(),
            mock: materials.mock,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::secret_shape::require_openvpn_sidecar_secret;

    #[test]
    fn azure_forces_aad_username_and_passes_shape_gate() {
        let materials = azure_materials_from_access_token("client\nremote gw 443\n", "access.token");
        let json = AzureVpnAuthGlue.to_sidecar_json(&materials).unwrap();
        require_openvpn_sidecar_secret(&json).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(v["username"], AZURE_AAD_USERNAME);
        assert_eq!(v["password"], "access.token");
        assert!(v["profile_ovpn"].as_str().unwrap().contains("remote"));
    }

    #[test]
    fn azure_overrides_wrong_username_to_aad() {
        let materials = ResolvedOvpnMaterials {
            profile_ovpn: "client\n".into(),
            username: Some("not-azure-ad".into()),
            password: Some("access.token".into()),
            ..Default::default()
        };
        let cfg = AzureVpnAuthGlue.to_sidecar_config(&materials).unwrap();
        assert_eq!(cfg.username.as_deref(), Some(AZURE_AAD_USERNAME));
        let json = cfg.to_stdin_json().unwrap();
        require_openvpn_sidecar_secret(&json).unwrap();
    }

    #[test]
    fn azure_rejects_whitespace_password() {
        let materials = ResolvedOvpnMaterials {
            profile_ovpn: "client".into(),
            username: Some(AZURE_AAD_USERNAME.into()),
            password: Some("   ".into()),
            ..Default::default()
        };
        let err = AzureVpnAuthGlue.to_sidecar_json(&materials).unwrap_err();
        let rendered = format!("{err}");
        assert!(rendered.contains("access token") || rendered.contains("password"));
    }

    #[test]
    fn azure_rejects_none_password_without_echo() {
        let materials = ResolvedOvpnMaterials {
            profile_ovpn: "client".into(),
            username: Some(AZURE_AAD_USERNAME.into()),
            password: None,
            ..Default::default()
        };
        let err = AzureVpnAuthGlue.to_sidecar_json(&materials).unwrap_err();
        let rendered = format!("{err}");
        assert!(rendered.contains("access token") || rendered.contains("password"));
        assert!(!rendered.contains("SUPER_SECRET"));
    }

    #[test]
    fn materials_debug_redacts_secrets() {
        let materials = watchguard_materials(
            "client\n<key>PROFILE_SECRET</key>\n",
            "user",
            "PASS_SECRET",
            Some("OTP_SECRET".into()),
        );
        let dbg = format!("{materials:?}");
        assert!(dbg.contains("[REDACTED]"), "{dbg}");
        assert!(!dbg.contains("PROFILE_SECRET"), "{dbg}");
        assert!(!dbg.contains("PASS_SECRET"), "{dbg}");
        assert!(!dbg.contains("OTP_SECRET"), "{dbg}");
    }

    #[test]
    fn watchguard_challenge_response_roundtrips() {
        let materials = watchguard_materials("client\n", "user", "pass", Some("123456".into()));
        let cfg = WatchguardAuthGlue.to_sidecar_config(&materials).unwrap();
        assert_eq!(cfg.challenge_response.as_deref(), Some("123456"));
        let json = cfg.to_stdin_json().unwrap();
        require_openvpn_sidecar_secret(&json).unwrap();
    }

    #[test]
    fn empty_profile_fails_before_serialize() {
        let materials = ResolvedOvpnMaterials {
            profile_ovpn: "  ".into(),
            ..Default::default()
        };
        let err = StormshieldAuthGlue.to_sidecar_json(&materials).unwrap_err();
        assert!(format!("{err}").contains("profile_ovpn"));
    }

    #[test]
    fn constructed_config_accepted_by_establish_shape() {
        let materials = stormshield_materials(
            "dev tun\nremote fw.example 1194 udp\n",
            Some("alice".into()),
            Some("pw".into()),
            Some(vec!["{adapter}".into()]),
            Some(vec![OpenVpnTransportRemote {
                host: "fw.example".into(),
                port: "1194".into(),
                protocol: "udp".into(),
            }]),
        );
        let json = StormshieldAuthGlue.to_sidecar_json(&materials).unwrap();
        require_openvpn_sidecar_secret(&json).unwrap();
    }
}
