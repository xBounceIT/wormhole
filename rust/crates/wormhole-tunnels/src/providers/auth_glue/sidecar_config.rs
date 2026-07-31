//! `OpenVpnSidecarConfig` — stdin JSON for `wormhole-ovpnproxy`.
//!
//! Field names are lower_snake_case to match Go and C#
//! `Services/Tunneling/OpenVpn/OpenVpnSidecarConfig.cs`.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::TunnelError;

use super::super::secret_shape::require_openvpn_sidecar_secret;

/// Wire format passed to `wormhole-ovpnproxy.exe` via stdin (one JSON object).
///
/// [`Debug`] redacts `profile_ovpn` / `password` / `challenge_response` so tracing
/// never prints sidecar secrets.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenVpnSidecarConfig {
    /// Opaque `.ovpn` profile text (must be non-empty before spawn).
    pub profile_ovpn: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// OpenVPN dynamic challenge (CRV1) response — OTP or `"p"` / `"push"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge_response: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_adapter_ids: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_remotes: Option<Vec<OpenVpnTransportRemote>>,
    #[serde(default)]
    pub mock: bool,
}

/// One OpenVPN `remote` for transport pinning (Stormshield).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenVpnTransportRemote {
    pub host: String,
    pub port: String,
    pub protocol: String,
}

impl fmt::Debug for OpenVpnSidecarConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenVpnSidecarConfig")
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

impl OpenVpnSidecarConfig {
    /// Serialize to UTF-8 JSON bytes and validate the establish shape gate.
    pub fn to_stdin_json(&self) -> Result<Vec<u8>, TunnelError> {
        let bytes = serde_json::to_vec(self).map_err(|_| {
            TunnelError::Establish("failed to serialize OpenVpnSidecarConfig JSON".into())
        })?;
        require_openvpn_sidecar_secret(&bytes)?;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_password_and_profile() {
        let cfg = OpenVpnSidecarConfig {
            profile_ovpn: "client\n<key>PROFILE_SECRET</key>\n".into(),
            username: Some("AzureAD".into()),
            password: Some("ACCESS_TOKEN_SECRET".into()),
            challenge_response: Some("OTP_SECRET".into()),
            transport_adapter_ids: None,
            transport_remotes: None,
            mock: false,
        };
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("[REDACTED]"), "{dbg}");
        assert!(!dbg.contains("PROFILE_SECRET"), "{dbg}");
        assert!(!dbg.contains("ACCESS_TOKEN_SECRET"), "{dbg}");
        assert!(!dbg.contains("OTP_SECRET"), "{dbg}");
        assert!(dbg.contains("AzureAD"), "{dbg}");
    }
}
