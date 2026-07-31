//! Pre-spawn secret blob shape checks for sidecar stdin JSON.
//!
//! WatchGuard / Stormshield / Azure VPN store **editor** settings under DPAPI; C# converts
//! those into OpenVPN sidecar JSON (`profile_ovpn`, snake_case) before spawn. Feeding the
//! editor blob (or empty `profile_ovpn`) to ovpnproxy — especially with `mock: true` — can
//! still emit READY and look Connected. Reject wrong shapes here so establish fails closed
//! without logging secrets.

use serde_json::Value;

use crate::TunnelError;

/// Empty check + OpenVPN sidecar shape (non-empty `profile_ovpn`).
pub(crate) fn require_openvpn_establish_secret(
    secret_blob: &[u8],
    kind_label: &str,
    config_name: &str,
) -> Result<(), TunnelError> {
    if secret_blob.is_empty() {
        return Err(TunnelError::Establish(format!(
            "{kind_label} tunnel '{config_name}' has an empty secret payload \
             (expected OpenVpnSidecarConfig JSON)"
        )));
    }
    require_openvpn_sidecar_secret(secret_blob)
}

/// Empty check + Cisco sidecar shape (non-empty `host`).
pub(crate) fn require_cisco_establish_secret(
    secret_blob: &[u8],
    config_name: &str,
) -> Result<(), TunnelError> {
    if secret_blob.is_empty() {
        return Err(TunnelError::Establish(format!(
            "Cisco Secure Client tunnel '{config_name}' has an empty secret payload"
        )));
    }
    require_cisco_sidecar_secret(secret_blob)
}

/// Empty check + Fortinet sidecar shape (non-empty `host`).
pub(crate) fn require_fortinet_establish_secret(
    secret_blob: &[u8],
    config_name: &str,
) -> Result<(), TunnelError> {
    if secret_blob.is_empty() {
        return Err(TunnelError::Establish(format!(
            "Fortinet tunnel '{config_name}' has an empty secret payload"
        )));
    }
    require_fortinet_sidecar_secret(secret_blob)
}

/// Empty check + WireGuard sidecar shape (non-empty `interface_private_key`).
pub(crate) fn require_wireguard_establish_secret(
    secret_blob: &[u8],
    config_name: &str,
) -> Result<(), TunnelError> {
    if secret_blob.is_empty() {
        return Err(TunnelError::Establish(format!(
            "WireGuard tunnel '{config_name}' has an empty secret payload \
             (expected WireGuard sidecar JSON)"
        )));
    }
    require_wireguard_sidecar_secret(secret_blob)
}

/// Require WireGuard sidecar stdin JSON with a non-empty `interface_private_key`.
///
/// Rejects PascalCase editor blobs (`PrivateKey` / `Endpoint`) so establish cannot
/// pretend Up. Never echoes `secret_blob` into the error.
pub(crate) fn require_wireguard_sidecar_secret(secret_blob: &[u8]) -> Result<(), TunnelError> {
    let value = parse_json_object(
        secret_blob,
        "WireGuard sidecar JSON with non-empty interface_private_key",
    )?;
    let key = value
        .get("interface_private_key")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    if key.is_empty() {
        return Err(TunnelError::Establish(
            "tunnel secret is not WireGuard sidecar JSON with non-empty interface_private_key \
             (editor settings must use the sidecar snake_case shape before spawn)"
                .into(),
        ));
    }
    Ok(())
}

/// Require OpenVPN sidecar stdin JSON with a non-empty `profile_ovpn` string.
///
/// Does **not** accept PascalCase editor blobs (`ProfileOvpn` / `Server` / …).
/// Never echoes `secret_blob` into the error.
pub(crate) fn require_openvpn_sidecar_secret(secret_blob: &[u8]) -> Result<(), TunnelError> {
    let value = parse_json_object(
        secret_blob,
        "OpenVpnSidecarConfig JSON with non-empty profile_ovpn",
    )?;
    let profile = value
        .get("profile_ovpn")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    if profile.is_empty() {
        return Err(TunnelError::Establish(
            "tunnel secret is not OpenVpnSidecarConfig JSON with non-empty profile_ovpn \
             (editor settings / auth glue must run before spawn)"
                .into(),
        ));
    }
    Ok(())
}

/// Require Cisco Secure Client sidecar stdin JSON with a non-empty `host` string.
///
/// Rejects PascalCase editor settings (`Host`) so establish cannot pretend Up.
pub(crate) fn require_cisco_sidecar_secret(secret_blob: &[u8]) -> Result<(), TunnelError> {
    let value = parse_json_object(
        secret_blob,
        "CiscoSecureClientSidecarConfig JSON with non-empty host",
    )?;
    let host = value
        .get("host")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    if host.is_empty() {
        return Err(TunnelError::Establish(
            "tunnel secret is not CiscoSecureClientSidecarConfig JSON with non-empty host \
             (editor settings must be converted before spawn)"
                .into(),
        ));
    }
    Ok(())
}

/// Require Fortinet sidecar stdin JSON with a non-empty snake_case `host`.
///
/// Rejects PascalCase editor blobs (`Host`) so establish cannot pretend Up after
/// auth glue. Never echoes `secret_blob` into the error.
pub(crate) fn require_fortinet_sidecar_secret(secret_blob: &[u8]) -> Result<(), TunnelError> {
    let value = parse_json_object(
        secret_blob,
        "FortinetSidecarConfig JSON with non-empty host",
    )?;
    let host = value
        .get("host")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    if host.is_empty() {
        return Err(TunnelError::Establish(
            "tunnel secret is not FortinetSidecarConfig JSON with non-empty host \
             (FortinetSettings / SAML glue must run before spawn)"
                .into(),
        ));
    }
    Ok(())
}

fn parse_json_object(secret_blob: &[u8], expected: &str) -> Result<Value, TunnelError> {
    let value: Value = serde_json::from_slice(secret_blob).map_err(|_| {
        TunnelError::Establish(format!(
            "tunnel secret is not valid JSON (expected {expected})"
        ))
    })?;
    if !value.is_object() {
        return Err(TunnelError::Establish(format!(
            "tunnel secret must be a JSON object (expected {expected})"
        )));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openvpn_accepts_profile_ovpn() {
        require_openvpn_sidecar_secret(br#"{"profile_ovpn":"client\n","mock":true}"#).unwrap();
    }

    #[test]
    fn openvpn_rejects_watchguard_editor_blob() {
        let blob =
            br#"{"Server":"vpn.example","Port":443,"Password":"SUPER_SECRET","ProfileOvpn":"client"}"#;
        let err = require_openvpn_sidecar_secret(blob).unwrap_err();
        let rendered = format!("{err}");
        assert!(rendered.contains("profile_ovpn"), "{rendered}");
        assert!(
            !rendered.contains("SUPER_SECRET"),
            "must not echo secret: {rendered}"
        );
    }

    #[test]
    fn openvpn_rejects_empty_profile_even_with_mock() {
        let err = require_openvpn_sidecar_secret(br#"{"profile_ovpn":"","mock":true}"#).unwrap_err();
        assert!(matches!(err, TunnelError::Establish(_)));
    }

    #[test]
    fn establish_helper_rejects_empty() {
        let err = require_openvpn_establish_secret(b"", "WatchGuard", "lab").unwrap_err();
        assert!(format!("{err}").contains("empty"));
    }

    #[test]
    fn cisco_accepts_host() {
        require_cisco_sidecar_secret(br#"{"host":"vpn.example","username":"u"}"#).unwrap();
    }

    #[test]
    fn cisco_rejects_pascal_case_editor_host() {
        let blob = br#"{"Host":"vpn.example","Password":"CISCO_SECRET_MARKER"}"#;
        let err = require_cisco_sidecar_secret(blob).unwrap_err();
        let rendered = format!("{err}");
        assert!(rendered.contains("host"), "{rendered}");
        assert!(!rendered.contains("CISCO_SECRET_MARKER"), "{rendered}");
    }

    #[test]
    fn wireguard_accepts_interface_private_key() {
        require_wireguard_sidecar_secret(
            br#"{"interface_private_key":"x","endpoint":"127.0.0.1:51820"}"#,
        )
        .unwrap();
    }

    #[test]
    fn wireguard_rejects_pascal_case_editor_blob() {
        let blob = br#"{"PrivateKey":"WG_SECRET_MARKER","Endpoint":"10.0.0.1"}"#;
        let err = require_wireguard_sidecar_secret(blob).unwrap_err();
        let rendered = format!("{err}");
        assert!(rendered.contains("interface_private_key"), "{rendered}");
        assert!(!rendered.contains("WG_SECRET_MARKER"), "{rendered}");
    }

    #[test]
    fn wireguard_establish_helper_rejects_empty() {
        let err = require_wireguard_establish_secret(b"", "lab").unwrap_err();
        assert!(format!("{err}").contains("empty"));
    }

    #[test]
    fn fortinet_accepts_snake_case_host() {
        require_fortinet_sidecar_secret(
            br#"{"host":"vpn.example.com","username":"u","password":"p"}"#,
        )
        .unwrap();
    }

    #[test]
    fn fortinet_rejects_pascal_case_editor_host() {
        let blob = br#"{"Host":"vpn.example.com","Password":"FORTI_SECRET_MARKER"}"#;
        let err = require_fortinet_sidecar_secret(blob).unwrap_err();
        let rendered = format!("{err}");
        assert!(rendered.contains("host"), "{rendered}");
        assert!(!rendered.contains("FORTI_SECRET_MARKER"), "{rendered}");
    }

    #[test]
    fn fortinet_establish_helper_rejects_empty() {
        let err = require_fortinet_establish_secret(b"", "lab").unwrap_err();
        assert!(format!("{err}").contains("empty"));
    }
}
