//! WatchGuard / Stormshield / Azure VPN — data plane is `wormhole-ovpnproxy`.
//!
//! C# does portal / Entra auth in managed code, then feeds `OpenVpnSidecarConfig`
//! JSON to the same sidecar as OpenVPN. This crate wires the **sidecar spawn**
//! (READY/SOCKS + `SidecarProcess`) and exposes [`crate::providers::auth_glue`]
//! builders that construct that stdin JSON from already-resolved materials.
//!
//! WatchGuard Firebox username/password + optional OTP typing helpers and
//! establish-path glue: [`crate::providers::watchguard`] (reuses [`crate::request_otp`];
//! see [`crate::establish_watchguard_crv1`]). Stormshield SNS username/password +
//! optional `password+otp` concat helpers + establish glue:
//! [`crate::StormshieldSnsAuth`] / [`crate::establish_stormshield_sns`] (shared
//! OpenVPN sidecar). Azure VPN establish glue:
//! [`crate::establish_azure`] / [`crate::establish_azure_from_entra`]. This provider
//! `establish` still expects stdin JSON already built (glue resolves auth before
//! spawn). SAML / Entra WebView2 / SNS portal UI remain TODO — see
//! `docs/migration/07-tunnels-mcp.md`.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use super::secret_shape::require_openvpn_establish_secret;
use super::spawn::{
    default_ready_timeout, establish_sidecar_instance, resolve_sidecar_binary,
};
use crate::sidecar::SidecarBinary;
use crate::{
    TunnelConfigSnapshot, TunnelError, TunnelInstance, TunnelKind, TunnelProvider,
};

macro_rules! define_ovpn_backed_provider {
    ($name:ident, $kind:ident, $label:expr) => {
        #[doc = concat!(
            stringify!($kind),
            " provider — spawns `tools/wormhole-ovpnproxy` via [`SidecarProcess`].\n\n",
            "`secret_blob` must be OpenVPN sidecar stdin JSON (`profile_ovpn`, optional\n",
            "username/password/challenge_response). Missing binary → [`TunnelError::BinaryNotFound`]."
        )]
        pub struct $name {
            establish_count: AtomicUsize,
            binary_override: Option<PathBuf>,
            extra_args: Vec<String>,
            ready_timeout: Duration,
        }

        impl $name {
            pub fn new() -> Self {
                Self {
                    establish_count: AtomicUsize::new(0),
                    binary_override: None,
                    extra_args: Vec::new(),
                    ready_timeout: default_ready_timeout(),
                }
            }

            pub fn with_binary_path(path: impl Into<PathBuf>) -> Self {
                Self {
                    binary_override: Some(path.into()),
                    ..Self::new()
                }
            }

            pub fn with_extra_args(
                mut self,
                args: impl IntoIterator<Item = impl Into<String>>,
            ) -> Self {
                self.extra_args = args.into_iter().map(Into::into).collect();
                self
            }

            pub fn with_ready_timeout(mut self, timeout: Duration) -> Self {
                self.ready_timeout = timeout;
                self
            }

            pub fn establish_count(&self) -> usize {
                self.establish_count.load(Ordering::SeqCst)
            }

            fn resolve_binary(&self) -> Result<PathBuf, TunnelError> {
                resolve_sidecar_binary(SidecarBinary::OvpnProxy, self.binary_override.as_deref())
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        #[async_trait]
        impl TunnelProvider for $name {
            fn kind(&self) -> TunnelKind {
                TunnelKind::$kind
            }

            async fn establish(
                &self,
                config: &TunnelConfigSnapshot,
                secret_blob: &[u8],
            ) -> Result<Arc<dyn TunnelInstance>, TunnelError> {
                self.establish_count.fetch_add(1, Ordering::SeqCst);

                require_openvpn_establish_secret(secret_blob, $label, &config.name)?;

                let path = self.resolve_binary()?;
                establish_sidecar_instance(
                    &path,
                    &self.extra_args,
                    secret_blob,
                    self.ready_timeout,
                    &config.name,
                    $label,
                )
                .await
            }
        }
    };
}

define_ovpn_backed_provider!(WatchguardProvider, Watchguard, "WatchGuard");
define_ovpn_backed_provider!(StormshieldProvider, Stormshield, "Stormshield");
define_ovpn_backed_provider!(AzureVpnProvider, AzureVpn, "Azure VPN");

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[tokio::test]
    async fn watchguard_missing_binary_is_binary_not_found() {
        let provider = WatchguardProvider::with_binary_path(
            std::env::temp_dir().join("wormhole-ovpnproxy-missing-wg-unit.exe"),
        );
        let err = match provider
            .establish(
                &TunnelConfigSnapshot::new(Uuid::nil(), TunnelKind::Watchguard, "lab"),
                br#"{"profile_ovpn":"client","mock":true}"#,
            )
            .await
        {
            Ok(_) => panic!("expected BinaryNotFound"),
            Err(e) => e,
        };
        assert!(matches!(err, TunnelError::BinaryNotFound { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn stormshield_empty_secret_before_locate() {
        let provider = StormshieldProvider::with_binary_path(
            std::env::temp_dir().join("wormhole-ovpnproxy-missing-ss-unit.exe"),
        );
        let err = match provider
            .establish(
                &TunnelConfigSnapshot::new(Uuid::nil(), TunnelKind::Stormshield, "lab"),
                b"",
            )
            .await
        {
            Ok(_) => panic!("expected Establish error"),
            Err(e) => e,
        };
        assert!(matches!(err, TunnelError::Establish(_)), "{err:?}");
        let rendered = format!("{err}");
        assert!(
            rendered.contains("OpenVpnSidecarConfig") || rendered.contains("empty"),
            "{rendered}"
        );
    }

    #[tokio::test]
    async fn azure_missing_binary_is_binary_not_found() {
        let provider = AzureVpnProvider::with_binary_path(
            std::env::temp_dir().join("wormhole-ovpnproxy-missing-azure-unit.exe"),
        );
        let err = match provider
            .establish(
                &TunnelConfigSnapshot::new(Uuid::nil(), TunnelKind::AzureVpn, "lab"),
                br#"{"profile_ovpn":"client","username":"AzureAD","password":"token","mock":true}"#,
            )
            .await
        {
            Ok(_) => panic!("expected BinaryNotFound"),
            Err(e) => e,
        };
        assert!(matches!(err, TunnelError::BinaryNotFound { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn azure_rejects_editor_settings_blob_before_spawn() {
        let provider = AzureVpnProvider::with_binary_path(
            std::env::temp_dir().join("wormhole-ovpnproxy-missing-azure-shape.exe"),
        );
        let err = match provider
            .establish(
                &TunnelConfigSnapshot::new(Uuid::nil(), TunnelKind::AzureVpn, "lab"),
                br#"{"TenantId":"t","ClientId":"c","Password":"AZURE_SECRET_MARKER","mock":true}"#,
            )
            .await
        {
            Ok(_) => panic!("must not pretend Up on editor blob"),
            Err(e) => e,
        };
        assert!(matches!(err, TunnelError::Establish(_)), "{err:?}");
        let rendered = format!("{err}");
        assert!(rendered.contains("profile_ovpn"), "{rendered}");
        assert!(!rendered.contains("AZURE_SECRET_MARKER"), "{rendered}");
    }

    #[tokio::test]
    async fn watchguard_rejects_pascal_case_settings_before_locate() {
        let provider = WatchguardProvider::with_binary_path(
            std::env::temp_dir().join("wormhole-ovpnproxy-missing-wg-shape.exe"),
        );
        let err = match provider
            .establish(
                &TunnelConfigSnapshot::new(Uuid::nil(), TunnelKind::Watchguard, "lab"),
                br#"{"Server":"vpn.example","Password":"WG_SECRET_MARKER","ProfileOvpn":"client"}"#,
            )
            .await
        {
            Ok(_) => panic!("expected shape Establish error"),
            Err(e) => e,
        };
        assert!(matches!(err, TunnelError::Establish(_)), "{err:?}");
        let rendered = format!("{err}");
        assert!(rendered.contains("profile_ovpn"), "{rendered}");
        assert!(!rendered.contains("WG_SECRET_MARKER"), "{rendered}");
    }
}
