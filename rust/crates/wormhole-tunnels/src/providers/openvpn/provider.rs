//! OpenVPN provider — spawns `tools/wormhole-ovpnproxy` via [`SidecarProcess`].
//!
//! Wire protocol matches WireGuard: stdin JSON line, stdout `READY <port>`, stdin EOF = shutdown.
//! Also the data-plane binary for WatchGuard / Stormshield / Azure VPN (see `ovpn_backed`).

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use super::super::secret_shape::require_openvpn_establish_secret;
use super::super::spawn::{
    default_ready_timeout, establish_sidecar_instance, resolve_sidecar_binary,
};
use crate::sidecar::SidecarBinary;
use crate::{
    TunnelConfigSnapshot, TunnelError, TunnelInstance, TunnelKind, TunnelProvider,
};

/// OpenVPN tunnel provider that drives the existing `wormhole-ovpnproxy` Go sidecar.
///
/// `secret_blob` is the stdin JSON payload (same snake_case fields as C#
/// `OpenVpnSidecarConfig` / Go `config`). Missing binary → [`TunnelError::BinaryNotFound`].
pub struct OpenVpnProvider {
    establish_count: AtomicUsize,
    binary_override: Option<PathBuf>,
    extra_args: Vec<String>,
    ready_timeout: Duration,
}

impl OpenVpnProvider {
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

    pub fn with_extra_args(mut self, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
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

impl Default for OpenVpnProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TunnelProvider for OpenVpnProvider {
    fn kind(&self) -> TunnelKind {
        TunnelKind::OpenVpn
    }

    async fn establish(
        &self,
        config: &TunnelConfigSnapshot,
        secret_blob: &[u8],
    ) -> Result<Arc<dyn TunnelInstance>, TunnelError> {
        self.establish_count.fetch_add(1, Ordering::SeqCst);

        require_openvpn_establish_secret(secret_blob, "OpenVPN", &config.name)?;

        let path = self.resolve_binary()?;
        establish_sidecar_instance(
            &path,
            &self.extra_args,
            secret_blob,
            self.ready_timeout,
            &config.name,
            "OpenVpn",
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[tokio::test]
    async fn missing_binary_returns_binary_not_found_not_up() {
        let provider = OpenVpnProvider::with_binary_path(
            std::env::temp_dir().join("wormhole-ovpnproxy-missing-for-unit-test.exe"),
        );
        let err = match provider
            .establish(
                &TunnelConfigSnapshot::new(Uuid::nil(), TunnelKind::OpenVpn, "lab"),
                br#"{"profile_ovpn":"client","mock":true}"#,
            )
            .await
        {
            Ok(_) => panic!("expected BinaryNotFound"),
            Err(e) => e,
        };
        assert!(
            matches!(err, TunnelError::BinaryNotFound { .. }),
            "expected BinaryNotFound, got {err:?}"
        );
        let rendered = format!("{err}");
        assert!(
            rendered.contains("wormhole-ovpnproxy") || rendered.contains("not found"),
            "{rendered}"
        );
    }

    #[tokio::test]
    async fn empty_secret_is_establish_error() {
        let provider = OpenVpnProvider::with_binary_path(
            std::env::temp_dir().join("wormhole-ovpnproxy-missing-for-unit-test.exe"),
        );
        let err = match provider
            .establish(
                &TunnelConfigSnapshot::new(Uuid::nil(), TunnelKind::OpenVpn, "lab"),
                b"",
            )
            .await
        {
            Ok(_) => panic!("expected Establish error"),
            Err(e) => e,
        };
        assert!(matches!(err, TunnelError::Establish(_)), "{err:?}");
    }
}
