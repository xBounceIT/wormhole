//! WireGuard provider — spawns `tools/wormhole-wgproxy` via [`SidecarProcess`].

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use super::super::secret_shape::require_wireguard_establish_secret;
use super::super::spawn::{
    default_ready_timeout, establish_sidecar_instance, resolve_sidecar_binary,
};
use crate::sidecar::SidecarBinary;
use crate::{
    TunnelConfigSnapshot, TunnelError, TunnelInstance, TunnelKind, TunnelProvider,
};

/// WireGuard tunnel provider that drives the existing `wormhole-wgproxy` Go sidecar.
///
/// `secret_blob` is the stdin JSON payload (same snake_case fields as
/// `WireGuardSidecarConfig` / the Go `config` struct). Missing binary →
/// [`TunnelError::BinaryNotFound`] (never a fake `Connected` / `Up` without READY).
pub struct WireGuardProvider {
    establish_count: AtomicUsize,
    /// Optional absolute path override (tests / explicit host wiring).
    binary_override: Option<PathBuf>,
    /// Extra process args (e.g. `["-mock"]` for local smoke tests only).
    extra_args: Vec<String>,
    ready_timeout: Duration,
}

impl WireGuardProvider {
    pub fn new() -> Self {
        Self {
            establish_count: AtomicUsize::new(0),
            binary_override: None,
            extra_args: Vec::new(),
            ready_timeout: default_ready_timeout(),
        }
    }

    /// Force a specific sidecar binary path (used by unit tests for missing-binary coverage).
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
        resolve_sidecar_binary(SidecarBinary::WgProxy, self.binary_override.as_deref())
    }
}

impl Default for WireGuardProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TunnelProvider for WireGuardProvider {
    fn kind(&self) -> TunnelKind {
        TunnelKind::WireGuard
    }

    async fn establish(
        &self,
        config: &TunnelConfigSnapshot,
        secret_blob: &[u8],
    ) -> Result<Arc<dyn TunnelInstance>, TunnelError> {
        self.establish_count.fetch_add(1, Ordering::SeqCst);

        require_wireguard_establish_secret(secret_blob, &config.name)?;

        let path = self.resolve_binary()?;
        establish_sidecar_instance(
            &path,
            &self.extra_args,
            secret_blob,
            self.ready_timeout,
            &config.name,
            "WireGuard",
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
        let provider = WireGuardProvider::with_binary_path(
            std::env::temp_dir().join("wormhole-wgproxy-missing-for-unit-test.exe"),
        );
        let err = match provider
            .establish(
                &TunnelConfigSnapshot::new(Uuid::nil(), TunnelKind::WireGuard, "lab"),
                br#"{"interface_private_key":"x"}"#,
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
            rendered.contains("wormhole-wgproxy") || rendered.contains("not found"),
            "{rendered}"
        );
    }

    #[tokio::test]
    async fn empty_secret_is_establish_error() {
        let provider = WireGuardProvider::with_binary_path(
            std::env::temp_dir().join("wormhole-wgproxy-missing-for-unit-test.exe"),
        );
        let err = match provider
            .establish(
                &TunnelConfigSnapshot::new(Uuid::nil(), TunnelKind::WireGuard, "lab"),
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
