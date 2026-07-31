//! Fortinet provider — spawns `tools/wormhole-fortiproxy` via [`SidecarProcess`].
//!
//! Wire protocol matches WireGuard / OpenVPN: stdin JSON line, stdout `READY <port>`,
//! stdin EOF = shutdown.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use super::super::spawn::{
    default_ready_timeout, establish_sidecar_instance, resolve_sidecar_binary,
};
use crate::sidecar::SidecarBinary;
use crate::{
    TunnelConfigSnapshot, TunnelError, TunnelInstance, TunnelKind, TunnelProvider,
};

/// Fortinet SSL-VPN provider that drives the existing `wormhole-fortiproxy` Go sidecar.
///
/// `secret_blob` is the stdin JSON payload (credentials / SAML material — never logged).
/// Missing binary → [`TunnelError::BinaryNotFound`].
pub struct FortinetProvider {
    establish_count: AtomicUsize,
    binary_override: Option<PathBuf>,
    extra_args: Vec<String>,
    ready_timeout: Duration,
}

impl FortinetProvider {
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
        resolve_sidecar_binary(SidecarBinary::FortiProxy, self.binary_override.as_deref())
    }
}

impl Default for FortinetProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TunnelProvider for FortinetProvider {
    fn kind(&self) -> TunnelKind {
        TunnelKind::Fortinet
    }

    async fn establish(
        &self,
        config: &TunnelConfigSnapshot,
        secret_blob: &[u8],
    ) -> Result<Arc<dyn TunnelInstance>, TunnelError> {
        self.establish_count.fetch_add(1, Ordering::SeqCst);

        if secret_blob.is_empty() {
            return Err(TunnelError::Establish(format!(
                "Fortinet tunnel '{}' has an empty secret payload",
                config.name
            )));
        }

        let path = self.resolve_binary()?;
        establish_sidecar_instance(
            &path,
            &self.extra_args,
            secret_blob,
            self.ready_timeout,
            &config.name,
            "Fortinet",
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
        let provider = FortinetProvider::with_binary_path(
            std::env::temp_dir().join("wormhole-fortiproxy-missing-for-unit-test.exe"),
        );
        let err = match provider
            .establish(
                &TunnelConfigSnapshot::new(Uuid::nil(), TunnelKind::Fortinet, "lab"),
                br#"{"host":"vpn.example","username":"u","password":"p"}"#,
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
            rendered.contains("wormhole-fortiproxy") || rendered.contains("not found"),
            "{rendered}"
        );
    }

    #[tokio::test]
    async fn empty_secret_is_establish_error() {
        let provider = FortinetProvider::with_binary_path(
            std::env::temp_dir().join("wormhole-fortiproxy-missing-for-unit-test.exe"),
        );
        let err = match provider
            .establish(
                &TunnelConfigSnapshot::new(Uuid::nil(), TunnelKind::Fortinet, "lab"),
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
