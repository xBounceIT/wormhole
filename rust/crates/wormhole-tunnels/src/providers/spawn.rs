//! Shared spawn/handshake for Go sidecars that speak stdin-JSON + READY/SOCKS.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::sidecar::{
    locate_sidecar, SidecarBinary, SidecarProcess, SidecarTunnelInstance, DEFAULT_READY_TIMEOUT,
};
use crate::{TunnelError, TunnelInstance};

/// Resolve binary path: explicit override (any file name, for tests) or locate by sidecar name.
pub(crate) fn resolve_sidecar_binary(
    binary: SidecarBinary,
    binary_override: Option<&Path>,
) -> Result<PathBuf, TunnelError> {
    if let Some(path) = binary_override {
        if path.is_file() {
            return Ok(path.to_path_buf());
        }
        return Err(TunnelError::BinaryNotFound {
            binary: binary.exe_name().to_string(),
            searched: vec![path.display().to_string()],
        });
    }
    locate_sidecar(binary)
}

/// Spawn sidecar, write secret config line, await READY/SOCKS → [`SidecarTunnelInstance`].
///
/// Never logs `secret_blob`. Empty secrets are rejected by the caller before this is invoked.
pub(crate) async fn establish_sidecar_instance(
    path: &Path,
    extra_args: &[String],
    secret_blob: &[u8],
    ready_timeout: Duration,
    config_name: &str,
    kind_label: &str,
) -> Result<Arc<dyn TunnelInstance>, TunnelError> {
    tracing::debug!(
        config = %config_name,
        path = %path.display(),
        kind = kind_label,
        "launching tunnel sidecar"
    );

    let arg_refs: Vec<&str> = extra_args.iter().map(String::as_str).collect();
    let mut proc = SidecarProcess::spawn(path, &arg_refs).await?;
    let port = match proc.handshake(secret_blob, ready_timeout).await {
        Ok(port) => port,
        Err(e) => {
            let _ = proc.shutdown().await;
            return Err(e);
        }
    };

    Ok(Arc::new(SidecarTunnelInstance::new(proc, port)))
}

pub(crate) fn default_ready_timeout() -> Duration {
    DEFAULT_READY_TIMEOUT
}
