//! Spawn and supervise an existing Go sidecar process (do not rewrite the sidecar).

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::time::timeout;

use super::protocol::{parse_ready_or_socks_line, MAX_HANDSHAKE_LINE_BYTES};
use crate::forwarder::{bind_local_forwarder_for, ForwarderRegistry};
use crate::{Socks5Endpoint, TunnelError, TunnelInstance, TunnelState};

/// Default budget for stdin config write + READY/SOCKS handshake (matches C# hosts).
pub const DEFAULT_READY_TIMEOUT: Duration = Duration::from_secs(15);

/// Owns a live sidecar child: stdin config line, stdout READY/SOCKS, graceful stdin-EOF shutdown.
pub struct SidecarProcess {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Option<BufReader<ChildStdout>>,
    path: PathBuf,
    socks_port: Option<u16>,
    /// Background stdout/stderr drain tasks (avoids pipe-buffer deadlock).
    io_drains: Vec<tokio::task::JoinHandle<()>>,
}

impl SidecarProcess {
    /// Spawn `path` with optional args; stdin/stdout/stderr redirected. Does not yet write config.
    pub async fn spawn(path: impl AsRef<Path>, args: &[&str]) -> Result<Self, TunnelError> {
        let path = path.as_ref();
        if !path.is_file() {
            return Err(TunnelError::BinaryNotFound {
                binary: path
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| path.display().to_string()),
                searched: vec![path.display().to_string()],
            });
        }

        let mut cmd = Command::new(path);
        cmd.args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        #[cfg(windows)]
        {
            // Avoid flashing a console window when the parent is a GUI app.
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }

        let mut child = cmd.spawn().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                TunnelError::BinaryNotFound {
                    binary: path
                        .file_name()
                        .map(|s| s.to_string_lossy().into_owned())
                        .unwrap_or_else(|| path.display().to_string()),
                    searched: vec![path.display().to_string()],
                }
            } else {
                TunnelError::Establish(format!(
                    "failed to spawn sidecar {}: {e}",
                    path.display()
                ))
            }
        })?;

        let stdin = child.stdin.take().ok_or_else(|| {
            TunnelError::Establish("sidecar stdin pipe missing after spawn".into())
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            TunnelError::Establish("sidecar stdout pipe missing after spawn".into())
        })?;

        // Drain stderr so a chatty/misbehaving sidecar cannot fill the OS pipe and deadlock.
        // Content is discarded (never logged here — sidecars may echo config-adjacent noise).
        let mut io_drains = Vec::new();
        if let Some(stderr) = child.stderr.take() {
            io_drains.push(spawn_pipe_drain(stderr));
        }

        Ok(Self {
            child,
            stdin: Some(stdin),
            stdout: Some(BufReader::new(stdout)),
            path: path.to_path_buf(),
            socks_port: None,
            io_drains,
        })
    }

    /// Write one JSON (or opaque) config line to stdin and flush. Does **not** close stdin —
    /// EOF is the shutdown signal for Wormhole sidecars.
    ///
    /// Never log `payload` — it carries DPAPI-decrypted tunnel secrets.
    pub async fn write_config_line(&mut self, payload: &[u8]) -> Result<(), TunnelError> {
        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| TunnelError::Establish("sidecar stdin already closed".into()))?;
        stdin
            .write_all(payload)
            .await
            .map_err(|e| TunnelError::Establish(format!("sidecar stdin write failed: {e}")))?;
        if !payload.ends_with(b"\n") {
            stdin
                .write_all(b"\n")
                .await
                .map_err(|e| TunnelError::Establish(format!("sidecar stdin newline failed: {e}")))?;
        }
        stdin
            .flush()
            .await
            .map_err(|e| TunnelError::Establish(format!("sidecar stdin flush failed: {e}")))?;
        Ok(())
    }

    /// Read the first stdout line (bounded) and parse `READY <port>` / `SOCKS <port>`.
    pub async fn read_ready_line(&mut self) -> Result<u16, TunnelError> {
        let stdout = self
            .stdout
            .as_mut()
            .ok_or_else(|| TunnelError::Establish("sidecar stdout already consumed".into()))?;

        let mut buf = Vec::with_capacity(32);
        let read_result = {
            // Cap bytes so a sidecar that never emits `\n` cannot grow the buffer without bound.
            let mut limited = stdout.take(MAX_HANDSHAKE_LINE_BYTES as u64 + 1);
            limited.read_until(b'\n', &mut buf).await
        };

        match read_result {
            Err(e) => Err(TunnelError::Establish(format!(
                "sidecar stdout read failed: {e}"
            ))),
            Ok(0) => Err(TunnelError::Establish(format!(
                "sidecar {} exited before becoming ready",
                self.path.display()
            ))),
            Ok(_) if buf.len() > MAX_HANDSHAKE_LINE_BYTES => Err(TunnelError::Establish(format!(
                "sidecar {} handshake line exceeded {MAX_HANDSHAKE_LINE_BYTES} bytes",
                self.path.display()
            ))),
            Ok(_) => {
                let line = String::from_utf8_lossy(&buf);
                let port = parse_ready_or_socks_line(&line)?;
                self.socks_port = Some(port);
                // Handshake complete — drain any further stdout so later chatter cannot
                // fill the pipe and stall the sidecar data plane.
                if let Some(stdout) = self.stdout.take() {
                    self.io_drains.push(spawn_pipe_drain(stdout));
                }
                tracing::info!(
                    path = %self.path.display(),
                    port,
                    "tunnel sidecar ready on 127.0.0.1"
                );
                Ok(port)
            }
        }
    }

    /// Read READY/SOCKS with an explicit timeout.
    pub async fn await_ready_line(&mut self, ready_timeout: Duration) -> Result<u16, TunnelError> {
        match timeout(ready_timeout, self.read_ready_line()).await {
            Ok(result) => result,
            Err(_) => Err(TunnelError::Establish(format!(
                "sidecar {} did not produce a READY/SOCKS line within {}s",
                self.path.display(),
                ready_timeout.as_secs()
            ))),
        }
    }

    /// Write config, then wait for READY/SOCKS within one shared `ready_timeout` budget
    /// (parity with C# `WireGuardProcessHost`).
    pub async fn handshake(
        &mut self,
        config_line: &[u8],
        ready_timeout: Duration,
    ) -> Result<u16, TunnelError> {
        let work = async {
            self.write_config_line(config_line).await?;
            self.read_ready_line().await
        };
        match timeout(ready_timeout, work).await {
            Ok(result) => result,
            Err(_) => Err(TunnelError::Establish(format!(
                "sidecar {} handshake timed out after {}s",
                self.path.display(),
                ready_timeout.as_secs()
            ))),
        }
    }

    pub fn socks_port(&self) -> Option<u16> {
        self.socks_port
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Best-effort child PID (for tests asserting kill-on-failure).
    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    /// Close stdin (sidecar shutdown signal), wait briefly, then kill if needed.
    pub async fn shutdown(mut self) -> Result<(), TunnelError> {
        // Drop stdout reader so the child isn't kept alive by a pipe.
        self.stdout.take();
        if let Some(mut stdin) = self.stdin.take() {
            let _ = stdin.shutdown().await;
            drop(stdin);
        }
        let wait = timeout(Duration::from_secs(2), self.child.wait());
        match wait.await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                return Err(TunnelError::Establish(format!(
                    "waiting for sidecar exit failed: {e}"
                )));
            }
            Err(_) => {
                let _ = self.child.kill().await;
                let _ = self.child.wait().await;
            }
        }
        for handle in self.io_drains.drain(..) {
            let _ = timeout(Duration::from_millis(200), handle).await;
        }
        Ok(())
    }
}

impl Drop for SidecarProcess {
    fn drop(&mut self) {
        // Belt-and-suspenders with `kill_on_drop(true)`: ensure pipes are dropped and any
        // still-running child is not left as a zombie if async `shutdown` was skipped.
        self.stdout.take();
        self.stdin.take();
        for handle in self.io_drains.drain(..) {
            handle.abort();
        }
        let _ = self.child.start_kill();
    }
}

fn spawn_pipe_drain<R>(mut reader: R) -> tokio::task::JoinHandle<()>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    })
}

/// [`TunnelInstance`] backed by a live [`SidecarProcess`].
pub struct SidecarTunnelInstance {
    process: Mutex<Option<SidecarProcess>>,
    socks: Socks5Endpoint,
    forwarders: ForwarderRegistry,
    closed: AtomicBool,
}

impl SidecarTunnelInstance {
    pub fn new(process: SidecarProcess, socks_port: u16) -> Self {
        Self {
            process: Mutex::new(Some(process)),
            socks: Socks5Endpoint::loopback(socks_port),
            forwarders: ForwarderRegistry::new(),
            closed: AtomicBool::new(false),
        }
    }
}

#[async_trait::async_trait]
impl TunnelInstance for SidecarTunnelInstance {
    fn state(&self) -> TunnelState {
        if self.closed.load(Ordering::SeqCst) {
            TunnelState::Closed
        } else {
            TunnelState::Up
        }
    }

    fn socks5_endpoint(&self) -> Option<Socks5Endpoint> {
        if self.closed.load(Ordering::SeqCst) {
            None
        } else {
            Some(self.socks)
        }
    }

    async fn bind_local_forwarder(&self, host: &str, port: u16) -> Result<u16, TunnelError> {
        bind_local_forwarder_for(
            self.state(),
            self.socks5_endpoint(),
            &self.forwarders,
            host,
            port,
        )
        .await
    }

    async fn close(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        self.forwarders.close_all().await;
        let proc = self
            .process
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
        if let Some(proc) = proc {
            let _ = proc.shutdown().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn missing_spawn_path_is_binary_not_found() {
        let err = match SidecarProcess::spawn(
            std::env::temp_dir().join("wormhole-definitely-missing-sidecar-xyz.exe"),
            &[],
        )
        .await
        {
            Ok(_) => panic!("expected BinaryNotFound"),
            Err(e) => e,
        };
        assert!(matches!(err, TunnelError::BinaryNotFound { .. }), "{err:?}");
    }
}
