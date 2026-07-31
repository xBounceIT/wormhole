//! Tunnel test dialog Fake VM glue (C# `TunnelTestDialogViewModel` spirit).
//!
//! Select a saved tunnel config → establish once via [`FakeTunnelProvider`] /
//! [`TunnelManager`] → optional Fake target probe → success / failure / cancel /
//! informational report. **No GPUI**; **no live sidecar** or DPAPI I/O in the
//! default lab harness. Secrets never appear in [`Debug`] / log surfaces.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use chrono::Utc;
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use wormhole_domain::TunnelKind;
use wormhole_session::{describe_tunnel_phase, TunnelProgressReport, TunnelSubPhase};
use wormhole_tunnels::{
    FakeTunnelConfigLookup, FakeTunnelProvider, FakeTunnelSecretLookup, TunnelConfigLookup,
    TunnelConfigRecord, TunnelError, TunnelInstance, TunnelLease, TunnelManager,
    TunnelSecretLookup, TunnelState,
};

use crate::tunnel_configs_ui::{tunnel_kind_display_name, TunnelConfigRow};

/// Prefix for lab informational establish failures (`NOTICE:title|message`).
pub const INFORMATIONAL_ESTABLISH_PREFIX: &str = "NOTICE:";

/// Dialog / establish errors — never carry secret blobs.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TunnelTestDialogError {
    #[error("tunnel config is required")]
    NoConfig,
    #[error("tunnel test is already running")]
    AlreadyBusy,
    #[error("tunnel config not found: {0}")]
    ConfigNotFound(Uuid),
    #[error("tunnel secret missing for config: {0}")]
    SecretMissing(Uuid),
    #[error("invalid tunnel config row")]
    InvalidConfigRow,
    #[error("target host is required when a target port is provided")]
    ProbeHostRequired,
    #[error("target port must be between 1 and 65535")]
    InvalidProbePort,
    #[error("target probe failed: {0}")]
    Probe(String),
    #[error("tunnel test failed: {0}")]
    Establish(String),
    #[error("tunnel test cancelled")]
    Cancelled,
}

impl From<TunnelError> for TunnelTestDialogError {
    fn from(value: TunnelError) -> Self {
        match value {
            TunnelError::Cancelled => Self::Cancelled,
            TunnelError::ConfigNotFound { id } => Self::ConfigNotFound(id),
            TunnelError::SecretMissing { id } => Self::SecretMissing(id),
            TunnelError::Establish(msg) => Self::Establish(sanitize_establish_message(&msg)),
            other => Self::Establish(sanitize_establish_message(&other.to_string())),
        }
    }
}

fn sanitize_establish_message(msg: &str) -> String {
    if msg.contains("interface_private_key") || msg.contains("private_key") {
        return "tunnel establishment failed (details redacted)".into();
    }
    msg.to_string()
}

/// Benign provider outcome (C# `TunnelRecoverableNoticeException`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelTestInformationalOutcome {
    pub title: String,
    pub message: String,
}

/// Optional target reachability probe (C# `ITunnelInstance.DialAsync` stand-in).
#[async_trait::async_trait]
pub trait TunnelTargetProbe: Send + Sync {
    async fn probe_target(
        &self,
        instance: &dyn TunnelInstance,
        host: &str,
        port: u16,
    ) -> Result<(), TunnelTestDialogError>;
}

/// Scripted dial probe for unit tests (no live SOCKS).
#[derive(Default)]
pub struct FakeTunnelTargetProbe {
    dial_failure: Mutex<Option<String>>,
    dial_calls: AtomicUsize,
    last_dial: Mutex<Option<(String, u16)>>,
}

impl fmt::Debug for FakeTunnelTargetProbe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeTunnelTargetProbe")
            .field("dial_calls", &self.dial_calls.load(Ordering::SeqCst))
            .field(
                "has_dial_failure",
                &self.dial_failure.lock().unwrap_or_else(|p| p.into_inner()).is_some(),
            )
            .field("has_last_dial", &self.last_dial.lock().unwrap_or_else(|p| p.into_inner()).is_some())
            .finish()
    }
}

impl FakeTunnelTargetProbe {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn fail_next(&self, message: impl Into<String>) {
        *self
            .dial_failure
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(message.into());
    }

    pub fn dial_calls(&self) -> usize {
        self.dial_calls.load(Ordering::SeqCst)
    }

    pub fn last_dial(&self) -> Option<(String, u16)> {
        self.last_dial.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

#[async_trait::async_trait]
impl TunnelTargetProbe for FakeTunnelTargetProbe {
    async fn probe_target(
        &self,
        instance: &dyn TunnelInstance,
        host: &str,
        port: u16,
    ) -> Result<(), TunnelTestDialogError> {
        self.dial_calls.fetch_add(1, Ordering::SeqCst);
        *self.last_dial.lock().unwrap_or_else(|p| p.into_inner()) = Some((host.to_string(), port));
        if let Some(msg) = self
            .dial_failure
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
        {
            return Err(TunnelTestDialogError::Probe(msg));
        }
        if instance.state() != TunnelState::Up {
            return Err(TunnelTestDialogError::Probe(
                "tunnel is not up for target probe".into(),
            ));
        }
        Ok(())
    }
}

/// In-memory lab harness: metadata + secret lookups + [`TunnelManager`] over Fakes.
pub struct FakeTunnelTestLab {
    configs: FakeTunnelConfigLookup,
    secrets: FakeTunnelSecretLookup,
    manager: TunnelManager,
    providers: HashMap<TunnelKind, Arc<FakeTunnelProvider>>,
    probe: Arc<FakeTunnelTargetProbe>,
}

impl fmt::Debug for FakeTunnelTestLab {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeTunnelTestLab")
            .field("provider_kinds", &self.providers.keys().copied().collect::<Vec<_>>())
            .field("probe", &self.probe)
            .field("manager", &self.manager)
            .finish()
    }
}

impl FakeTunnelTestLab {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(record: TunnelConfigRecord, secret: impl Into<Vec<u8>>) -> Self {
        let mut lab = Self::default();
        let kind = record.kind;
        lab.configs.insert(record.clone());
        lab.secrets.insert(record.id, secret);
        lab.ensure_provider(kind);
        lab
    }

    pub fn wireguard(id: Uuid, name: impl Into<String>, secret: impl Into<Vec<u8>>) -> Self {
        Self::with_config(
            TunnelConfigRecord::new(id, TunnelKind::WireGuard, name),
            secret,
        )
    }

    pub fn configs(&self) -> &FakeTunnelConfigLookup {
        &self.configs
    }

    pub fn secrets(&self) -> &FakeTunnelSecretLookup {
        &self.secrets
    }

    pub fn manager(&self) -> &TunnelManager {
        &self.manager
    }

    pub fn provider(&self, kind: TunnelKind) -> Option<Arc<FakeTunnelProvider>> {
        self.providers.get(&kind).cloned()
    }

    pub fn probe(&self) -> &FakeTunnelTargetProbe {
        &self.probe
    }

    pub fn insert_config(&mut self, record: TunnelConfigRecord, secret: Option<Vec<u8>>) {
        let kind = record.kind;
        self.configs.insert(record.clone());
        if let Some(blob) = secret {
            self.secrets.insert(record.id, blob);
        }
        self.ensure_provider(kind);
    }

    fn ensure_provider(&mut self, kind: TunnelKind) {
        if self.providers.contains_key(&kind) {
            return;
        }
        let provider = Arc::new(FakeTunnelProvider::new(kind));
        self.providers.insert(kind, Arc::clone(&provider));
        self.rebuild_manager();
    }

    fn rebuild_manager(&mut self) {
        let providers: Vec<Arc<dyn wormhole_tunnels::TunnelProvider>> = self
            .providers
            .values()
            .map(|p| Arc::clone(p) as Arc<dyn wormhole_tunnels::TunnelProvider>)
            .collect();
        self.manager = TunnelManager::new(providers).expect("FakeTunnelTestLab manager");
    }

    pub async fn establish_config(
        &self,
        config_id: Uuid,
        cancel: &CancellationToken,
    ) -> Result<TunnelLease, TunnelTestDialogError> {
        let record = self
            .configs
            .get(config_id)?
            .ok_or(TunnelTestDialogError::ConfigNotFound(config_id))?;
        let secret = self
            .secrets
            .read(&config_id)?
            .ok_or(TunnelTestDialogError::SecretMissing(config_id))?;
        if secret.is_empty() {
            return Err(TunnelTestDialogError::SecretMissing(config_id));
        }
        let snapshot = record.to_snapshot();
        let establish = self.manager.establish(snapshot, secret);
        tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(TunnelTestDialogError::Cancelled),
            result = establish => result.map_err(Into::into),
        }
    }
}

impl Default for FakeTunnelTestLab {
    fn default() -> Self {
        let manager = TunnelManager::new(Vec::<Arc<dyn wormhole_tunnels::TunnelProvider>>::new())
            .expect("empty FakeTunnelTestLab manager");
        Self {
            configs: FakeTunnelConfigLookup::new(),
            secrets: FakeTunnelSecretLookup::new(),
            manager,
            providers: HashMap::new(),
            probe: Arc::new(FakeTunnelTargetProbe::new()),
        }
    }
}


/// Tunnel test dialog VM — log lines + result bindings only in [`Debug`] counts.
pub struct TunnelTestDialogVm {
    config_id: Option<Uuid>,
    config_name: String,
    config_kind: Option<TunnelKind>,
    header_text: String,
    is_busy: bool,
    status: String,
    target_host: String,
    target_port: String,
    succeeded: Option<bool>,
    result_title: String,
    result_message: String,
    was_cancelled: bool,
    was_informational: bool,
    log: Vec<String>,
    cancel_token: Arc<Mutex<Option<CancellationToken>>>,
    last_progress: Mutex<Option<TunnelProgressReport>>,
}

impl Default for TunnelTestDialogVm {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for TunnelTestDialogVm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunnelTestDialogVm")
            .field("config_id", &self.config_id)
            .field("config_name_len", &self.config_name.len())
            .field("config_kind", &self.config_kind)
            .field("is_busy", &self.is_busy)
            .field("succeeded", &self.succeeded)
            .field("was_cancelled", &self.was_cancelled)
            .field("was_informational", &self.was_informational)
            .field("log_len", &self.log.len())
            .field("target_host_len", &self.target_host.len())
            .field("target_port_len", &self.target_port.len())
            .finish()
    }
}

impl TunnelTestDialogVm {
    pub fn new() -> Self {
        Self {
            config_id: None,
            config_name: String::new(),
            config_kind: None,
            header_text: String::new(),
            is_busy: false,
            status: String::new(),
            target_host: String::new(),
            target_port: String::new(),
            succeeded: None,
            result_title: String::new(),
            result_message: String::new(),
            was_cancelled: false,
            was_informational: false,
            log: Vec::new(),
            cancel_token: Arc::new(Mutex::new(None)),
            last_progress: Mutex::new(None),
        }
    }

    pub fn header_text(&self) -> &str {
        &self.header_text
    }

    pub fn status(&self) -> &str {
        &self.status
    }

    pub fn target_host(&self) -> &str {
        &self.target_host
    }

    pub fn target_port(&self) -> &str {
        &self.target_port
    }

    pub fn set_target_host(&mut self, host: impl Into<String>) {
        self.target_host = host.into();
    }

    pub fn set_target_port(&mut self, port: impl Into<String>) {
        self.target_port = port.into();
    }

    pub fn log(&self) -> &[String] {
        &self.log
    }

    pub fn is_busy(&self) -> bool {
        self.is_busy
    }

    pub fn can_close(&self) -> bool {
        !self.is_busy
    }

    pub fn can_start(&self) -> bool {
        !self.is_busy && self.config_id.is_some()
    }

    pub fn has_result(&self) -> bool {
        self.succeeded.is_some()
    }

    pub fn is_success(&self) -> bool {
        self.succeeded == Some(true)
    }

    pub fn succeeded(&self) -> Option<bool> {
        self.succeeded
    }

    pub fn was_cancelled(&self) -> bool {
        self.was_cancelled
    }

    pub fn was_informational(&self) -> bool {
        self.was_informational
    }

    pub fn result_title(&self) -> &str {
        &self.result_title
    }

    pub fn result_message(&self) -> &str {
        &self.result_message
    }

    /// Prepare dialog for a metadata row without starting a test (C# `Prepare`).
    pub fn prepare(&mut self, row: &TunnelConfigRow) -> Result<(), TunnelTestDialogError> {
        if row.is_sentinel() {
            return Err(TunnelTestDialogError::InvalidConfigRow);
        }
        let kind = row.kind.ok_or(TunnelTestDialogError::InvalidConfigRow)?;
        self.config_id = Some(row.id);
        self.config_name = row.name.clone();
        self.config_kind = Some(kind);
        self.header_text = format!("Test tunnel: {}", row.name);
        self.status = "Ready to test.".into();
        self.log.clear();
        self.succeeded = None;
        self.was_cancelled = false;
        self.was_informational = false;
        self.result_title.clear();
        self.result_message.clear();
        *self.last_progress.lock().unwrap_or_else(|p| p.into_inner()) = None;
        Ok(())
    }

    /// Prepare from a storage record (lab harness).
    pub fn prepare_record(&mut self, record: &TunnelConfigRecord) -> Result<(), TunnelTestDialogError> {
        self.config_id = Some(record.id);
        self.config_name = record.name.clone();
        self.config_kind = Some(record.kind);
        self.header_text = format!("Test tunnel: {}", record.name);
        self.status = "Ready to test.".into();
        self.log.clear();
        self.succeeded = None;
        self.was_cancelled = false;
        self.was_informational = false;
        self.result_title.clear();
        self.result_message.clear();
        *self.last_progress.lock().unwrap_or_else(|p| p.into_inner()) = None;
        Ok(())
    }

    pub fn request_cancel_for_close(&self) {
        if let Some(token) = self
            .cancel_token
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
        {
            token.cancel();
        }
    }

    /// Cloneable cancel slot for concurrent host close during [`Self::run`].
    pub fn cancel_token_slot(&self) -> Arc<Mutex<Option<CancellationToken>>> {
        Arc::clone(&self.cancel_token)
    }

    /// Run the diagnostic for the prepared config. Never panics — outcomes bind to VM state.
    pub async fn run(&mut self, lab: &FakeTunnelTestLab) -> Result<(), TunnelTestDialogError> {
        let config_id = self.config_id.ok_or(TunnelTestDialogError::NoConfig)?;
        if self.is_busy {
            return Err(TunnelTestDialogError::AlreadyBusy);
        }

        let name = self.config_name.clone();
        let kind = self
            .config_kind
            .ok_or(TunnelTestDialogError::InvalidConfigRow)?;
        let kind_label = tunnel_kind_display_name(kind);

        self.is_busy = true;
        self.succeeded = None;
        self.was_cancelled = false;
        self.was_informational = false;
        self.result_title.clear();
        self.result_message.clear();
        *self.last_progress.lock().unwrap_or_else(|p| p.into_inner()) = None;
        self.log.clear();
        self.status = "Starting tunnel test…".into();

        let cancel = CancellationToken::new();
        *self
            .cancel_token
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(cancel.clone());

        self.append_log(format!("Testing '{name}' ({kind_label})…"));

        let probe_target = match self.read_probe_target() {
            Ok(target) => target,
            Err(err) => {
                self.finish_failure(
                    false,
                    "Tunnel test failed",
                    &format!("'{name}' failed to start: {err}"),
                    Some(&err.to_string()),
                    false,
                );
                self.is_busy = false;
                *self
                    .cancel_token
                    .lock()
                    .unwrap_or_else(|p| p.into_inner()) = None;
                return Ok(());
            }
        };
        let probe_requested = probe_target.is_some();

        self.report_progress(&TunnelProgressReport::new(TunnelSubPhase::StartingTunnel));

        let run_result: Result<(), TunnelTestDialogError> = async {
            let lease = lab.establish_config(config_id, &cancel).await?;
            let instance = Arc::clone(lease.instance());

            if let Some((host, port)) = probe_target {
                self.status = "Testing target reachability…".into();
                self.append_log(format!("Testing target {host}:{port} through the tunnel…"));
                lab.probe()
                    .probe_target(instance.as_ref(), &host, port)
                    .await?;
                self.append_log(format!("Target {host}:{port} is reachable through the tunnel."));
            }

            // Lease drops here — diagnostic tunnel must close.
            drop(lease);
            Ok(())
        }
        .await;

        match run_result {
            Ok(()) => {
                self.status = "Tunnel test succeeded.".into();
                self.append_log("Tunnel established successfully. Test tunnel closed.".into());
                self.result_title = "Tunnel test succeeded".into();
                self.result_message = if probe_requested {
                    format!(
                        "'{name}' started successfully and reached the target. The test tunnel has been closed."
                    )
                } else {
                    format!("'{name}' started successfully. The test tunnel has been closed.")
                };
                self.succeeded = Some(true);
            }
            Err(TunnelTestDialogError::Cancelled) => {
                self.status = "Tunnel test cancelled.".into();
                self.append_log("Test cancelled.".into());
                self.result_title = "Tunnel test cancelled".into();
                self.result_message =
                    format!("The test for '{name}' was cancelled before it finished.");
                self.was_cancelled = true;
                self.succeeded = Some(false);
            }
            Err(err) => {
                if let Some(info) = classify_informational(&err) {
                    self.status = format!("{}.", info.title);
                    self.append_log(info.message.clone());
                    self.result_title = info.title;
                    self.result_message = info.message;
                    self.was_informational = true;
                    self.succeeded = Some(false);
                } else {
                    let msg = err.to_string();
                    let last_step = describe_last_progress(
                        &self.last_progress.lock().unwrap_or_else(|p| p.into_inner()),
                    );
                    if probe_requested {
                        self.finish_failure(
                            true,
                            "Target probe failed",
                            &format!(
                                "'{name}' started, but the target could not be reached through the tunnel: {msg}{last_step}"
                            ),
                            Some(&format!("Failed: {msg}{last_step}")),
                            false,
                        );
                    } else {
                        self.finish_failure(
                            false,
                            "Tunnel test failed",
                            &format!("'{name}' failed to start: {msg}{last_step}"),
                            Some(&format!("Failed: {msg}{last_step}")),
                            false,
                        );
                    }
                }
            }
        }

        self.is_busy = false;
        *self
            .cancel_token
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = None;
        Ok(())
    }

    fn finish_failure(
        &mut self,
        probe_failed: bool,
        title: &str,
        message: &str,
        log_line: Option<&str>,
        cancelled: bool,
    ) {
        self.status = if probe_failed {
            "Target probe failed.".into()
        } else if cancelled {
            "Tunnel test cancelled.".into()
        } else {
            "Tunnel test failed.".into()
        };
        if let Some(line) = log_line {
            self.append_log(line.to_string());
        }
        self.result_title = title.into();
        self.result_message = message.into();
        self.was_cancelled = cancelled;
        self.succeeded = Some(false);
    }

    fn report_progress(&mut self, progress: &TunnelProgressReport) {
        *self.last_progress.lock().unwrap_or_else(|p| p.into_inner()) = Some(progress.clone());
        let line = describe_tunnel_phase(progress);
        self.status = line.clone();
        self.append_log(line);
    }

    fn append_log(&mut self, line: String) {
        let stamp = Utc::now().format("%H:%M:%S");
        self.log.push(format!("[{stamp}] {line}"));
    }

    fn read_probe_target(&self) -> Result<Option<(String, u16)>, TunnelTestDialogError> {
        let host = self.target_host.trim();
        let port_text = self.target_port.trim();
        if host.is_empty() && port_text.is_empty() {
            return Ok(None);
        }
        if host.is_empty() {
            return Err(TunnelTestDialogError::ProbeHostRequired);
        }
        let port: u16 = port_text
            .parse()
            .ok()
            .filter(|p| (1..=65535).contains(p))
            .ok_or(TunnelTestDialogError::InvalidProbePort)?;
        Ok(Some((host.to_string(), port)))
    }
}

fn describe_last_progress(progress: &Option<TunnelProgressReport>) -> String {
    let Some(progress) = progress else {
        return String::new();
    };
    let detail = progress
        .detail
        .as_deref()
        .filter(|d| !d.trim().is_empty())
        .map(|d| d.trim().to_string())
        .unwrap_or_else(|| match progress.phase {
            TunnelSubPhase::Preparing => "preparing tunnel".into(),
            TunnelSubPhase::Authenticating => "authenticating".into(),
            TunnelSubPhase::DownloadingConfiguration => "downloading configuration".into(),
            TunnelSubPhase::StartingTunnel => "starting tunnel".into(),
        });
    format!(" Last step: {detail}.")
}

pub fn classify_informational(err: &TunnelTestDialogError) -> Option<TunnelTestInformationalOutcome> {
    match err {
        TunnelTestDialogError::Establish(msg) => parse_informational_establish(msg).or_else(|| {
            msg.strip_prefix("tunnel establishment failed: ")
                .and_then(parse_informational_establish)
        }),
        _ => None,
    }
}

fn parse_informational_establish(msg: &str) -> Option<TunnelTestInformationalOutcome> {
    let rest = msg.strip_prefix(INFORMATIONAL_ESTABLISH_PREFIX)?;
    let (title, message) = rest.split_once('|')?;
    if title.trim().is_empty() || message.trim().is_empty() {
        return None;
    }
    Some(TunnelTestInformationalOutcome {
        title: title.trim().to_string(),
        message: message.trim().to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn alpha_id() -> Uuid {
        Uuid::parse_str("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap()
    }

    #[test]
    fn prepare_does_not_start_tunnel() {
        let lab = FakeTunnelTestLab::wireguard(alpha_id(), "alpha", vec![1, 2, 3]);
        let mut vm = TunnelTestDialogVm::new();
        let row = TunnelConfigRow::config(
            alpha_id(),
            "alpha",
            TunnelKind::WireGuard,
            Utc::now(),
            Utc::now(),
        );
        vm.prepare(&row).unwrap();
        assert_eq!(vm.status(), "Ready to test.");
        assert!(vm.can_start());
        assert!(!vm.has_result());
        assert_eq!(lab.provider(TunnelKind::WireGuard).unwrap().establish_count(), 0);
    }

    #[tokio::test]
    async fn run_success_establishes_disposes_and_reports_success() {
        let lab = FakeTunnelTestLab::wireguard(alpha_id(), "alpha", vec![1, 2, 3]);
        let provider = lab.provider(TunnelKind::WireGuard).unwrap();
        let mut vm = TunnelTestDialogVm::new();
        vm.prepare_record(&TunnelConfigRecord::new(
            alpha_id(),
            TunnelKind::WireGuard,
            "alpha",
        ))
        .unwrap();

        vm.run(&lab).await.unwrap();

        assert!(!vm.is_busy());
        assert!(vm.has_result());
        assert!(vm.is_success());
        assert_eq!(provider.establish_count(), 1);
        assert_eq!(vm.result_title(), "Tunnel test succeeded");
        assert!(
            vm.log()
                .iter()
                .any(|l| l.contains("Bringing up the VPN tunnel")),
            "log={:?}",
            vm.log()
        );
        assert!(
            vm.log()
                .iter()
                .any(|l| l.contains("established successfully")),
            "log={:?}",
            vm.log()
        );
    }

    #[tokio::test]
    async fn run_with_probe_target_dials_before_success() {
        let lab = FakeTunnelTestLab::wireguard(alpha_id(), "alpha", vec![1, 2, 3]);
        let mut vm = TunnelTestDialogVm::new();
        vm.prepare_record(&TunnelConfigRecord::new(
            alpha_id(),
            TunnelKind::WireGuard,
            "alpha",
        ))
        .unwrap();
        vm.set_target_host("192.0.2.10");
        vm.set_target_port("22");

        vm.run(&lab).await.unwrap();

        assert!(vm.is_success());
        assert_eq!(lab.probe().dial_calls(), 1);
        assert_eq!(
            lab.probe().last_dial(),
            Some(("192.0.2.10".into(), 22))
        );
        assert!(vm.result_message().contains("reached the target"));
    }

    #[tokio::test]
    async fn run_with_probe_failure_reports_target_probe_failed() {
        let lab = FakeTunnelTestLab::wireguard(alpha_id(), "alpha", vec![1, 2, 3]);
        lab.probe()
            .fail_next("SOCKS5: Host unreachable.");
        let mut vm = TunnelTestDialogVm::new();
        vm.prepare_record(&TunnelConfigRecord::new(
            alpha_id(),
            TunnelKind::WireGuard,
            "alpha",
        ))
        .unwrap();
        vm.set_target_host("192.0.2.10");
        vm.set_target_port("22");

        vm.run(&lab).await.unwrap();

        assert!(!vm.is_success());
        assert_eq!(vm.status(), "Target probe failed.");
        assert_eq!(vm.result_title(), "Target probe failed");
        assert!(vm
            .result_message()
            .contains("started, but the target could not be reached"));
    }

    #[tokio::test]
    async fn run_provider_failure_reports_last_step() {
        let lab = FakeTunnelTestLab::wireguard(alpha_id(), "alpha", vec![1, 2, 3]);
        lab.provider(TunnelKind::WireGuard)
            .unwrap()
            .fail_next("simulated auth failure");
        let mut vm = TunnelTestDialogVm::new();
        vm.prepare_record(&TunnelConfigRecord::new(
            alpha_id(),
            TunnelKind::WireGuard,
            "alpha",
        ))
        .unwrap();

        vm.run(&lab).await.unwrap();

        assert!(!vm.is_busy());
        assert!(vm.has_result());
        assert!(!vm.is_success());
        assert_eq!(vm.result_title(), "Tunnel test failed");
        assert!(vm.result_message().contains("simulated auth failure"));
        assert!(vm.result_message().contains("Last step: starting tunnel."));
    }

    #[tokio::test]
    async fn run_informational_notice_not_failure() {
        let lab = FakeTunnelTestLab::wireguard(alpha_id(), "alpha", vec![1, 2, 3]);
        lab.provider(TunnelKind::WireGuard).unwrap().fail_next(
            "NOTICE:Profile downloaded|Downloaded an updated VPN profile. Enter a NEW code and reconnect.",
        );
        let mut vm = TunnelTestDialogVm::new();
        vm.prepare_record(&TunnelConfigRecord::new(
            alpha_id(),
            TunnelKind::WireGuard,
            "alpha",
        ))
        .unwrap();

        vm.run(&lab).await.unwrap();

        assert!(!vm.is_success());
        assert!(vm.was_informational());
        assert_eq!(vm.result_title(), "Profile downloaded");
        assert!(vm.result_message().contains("NEW code"));
    }

    #[tokio::test]
    async fn run_missing_secret_reports_failure_before_provider() {
        let lab = FakeTunnelTestLab::wireguard(alpha_id(), "alpha", vec![1, 2, 3]);
        let mut vm = TunnelTestDialogVm::new();
        vm.prepare_record(&TunnelConfigRecord::new(
            alpha_id(),
            TunnelKind::WireGuard,
            "alpha",
        ))
        .unwrap();
        // Remove secret after prepare.
        let id = alpha_id();
        lab.secrets().insert(id, Vec::new());

        vm.run(&lab).await.unwrap();

        assert!(!vm.is_success());
        assert_eq!(
            lab.provider(TunnelKind::WireGuard).unwrap().establish_count(),
            0
        );
    }

    #[tokio::test]
    async fn establish_config_cancel_aborts_in_flight() {
        let mut lab = FakeTunnelTestLab::wireguard(alpha_id(), "alpha", vec![1, 2, 3]);
        let provider = Arc::new(FakeTunnelProvider::with_delay(
            TunnelKind::WireGuard,
            Duration::from_millis(500),
        ));
        lab.providers
            .insert(TunnelKind::WireGuard, Arc::clone(&provider));
        lab.rebuild_manager();

        let cancel = CancellationToken::new();
        let cancel_bg = cancel.clone();
        let establish = lab.establish_config(alpha_id(), &cancel);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            cancel_bg.cancel();
        });
        let result = establish.await;
        assert!(matches!(result, Err(TunnelTestDialogError::Cancelled)));
    }

    #[tokio::test]
    async fn run_user_cancel_reports_cancelled() {
        let mut lab = FakeTunnelTestLab::wireguard(alpha_id(), "alpha", vec![1, 2, 3]);
        let provider = Arc::new(FakeTunnelProvider::with_delay(
            TunnelKind::WireGuard,
            Duration::from_millis(500),
        ));
        lab.providers
            .insert(TunnelKind::WireGuard, Arc::clone(&provider));
        lab.rebuild_manager();
        let lab = Arc::new(lab);

        let mut vm = TunnelTestDialogVm::new();
        vm.prepare_record(&TunnelConfigRecord::new(
            alpha_id(),
            TunnelKind::WireGuard,
            "alpha",
        ))
        .unwrap();
        let vm = Arc::new(tokio::sync::Mutex::new(vm));
        let cancel_slot = vm.lock().await.cancel_token_slot();

        let handle = {
            let vm = Arc::clone(&vm);
            let lab = Arc::clone(&lab);
            tokio::spawn(async move { vm.lock().await.run(&lab).await })
        };

        for _ in 0..200 {
            if let Some(token) = cancel_slot.lock().unwrap().clone() {
                tokio::time::sleep(Duration::from_millis(20)).await;
                token.cancel();
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        handle.await.expect("join").expect("run");
        let vm = vm.lock().await;
        assert!(!vm.is_busy());
        assert!(vm.has_result());
        assert!(!vm.is_success());
        assert!(vm.was_cancelled());
        assert_eq!(vm.result_title(), "Tunnel test cancelled");
    }

    #[test]
    fn probe_validation_leaves_vm_idle() {
        let mut vm = TunnelTestDialogVm::new();
        vm.prepare_record(&TunnelConfigRecord::new(
            alpha_id(),
            TunnelKind::WireGuard,
            "alpha",
        ))
        .unwrap();
        vm.set_target_port("22");
        let lab = FakeTunnelTestLab::wireguard(alpha_id(), "alpha", vec![1, 2, 3]);
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(vm.run(&lab)).unwrap();
        assert!(!vm.is_busy());
        assert!(vm.has_result());
        assert!(!vm.is_success());
    }

    #[test]
    fn probe_validation_fail_closed() {
        let mut vm = TunnelTestDialogVm::new();
        vm.set_target_port("22");
        assert_eq!(
            vm.read_probe_target().unwrap_err(),
            TunnelTestDialogError::ProbeHostRequired
        );
        vm.set_target_host("host");
        vm.set_target_port("0");
        assert_eq!(
            vm.read_probe_target().unwrap_err(),
            TunnelTestDialogError::InvalidProbePort
        );
    }

    #[test]
    fn vm_debug_omits_log_bodies() {
        let mut vm = TunnelTestDialogVm::new();
        vm.append_log("super_secret_tunnel_password".into());
        let dbg = format!("{vm:?}");
        assert!(!dbg.contains("super_secret"));
        assert!(dbg.contains("log_len"));
    }

    #[test]
    fn parse_informational_round_trip() {
        let err = TunnelTestDialogError::Establish(
            "NOTICE:One-time code already used|Wait for a NEW code.".into(),
        );
        let info = classify_informational(&err).unwrap();
        assert_eq!(info.title, "One-time code already used");
        assert!(info.message.contains("NEW code"));
    }
}
