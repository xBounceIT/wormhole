//! mRemoteNG import dialog Fake VM glue (C# `MRemoteNgImportDialogViewModel` spirit).
//!
//! Flow: Fake XML path pick → parse/plan (SSH/RDP/VNC) → soft-skip report → optional
//! apply via [`apply_import_plan`]. Composes [`wormhole_import`] planning + skip report +
//! storage apply stub. **No GPUI**; **no live file-picker COM** — hosts supply paths through
//! [`MRemoteNgImportPathUi`] / [`set_xml_path`]. Fail-closed on empty path and parse errors.
//! Password material stays out of list/preview [`Debug`] surfaces.

use std::fmt;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use thiserror::Error;
use wormhole_import::{
    apply_import_plan, format_skip_summary, inspect_xml, parse_xml_path, plan_nodes,
    ApplyImportResult, FakeImportSkipReporter, ImportError, ImportPlan, ImportSkipReport,
    MRemoteNgFileInfo,
};

#[cfg(feature = "storage")]
use wormhole_storage::{ConnectionRepository, MigrationRunner, SqliteConnectionFactory};

/// Dialog VM errors — never carry password / ciphertext bodies.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MRemoteNgImportDialogError {
    #[error("import XML path is required")]
    EmptyPath,
    #[error("import failed: {0}")]
    Import(String),
    #[error("import must be planned before apply")]
    NotPlanned,
    #[error("import has already been applied for the current plan")]
    AlreadyApplied,
    #[error("import path pick failed: {0}")]
    PathPick(String),
}

impl From<ImportError> for MRemoteNgImportDialogError {
    fn from(value: ImportError) -> Self {
        MRemoteNgImportDialogError::Import(sanitize_import_message(&value.to_string()))
    }
}

fn sanitize_import_message(msg: &str) -> String {
    // Defensive: planning warnings should never echo decrypted passwords; strip common shapes.
    if msg.contains("Password=") || msg.contains("password_plaintext") {
        return "import operation failed (details redacted)".into();
    }
    msg.to_string()
}

/// Secrets-safe plan preview for dialog binding (no `PlannedNode` / password fields).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportPlanPreview {
    pub folder_count: usize,
    pub connection_count: usize,
    pub skipped: usize,
    pub skip_report: ImportSkipReport,
    pub skip_summary: String,
    pub warnings: Vec<String>,
    pub has_password_payloads: bool,
    pub xml_path: String,
}

/// Outcome of a successful apply step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MRemoteNgImportApplyOutcome {
    pub inserted: usize,
    pub folder_count: usize,
    pub connection_count: usize,
    pub skipped: usize,
}

impl From<ApplyImportResult> for MRemoteNgImportApplyOutcome {
    fn from(value: ApplyImportResult) -> Self {
        Self {
            inserted: value.inserted,
            folder_count: value.folder_count,
            connection_count: value.connection_count,
            skipped: value.skipped,
        }
    }
}

/// Headless XML path surface — stand-in for WinUI `FileOpenPicker` (no COM).
pub trait MRemoteNgImportPathUi {
    fn pick_xml_path(&self) -> Result<String, MRemoteNgImportDialogError>;
}

/// Fake file-picker returning a canned path or error (counts-only [`Debug`]).
pub struct FakeMRemoteNgImportPathUi {
    forced: Mutex<Option<Result<String, String>>>,
    pick_calls: AtomicUsize,
}

impl Default for FakeMRemoteNgImportPathUi {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for FakeMRemoteNgImportPathUi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let forced = self.forced.lock().unwrap_or_else(|p| p.into_inner());
        f.debug_struct("FakeMRemoteNgImportPathUi")
            .field("forced_is_ok", &forced.as_ref().map(|r| r.is_ok()))
            .field("pick_calls", &self.pick_calls.load(Ordering::SeqCst))
            .finish()
    }
}

impl FakeMRemoteNgImportPathUi {
    pub fn new() -> Self {
        Self {
            forced: Mutex::new(None),
            pick_calls: AtomicUsize::new(0),
        }
    }

    pub fn returning(path: impl Into<String>) -> Self {
        let ui = Self::new();
        ui.force_ok(path);
        ui
    }

    pub fn failing(message: impl Into<String>) -> Self {
        let ui = Self::new();
        ui.force_err(message);
        ui
    }

    pub fn force_ok(&self, path: impl Into<String>) {
        let mut guard = self.forced.lock().unwrap_or_else(|p| p.into_inner());
        *guard = Some(Ok(path.into()));
    }

    pub fn force_err(&self, message: impl Into<String>) {
        let mut guard = self.forced.lock().unwrap_or_else(|p| p.into_inner());
        *guard = Some(Err(message.into()));
    }

    pub fn clear_forced(&self) {
        let mut guard = self.forced.lock().unwrap_or_else(|p| p.into_inner());
        *guard = None;
    }

    pub fn pick_calls(&self) -> usize {
        self.pick_calls.load(Ordering::SeqCst)
    }
}

impl MRemoteNgImportPathUi for FakeMRemoteNgImportPathUi {
    fn pick_xml_path(&self) -> Result<String, MRemoteNgImportDialogError> {
        self.pick_calls.fetch_add(1, Ordering::SeqCst);
        let forced = self.forced.lock().unwrap_or_else(|p| p.into_inner());
        match forced.as_ref() {
            Some(Ok(path)) => Ok(path.clone()),
            Some(Err(msg)) => Err(MRemoteNgImportDialogError::PathPick(msg.clone())),
            None => Err(MRemoteNgImportDialogError::PathPick(
                "FakeMRemoteNgImportPathUi has no forced path".into(),
            )),
        }
    }
}

/// Apply port for dialog commit (SQLite repo or temp lab).
pub trait MRemoteNgImportApplySink {
    fn apply_plan(&self, plan: &ImportPlan) -> Result<ApplyImportResult, ImportError>;
}

#[cfg(feature = "storage")]
pub struct StorageMRemoteNgImportSink<'a> {
    repo: ConnectionRepository<'a>,
}

#[cfg(feature = "storage")]
impl<'a> StorageMRemoteNgImportSink<'a> {
    pub fn new(repo: ConnectionRepository<'a>) -> Self {
        Self { repo }
    }
}

#[cfg(feature = "storage")]
impl MRemoteNgImportApplySink for StorageMRemoteNgImportSink<'_> {
    fn apply_plan(&self, plan: &ImportPlan) -> Result<ApplyImportResult, ImportError> {
        apply_import_plan(&self.repo, plan)
    }
}

/// Temp SQLite lab for apply round-trips (never touches user AppData).
#[cfg(feature = "storage")]
pub struct FakeMRemoteNgImportLab {
    _dir: tempfile::TempDir,
    factory: SqliteConnectionFactory,
}

#[cfg(feature = "storage")]
impl FakeMRemoteNgImportLab {
    pub fn new() -> Self {
        let dir = tempfile::TempDir::new().expect("FakeMRemoteNgImportLab tempdir");
        let path = dir.path().join("wormhole.db");
        let factory = SqliteConnectionFactory::new(&path);
        MigrationRunner::embedded()
            .run(&factory)
            .expect("FakeMRemoteNgImportLab migrate");
        Self { _dir: dir, factory }
    }

    pub fn repo(&self) -> ConnectionRepository<'_> {
        ConnectionRepository::new(&self.factory)
    }

    pub fn node_count(&self) -> usize {
        self.repo().list_all().map(|n| n.len()).unwrap_or(0)
    }
}

#[cfg(feature = "storage")]
impl fmt::Debug for FakeMRemoteNgImportLab {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeMRemoteNgImportLab")
            .field("node_count", &self.node_count())
            .finish()
    }
}

#[cfg(feature = "storage")]
impl MRemoteNgImportApplySink for FakeMRemoteNgImportLab {
    fn apply_plan(&self, plan: &ImportPlan) -> Result<ApplyImportResult, ImportError> {
        apply_import_plan(&self.repo(), plan)
    }
}

/// mRemoteNG import dialog VM — metadata + skip summary only in [`Debug`].
pub struct MRemoteNgImportDialogVm {
    xml_path: String,
    import_password: String,
    file_info: Option<MRemoteNgFileInfo>,
    preview: Option<ImportPlanPreview>,
    plan: Option<ImportPlan>,
    applied: bool,
    last_apply: Option<MRemoteNgImportApplyOutcome>,
}

impl Default for MRemoteNgImportDialogVm {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for MRemoteNgImportDialogVm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MRemoteNgImportDialogVm")
            .field("xml_path_len", &self.xml_path.len())
            .field("has_import_password", &!self.import_password.is_empty())
            .field(
                "has_password_payloads",
                &self.file_info.as_ref().map(|i| i.has_password_payloads),
            )
            .field("is_planned", &self.plan.is_some())
            .field("folder_count", &self.preview.as_ref().map(|p| p.folder_count))
            .field("connection_count", &self.preview.as_ref().map(|p| p.connection_count))
            .field("skipped", &self.preview.as_ref().map(|p| p.skipped))
            .field("applied", &self.applied)
            .field("last_inserted", &self.last_apply.as_ref().map(|a| a.inserted))
            .finish()
    }
}

impl MRemoteNgImportDialogVm {
    pub fn new() -> Self {
        Self {
            xml_path: String::new(),
            import_password: String::new(),
            file_info: None,
            preview: None,
            plan: None,
            applied: false,
            last_apply: None,
        }
    }

    pub fn xml_path(&self) -> &str {
        &self.xml_path
    }

    pub fn set_xml_path(&mut self, path: impl Into<String>) {
        self.xml_path = path.into();
        self.clear_plan_state();
    }

    pub fn set_import_password(&mut self, password: impl Into<String>) {
        self.import_password = password.into();
        self.clear_plan_state();
    }

    pub fn preview(&self) -> Option<&ImportPlanPreview> {
        self.preview.as_ref()
    }

    pub fn is_planned(&self) -> bool {
        self.plan.is_some()
    }

    pub fn can_apply(&self) -> bool {
        self.plan.is_some() && !self.applied
    }

    pub fn applied(&self) -> bool {
        self.applied
    }

    pub fn last_apply(&self) -> Option<&MRemoteNgImportApplyOutcome> {
        self.last_apply.as_ref()
    }

    pub fn has_password_payloads(&self) -> bool {
        self.file_info
            .as_ref()
            .is_some_and(|i| i.has_password_payloads)
    }

    /// Fake picker → set path → plan (fail-closed on empty path / parse errors).
    pub fn pick_and_plan_from_ui(
        &mut self,
        ui: &dyn MRemoteNgImportPathUi,
        skip_reporter: &FakeImportSkipReporter,
    ) -> Result<(), MRemoteNgImportDialogError> {
        let path = ui.pick_xml_path()?;
        self.set_xml_path(path);
        self.plan_with_reporter(skip_reporter)
    }

    /// Plan from the current [`xml_path`] (fail-closed when empty / parse error).
    pub fn plan_with_reporter(
        &mut self,
        skip_reporter: &FakeImportSkipReporter,
    ) -> Result<(), MRemoteNgImportDialogError> {
        let path = validated_path(&self.xml_path)?;
        self.file_info = Some(inspect_xml(path)?);
        let (root, raw) = parse_xml_path(path)?;
        let plan = plan_nodes(&raw, &root, &self.import_password)?;
        let skip_report = skip_reporter.report(&plan);
        let skip_summary = format_skip_summary(&skip_report);
        self.preview = Some(ImportPlanPreview {
            folder_count: plan.folder_count,
            connection_count: plan.connection_count,
            skipped: plan.skipped,
            skip_report,
            skip_summary,
            warnings: plan.warnings.clone(),
            has_password_payloads: self.file_info.as_ref().is_some_and(|i| i.has_password_payloads),
            xml_path: self.xml_path.clone(),
        });
        self.plan = Some(plan);
        self.applied = false;
        self.last_apply = None;
        Ok(())
    }

    /// Optional apply after a successful plan ([`NotPlanned`] when plan missing).
    pub fn apply(
        &mut self,
        sink: &dyn MRemoteNgImportApplySink,
    ) -> Result<MRemoteNgImportApplyOutcome, MRemoteNgImportDialogError> {
        if self.applied {
            return Err(MRemoteNgImportDialogError::AlreadyApplied);
        }
        let plan = self
            .plan
            .as_ref()
            .ok_or(MRemoteNgImportDialogError::NotPlanned)?;
        let result = sink.apply_plan(plan)?;
        let outcome = MRemoteNgImportApplyOutcome::from(result);
        self.applied = true;
        self.last_apply = Some(outcome.clone());
        Ok(outcome)
    }

    fn clear_plan_state(&mut self) {
        self.file_info = None;
        self.preview = None;
        self.plan = None;
        self.applied = false;
        self.last_apply = None;
    }
}

fn validated_path(path: &str) -> Result<&Path, MRemoteNgImportDialogError> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err(MRemoteNgImportDialogError::EmptyPath);
    }
    Ok(Path::new(trimmed))
}

#[cfg(all(test, feature = "import"))]
mod tests {
    use super::*;
    use std::io::Write;
    use wormhole_import::UNSUPPORTED_PROTOCOL_REASON;
    use wormhole_storage::{NodeKind, ProtocolType};

    const MINI_XML: &str = r#"<?xml version="1.0"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" ConfVersion="2.7"
 EncryptionEngine="AES" BlockCipherMode="GCM" Protected="" FullFileEncryption="false"
 KdfIterations="1000">
  <Node Name="Lab" Type="Container" Protocol="SSH2">
    <Node Name="jump-ssh" Type="Connection" Protocol="SSH2"
          Hostname="192.0.2.10" Port="22" Username="ops" Password="" />
    <Node Name="dc-rdp" Type="Connection" Protocol="RDP"
          Hostname="192.0.2.20" Port="3389" Username="admin" Domain="LAB" Password="" />
    <Node Name="desk-vnc" Type="Connection" Protocol="VNC"
          Hostname="192.0.2.30" Port="5900" Username="ignored" Password="" />
    <Node Name="skip-http" Type="Connection" Protocol="HTTP"
          Hostname="192.0.2.41" Port="80" Username="" Password="" />
    <Node Name="skip-serial" Type="Connection" Protocol="Serial"
          Hostname="COM4" Port="" Username="" Password="" />
  </Node>
</mrng:Connections>"#;

    fn write_temp_xml(dir: &tempfile::TempDir, contents: &str) -> String {
        let path = dir.path().join("confCons.xml");
        std::fs::write(&path, contents).expect("write xml");
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn empty_path_fails_closed_on_plan() {
        let mut vm = MRemoteNgImportDialogVm::new();
        let reporter = FakeImportSkipReporter::new();
        let err = vm.plan_with_reporter(&reporter).expect_err("empty path");
        assert_eq!(err, MRemoteNgImportDialogError::EmptyPath);
        assert!(!vm.is_planned());
    }

    #[test]
    fn whitespace_path_fails_closed() {
        let mut vm = MRemoteNgImportDialogVm::new();
        vm.set_xml_path("   \t  ");
        let err = vm
            .plan_with_reporter(&FakeImportSkipReporter::new())
            .expect_err("whitespace");
        assert_eq!(err, MRemoteNgImportDialogError::EmptyPath);
    }

    #[test]
    fn fake_picker_empty_path_fails_closed() {
        let mut vm = MRemoteNgImportDialogVm::new();
        let ui = FakeMRemoteNgImportPathUi::returning("   ");
        let err = vm
            .pick_and_plan_from_ui(&ui, &FakeImportSkipReporter::new())
            .expect_err("empty from picker");
        assert_eq!(err, MRemoteNgImportDialogError::EmptyPath);
        assert_eq!(ui.pick_calls(), 1);
    }

    #[test]
    fn parse_error_fails_closed_without_plan() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = write_temp_xml(&dir, "<not-mremoteng/>");
        let mut vm = MRemoteNgImportDialogVm::new();
        vm.set_xml_path(path);
        let err = vm
            .plan_with_reporter(&FakeImportSkipReporter::new())
            .expect_err("parse");
        assert!(matches!(err, MRemoteNgImportDialogError::Import(_)));
        assert!(!vm.is_planned());
        assert!(vm.preview().is_none());
    }

    #[test]
    fn plan_ssh_rdp_vnc_and_soft_skip_report() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = write_temp_xml(&dir, MINI_XML);
        let mut vm = MRemoteNgImportDialogVm::new();
        vm.set_xml_path(path);
        vm.plan_with_reporter(&FakeImportSkipReporter::new())
            .expect("plan");
        let preview = vm.preview().expect("preview");
        assert_eq!(preview.folder_count, 1);
        assert_eq!(preview.connection_count, 3);
        assert_eq!(preview.skipped, 2);
        assert_eq!(preview.skip_report.total_skipped, 2);
        assert!(preview.skip_summary.contains("Skipped 2 unsupported connections."));
        assert!(preview.skip_summary.contains("skip-http (HTTP)"));
        assert!(preview.skip_summary.contains(UNSUPPORTED_PROTOCOL_REASON));
        assert!(vm.can_apply());
    }

    #[test]
    fn apply_after_plan_via_fake_lab() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = write_temp_xml(&dir, MINI_XML);
        let mut vm = MRemoteNgImportDialogVm::new();
        vm.set_xml_path(path);
        vm.plan_with_reporter(&FakeImportSkipReporter::new())
            .expect("plan");
        let lab = FakeMRemoteNgImportLab::new();
        let outcome = vm.apply(&lab).expect("apply");
        assert_eq!(outcome.inserted, 4);
        assert_eq!(outcome.skipped, 2);
        assert_eq!(lab.node_count(), 4);
        assert!(!vm.can_apply());
        assert!(vm.applied());

        let folders = lab.repo().list_folders().expect("folders");
        assert_eq!(folders.len(), 1);
        let conns = lab.repo().list_connections().expect("conns");
        assert_eq!(conns.len(), 3);
        assert!(conns.iter().any(|n| n.node.name == "jump-ssh"));
        assert!(
            !lab
                .repo()
                .list_all()
                .expect("all")
                .iter()
                .any(|n| n.node.name == "skip-http")
        );
    }

    #[test]
    fn double_apply_fails_closed_without_duplicate_rows() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = write_temp_xml(&dir, MINI_XML);
        let mut vm = MRemoteNgImportDialogVm::new();
        vm.set_xml_path(path);
        vm.plan_with_reporter(&FakeImportSkipReporter::new())
            .expect("plan");
        let lab = FakeMRemoteNgImportLab::new();
        vm.apply(&lab).expect("first apply");
        assert_eq!(lab.node_count(), 4);
        let err = vm.apply(&lab).expect_err("second apply");
        assert_eq!(err, MRemoteNgImportDialogError::AlreadyApplied);
        assert_eq!(lab.node_count(), 4);
    }

    #[test]
    fn apply_without_plan_fails_closed() {
        let mut vm = MRemoteNgImportDialogVm::new();
        let lab = FakeMRemoteNgImportLab::new();
        let err = vm.apply(&lab).expect_err("not planned");
        assert_eq!(err, MRemoteNgImportDialogError::NotPlanned);
        assert_eq!(lab.node_count(), 0);
    }

    #[test]
    fn path_change_clears_plan_and_apply_state() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = write_temp_xml(&dir, MINI_XML);
        let mut vm = MRemoteNgImportDialogVm::new();
        vm.set_xml_path(path);
        vm.plan_with_reporter(&FakeImportSkipReporter::new())
            .expect("plan");
        let lab = FakeMRemoteNgImportLab::new();
        vm.apply(&lab).expect("apply");
        vm.set_xml_path("other.xml");
        assert!(!vm.is_planned());
        assert!(!vm.applied());
        assert!(vm.last_apply().is_none());
    }

    #[test]
    fn password_change_clears_stale_plan() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = write_temp_xml(&dir, MINI_XML);
        let mut vm = MRemoteNgImportDialogVm::new();
        vm.set_xml_path(path);
        vm.plan_with_reporter(&FakeImportSkipReporter::new())
            .expect("plan");
        vm.set_import_password("new-pw");
        assert!(!vm.is_planned());
    }

    #[test]
    fn debug_never_echoes_password_or_planned_secrets() {
        const SECRET: &str = "SUPER_SECRET_IMPORT_DIALOG_PW";
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = dir.path().join("cipher.xml");
        let mut file = std::fs::File::create(&path).expect("create");
        // Minimal SSH node with password field in XML (plan may hold decrypted text internally).
        let xml = format!(
            r#"<?xml version="1.0"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" ConfVersion="2.7"
 EncryptionEngine="AES" BlockCipherMode="GCM" Protected="" FullFileEncryption="false"
 KdfIterations="1000">
  <Node Name="cipher-ssh" Type="Connection" Protocol="SSH2"
        Hostname="192.0.2.10" Port="22" Username="u" Password="{SECRET}" />
</mrng:Connections>"#
        );
        file.write_all(xml.as_bytes()).expect("write");
        let mut vm = MRemoteNgImportDialogVm::new();
        vm.set_xml_path(path.to_string_lossy().to_string());
        vm.set_import_password("dialog-pw");
        vm.plan_with_reporter(&FakeImportSkipReporter::new())
            .expect("plan");
        let dbg = format!("{vm:?}");
        assert!(!dbg.contains(SECRET), "vm Debug leaked xml password: {dbg}");
        assert!(!dbg.contains("dialog-pw"), "vm Debug leaked import password: {dbg}");
        let preview_dbg = format!("{:?}", vm.preview().expect("preview"));
        assert!(!preview_dbg.contains(SECRET), "preview leaked secret: {preview_dbg}");
    }

    #[test]
    fn fake_path_ui_forced_err_and_ok_paths() {
        let ui = FakeMRemoteNgImportPathUi::returning("C:\\lab\\confCons.xml");
        assert_eq!(
            ui.pick_xml_path().expect("ok"),
            "C:\\lab\\confCons.xml"
        );
        assert_eq!(ui.pick_calls(), 1);

        let fail = FakeMRemoteNgImportPathUi::failing("picker cancelled");
        let err = fail.pick_xml_path().expect_err("cancel");
        assert_eq!(
            err,
            MRemoteNgImportDialogError::PathPick("picker cancelled".into())
        );
        let dbg = format!("{fail:?}");
        assert!(!dbg.contains("cancelled"), "Fake Debug must be counts-only: {dbg}");
    }

    #[test]
    fn fake_skip_reporter_can_force_canned_report() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = write_temp_xml(&dir, MINI_XML);
        let mut vm = MRemoteNgImportDialogVm::new();
        vm.set_xml_path(path);
        let canned = ImportSkipReport {
            total_skipped: 1,
            entries: vec![],
        };
        let reporter = FakeImportSkipReporter::from_report(canned.clone());
        vm.plan_with_reporter(&reporter).expect("plan");
        assert_eq!(vm.preview().expect("p").skip_report, canned);
    }

    #[test]
    fn pick_and_plan_round_trip_via_fake_ui() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = write_temp_xml(&dir, MINI_XML);
        let ui = FakeMRemoteNgImportPathUi::returning(path);
        let mut vm = MRemoteNgImportDialogVm::new();
        vm.pick_and_plan_from_ui(&ui, &FakeImportSkipReporter::new())
            .expect("flow");
        assert!(vm.xml_path().ends_with("confCons.xml"));
        let lab = FakeMRemoteNgImportLab::new();
        vm.apply(&lab).expect("apply");
        let conns = lab.repo().list_connections().expect("conns");
        let ssh = conns
            .iter()
            .find(|n| n.node.name == "jump-ssh")
            .expect("ssh");
        assert_eq!(ssh.node.protocol, Some(ProtocolType::Ssh));
        assert_eq!(ssh.node.kind, NodeKind::Connection);
        assert!(ssh.node.protocol != Some(ProtocolType::Http));
    }

    #[test]
    fn doctype_xml_fails_closed_before_apply() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let bad = r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<mrng:Connections xmlns:mrng="http://mremoteng.org" ConfVersion="2.7"
 EncryptionEngine="AES" BlockCipherMode="GCM" Protected="" FullFileEncryption="false"
 KdfIterations="1000"></mrng:Connections>"#;
        let path = write_temp_xml(&dir, bad);
        let mut vm = MRemoteNgImportDialogVm::new();
        vm.set_xml_path(path);
        let err = vm
            .plan_with_reporter(&FakeImportSkipReporter::new())
            .expect_err("doctype");
        assert!(matches!(err, MRemoteNgImportDialogError::Import(_)));
        let lab = FakeMRemoteNgImportLab::new();
        assert_eq!(
            vm.apply(&lab).expect_err("apply blocked"),
            MRemoteNgImportDialogError::NotPlanned
        );
    }
}
