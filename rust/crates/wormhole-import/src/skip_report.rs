//! Soft-skip → user-facing UnsupportedProtocol report glue.
//!
//! Converts [`ImportPlan`] soft-skips (`skipped` + `skipped_samples`) into a
//! structured, secrets-free summary for UI / logs. **No GPUI** — headless
//! [`FakeImportSkipReporter`] covers unit tests. Does not apply plans or touch
//! Credential Manager / decrypted passwords on [`crate::PlannedNode`].

use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use crate::mremoteng::ImportPlan;

/// Stable reason string for soft-skipped Connection leaves (SSH/RDP/VNC-only import).
pub const UNSUPPORTED_PROTOCOL_REASON: &str =
    "unsupported mRemoteNG protocol (import supports SSH, RDP, and VNC only)";

/// One soft-skipped Connection leaf (name + protocol label + reason).
///
/// Never carries password / credential fields — only planning metadata that was
/// already safe to show in `ImportPlan.skipped_samples`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsupportedProtocolSkip {
    /// Connection display name from the mRemoteNG export.
    pub name: String,
    /// Raw protocol attribute (or `(unspecified)` when empty).
    pub protocol: String,
    /// Why the leaf was not imported.
    pub reason: String,
}

/// Structured skip report for a single import plan (empty skips are valid).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ImportSkipReport {
    /// Total soft-skipped Connection leaves (`ImportPlan.skipped`).
    pub total_skipped: usize,
    /// Sample entries (at most the plan's `skipped_samples`, typically ≤ 5).
    pub entries: Vec<UnsupportedProtocolSkip>,
}

impl ImportSkipReport {
    /// No soft-skips.
    pub fn empty() -> Self {
        Self::default()
    }

    /// True when nothing was soft-skipped.
    pub fn is_empty(&self) -> bool {
        self.total_skipped == 0
    }
}

/// Build a secrets-free skip report from an [`ImportPlan`].
///
/// Reads only `skipped` / `skipped_samples`. Never inspects
/// [`crate::PlannedNode::password_plaintext`] (or any other node field).
pub fn report_unsupported_skips(plan: &ImportPlan) -> ImportSkipReport {
    ImportSkipReport {
        total_skipped: plan.skipped,
        entries: plan
            .skipped_samples
            .iter()
            .map(|sample| entry_from_sample(sample))
            .collect(),
    }
}

/// User-facing skip summary (InfoBar / log paste). Empty when `total_skipped == 0`.
///
/// Sample lines include the full [`UNSUPPORTED_PROTOCOL_REASON`] (never truncated).
/// `+N more` is only appended when at least one sample entry was listed.
pub fn format_skip_summary(report: &ImportSkipReport) -> String {
    if report.total_skipped == 0 {
        return String::new();
    }

    let plural = if report.total_skipped == 1 { "" } else { "s" };
    let mut out = format!(
        "Skipped {} unsupported connection{plural}.",
        report.total_skipped
    );
    for entry in &report.entries {
        out.push_str(&format!(
            "\n  - {} ({}): {}",
            entry.name, entry.protocol, entry.reason
        ));
    }
    // Only when samples were shown: "+N more" means beyond the listed lines.
    if !report.entries.is_empty() && report.total_skipped > report.entries.len() {
        let more = report.total_skipped - report.entries.len();
        out.push_str(&format!("\n  (+{more} more)"));
    }
    out
}

fn entry_from_sample(sample: &str) -> UnsupportedProtocolSkip {
    // Planning writes `"name: protocol"` (C# `SkippedProtocolSamples` parity).
    // Use rsplit so a display name that itself contains `: ` keeps the trailing
    // protocol label (protocols never embed `: `; names sometimes do).
    match sample.rsplit_once(": ") {
        Some((name, protocol)) => UnsupportedProtocolSkip {
            name: name.to_string(),
            protocol: protocol.to_string(),
            reason: UNSUPPORTED_PROTOCOL_REASON.to_string(),
        },
        None => UnsupportedProtocolSkip {
            name: sample.to_string(),
            protocol: String::new(),
            reason: UNSUPPORTED_PROTOCOL_REASON.to_string(),
        },
    }
}

/// Headless skip-report stub for unit tests (**no GPUI** dialog).
///
/// Callers may force a canned [`ImportSkipReport`], or fall through to
/// [`report_unsupported_skips`]. Forced / Debug paths never retain passwords.
pub struct FakeImportSkipReporter {
    forced: Mutex<Option<ImportSkipReport>>,
    report_calls: AtomicUsize,
}

impl Default for FakeImportSkipReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for FakeImportSkipReporter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let forced = self.forced.lock().unwrap_or_else(|p| p.into_inner());
        f.debug_struct("FakeImportSkipReporter")
            .field("forced_total_skipped", &forced.as_ref().map(|r| r.total_skipped))
            .field("forced_entry_count", &forced.as_ref().map(|r| r.entries.len()))
            .field("report_calls", &self.report_calls.load(Ordering::SeqCst))
            .finish()
    }
}

impl FakeImportSkipReporter {
    /// No forced report — [`report`](Self::report) builds from the plan.
    pub fn new() -> Self {
        Self {
            forced: Mutex::new(None),
            report_calls: AtomicUsize::new(0),
        }
    }

    /// Always return this canned report (plan soft-skips ignored).
    pub fn from_report(report: ImportSkipReport) -> Self {
        let fake = Self::new();
        fake.force(report);
        fake
    }

    /// Replace the forced report (plan soft-skips ignored until [`clear_forced`](Self::clear_forced)).
    pub fn force(&self, report: ImportSkipReport) {
        let mut guard = self.forced.lock().unwrap_or_else(|p| p.into_inner());
        *guard = Some(report);
    }

    /// Clear any forced report and resume plan-driven [`report`](Self::report).
    pub fn clear_forced(&self) {
        let mut guard = self.forced.lock().unwrap_or_else(|p| p.into_inner());
        *guard = None;
    }

    /// How many times [`report`](Self::report) was called.
    pub fn report_calls(&self) -> usize {
        self.report_calls.load(Ordering::SeqCst)
    }

    /// Prefer forced report; otherwise [`report_unsupported_skips`] (no passwords).
    pub fn report(&self, plan: &ImportPlan) -> ImportSkipReport {
        self.report_calls.fetch_add(1, Ordering::SeqCst);
        let forced = self.forced.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(report) = forced.as_ref() {
            report.clone()
        } else {
            report_unsupported_skips(plan)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mremoteng::{parse_xml_bytes, plan_nodes, ImportPlan, PlannedNode};
    use crate::protocol::MappedProtocol;
    use uuid::Uuid;

    fn empty_plan() -> ImportPlan {
        ImportPlan {
            nodes: vec![],
            folder_count: 0,
            connection_count: 0,
            skipped: 0,
            skipped_samples: vec![],
            warnings: vec![],
        }
    }

    #[test]
    fn empty_skips_yield_empty_report_and_summary() {
        let report = report_unsupported_skips(&empty_plan());
        assert!(report.is_empty());
        assert_eq!(report.total_skipped, 0);
        assert!(report.entries.is_empty());
        assert_eq!(format_skip_summary(&report), "");
    }

    #[test]
    fn structured_entries_from_samples() {
        let plan = ImportPlan {
            nodes: vec![],
            folder_count: 0,
            connection_count: 0,
            skipped: 2,
            skipped_samples: vec!["web-http: HTTP".into(), "console: Serial".into()],
            warnings: vec![],
        };
        let report = report_unsupported_skips(&plan);
        assert_eq!(report.total_skipped, 2);
        assert_eq!(report.entries.len(), 2);
        assert_eq!(report.entries[0].name, "web-http");
        assert_eq!(report.entries[0].protocol, "HTTP");
        assert_eq!(report.entries[0].reason, UNSUPPORTED_PROTOCOL_REASON);
        assert_eq!(report.entries[1].name, "console");
        assert_eq!(report.entries[1].protocol, "Serial");

        let text = format_skip_summary(&report);
        assert!(text.starts_with("Skipped 2 unsupported connections."));
        assert!(text.contains("web-http (HTTP)"));
        assert!(text.contains("console (Serial)"));
        assert!(text.contains(UNSUPPORTED_PROTOCOL_REASON));
    }

    #[test]
    fn overflow_samples_note_more() {
        let plan = ImportPlan {
            nodes: vec![],
            folder_count: 0,
            connection_count: 0,
            skipped: 7,
            skipped_samples: vec![
                "a: HTTP".into(),
                "b: HTTPS".into(),
                "c: Serial".into(),
                "d: TELNET".into(),
                "e: RAW".into(),
            ],
            warnings: vec![],
        };
        let text = format_skip_summary(&report_unsupported_skips(&plan));
        assert!(text.contains("Skipped 7 unsupported connections."));
        assert!(text.contains("(+2 more)"));
    }

    #[test]
    fn count_only_skips_omit_plus_more_when_no_samples() {
        let plan = ImportPlan {
            skipped: 3,
            skipped_samples: vec![],
            ..empty_plan()
        };
        let text = format_skip_summary(&report_unsupported_skips(&plan));
        assert_eq!(text, "Skipped 3 unsupported connections.");
        assert!(!text.contains("more"));
    }

    #[test]
    fn colon_in_connection_name_keeps_trailing_protocol() {
        let plan = ImportPlan {
            skipped: 1,
            skipped_samples: vec!["lab: prod gateway: HTTP".into()],
            ..empty_plan()
        };
        let report = report_unsupported_skips(&plan);
        assert_eq!(report.entries[0].name, "lab: prod gateway");
        assert_eq!(report.entries[0].protocol, "HTTP");
        let summary = format_skip_summary(&report);
        assert!(summary.contains("lab: prod gateway (HTTP)"));
        assert!(!summary.contains("prod gateway: HTTP)"));
    }

    #[test]
    fn unicode_names_round_trip_in_report_and_summary() {
        let name = "café-服务器-🔐";
        let plan = ImportPlan {
            skipped: 1,
            skipped_samples: vec![format!("{name}: HTTPS")],
            ..empty_plan()
        };
        let report = report_unsupported_skips(&plan);
        assert_eq!(report.entries[0].name, name);
        assert_eq!(report.entries[0].protocol, "HTTPS");
        let summary = format_skip_summary(&report);
        assert!(summary.contains(name));
        assert!(summary.contains("(HTTPS)"));
    }

    #[test]
    fn reason_is_never_truncated_in_summary() {
        let plan = ImportPlan {
            skipped: 1,
            skipped_samples: vec!["x: Serial".into()],
            ..empty_plan()
        };
        let summary = format_skip_summary(&report_unsupported_skips(&plan));
        assert!(
            summary.contains(UNSUPPORTED_PROTOCOL_REASON),
            "reason truncated: {summary}"
        );
        assert_eq!(
            summary.matches(UNSUPPORTED_PROTOCOL_REASON).count(),
            1,
            "expected exactly one full reason line"
        );
    }

    #[test]
    fn malformed_sample_without_delimiter_keeps_whole_as_name() {
        let plan = ImportPlan {
            skipped: 1,
            skipped_samples: vec!["no-delimiter-HTTP".into()],
            ..empty_plan()
        };
        let report = report_unsupported_skips(&plan);
        assert_eq!(report.entries[0].name, "no-delimiter-HTTP");
        assert!(report.entries[0].protocol.is_empty());
        assert_eq!(report.entries[0].reason, UNSUPPORTED_PROTOCOL_REASON);
    }

    #[test]
    fn report_never_includes_decrypted_passwords() {
        const SECRET: &str = "SUPER_SECRET_IMPORT_PW_xyz";
        let plan = ImportPlan {
            nodes: vec![PlannedNode {
                id: Uuid::nil(),
                parent_id: None,
                name: "cipher-ssh".into(),
                is_folder: false,
                protocol: Some(MappedProtocol::Ssh),
                host: Some("192.0.2.10".into()),
                port: Some(22),
                username: Some("u".into()),
                domain: None,
                sort_order: 0,
                password_plaintext: Some(SECRET.into()),
                password_decrypt_failed: false,
            }],
            folder_count: 0,
            connection_count: 1,
            skipped: 1,
            skipped_samples: vec!["web-http: HTTP".into()],
            warnings: vec![],
        };

        let report = report_unsupported_skips(&plan);
        let dbg = format!("{report:?}");
        let summary = format_skip_summary(&report);
        assert!(!dbg.contains(SECRET), "Debug leaked password: {dbg}");
        assert!(!summary.contains(SECRET), "summary leaked password: {summary}");
        // Report surface has no password fields at all.
        assert!(!format!("{report:#?}").contains("password"));

        // Fake path must also ignore PlannedNode secrets (counts-only Debug).
        let fake = FakeImportSkipReporter::new();
        let via_fake = fake.report(&plan);
        assert!(!format!("{via_fake:?}").contains(SECRET));
        assert!(!format!("{fake:?}").contains(SECRET));
        assert_eq!(via_fake, report);
    }

    #[test]
    fn fake_reporter_forces_canned_report() {
        let canned = ImportSkipReport {
            total_skipped: 1,
            entries: vec![UnsupportedProtocolSkip {
                name: "forced-secret-looking".into(),
                protocol: "ICA".into(),
                reason: UNSUPPORTED_PROTOCOL_REASON.into(),
            }],
        };
        let fake = FakeImportSkipReporter::from_report(canned.clone());
        let plan = ImportPlan {
            skipped: 99,
            skipped_samples: vec!["ignored: HTTP".into()],
            ..empty_plan()
        };
        let got = fake.report(&plan);
        assert_eq!(got, canned);
        assert_eq!(fake.report_calls(), 1);

        let dbg = format!("{fake:?}");
        assert!(dbg.contains("forced_total_skipped"));
        assert!(dbg.contains("forced_entry_count: Some(1)"));
        assert!(!dbg.contains("ICA"), "Fake Debug should be counts-only: {dbg}");
        assert!(
            !dbg.contains("forced-secret-looking"),
            "Fake Debug must not echo entry names: {dbg}"
        );
        assert!(
            !dbg.contains(UNSUPPORTED_PROTOCOL_REASON),
            "Fake Debug must not echo reasons: {dbg}"
        );
    }

    #[test]
    fn fake_reporter_falls_through_to_plan() {
        let fake = FakeImportSkipReporter::new();
        let plan = ImportPlan {
            skipped: 1,
            skipped_samples: vec!["mystery: (unspecified)".into()],
            ..empty_plan()
        };
        let got = fake.report(&plan);
        assert_eq!(got.total_skipped, 1);
        assert_eq!(got.entries[0].protocol, "(unspecified)");
        assert_eq!(fake.report_calls(), 1);

        fake.force(ImportSkipReport {
            total_skipped: 2,
            entries: vec![],
        });
        assert_eq!(fake.report(&plan).total_skipped, 2);
        fake.clear_forced();
        assert_eq!(fake.report(&plan).total_skipped, 1);
        assert_eq!(fake.report_calls(), 3);
    }

    #[test]
    fn plan_soft_skips_round_trip_to_report() {
        let xml = br#"<?xml version="1.0"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" ConfVersion="2.7"
 EncryptionEngine="AES" BlockCipherMode="GCM" Protected="" FullFileEncryption="false"
 KdfIterations="1000">
  <Node Name="web-http" Type="Connection" Protocol="HTTP"
        Hostname="192.0.2.41" Port="80" Username="" Password="" />
  <Node Name="keep-ssh" Type="Connection" Protocol="SSH2"
        Hostname="192.0.2.10" Port="22" Username="u" Password="" />
</mrng:Connections>"#;
        let (root, nodes) = parse_xml_bytes(xml).expect("parse");
        let plan = plan_nodes(&nodes, &root, "").expect("plan");
        let report = report_unsupported_skips(&plan);
        assert_eq!(report.total_skipped, 1);
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.entries[0].name, "web-http");
        assert_eq!(report.entries[0].protocol, "HTTP");
        let summary = format_skip_summary(&report);
        assert!(summary.contains("Skipped 1 unsupported connection."));
        assert!(summary.contains("web-http (HTTP)"));
    }

    #[test]
    fn xml_colon_and_unicode_names_plan_into_report() {
        // Non-ASCII + embedded ": " in Name — planning sample must round-trip via rsplit.
        let xml = concat!(
            r#"<?xml version="1.0"?>"#,
            r#"<mrng:Connections xmlns:mrng="http://mremoteng.org" ConfVersion="2.7""#,
            r#" EncryptionEngine="AES" BlockCipherMode="GCM" Protected="""#,
            r#" FullFileEncryption="false" KdfIterations="1000">"#,
            r#"  <Node Name="site: café" Type="Connection" Protocol="HTTP""#,
            r#"        Hostname="192.0.2.41" Port="80" Username="" Password="" />"#,
            r#"</mrng:Connections>"#,
        );
        let (root, nodes) = parse_xml_bytes(xml.as_bytes()).expect("parse");
        let plan = plan_nodes(&nodes, &root, "").expect("plan");
        assert_eq!(plan.skipped_samples, vec!["site: café: HTTP".to_string()]);
        let report = report_unsupported_skips(&plan);
        assert_eq!(report.entries[0].name, "site: café");
        assert_eq!(report.entries[0].protocol, "HTTP");
    }
}
