//! Apply an [`ImportPlan`] to SQLite via [`wormhole_storage::ConnectionRepository`].
//!
//! This is the **node write stub**: planned folders + SSH/RDP/VNC connections are
//! inserted transactionally. Credential Manager / `CredentialProfiles` / password
//! plaintext are **not** written yet (see `docs/migration/12-import.md`).

use wormhole_domain::{ConnectionNode, NodeKind, ProtocolType};
use wormhole_storage::{ConnectionRepository, StoredConnectionNode};

use crate::error::ImportError;
use crate::mremoteng::{ImportPlan, PlannedNode};

/// Outcome of [`apply_import_plan`].
#[derive(Debug, Clone)]
pub struct ApplyImportResult {
    /// Rows successfully inserted (same length as `plan.nodes` on success).
    pub inserted: usize,
    pub folder_count: usize,
    pub connection_count: usize,
    /// Soft-skipped unsupported Connection leaves from planning (not in `plan.nodes`).
    pub skipped: usize,
    pub warnings: Vec<String>,
    pub stored: Vec<StoredConnectionNode>,
}

/// Soft-skipped / gap protocols must never be written (defense-in-depth if a plan
/// is hand-crafted). Folders may carry `None`; connections may be SSH/RDP/VNC only.
fn reject_gap_protocol(protocol: Option<ProtocolType>) -> Result<(), ImportError> {
    match protocol {
        None | Some(ProtocolType::Ssh | ProtocolType::Rdp | ProtocolType::Vnc) => Ok(()),
        Some(other) => Err(ImportError::InvalidData(format!(
            "import apply refuses protocol {other:?}; HTTP/HTTPS/Serial and other \
             soft-skipped protocols must not be written to SQLite"
        ))),
    }
}

/// Map a planned import node to a domain [`ConnectionNode`].
///
/// - Soft-skipped protocols are rejected here (planning already drops them; this
///   blocks hand-crafted plans from leaking HTTP/HTTPS/Serial into SQLite).
/// - `password_plaintext` is **ignored** — secrets persist is a later spike.
/// - `credential_id` / RDP screen-size fields stay unset in this stub.
pub fn planned_to_connection_node(planned: &PlannedNode) -> Result<ConnectionNode, ImportError> {
    reject_gap_protocol(planned.protocol)?;
    let protocol = planned.protocol;
    // C# parity: RdpDomain only when protocol is RDP or unset (folder inherit).
    let rdp_domain = match protocol {
        Some(ProtocolType::Rdp) | None => planned.domain.clone(),
        _ => None,
    };
    Ok(ConnectionNode {
        id: planned.id,
        parent_id: planned.parent_id,
        name: planned.name.clone(),
        kind: if planned.is_folder {
            NodeKind::Folder
        } else {
            NodeKind::Connection
        },
        sort_order: planned.sort_order,
        protocol,
        host: planned.host.clone(),
        port: planned.port,
        username: planned.username.clone(),
        credential_id: None,
        rdp_domain,
        ..ConnectionNode::default()
    })
}

/// Convert every planned node and insert them in one SQLite transaction.
///
/// Soft-skipped leaves are already absent from `plan.nodes`; they only surface as
/// `ApplyImportResult::skipped`. Nodes must remain in DFS parent-before-child order
/// (as produced by [`crate::plan_nodes`]). Gap protocols in `plan.nodes` fail closed
/// before any write.
pub fn apply_import_plan(
    repo: &ConnectionRepository<'_>,
    plan: &ImportPlan,
) -> Result<ApplyImportResult, ImportError> {
    let domain_nodes: Vec<ConnectionNode> = plan
        .nodes
        .iter()
        .map(planned_to_connection_node)
        .collect::<Result<Vec<_>, _>>()?;
    let stored = repo.insert_many(&domain_nodes)?;
    Ok(ApplyImportResult {
        inserted: stored.len(),
        folder_count: plan.folder_count,
        connection_count: plan.connection_count,
        skipped: plan.skipped,
        warnings: plan.warnings.clone(),
        stored,
    })
}

/// Apply an already-mapped `&[ConnectionNode]` slice (same transactional semantics).
pub fn apply_connection_nodes(
    repo: &ConnectionRepository<'_>,
    nodes: &[ConnectionNode],
) -> Result<Vec<StoredConnectionNode>, ImportError> {
    Ok(repo.insert_many(nodes)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parse_xml_bytes, plan_nodes, MappedProtocol};
    use tempfile::TempDir;
    use uuid::Uuid;
    use wormhole_storage::{MigrationRunner, ProtocolType, SqliteConnectionFactory};

    fn temp_repo() -> (TempDir, SqliteConnectionFactory) {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("wormhole.db");
        let factory = SqliteConnectionFactory::new(&path);
        MigrationRunner::embedded().run(&factory).expect("migrate");
        (dir, factory)
    }

    #[test]
    fn planned_to_connection_drops_password_and_sets_kinds() {
        let planned = PlannedNode {
            id: Uuid::nil(),
            parent_id: None,
            name: "jump".into(),
            is_folder: false,
            protocol: Some(MappedProtocol::Ssh),
            host: Some("192.0.2.10".into()),
            port: Some(22),
            username: Some("u".into()),
            domain: Some("SHOULD_NOT_BE_RDP_DOMAIN".into()),
            sort_order: 0,
            password_plaintext: Some("secret".into()),
            password_decrypt_failed: false,
        };
        let node = planned_to_connection_node(&planned).expect("map");
        assert_eq!(node.kind, NodeKind::Connection);
        assert_eq!(node.protocol, Some(ProtocolType::Ssh));
        assert!(node.credential_id.is_none());
        assert!(node.credential_mode.is_none());
        assert!(node.use_inline_password.is_none());
        assert!(node.rdp_domain.is_none(), "SSH must not copy domain to RdpDomain");
        assert_eq!(node.username.as_deref(), Some("u"));
        let dbg = format!("{node:?}");
        assert!(
            !dbg.contains("secret"),
            "mapped ConnectionNode Debug must not echo password plaintext"
        );
    }

    #[test]
    fn planned_rdp_keeps_domain_on_rdp_domain() {
        let planned = PlannedNode {
            id: Uuid::nil(),
            parent_id: None,
            name: "dc".into(),
            is_folder: false,
            protocol: Some(MappedProtocol::Rdp),
            host: Some("192.0.2.20".into()),
            port: Some(3389),
            username: Some("a".into()),
            domain: Some("LAB".into()),
            sort_order: 0,
            password_plaintext: None,
            password_decrypt_failed: false,
        };
        let node = planned_to_connection_node(&planned).expect("map");
        assert_eq!(node.rdp_domain.as_deref(), Some("LAB"));
        assert_eq!(node.protocol, Some(ProtocolType::Rdp));
    }

    #[test]
    fn planned_folder_unset_protocol_keeps_domain_on_rdp_domain() {
        let planned = PlannedNode {
            id: Uuid::nil(),
            parent_id: None,
            name: "Lab".into(),
            is_folder: true,
            protocol: None,
            host: None,
            port: None,
            username: None,
            domain: Some("INHERIT-DOM".into()),
            sort_order: 0,
            password_plaintext: None,
            password_decrypt_failed: false,
        };
        let node = planned_to_connection_node(&planned).expect("map");
        assert_eq!(node.kind, NodeKind::Folder);
        assert!(node.protocol.is_none());
        assert_eq!(node.rdp_domain.as_deref(), Some("INHERIT-DOM"));
    }

    #[test]
    fn planned_rejects_gap_protocols_http_https_serial() {
        for proto in [
            MappedProtocol::Http,
            MappedProtocol::Https,
            MappedProtocol::Serial,
        ] {
            let planned = PlannedNode {
                id: Uuid::nil(),
                parent_id: None,
                name: "leak".into(),
                is_folder: false,
                protocol: Some(proto),
                host: Some("192.0.2.99".into()),
                port: Some(80),
                username: None,
                domain: None,
                sort_order: 0,
                password_plaintext: Some("must-not-matter".into()),
                password_decrypt_failed: false,
            };
            let err = planned_to_connection_node(&planned).expect_err("gap protocol");
            assert!(
                matches!(err, ImportError::InvalidData(_)),
                "expected InvalidData for {proto:?}, got {err:?}"
            );
            let msg = err.to_string();
            assert!(msg.contains("refuses protocol"), "{msg}");
            assert!(!msg.contains("must-not-matter"), "{msg}");
        }
    }

    #[test]
    fn apply_refuses_handcrafted_http_before_any_write() {
        let (_dir, factory) = temp_repo();
        let repo = ConnectionRepository::new(&factory);
        let plan = ImportPlan {
            nodes: vec![PlannedNode {
                id: Uuid::parse_str("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap(),
                parent_id: None,
                name: "appliance".into(),
                is_folder: false,
                protocol: Some(MappedProtocol::Http),
                host: Some("192.0.2.41".into()),
                port: Some(80),
                username: None,
                domain: None,
                sort_order: 0,
                password_plaintext: None,
                password_decrypt_failed: false,
            }],
            folder_count: 0,
            connection_count: 1,
            skipped: 0,
            skipped_samples: vec![],
            warnings: vec![],
        };
        let err = apply_import_plan(&repo, &plan).expect_err("HTTP must not apply");
        assert!(matches!(err, ImportError::InvalidData(_)), "got {err:?}");
        assert!(repo.list_all().unwrap().is_empty());
    }

    #[test]
    fn mini_xml_plan_apply_round_trip_ssh_rdp_vnc_skips_gaps() {
        let xml = br#"<?xml version="1.0"?>
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
        let (root, raw) = parse_xml_bytes(xml).expect("parse");
        let plan = plan_nodes(&raw, &root, "").expect("plan");
        assert_eq!(plan.folder_count, 1);
        assert_eq!(plan.connection_count, 3);
        assert_eq!(plan.skipped, 2);

        let (_dir, factory) = temp_repo();
        let repo = ConnectionRepository::new(&factory);
        let result = apply_import_plan(&repo, &plan).expect("apply");
        assert_eq!(result.inserted, 4);
        assert_eq!(result.skipped, 2);
        assert_eq!(result.folder_count, 1);
        assert_eq!(result.connection_count, 3);
        let result_dbg = format!("{result:?}");
        assert!(!result_dbg.contains("Password="));

        let all = repo.list_all().expect("list");
        assert_eq!(all.len(), 4);
        let folders = repo.list_folders().expect("folders");
        assert_eq!(folders.len(), 1);
        assert_eq!(folders[0].node.name, "Lab");

        let conns = repo.list_connections().expect("conns");
        assert_eq!(conns.len(), 3);
        let ssh = conns
            .iter()
            .find(|n| n.node.name == "jump-ssh")
            .expect("ssh");
        assert_eq!(ssh.node.protocol, Some(ProtocolType::Ssh));
        assert_eq!(ssh.node.host.as_deref(), Some("192.0.2.10"));
        assert_eq!(ssh.node.port, Some(22));
        assert_eq!(ssh.node.username.as_deref(), Some("ops"));
        assert_eq!(ssh.node.parent_id, Some(folders[0].node.id));
        assert!(ssh.node.credential_id.is_none());
        assert!(ssh.node.use_inline_password.is_none());

        let rdp = conns
            .iter()
            .find(|n| n.node.name == "dc-rdp")
            .expect("rdp");
        assert_eq!(rdp.node.protocol, Some(ProtocolType::Rdp));
        assert_eq!(rdp.node.host.as_deref(), Some("192.0.2.20"));
        assert_eq!(rdp.node.port, Some(3389));
        assert_eq!(rdp.node.rdp_domain.as_deref(), Some("LAB"));

        let vnc = conns
            .iter()
            .find(|n| n.node.name == "desk-vnc")
            .expect("vnc");
        assert_eq!(vnc.node.protocol, Some(ProtocolType::Vnc));
        assert_eq!(vnc.node.host.as_deref(), Some("192.0.2.30"));
        assert_eq!(vnc.node.port, Some(5900));
        assert!(vnc.node.username.is_none(), "VNC username cleared at plan");
        assert!(vnc.node.rdp_domain.is_none());

        assert!(
            !all.iter().any(|n| n.node.name == "skip-http" || n.node.name == "skip-serial"),
            "HTTP/Serial soft-skip must not land in SQLite"
        );
        assert!(
            !all.iter().any(|n| {
                matches!(
                    n.node.protocol,
                    Some(ProtocolType::Http | ProtocolType::Https | ProtocolType::Serial)
                )
            }),
            "gap ProtocolType values must never appear in Nodes after apply"
        );
    }

    #[test]
    fn apply_ignores_password_plaintext_in_sqlite() {
        let (_dir, factory) = temp_repo();
        let repo = ConnectionRepository::new(&factory);
        let secret = "super-secret-import-pw";
        let plan = ImportPlan {
            nodes: vec![PlannedNode {
                id: Uuid::parse_str("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap(),
                parent_id: None,
                name: "jump".into(),
                is_folder: false,
                protocol: Some(MappedProtocol::Ssh),
                host: Some("192.0.2.10".into()),
                port: Some(22),
                username: Some("ops".into()),
                domain: None,
                sort_order: 0,
                password_plaintext: Some(secret.into()),
                password_decrypt_failed: false,
            }],
            folder_count: 0,
            connection_count: 1,
            skipped: 0,
            skipped_samples: vec![],
            warnings: vec![],
        };
        let result = apply_import_plan(&repo, &plan).expect("apply");
        assert_eq!(result.inserted, 1);
        assert!(result.stored[0].node.credential_id.is_none());
        assert!(result.stored[0].node.use_inline_password.is_none());

        let stored = repo.list_all().expect("list");
        assert_eq!(stored.len(), 1);
        let n = &stored[0].node;
        assert_ne!(n.host.as_deref(), Some(secret));
        assert_ne!(n.username.as_deref(), Some(secret));
        assert_ne!(n.name.as_str(), secret);
        assert_ne!(n.rdp_domain.as_deref(), Some(secret));
        assert!(n.credential_id.is_none());
        assert!(n.use_inline_password.is_none());
        let dbg = format!("{n:?}");
        assert!(!dbg.contains(secret), "stored node Debug must not echo password");

        let conn = factory.open().unwrap();
        let cred_rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM CredentialProfiles;", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            cred_rows, 0,
            "apply stub must not write CredentialProfiles (CredMgr still out of band)"
        );
        let use_inline: Option<i64> = conn
            .query_row("SELECT UseInlinePassword FROM Nodes LIMIT 1;", [], |r| r.get(0))
            .unwrap();
        assert!(use_inline.is_none());
    }

    #[test]
    fn apply_rolls_back_entire_batch_on_orphan_parent() {
        let (_dir, factory) = temp_repo();
        let repo = ConnectionRepository::new(&factory);
        let missing_parent = Uuid::parse_str("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb").unwrap();
        let orphan = ConnectionNode {
            id: Uuid::parse_str("cccccccc-cccc-cccc-cccc-cccccccccccc").unwrap(),
            parent_id: Some(missing_parent),
            name: "orphan".into(),
            kind: NodeKind::Connection,
            protocol: Some(ProtocolType::Ssh),
            host: Some("127.0.0.1".into()),
            port: Some(22),
            ..ConnectionNode::default()
        };
        let ok_root = ConnectionNode {
            id: Uuid::parse_str("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap(),
            name: "root".into(),
            kind: NodeKind::Folder,
            ..ConnectionNode::default()
        };
        // Second row fails FK → whole transaction must roll back (no root either).
        let err = apply_connection_nodes(&repo, &[ok_root.clone(), orphan]).unwrap_err();
        assert!(
            matches!(err, ImportError::Storage(_)),
            "expected Storage error, got {err:?}"
        );
        assert!(repo.list_all().unwrap().is_empty());
    }

    #[test]
    fn empty_plan_apply_is_noop() {
        let (_dir, factory) = temp_repo();
        let repo = ConnectionRepository::new(&factory);
        let plan = ImportPlan {
            nodes: vec![],
            folder_count: 0,
            connection_count: 0,
            skipped: 2,
            skipped_samples: vec!["a: HTTP".into(), "b: Serial".into()],
            warnings: vec![],
        };
        let result = apply_import_plan(&repo, &plan).expect("empty apply");
        assert_eq!(result.inserted, 0);
        assert_eq!(result.skipped, 2);
        assert!(repo.list_all().unwrap().is_empty());
    }

    #[test]
    fn hostile_doctype_never_reaches_apply() {
        let xml = br#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<mrng:Connections xmlns:mrng="http://mremoteng.org" ConfVersion="2.7"
 EncryptionEngine="AES" BlockCipherMode="GCM" Protected="" FullFileEncryption="false"
 KdfIterations="1000"></mrng:Connections>"#;
        let err = parse_xml_bytes(xml).expect_err("DOCTYPE must fail closed");
        assert!(
            matches!(err, ImportError::InvalidData(_) | ImportError::Xml(_)),
            "got {err:?}"
        );
    }
}
