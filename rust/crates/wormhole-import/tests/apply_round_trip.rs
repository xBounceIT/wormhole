//! Integration: mini mRemoteNG XML → plan → SQLite apply round-trip (SSH/RDP/VNC).

use tempfile::TempDir;
use wormhole_import::{apply_import_plan, parse_xml_bytes, plan_nodes, MappedProtocol};
use wormhole_storage::{
    ConnectionRepository, MigrationRunner, NodeKind, ProtocolType, SqliteConnectionFactory,
};

fn temp_repo() -> (TempDir, SqliteConnectionFactory) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("wormhole.db");
    let factory = SqliteConnectionFactory::new(&path);
    MigrationRunner::embedded().run(&factory).expect("migrate");
    (dir, factory)
}

#[test]
fn mini_xml_plan_apply_db_round_trip_ssh_rdp_vnc() {
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
    <Node Name="skip-https" Type="Connection" Protocol="HTTPS"
          Hostname="192.0.2.42" Port="443" Username="" Password="" />
    <Node Name="skip-serial" Type="Connection" Protocol="Serial"
          Hostname="COM4" Port="" Username="" Password="" />
  </Node>
</mrng:Connections>"#;

    let (root, raw) = parse_xml_bytes(xml).expect("parse");
    let plan = plan_nodes(&raw, &root, "").expect("plan");
    assert_eq!(plan.folder_count, 1);
    assert_eq!(plan.connection_count, 3);
    assert_eq!(plan.skipped, 2);
    assert!(plan.nodes.iter().any(|n| {
        n.name == "jump-ssh" && n.protocol == Some(MappedProtocol::Ssh)
    }));
    assert!(plan.nodes.iter().any(|n| {
        n.name == "dc-rdp" && n.protocol == Some(MappedProtocol::Rdp)
    }));
    assert!(plan.nodes.iter().any(|n| {
        n.name == "desk-vnc" && n.protocol == Some(MappedProtocol::Vnc)
    }));

    let (_dir, factory) = temp_repo();
    let repo = ConnectionRepository::new(&factory);
    let applied = apply_import_plan(&repo, &plan).expect("apply");
    assert_eq!(applied.inserted, 4);
    assert_eq!(applied.skipped, 2);

    let folders = repo.list_folders().expect("folders");
    assert_eq!(folders.len(), 1);
    assert_eq!(folders[0].node.kind, NodeKind::Folder);
    assert_eq!(folders[0].node.name, "Lab");

    let conns = repo.list_connections().expect("conns");
    assert_eq!(conns.len(), 3);

    let ssh = conns
        .iter()
        .find(|n| n.node.name == "jump-ssh")
        .expect("ssh row");
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
        .expect("rdp row");
    assert_eq!(rdp.node.protocol, Some(ProtocolType::Rdp));
    assert_eq!(rdp.node.host.as_deref(), Some("192.0.2.20"));
    assert_eq!(rdp.node.port, Some(3389));
    assert_eq!(rdp.node.rdp_domain.as_deref(), Some("LAB"));
    assert_eq!(rdp.node.parent_id, Some(folders[0].node.id));

    let vnc = conns
        .iter()
        .find(|n| n.node.name == "desk-vnc")
        .expect("vnc row");
    assert_eq!(vnc.node.protocol, Some(ProtocolType::Vnc));
    assert_eq!(vnc.node.host.as_deref(), Some("192.0.2.30"));
    assert_eq!(vnc.node.port, Some(5900));
    assert!(vnc.node.username.is_none());

    let all = repo.list_all().expect("all");
    assert!(!all.iter().any(|n| n.node.name == "skip-https" || n.node.name == "skip-serial"));
    assert!(!all.iter().any(|n| {
        matches!(
            n.node.protocol,
            Some(ProtocolType::Http | ProtocolType::Https | ProtocolType::Serial)
        )
    }));
}
