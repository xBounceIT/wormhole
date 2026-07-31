//! Integration tests for mRemoteNG XML parse + plan (fixture has no real secrets).

use wormhole_import::{
    inspect_xml, map_protocol, parse_xml_path, plan_nodes, try_map_protocol, ImportError,
    MappedProtocol, PROTECTED_VERIFIER,
};
use wormhole_testkit::fixtures_dir;

#[test]
fn protected_verifier_constant_matches_csharp() {
    assert_eq!(PROTECTED_VERIFIER, "ThisIsProtected");
}

#[test]
fn sample_fixture_parses_and_plans_ssh_rdp_vnc() {
    let path = fixtures_dir().join("mremoteng-sample.xml");
    let info = inspect_xml(&path).expect("inspect");
    assert_eq!(info.conf_version, "2.7");
    assert_eq!(info.encryption_engine, "AES");
    assert_eq!(info.block_cipher_mode, "GCM");
    assert_eq!(info.kdf_iterations, 1000);
    assert!(!info.full_file_encryption);
    assert!(info.has_password_payloads, "cipher-ssh has a Password attr");

    let (root, nodes) = parse_xml_path(&path).expect("parse");
    assert_eq!(root.conf_version, "2.7");
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].name, "Lab");
    assert_eq!(nodes[0].type_name, "Container");
    assert_eq!(nodes[0].children.len(), 7);

    let plan = plan_nodes(&nodes, &root, "import-pw").expect("plan");
    assert_eq!(plan.folder_count, 1);
    // jump-ssh, dc-rdp, kvm-vnc, cipher-ssh, bad-cipher-ssh — HTTPS + Serial skipped
    assert_eq!(plan.connection_count, 5);
    assert_eq!(plan.skipped, 2);
    assert!(plan.skipped_samples.iter().any(|s| s.contains("HTTPS")));
    assert!(plan.skipped_samples.iter().any(|s| s.contains("Serial")));
    assert!(!plan.nodes.iter().any(|n| n.name == "appliance-https"));
    assert!(!plan.nodes.iter().any(|n| n.name == "console-serial"));

    let conns: Vec<_> = plan.nodes.iter().filter(|n| !n.is_folder).collect();
    assert_eq!(conns.len(), 5);
    assert!(conns.iter().any(|n| {
        n.name == "jump-ssh" && n.protocol == Some(MappedProtocol::Ssh) && n.port == Some(22)
    }));
    assert!(conns.iter().any(|n| {
        n.name == "dc-rdp"
            && n.protocol == Some(MappedProtocol::Rdp)
            && n.domain.as_deref() == Some("LAB")
    }));
    assert!(conns.iter().any(|n| {
        n.name == "kvm-vnc" && n.protocol == Some(MappedProtocol::Vnc) && n.username.is_none()
    }));

    let cipher = conns.iter().find(|n| n.name == "cipher-ssh").expect("cipher");
    assert!(!cipher.password_decrypt_failed);
    assert_eq!(cipher.password_plaintext.as_deref(), Some("lab-secret"));

    let bad = conns
        .iter()
        .find(|n| n.name == "bad-cipher-ssh")
        .expect("bad-cipher");
    assert!(bad.password_decrypt_failed);
    assert!(bad.password_plaintext.is_none());
    assert!(plan.warnings.iter().any(|w| w.contains("bad-cipher-ssh")));
}

#[test]
fn rejects_non_mremoteng_root() {
    let xml = br#"<?xml version="1.0"?><root/>"#;
    let err = wormhole_import::parse_xml(&xml[..]).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("mrng:Connections") || msg.contains("mRemoteNG"),
        "{msg}"
    );
}

#[test]
fn map_protocol_parity_ssh_rdp_vnc_only() {
    assert_eq!(map_protocol("SSH2"), Some(MappedProtocol::Ssh));
    assert_eq!(map_protocol("RDP"), Some(MappedProtocol::Rdp));
    assert_eq!(map_protocol("VNC"), Some(MappedProtocol::Vnc));
    for raw in ["HTTP", "HTTPS", "Serial", "Telnet", "RAW", "ICA"] {
        assert!(map_protocol(raw).is_none());
        match try_map_protocol(raw) {
            Err(ImportError::UnsupportedProtocol(label)) => assert_eq!(label, raw),
            other => panic!("expected UnsupportedProtocol for {raw}, got {other:?}"),
        }
    }
    // Soft-skip contract: gap protocols are never remapped to SSH.
    assert_ne!(map_protocol("HTTP"), Some(MappedProtocol::Ssh));
    assert_ne!(map_protocol("HTTPS"), Some(MappedProtocol::Ssh));
}

#[test]
fn sample_fixture_never_maps_https_or_serial_to_planned_protocol() {
    let path = fixtures_dir().join("mremoteng-sample.xml");
    let (root, nodes) = parse_xml_path(&path).expect("parse");
    let plan = plan_nodes(&nodes, &root, "import-pw").expect("plan");
    for n in &plan.nodes {
        assert!(
            matches!(
                n.protocol,
                None
                    | Some(MappedProtocol::Ssh)
                    | Some(MappedProtocol::Rdp)
                    | Some(MappedProtocol::Vnc)
            ),
            "fixture node '{}' must not carry Http/Https/Serial (got {:?})",
            n.name,
            n.protocol
        );
    }
}
