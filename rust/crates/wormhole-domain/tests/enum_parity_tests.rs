//! Discriminant parity with C# / SQLite + TryFrom round-trips.

use wormhole_domain::{
    CredentialBindingMode, CredentialKind, CredentialSecretProvider, NodeKind, ProtocolType,
    SerialFlowControlMode, SerialParityMode, SerialStopBitsMode, TunnelKind,
    BITWARDEN_PASSWORD_FIELD_PATH,
};

#[test]
fn protocol_type_discriminants_match_csharp() {
    assert_eq!(ProtocolType::Ssh.as_i32(), 0);
    assert_eq!(ProtocolType::Rdp.as_i32(), 1);
    assert_eq!(ProtocolType::Http.as_i32(), 3);
    assert_eq!(ProtocolType::Https.as_i32(), 4);
    assert_eq!(ProtocolType::Serial.as_i32(), 5);
    assert_eq!(ProtocolType::Vnc.as_i32(), 6);
    assert!(ProtocolType::try_from(2).is_err(), "retired SFTP must stay rejected");
    for v in [0, 1, 3, 4, 5, 6] {
        let parsed = ProtocolType::try_from(v).unwrap();
        assert_eq!(parsed.as_i32(), v);
    }
}

#[test]
fn node_kind_and_credential_mode_discriminants_match_csharp() {
    assert_eq!(NodeKind::Folder.as_i32(), 0);
    assert_eq!(NodeKind::Connection.as_i32(), 1);
    assert_eq!(CredentialBindingMode::Inherit.as_i32(), 0);
    assert_eq!(CredentialBindingMode::None.as_i32(), 1);
    assert_eq!(CredentialBindingMode::Saved.as_i32(), 2);
    assert_eq!(CredentialKind::Password.as_i32(), 0);
    assert_eq!(CredentialKind::SshKey.as_i32(), 1);
    assert_eq!(CredentialSecretProvider::Local.as_i32(), 0);
    assert_eq!(CredentialSecretProvider::Bitwarden.as_i32(), 1);
    assert_eq!(BITWARDEN_PASSWORD_FIELD_PATH, "login.password");
    assert!(NodeKind::try_from(2).is_err());
    assert!(CredentialBindingMode::try_from(3).is_err());
    assert!(CredentialKind::try_from(2).is_err());
    assert!(CredentialSecretProvider::try_from(2).is_err());
}

#[test]
fn serial_and_tunnel_kind_discriminants_match_csharp() {
    assert_eq!(SerialParityMode::None.as_i32(), 0);
    assert_eq!(SerialParityMode::Space.as_i32(), 4);
    assert_eq!(SerialStopBitsMode::One.as_i32(), 1);
    assert_eq!(SerialStopBitsMode::OnePointFive.as_i32(), 3);
    assert_eq!(SerialFlowControlMode::None.as_i32(), 0);
    assert_eq!(SerialFlowControlMode::DsrDtr.as_i32(), 3);
    assert_eq!(TunnelKind::WireGuard.as_i32(), 0);
    assert_eq!(TunnelKind::CiscoSecureClient.as_i32(), 6);
    assert!(SerialStopBitsMode::try_from(0).is_err());
    assert!(TunnelKind::try_from(7).is_err());
}
