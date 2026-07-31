//! Helpers: GUID D format, sentinels, serial/RDP normalizers (no secrets).

use uuid::Uuid;
use wormhole_domain::{
    format_guid_d, CredentialBindingSentinelIds, RdpScreenSizes, SerialDefaults,
    SerialFlowControlMode, SerialParityMode, SerialStopBitsMode,
};

#[test]
fn format_guid_d_matches_dotnet_lowercase_d() {
    let id = Uuid::parse_str("A1B2C3D4-E5F6-7890-ABCD-EF1234567890").unwrap();
    assert_eq!(format_guid_d(&id), "a1b2c3d4-e5f6-7890-abcd-ef1234567890");
}

#[test]
fn credential_binding_sentinel_ids_match_csharp() {
    assert_eq!(
        CredentialBindingSentinelIds::INHERIT.to_string(),
        "00000000-0000-0000-0000-000000000001"
    );
    assert_eq!(
        CredentialBindingSentinelIds::CONNECTION_NONE.to_string(),
        "00000000-0000-0000-0000-000000000000"
    );
    assert_eq!(
        CredentialBindingSentinelIds::FOLDER_NONE.to_string(),
        "ffffffff-ffff-ffff-ffff-fffffffffffe"
    );
    assert!(CredentialBindingSentinelIds::is_sentinel(
        CredentialBindingSentinelIds::INHERIT
    ));
    assert!(CredentialBindingSentinelIds::is_sentinel(
        CredentialBindingSentinelIds::CONNECTION_NONE
    ));
    assert!(CredentialBindingSentinelIds::is_sentinel(
        CredentialBindingSentinelIds::FOLDER_NONE
    ));
    assert!(!CredentialBindingSentinelIds::is_sentinel(Uuid::new_v4()));
}

#[test]
fn serial_defaults_normalize_edges() {
    assert_eq!(SerialDefaults::normalize_baud_rate(None), 9600);
    assert_eq!(SerialDefaults::normalize_baud_rate(Some(0)), 9600);
    assert_eq!(SerialDefaults::normalize_baud_rate(Some(-1)), 9600);
    assert_eq!(SerialDefaults::normalize_baud_rate(Some(115200)), 115200);
    assert_eq!(SerialDefaults::normalize_data_bits(Some(4)), 8);
    assert_eq!(SerialDefaults::normalize_data_bits(Some(9)), 8);
    assert_eq!(SerialDefaults::normalize_data_bits(Some(7)), 7);
    assert_eq!(
        SerialDefaults::normalize_stop_bits(None),
        SerialStopBitsMode::One
    );
    assert_eq!(
        SerialDefaults::normalize_stop_bits(Some(SerialStopBitsMode::Two)),
        SerialStopBitsMode::Two
    );
    assert_eq!(
        SerialDefaults::normalize_parity(Some(SerialParityMode::Mark)),
        SerialParityMode::Mark
    );
    assert_eq!(
        SerialDefaults::normalize_flow_control(Some(SerialFlowControlMode::XonXoff)),
        SerialFlowControlMode::XonXoff
    );
}

#[test]
fn rdp_screen_sizes_recognize_dynamic_aliases() {
    assert!(RdpScreenSizes::is_full_connection_content(None));
    assert!(RdpScreenSizes::is_full_connection_content(Some("")));
    assert!(RdpScreenSizes::is_full_connection_content(Some(
        RdpScreenSizes::FULL_CONNECTION_CONTENT
    )));
    assert!(RdpScreenSizes::is_full_connection_content(Some(
        RdpScreenSizes::LEGACY_FULL_SCREEN_SENTINEL
    )));
    assert!(RdpScreenSizes::is_full_connection_content(Some(
        RdpScreenSizes::M_REMOTE_NG_FIT_TO_WINDOW_SENTINEL
    )));
    assert!(!RdpScreenSizes::is_full_connection_content(Some("1024x768")));
    assert_eq!(
        RdpScreenSizes::normalize_for_picker(Some("Full screen")).as_deref(),
        Some(RdpScreenSizes::FULL_CONNECTION_CONTENT)
    );
    assert_eq!(RdpScreenSizes::normalize_for_picker(Some("  ")), None);
}
