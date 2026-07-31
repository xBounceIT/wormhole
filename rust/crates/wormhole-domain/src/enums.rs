use std::fmt;

use uuid::Uuid;

use crate::error::InvalidEnumValue;

/// Mirrors `Wormhole.Models.ProtocolType`. Numeric values must match C# / SQLite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum ProtocolType {
    Ssh = 0,
    Rdp = 1,
    // Value 2 was retired SFTP — deliberately skipped.
    Http = 3,
    Https = 4,
    Serial = 5,
    Vnc = 6,
}

impl ProtocolType {
    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}

impl TryFrom<i32> for ProtocolType {
    type Error = InvalidEnumValue;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Ssh),
            1 => Ok(Self::Rdp),
            3 => Ok(Self::Http),
            4 => Ok(Self::Https),
            5 => Ok(Self::Serial),
            6 => Ok(Self::Vnc),
            _ => Err(InvalidEnumValue {
                enum_name: "ProtocolType",
                value,
            }),
        }
    }
}

impl fmt::Display for ProtocolType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Ssh => "Ssh",
            Self::Rdp => "Rdp",
            Self::Http => "Http",
            Self::Https => "Https",
            Self::Serial => "Serial",
            Self::Vnc => "Vnc",
        })
    }
}

/// Mirrors `Wormhole.Models.NodeKind` (Folder = 0, Connection = 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum NodeKind {
    Folder = 0,
    Connection = 1,
}

impl NodeKind {
    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}

impl TryFrom<i32> for NodeKind {
    type Error = InvalidEnumValue;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Folder),
            1 => Ok(Self::Connection),
            _ => Err(InvalidEnumValue {
                enum_name: "NodeKind",
                value,
            }),
        }
    }
}

impl fmt::Display for NodeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Folder => "Folder",
            Self::Connection => "Connection",
        })
    }
}

/// Mirrors `Wormhole.Models.CredentialBindingMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum CredentialBindingMode {
    Inherit = 0,
    None = 1,
    Saved = 2,
}

impl CredentialBindingMode {
    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}

impl TryFrom<i32> for CredentialBindingMode {
    type Error = InvalidEnumValue;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Inherit),
            1 => Ok(Self::None),
            2 => Ok(Self::Saved),
            _ => Err(InvalidEnumValue {
                enum_name: "CredentialBindingMode",
                value,
            }),
        }
    }
}

impl fmt::Display for CredentialBindingMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Inherit => "Inherit",
            Self::None => "None",
            Self::Saved => "Saved",
        })
    }
}

/// Sentinel GUIDs used by credential pickers (`CredentialBindingSentinelIds` in C#).
pub struct CredentialBindingSentinelIds;

impl CredentialBindingSentinelIds {
    pub const INHERIT: Uuid = Uuid::from_bytes([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ]);
    pub const CONNECTION_NONE: Uuid = Uuid::nil();
    pub const FOLDER_NONE: Uuid = Uuid::from_bytes([
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe,
    ]);

    pub fn is_sentinel(id: Uuid) -> bool {
        id == Self::INHERIT || id == Self::CONNECTION_NONE || id == Self::FOLDER_NONE
    }
}

/// Mirrors `Wormhole.Models.CredentialKind` (Password = 0, SshKey = 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum CredentialKind {
    Password = 0,
    SshKey = 1,
}

impl CredentialKind {
    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}

impl TryFrom<i32> for CredentialKind {
    type Error = InvalidEnumValue;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Password),
            1 => Ok(Self::SshKey),
            _ => Err(InvalidEnumValue {
                enum_name: "CredentialKind",
                value,
            }),
        }
    }
}

impl fmt::Display for CredentialKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Password => "Password",
            Self::SshKey => "SshKey",
        })
    }
}

/// Mirrors `Wormhole.Models.CredentialSecretProvider` (Local = 0, Bitwarden = 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum CredentialSecretProvider {
    Local = 0,
    Bitwarden = 1,
}

impl CredentialSecretProvider {
    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}

impl TryFrom<i32> for CredentialSecretProvider {
    type Error = InvalidEnumValue;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Local),
            1 => Ok(Self::Bitwarden),
            _ => Err(InvalidEnumValue {
                enum_name: "CredentialSecretProvider",
                value,
            }),
        }
    }
}

impl fmt::Display for CredentialSecretProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Local => "Local",
            Self::Bitwarden => "Bitwarden",
        })
    }
}

/// Default Bitwarden field path (`Wormhole.Models.BitwardenDefaults.PasswordFieldPath`).
pub const BITWARDEN_PASSWORD_FIELD_PATH: &str = "login.password";

/// Mirrors `Wormhole.Models.SerialParityMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum SerialParityMode {
    None = 0,
    Odd = 1,
    Even = 2,
    Mark = 3,
    Space = 4,
}

impl SerialParityMode {
    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}

impl TryFrom<i32> for SerialParityMode {
    type Error = InvalidEnumValue;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Odd),
            2 => Ok(Self::Even),
            3 => Ok(Self::Mark),
            4 => Ok(Self::Space),
            _ => Err(InvalidEnumValue {
                enum_name: "SerialParityMode",
                value,
            }),
        }
    }
}

/// Mirrors `Wormhole.Models.SerialStopBitsMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum SerialStopBitsMode {
    One = 1,
    Two = 2,
    OnePointFive = 3,
}

impl SerialStopBitsMode {
    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}

impl TryFrom<i32> for SerialStopBitsMode {
    type Error = InvalidEnumValue;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::One),
            2 => Ok(Self::Two),
            3 => Ok(Self::OnePointFive),
            _ => Err(InvalidEnumValue {
                enum_name: "SerialStopBitsMode",
                value,
            }),
        }
    }
}

/// Mirrors `Wormhole.Models.SerialFlowControlMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum SerialFlowControlMode {
    None = 0,
    XonXoff = 1,
    RtsCts = 2,
    DsrDtr = 3,
}

impl SerialFlowControlMode {
    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}

impl TryFrom<i32> for SerialFlowControlMode {
    type Error = InvalidEnumValue;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::XonXoff),
            2 => Ok(Self::RtsCts),
            3 => Ok(Self::DsrDtr),
            _ => Err(InvalidEnumValue {
                enum_name: "SerialFlowControlMode",
                value,
            }),
        }
    }
}

/// Mirrors `Wormhole.Models.TunnelKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum TunnelKind {
    WireGuard = 0,
    OpenVpn = 1,
    Fortinet = 2,
    Watchguard = 3,
    Stormshield = 4,
    AzureVpn = 5,
    CiscoSecureClient = 6,
}

impl TunnelKind {
    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}

impl TryFrom<i32> for TunnelKind {
    type Error = InvalidEnumValue;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::WireGuard),
            1 => Ok(Self::OpenVpn),
            2 => Ok(Self::Fortinet),
            3 => Ok(Self::Watchguard),
            4 => Ok(Self::Stormshield),
            5 => Ok(Self::AzureVpn),
            6 => Ok(Self::CiscoSecureClient),
            _ => Err(InvalidEnumValue {
                enum_name: "TunnelKind",
                value,
            }),
        }
    }
}

impl fmt::Display for TunnelKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::WireGuard => "WireGuard",
            Self::OpenVpn => "OpenVpn",
            Self::Fortinet => "Fortinet",
            Self::Watchguard => "Watchguard",
            Self::Stormshield => "Stormshield",
            Self::AzureVpn => "AzureVpn",
            Self::CiscoSecureClient => "CiscoSecureClient",
        })
    }
}
