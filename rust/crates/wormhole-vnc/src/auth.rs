use std::fmt;

use crate::protocol::RfbSecurityType;
use crate::VncError;

/// Classic VNC passwords are DES-truncated to 8 **bytes** (RFC 6143).
pub const MAX_VNC_PASSWORD_BYTES: usize = 8;
/// Historical alias — same as [`MAX_VNC_PASSWORD_BYTES`].
pub const MAX_VNC_PASSWORD_CHARS: usize = MAX_VNC_PASSWORD_BYTES;

/// Auth method Wormhole v1 supports (mirrors C# `PasswordProviderAuthenticationHandler`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VncAuthMethod {
    /// Security type None — no credentials.
    None,
    /// Classic VNC Authentication (security type 2).
    Password,
}

impl VncAuthMethod {
    pub fn from_security(security: RfbSecurityType) -> Self {
        match security {
            RfbSecurityType::None => Self::None,
            RfbSecurityType::VncAuth => Self::Password,
        }
    }

    pub fn requires_password(self) -> bool {
        matches!(self, Self::Password)
    }
}

/// Classic VNC password (redacted in `Debug`; never implements `Display`).
#[derive(Clone, PartialEq, Eq)]
pub struct VncPassword(String);

impl VncPassword {
    pub fn new(password: impl Into<String>) -> Result<Self, VncError> {
        let password = password.into();
        // RFC 6143: DES key is 8 bytes. Reject by UTF-8 byte length (not Unicode scalars).
        if password.len() > MAX_VNC_PASSWORD_BYTES {
            return Err(VncError::PasswordTooLong(MAX_VNC_PASSWORD_BYTES));
        }
        Ok(Self(password))
    }

    /// Truncate to 8 bytes the way many VNC servers/clients do.
    pub fn from_lossy(password: impl Into<String>) -> Self {
        let s = password.into();
        let mut end = s.len().min(MAX_VNC_PASSWORD_BYTES);
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        Self(s[..end].to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Debug for VncPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VncPassword(***)")
    }
}

/// True when a password can satisfy classic VncAuth (non-empty).
///
/// Empty passwords fail closed as [`VncError::PasswordRequired`] — same contract
/// as [`crate::auth_glue`].
pub fn password_is_usable(password: &VncPassword) -> bool {
    !password.as_str().is_empty()
}

/// Resolve credentials for a negotiated security type.
///
/// Missing **or empty** password when VncAuth is required → [`VncError::PasswordRequired`].
pub fn resolve_auth(
    security: RfbSecurityType,
    password: Option<&VncPassword>,
) -> Result<VncAuthMethod, VncError> {
    let method = VncAuthMethod::from_security(security);
    if method.requires_password() {
        match password {
            Some(p) if password_is_usable(p) => {}
            _ => return Err(VncError::PasswordRequired),
        }
    }
    Ok(method)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_redacted_in_debug() {
        let p = VncPassword::new("secret").unwrap();
        assert_eq!(format!("{p:?}"), "VncPassword(***)");
        assert!(!format!("{p:?}").contains("secret"));
    }

    #[test]
    fn password_rejects_over_eight_bytes() {
        assert!(VncPassword::new("123456789").is_err());
        assert!(VncPassword::new("12345678").is_ok());
        // UTF-8: three emoji are 12 bytes (< 8 Unicode scalars) — still rejected.
        assert!(VncPassword::new("😀😀😀").is_err());
        // "café" is 5 bytes; +4 ASCII → 9 bytes → reject; +3 → 8 bytes → ok.
        assert!(VncPassword::new("café!!!!").is_err());
        assert!(VncPassword::new("café!!!").is_ok());
    }

    #[test]
    fn from_lossy_truncates_on_byte_boundary() {
        let p = VncPassword::from_lossy("1234567890");
        assert_eq!(p.as_str(), "12345678");
        let emoji = VncPassword::from_lossy("😀😀😀");
        assert!(emoji.as_bytes().len() <= MAX_VNC_PASSWORD_BYTES);
        // Truncation must land on a char boundary (valid UTF-8).
        assert!(std::str::from_utf8(emoji.as_bytes()).is_ok());
    }

    #[test]
    fn resolve_requires_password_for_vnc_auth() {
        assert!(resolve_auth(RfbSecurityType::VncAuth, None).is_err());
        let p = VncPassword::new("x").unwrap();
        assert_eq!(
            resolve_auth(RfbSecurityType::VncAuth, Some(&p)).unwrap(),
            VncAuthMethod::Password
        );
        assert_eq!(
            resolve_auth(RfbSecurityType::None, None).unwrap(),
            VncAuthMethod::None
        );
        // Password present but None negotiated — still OK (password unused).
        assert_eq!(
            resolve_auth(RfbSecurityType::None, Some(&p)).unwrap(),
            VncAuthMethod::None
        );
    }

    #[test]
    fn resolve_rejects_empty_password_for_vnc_auth() {
        let empty = VncPassword::new("").unwrap();
        assert!(!password_is_usable(&empty));
        assert_eq!(
            resolve_auth(RfbSecurityType::VncAuth, Some(&empty)),
            Err(VncError::PasswordRequired)
        );
        // Empty password is fine when no-auth was negotiated (unused).
        assert_eq!(
            resolve_auth(RfbSecurityType::None, Some(&empty)).unwrap(),
            VncAuthMethod::None
        );
    }
}
