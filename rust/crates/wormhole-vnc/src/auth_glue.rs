//! VNC password-only auth glue stub.
//!
//! Thin Lab stub (no GPUI / no live RFB), mirroring C#
//! `PasswordProviderAuthenticationHandler` + editor visibility:
//! - Negotiated security → **no-auth** vs **classic VNC password**
//! - Username / domain from connection materials are **ignored** (C# hides
//!   username for VNC; domain is RDP-only — `ShowConnectionUsername` /
//!   `ShowRdpDomain`)
//! - Server request for username+password (`CredentialsAuthenticationInput`)
//!   → [`VncError::UnsupportedCredentialsAuth`] (fail-closed)
//! - Missing / empty password when VncAuth required →
//!   [`VncError::PasswordRequired`] (fail-closed)
//! - Provider cancel (`None`) → [`VncError::AuthCancelled`]
//! - [`VncAuthFields`] / [`FakeVncPasswordProvider`] `Debug` redacts passwords
//!
//! Live RFB challenge/response remains deferred behind feature `engine`.

use std::cell::Cell;
use std::fmt;

use crate::auth::{resolve_auth, VncAuthMethod, VncPassword};
use crate::protocol::RfbSecurityType;
use crate::VncError;

/// Which authentication input the RFB stack is asking for.
///
/// Mirrors the C# `ProvideAuthenticationInputAsync<TInput>` branch on
/// `PasswordAuthenticationInput` vs `CredentialsAuthenticationInput`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VncAuthInputKind {
    /// No credentials (security type None).
    None,
    /// Classic VNC password challenge (`PasswordAuthenticationInput`).
    Password,
    /// Username + password (MS Logon / etc.) — unsupported in Wormhole v1.
    Credentials,
}

impl VncAuthInputKind {
    /// Map a negotiated security type to the input the client must supply.
    pub fn from_security(security: RfbSecurityType) -> Self {
        match VncAuthMethod::from_security(security) {
            VncAuthMethod::None => Self::None,
            VncAuthMethod::Password => Self::Password,
        }
    }
}

/// Connection-side credential fields presented to VNC auth glue.
///
/// Username and domain may be present on a shared editor model; for VNC they
/// are **ignored** (not sent on the wire). Only [`Self::password`] participates
/// when classic VncAuth is selected.
#[derive(Clone, PartialEq, Eq)]
pub struct VncAuthFields {
    /// Ignored for VNC v1 (editor hides the username box).
    pub username: Option<String>,
    /// Ignored for VNC v1 (domain is RDP-only in the editor).
    pub domain: Option<String>,
    /// Classic VNC password when the server negotiates VncAuth.
    pub password: Option<VncPassword>,
}

impl VncAuthFields {
    pub fn new() -> Self {
        Self {
            username: None,
            domain: None,
            password: None,
        }
    }

    pub fn with_password(mut self, password: VncPassword) -> Self {
        self.password = Some(password);
        self
    }

    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self
    }

    /// Username/domain never affect auth selection (parity pin for tests).
    pub fn username_ignored(&self) -> bool {
        true
    }

    /// See [`Self::username_ignored`].
    pub fn domain_ignored(&self) -> bool {
        true
    }
}

impl Default for VncAuthFields {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for VncAuthFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VncAuthFields")
            .field("username_present", &self.username.is_some())
            .field("domain_present", &self.domain.is_some())
            // VncPassword Debug is already redacted; keep explicit for auditability.
            .field("password", &self.password)
            .finish()
    }
}

/// Result of selecting / resolving VNC auth for a negotiated security type.
#[derive(Clone, PartialEq, Eq)]
pub struct VncAuthSelection {
    pub method: VncAuthMethod,
    /// Present only when [`VncAuthMethod::Password`]; never logged via Debug.
    pub password: Option<VncPassword>,
}

impl fmt::Debug for VncAuthSelection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VncAuthSelection")
            .field("method", &self.method)
            .field("password", &self.password)
            .finish()
    }
}

/// Password source for classic VncAuth (mirrors C# `IVncPasswordProvider`).
///
/// `Ok(None)` means the user cancelled — mapped to [`VncError::AuthCancelled`].
/// Empty string passwords fail closed as [`VncError::PasswordRequired`].
pub trait VncPasswordProvider {
    fn get_password(&self) -> Result<Option<VncPassword>, VncError>;
}

/// In-memory password provider for offline unit tests (no UI / CredMgr).
#[derive(Clone)]
pub struct FakeVncPasswordProvider {
    /// Scripted password; `None` = cancel.
    password: Option<VncPassword>,
    /// Optional hard error (fail-closed path).
    error: Option<VncError>,
    calls: Cell<usize>,
}

impl FakeVncPasswordProvider {
    pub fn with_password(password: VncPassword) -> Self {
        Self {
            password: Some(password),
            error: None,
            calls: Cell::new(0),
        }
    }

    /// User cancelled the password prompt (`Ok(None)` → AuthCancelled).
    pub fn cancelled() -> Self {
        Self {
            password: None,
            error: None,
            calls: Cell::new(0),
        }
    }

    /// Empty password material (fail-closed as PasswordRequired when used).
    pub fn empty_password() -> Self {
        Self {
            password: Some(VncPassword::new("").expect("empty password is under 8 bytes")),
            error: None,
            calls: Cell::new(0),
        }
    }

    pub fn failing(error: VncError) -> Self {
        Self {
            password: None,
            error: Some(error),
            calls: Cell::new(0),
        }
    }

    pub fn call_count(&self) -> usize {
        self.calls.get()
    }
}

impl fmt::Debug for FakeVncPasswordProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeVncPasswordProvider")
            .field("password", &self.password)
            .field("error", &self.error)
            .field("calls", &self.calls.get())
            .finish()
    }
}

impl VncPasswordProvider for FakeVncPasswordProvider {
    fn get_password(&self) -> Result<Option<VncPassword>, VncError> {
        self.calls.set(self.calls.get().saturating_add(1));
        if let Some(err) = self.error.clone() {
            return Err(err);
        }
        Ok(self.password.clone())
    }
}

/// Select no-auth vs password from negotiated security + static fields.
///
/// Username / domain on `fields` are ignored. Empty password when VncAuth is
/// required fails closed ([`VncError::PasswordRequired`]).
pub fn select_vnc_auth(
    security: RfbSecurityType,
    fields: &VncAuthFields,
) -> Result<VncAuthSelection, VncError> {
    let _ = (fields.username.as_ref(), fields.domain.as_ref()); // explicitly unused
    let method = resolve_auth(security, fields.password.as_ref())?;
    Ok(VncAuthSelection {
        method,
        password: match method {
            VncAuthMethod::None => None,
            VncAuthMethod::Password => fields.password.clone(),
        },
    })
}

/// Provide auth input the way C# `PasswordProviderAuthenticationHandler` does.
///
/// - [`VncAuthInputKind::None`] → no provider call
/// - [`VncAuthInputKind::Password`] → provider; cancel / empty fail closed
/// - [`VncAuthInputKind::Credentials`] → [`VncError::UnsupportedCredentialsAuth`]
pub fn provide_vnc_auth_input(
    kind: VncAuthInputKind,
    provider: &dyn VncPasswordProvider,
) -> Result<VncAuthSelection, VncError> {
    match kind {
        VncAuthInputKind::None => Ok(VncAuthSelection {
            method: VncAuthMethod::None,
            password: None,
        }),
        VncAuthInputKind::Credentials => Err(VncError::UnsupportedCredentialsAuth),
        VncAuthInputKind::Password => {
            let password = provider.get_password()?.ok_or(VncError::AuthCancelled)?;
            // Empty / missing stay one contract via resolve_auth (PasswordRequired).
            let method = resolve_auth(RfbSecurityType::VncAuth, Some(&password))?;
            Ok(VncAuthSelection {
                method,
                password: Some(password),
            })
        }
    }
}

/// Convenience: map security → input kind, then [`provide_vnc_auth_input`].
pub fn resolve_vnc_auth_from_provider(
    security: RfbSecurityType,
    provider: &dyn VncPasswordProvider,
) -> Result<VncAuthSelection, VncError> {
    provide_vnc_auth_input(VncAuthInputKind::from_security(security), provider)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_no_auth_ignores_username_domain_and_password() {
        let fields = VncAuthFields::new()
            .with_username("alice")
            .with_domain("CORP")
            .with_password(VncPassword::new("secret").unwrap());
        assert!(fields.username_ignored());
        assert!(fields.domain_ignored());

        let selected = select_vnc_auth(RfbSecurityType::None, &fields).unwrap();
        assert_eq!(selected.method, VncAuthMethod::None);
        assert!(selected.password.is_none());
    }

    #[test]
    fn select_no_auth_allows_empty_password_and_strips_it() {
        // Empty only fails closed when VncAuth is required — None negotiation keeps going.
        let fields = VncAuthFields::new().with_password(VncPassword::new("").unwrap());
        let selected = select_vnc_auth(RfbSecurityType::None, &fields).unwrap();
        assert_eq!(selected.method, VncAuthMethod::None);
        assert!(selected.password.is_none());
    }

    #[test]
    fn select_password_auth_uses_password_ignores_username_domain() {
        let fields = VncAuthFields::new()
            .with_username("alice")
            .with_domain("CORP")
            .with_password(VncPassword::new("secret").unwrap());
        let selected = select_vnc_auth(RfbSecurityType::VncAuth, &fields).unwrap();
        assert_eq!(selected.method, VncAuthMethod::Password);
        assert_eq!(selected.password.as_ref().map(VncPassword::as_str), Some("secret"));
    }

    #[test]
    fn select_password_auth_fail_closed_when_missing() {
        let fields = VncAuthFields::new().with_username("alice");
        assert_eq!(
            select_vnc_auth(RfbSecurityType::VncAuth, &fields),
            Err(VncError::PasswordRequired)
        );
    }

    #[test]
    fn select_password_auth_fail_closed_when_empty() {
        let fields =
            VncAuthFields::new().with_password(VncPassword::new("").unwrap());
        assert_eq!(
            select_vnc_auth(RfbSecurityType::VncAuth, &fields),
            Err(VncError::PasswordRequired)
        );
    }

    #[test]
    fn provide_password_from_fake() {
        let fake = FakeVncPasswordProvider::with_password(VncPassword::new("pw").unwrap());
        let selected =
            provide_vnc_auth_input(VncAuthInputKind::Password, &fake).unwrap();
        assert_eq!(selected.method, VncAuthMethod::Password);
        assert_eq!(selected.password.unwrap().as_str(), "pw");
        assert_eq!(fake.call_count(), 1);
    }

    #[test]
    fn provide_password_cancel_is_auth_cancelled() {
        let fake = FakeVncPasswordProvider::cancelled();
        assert_eq!(
            provide_vnc_auth_input(VncAuthInputKind::Password, &fake),
            Err(VncError::AuthCancelled)
        );
        assert_eq!(fake.call_count(), 1);
    }

    #[test]
    fn provide_empty_password_fail_closed() {
        let fake = FakeVncPasswordProvider::empty_password();
        assert_eq!(
            provide_vnc_auth_input(VncAuthInputKind::Password, &fake),
            Err(VncError::PasswordRequired)
        );
        assert_eq!(fake.call_count(), 1);
    }

    #[test]
    fn provide_propagates_provider_hard_error() {
        let fake = FakeVncPasswordProvider::failing(VncError::Message("provider failed".into()));
        assert_eq!(
            provide_vnc_auth_input(VncAuthInputKind::Password, &fake),
            Err(VncError::Message("provider failed".into()))
        );
        assert_eq!(fake.call_count(), 1);
    }

    #[test]
    fn provide_accepts_exact_eight_byte_password() {
        let pw = VncPassword::new("12345678").unwrap();
        let fake = FakeVncPasswordProvider::with_password(pw);
        let selected = provide_vnc_auth_input(VncAuthInputKind::Password, &fake).unwrap();
        assert_eq!(selected.method, VncAuthMethod::Password);
        assert_eq!(selected.password.as_ref().map(VncPassword::as_str), Some("12345678"));
    }

    #[test]
    fn auth_errors_display_without_secrets() {
        let secret = "sekrit!!";
        for err in [
            VncError::PasswordRequired,
            VncError::AuthCancelled,
            VncError::UnsupportedCredentialsAuth,
        ] {
            let display = err.to_string();
            assert!(!display.is_empty());
            assert!(!display.contains(secret));
            assert!(!display.contains("password="));
        }
        // Hard Message path must not silently swallow — Display is the message body.
        let msg = VncError::Message("provider failed".into());
        assert_eq!(msg.to_string(), "provider failed");
        assert!(!msg.to_string().contains(secret));
    }

    #[test]
    fn credentials_input_unsupported() {
        let fake = FakeVncPasswordProvider::with_password(VncPassword::new("pw").unwrap());
        assert_eq!(
            provide_vnc_auth_input(VncAuthInputKind::Credentials, &fake),
            Err(VncError::UnsupportedCredentialsAuth)
        );
        // Must not consult the provider for unsupported input.
        assert_eq!(fake.call_count(), 0);
    }

    #[test]
    fn none_input_skips_provider() {
        let fake = FakeVncPasswordProvider::with_password(VncPassword::new("pw").unwrap());
        let selected = provide_vnc_auth_input(VncAuthInputKind::None, &fake).unwrap();
        assert_eq!(selected.method, VncAuthMethod::None);
        assert!(selected.password.is_none());
        assert_eq!(fake.call_count(), 0);
    }

    #[test]
    fn resolve_from_provider_maps_security() {
        let fake = FakeVncPasswordProvider::with_password(VncPassword::new("x").unwrap());
        assert_eq!(
            resolve_vnc_auth_from_provider(RfbSecurityType::None, &fake)
                .unwrap()
                .method,
            VncAuthMethod::None
        );
        assert_eq!(fake.call_count(), 0);
        assert_eq!(
            resolve_vnc_auth_from_provider(RfbSecurityType::VncAuth, &fake)
                .unwrap()
                .method,
            VncAuthMethod::Password
        );
        assert_eq!(fake.call_count(), 1);
    }

    #[test]
    fn resolve_from_provider_fail_closed_on_cancel_and_empty() {
        let cancelled = FakeVncPasswordProvider::cancelled();
        assert_eq!(
            resolve_vnc_auth_from_provider(RfbSecurityType::VncAuth, &cancelled),
            Err(VncError::AuthCancelled)
        );
        assert_eq!(cancelled.call_count(), 1);

        let empty = FakeVncPasswordProvider::empty_password();
        assert_eq!(
            resolve_vnc_auth_from_provider(RfbSecurityType::VncAuth, &empty),
            Err(VncError::PasswordRequired)
        );
        assert_eq!(empty.call_count(), 1);

        // None security never consults the provider even when it would cancel/empty.
        let unused = FakeVncPasswordProvider::cancelled();
        assert_eq!(
            resolve_vnc_auth_from_provider(RfbSecurityType::None, &unused)
                .unwrap()
                .method,
            VncAuthMethod::None
        );
        assert_eq!(unused.call_count(), 0);
    }

    #[test]
    fn debug_redacts_password_on_fields_selection_and_fake() {
        let secret = "sekrit!!";
        let fields = VncAuthFields::new()
            .with_username("alice")
            .with_domain("CORP\\unique-domain-token")
            .with_password(VncPassword::new(secret).unwrap());
        let fields_dbg = format!("{fields:?}");
        assert!(fields_dbg.contains("VncPassword(***)"));
        assert!(!fields_dbg.contains(secret));
        assert!(!fields_dbg.contains("alice")); // presence only
        assert!(!fields_dbg.contains("CORP\\unique-domain-token"));
        assert!(fields_dbg.contains("username_present: true"));
        assert!(fields_dbg.contains("domain_present: true"));

        let selected = select_vnc_auth(RfbSecurityType::VncAuth, &fields).unwrap();
        let sel_dbg = format!("{selected:?}");
        assert!(sel_dbg.contains("VncPassword(***)"));
        assert!(!sel_dbg.contains(secret));
        // Selection carries method + password only — never username/domain.
        assert!(!sel_dbg.contains("alice"));
        assert!(!sel_dbg.contains("CORP"));

        let fake = FakeVncPasswordProvider::with_password(VncPassword::new(secret).unwrap());
        let fake_dbg = format!("{fake:?}");
        assert!(fake_dbg.contains("VncPassword(***)"));
        assert!(!fake_dbg.contains(secret));
    }

    #[test]
    fn input_kind_from_security() {
        assert_eq!(
            VncAuthInputKind::from_security(RfbSecurityType::None),
            VncAuthInputKind::None
        );
        assert_eq!(
            VncAuthInputKind::from_security(RfbSecurityType::VncAuth),
            VncAuthInputKind::Password
        );
    }

    #[test]
    fn input_kind_tracks_auth_method_from_security() {
        // Glue input kind and core method mapping must stay aligned for every
        // RfbSecurityType Wormhole v1 accepts.
        for security in [RfbSecurityType::None, RfbSecurityType::VncAuth] {
            let kind = VncAuthInputKind::from_security(security);
            let method = VncAuthMethod::from_security(security);
            match (kind, method) {
                (VncAuthInputKind::None, VncAuthMethod::None) => {}
                (VncAuthInputKind::Password, VncAuthMethod::Password) => {}
                (VncAuthInputKind::Credentials, _) => {
                    panic!("from_security must never yield Credentials")
                }
                (k, m) => panic!("mismatched kind/method for {security:?}: {k:?} vs {m:?}"),
            }
        }
    }
}
