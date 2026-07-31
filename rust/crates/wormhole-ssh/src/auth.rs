//! SSH authentication method API (password / private key / agent / keyboard-interactive).
//!
//! Agent and keyboard-interactive are stubs that return
//! [`SshError::AuthNotImplemented`]. Availability of a local agent endpoint is
//! a separate always-on API ([`crate::is_agent_available`] /
//! [`crate::FakeAgent`]) — probing never authenticates. Connect prep wires the
//! probe into method selection via [`crate::select_auth_methods_for_connect`] /
//! [`crate::filter_ssh_auth_methods_for_connect`] (include Agent only when
//! available; probe errors fail closed). Password and private-key paths load
//! credentials and delegate to an [`SshAuthenticator`] so unit tests can use a
//! fake backend without a network.
//!
//! # Private key sources
//!
//! - [`PrivateKeySource::Bytes`] — in-memory PEM (e.g. DPAPI-decrypted payload).
//! - [`PrivateKeySource::Path`] — **caller-trusted absolute** filesystem path.
//!   Relative paths and `..` components are rejected at load time so hostile
//!   relative profile values cannot be auto-loaded via CWD / traversal.

use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use russh::keys::{self, PrivateKey, PrivateKeyWithHashAlg};

use crate::error::SshError;
use crate::Result;

/// Password credentials.
///
/// `Debug` redacts the password so logs/`:?` formatting cannot leak secrets.
#[derive(Clone)]
pub struct PasswordAuth {
    pub username: String,
    pub password: String,
}

impl fmt::Debug for PasswordAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasswordAuth")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// Where a private key comes from (file path or in-memory bytes / DPAPI payload).
///
/// # Path contract
///
/// [`PrivateKeySource::Path`] must be an **absolute** path with no `..`
/// components. Callers resolve/choose the file (file picker, known keys dir);
/// this crate does not interpret relative paths against CWD. Prefer
/// [`PrivateKeySource::bytes`] for DPAPI / in-memory material.
#[derive(Clone)]
pub enum PrivateKeySource {
    Path(PathBuf),
    Bytes(Vec<u8>),
}

impl PrivateKeySource {
    /// In-memory PEM / key bytes (DPAPI payload after decrypt, clipboard, tests).
    pub fn bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self::Bytes(bytes.into())
    }

    /// Absolute filesystem path to a private key file.
    ///
    /// Returns [`SshError::PrivateKeyLoad`] when `path` is relative or contains
    /// `..` (no auto-load of hostile relative paths).
    pub fn absolute_path(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        validate_private_key_path(&path)?;
        Ok(Self::Path(path))
    }
}

impl fmt::Debug for PrivateKeySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Path(path) => f.debug_tuple("Path").field(path).finish(),
            Self::Bytes(bytes) => f
                .debug_struct("Bytes")
                .field("len", &bytes.len())
                .finish(),
        }
    }
}

impl PartialEq for PrivateKeySource {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Path(a), Self::Path(b)) => a == b,
            (Self::Bytes(a), Self::Bytes(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for PrivateKeySource {}

/// Reject relative paths and `..` components (clear Path API contract).
pub fn validate_private_key_path(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() {
        return Err(SshError::PrivateKeyLoad(
            "private key path must not be empty".into(),
        ));
    }
    if !path.is_absolute() {
        return Err(SshError::PrivateKeyLoad(
            "private key path must be absolute (relative paths are not auto-loaded)".into(),
        ));
    }
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(SshError::PrivateKeyLoad(
            "private key path must not contain '..' components".into(),
        ));
    }
    Ok(())
}

/// Auth method selection for the SSH connect path.
///
/// Maps to C# `SshAuthMethodsBuilder` (password + private key today; agent /
/// keyboard-interactive reserved). Secrets are redacted in `Debug`.
#[derive(Clone)]
pub enum SshAuthMethod {
    Password(PasswordAuth),
    PrivateKey {
        username: String,
        source: PrivateKeySource,
        /// Passphrase to decrypt an encrypted key — never sent as a login password.
        passphrase: Option<String>,
    },
    /// SSH agent (Pageant / OpenSSH agent) — wire auth stub.
    ///
    /// Connect prep should gate this variant with
    /// [`crate::select_auth_methods_for_connect`] /
    /// [`crate::filter_ssh_auth_methods_for_connect`] (or
    /// [`crate::is_agent_available`] / [`crate::FakeAgent`]).
    /// [`authenticate_with`] still returns [`SshError::AuthNotImplemented`]
    /// until russh agent signing lands.
    Agent {
        username: String,
    },
    /// Keyboard-interactive — stub.
    KeyboardInteractive {
        username: String,
    },
}

impl fmt::Debug for SshAuthMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Password(auth) => f.debug_tuple("Password").field(auth).finish(),
            Self::PrivateKey {
                username,
                source,
                passphrase,
            } => f
                .debug_struct("PrivateKey")
                .field("username", username)
                .field("source", source)
                .field(
                    "passphrase",
                    &passphrase.as_ref().map(|_| "<redacted>"),
                )
                .finish(),
            Self::Agent { username } => {
                f.debug_struct("Agent").field("username", username).finish()
            }
            Self::KeyboardInteractive { username } => f
                .debug_struct("KeyboardInteractive")
                .field("username", username)
                .finish(),
        }
    }
}

impl From<PasswordAuth> for SshAuthMethod {
    fn from(auth: PasswordAuth) -> Self {
        Self::Password(auth)
    }
}

impl SshAuthMethod {
    /// Username carried by every variant.
    pub fn username(&self) -> &str {
        match self {
            Self::Password(auth) => &auth.username,
            Self::PrivateKey { username, .. }
            | Self::Agent { username }
            | Self::KeyboardInteractive { username } => username,
        }
    }

    /// Short label for logs / errors (never includes secrets).
    pub fn kind_label(&self) -> &'static str {
        match self {
            Self::Password(_) => "password",
            Self::PrivateKey { .. } => "private-key",
            Self::Agent { .. } => "agent",
            Self::KeyboardInteractive { .. } => "keyboard-interactive",
        }
    }
}

/// Fail closed for agent / keyboard-interactive before any network or backend call.
pub fn ensure_auth_method_supported(method: &SshAuthMethod) -> Result<()> {
    match method {
        SshAuthMethod::Agent { .. } => Err(SshError::AuthNotImplemented("agent")),
        SshAuthMethod::KeyboardInteractive { .. } => {
            Err(SshError::AuthNotImplemented("keyboard-interactive"))
        }
        SshAuthMethod::Password(_) | SshAuthMethod::PrivateKey { .. } => Ok(()),
    }
}

/// Outcome recorded by [`FakeAuthenticator`] (no secret material).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthAttempt {
    Password { username: String },
    PrivateKey {
        username: String,
        algorithm: String,
    },
}

/// Backend that performs the wire authentication step.
///
/// Production uses a russh `Handle`; tests inject [`FakeAuthenticator`].
#[async_trait]
pub trait SshAuthenticator: Send {
    async fn authenticate_password(&mut self, username: String, password: String) -> Result<()>;

    async fn authenticate_publickey(&mut self, username: String, key: PrivateKey) -> Result<()>;
}

/// In-memory authenticator for unit tests (no network).
#[derive(Debug, Default)]
pub struct FakeAuthenticator {
    pub attempts: Vec<AuthAttempt>,
    /// When set, password auth returns this instead of success.
    pub password_result: Option<Result<()>>,
    /// When set, public-key auth returns this instead of success.
    pub publickey_result: Option<Result<()>>,
}

#[async_trait]
impl SshAuthenticator for FakeAuthenticator {
    async fn authenticate_password(&mut self, username: String, password: String) -> Result<()> {
        let _ = password; // never recorded
        self.attempts.push(AuthAttempt::Password { username });
        self.password_result.take().unwrap_or(Ok(()))
    }

    async fn authenticate_publickey(&mut self, username: String, key: PrivateKey) -> Result<()> {
        self.attempts.push(AuthAttempt::PrivateKey {
            username,
            algorithm: key.algorithm().to_string(),
        });
        self.publickey_result.take().unwrap_or(Ok(()))
    }
}

/// Strip passphrase from an error string when present (defense in depth).
fn sanitize_key_load_message(message: String, passphrase: Option<&str>) -> String {
    match passphrase {
        Some(pp) if !pp.is_empty() && message.contains(pp) => message.replace(pp, "<redacted>"),
        _ => message,
    }
}

fn private_key_load_err(message: String, passphrase: Option<&str>) -> SshError {
    SshError::PrivateKeyLoad(sanitize_key_load_message(message, passphrase))
}

/// Load a russh [`PrivateKey`] from path or bytes. Errors never include the passphrase.
pub fn load_private_key(
    source: &PrivateKeySource,
    passphrase: Option<&str>,
) -> Result<PrivateKey> {
    match source {
        PrivateKeySource::Path(path) => {
            validate_private_key_path(path)?;
            keys::load_secret_key(path, passphrase).map_err(|e| {
                private_key_load_err(format!("{}: {e}", path.display()), passphrase)
            })
        }
        PrivateKeySource::Bytes(bytes) => {
            let pem = std::str::from_utf8(bytes).map_err(|_| {
                SshError::PrivateKeyLoad("private key bytes are not valid UTF-8".into())
            })?;
            keys::decode_secret_key(pem, passphrase)
                .map_err(|e| private_key_load_err(e.to_string(), passphrase))
        }
    }
}

/// Dispatch [`SshAuthMethod`] against an authenticator.
///
/// Agent / keyboard-interactive return [`SshError::AuthNotImplemented`] without
/// calling the backend. Private-key material is loaded first (testable offline).
pub async fn authenticate_with<A: SshAuthenticator>(
    authenticator: &mut A,
    method: SshAuthMethod,
) -> Result<()> {
    ensure_auth_method_supported(&method)?;
    match method {
        SshAuthMethod::Password(mut auth) => {
            let username = std::mem::take(&mut auth.username);
            let password = std::mem::take(&mut auth.password);
            authenticator
                .authenticate_password(username, password)
                .await
        }
        SshAuthMethod::PrivateKey {
            mut username,
            source,
            passphrase,
        } => {
            let username = std::mem::take(&mut username);
            let key = load_private_key(&source, passphrase.as_deref())?;
            // Drop passphrase ASAP after load.
            drop(passphrase);
            authenticator.authenticate_publickey(username, key).await
        }
        // Defensive: keep fail-closed even if ensure_auth_method_supported drifts.
        SshAuthMethod::Agent { .. } => Err(SshError::AuthNotImplemented("agent")),
        SshAuthMethod::KeyboardInteractive { .. } => {
            Err(SshError::AuthNotImplemented("keyboard-interactive"))
        }
    }
}

/// Map a russh auth-path error without embedding password/passphrase material.
fn auth_transport_error(kind: &'static str, err: russh::Error) -> SshError {
    // Protocol/I/O detail only — never interpolate caller secrets.
    SshError::Other(format!("SSH {kind} authentication error: {err}"))
}

/// Russh `Handle` adapter used by the live connect path.
pub struct RusshAuthenticator<'a, H: russh::client::Handler> {
    handle: &'a mut russh::client::Handle<H>,
}

impl<'a, H: russh::client::Handler> RusshAuthenticator<'a, H> {
    pub fn new(handle: &'a mut russh::client::Handle<H>) -> Self {
        Self { handle }
    }
}

#[async_trait]
impl<H> SshAuthenticator for RusshAuthenticator<'_, H>
where
    H: russh::client::Handler + Send,
{
    async fn authenticate_password(&mut self, username: String, password: String) -> Result<()> {
        let auth_result = self
            .handle
            .authenticate_password(username, password)
            .await
            .map_err(|e| auth_transport_error("password", e))?;
        if !auth_result.success() {
            return Err(SshError::AuthFailed);
        }
        Ok(())
    }

    async fn authenticate_publickey(&mut self, username: String, key: PrivateKey) -> Result<()> {
        let hash_alg = self
            .handle
            .best_supported_rsa_hash()
            .await
            .map_err(|e| auth_transport_error("publickey", e))?
            .flatten();
        let key = PrivateKeyWithHashAlg::new(Arc::new(key), hash_alg);
        let auth_result = self
            .handle
            .authenticate_publickey(username, key)
            .await
            .map_err(|e| auth_transport_error("publickey", e))?;
        if !auth_result.success() {
            return Err(SshError::AuthFailed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unencrypted OpenSSH ed25519 fixture (generated offline; no network).
    const ED25519_OPENSSH: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBbFUbVHA/aTwRyN1jZxGQ6MCo8XxxDCMFXs7R2RB3KZQAAAJDihAl14oQJ
dQAAAAtzc2gtZWQyNTUxOQAAACBbFUbVHA/aTwRyN1jZxGQ6MCo8XxxDCMFXs7R2RB3KZQ
AAAEAdtf+WxkId7Llsly+dMZc7ReP7dOPqCK3QmfMv1KONx1sVRtUcD9pPBHI3WNnEZDow
KjxfHEMIwVeztHZEHcplAAAADXRlc3RAd29ybWhvbGU=
-----END OPENSSH PRIVATE KEY-----
";

    /// Encrypted OpenSSH ed25519 (passphrase `test-key-passphrase-NOT-FOR-PROD`).
    const ED25519_ENCRYPTED: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABDgAZEpeA
yMMAD69qMqlVuXAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIBxlKVeTh1T5WspT
JccKJZE6kzC8eWo2cRbXEy+hAsgJAAAAoBRx7V3HousgGpQlIKNvO6STutsqOK29slya8P
cspW0XNyJN2MObvdqesA7PTe2FthyWxjLkcsOqXCaAIAt9BjloeL7SZg7ncFSxwRFmOJR5
3oVm9f9yCNJIWOZ6ndtMaHnvaS4RFpXLjBbU87mQwcR4jDTQUW7+hNsFizE0tXOP2IwMtT
YnFdca2279Hz5wjekqcBS8uvS3ncKjrBINj8M=
-----END OPENSSH PRIVATE KEY-----
";

    const ENCRYPTED_PASSPHRASE: &str = "wrong-pass-LEAKCHECK-42";

    #[test]
    fn password_debug_is_redacted() {
        let auth = PasswordAuth {
            username: "alice".into(),
            password: "s3cret-value".into(),
        };
        let rendered = format!("{auth:?}");
        assert!(rendered.contains("alice"));
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("s3cret-value"));
    }

    #[test]
    fn auth_method_debug_redacts_secrets() {
        let method = SshAuthMethod::PrivateKey {
            username: "bob".into(),
            source: PrivateKeySource::Bytes(b"-----BEGIN SECRET-----".to_vec()),
            passphrase: Some("key-pass".into()),
        };
        let rendered = format!("{method:?}");
        assert!(rendered.contains("bob"));
        assert!(rendered.contains("len"));
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("key-pass"));
        assert!(!rendered.contains("BEGIN SECRET"));
    }

    #[test]
    fn auth_error_display_has_no_password() {
        let err = SshError::AuthFailed;
        assert_eq!(err.to_string(), "authentication failed");
        let stub = SshError::AuthNotImplemented("agent");
        assert!(!stub.to_string().contains("password"));
    }

    #[tokio::test]
    async fn fake_password_auth_succeeds_without_network() {
        let mut fake = FakeAuthenticator::default();
        authenticate_with(
            &mut fake,
            SshAuthMethod::Password(PasswordAuth {
                username: "alice".into(),
                password: "pw".into(),
            }),
        )
        .await
        .unwrap();
        assert_eq!(
            fake.attempts,
            vec![AuthAttempt::Password {
                username: "alice".into()
            }]
        );
        // Password must never appear in recorded attempts / Debug.
        let dbg = format!("{fake:?}");
        assert!(!dbg.contains("pw"));
    }

    #[tokio::test]
    async fn fake_password_auth_maps_failure() {
        let mut fake = FakeAuthenticator {
            password_result: Some(Err(SshError::AuthFailed)),
            ..Default::default()
        };
        let err = authenticate_with(
            &mut fake,
            SshAuthMethod::Password(PasswordAuth {
                username: "alice".into(),
                password: "bad".into(),
            }),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, SshError::AuthFailed));
    }

    #[tokio::test]
    async fn agent_stub_is_not_implemented() {
        let mut fake = FakeAuthenticator::default();
        let err = authenticate_with(
            &mut fake,
            SshAuthMethod::Agent {
                username: "alice".into(),
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(err, SshError::AuthNotImplemented("agent")));
        assert!(fake.attempts.is_empty());
    }

    #[tokio::test]
    async fn keyboard_interactive_stub_is_not_implemented() {
        let mut fake = FakeAuthenticator::default();
        let err = authenticate_with(
            &mut fake,
            SshAuthMethod::KeyboardInteractive {
                username: "alice".into(),
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            SshError::AuthNotImplemented("keyboard-interactive")
        ));
        assert!(fake.attempts.is_empty());
    }

    #[test]
    fn ensure_auth_method_supported_fail_closed() {
        assert!(ensure_auth_method_supported(&SshAuthMethod::Password(
            PasswordAuth {
                username: "u".into(),
                password: "p".into(),
            }
        ))
        .is_ok());
        assert!(matches!(
            ensure_auth_method_supported(&SshAuthMethod::Agent {
                username: "u".into()
            }),
            Err(SshError::AuthNotImplemented("agent"))
        ));
        assert!(matches!(
            ensure_auth_method_supported(&SshAuthMethod::KeyboardInteractive {
                username: "u".into()
            }),
            Err(SshError::AuthNotImplemented("keyboard-interactive"))
        ));
    }

    #[tokio::test]
    async fn private_key_bytes_load_and_fake_auth() {
        let mut fake = FakeAuthenticator::default();
        authenticate_with(
            &mut fake,
            SshAuthMethod::PrivateKey {
                username: "carol".into(),
                source: PrivateKeySource::bytes(ED25519_OPENSSH.as_bytes()),
                passphrase: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            fake.attempts,
            vec![AuthAttempt::PrivateKey {
                username: "carol".into(),
                algorithm: "ssh-ed25519".into(),
            }]
        );
    }

    #[tokio::test]
    async fn private_key_path_load_and_fake_auth() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("id_ed25519");
        std::fs::write(&path, ED25519_OPENSSH).unwrap();
        // tempfile paths are absolute; use the fallible constructor contract.
        let source = PrivateKeySource::absolute_path(&path).unwrap();

        let mut fake = FakeAuthenticator::default();
        authenticate_with(
            &mut fake,
            SshAuthMethod::PrivateKey {
                username: "dave".into(),
                source,
                passphrase: None,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            &fake.attempts[0],
            AuthAttempt::PrivateKey { username, algorithm }
                if username == "dave" && algorithm == "ssh-ed25519"
        ));
    }

    #[test]
    fn private_key_path_missing_file_errors_without_passphrase_leak() {
        let path = if cfg!(windows) {
            PathBuf::from("C:\\nonexistent\\wormhole-ssh-no-such-key")
        } else {
            PathBuf::from("/nonexistent/wormhole-ssh-no-such-key")
        };
        let err = load_private_key(
            &PrivateKeySource::Path(path),
            Some("super-secret-passphrase"),
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(!msg.contains("super-secret-passphrase"));
        assert!(matches!(err, SshError::PrivateKeyLoad(_)));
    }

    #[test]
    fn relative_private_key_path_rejected() {
        let err = load_private_key(
            &PrivateKeySource::Path(PathBuf::from("..\\hostile\\id_rsa")),
            Some("pp-should-not-leak"),
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("absolute"));
        assert!(!msg.contains("pp-should-not-leak"));
        assert!(PrivateKeySource::absolute_path("relative/id_rsa").is_err());
    }

    #[test]
    fn parent_dir_component_in_absolute_path_rejected() {
        let path = if cfg!(windows) {
            PathBuf::from("C:\\Users\\..\\Windows\\id_rsa")
        } else {
            PathBuf::from("/tmp/../etc/id_rsa")
        };
        let err = validate_private_key_path(&path).unwrap_err();
        assert!(err.to_string().contains(".."));
    }

    #[test]
    fn encrypted_key_loads_with_passphrase_and_wrong_passphrase_does_not_leak() {
        load_private_key(
            &PrivateKeySource::bytes(ED25519_ENCRYPTED.as_bytes()),
            Some(ENCRYPTED_PASSPHRASE),
        )
        .expect("fixture decrypts with known passphrase");

        let wrong = load_private_key(
            &PrivateKeySource::bytes(ED25519_ENCRYPTED.as_bytes()),
            Some("definitely-wrong-passphrase-XYZ"),
        )
        .unwrap_err();
        let msg = wrong.to_string();
        assert!(!msg.contains("definitely-wrong-passphrase-XYZ"));
        assert!(!msg.contains(ENCRYPTED_PASSPHRASE));
        assert!(matches!(wrong, SshError::PrivateKeyLoad(_)));
    }

    #[test]
    fn sanitize_strips_passphrase_substring() {
        let msg = sanitize_key_load_message(
            "failed with passphrase=hunter2 nested".into(),
            Some("hunter2"),
        );
        assert_eq!(msg, "failed with passphrase=<redacted> nested");
    }

    #[test]
    fn kind_label_covers_all_variants() {
        assert_eq!(
            SshAuthMethod::Password(PasswordAuth {
                username: String::new(),
                password: String::new(),
            })
            .kind_label(),
            "password"
        );
        assert_eq!(
            SshAuthMethod::Agent {
                username: "u".into()
            }
            .kind_label(),
            "agent"
        );
        assert_eq!(
            SshAuthMethod::KeyboardInteractive {
                username: "u".into()
            }
            .kind_label(),
            "keyboard-interactive"
        );
        assert_eq!(
            SshAuthMethod::PrivateKey {
                username: "u".into(),
                source: PrivateKeySource::Bytes(vec![]),
                passphrase: None,
            }
            .kind_label(),
            "private-key"
        );
    }
}
