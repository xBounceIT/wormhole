//! SSH full password resolver + Bitwarden unlock-prompt glue — Fake-first.
//!
//! Mirrors `Services/Ssh/SshCredentialResolver.cs` **password path** plus the
//! unlock semantics of `Services/CredentialPasswordResolver.cs` /
//! `Services/Bitwarden/*` and the Bitwarden unlock prompt
//! (`IDialogService.PromptBitwardenUnlockAsync`), restricted to login-password
//! resolution (SSH **private-key / passphrase** resolution is out of scope).
//!
//! Resolution order (C# `SshCredentialResolver.ResolveAsync`):
//!
//! 1. **Inline** per-node (leaf-only, `use_inline_password && !is_ephemeral`) —
//!    read [`PasswordStore`] keyed by `node_id`; inline suppresses a saved
//!    credential (C# editor forces `CredentialId == null` when inline is on).
//! 2. **Saved local** credential — read [`PasswordStore`] keyed by `credential.id`.
//! 3. **Bitwarden** vault password ([`BitwardenVaultPasswordSource`]) — with the
//!    injected [`UnlockPromptUi`] seam: a **locked** vault prompts once; a
//!    successful unlock retries the resolution once; Cancel / prompt error
//!    aborts with a fail-closed error (C# `BitwardenUnlockCancelledException`
//!    escapes `SshCredentialResolver`).
//!
//! | Condition | [`SshPasswordResolution`] |
//! |---|---|
//! | inline stored, non-empty | `Resolved` (inline) |
//! | inline not stored | `PromptRequired` (C# falls to the account-password prompt) |
//! | inline stored but empty / whitespace | **error** `EmptyPassword` (fail-closed — C# would prompt; Rust treats a stored-blank as anomalous) |
//! | no inline and no `credential_id` / no saved credential / credential protocol ≠ SSH | `PromptRequired` |
//! | saved credential kind = SSH key | **error** `SshKeyCredential` (key path out of scope — never silently degrade to password auth) |
//! | saved-local stored, non-empty | `Resolved` (saved local) |
//! | saved-local not stored | `PromptRequired` |
//! | saved-local stored but empty / whitespace | **error** `EmptyPassword` |
//! | Bitwarden vault disabled / item id missing / field path unsupported / item missing / password blank | `PromptRequired` (C# `BitwardenVaultException` → account-password prompt) |
//! | Bitwarden password stored but empty / whitespace | **error** `EmptyPassword` |
//! | Bitwarden vault locked, no unlock UI | `PromptRequired` (C# null `unlockPrompt` → locked-vault exception → prompt) |
//! | Bitwarden vault locked, unlock prompt **Canceled** | **error** `UnlockCanceled` (C# abort) |
//! | Bitwarden vault locked, unlock prompt / unlock **Failed** | **error** `UnlockPromptFailed` (fail-closed abort) |
//! | Bitwarden vault locked, unlock **Unlocked** | retry resolution once; then table rows above |
//! | unlock succeeds but vault still reports locked on retry | **error** `Resolve(VaultLocked)` (no infinite retry) |
//!
//! "PromptRequired" is the **explicit** "C# would show the interactive
//! account-password dialog here" outcome — never a silent empty password: a host
//! that declines to show the prompt must abort. Every stored-but-empty secret
//! fails closed to an error (parity deviation, detailed in the module header of
//! [`SshPasswordError`]).
//!
//! **Never** log passwords / master passwords / session keys. The resolved
//! password is wrapped in [`SshPasswordValue`] whose `Debug`/`Display` expose
//! length only; [`Debug`] on the glue is counts + session status.
//!
//! Ephemeral / transient-store resolution (C# transient Quick Connect branch)
//! stays a host concern via [`crate::TransientSessionCredentialStore`] — this
//! glue handles stored sources only.

use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};

use uuid::Uuid;
use wormhole_domain::{
    CredentialKind, CredentialSecretProvider, ProtocolType, BITWARDEN_PASSWORD_FIELD_PATH,
};

use crate::bitwarden_credential_catalog::BitwardenCatalogProfile;
use crate::bitwarden_session::{BitwardenSession, BitwardenSessionStatus};
use crate::credential_password_resolver::{
    BitwardenVaultPasswordSource, CredentialPasswordError,
};
use crate::cred_mgr::PasswordStore;

/// Inputs for an SSH password resolution (host derives from a
/// `wormhole_domain::ConnectionProfile` + credential-catalog lookup).
///
/// `use_inline_password` / `is_ephemeral` map from
/// `ConnectionProfile.UseInlinePassword` / `IsEphemeral`; `credential` maps from
/// `ICredentialCredentialCatalog.GetByIdAsync(profile.CredentialId)` (C# does the
/// lookup inside `SshCredentialResolver`; here the host supplies the resolved
/// metadata so this glue stays free of catalog I/O).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshPasswordRequest {
    /// Leaf node id — inline per-node secrets are keyed by it in [`PasswordStore`].
    pub node_id: Uuid,
    /// C# `ConnectionProfile.UseInlinePassword` (leaf-only flag).
    pub use_inline_password: bool,
    /// C# `ConnectionProfile.IsEphemeral` — ephemeral nodes never use inline or saved.
    pub is_ephemeral: bool,
    /// Resolved saved credential metadata (C# `GetByIdAsync` result), if bound.
    pub credential: Option<BitwardenCatalogProfile>,
}

impl SshPasswordRequest {
    /// Construct a resolution request.
    pub fn new(
        node_id: Uuid,
        use_inline_password: bool,
        is_ephemeral: bool,
        credential: Option<BitwardenCatalogProfile>,
    ) -> Self {
        Self {
            node_id,
            use_inline_password,
            is_ephemeral,
            credential,
        }
    }
}

/// Which stored source produced a resolved SSH password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshPasswordSource {
    /// Inline per-node password (keyed by `node_id`).
    Inline,
    /// Saved local credential password (keyed by `credential.id`).
    SavedLocal,
    /// Linked Bitwarden vault login password.
    SavedBitwarden,
}

/// Resolved SSH login password, `SecretString`-style.
///
/// `Debug` / `Display` never print the value — length only. Use
/// [`expose`](Self::expose) to hand the value to a session; never log it.
#[derive(Clone, PartialEq, Eq)]
pub struct SshPasswordValue {
    value: String,
}

impl fmt::Debug for SshPasswordValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SshPasswordValue")
            .field("len", &self.value.len())
            .finish()
    }
}

impl fmt::Display for SshPasswordValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[redacted SSH password; len={}]", self.value.len())
    }
}

impl SshPasswordValue {
    /// Wrap a password value (test dummies only — never log the input).
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
        }
    }

    /// Borrow the raw password. **Never** log the return value.
    pub fn expose(&self) -> &str {
        &self.value
    }

    /// UTF-8 byte length (safe to log / assert).
    pub fn len(&self) -> usize {
        self.value.len()
    }

    /// Whether the held value is blank (empty / whitespace).
    pub fn is_empty(&self) -> bool {
        self.value.trim().is_empty()
    }
}

/// Outcome of an SSH password resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshPasswordResolution {
    /// A stored, non-empty login password was resolved.
    Resolved {
        /// The resolved password (`Debug` is length-only).
        value: SshPasswordValue,
        /// Which stored source won (for C#-order parity tests / host logging).
        source: SshPasswordSource,
    },
    /// No stored secret across the applicable sources; C# `SshCredentialResolver`
    /// would show the interactive account-password dialog here. **Explicit** —
    /// never a silent empty value; a host that declines to prompt must abort.
    PromptRequired,
}

/// Errors from SSH password resolution (never carry passwords).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SshPasswordError {
    /// Saved credential is an SSH **key**; key/passphrase resolution is out of
    /// password scope — the host must not degrade to a password prompt silently.
    #[error("SSH credential is an SSH key; resolve the private-key path instead")]
    SshKeyCredential,
    /// Bitwarden vault unlock prompt was canceled (C# `BitwardenUnlockCancelledException`
    /// escapes `SshCredentialResolver.ResolveAsync` — an abort, not a prompt).
    #[error("Bitwarden vault unlock was canceled")]
    UnlockCanceled,
    /// Bitwarden vault unlock prompt / unlock attempt failed (wrong master
    /// password, prompt error, abandoned channel) — abort fail-closed.
    #[error("Bitwarden vault unlock failed")]
    UnlockPromptFailed,
    /// Lower-level saved-credential / vault resolution error. See
    /// [`CredentialPasswordError`]: `EmptyPassword` (stored-but-blank fail-closed),
    /// `LocalRead`, `VaultLocked` (hostile session after a claimed unlock), etc.
    #[error(transparent)]
    Resolve(#[from] CredentialPasswordError),
}

/// Choice an unlock prompt can return.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockPromptChoice {
    /// The user submitted a master password and `session.unlock` succeeded; the
    /// vault now holds a session key (resolution may be retried once).
    Unlocked,
    /// The user dismissed the prompt (C# null session key → abort).
    Canceled,
    /// The prompt / unlock attempt failed (wrong password, UI error) — abort.
    Failed,
}

/// Injectable Bitwarden vault unlock prompt (C# `IDialogService.PromptBitwardenUnlockAsync`).
///
/// The UI calls [`BitwardenSession::unlock`] itself with the entered master
/// password (C# passes the unlock op into the dialog) and reports the outcome.
/// Implementations must **never** retain or log the master password.
pub trait UnlockPromptUi: Send + Sync {
    /// Show the unlock prompt, submit the entered master password to `session`,
    /// and return the resulting [`UnlockPromptChoice`].
    fn prompt_unlock(&self, session: &dyn BitwardenSession) -> UnlockPromptChoice;
}

/// Scripted [Bitwarden vault `unlock`] outcome for unit tests (no `bw` process).
///
/// [`FakeUnlockPromptScript::Submit`] drives the real [`BitwardenSession::unlock`] call
/// (so a scripted "Unlocked" actually transitions the fake session), then mirrors
/// the result; `master` is a **test dummy** — never real vault material.
/// [`Debug`] redacts held master values (module invariant: never echo via Debug).
#[derive(Clone, PartialEq, Eq)]
pub enum FakeUnlockPromptScript {
    /// Submit `master` to `session.unlock` and report its outcome.
    Submit(String),
    /// User dismissed the prompt.
    Cancel,
    /// Prompt / unlock failed (wrong password, UI error).
    Fail,
}

impl fmt::Debug for FakeUnlockPromptScript {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Submit(_) => f.write_str("Submit([REDACTED])"),
            Self::Cancel => f.write_str("Cancel"),
            Self::Fail => f.write_str("Fail"),
        }
    }
}

/// Scripted unlock prompt for unit tests.
///
/// Each [`prompt_unlock`](Self::prompt_unlock) dequeues one scripted outcome; an
/// exhausted script → [`FakeUnlockPromptScript::Cancel`] (fail-closed). [`Debug`]
/// redacts submitted master values.
pub struct FakeUnlockPromptUi {
    script: Mutex<VecDeque<FakeUnlockPromptScript>>,
    prompt_calls: AtomicUsize,
}

impl Default for FakeUnlockPromptUi {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for FakeUnlockPromptUi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let script = self.script.lock().unwrap_or_else(|p| p.into_inner());
        let kinds: Vec<&str> = script
            .iter()
            .map(|s| match s {
                FakeUnlockPromptScript::Submit(_) => "Submit([REDACTED])",
                FakeUnlockPromptScript::Cancel => "Cancel",
                FakeUnlockPromptScript::Fail => "Fail",
            })
            .collect();
        f.debug_struct("FakeUnlockPromptUi")
            .field("script", &kinds)
            .field("prompt_calls", &self.prompt_calls.load(Ordering::SeqCst))
            .finish()
    }
}

impl FakeUnlockPromptUi {
    fn script_guard(&self) -> std::sync::MutexGuard<'_, VecDeque<FakeUnlockPromptScript>> {
        self.script.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Empty script (every prompt cancels, fail-closed).
    pub fn new() -> Self {
        Self {
            script: Mutex::new(VecDeque::new()),
            prompt_calls: AtomicUsize::new(0),
        }
    }

    /// Prompt that always submits `master` to the session and mirrors the result.
    pub fn with_submit(master: impl Into<String>) -> Self {
        let mut ui = Self::new();
        ui.push_submit(master);
        ui
    }

    /// Prompt that always cancels.
    pub fn with_cancel() -> Self {
        let mut ui = Self::new();
        ui.push(FakeUnlockPromptScript::Cancel);
        ui
    }

    /// Prompt that always reports failure.
    pub fn with_fail() -> Self {
        let mut ui = Self::new();
        ui.push(FakeUnlockPromptScript::Fail);
        ui
    }

    /// Queue a submit script entry (test dummy master only).
    pub fn push_submit(&mut self, master: impl Into<String>) {
        self.push(FakeUnlockPromptScript::Submit(master.into()));
    }

    /// Queue a scripted outcome.
    pub fn push(&mut self, script: FakeUnlockPromptScript) {
        self.script_guard().push_back(script);
    }

    /// How many times [`UnlockPromptUi::prompt_unlock`] ran.
    pub fn prompt_calls(&self) -> usize {
        self.prompt_calls.load(Ordering::SeqCst)
    }
}

impl UnlockPromptUi for FakeUnlockPromptUi {
    fn prompt_unlock(&self, session: &dyn BitwardenSession) -> UnlockPromptChoice {
        self.prompt_calls.fetch_add(1, Ordering::SeqCst);
        match self.script_guard().pop_front() {
            Some(FakeUnlockPromptScript::Submit(master)) => {
                let result = session.unlock(&master);
                if result.unlocked {
                    UnlockPromptChoice::Unlocked
                } else {
                    UnlockPromptChoice::Failed
                }
            }
            Some(FakeUnlockPromptScript::Cancel) | None => UnlockPromptChoice::Canceled,
            Some(FakeUnlockPromptScript::Fail) => UnlockPromptChoice::Failed,
        }
    }
}

/// Response a pending unlock prompt can receive (master password crosses the
/// in-process channel only — never log it). [`Debug`] redacts the master value
/// (module invariant: no Debug oracle for `Submitted { master }`).
#[derive(Clone, PartialEq, Eq)]
pub enum UnlockPromptResponse {
    /// The UI captured a master password and is asking the caller to unlock.
    Submitted {
        /// Vault master password (secret — never log / retain).
        master: String,
    },
    /// The user dismissed the prompt.
    Canceled,
}

impl fmt::Debug for UnlockPromptResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Submitted { .. } => f.write_str("Submitted([REDACTED])"),
            Self::Canceled => f.write_str("Canceled"),
        }
    }
}

/// A pending unlock prompt awaiting a UI response.
///
/// UI side receives it then calls [`submit`](Self::submit) /
/// [`cancel`](Self::cancel). Dropping unanswered → the unlock prompt reports
/// [`UnlockPromptChoice::Canceled`] (fail-closed, mirroring a user dismissing
/// the dialog — C# closes the prompt with no password).
pub struct PendingUnlockPrompt {
    respond: mpsc::Sender<UnlockPromptResponse>,
}

impl PendingUnlockPrompt {
    /// Submit a master password (never log). `false` if the requester abandoned.
    pub fn submit(self, master: impl Into<String>) -> bool {
        self.respond
            .send(UnlockPromptResponse::Submitted {
                master: master.into(),
            })
            .is_ok()
    }

    /// Cancel the unlock prompt.
    pub fn cancel(self) -> bool {
        self.respond.send(UnlockPromptResponse::Canceled).is_ok()
    }
}

/// Channel-backed unlock prompt (mirrors the `OtpPromptChannel` shape with
/// `std::sync::mpsc`). `prompt_unlock` sends a [`PendingUnlockPrompt`] and blocks
/// for the UI's response, then drives [`BitwardenSession::unlock`]. Abandoning /
/// dropping the pending queue fails closed.
pub struct ChannelUnlockPromptUi {
    tx: mpsc::Sender<PendingUnlockPrompt>,
}

impl fmt::Debug for ChannelUnlockPromptUi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChannelUnlockPromptUi")
            .field("tx", &"<mpsc>")
            .finish_non_exhaustive()
    }
}

impl UnlockPromptUi for ChannelUnlockPromptUi {
    fn prompt_unlock(&self, session: &dyn BitwardenSession) -> UnlockPromptChoice {
        let (respond_tx, respond_rx) = mpsc::channel();
        let pending = PendingUnlockPrompt { respond: respond_tx };
        if self.tx.send(pending).is_err() {
            // Receiver abandoned → fail closed.
            return UnlockPromptChoice::Failed;
        }
        match respond_rx.recv() {
            Ok(UnlockPromptResponse::Submitted { master }) => {
                let result = session.unlock(&master);
                if result.unlocked {
                    UnlockPromptChoice::Unlocked
                } else {
                    UnlockPromptChoice::Failed
                }
            }
            Ok(UnlockPromptResponse::Canceled) | Err(_) => UnlockPromptChoice::Canceled,
        }
    }
}

impl UnlockPromptUi for Arc<ChannelUnlockPromptUi> {
    fn prompt_unlock(&self, session: &dyn BitwardenSession) -> UnlockPromptChoice {
        self.as_ref().prompt_unlock(session)
    }
}

/// Open provider-facing [`ChannelUnlockPromptUi`] + the UI-facing pending queue.
///
/// Join pattern (mirrors `OtpPromptChannel` / `HelloConsentChannel`): `shared()`
/// goes to the glue, the UI drains `pending_rx` / [`PendingUnlockPrompt::submit`]
/// / [`PendingUnlockPrompt::cancel`].
pub struct UnlockPromptChannel {
    shared: Arc<ChannelUnlockPromptUi>,
    pending_rx: mpsc::Receiver<PendingUnlockPrompt>,
}

impl fmt::Debug for UnlockPromptChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnlockPromptChannel")
            .field("pending_rx", &"<mpsc>")
            .finish()
    }
}

impl UnlockPromptChannel {
    /// Create a channel-backed unlock prompt and arm the UI listener.
    pub fn open() -> Self {
        let (tx, pending_rx) = mpsc::channel();
        Self {
            shared: Arc::new(ChannelUnlockPromptUi { tx }),
            pending_rx,
        }
    }

    /// Shared unlock handle (implements [`UnlockPromptUi`]).
    pub fn shared(&self) -> Arc<ChannelUnlockPromptUi> {
        Arc::clone(&self.shared)
    }

    /// UI-facing pending queue (one [`PendingUnlockPrompt`] per prompt).
    pub fn pending_rx(&mut self) -> &mut mpsc::Receiver<PendingUnlockPrompt> {
        &mut self.pending_rx
    }

    /// Detach the shared handle while keeping the receiver.
    pub fn into_parts(
        self,
    ) -> (
        Arc<ChannelUnlockPromptUi>,
        mpsc::Receiver<PendingUnlockPrompt>,
    ) {
        (self.shared, self.pending_rx)
    }
}

/// SSH full password resolver: inline → saved local → Bitwarden vault (C# order).
///
/// Composes [`PasswordStore`] (inline by `node_id` + saved-local by `credential.id`),
/// [`BitwardenSession`], [`BitwardenVaultPasswordSource`], and the optional
/// [`UnlockPromptUi`]. Fail-closed table in the module header.
pub struct SshPasswordResolverGlue<P, S, V, U>
where
    P: PasswordStore,
    S: BitwardenSession,
    V: BitwardenVaultPasswordSource,
    U: UnlockPromptUi,
{
    local: P,
    session: S,
    vault: V,
    unlock_ui: Option<U>,
    vault_enabled: bool,
    resolve_calls: AtomicUsize,
    unlock_prompt_calls: AtomicUsize,
}

impl<P, S, V, U> fmt::Debug for SshPasswordResolverGlue<P, S, V, U>
where
    P: PasswordStore + Send + Sync,
    S: BitwardenSession,
    V: BitwardenVaultPasswordSource,
    U: UnlockPromptUi,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Counts + session status only; stores / vault / UI script internals are
        // never dumped (they may hold secret material).
        f.debug_struct("SshPasswordResolverGlue")
            .field("vault_enabled", &self.vault_enabled)
            .field("session_status", &self.session.status())
            .field("unlock_ui_present", &self.unlock_ui.is_some())
            .field("resolve_calls", &self.resolve_calls.load(Ordering::SeqCst))
            .field(
                "unlock_prompt_calls",
                &self.unlock_prompt_calls.load(Ordering::SeqCst),
            )
            .finish()
    }
}

impl<P, S, V, U> SshPasswordResolverGlue<P, S, V, U>
where
    P: PasswordStore + Send + Sync,
    S: BitwardenSession,
    V: BitwardenVaultPasswordSource,
    U: UnlockPromptUi,
{
    /// Construct with injectable store, session, vault Fake, optional unlock
    /// prompt UI, and the `EnableBitwardenVault` settings flag.
    ///
    /// `unlock_ui: None` mirrors C# `unlockPrompt == null`: a locked vault then
    /// resolves to [`SshPasswordResolution::PromptRequired`] instead of prompting.
    pub fn new(
        local: P,
        session: S,
        vault: V,
        unlock_ui: Option<U>,
        vault_enabled: bool,
    ) -> Self {
        Self {
            local,
            session,
            vault,
            unlock_ui,
            vault_enabled,
            resolve_calls: AtomicUsize::new(0),
            unlock_prompt_calls: AtomicUsize::new(0),
        }
    }

    /// How many times [`resolve`](Self::resolve) ran.
    pub fn resolve_calls(&self) -> usize {
        self.resolve_calls.load(Ordering::SeqCst)
    }

    /// How many times the unlock-prompt seam was invoked.
    pub fn unlock_prompt_calls(&self) -> usize {
        self.unlock_prompt_calls.load(Ordering::SeqCst)
    }

    /// Resolve the SSH login password in C# order (module-header table).
    pub fn resolve(
        &self,
        request: &SshPasswordRequest,
    ) -> Result<SshPasswordResolution, SshPasswordError> {
        self.resolve_calls.fetch_add(1, Ordering::SeqCst);

        // Inline per-node (leaf-only, non-ephemeral) suppresses a saved credential.
        if request.use_inline_password && !request.is_ephemeral {
            return self.resolve_inline(&request.node_id);
        }

        // Ephemeral nodes never carry a saved credential (C# prompt path).
        let Some(credential) = request.credential.as_ref() else {
            return Ok(SshPasswordResolution::PromptRequired);
        };

        if credential.protocol != ProtocolType::Ssh {
            return Ok(SshPasswordResolution::PromptRequired);
        }

        // SSH key credentials hand off to the private-key path, out of password scope.
        if credential.kind != CredentialKind::Password {
            return Err(SshPasswordError::SshKeyCredential);
        }

        match credential.secret_provider {
            CredentialSecretProvider::Local => self.resolve_saved_local(&credential.id),
            CredentialSecretProvider::Bitwarden => self.resolve_bitwarden(credential),
        }
    }

    fn resolve_inline(
        &self,
        node_id: &Uuid,
    ) -> Result<SshPasswordResolution, SshPasswordError> {
        match self.local_read(node_id)? {
            Some(password) => Ok(SshPasswordResolution::Resolved {
                value: SshPasswordValue::new(self.ensure_non_empty(password)?),
                source: SshPasswordSource::Inline,
            }),
            None => Ok(SshPasswordResolution::PromptRequired),
        }
    }

    fn resolve_saved_local(
        &self,
        credential_id: &Uuid,
    ) -> Result<SshPasswordResolution, SshPasswordError> {
        match self.local_read(credential_id)? {
            Some(password) => Ok(SshPasswordResolution::Resolved {
                value: SshPasswordValue::new(self.ensure_non_empty(password)?),
                source: SshPasswordSource::SavedLocal,
            }),
            None => Ok(SshPasswordResolution::PromptRequired),
        }
    }

    fn local_read(&self, id: &Uuid) -> Result<Option<String>, SshPasswordError> {
        self.local
            .read(id)
            .map_err(|e| SshPasswordError::Resolve(CredentialPasswordError::LocalRead(e.to_string())))
    }

    fn ensure_non_empty(&self, password: String) -> Result<String, SshPasswordError> {
        if password.trim().is_empty() {
            // Stored-but-blank is an anomalous entry — fail closed (never return
            // a silent empty password; C# would instead fall to a prompt).
            return Err(SshPasswordError::Resolve(CredentialPasswordError::EmptyPassword));
        }
        Ok(password)
    }

    fn resolve_bitwarden(
        &self,
        profile: &BitwardenCatalogProfile,
    ) -> Result<SshPasswordResolution, SshPasswordError> {
        let first = self.read_bitwarden_password(profile);
        let locked = matches!(first, Err(CredentialPasswordError::VaultLocked));
        if !locked {
            return self.map_bitwarden_read(first);
        }

        let Some(ui) = &self.unlock_ui else {
            // C# null unlockPrompt → locked-vault exception → SshCredentialResolver
            // catches it and shows the account-password prompt.
            return Ok(SshPasswordResolution::PromptRequired);
        };

        self.unlock_prompt_calls.fetch_add(1, Ordering::SeqCst);
        let session = self.session_trait();
        match ui.prompt_unlock(session) {
            UnlockPromptChoice::Unlocked => {
                // Retry the resolution once (mirror C#); never loop infinitely.
                self.map_bitwarden_read(self.read_bitwarden_password(profile))
            }
            UnlockPromptChoice::Canceled => Err(SshPasswordError::UnlockCanceled),
            UnlockPromptChoice::Failed => Err(SshPasswordError::UnlockPromptFailed),
        }
    }

    fn map_bitwarden_read(
        &self,
        read: Result<SshPasswordValue, CredentialPasswordError>,
    ) -> Result<SshPasswordResolution, SshPasswordError> {
        match read {
            Ok(value) => Ok(SshPasswordResolution::Resolved {
                value,
                source: SshPasswordSource::SavedBitwarden,
            }),
            Err(CredentialPasswordError::VaultDisabled)
            | Err(CredentialPasswordError::MissingBitwardenItemId)
            | Err(CredentialPasswordError::UnsupportedFieldPath)
            | Err(CredentialPasswordError::BitwardenItemNotFound)
            | Err(CredentialPasswordError::BitwardenPasswordMissing) => {
                // C# CredentialPasswordResolver throws BitwardenVaultException for
                // these → SshCredentialResolver catches → account-password prompt.
                Ok(SshPasswordResolution::PromptRequired)
            }
            Err(err) => Err(SshPasswordError::Resolve(err)),
        }
    }

    fn read_bitwarden_password(
        &self,
        profile: &BitwardenCatalogProfile,
    ) -> Result<SshPasswordValue, CredentialPasswordError> {
        if !self.vault_enabled {
            return Err(CredentialPasswordError::VaultDisabled);
        }
        // C# order (`CredentialPasswordResolver.ReadPasswordAsync`): the item
        // reference is validated before the session gate, so a misconfigured
        // credential never triggers a master-password prompt.
        let item_id = profile
            .bitwarden_item_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or(CredentialPasswordError::MissingBitwardenItemId)?;

        let field_path = profile
            .bitwarden_field_path
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(BITWARDEN_PASSWORD_FIELD_PATH);
        if field_path != BITWARDEN_PASSWORD_FIELD_PATH {
            return Err(CredentialPasswordError::UnsupportedFieldPath);
        }

        if self.session.status() != BitwardenSessionStatus::Unlocked {
            return Err(CredentialPasswordError::VaultLocked);
        }
        let _ = self.session.session_key(); // parity check — must not log

        let password = self
            .vault
            .read_login_password(item_id)?
            .ok_or(CredentialPasswordError::BitwardenItemNotFound)?;
        if password.trim().is_empty() {
            return Err(CredentialPasswordError::EmptyPassword);
        }
        Ok(SshPasswordValue::new(password))
    }

    fn session_trait(&self) -> &dyn BitwardenSession {
        &self.session
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FakeBitwardenSession, FakeBitwardenVaultPasswords, FakePasswordStore};
    use wormhole_domain::ProtocolType;

    type TestGlue = SshPasswordResolverGlue<
        FakePasswordStore,
        FakeBitwardenSession,
        FakeBitwardenVaultPasswords,
        FakeUnlockPromptUi,
    >;

    fn unlocked_session() -> FakeBitwardenSession {
        let session = FakeBitwardenSession::with_session_key("opaque-lab-session");
        assert!(session.unlock("lab-master").unlocked);
        session
    }

    fn locked_session() -> FakeBitwardenSession {
        FakeBitwardenSession::with_session_key("opaque-lab-session") // holds key only on unlock
    }

    fn local_credential(id: Uuid) -> BitwardenCatalogProfile {
        BitwardenCatalogProfile::local_password(id, "lab", ProtocolType::Ssh, Some("root".into()))
    }

    fn bitwarden_credential(id: Uuid, item_id: &str) -> BitwardenCatalogProfile {
        BitwardenCatalogProfile::linked_bitwarden(id, "lab", ProtocolType::Ssh, item_id, Some("root".into()))
    }

    fn request_for(profile: &BitwardenCatalogProfile) -> SshPasswordRequest {
        SshPasswordRequest::new(
            Uuid::new_v4(),
            false,
            false,
            Some(profile.clone()),
        )
    }

    fn glue_with(
        store: FakePasswordStore,
        session: FakeBitwardenSession,
        vault: FakeBitwardenVaultPasswords,
        unlock_ui: Option<FakeUnlockPromptUi>,
        vault_enabled: bool,
    ) -> TestGlue {
        SshPasswordResolverGlue::new(store, session, vault, unlock_ui, vault_enabled)
    }

    #[test]
    fn inline_wins_over_saved() {
        let node_id = Uuid::new_v4();
        let cred_id = Uuid::new_v4();
        let store = FakePasswordStore::new();
        store.store(&node_id, "inline-secret").unwrap();
        store.store(&cred_id, "saved-secret").unwrap();
        let glue = glue_with(
            store,
            unlocked_session(),
            FakeBitwardenVaultPasswords::new(),
            None,
            true,
        );
        let request = SshPasswordRequest::new(node_id, true, false, Some(local_credential(cred_id)));
        let resolution = glue.resolve(&request).expect("resolve");
        match resolution {
            SshPasswordResolution::Resolved { value, source } => {
                assert_eq!(source, SshPasswordSource::Inline);
                assert_eq!(value.expose(), "inline-secret");
            }
            other => panic!("expected inline Resolved, got {other:?}"),
        }
    }

    #[test]
    fn saved_local_wins_over_vault() {
        let cred_id = Uuid::new_v4();
        let store = FakePasswordStore::new();
        store.store(&cred_id, "saved-secret").unwrap();
        let vault = FakeBitwardenVaultPasswords::with_items([("lab-router", "vault-secret")]);
        let glue = glue_with(store, unlocked_session(), vault, None, true);
        let request = request_for(&local_credential(cred_id));
        let resolution = glue.resolve(&request).expect("resolve");
        match resolution {
            SshPasswordResolution::Resolved { value, source } => {
                assert_eq!(source, SshPasswordSource::SavedLocal);
                assert_eq!(value.expose(), "saved-secret");
            }
            other => panic!("expected saved-local Resolved, got {other:?}"),
        }
        // The vault must never have been consulted while a saved local exists
        // for a Local-provider credential.
        assert_eq!(glue.resolve_calls(), 1);
    }

    #[test]
    fn bitwarden_provider_never_reads_local_store() {
        // Provider dispatch parity: a Bitwarden-provider credential resolves
        // from the vault even when a local CredMgr entry exists for the same
        // credential id — the local store is Local-provider-only.
        let cred_id = Uuid::new_v4();
        let store = FakePasswordStore::new();
        store.store(&cred_id, "local-trap-secret").unwrap();
        let vault = FakeBitwardenVaultPasswords::with_items([("lab-router", "vault-secret")]);
        let glue = glue_with(store, unlocked_session(), vault, None, true);
        let request = request_for(&bitwarden_credential(cred_id, "lab-router"));
        let resolution = glue.resolve(&request).unwrap();
        assert_source(&resolution, SshPasswordSource::SavedBitwarden, "vault-secret");
        assert!(!matches!(
            resolution,
            SshPasswordResolution::Resolved { source: SshPasswordSource::SavedLocal, .. }
        ));
    }

    #[test]
    fn no_credential_and_ephemeral_prompt_required() {
        let glue = glue_with(
            FakePasswordStore::new(),
            unlocked_session(),
            FakeBitwardenVaultPasswords::new(),
            None,
            true,
        );
        // No inline, no credential → C# prompt.
        let none = SshPasswordRequest::new(Uuid::new_v4(), false, false, None);
        assert_eq!(glue.resolve(&none).unwrap(), SshPasswordResolution::PromptRequired);
        // Inline flag on an ephemeral node is ignored (C# `UseInlinePassword && !IsEphemeral`).
        let ephemeral_inline = SshPasswordRequest::new(Uuid::new_v4(), true, true, None);
        assert_eq!(
            glue.resolve(&ephemeral_inline).unwrap(),
            SshPasswordResolution::PromptRequired
        );
    }

    #[test]
    fn inline_missing_prompt_required_and_empty_error() {
        let node_id = Uuid::new_v4();
        let missing = SshPasswordRequest::new(node_id, true, false, Some(local_credential(Uuid::new_v4())));
        let glue = glue_with(
            FakePasswordStore::new(),
            unlocked_session(),
            FakeBitwardenVaultPasswords::new(),
            None,
            true,
        );
        // Missing inline → C# falls to prompt.
        assert_eq!(glue.resolve(&missing).unwrap(), SshPasswordResolution::PromptRequired);

        let blank = FakePasswordStore::new();
        blank.store(&node_id, "   ").unwrap();
        let glue2 = glue_with(
            blank,
            unlocked_session(),
            FakeBitwardenVaultPasswords::new(),
            None,
            true,
        );
        // Stored-but-blank inline → fail-closed error (never a silent empty).
        assert_eq!(
            glue2.resolve(&missing).unwrap_err(),
            SshPasswordError::Resolve(CredentialPasswordError::EmptyPassword)
        );
    }

    #[test]
    fn saved_local_missing_prompt_required_and_empty_error() {
        let cred_id = Uuid::new_v4();
        let glue = glue_with(
            FakePasswordStore::new(),
            unlocked_session(),
            FakeBitwardenVaultPasswords::new(),
            None,
            true,
        );
        assert_eq!(
            glue.resolve(&request_for(&local_credential(cred_id))).unwrap(),
            SshPasswordResolution::PromptRequired
        );

        let blank = FakePasswordStore::new();
        blank.store(&cred_id, "").unwrap();
        let glue2 = glue_with(blank, unlocked_session(), FakeBitwardenVaultPasswords::new(), None, true);
        assert_eq!(
            glue2.resolve(&request_for(&local_credential(cred_id))).unwrap_err(),
            SshPasswordError::Resolve(CredentialPasswordError::EmptyPassword)
        );
    }

    #[test]
    fn protocol_mismatch_and_ssh_key_fail_closed() {
        let cred_id = Uuid::new_v4();
        let mut rdp = local_credential(cred_id);
        rdp.protocol = ProtocolType::Rdp;
        let glue = glue_with(
            FakePasswordStore::new(),
            unlocked_session(),
            FakeBitwardenVaultPasswords::new(),
            None,
            true,
        );
        // Non-SSH credential → C# account-password prompt.
        assert_eq!(
            glue.resolve(&request_for(&rdp)).unwrap(),
            SshPasswordResolution::PromptRequired
        );

        let mut key = local_credential(Uuid::new_v4());
        key.kind = CredentialKind::SshKey;
        // SSH key must never silently degrade to a password prompt.
        assert_eq!(
            glue.resolve(&request_for(&key)).unwrap_err(),
            SshPasswordError::SshKeyCredential
        );
    }

    #[test]
    fn vault_disabled_item_missing_and_empty_fail_closed_prompt() {
        let vault = FakeBitwardenVaultPasswords::with_items([("lab-router", "vault-secret")]);
        // Vault disabled → C# BitwardenVaultException → prompt.
        let disabled = glue_with(
            FakePasswordStore::new(),
            unlocked_session(),
            vault,
            None,
            false,
        );
        let request = request_for(&bitwarden_credential(Uuid::new_v4(), "lab-router"));
        assert_eq!(disabled.resolve(&request).unwrap(), SshPasswordResolution::PromptRequired);

        // Item not in the vault → prompt (C# vault exception → prompt).
        let enabled = glue_with(
            FakePasswordStore::new(),
            unlocked_session(),
            FakeBitwardenVaultPasswords::with_items([("other", "x")]),
            None,
            true,
        );
        let missing = request_for(&bitwarden_credential(Uuid::new_v4(), "no-such-item"));
        assert_eq!(enabled.resolve(&missing).unwrap(), SshPasswordResolution::PromptRequired);

        // Item present but blank → fail-closed error, never a silent empty.
        let blank_vault = FakeBitwardenVaultPasswords::with_items([("blank-item", " \t ")]);
        let blank_glue = glue_with(FakePasswordStore::new(), unlocked_session(), blank_vault, None, true);
        let blank_profile = bitwarden_credential(Uuid::new_v4(), "blank-item");
        assert_eq!(
            blank_glue.resolve(&request_for(&blank_profile)).unwrap_err(),
            SshPasswordError::Resolve(CredentialPasswordError::EmptyPassword)
        );
    }

    #[test]
    fn locked_vault_prompt_unlock_resolve_once() {
        let vault = FakeBitwardenVaultPasswords::with_items([("lab-router", "vault-secret")]);
        let session = locked_session();
        let glue = SshPasswordResolverGlue::new(
            FakePasswordStore::new(),
            &session,
            &vault,
            Some(FakeUnlockPromptUi::with_submit("master-password")),
            true,
        );
        let request = request_for(&bitwarden_credential(Uuid::new_v4(), "lab-router"));
        let resolution = glue.resolve(&request).expect("resolve");
        match resolution {
            SshPasswordResolution::Resolved { value, source } => {
                assert_eq!(source, SshPasswordSource::SavedBitwarden);
                assert_eq!(value.expose(), "vault-secret");
            }
            other => panic!("expected bitwarden Resolved, got {other:?}"),
        }
        assert_eq!(glue.unlock_prompt_calls(), 1);
        // The vault read happened exactly once, after the unlock (retry-once):
        // the first attempt short-circuits on Locked *before* any vault read.
        assert_eq!(vault.read_calls(), 1);
        assert_eq!(session.status(), BitwardenSessionStatus::Unlocked);
    }

    #[test]
    fn locked_vault_missing_item_after_unlock_prompts() {
        // Unlock succeeds; the retry still finds no item → C# vault exception → prompt.
        let session = locked_session();
        let glue = SshPasswordResolverGlue::new(
            FakePasswordStore::new(),
            &session,
            FakeBitwardenVaultPasswords::with_items([("other", "x")]),
            Some(FakeUnlockPromptUi::with_submit("master-password")),
            true,
        );
        let request = request_for(&bitwarden_credential(Uuid::new_v4(), "no-such-item"));
        assert_eq!(glue.resolve(&request).unwrap(), SshPasswordResolution::PromptRequired);
        assert_eq!(session.status(), BitwardenSessionStatus::Unlocked);
    }

    #[test]
    fn locked_vault_cancel_aborts() {
        let session = locked_session();
        let glue = SshPasswordResolverGlue::new(
            FakePasswordStore::new(),
            &session,
            FakeBitwardenVaultPasswords::with_items([("lab-router", "vault-secret")]),
            Some(FakeUnlockPromptUi::with_cancel()),
            true,
        );
        let request = request_for(&bitwarden_credential(Uuid::new_v4(), "lab-router"));
        assert_eq!(glue.resolve(&request).unwrap_err(), SshPasswordError::UnlockCanceled);
        // Session stayed locked — nothing resolved.
        assert_eq!(session.status(), BitwardenSessionStatus::Locked);
        assert_eq!(glue.unlock_prompt_calls(), 1);
    }

    #[test]
    fn locked_vault_failed_prompt_aborts() {
        let glue = glue_with(
            FakePasswordStore::new(),
            locked_session(),
            FakeBitwardenVaultPasswords::with_items([("lab-router", "vault-secret")]),
            Some(FakeUnlockPromptUi::with_fail()),
            true,
        );
        let request = request_for(&bitwarden_credential(Uuid::new_v4(), "lab-router"));
        assert_eq!(
            glue.resolve(&request).unwrap_err(),
            SshPasswordError::UnlockPromptFailed
        );
    }

    #[test]
    fn locked_vault_without_ui_prompt_required() {
        // C# `unlockPrompt == null` → locked-vault exception → account-password prompt.
        let session = locked_session();
        let glue = SshPasswordResolverGlue::new(
            FakePasswordStore::new(),
            &session,
            FakeBitwardenVaultPasswords::with_items([("lab-router", "vault-secret")]),
            Option::<FakeUnlockPromptUi>::None,
            true,
        );
        let request = request_for(&bitwarden_credential(Uuid::new_v4(), "lab-router"));
        assert_eq!(glue.resolve(&request).unwrap(), SshPasswordResolution::PromptRequired);
        assert_eq!(session.status(), BitwardenSessionStatus::Locked);
        assert_eq!(glue.unlock_prompt_calls(), 0);
    }

    #[test]
    fn missing_item_ref_never_prompts_unlock() {
        // C# order parity: a locked vault with a missing/blank item reference is
        // reported before the session gate — the unlock prompt must never fire
        // for a misconfigured credential (no spurious master-password dialog).
        let session = locked_session();
        let glue = SshPasswordResolverGlue::new(
            FakePasswordStore::new(),
            &session,
            FakeBitwardenVaultPasswords::with_items([("lab-router", "vault-secret")]),
            Some(FakeUnlockPromptUi::with_submit("master-password")),
            true,
        );
        let mut profile = bitwarden_credential(Uuid::new_v4(), "lab-router");
        profile.bitwarden_item_id = Some("   ".into());
        let request = request_for(&profile);
        assert_eq!(glue.resolve(&request).unwrap(), SshPasswordResolution::PromptRequired);
        assert_eq!(glue.unlock_prompt_calls(), 0);
        assert_eq!(session.status(), BitwardenSessionStatus::Locked);
    }

    #[test]
    fn unlock_wrong_master_password_aborts_fail_closed() {
        // The fake session rejects a blank master; the prompt mirrors that as Failed.
        let glue = glue_with(
            FakePasswordStore::new(),
            locked_session(),
            FakeBitwardenVaultPasswords::with_items([("lab-router", "vault-secret")]),
            Some(FakeUnlockPromptUi::with_submit("   ")),
            true,
        );
        let request = request_for(&bitwarden_credential(Uuid::new_v4(), "lab-router"));
        assert_eq!(
            glue.resolve(&request).unwrap_err(),
            SshPasswordError::UnlockPromptFailed
        );
    }

    #[test]
    fn ordering_inline_saved_then_vault_parity() {
        // C# order pin: with inline + saved local + vault all populated, inline
        // wins; then saved-local wins over a bitwarden-linked credential only when
        // the credential is Local-provider; a Bitwarden-provider credential reads
        // the vault.
        let node_id = Uuid::new_v4();
        let cred_id = Uuid::new_v4();
        let store = FakePasswordStore::new();
        store.store(&node_id, "inline").unwrap();
        store.store(&cred_id, "saved").unwrap();
        let glue = glue_with(
            store,
            unlocked_session(),
            FakeBitwardenVaultPasswords::with_items([("lab-router", "vault")]),
            None,
            true,
        );

        let inline_req = SshPasswordRequest::new(node_id, true, false, Some(local_credential(cred_id)));
        assert_source(&glue.resolve(&inline_req).unwrap(), SshPasswordSource::Inline, "inline");

        let saved_req = request_for(&local_credential(cred_id));
        assert_source(&glue.resolve(&saved_req).unwrap(), SshPasswordSource::SavedLocal, "saved");

        let vault_req = request_for(&bitwarden_credential(Uuid::new_v4(), "lab-router"));
        assert_source(&glue.resolve(&vault_req).unwrap(), SshPasswordSource::SavedBitwarden, "vault");
    }

    fn assert_source(res: &SshPasswordResolution, expected: SshPasswordSource, value: &str) {
        match res {
            SshPasswordResolution::Resolved { value: v, source } => {
                assert_eq!(source, &expected);
                assert_eq!(v.expose(), value);
            }
            other => panic!("expected {expected:?} Resolved, got {other:?}"),
        }
    }

    #[test]
    fn debug_and_errors_never_echo_secrets() {
        let secret = "super-secret-ssh-password-never-log";
        let node_id = Uuid::new_v4();
        let store = FakePasswordStore::new();
        store.store(&node_id, secret).unwrap();
        let glue = glue_with(
            store,
            unlocked_session(),
            FakeBitwardenVaultPasswords::new(),
            Some(FakeUnlockPromptUi::with_submit("master-pw-dummy-xyz")),
            true,
        );
        let dbg = format!("{glue:?}");
        assert!(!dbg.contains(secret));
        assert!(!dbg.contains("super-secret"));
        assert!(!dbg.contains("master-pw"));
        assert!(dbg.contains("session_status"));
        assert!(dbg.contains("Unlocked"));

        // SshPasswordValue Debug/Display are length-only.
        let value = SshPasswordValue::new(secret);
        assert_eq!(value.len(), secret.len());
        assert!(!value.is_empty());
        assert!(!format!("{value:?}").contains(secret));
        assert!(!format!("{value}").contains(secret));
        assert!(format!("{value}").contains("redacted"));
        assert_eq!(value.expose(), secret);

        // A resolved resolution's Debug never carries the value either.
        let resolution = SshPasswordResolution::Resolved {
            value,
            source: SshPasswordSource::Inline,
        };
        let res_dbg = format!("{resolution:?}");
        assert!(!res_dbg.contains(secret));
        assert!(res_dbg.contains("SshPasswordValue"));

        // Error Debug is safe too.
        let err = SshPasswordError::Resolve(CredentialPasswordError::EmptyPassword);
        assert!(!format!("{err:?}").contains(secret));
        let ok = format!("{err}");
        assert!(!ok.contains(secret));
    }

    #[test]
    fn fake_unlock_prompt_debug_redacts_master_and_exhausted_script_cancels() {
        let ui = FakeUnlockPromptUi::with_submit("hunter2-master-password");
        let dbg = format!("{ui:?}");
        assert!(!dbg.contains("hunter2"));
        assert!(!dbg.contains("master-password"));
        assert!(dbg.contains("[REDACTED]"));
        assert!(dbg.contains("Submit"));

        // Driving it once consumes the seeded submit; a second prompt (exhausted)
        // cancels fail-closed.
        let session = FakeBitwardenSession::with_session_key("opaque");
        assert!(matches!(ui.prompt_unlock(&session), UnlockPromptChoice::Unlocked));
        assert_eq!(ui.prompt_calls(), 1);
        assert_eq!(ui.prompt_unlock(&session), UnlockPromptChoice::Canceled);
        assert_eq!(ui.prompt_calls(), 2);

        // An explicit Cancel entry cancels too.
        let mut cancel_ui = FakeUnlockPromptUi::new();
        cancel_ui.push(FakeUnlockPromptScript::Cancel);
        assert_eq!(cancel_ui.prompt_unlock(&session), UnlockPromptChoice::Canceled);

        // Fail-closed: empty script → cancel.
        let empty = FakeUnlockPromptUi::new();
        assert_eq!(empty.prompt_unlock(&session), UnlockPromptChoice::Canceled);
    }

    #[test]
    fn channel_unlock_roundtrip_resolves_and_cancel_aborts() {
        // Round-trip: glue → channel → UI thread submits master → unlock → retry once.
        let channel = UnlockPromptChannel::open();
        let (shared, rx) = channel.into_parts();
        let session = locked_session();
        let glue = SshPasswordResolverGlue::new(
            FakePasswordStore::new(),
            &session,
            FakeBitwardenVaultPasswords::with_items([("lab-router", "vault-secret")]),
            Some(shared),
            true,
        );
        let answerer = std::thread::spawn(move || {
            let pending = rx.recv().expect("pending unlock");
            assert!(pending.submit("master-password"));
        });
        let request = request_for(&bitwarden_credential(Uuid::new_v4(), "lab-router"));
        let resolution = glue.resolve(&request).expect("resolve");
        answerer.join().expect("ui thread");
        assert_source(&resolution, SshPasswordSource::SavedBitwarden, "vault-secret");
        assert_eq!(session.status(), BitwardenSessionStatus::Unlocked);
        assert_eq!(glue.unlock_prompt_calls(), 1);

        // Cancel via the channel → abort.
        let channel = UnlockPromptChannel::open();
        let (shared, rx) = channel.into_parts();
        let glue2 = SshPasswordResolverGlue::new(
            FakePasswordStore::new(),
            locked_session(),
            FakeBitwardenVaultPasswords::with_items([("lab-router", "vault-secret")]),
            Some(shared),
            true,
        );
        let canceler = std::thread::spawn(move || {
            let pending = rx.recv().expect("pending unlock");
            assert!(pending.cancel());
        });
        let request2 = request_for(&bitwarden_credential(Uuid::new_v4(), "lab-router"));
        assert_eq!(glue2.resolve(&request2).unwrap_err(), SshPasswordError::UnlockCanceled);
        canceler.join().expect("ui thread");
    }

    #[test]
    fn channel_abandon_fail_closed() {
        let channel = UnlockPromptChannel::open();
        let (shared, rx) = channel.into_parts();
        let glue = SshPasswordResolverGlue::new(
            FakePasswordStore::new(),
            locked_session(),
            FakeBitwardenVaultPasswords::with_items([("lab-router", "vault-secret")]),
            Some(shared),
            true,
        );
        let abandon = std::thread::spawn(move || {
            let pending = rx.recv().expect("pending");
            drop(pending); // never answers
        });
        let request = request_for(&bitwarden_credential(Uuid::new_v4(), "lab-router"));
        // Dropping the pending responder maps to Canceled → abort (fail-closed).
        assert_eq!(glue.resolve(&request).unwrap_err(), SshPasswordError::UnlockCanceled);
        abandon.join().expect("ui thread");
    }

    #[test]
    fn unlock_response_and_script_debug_never_echo_master() {
        // Acceptance: `UnlockPromptResponse::Submitted { master }` is never a
        // Debug oracle — a stray `{:?}` log must not leak the master password.
        let submitted = UnlockPromptResponse::Submitted {
            master: "hunter2-master-password".into(),
        };
        let dbg = format!("{submitted:?}");
        assert!(!dbg.contains("hunter2"));
        assert!(!dbg.contains("master-password"));
        assert!(dbg.contains("REDACTED"));
        let canceled = format!("{:?}", UnlockPromptResponse::Canceled);
        assert!(canceled.contains("Canceled"));
        assert!(!canceled.contains("hunter2"));

        // The scripted entry backing the fake prompt follows the same rule.
        let script = FakeUnlockPromptScript::Submit("hunter2-master-password".into());
        let script_dbg = format!("{script:?}");
        assert!(!script_dbg.contains("hunter2"));
        assert!(script_dbg.contains("[REDACTED]"));
    }

    #[test]
    fn unlock_claims_success_but_session_still_locked_errors() {
        // Module table row: unlock prompt reports `Unlocked` (hostile/buggy UI —
        // it did not actually transition the session) → retry sees the vault
        // still locked → fail-closed error, never a silent prompt/resolve loop.
        #[derive(Debug)]
        struct LyingUnlockUi;
        impl UnlockPromptUi for LyingUnlockUi {
            fn prompt_unlock(&self, _session: &dyn BitwardenSession) -> UnlockPromptChoice {
                UnlockPromptChoice::Unlocked
            }
        }
        let session = locked_session();
        let vault = FakeBitwardenVaultPasswords::with_items([("lab-router", "vault-secret")]);
        let glue = SshPasswordResolverGlue::new(
            FakePasswordStore::new(),
            &session,
            &vault,
            Some(LyingUnlockUi),
            true,
        );
        let request = request_for(&bitwarden_credential(Uuid::new_v4(), "lab-router"));
        assert_eq!(
            glue.resolve(&request).unwrap_err(),
            SshPasswordError::Resolve(CredentialPasswordError::VaultLocked)
        );
        // Exactly one prompt; the retry read hit the still-locked session — no
        // second vault read, no infinite loop.
        assert_eq!(glue.unlock_prompt_calls(), 1);
        assert_eq!(vault.read_calls(), 0);
        assert_eq!(session.status(), BitwardenSessionStatus::Locked);
    }

    #[test]
    fn unlock_channel_receiver_dropped_fails_closed() {
        // Dropping the whole channel (pending_rx gone) → the request cannot even
        // be sent → prompt reports Failed → abort fail-closed.
        let channel = UnlockPromptChannel::open();
        let shared = channel.shared();
        drop(channel);
        let glue = SshPasswordResolverGlue::new(
            FakePasswordStore::new(),
            locked_session(),
            FakeBitwardenVaultPasswords::with_items([("lab-router", "vault-secret")]),
            Some(shared),
            true,
        );
        let request = request_for(&bitwarden_credential(Uuid::new_v4(), "lab-router"));
        assert_eq!(
            glue.resolve(&request).unwrap_err(),
            SshPasswordError::UnlockPromptFailed
        );
    }

    #[test]
    fn channel_debug_never_shows_pending_master() {
        let mut channel = UnlockPromptChannel::open();
        let shared = channel.shared();
        let caller = std::thread::spawn(move || {
            let ui = shared.as_ref();
            let session = FakeBitwardenSession::with_session_key("opaque");
            UnlockPromptUi::prompt_unlock(ui, &session)
        });
        let pending = channel.pending_rx().recv().expect("pending");
        let dbg = format!("{channel:?}");
        assert!(!dbg.contains("hunter2"));
        pending.submit("hunter2-master-password");
        let _ = caller.join().expect("caller");
        let shared_dbg = format!("{channel:?}");
        assert!(!shared_dbg.contains("hunter2"));
    }

    #[test]
    fn request_maps_from_connection_profile_semantics() {
        // Host mapping from wormhole_domain::ConnectionProfile fields → request.
        use wormhole_domain::ConnectionProfile;
        let mut profile = ConnectionProfile::default();
        profile.node_id = Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap();
        profile.use_inline_password = true;
        let request = SshPasswordRequest::new(
            profile.node_id,
            profile.use_inline_password,
            profile.is_ephemeral,
            None,
        );
        assert_eq!(request.node_id, profile.node_id);
        assert!(request.use_inline_password);
        assert!(!request.is_ephemeral);
        assert!(request.credential.is_none());
    }
}
