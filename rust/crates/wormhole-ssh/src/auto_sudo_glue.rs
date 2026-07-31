//! Auto-sudo detector ↔ SSH session glue stub.
//!
//! Mirrors C# `Services/Ssh/SshAutoSudoDriver.cs` state machine:
//! first shell output → send [`ELEVATION_COMMAND`]; rolling tail classify →
//! optional password inject; no prompt within [`PROMPT_TIMEOUT_SECS`] →
//! password is **not** sent.
//!
//! Wires the existing [`SudoPromptTail`] / classify detector — does **not**
//! reimplement prompt recognition. The password is held out-of-band and never
//! appears in [`Debug`] output. Unit tests drive
//! [`wormhole_terminal::FakeTerminalSession`] (no GPUI / WebView2 / live SSH).
//!
//! Sync write failures fail closed (secret cleared, phase [`AutoSudoPhase::Done`])
//! so a later prompt cannot inject without a successful elevation write. C#
//! fire-and-forget writes rely on the prompt timeout as the backstop instead.

use std::fmt;

use wormhole_terminal::FakeTerminalSession;

use crate::auto_sudo::{
    SudoOutputClass, SudoPromptTail, ELEVATION_COMMAND, PROMPT_TIMEOUT_SECS,
};

/// Carriage return line terminator (C# / xterm Enter → PTY `ICRNL`).
pub const LINE_TERMINATOR: u8 = b'\r';

/// Driver phase (C# `SshAutoSudoDriver` private `State`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AutoSudoPhase {
    /// Waiting for the first non-empty shell output chunk.
    WaitingForShell,
    /// Elevation successfully written; scanning the rolling tail for a password prompt.
    WaitingForPassword,
    /// Finished (prompt handled, timed out, or disposed).
    Done,
}

/// Outcome of one glue step (elevation / password / idle / finish).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AutoSudoStep {
    /// No write; still waiting or already done.
    Idle,
    /// Wrote [`ELEVATION_COMMAND`] + `\r`.
    SentElevation,
    /// Wrote the held password + `\r` after a detected prompt.
    SentPassword,
    /// Abandoned without sending the password (timeout / explicit finish /
    /// missing secret at prompt). Write failures return [`Err`] instead and
    /// also clear the secret.
    FinishedWithoutPassword,
}

/// Write failure from the terminal sink — **never** carries payload bytes
/// (payload may be the password).
#[derive(Clone, PartialEq, Eq)]
pub struct AutoSudoWriteError {
    message: &'static str,
}

impl AutoSudoWriteError {
    pub fn new(message: &'static str) -> Self {
        Self { message }
    }

    pub fn message(&self) -> &'static str {
        self.message
    }

    pub fn from_closing() -> Self {
        Self::new("terminal session is closing")
    }
}

impl fmt::Debug for AutoSudoWriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AutoSudoWriteError")
            .field("message", &self.message)
            .finish()
    }
}

impl fmt::Display for AutoSudoWriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message)
    }
}

impl std::error::Error for AutoSudoWriteError {}

/// Terminal write sink for elevation / password lines.
///
/// Production will bridge to the live SSH shell channel; tests use
/// [`FakeTerminalSession`] via [`AutoSudoSessionGlue::on_output_fake`].
pub trait AutoSudoTerminal {
    /// Write raw bytes to the session (already includes the trailing `\r`).
    fn write_bytes(&mut self, data: &[u8]) -> Result<(), AutoSudoWriteError>;
}

/// Out-of-band password for Auto sudo — value never appears in [`Debug`].
pub struct AutoSudoPassword {
    value: String,
}

impl AutoSudoPassword {
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
        }
    }

    /// UTF-8 length only (safe for metrics / Debug helpers).
    pub fn utf8_len(&self) -> usize {
        self.value.len()
    }

    fn into_inner(self) -> String {
        self.value
    }
}

impl fmt::Debug for AutoSudoPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AutoSudoPassword")
            .field("utf8_len", &self.utf8_len())
            .field("value", &"[REDACTED]")
            .finish()
    }
}

impl From<String> for AutoSudoPassword {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for AutoSudoPassword {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

/// Adapter: [`FakeTerminalSession`] as an [`AutoSudoTerminal`] sink.
struct FakeTerminalSink<'a> {
    session: &'a FakeTerminalSession,
}

impl AutoSudoTerminal for FakeTerminalSink<'_> {
    fn write_bytes(&mut self, data: &[u8]) -> Result<(), AutoSudoWriteError> {
        self.session
            .write_bytes_sync(data)
            .map_err(|_| AutoSudoWriteError::from_closing())
    }
}

/// Session glue: feed output chunks → detector → optional Fake/real inject.
pub struct AutoSudoSessionGlue {
    password: Option<AutoSudoPassword>,
    phase: AutoSudoPhase,
    tail: SudoPromptTail,
}

impl AutoSudoSessionGlue {
    /// Build glue holding `password` out-of-band until prompt or finish.
    pub fn new(password: impl Into<AutoSudoPassword>) -> Self {
        Self {
            password: Some(password.into()),
            phase: AutoSudoPhase::WaitingForShell,
            tail: SudoPromptTail::new(),
        }
    }

    pub fn phase(&self) -> AutoSudoPhase {
        self.phase
    }

    pub fn has_password(&self) -> bool {
        self.password.is_some()
    }

    /// Informational — matches C# `PromptTimeout` (caller arms the timer).
    pub fn prompt_timeout_secs() -> u64 {
        PROMPT_TIMEOUT_SECS
    }

    pub fn tail_len(&self) -> usize {
        self.tail.len()
    }

    /// Feed a remote output chunk (C# `OnDataReceived`).
    ///
    /// Empty chunks are ignored. First non-empty chunk while waiting for the
    /// shell sends elevation (chunk is **not** appended to the prompt tail).
    /// Later chunks append + classify; on [`SudoOutputClass::PasswordPrompt`]
    /// the held password is written once and cleared.
    ///
    /// Sync write failures return [`Err`] after fail-closed cleanup (phase
    /// [`AutoSudoPhase::Done`], secret cleared). Errors never include payload.
    pub fn on_output(
        &mut self,
        data: &[u8],
        term: &mut dyn AutoSudoTerminal,
    ) -> Result<AutoSudoStep, AutoSudoWriteError> {
        if data.is_empty() {
            return Ok(AutoSudoStep::Idle);
        }

        match self.phase {
            AutoSudoPhase::WaitingForShell => {
                // Advance before write (C# does the same), but a *sync* write
                // failure means elevation never left — fail closed so a later
                // spurious prompt cannot inject the password without sudo.
                self.phase = AutoSudoPhase::WaitingForPassword;
                if let Err(err) = write_line(term, ELEVATION_COMMAND) {
                    self.finish_internal();
                    return Err(err);
                }
                Ok(AutoSudoStep::SentElevation)
            }
            AutoSudoPhase::WaitingForPassword => {
                self.tail.append(data);
                if self.tail.classify() != SudoOutputClass::PasswordPrompt {
                    return Ok(AutoSudoStep::Idle);
                }
                let password = match self.password.take() {
                    Some(p) => p.into_inner(),
                    None => {
                        self.finish_internal();
                        return Ok(AutoSudoStep::FinishedWithoutPassword);
                    }
                };
                // Clear secret before write (C# Finish then SendLine). A write
                // failure must not leave the password armed for retry into a
                // possibly non-echo-off shell.
                self.finish_internal();
                write_line(term, &password)?;
                Ok(AutoSudoStep::SentPassword)
            }
            AutoSudoPhase::Done => Ok(AutoSudoStep::Idle),
        }
    }

    /// Feed output through [`FakeTerminalSession`] (unit tests / lab).
    pub fn on_output_fake(
        &mut self,
        data: &[u8],
        session: &FakeTerminalSession,
    ) -> Result<AutoSudoStep, AutoSudoWriteError> {
        let mut sink = FakeTerminalSink { session };
        self.on_output(data, &mut sink)
    }

    /// C# prompt timer fired — forget the password without injecting it.
    pub fn on_timeout(&mut self) -> AutoSudoStep {
        if self.phase != AutoSudoPhase::WaitingForPassword {
            return AutoSudoStep::Idle;
        }
        self.finish_internal();
        AutoSudoStep::FinishedWithoutPassword
    }

    /// Idempotent dispose (C# `Finish` / `Dispose`).
    pub fn finish(&mut self) {
        self.finish_internal();
    }

    fn finish_internal(&mut self) {
        self.phase = AutoSudoPhase::Done;
        self.password = None;
        self.tail.clear();
    }
}

impl fmt::Debug for AutoSudoSessionGlue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never dump the secret — only whether one is still held.
        f.debug_struct("AutoSudoSessionGlue")
            .field("phase", &self.phase)
            .field("has_password", &self.password.is_some())
            .field("tail", &self.tail)
            .finish()
    }
}

fn write_line(term: &mut dyn AutoSudoTerminal, text: &str) -> Result<(), AutoSudoWriteError> {
    let mut buf = Vec::with_capacity(text.len() + 1);
    buf.extend_from_slice(text.as_bytes());
    buf.push(LINE_TERMINATOR);
    term.write_bytes(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auto_sudo::ELEVATION_COMMAND;

    fn line_bytes(text: &str) -> Vec<u8> {
        let mut v = text.as_bytes().to_vec();
        v.push(LINE_TERMINATOR);
        v
    }

    fn elev_bytes() -> Vec<u8> {
        line_bytes(ELEVATION_COMMAND)
    }

    #[test]
    fn first_output_sends_elevation_via_fake() {
        let mut glue = AutoSudoSessionGlue::new("s3cret");
        let fake = FakeTerminalSession::new();
        let step = glue.on_output_fake(b"welcome\r\n", &fake).unwrap();
        assert_eq!(step, AutoSudoStep::SentElevation);
        assert_eq!(glue.phase(), AutoSudoPhase::WaitingForPassword);
        assert_eq!(fake.writes(), vec![elev_bytes()]);
        assert!(glue.has_password());
    }

    #[test]
    fn first_chunk_prompt_text_is_not_tailed() {
        // C#: first shell chunk triggers elevation and is not scanned. A banner
        // that already ends in `Password: ` must not linger in the tail and
        // fire inject on the next ordinary chunk.
        let mut glue = AutoSudoSessionGlue::new("pw");
        let fake = FakeTerminalSession::new();
        assert_eq!(
            glue.on_output_fake(b"Password: ", &fake).unwrap(),
            AutoSudoStep::SentElevation
        );
        assert_eq!(glue.tail_len(), 0);
        assert_eq!(glue.phase(), AutoSudoPhase::WaitingForPassword);
        assert_eq!(
            glue.on_output_fake(b"$ ", &fake).unwrap(),
            AutoSudoStep::Idle
        );
        assert_eq!(fake.writes_count(), 1);
        assert!(glue.has_password());
    }

    #[test]
    fn empty_chunk_ignored_before_shell() {
        let mut glue = AutoSudoSessionGlue::new("pw");
        let fake = FakeTerminalSession::new();
        assert_eq!(
            glue.on_output_fake(b"", &fake).unwrap(),
            AutoSudoStep::Idle
        );
        assert_eq!(glue.phase(), AutoSudoPhase::WaitingForShell);
        assert_eq!(fake.writes_count(), 0);
    }

    #[test]
    fn prompt_injects_password_once_then_done() {
        let mut glue = AutoSudoSessionGlue::new("s3cret");
        let fake = FakeTerminalSession::new();
        glue.on_output_fake(b"$ ", &fake).unwrap();
        let step = glue
            .on_output_fake(b"[sudo] password for alice: ", &fake)
            .unwrap();
        assert_eq!(step, AutoSudoStep::SentPassword);
        assert_eq!(glue.phase(), AutoSudoPhase::Done);
        assert!(!glue.has_password());
        assert_eq!(fake.writes_count(), 2);
        assert_eq!(fake.writes()[0], elev_bytes());
        assert_eq!(fake.writes()[1], b"s3cret\r".as_slice());
        // Further output is ignored.
        assert_eq!(
            glue.on_output_fake(b"root# ", &fake).unwrap(),
            AutoSudoStep::Idle
        );
        assert_eq!(fake.writes_count(), 2);
    }

    #[test]
    fn prompt_across_chunks_uses_detector_tail() {
        let mut glue = AutoSudoSessionGlue::new("pw");
        let fake = FakeTerminalSession::new();
        glue.on_output_fake(b"x", &fake).unwrap();
        assert_eq!(
            glue.on_output_fake(b"[sudo] pass", &fake).unwrap(),
            AutoSudoStep::Idle
        );
        assert_eq!(
            glue.on_output_fake(b"word for u: ", &fake).unwrap(),
            AutoSudoStep::SentPassword
        );
        assert_eq!(fake.writes()[1], b"pw\r".as_slice());
    }

    #[test]
    fn timeout_finishes_without_password() {
        let mut glue = AutoSudoSessionGlue::new("must-not-send");
        let fake = FakeTerminalSession::new();
        glue.on_output_fake(b"banner", &fake).unwrap();
        assert_eq!(
            glue.on_timeout(),
            AutoSudoStep::FinishedWithoutPassword
        );
        assert_eq!(glue.phase(), AutoSudoPhase::Done);
        assert!(!glue.has_password());
        assert_eq!(fake.writes_count(), 1); // elevation only
        assert_eq!(AutoSudoSessionGlue::prompt_timeout_secs(), 10);
    }

    #[test]
    fn timeout_idle_before_shell_ready() {
        let mut glue = AutoSudoSessionGlue::new("pw");
        assert_eq!(glue.on_timeout(), AutoSudoStep::Idle);
        assert_eq!(glue.phase(), AutoSudoPhase::WaitingForShell);
        assert!(glue.has_password());
    }

    #[test]
    fn banner_mentioning_password_does_not_inject() {
        let mut glue = AutoSudoSessionGlue::new("pw");
        let fake = FakeTerminalSession::new();
        glue.on_output_fake(b"hi", &fake).unwrap();
        let banner = b"Your password expires in 7 days.\n$ ";
        assert_eq!(
            glue.on_output_fake(banner, &fake).unwrap(),
            AutoSudoStep::Idle
        );
        assert_eq!(fake.writes_count(), 1);
        assert_eq!(glue.phase(), AutoSudoPhase::WaitingForPassword);
    }

    #[test]
    fn debug_never_echoes_password() {
        let glue = AutoSudoSessionGlue::new("super-secret-password-value");
        let dbg = format!("{glue:?}");
        assert!(dbg.contains("AutoSudoSessionGlue"));
        assert!(dbg.contains("has_password"));
        assert!(!dbg.contains("super-secret-password-value"));
        assert!(!dbg.contains("value"));

        let pw = AutoSudoPassword::new("super-secret-password-value");
        let pwd_dbg = format!("{pw:?}");
        assert!(pwd_dbg.contains("[REDACTED]"));
        assert!(!pwd_dbg.contains("super-secret-password-value"));

        let fake = FakeTerminalSession::new();
        let mut g2 = AutoSudoSessionGlue::new("super-secret-password-value");
        g2.on_output_fake(b"a", &fake).unwrap();
        g2.on_output_fake(b"Password: ", &fake).unwrap();
        let fake_dbg = format!("{fake:?}");
        assert!(fake_dbg.contains("FakeTerminalSession"));
        assert!(fake_dbg.contains("utf8_len") || fake_dbg.contains("writes_count"));
        assert!(!fake_dbg.contains("super-secret-password-value"));
    }

    #[test]
    fn closing_session_elevation_write_fails_closed() {
        let mut glue = AutoSudoSessionGlue::new("leak-me");
        let fake = FakeTerminalSession::new();
        fake.mark_closing();
        let err = glue.on_output_fake(b"ready", &fake).unwrap_err();
        let rendered = format!("{err:?}{err}");
        assert!(rendered.contains("closing"));
        assert!(!rendered.contains("leak-me"));
        // Sync elevation write failed → fail closed (secret cleared; no inject later).
        assert_eq!(glue.phase(), AutoSudoPhase::Done);
        assert!(!glue.has_password());
        assert_eq!(fake.writes_count(), 0);
        // Further output must not resurrect elevation / password inject.
        assert_eq!(
            glue.on_output_fake(b"[sudo] password for u: ", &fake).unwrap(),
            AutoSudoStep::Idle
        );
        assert_eq!(fake.writes_count(), 0);
    }

    #[test]
    fn password_write_failure_clears_secret_without_send() {
        let mut glue = AutoSudoSessionGlue::new("leak-me");
        let fake = FakeTerminalSession::new();
        fake.close_after_n_writes(1); // elevation ok, then close
        glue.on_output_fake(b"$ ", &fake).unwrap();
        assert_eq!(fake.writes_count(), 1);
        let err = glue
            .on_output_fake(b"[sudo] password for alice: ", &fake)
            .unwrap_err();
        let rendered = format!("{err:?}{err}");
        assert!(rendered.contains("closing"));
        assert!(!rendered.contains("leak-me"));
        assert_eq!(glue.phase(), AutoSudoPhase::Done);
        assert!(!glue.has_password());
        // Elevation only — password never landed in the sink.
        assert_eq!(fake.writes_count(), 1);
        assert_eq!(fake.writes()[0], elev_bytes());
        assert!(!fake
            .writes()
            .iter()
            .any(|w| w.windows(7).any(|s| s == b"leak-me")));
    }

    #[test]
    fn crlf_terminated_prompt_injects_via_glue() {
        let mut glue = AutoSudoSessionGlue::new("pw");
        let fake = FakeTerminalSession::new();
        glue.on_output_fake(b"$ ", &fake).unwrap();
        let step = glue
            .on_output_fake(b"[sudo] password for alice: \r\n", &fake)
            .unwrap();
        assert_eq!(step, AutoSudoStep::SentPassword);
        assert_eq!(fake.writes()[1], line_bytes("pw"));
    }

    #[test]
    fn timeout_and_finish_are_idempotent_when_done() {
        let mut glue = AutoSudoSessionGlue::new("pw");
        let fake = FakeTerminalSession::new();
        glue.on_output_fake(b"banner", &fake).unwrap();
        assert_eq!(
            glue.on_timeout(),
            AutoSudoStep::FinishedWithoutPassword
        );
        assert_eq!(glue.on_timeout(), AutoSudoStep::Idle);
        glue.finish();
        assert_eq!(glue.phase(), AutoSudoPhase::Done);
        assert!(!glue.has_password());
        assert_eq!(
            glue.on_output_fake(b"Password: ", &fake).unwrap(),
            AutoSudoStep::Idle
        );
        assert_eq!(fake.writes_count(), 1);
    }

    #[test]
    fn dyn_terminal_path_sends_elevation() {
        let mut glue = AutoSudoSessionGlue::new("pw");
        let fake = FakeTerminalSession::new();
        let mut sink = FakeTerminalSink { session: &fake };
        let step = glue.on_output(b"shell", &mut sink).unwrap();
        assert_eq!(step, AutoSudoStep::SentElevation);
        assert_eq!(fake.writes()[0], elev_bytes().as_slice());
        assert!(fake.writes()[0].ends_with(&[LINE_TERMINATOR]));
        assert_eq!(
            std::str::from_utf8(&fake.writes()[0][..ELEVATION_COMMAND.len()]).unwrap(),
            ELEVATION_COMMAND
        );
    }

    #[test]
    fn finish_clears_secret() {
        let mut glue = AutoSudoSessionGlue::new("pw");
        glue.finish();
        assert_eq!(glue.phase(), AutoSudoPhase::Done);
        assert!(!glue.has_password());
    }
}
