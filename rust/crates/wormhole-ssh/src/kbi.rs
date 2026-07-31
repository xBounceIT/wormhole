//! Keyboard-interactive (KBI) multi-prompt Fake channel stub.
//!
//! Models the RFC 4256 / russh `InfoRequest` shape (name, instructions,
//! zero-or-more prompts with echo flags) so UI / session code can exercise
//! multi-prompt rounds offline.
//!
//! # Boundary vs [`crate::SshError::AuthNotImplemented`]
//!
//! - **Wire auth** — [`crate::SshAuthMethod::KeyboardInteractive`] still fails
//!   closed with [`crate::SshError::AuthNotImplemented`]
//!   (`"keyboard-interactive"`) in [`crate::ensure_auth_method_supported`] /
//!   [`crate::authenticate_with`] **before dial**. This module does **not**
//!   speak the SSH userauth wire protocol and does **not** clear that stub.
//! - **This glue** — answers scripted [`KbiInfoRequest`] rounds via
//!   [`KeyboardInteractiveChannel`] / [`FakeKbiChannel`]. Cancel and answer-
//!   count mismatch fail closed. LabOnly until a russh
//!   `authenticate_keyboard_interactive_*` path consumes these answers.
//!
//! No live SSH, no GPUI, no russh dependency (always on under
//! `--no-default-features`). [`Debug`] redacts answer strings.

use std::collections::VecDeque;
use std::fmt;

/// One prompt line from an SSH `USERAUTH_INFO_REQUEST` (RFC 4256).
///
/// Prompt **text** may appear in [`Debug`] (server-supplied labels). Answers
/// never live on this type.
#[derive(Clone, PartialEq, Eq)]
pub struct KbiPrompt {
    pub text: String,
    /// When `false`, the UI should treat the response as a secret (password /
    /// OTP-style). Echo is metadata only — this crate does not render UI.
    pub echo: bool,
}

impl KbiPrompt {
    pub fn new(text: impl Into<String>, echo: bool) -> Self {
        Self {
            text: text.into(),
            echo,
        }
    }

    /// Password / OTP style — echo off.
    pub fn secret(text: impl Into<String>) -> Self {
        Self::new(text, false)
    }

    /// Visible challenge (e.g. "Token serial") — echo on.
    pub fn visible(text: impl Into<String>) -> Self {
        Self::new(text, true)
    }
}

impl fmt::Debug for KbiPrompt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KbiPrompt")
            .field("text", &self.text)
            .field("echo", &self.echo)
            .finish()
    }
}

/// One InfoRequest round (may contain zero or more prompts).
///
/// Mirrors russh `KeyboardInteractiveAuthResponse::InfoRequest` fields without
/// depending on russh. Empty `prompts` is valid (server may send empty
/// requests); the matching response must be an empty answer list.
#[derive(Clone, PartialEq, Eq)]
pub struct KbiInfoRequest {
    pub name: String,
    pub instructions: String,
    pub prompts: Vec<KbiPrompt>,
}

impl KbiInfoRequest {
    pub fn new(
        name: impl Into<String>,
        instructions: impl Into<String>,
        prompts: impl IntoIterator<Item = KbiPrompt>,
    ) -> Self {
        Self {
            name: name.into(),
            instructions: instructions.into(),
            prompts: prompts.into_iter().collect(),
        }
    }

    pub fn prompt_count(&self) -> usize {
        self.prompts.len()
    }
}

impl fmt::Debug for KbiInfoRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KbiInfoRequest")
            .field("name", &self.name)
            .field("instructions", &self.instructions)
            .field("prompts", &self.prompts)
            .finish()
    }
}

/// Outcome of one KBI round from the UI / Fake channel.
///
/// [`Debug`] redacts answer payloads (`[REDACTED]` + length only).
#[derive(Clone, PartialEq, Eq)]
pub enum KbiRoundResponse {
    /// One answer per prompt, same order. Empty prompts → empty `Vec`.
    Answers(Vec<String>),
    /// User dismiss / Fake exhausted / Null — fail closed (no silent empty
    /// answers that could be mistaken for a successful round).
    Cancel,
}

impl KbiRoundResponse {
    pub fn answers(answers: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self::Answers(answers.into_iter().map(Into::into).collect())
    }
}

impl fmt::Debug for KbiRoundResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancel => f.write_str("Cancel"),
            Self::Answers(answers) => {
                let redacted: Vec<_> = answers
                    .iter()
                    .map(|a| {
                        if a.is_empty() {
                            "\"\"".to_string()
                        } else {
                            format!("[REDACTED len={}]", a.len())
                        }
                    })
                    .collect();
                f.debug_tuple("Answers").field(&redacted).finish()
            }
        }
    }
}

/// Why a KBI round failed closed (never carries answer bytes).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum KbiPromptError {
    /// User / Null / exhausted Fake cancelled the round.
    Cancelled,
    /// Answer count ≠ prompt count (hostile or buggy UI / Fake script).
    AnswerCountMismatch {
        expected: usize,
        actual: usize,
    },
}

impl KbiPromptError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cancelled => "keyboard-interactive prompt cancelled",
            Self::AnswerCountMismatch { .. } => {
                "keyboard-interactive answer count mismatch"
            }
        }
    }
}

impl fmt::Debug for KbiPromptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => f.write_str("Cancelled"),
            Self::AnswerCountMismatch { expected, actual } => f
                .debug_struct("AnswerCountMismatch")
                .field("expected", expected)
                .field("actual", actual)
                .finish(),
        }
    }
}

impl fmt::Display for KbiPromptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => f.write_str(self.as_str()),
            Self::AnswerCountMismatch { expected, actual } => {
                write!(
                    f,
                    "keyboard-interactive answer count mismatch: expected {expected}, got {actual}"
                )
            }
        }
    }
}

impl std::error::Error for KbiPromptError {}

/// Multi-prompt KBI answer channel (UI stub / Fake).
///
/// Implementations must not log answer bytes. Cancel and count mismatch are
/// fail-closed at [`answer_kbi_round`].
pub trait KeyboardInteractiveChannel: Send {
    fn respond_round(&mut self, request: &KbiInfoRequest) -> KbiRoundResponse;
}

/// Always cancels — fail-closed default until a real dialog is wired.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullKbiChannel;

impl KeyboardInteractiveChannel for NullKbiChannel {
    fn respond_round(&mut self, _request: &KbiInfoRequest) -> KbiRoundResponse {
        KbiRoundResponse::Cancel
    }
}

/// Scripted multi-round Fake for unit tests (no network / no UI).
///
/// Each [`respond_round`](FakeKbiChannel::respond_round) dequeues one scripted
/// [`KbiRoundResponse`]. Exhausted / empty script → [`KbiRoundResponse::Cancel`]
/// (fail closed). [`Debug`] redacts queued answers.
#[derive(Default)]
pub struct FakeKbiChannel {
    script: VecDeque<KbiRoundResponse>,
    seen: Vec<KbiInfoRequest>,
}

impl fmt::Debug for FakeKbiChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeKbiChannel")
            .field("script", &self.script)
            .field("rounds_seen", &self.seen.len())
            .finish()
    }
}

impl FakeKbiChannel {
    pub fn new() -> Self {
        Self::default()
    }

    /// Empty script → every round cancels (fail closed).
    pub fn cancel_all() -> Self {
        Self::new()
    }

    pub fn from_rounds(rounds: impl IntoIterator<Item = KbiRoundResponse>) -> Self {
        Self {
            script: rounds.into_iter().collect(),
            seen: Vec::new(),
        }
    }

    /// One round of answers (convenience for single InfoRequest tests).
    pub fn from_answers(answers: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self::from_rounds([KbiRoundResponse::answers(answers)])
    }

    pub fn push(&mut self, response: KbiRoundResponse) {
        self.script.push_back(response);
    }

    pub fn rounds_remaining(&self) -> usize {
        self.script.len()
    }

    pub fn requests_seen(&self) -> &[KbiInfoRequest] {
        &self.seen
    }
}

impl KeyboardInteractiveChannel for FakeKbiChannel {
    fn respond_round(&mut self, request: &KbiInfoRequest) -> KbiRoundResponse {
        self.seen.push(request.clone());
        self.script
            .pop_front()
            .unwrap_or(KbiRoundResponse::Cancel)
    }
}

/// Drive one InfoRequest round against a channel.
///
/// - [`KbiRoundResponse::Cancel`] → [`KbiPromptError::Cancelled`]
/// - Answer length ≠ `request.prompts.len()` →
///   [`KbiPromptError::AnswerCountMismatch`] (fail closed; answers dropped)
/// - Otherwise returns the answers (caller owns secret lifetime)
pub fn answer_kbi_round(
    channel: &mut impl KeyboardInteractiveChannel,
    request: &KbiInfoRequest,
) -> Result<Vec<String>, KbiPromptError> {
    match channel.respond_round(request) {
        KbiRoundResponse::Cancel => Err(KbiPromptError::Cancelled),
        KbiRoundResponse::Answers(answers) => {
            let expected = request.prompt_count();
            if answers.len() != expected {
                return Err(KbiPromptError::AnswerCountMismatch {
                    expected,
                    actual: answers.len(),
                });
            }
            Ok(answers)
        }
    }
}

/// Drive a sequence of InfoRequest rounds (multi-round KBI sessions).
///
/// Stops and fails closed on the first Cancel or count mismatch. Successful
/// return length equals `requests.len()`.
pub fn answer_kbi_rounds(
    channel: &mut impl KeyboardInteractiveChannel,
    requests: &[KbiInfoRequest],
) -> Result<Vec<Vec<String>>, KbiPromptError> {
    let mut out = Vec::with_capacity(requests.len());
    for request in requests {
        out.push(answer_kbi_round(channel, request)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn password_request() -> KbiInfoRequest {
        KbiInfoRequest::new(
            "Password",
            "Enter password for alice",
            [KbiPrompt::secret("Password: ")],
        )
    }

    fn dual_prompt_request() -> KbiInfoRequest {
        KbiInfoRequest::new(
            "2FA",
            "Enter password and OTP",
            [
                KbiPrompt::secret("Password: "),
                KbiPrompt::secret("OTP: "),
            ],
        )
    }

    #[test]
    fn null_channel_cancels() {
        let mut null = NullKbiChannel;
        let err = answer_kbi_round(&mut null, &password_request()).unwrap_err();
        assert_eq!(err, KbiPromptError::Cancelled);
        assert!(!err.to_string().contains("alice"));
    }

    #[test]
    fn fake_empty_script_cancels_fail_closed() {
        let mut fake = FakeKbiChannel::cancel_all();
        let err = answer_kbi_round(&mut fake, &password_request()).unwrap_err();
        assert_eq!(err, KbiPromptError::Cancelled);
        assert_eq!(fake.requests_seen().len(), 1);
        assert_eq!(fake.rounds_remaining(), 0);
    }

    #[test]
    fn fake_single_prompt_answers() {
        let mut fake = FakeKbiChannel::from_answers(["s3cret-NOT-FOR-LOG"]);
        let answers = answer_kbi_round(&mut fake, &password_request()).unwrap();
        assert_eq!(answers, vec!["s3cret-NOT-FOR-LOG"]);
        assert_eq!(fake.rounds_remaining(), 0);
    }

    #[test]
    fn fake_multi_prompt_one_round() {
        let mut fake = FakeKbiChannel::from_answers(["pw-value", "otp-999999"]);
        let answers = answer_kbi_round(&mut fake, &dual_prompt_request()).unwrap();
        assert_eq!(answers, vec!["pw-value", "otp-999999"]);
    }

    #[test]
    fn fake_multi_round_session() {
        let mut fake = FakeKbiChannel::from_rounds([
            KbiRoundResponse::answers(["first-pass"]),
            KbiRoundResponse::answers(["otp-123456"]),
        ]);
        let rounds = [
            password_request(),
            KbiInfoRequest::new("OTP", "Second factor", [KbiPrompt::secret("OTP: ")]),
        ];
        let all = answer_kbi_rounds(&mut fake, &rounds).unwrap();
        assert_eq!(all, vec![vec!["first-pass"], vec!["otp-123456"]]);
        assert_eq!(fake.requests_seen().len(), 2);
    }

    #[test]
    fn cancel_mid_multi_round_fail_closed() {
        let mut fake = FakeKbiChannel::from_rounds([
            KbiRoundResponse::answers(["first-pass"]),
            KbiRoundResponse::Cancel,
        ]);
        let rounds = [
            password_request(),
            KbiInfoRequest::new("OTP", "Second factor", [KbiPrompt::secret("OTP: ")]),
        ];
        let err = answer_kbi_rounds(&mut fake, &rounds).unwrap_err();
        assert_eq!(err, KbiPromptError::Cancelled);
        // First round was consumed; second recorded as seen then cancelled.
        assert_eq!(fake.requests_seen().len(), 2);
    }

    #[test]
    fn answer_count_mismatch_fail_closed() {
        let mut fake = FakeKbiChannel::from_answers(["only-one"]);
        let err = answer_kbi_round(&mut fake, &dual_prompt_request()).unwrap_err();
        assert_eq!(
            err,
            KbiPromptError::AnswerCountMismatch {
                expected: 2,
                actual: 1
            }
        );
        let msg = err.to_string();
        assert!(!msg.contains("only-one"));
    }

    #[test]
    fn empty_prompts_require_empty_answers() {
        let request = KbiInfoRequest::new("Continue", "Press enter", []);
        let mut ok = FakeKbiChannel::from_answers(std::iter::empty::<String>());
        assert!(answer_kbi_round(&mut ok, &request).unwrap().is_empty());

        let mut bad = FakeKbiChannel::from_answers(["unexpected"]);
        let err = answer_kbi_round(&mut bad, &request).unwrap_err();
        assert_eq!(
            err,
            KbiPromptError::AnswerCountMismatch {
                expected: 0,
                actual: 1
            }
        );
    }

    #[test]
    fn debug_redacts_answers_not_prompt_labels() {
        let response = KbiRoundResponse::answers(["super-secret-kbi"]);
        let rendered = format!("{response:?}");
        assert!(rendered.contains("[REDACTED"));
        assert!(rendered.contains("len=16"));
        assert!(!rendered.contains("super-secret-kbi"));

        let mut fake = FakeKbiChannel::from_answers(["super-secret-kbi"]);
        let dbg = format!("{fake:?}");
        assert!(!dbg.contains("super-secret-kbi"));
        assert!(dbg.contains("[REDACTED"));
        assert!(dbg.contains("rounds_seen"));
        // Consume so Debug of an empty script is also checked for no leak.
        let _ = answer_kbi_round(&mut fake, &password_request());
        assert!(!format!("{fake:?}").contains("super-secret-kbi"));

        let request = dual_prompt_request();
        let req_dbg = format!("{request:?}");
        assert!(req_dbg.contains("Password: "));
        assert!(req_dbg.contains("OTP: "));
        assert!(!req_dbg.contains("super-secret"));
    }

    #[test]
    fn unicode_answers_round_trip() {
        let mut fake = FakeKbiChannel::from_answers(["pässwörd-🔐"]);
        let answers = answer_kbi_round(&mut fake, &password_request()).unwrap();
        assert_eq!(answers, vec!["pässwörd-🔐"]);
        assert!(!format!("{:?}", KbiRoundResponse::answers(["pässwörd-🔐"]))
            .contains("pässwörd"));
    }

    #[test]
    fn answer_kbi_rounds_empty_slice_ok() {
        let mut fake = FakeKbiChannel::cancel_all();
        let all = answer_kbi_rounds(&mut fake, &[]).unwrap();
        assert!(all.is_empty());
        assert_eq!(fake.requests_seen().len(), 0);
    }

    #[test]
    fn seen_requests_preserve_echo_flags() {
        let mut fake = FakeKbiChannel::from_answers(["visible-token", "hidden-pass"]);
        let request = KbiInfoRequest::new(
            "Mixed",
            "one visible one secret",
            [
                KbiPrompt::visible("Token: "),
                KbiPrompt::secret("Password: "),
            ],
        );
        let _ = answer_kbi_round(&mut fake, &request).unwrap();
        let seen = &fake.requests_seen()[0];
        assert!(seen.prompts[0].echo);
        assert!(!seen.prompts[1].echo);
        let dbg = format!("{fake:?}");
        assert!(!dbg.contains("hidden-pass"));
        assert!(!dbg.contains("visible-token"));
    }

    #[test]
    fn error_display_has_no_answer_bytes() {
        let err = KbiPromptError::AnswerCountMismatch {
            expected: 2,
            actual: 1,
        };
        assert!(!format!("{err}").contains("password"));
        assert!(!format!("{err:?}").contains("s3cret"));
        assert_eq!(
            KbiPromptError::Cancelled.as_str(),
            "keyboard-interactive prompt cancelled"
        );
    }

    #[test]
    fn too_many_answers_fail_closed() {
        let mut fake = FakeKbiChannel::from_answers(["a", "b", "extra"]);
        let err = answer_kbi_round(&mut fake, &dual_prompt_request()).unwrap_err();
        assert_eq!(
            err,
            KbiPromptError::AnswerCountMismatch {
                expected: 2,
                actual: 3
            }
        );
    }

    #[test]
    fn scripted_cancel_response_fail_closed() {
        let mut fake = FakeKbiChannel::from_rounds([KbiRoundResponse::Cancel]);
        assert_eq!(
            answer_kbi_round(&mut fake, &password_request()).unwrap_err(),
            KbiPromptError::Cancelled
        );
    }

    #[test]
    fn empty_answer_string_is_allowed_when_count_matches() {
        // Server may ask for an empty response; empty ≠ Cancel.
        let mut fake = FakeKbiChannel::from_answers([""]);
        let answers = answer_kbi_round(&mut fake, &password_request()).unwrap();
        assert_eq!(answers, vec![""]);
        let dbg = format!("{:?}", KbiRoundResponse::answers([""]));
        assert!(dbg.contains("\"\""));
        assert!(!dbg.contains("[REDACTED"));
    }
}
