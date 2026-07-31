//! Auto-sudo password-prompt detector stub.
//!
//! Mirrors C# `Services/Ssh/SshAutoSudoDriver.cs` prompt recognition only:
//! after `sudo su` is sent, scan a bounded UTF-8 output tail for a line that
//! ends in a password prompt (`[Pp]assword…:`). This module **never** holds,
//! accepts, sends, or logs a password — callers supply secrets separately when
//! classification says [`SudoOutputClass::PasswordPrompt`].
//!
//! Session wiring (elevation + optional password inject via Fake/real terminal)
//! lives in [`crate::auto_sudo_glue`] — it **uses** this detector; it does not
//! reimplement prompt matching.

use std::fmt;

/// Elevation command the C# driver sends once the shell first produces output.
pub const ELEVATION_COMMAND: &str = "sudo su";

/// Max bytes retained in the rolling output tail (C# `TailCapacity`).
pub const TAIL_CAPACITY: usize = 512;

/// How long the full driver waits for a prompt before giving up (informational;
/// this stub does not arm timers).
pub const PROMPT_TIMEOUT_SECS: u64 = 10;

/// Classification of a terminal output sample for Auto sudo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SudoOutputClass {
    /// Ordinary shell / banner / command output — not a password prompt.
    Ordinary,
    /// Tail matches C# `PasswordPrompt` (`[Pp]assword[^\r\n]*:\s*$`).
    PasswordPrompt,
}

impl fmt::Display for SudoOutputClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ordinary => write!(f, "ordinary"),
            Self::PasswordPrompt => write!(f, "password-prompt"),
        }
    }
}

/// Classify a complete UTF-8 string (typically the rolling tail) against the
/// C# Auto sudo password-prompt regex.
///
/// The match is end-anchored so a login banner that merely mentions "password"
/// earlier cannot trip it. Callers should only invoke this **after** sending
/// [`ELEVATION_COMMAND`], matching the C# driver's scan window.
pub fn classify_sudo_output(text: &str) -> SudoOutputClass {
    if looks_like_password_prompt(text) {
        SudoOutputClass::PasswordPrompt
    } else {
        SudoOutputClass::Ordinary
    }
}

/// Classify a single logical line (no embedded `\r`/`\n` required).
pub fn classify_sudo_line(line: &str) -> SudoOutputClass {
    classify_sudo_output(line.trim_end_matches(['\r', '\n']))
}

/// Rolling UTF-8-ish byte tail used while waiting for the sudo password prompt.
///
/// Bytes are kept raw (lossy UTF-8 decode on classify) so multi-chunk PTY
/// output can complete a prompt that straddles reads. Secrets are never stored
/// here — only remote echo / prompts.
#[derive(Clone, Default)]
pub struct SudoPromptTail {
    buf: Vec<u8>,
}

impl SudoPromptTail {
    /// Empty tail with capacity hint.
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(TAIL_CAPACITY.min(64)),
        }
    }

    /// Append session output and trim to [`TAIL_CAPACITY`].
    pub fn append(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        self.buf.extend_from_slice(data);
        if self.buf.len() > TAIL_CAPACITY {
            let drop = self.buf.len() - TAIL_CAPACITY;
            self.buf.drain(..drop);
        }
    }

    /// Current tail as lossy UTF-8 (for classification only).
    ///
    /// Do not log the returned string — remote output may be sensitive even
    /// though this detector never receives a local password value.
    pub fn as_lossy_str(&self) -> String {
        String::from_utf8_lossy(&self.buf).into_owned()
    }

    /// Classify the current tail.
    pub fn classify(&self) -> SudoOutputClass {
        classify_sudo_output(&self.as_lossy_str())
    }

    /// Clear the buffer (C# `Finish` clears the tail when done).
    pub fn clear(&mut self) {
        self.buf.clear();
    }

    /// Bytes currently retained.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether the tail is empty.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

impl fmt::Debug for SudoPromptTail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never dump the raw tail (could include sensitive remote text).
        f.debug_struct("SudoPromptTail")
            .field("len", &self.buf.len())
            .field("class", &self.classify())
            .finish()
    }
}

/// C# `PasswordPrompt`: `[Pp]assword[^\r\n]*:\s*$` on the full tail string.
///
/// Mirrors .NET `$` without `RegexOptions.Multiline`: end-of-string **or**
/// immediately before a terminating `\n`. `\s` after the colon includes CR so
/// prompts that arrive as `Password: \r\n` still match (PTY CRLF).
fn looks_like_password_prompt(text: &str) -> bool {
    let s = text.strip_suffix('\n').unwrap_or(text);
    password_prompt_end_anchored(s)
}

fn password_prompt_end_anchored(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i + 8 <= bytes.len() {
        if is_password_word_at(bytes, i) {
            let after = &s[i + 8..];
            // Backtracking equivalent of `[^\r\n]*:\s*$`: any colon on the same
            // line whose remainder is only whitespace through EOS.
            for (rel, _) in after.match_indices(':') {
                let between = &after[..rel];
                if between.bytes().any(|b| b == b'\r' || b == b'\n') {
                    continue;
                }
                let trailing = &after[rel + 1..];
                if trailing.bytes().all(is_dotnet_ascii_whitespace) {
                    return true;
                }
            }
        }
        i += 1;
    }
    false
}

/// C# `[Pp]assword` — only the leading `P`/`p` is case-flexible; the rest is
/// lowercase `assword`.
fn is_password_word_at(bytes: &[u8], i: usize) -> bool {
    (bytes[i] == b'P' || bytes[i] == b'p') && &bytes[i + 1..i + 8] == b"assword"
}

/// .NET regex `\s` ASCII set (sufficient for PTY prompts; CultureInvariant).
fn is_dotnet_ascii_whitespace(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n' | 0x0B | 0x0C)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_classic_sudo_prompt() {
        assert_eq!(
            classify_sudo_line("[sudo] password for alice: "),
            SudoOutputClass::PasswordPrompt
        );
        assert_eq!(
            classify_sudo_line("[sudo] Password for root:"),
            SudoOutputClass::PasswordPrompt
        );
    }

    #[test]
    fn detects_prompt_with_trailing_crlf() {
        // PTY often ends the prompt line with CRLF before the next chunk.
        assert_eq!(
            classify_sudo_output("[sudo] password for alice: \r\n"),
            SudoOutputClass::PasswordPrompt
        );
        assert_eq!(
            classify_sudo_output("Password: \n"),
            SudoOutputClass::PasswordPrompt
        );
        assert_eq!(
            classify_sudo_output("Password: \r"),
            SudoOutputClass::PasswordPrompt
        );
        let mut tail = SudoPromptTail::new();
        tail.append(b"[sudo] password for alice: \r\n");
        assert_eq!(tail.classify(), SudoOutputClass::PasswordPrompt);
    }

    #[test]
    fn ignores_banner_mentioning_password_earlier() {
        let banner = "Authorized users only.\nYour password expires in 7 days.\n$ ";
        assert_eq!(classify_sudo_output(banner), SudoOutputClass::Ordinary);
    }

    #[test]
    fn ignores_mid_line_password_without_end_anchor() {
        assert_eq!(
            classify_sudo_output("set password=secret"),
            SudoOutputClass::Ordinary
        );
        assert_eq!(
            classify_sudo_output("Password: is wrong\n$ "),
            SudoOutputClass::Ordinary
        );
        assert_eq!(
            classify_sudo_line("pass: "),
            SudoOutputClass::Ordinary
        );
    }

    #[test]
    fn casing_matches_csharp_bracket_pp_assword() {
        assert_eq!(
            classify_sudo_line("Password:"),
            SudoOutputClass::PasswordPrompt
        );
        assert_eq!(
            classify_sudo_line("password:"),
            SudoOutputClass::PasswordPrompt
        );
        // C# `[Pp]assword` rejects non-lowercase "assword".
        assert_eq!(
            classify_sudo_line("PASSWORD:"),
            SudoOutputClass::Ordinary
        );
        assert_eq!(
            classify_sudo_line("PassWord:"),
            SudoOutputClass::Ordinary
        );
        assert_eq!(
            classify_sudo_line("[sudo] PASSWORD for root:"),
            SudoOutputClass::Ordinary
        );
    }

    #[test]
    fn substring_password_matches_like_csharp() {
        // C# `[Pp]assword` matches inside larger tokens (e.g. MyPassword).
        assert_eq!(
            classify_sudo_line("MyPassword: "),
            SudoOutputClass::PasswordPrompt
        );
        assert_eq!(
            classify_sudo_output("please enter your password now: "),
            SudoOutputClass::PasswordPrompt
        );
    }

    #[test]
    fn ignores_incomplete_password_word() {
        assert_eq!(classify_sudo_line("pass: "), SudoOutputClass::Ordinary);
        assert_eq!(classify_sudo_line("Password"), SudoOutputClass::Ordinary);
    }

    #[test]
    fn colon_backtracks_like_dotnet_regex() {
        // Greedy `[^\r\n]*` backtracks so the final `:` still matches `\s*$`.
        assert_eq!(
            classify_sudo_line("password: foo:"),
            SudoOutputClass::PasswordPrompt
        );
        assert_eq!(
            classify_sudo_line("password: foo: bar"),
            SudoOutputClass::Ordinary
        );
    }

    #[test]
    fn tail_detects_prompt_across_chunks() {
        let mut tail = SudoPromptTail::new();
        tail.append(b"[sudo] pass");
        assert_eq!(tail.classify(), SudoOutputClass::Ordinary);
        tail.append(b"word for u: ");
        assert_eq!(tail.classify(), SudoOutputClass::PasswordPrompt);
    }

    #[test]
    fn tail_trims_to_capacity() {
        let mut tail = SudoPromptTail::new();
        let big = vec![b'x'; TAIL_CAPACITY + 80];
        tail.append(&big);
        assert_eq!(tail.len(), TAIL_CAPACITY);
        // Prompt only in the kept window.
        tail.append(b"\nPassword: ");
        assert_eq!(tail.classify(), SudoOutputClass::PasswordPrompt);
    }

    #[test]
    fn tail_capacity_constant_is_512() {
        assert_eq!(TAIL_CAPACITY, 512);
    }

    #[test]
    fn debug_omits_raw_tail_bytes() {
        let mut tail = SudoPromptTail::new();
        tail.append(b"secret-looking-output Password: ");
        let dbg = format!("{tail:?}");
        assert!(dbg.contains("SudoPromptTail"));
        assert!(dbg.contains("password-prompt") || dbg.contains("PasswordPrompt"));
        assert!(!dbg.contains("secret-looking"));
        assert!(dbg.contains("len"));
    }

    #[test]
    fn elevation_command_matches_csharp() {
        assert_eq!(ELEVATION_COMMAND, "sudo su");
    }

    /// Detector APIs must not accept a password parameter (compile-time shape).
    #[test]
    fn classify_apis_have_no_password_parameter() {
        let _ = classify_sudo_line("[sudo] password for x: ");
        let _ = classify_sudo_output("Password: ");
        let mut t = SudoPromptTail::new();
        t.append(b"Password: ");
        let _ = t.classify();
    }
}
