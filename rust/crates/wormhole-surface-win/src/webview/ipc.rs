//! IPC inbox helpers for wry WebView2 child hosts (gate 5).
//!
//! Keeps lab/runtime message handling bounded and safe to log.

/// Soft cap on queued page→host IPC strings (oldest dropped on overflow).
pub const IPC_INBOX_CAP: usize = 256;

/// Hard max bytes for a single IPC payload (reject / drop, do not queue).
pub const IPC_MAX_MESSAGE_BYTES: usize = 64 * 1024;

/// Bounded page→host message inbox with overflow accounting.
#[derive(Debug, Default)]
pub struct IpcInbox {
    messages: Vec<String>,
    dropped: u64,
}

impl IpcInbox {
    /// Empty inbox.
    pub fn new() -> Self {
        Self::default()
    }

    /// Messages dropped due to size or capacity pressure.
    pub fn dropped_count(&self) -> u64 {
        self.dropped
    }

    /// Push a message, enforcing size and capacity limits.
    pub fn push(&mut self, msg: String) {
        if msg.len() > IPC_MAX_MESSAGE_BYTES {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        if self.messages.len() >= IPC_INBOX_CAP {
            self.messages.remove(0);
            self.dropped = self.dropped.saturating_add(1);
        }
        self.messages.push(msg);
    }

    /// Drain all queued messages.
    pub fn drain(&mut self) -> Vec<String> {
        std::mem::take(&mut self.messages)
    }

    /// Current queue length (tests / diagnostics).
    pub fn len(&self) -> usize {
        self.messages.len()
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }
}

/// Summarize an IPC payload for logs — never echo terminal/clipboard bodies.
///
/// Terminal bridge frames (`d:`, `q:`, `b:`, `c:`, `paste…`) may contain
/// keystrokes, passwords pasted into the shell, or session output. Lab echo
/// stubs (`ready`, `echo:…`) remain printable with a length cap.
pub fn summarize_ipc_for_log(msg: &str) -> String {
    let kind = msg.split(':').next().unwrap_or("");
    let sensitive = matches!(
        kind,
        "d" | "q" | "b" | "c" | "a" | "r" | "p"
            | "paste"
            | "paste-begin"
            | "paste-chunk"
            | "paste-end"
            | "paste-cancel"
            | "paste-drain"
    ) || msg.starts_with("paste:");

    if sensitive {
        return format!("<{kind} frame, {} bytes>", msg.len());
    }

    const MAX: usize = 80;
    if msg.len() <= MAX {
        msg.to_string()
    } else {
        format!("{}… ({} bytes)", msg.chars().take(MAX).collect::<String>(), msg.len())
    }
}

/// Escape `s` as a JavaScript string literal (double-quoted) for `evaluate_script`.
///
/// Handles control chars and U+2028/U+2029 so host→page posts cannot break out
/// of the string or inject statements.
pub fn escape_js_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if c.is_control() => {
                let code = c as u32;
                if code <= 0xffff {
                    out.push_str(&format!("\\u{code:04x}"));
                } else {
                    // Non-BMP control is vanishingly rare; use \u{…} via surrogate-safe \uXXXX pairs.
                    let (hi, lo) = {
                        let v = code - 0x10000;
                        (0xD800 + (v >> 10), 0xDC00 + (v & 0x3FF))
                    };
                    out.push_str(&format!("\\u{hi:04x}\\u{lo:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inbox_caps_and_counts_overflow() {
        let mut inbox = IpcInbox::new();
        for i in 0..(IPC_INBOX_CAP + 10) {
            inbox.push(format!("m{i}"));
        }
        assert_eq!(inbox.len(), IPC_INBOX_CAP);
        assert_eq!(inbox.dropped_count(), 10);
        let drained = inbox.drain();
        assert_eq!(drained.first().map(String::as_str), Some("m10"));
        assert!(inbox.is_empty());
    }

    #[test]
    fn inbox_rejects_oversized_message() {
        let mut inbox = IpcInbox::new();
        let huge = "x".repeat(IPC_MAX_MESSAGE_BYTES + 1);
        inbox.push(huge);
        assert!(inbox.is_empty());
        assert_eq!(inbox.dropped_count(), 1);
    }

    #[test]
    fn redact_terminal_frames_for_log() {
        assert_eq!(
            summarize_ipc_for_log("d:1:2:cGFzc3dvcmQ="),
            "<d frame, 18 bytes>"
        );
        assert_eq!(
            summarize_ipc_for_log("b:1:u:c2VjcmV0"),
            "<b frame, 14 bytes>"
        );
        assert_eq!(
            summarize_ipc_for_log("paste:1:c2VjcmV0"),
            "<paste frame, 16 bytes>"
        );
        assert_eq!(
            summarize_ipc_for_log("paste-begin:1:0:12"),
            "<paste-begin frame, 18 bytes>"
        );
        assert_eq!(
            summarize_ipc_for_log("paste-chunk:1:c2VjcmV0"),
            "<paste-chunk frame, 22 bytes>"
        );
        assert_eq!(
            summarize_ipc_for_log("paste-drain:7"),
            "<paste-drain frame, 13 bytes>"
        );
        assert_eq!(summarize_ipc_for_log("ready"), "ready");
        assert_eq!(summarize_ipc_for_log("ready:80x24"), "ready:80x24");
        assert_eq!(summarize_ipc_for_log("echo:ping"), "echo:ping");
        assert_eq!(summarize_ipc_for_log("focus:1"), "focus:1");
    }

    #[test]
    fn escape_js_handles_quotes_newlines_and_line_separators() {
        let lit = escape_js_string("a'b\"c\n\u{2028}d");
        assert_eq!(lit, "\"a'b\\\"c\\n\\u2028d\"");
        // Must not leave a raw newline inside the literal.
        assert!(!lit.contains('\n'));
    }
}
