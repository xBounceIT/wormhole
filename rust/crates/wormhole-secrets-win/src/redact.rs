//! Logging redaction helpers — never emit secrets.
//!
//! Mirrors `BitwardenCliVaultClient.SanitizeError` patterns (case-insensitive).

/// Placeholder substituted for secret values.
pub const REDACTED: &str = "[redacted]";

/// Default truncate length for free-form log lines (matches Bitwarden CLI sanitize).
pub const REDACT_TRUNCATE_DEFAULT: usize = 500;

/// Always replace a known secret with [`REDACTED`]. Prefer this over logging the value.
#[inline]
pub fn redact_secret(_secret: &str) -> &'static str {
    REDACTED
}

/// Truncate a free-form string for logs (no secret-pattern scan).
///
/// Truncates by Unicode scalar values (not raw UTF-8 bytes) so multi-byte
/// characters never panic on a mid-code-unit slice.
pub fn redact_truncated(value: &str) -> String {
    let trimmed = value.trim();
    truncate_chars(trimmed, REDACT_TRUNCATE_DEFAULT)
}

/// Redact common CLI / env secret patterns (Bitwarden-style), then truncate.
///
/// Patterns match C# `BitwardenCliVaultClient.SanitizeError` (case-insensitive):
/// - `--session` / `--session=` value
/// - `BW_SESSION=` value (optional spaces around `=`)
/// - `--code` / `--code=` value
/// - `WORMHOLE_BW_PASSWORD=` value (optional spaces around `=`)
pub fn redact_env_and_cli_secrets(value: &str) -> String {
    let trimmed = value.trim();
    let mut out = trimmed.to_string();
    out = redact_flag_values(&out, "--session");
    out = redact_env_assignment(&out, "BW_SESSION");
    out = redact_flag_values(&out, "--code");
    out = redact_env_assignment(&out, "WORMHOLE_BW_PASSWORD");
    redact_truncated(&out)
}

fn truncate_chars(s: &str, max_chars: usize) -> String {
    match s.char_indices().nth(max_chars) {
        None => s.to_string(),
        Some((idx, _)) => s[..idx].to_string(),
    }
}

/// `(?i)(--session(?:\s+|=))\S+` → keep delimiter, replace value with `[redacted]`.
fn redact_flag_values(input: &str, flag: &str) -> String {
    let lower = input.to_ascii_lowercase();
    let flag_lower = flag.to_ascii_lowercase();
    let mut result = String::with_capacity(input.len());
    let mut cursor = 0;

    while let Some(rel) = lower[cursor..].find(&flag_lower) {
        let idx = cursor + rel;
        result.push_str(&input[cursor..idx]);
        result.push_str(&input[idx..idx + flag.len()]);

        let after_flag = idx + flag.len();
        let rest = &input[after_flag..];
        let delim_len = if rest.starts_with('=') {
            1
        } else if rest.starts_with(|c: char| c.is_whitespace()) {
            rest.chars().take_while(|c| c.is_whitespace()).map(char::len_utf8).sum()
        } else {
            // Flag substring without a following separator — keep as-is and resume after the flag.
            cursor = idx + flag.len();
            continue;
        };

        let after_delim = after_flag + delim_len;
        let value = &input[after_delim..];
        let value_end = value
            .find(|c: char| c.is_whitespace())
            .unwrap_or(value.len());
        // C# `\S+` requires a non-empty value; leave bare `--flag=` alone.
        if value_end == 0 {
            cursor = after_flag;
            continue;
        }

        result.push_str(&input[after_flag..after_delim]);
        result.push_str(REDACTED);
        cursor = after_delim + value_end;
    }
    result.push_str(&input[cursor..]);
    result
}

/// `(?i)(BW_SESSION(?:\s*=\s*))\S+` → keep `NAME` + `=` form, replace value.
fn redact_env_assignment(input: &str, name: &str) -> String {
    let lower = input.to_ascii_lowercase();
    let name_lower = name.to_ascii_lowercase();
    let mut result = String::with_capacity(input.len());
    let mut cursor = 0;

    while let Some(rel) = lower[cursor..].find(&name_lower) {
        let idx = cursor + rel;
        result.push_str(&input[cursor..idx]);
        result.push_str(&input[idx..idx + name.len()]);

        let after_name = idx + name.len();
        let rest = &input[after_name..];

        // Optional whitespace, required '=', optional whitespace.
        let mut pos = 0;
        let ws1: usize = rest[pos..]
            .chars()
            .take_while(|c| c.is_whitespace())
            .map(char::len_utf8)
            .sum();
        pos += ws1;
        if rest.get(pos..).is_none_or(|s| !s.starts_with('=')) {
            cursor = after_name;
            continue;
        }
        pos += 1; // '='
        let ws2: usize = rest[pos..]
            .chars()
            .take_while(|c| c.is_whitespace())
            .map(char::len_utf8)
            .sum();
        pos += ws2;

        let after_eq = after_name + pos;
        let value = &input[after_eq..];
        let value_end = value
            .find(|c: char| c.is_whitespace())
            .unwrap_or(value.len());
        // C# `\S+` requires a non-empty value; leave `NAME=` alone.
        if value_end == 0 {
            cursor = after_name;
            continue;
        }

        result.push_str(&input[after_name..after_eq]);
        result.push_str(REDACTED);
        cursor = after_eq + value_end;
    }
    result.push_str(&input[cursor..]);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_multiple_patterns() {
        let s = "err --session abc BW_SESSION=xyz --code 12 WORMHOLE_BW_PASSWORD=pw done";
        let out = redact_env_and_cli_secrets(s);
        assert_eq!(
            out,
            format!(
                "err --session {REDACTED} BW_SESSION={REDACTED} --code {REDACTED} WORMHOLE_BW_PASSWORD={REDACTED} done"
            )
        );
    }

    #[test]
    fn bare_equals_without_value_left_alone() {
        // Isolate each pattern so a following token is not consumed as `\S+`.
        assert_eq!(redact_env_and_cli_secrets("--session="), "--session=");
        assert_eq!(redact_env_and_cli_secrets("BW_SESSION="), "BW_SESSION=");
        assert_eq!(redact_env_and_cli_secrets("--code="), "--code=");
        assert_eq!(
            redact_env_and_cli_secrets("WORMHOLE_BW_PASSWORD="),
            "WORMHOLE_BW_PASSWORD="
        );
    }

    #[test]
    fn equals_forms_and_case_insensitive() {
        let s = "X --SESSION=secret1 bw_session = secret2 --Code=999 WORMHOLE_bw_PASSWORD=pw";
        let out = redact_env_and_cli_secrets(s);
        assert!(!out.to_ascii_lowercase().contains("secret"));
        assert!(!out.contains("999"));
        assert!(!out.contains("=pw") || out.contains(&format!("={REDACTED}")));
        assert!(out.contains(REDACTED));
        assert!(out.contains("--SESSION=") || out.contains("--SESSION"));
    }

    #[test]
    fn truncate_does_not_panic_on_multibyte_boundary() {
        // 400 × 'é' (2-byte UTF-8) ⇒ 800 bytes; truncate at 500 chars must be char-safe.
        let s: String = std::iter::repeat_n('é', 600).collect();
        let out = redact_truncated(&s);
        assert_eq!(out.chars().count(), REDACT_TRUNCATE_DEFAULT);
        assert!(std::str::from_utf8(out.as_bytes()).is_ok());
    }
}
