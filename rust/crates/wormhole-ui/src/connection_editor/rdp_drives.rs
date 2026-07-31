//! RDP drive-redirect list validation / normalisation (`RdpDriveList`).

pub const ALL_SENTINEL: &str = "all";

/// Strict editor validation. Returns an error message or `None` when well-formed.
pub fn validate(raw: &str) -> Option<&'static str> {
    let tokens: Vec<_> = tokens(raw).collect();
    if tokens.is_empty() {
        return Some("Specify at least one drive letter (e.g. C,D).");
    }
    let mut seen = [false; 26];
    for token in tokens {
        if token.len() != 1 {
            return Some("Drive token is not a single letter.");
        }
        let ch = token.chars().next().unwrap().to_ascii_uppercase();
        if !ch.is_ascii_uppercase() {
            return Some("Drive letter must be A-Z.");
        }
        let idx = (ch as u8 - b'A') as usize;
        if seen[idx] {
            return Some("Duplicate drive letter.");
        }
        seen[idx] = true;
    }
    None
}

pub fn normalise(raw: &str) -> String {
    if raw.trim().is_empty() {
        return String::new();
    }
    if raw.eq_ignore_ascii_case(ALL_SENTINEL) {
        return ALL_SENTINEL.to_string();
    }
    let mut seen = [false; 26];
    let mut out = String::new();
    for token in tokens(raw) {
        if token.len() != 1 {
            continue;
        }
        let ch = token.chars().next().unwrap().to_ascii_uppercase();
        if !ch.is_ascii_uppercase() {
            continue;
        }
        let idx = (ch as u8 - b'A') as usize;
        if seen[idx] {
            continue;
        }
        seen[idx] = true;
        if !out.is_empty() {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

fn tokens(raw: &str) -> impl Iterator<Item = &str> {
    raw.split(|c| c == ',' || c == ';' || c == ' ')
        .map(str::trim)
        .filter(|t| !t.is_empty())
}
