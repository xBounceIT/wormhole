//! RDP drive-redirect list parity — pure port of C# `Helpers/RdpDriveList.cs`.
//!
//! The persisted `RdpRedirectDrives` value is one of: `""` (no redirect), `"all"`
//! (redirect every fixed drive), or a comma/space/semicolon-separated upper-case
//! letter list like `"C,D,E"`. This module mirrors the C# helper so the canonical
//! form stays consistent across the editor (validate/normalise) and the connect
//! path (parse → per-letter DriveCollection). No `MsRdpClient` COM enumeration:
//! everything here is pure string → letters.
//!
//! Fail-closed letter rule (deliberate deviation from C# `char.ToUpperInvariant`):
//! a single token is a drive letter **only** when it is one ASCII `A`–`Z` after
//! upper-casing. Non-ASCII letters, control characters, digits, and multi-char
//! tokens are rejected (never silently mapped through Unicode uppercasing).
//!
//! | Raw input | `parse_drive_letters` | `validate_drive_list` | `normalise_drive_list` |
//! |---|---|---|---|
//! | `null` / `""` / whitespace | `Some([])` | error "Specify at least one drive letter" | `""` |
//! | `"all"` (any case, exact, untrimmed) | `None` | error "'all' is not a single drive letter." | `"all"` |
//! | `"C,D,E"` / `"c;d, e"` / `"C D"` | `Some(['C','D','E'])` | `Ok` | `"C,D,E"` |
//! | `"Z,A"` | `Some(['Z','A'])` | `Ok` | `"Z,A"` (input order preserved — **not** sorted) |
//! | `"C,C"` / `"c,C"` | `Some(['C'])` (dedupe) | error "Drive 'C' is listed more than once." | `"C"` |
//! | `"C,12"` / `"cf"` | junk token dropped → `Some(['C'])` / `Some([])` | error (`'12' is not a single drive letter.` / `'cf' is not a single drive letter.`) | junk dropped (`"C"` / `""`) |
//!
//! `parse_drive_letters` is the **tolerant** C#-parity shape (invalid tokens are
//! silently dropped); [`DriveLetters`] is the **strict** host-friendly wrapper
//! (any hostile input is an error). [`Debug`] never exposes anything but drive
//! letters.

use std::collections::BTreeSet;
use std::fmt;

/// C# `RdpDriveList.AllSentinel` — `"all"` redirect-every-fixed-drive token.
pub const DRIVE_LIST_ALL_SENTINEL: &str = "all";

/// Split into trimmed, non-empty tokens on C# separators `, ;` and space.
///
/// Mirrors `RdpDriveList.TryReadNextToken`: each raw chunk is trimmed (Unicode
/// whitespace) and empty chunks are skipped, so leading/trailing/consecutive
/// separators produce no phantom tokens.
fn iter_tokens(raw: &str) -> impl Iterator<Item = &str> {
    raw.split([',', ';', ' '])
        .map(str::trim)
        .filter(|t| !t.is_empty())
}

/// Single letter check. C# `TryParseLetter`: exactly one char, ASCII `A`–`Z`
/// after upper-casing. Fail-closed: non-ASCII / control / multi-char → `None`.
fn parse_letter_token(token: &str) -> Option<char> {
    let mut chars = token.chars();
    let ch = chars.next()?;
    if chars.next().is_some() {
        return None;
    }
    let upper = ch.to_ascii_uppercase();
    if upper.is_ascii_uppercase() {
        Some(upper)
    } else {
        None
    }
}

/// `RdpDriveList.ParseLetters(raw)` — tolerant parse into an upper-case letter list.
///
/// Parity with C#:
/// - `null` / `""` / whitespace-only → `Some(vec![])` (no letters).
/// - `"all"` (C# `OrdinalIgnoreCase`, on the exact raw value — **not** trimmed)
///   → `None`, so callers can distinguish "no letters" from "redirect everything".
/// - otherwise → invalid tokens silently dropped; result keeps first-occurrence
///   order, de-duplicated.
pub fn parse_drive_letters(raw: Option<&str>) -> Option<Vec<char>> {
    let raw = raw.unwrap_or("");
    if raw.trim().is_empty() {
        return Some(Vec::new());
    }
    if raw.eq_ignore_ascii_case(DRIVE_LIST_ALL_SENTINEL) {
        return None;
    }
    let mut seen: Vec<char> = Vec::with_capacity(4);
    for token in iter_tokens(raw) {
        if let Some(ch) = parse_letter_token(token) {
            if !seen.contains(&ch) {
                seen.push(ch);
            }
        }
    }
    Some(seen)
}

/// Error shape for [`validate_drive_list`] / [`DriveLetters::parse_strict`].
///
/// Carries a C# `RdpDriveList.Validate` message; `Debug`/`Display` expose letters
/// only (no credentials anywhere in this module).
#[derive(Clone, PartialEq, Eq)]
pub struct RdpDriveListError {
    kind: RdpDriveListErrorKind,
}

impl RdpDriveListError {
    /// Which validation rule failed (payload = offending token / letter).
    pub fn kind(&self) -> &RdpDriveListErrorKind {
        &self.kind
    }

    /// C#-exact error message for the editor InfoBar.
    pub fn message(&self) -> String {
        self.kind.message()
    }
}

impl fmt::Debug for RdpDriveListError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RdpDriveListError")
            .field(&self.kind.message())
            .finish()
    }
}

impl fmt::Display for RdpDriveListError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.kind.message())
    }
}

impl std::error::Error for RdpDriveListError {}

/// C# `RdpDriveList.Validate` rule that fired.
#[derive(Clone, PartialEq, Eq)]
pub enum RdpDriveListErrorKind {
    /// C#: empty / whitespace / no tokens →
    /// `"Specify at least one drive letter (e.g. C,D)."`
    SpecifyDrives,
    /// C#: token length ≠ 1 →
    /// `"'{p}' is not a single drive letter."` (`p` = token as entered).
    NotSingleLetter(String),
    /// C#: single char outside `A`–`Z` →
    /// `"'{p}' is not a drive letter (A-Z)."` (`p` = token as entered).
    NotLetter(String),
    /// C#: repeated letter → `"Drive '{ch}' is listed more than once."`
    /// (`ch` = upper-cased letter).
    Duplicate(char),
}

impl RdpDriveListErrorKind {
    /// C#-exact message text.
    pub fn message(&self) -> String {
        match self {
            Self::SpecifyDrives => {
                "Specify at least one drive letter (e.g. C,D).".to_string()
            }
            Self::NotSingleLetter(p) => format!("'{p}' is not a single drive letter."),
            Self::NotLetter(p) => format!("'{p}' is not a drive letter (A-Z)."),
            Self::Duplicate(ch) => format!("Drive '{ch}' is listed more than once."),
        }
    }
}

impl fmt::Debug for RdpDriveListErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RdpDriveListErrorKind")
            .field(&self.message())
            .finish()
    }
}

/// `RdpDriveList.Validate(raw)` — strict editor input validation.
///
/// `Ok(())` when every token is a single `A`–`Z` letter (after upper-casing) and
/// no letter repeats. Any other input — including `""` / whitespace and the
/// `"all"` sentinel — is an error. Message parity with C# via
/// [`RdpDriveListError::message`].
pub fn validate_drive_list(raw: &str) -> Result<(), RdpDriveListError> {
    let mut seen: Vec<char> = Vec::with_capacity(4);
    let mut found_any = false;
    for token in iter_tokens(raw) {
        found_any = true;
        // C# checks UTF-16 length (`p.Length != 1`), so an astral-plane single
        // char (surrogate pair, e.g. an emoji) is "not a single drive letter",
        // while a single BMP non-ASCII char falls through to the A-Z check.
        if token.encode_utf16().count() != 1 {
            return Err(RdpDriveListError {
                kind: RdpDriveListErrorKind::NotSingleLetter(token.to_string()),
            });
        }
        let ch = token.chars().next().expect("single char").to_ascii_uppercase();
        if !ch.is_ascii_uppercase() {
            return Err(RdpDriveListError {
                kind: RdpDriveListErrorKind::NotLetter(token.to_string()),
            });
        }
        if seen.contains(&ch) {
            return Err(RdpDriveListError {
                kind: RdpDriveListErrorKind::Duplicate(ch),
            });
        }
        seen.push(ch);
    }
    if !found_any {
        return Err(RdpDriveListError {
            kind: RdpDriveListErrorKind::SpecifyDrives,
        });
    }
    Ok(())
}

/// `RdpDriveList.Normalise(raw)` — canonical persisted form.
///
/// Parity with C#: `""`/whitespace → `""`; exact (untrimmed, case-insensitive)
/// `"all"` → `"all"`; otherwise comma-joined, upper-case, de-duplicated,
/// **preserving first-occurrence input order** (C# does **not** sort). Invalid
/// tokens are dropped.
pub fn normalise_drive_list(raw: &str) -> String {
    if raw.trim().is_empty() {
        return String::new();
    }
    if raw.eq_ignore_ascii_case(DRIVE_LIST_ALL_SENTINEL) {
        return DRIVE_LIST_ALL_SENTINEL.to_string();
    }
    let mut seen: Vec<char> = Vec::with_capacity(4);
    for token in iter_tokens(raw) {
        if let Some(ch) = parse_letter_token(token) {
            if !seen.contains(&ch) {
                seen.push(ch);
            }
        }
    }
    seen.iter()
        .map(char::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// Strict, upper-case `A`–`Z` drive-letter set — the fail-closed host wrapper.
///
/// Unlike the tolerant [`parse_drive_letters`], construction rejects **any**
/// hostile input (`""`/whitespace, `"all"`, non-ASCII letters, control chars,
/// digits, multi-char tokens, duplicates) via the same rules as
/// [`validate_drive_list`]. Consumable by the RDP display glue, e.g. mapped onto
/// `RedirectDrivesIntent::Letters` via [`Self::into_set`] for per-letter
/// `DriveCollection` filtering.
#[derive(Clone, PartialEq, Eq)]
pub struct DriveLetters {
    letters: BTreeSet<char>,
}

impl fmt::Debug for DriveLetters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DriveLetters(")?;
        for (i, ch) in self.letters.iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{ch}")?;
        }
        f.write_str(")")
    }
}

impl DriveLetters {
    /// Strict constructor (fail-closed): errors unless every token is a single
    /// `A`–`Z` letter and no letter repeats. Guarantees upper-case only.
    pub fn parse_strict(raw: &str) -> Result<Self, RdpDriveListError> {
        validate_drive_list(raw)?;
        let mut letters = BTreeSet::new();
        for token in iter_tokens(raw) {
            if let Some(ch) = parse_letter_token(token) {
                letters.insert(ch);
            }
        }
        Ok(Self { letters })
    }

    /// Sorted (`BTreeSet` order: `A ≤ B ≤ …`) upper-case letters.
    pub fn iter(&self) -> impl Iterator<Item = char> + '_ {
        self.letters.iter().copied()
    }

    /// Whether `ch` (any case) is in the set.
    pub fn contains(&self, ch: char) -> bool {
        self.letters.contains(&ch.to_ascii_uppercase())
    }

    /// Number of distinct letters.
    pub fn len(&self) -> usize {
        self.letters.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.letters.is_empty()
    }

    /// Consume into the backing sorted set (shape of
    /// `RedirectDrivesIntent::Letters`).
    pub fn into_set(self) -> BTreeSet<char> {
        self.letters
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- parse_drive_letters (C# ParseLetters parity) ----

    #[test]
    fn parse_null_and_empty_to_empty_vec() {
        assert_eq!(parse_drive_letters(None), Some(Vec::new()));
        assert_eq!(parse_drive_letters(Some("")), Some(Vec::new()));
        assert_eq!(parse_drive_letters(Some("   ")), Some(Vec::new()));
        assert_eq!(parse_drive_letters(Some("\t\r\n")), Some(Vec::new()));
    }

    #[test]
    fn parse_all_sentinel_is_none() {
        assert_eq!(parse_drive_letters(Some("all")), None);
        assert_eq!(parse_drive_letters(Some("ALL")), None);
        assert_eq!(parse_drive_letters(Some("AlL")), None);
        // Sentinel check is on the exact raw value (C# OrdinalIgnoreCase, no trim).
        assert_eq!(parse_drive_letters(Some(" all ")), Some(Vec::new()));
        assert_eq!(parse_drive_letters(Some("allx")), Some(Vec::new()));
    }

    #[test]
    fn parse_matches_csharp_table() {
        let cases: &[(&str, Option<Vec<char>>)] = &[
            ("C", Some(vec!['C'])),
            ("c", Some(vec!['C'])),
            ("C,D,E", Some(vec!['C', 'D', 'E'])),
            ("c;d;e", Some(vec!['C', 'D', 'E'])),
            ("C D E", Some(vec!['C', 'D', 'E'])),
            ("  C ,  d ; e ", Some(vec!['C', 'D', 'E'])),
            ("Z,A", Some(vec!['Z', 'A'])),
            // Dedupe keeps first occurrence.
            ("C,C,c", Some(vec!['C'])),
            // Invalid tokens are silently dropped (tolerant path).
            ("C,12,D", Some(vec!['C', 'D'])),
            ("cf", Some(vec![])),
            ("C,,D", Some(vec!['C', 'D'])),
            ("C,", Some(vec!['C'])),
            (",C", Some(vec!['C'])),
        ];
        for (raw, expected) in cases {
            assert_eq!(
                &parse_drive_letters(Some(raw)),
                expected,
                "parse_drive_letters({raw:?})"
            );
        }
    }

    #[test]
    fn parse_fail_closed_on_hostile_single_chars() {
        // Non-ASCII letters, digits, control chars never map into A-Z.
        assert_eq!(parse_drive_letters(Some("1")), Some(Vec::new()));
        assert_eq!(parse_drive_letters(Some("é")), Some(Vec::new()));
        assert_eq!(parse_drive_letters(Some("ß")), Some(Vec::new()));
        assert_eq!(parse_drive_letters(Some("ı")), Some(Vec::new()));
        assert_eq!(parse_drive_letters(Some("\u{1}")), Some(Vec::new()));
        assert_eq!(parse_drive_letters(Some("A;1")), Some(vec!['A']));
        // Astral-plane single char (C# UTF-16 length 2) is junk → dropped.
        assert_eq!(parse_drive_letters(Some("😀")), Some(Vec::new()));
        assert_eq!(parse_drive_letters(Some("A,😀")), Some(vec!['A']));
    }

    #[test]
    fn parse_internal_whitespace_is_not_a_separator() {
        // Tab / NBSP are not in the `, ; SPACE` separator set, so a run like
        // "A\tB" is one multi-char token and is dropped (C# same: `IndexOfAny`
        // only splits on `,` `;` and `' '`).
        assert_eq!(parse_drive_letters(Some("A\tB")), Some(Vec::new()));
        assert_eq!(parse_drive_letters(Some("A\u{00A0}B")), Some(Vec::new()));
        assert_eq!(parse_drive_letters(Some("A\tB,C")), Some(vec!['C']));
    }

    // ---- validate_drive_list (C# Validate parity) ----

    fn validate_err(raw: &str) -> String {
        match validate_drive_list(raw) {
            Ok(()) => panic!("expected Err for {raw:?}"),
            Err(e) => e.message(),
        }
    }

    #[test]
    fn validate_accepts_single_and_list() {
        for raw in ["C", "c", "C,D,E", "c;d;e", "C D E", "  C , d ; e "] {
            assert!(
                validate_drive_list(raw).is_ok(),
                "validate_drive_list({raw:?}) should be Ok"
            );
        }
    }

    #[test]
    fn validate_empty_whitespace_and_no_token() {
        let expected = "Specify at least one drive letter (e.g. C,D).";
        assert_eq!(validate_err(""), expected);
        assert_eq!(validate_err("   "), expected);
        assert_eq!(validate_err("\t\r\n"), expected);
    }

    #[test]
    fn validate_multi_char_token_message() {
        assert_eq!(
            validate_err("12"),
            "'12' is not a single drive letter."
        );
        assert_eq!(
            validate_err("cf"),
            "'cf' is not a single drive letter."
        );
        // "all" is not special in Validate.
        assert_eq!(
            validate_err("all"),
            "'all' is not a single drive letter."
        );
        // Padded sentinel is still a 3-char token → NotSingleLetter (never
        // treated as the sentinel; only the exact raw value is).
        assert_eq!(
            validate_err(" all "),
            "'all' is not a single drive letter."
        );
        // Tab / NBSP are not separators, so the whole run is one multi-char token.
        assert_eq!(
            validate_err("A\tB"),
            "'A\tB' is not a single drive letter."
        );
        assert_eq!(
            validate_err("A\u{00A0}B"),
            "'A\u{00A0}B' is not a single drive letter."
        );
    }

    #[test]
    fn validate_separator_only_and_padded() {
        let expected = "Specify at least one drive letter (e.g. C,D).";
        assert_eq!(validate_err(";"), expected);
        assert_eq!(validate_err(", ; ,"), expected);
    }

    #[test]
    fn validate_non_letter_message() {
        assert_eq!(
            validate_err("1"),
            "'1' is not a drive letter (A-Z)."
        );
        assert_eq!(
            validate_err("C,1"),
            "'1' is not a drive letter (A-Z)."
        );
        assert_eq!(
            validate_err("C;é"),
            "'é' is not a drive letter (A-Z)."
        );
    }

    #[test]
    fn validate_astral_char_is_not_single_letter_like_csharp() {
        // C# checks UTF-16 length, so an astral-plane single char (surrogate
        // pair) hits the "not a single drive letter" branch, not the A-Z one.
        assert_eq!(
            validate_err("😀"),
            "'😀' is not a single drive letter."
        );
        assert_eq!(
            validate_err("C,😀"),
            "'😀' is not a single drive letter."
        );
        let err = validate_drive_list("😀").expect_err("astral");
        assert!(matches!(
            err.kind(),
            RdpDriveListErrorKind::NotSingleLetter(p) if p == "😀"
        ));
    }

    #[test]
    fn validate_duplicate_message() {
        assert_eq!(
            validate_err("C,C"),
            "Drive 'C' is listed more than once."
        );
        assert_eq!(
            validate_err("c,C"),
            "Drive 'C' is listed more than once."
        );
        assert_eq!(
            validate_err("C;D; C"),
            "Drive 'C' is listed more than once."
        );
    }

    #[test]
    fn validate_longer_error_kind_and_debug_show_letters_only() {
        let err = validate_drive_list("C,cf").expect_err("multi-char");
        assert!(matches!(
            err.kind(),
            RdpDriveListErrorKind::NotSingleLetter(p) if p == "cf"
        ));
        let dbg = format!("{err:?}");
        assert!(dbg.contains("'cf' is not a single drive letter."));
        assert!(!dbg.contains("password"));
    }

    // ---- normalise_drive_list (C# Normalise parity) ----

    #[test]
    fn normalise_matches_csharp_table() {
        let cases: &[(&str, &str)] = &[
            ("", ""),
            ("   ", ""),
            ("all", "all"),
            ("ALL", "all"),
            ("AlL", "all"),
            (" all ", ""),
            ("C", "C"),
            ("c", "C"),
            ("C,D,E", "C,D,E"),
            ("c;d;e", "C,D,E"),
            ("C D E", "C,D,E"),
            ("  c , D ; e ", "C,D,E"),
            // Input order preserved, not sorted.
            ("Z,A", "Z,A"),
            ("C,B,A", "C,B,A"),
            // Dedupe keeps first occurrence.
            ("C,c,C", "C"),
            ("B,A,B", "B,A"),
            // Invalid tokens dropped.
            ("C,12,D", "C,D"),
            ("cf", ""),
            ("C,,D", "C,D"),
            ("C,", "C"),
            // Astral-plane single char is junk → dropped (normalise keeps letters).
            ("A,😀", "A"),
            ("😀", ""),
        ];
        for (raw, expected) in cases {
            assert_eq!(
                normalise_drive_list(raw),
                *expected,
                "normalise_drive_list({raw:?})"
            );
        }
    }

    // ---- DriveLetters (strict host wrapper) ----

    #[test]
    fn drive_letters_strict_accepts_letters_only() {
        let set = DriveLetters::parse_strict("c;D, e").expect("strict ok");
        assert_eq!(set.len(), 3);
        assert_eq!(set.iter().collect::<Vec<_>>(), vec!['C', 'D', 'E']);
        assert!(set.contains('c'));
        assert!(set.contains('D'));
        assert!(!set.contains('F'));
        assert!(!set.is_empty());
    }

    #[test]
    fn drive_letters_fail_closed_on_hostile_input() {
        for raw in ["", "   ", "all", "C,C", "12", "1", "é", "cf", "C\x01", "\u{1}", "😀"] {
            let res = DriveLetters::parse_strict(raw);
            assert!(res.is_err(), "DriveLetters::parse_strict({raw:?}) should fail");
            let _ = res.expect_err("checked").message();
        }
        let err = DriveLetters::parse_strict("😀").expect_err("astral");
        assert!(matches!(
            err.kind(),
            RdpDriveListErrorKind::NotSingleLetter(p) if p == "😀"
        ));
    }

    #[test]
    fn drive_letters_debug_is_letters_only() {
        let set = DriveLetters::parse_strict("D,C").expect("ok");
        assert_eq!(format!("{:?}", set), "DriveLetters(C, D)");
    }
}
