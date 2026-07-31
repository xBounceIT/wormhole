//! Transfer conflict overlay policy stub (pure Rust; Fake; no GPUI).
//!
//! Thin Lab glue mirroring C# `ConflictDecision` / `ConflictContext` /
//! `FileTransferDialog` inline overlay + orchestrator sticky `ApplyToAll`:
//! - Destination **missing** → [`ConflictOutcome::Proceed`] (no prompt)
//! - Destination **exists** → Skip / Overwrite / Rename / Cancel
//! - Empty / whitespace-only `item_name` or `destination_path` → fail closed
//! - Sticky apply-to-all only for [`ConflictDecision::Skip`] /
//!   [`ConflictDecision::Overwrite`] (C# parity). Rename needs a unique leaf;
//!   Cancel aborts the batch — neither sticks.
//! - Directory-at-destination is never an overwrite target here (C# skips
//!   conflict prompts for directory entries) — fail closed
//!
//! Lab keeps [`ConflictDecision::Cancel`] distinct from Skip (C# Cancel button
//! currently maps to Skip without apply-all). [`ConflictDecision::Rename`] is
//! Lab-forward for alternate leaf names; WinUI overlay buttons are Skip /
//! Overwrite / Cancel only today.
//!
//! No credentials on this surface. Display / Debug never echo secret-shaped text.

use std::collections::VecDeque;
use std::fmt;

use crate::path::is_safe_remote_name;

/// Overlay / resolver choice when a destination already exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConflictDecision {
    /// Leave the existing destination untouched; continue the batch.
    Skip,
    /// Replace the existing file at the destination path.
    Overwrite,
    /// Transfer under a different leaf name (see [`ConflictChoice::rename_to`]).
    Rename,
    /// Abort the remaining batch (distinct from Skip).
    Cancel,
}

impl ConflictDecision {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Skip => "skip",
            Self::Overwrite => "overwrite",
            Self::Rename => "rename",
            Self::Cancel => "cancel",
        }
    }

    /// Sticky apply-to-all is only meaningful for Skip / Overwrite.
    pub const fn may_stick(self) -> bool {
        matches!(self, Self::Skip | Self::Overwrite)
    }
}

/// Sanitized conflict prompt inputs (paths / sizes only — no credentials).
#[derive(Clone, PartialEq, Eq)]
pub struct ConflictContext {
    pub item_name: String,
    pub destination_path: String,
    pub incoming_size: Option<u64>,
    pub existing_size: Option<u64>,
    /// C# always passes `false` on the file conflict path; `true` fails closed.
    pub existing_is_directory: bool,
}

impl ConflictContext {
    pub fn new(
        item_name: impl Into<String>,
        destination_path: impl Into<String>,
        incoming_size: Option<u64>,
        existing_size: Option<u64>,
    ) -> Self {
        Self {
            item_name: item_name.into(),
            destination_path: destination_path.into(),
            incoming_size,
            existing_size,
            existing_is_directory: false,
        }
    }
}

impl fmt::Debug for ConflictContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConflictContext")
            .field("item_name", &self.item_name)
            .field("destination_path", &self.destination_path)
            .field("incoming_size", &self.incoming_size)
            .field("existing_size", &self.existing_size)
            .field("existing_is_directory", &self.existing_is_directory)
            .finish()
    }
}

/// One overlay answer (scripted Fake or host UI).
#[derive(Clone, PartialEq, Eq)]
pub struct ConflictChoice {
    pub decision: ConflictDecision,
    pub apply_to_all: bool,
    /// Required when [`ConflictDecision::Rename`]; ignored otherwise.
    pub rename_to: Option<String>,
}

impl ConflictChoice {
    pub fn skip(apply_to_all: bool) -> Self {
        Self {
            decision: ConflictDecision::Skip,
            apply_to_all,
            rename_to: None,
        }
    }

    pub fn overwrite(apply_to_all: bool) -> Self {
        Self {
            decision: ConflictDecision::Overwrite,
            apply_to_all,
            rename_to: None,
        }
    }

    pub fn rename(new_name: impl Into<String>) -> Self {
        Self {
            decision: ConflictDecision::Rename,
            apply_to_all: false,
            rename_to: Some(new_name.into()),
        }
    }

    pub fn cancel() -> Self {
        Self {
            decision: ConflictDecision::Cancel,
            apply_to_all: false,
            rename_to: None,
        }
    }
}

impl fmt::Debug for ConflictChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConflictChoice")
            .field("decision", &self.decision)
            .field("apply_to_all", &self.apply_to_all)
            .field("rename_to", &self.rename_to)
            .finish()
    }
}

/// Resolved action for one flattened transfer item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConflictOutcome {
    /// Destination free — transfer may proceed.
    Proceed,
    Skip,
    Overwrite,
    Rename { new_name: String },
    /// Stop processing further items in the batch.
    Cancel,
}

/// Failures from conflict policy validation / Fake prompt exhaustion.
///
/// Display / Debug never include credential-shaped text.
#[derive(Clone, PartialEq, Eq)]
pub enum ConflictOverlayError {
    /// Empty / whitespace-only item name or destination path.
    EmptyPath,
    /// Destination exists and is a directory (file conflict path refuse).
    ExistingDirectory,
    /// Rename without a safe non-empty leaf name.
    InvalidRename,
    /// `apply_to_all` requested for Rename / Cancel (cannot stick).
    InvalidSticky,
    /// Fake script exhausted (or host prompt cancelled without a choice).
    PromptExhausted,
}

impl fmt::Display for ConflictOverlayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPath => f.write_str("conflict path is empty"),
            Self::ExistingDirectory => f.write_str("destination is a directory"),
            Self::InvalidRename => f.write_str("invalid conflict rename"),
            Self::InvalidSticky => f.write_str("apply-to-all not allowed for this decision"),
            Self::PromptExhausted => f.write_str("conflict prompt exhausted"),
        }
    }
}

impl fmt::Debug for ConflictOverlayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPath => f.write_str("EmptyPath"),
            Self::ExistingDirectory => f.write_str("ExistingDirectory"),
            Self::InvalidRename => f.write_str("InvalidRename"),
            Self::InvalidSticky => f.write_str("InvalidSticky"),
            Self::PromptExhausted => f.write_str("PromptExhausted"),
        }
    }
}

impl std::error::Error for ConflictOverlayError {}

/// Host / Fake sink that answers one conflict prompt.
pub trait ConflictOverlayPrompt: Send {
    fn prompt(&mut self, ctx: &ConflictContext) -> Result<ConflictChoice, ConflictOverlayError>;
}

/// Scripted overlay answers for unit tests (no GPUI).
#[derive(Debug, Default)]
pub struct FakeConflictOverlay {
    script: VecDeque<ConflictChoice>,
    pub prompts: Vec<ConflictContext>,
}

impl FakeConflictOverlay {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn script(choices: impl IntoIterator<Item = ConflictChoice>) -> Self {
        Self {
            script: choices.into_iter().collect(),
            prompts: Vec::new(),
        }
    }

    pub fn push(&mut self, choice: ConflictChoice) {
        self.script.push_back(choice);
    }

    pub fn prompt_count(&self) -> usize {
        self.prompts.len()
    }
}

impl ConflictOverlayPrompt for FakeConflictOverlay {
    fn prompt(&mut self, ctx: &ConflictContext) -> Result<ConflictChoice, ConflictOverlayError> {
        self.prompts.push(ctx.clone());
        self.script
            .pop_front()
            .ok_or(ConflictOverlayError::PromptExhausted)
    }
}

/// Validate overlay context paths (trim-empty fails closed).
pub fn validate_conflict_context(ctx: &ConflictContext) -> Result<(), ConflictOverlayError> {
    if ctx.item_name.trim().is_empty() || ctx.destination_path.trim().is_empty() {
        return Err(ConflictOverlayError::EmptyPath);
    }
    Ok(())
}

/// Suggest an alternate leaf when the user/Fake picks Rename.
///
/// Inserts ` (1)` before the final extension (if any). Base must be a safe
/// remote name; empty / unsafe → `None` (caller fails closed).
pub fn suggest_rename_name(item_name: &str) -> Option<String> {
    let name = item_name.trim();
    if !is_safe_remote_name(name) {
        return None;
    }
    let (stem, ext) = match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() && !ext.is_empty() && !ext.contains('.') => {
            (stem, Some(ext))
        }
        _ => (name, None),
    };
    let suggested = match ext {
        Some(ext) => format!("{stem} (1).{ext}"),
        None => format!("{name} (1)"),
    };
    is_safe_remote_name(&suggested).then_some(suggested)
}

/// Resolve one item against destination existence + sticky apply-to-all.
///
/// `sticky` holds only Skip / Overwrite. Cancel clears any sticky. Rename never
/// writes sticky. Calling with `destination_exists == false` never prompts.
pub fn resolve_conflict_overlay(
    destination_exists: bool,
    ctx: &ConflictContext,
    sticky: &mut Option<ConflictDecision>,
    prompt: &mut dyn ConflictOverlayPrompt,
) -> Result<ConflictOutcome, ConflictOverlayError> {
    validate_conflict_context(ctx)?;

    if !destination_exists {
        return Ok(ConflictOutcome::Proceed);
    }

    if ctx.existing_is_directory {
        return Err(ConflictOverlayError::ExistingDirectory);
    }

    let choice = match *sticky {
        Some(decision) if decision.may_stick() => ConflictChoice {
            decision,
            apply_to_all: false,
            rename_to: None,
        },
        Some(_) => {
            // Defensive: foreign sticky values must not silently apply.
            *sticky = None;
            prompt.prompt(ctx)?
        }
        None => prompt.prompt(ctx)?,
    };

    apply_conflict_choice(choice, sticky)
}

/// Apply a choice and update sticky state (Skip / Overwrite only).
pub fn apply_conflict_choice(
    choice: ConflictChoice,
    sticky: &mut Option<ConflictDecision>,
) -> Result<ConflictOutcome, ConflictOverlayError> {
    if choice.apply_to_all && !choice.decision.may_stick() {
        return Err(ConflictOverlayError::InvalidSticky);
    }

    match choice.decision {
        ConflictDecision::Skip => {
            if choice.apply_to_all {
                *sticky = Some(ConflictDecision::Skip);
            }
            Ok(ConflictOutcome::Skip)
        }
        ConflictDecision::Overwrite => {
            if choice.apply_to_all {
                *sticky = Some(ConflictDecision::Overwrite);
            }
            Ok(ConflictOutcome::Overwrite)
        }
        ConflictDecision::Rename => {
            let raw = choice
                .rename_to
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or(ConflictOverlayError::InvalidRename)?;
            if !is_safe_remote_name(raw) {
                return Err(ConflictOverlayError::InvalidRename);
            }
            Ok(ConflictOutcome::Rename {
                new_name: raw.to_string(),
            })
        }
        ConflictDecision::Cancel => {
            *sticky = None;
            Ok(ConflictOutcome::Cancel)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(name: &str, dest: &str) -> ConflictContext {
        ConflictContext::new(name, dest, Some(10), Some(20))
    }

    #[test]
    fn missing_destination_proceeds_without_prompt() {
        let mut sticky = None;
        let mut fake = FakeConflictOverlay::script([ConflictChoice::overwrite(false)]);
        let out = resolve_conflict_overlay(false, &ctx("a.txt", "/r/a.txt"), &mut sticky, &mut fake)
            .unwrap();
        assert_eq!(out, ConflictOutcome::Proceed);
        assert_eq!(fake.prompt_count(), 0);
        assert!(sticky.is_none());
    }

    #[test]
    fn empty_paths_fail_closed() {
        let mut sticky = None;
        let mut fake = FakeConflictOverlay::new();
        for (name, dest) in [
            ("", "/r/a.txt"),
            ("   ", "/r/a.txt"),
            ("a.txt", ""),
            ("a.txt", "  \t  "),
            ("", ""),
        ] {
            let err = resolve_conflict_overlay(true, &ctx(name, dest), &mut sticky, &mut fake)
                .unwrap_err();
            assert_eq!(err, ConflictOverlayError::EmptyPath);
        }
        assert_eq!(fake.prompt_count(), 0);
    }

    #[test]
    fn existing_directory_fail_closed() {
        let mut sticky = None;
        let mut fake = FakeConflictOverlay::script([ConflictChoice::overwrite(false)]);
        let mut c = ctx("a.txt", "/r/a.txt");
        c.existing_is_directory = true;
        let err = resolve_conflict_overlay(true, &c, &mut sticky, &mut fake).unwrap_err();
        assert_eq!(err, ConflictOverlayError::ExistingDirectory);
        assert_eq!(fake.prompt_count(), 0);
    }

    #[test]
    fn skip_overwrite_rename_cancel_decisions() {
        let mut sticky = None;
        let mut fake = FakeConflictOverlay::script([
            ConflictChoice::skip(false),
            ConflictChoice::overwrite(false),
            ConflictChoice::rename("a (1).txt"),
            ConflictChoice::cancel(),
        ]);
        let c = ctx("a.txt", "/home/user/a.txt");

        assert_eq!(
            resolve_conflict_overlay(true, &c, &mut sticky, &mut fake).unwrap(),
            ConflictOutcome::Skip
        );
        assert_eq!(
            resolve_conflict_overlay(true, &c, &mut sticky, &mut fake).unwrap(),
            ConflictOutcome::Overwrite
        );
        assert_eq!(
            resolve_conflict_overlay(true, &c, &mut sticky, &mut fake).unwrap(),
            ConflictOutcome::Rename {
                new_name: "a (1).txt".into()
            }
        );
        assert_eq!(
            resolve_conflict_overlay(true, &c, &mut sticky, &mut fake).unwrap(),
            ConflictOutcome::Cancel
        );
        assert_eq!(fake.prompt_count(), 4);
    }

    #[test]
    fn apply_to_all_skip_suppresses_subsequent_prompts() {
        let mut sticky = None;
        let mut fake = FakeConflictOverlay::script([ConflictChoice::skip(true)]);
        let a = ctx("a.txt", "/r/a.txt");
        let b = ctx("b.txt", "/r/b.txt");

        assert_eq!(
            resolve_conflict_overlay(true, &a, &mut sticky, &mut fake).unwrap(),
            ConflictOutcome::Skip
        );
        assert_eq!(sticky, Some(ConflictDecision::Skip));
        assert_eq!(
            resolve_conflict_overlay(true, &b, &mut sticky, &mut fake).unwrap(),
            ConflictOutcome::Skip
        );
        assert_eq!(fake.prompt_count(), 1);
    }

    #[test]
    fn apply_to_all_overwrite_suppresses_subsequent_prompts() {
        let mut sticky = None;
        let mut fake = FakeConflictOverlay::script([ConflictChoice::overwrite(true)]);
        let a = ctx("a.txt", "/r/a.txt");
        let b = ctx("b.txt", "/r/b.txt");

        assert_eq!(
            resolve_conflict_overlay(true, &a, &mut sticky, &mut fake).unwrap(),
            ConflictOutcome::Overwrite
        );
        assert_eq!(
            resolve_conflict_overlay(true, &b, &mut sticky, &mut fake).unwrap(),
            ConflictOutcome::Overwrite
        );
        assert_eq!(fake.prompt_count(), 1);
    }

    #[test]
    fn rename_and_cancel_reject_apply_to_all() {
        let mut sticky = Some(ConflictDecision::Skip);
        assert_eq!(
            apply_conflict_choice(
                ConflictChoice {
                    decision: ConflictDecision::Rename,
                    apply_to_all: true,
                    rename_to: Some("x.txt".into()),
                },
                &mut sticky
            )
            .unwrap_err(),
            ConflictOverlayError::InvalidSticky
        );
        assert_eq!(
            apply_conflict_choice(
                ConflictChoice {
                    decision: ConflictDecision::Cancel,
                    apply_to_all: true,
                    rename_to: None,
                },
                &mut sticky
            )
            .unwrap_err(),
            ConflictOverlayError::InvalidSticky
        );
        // Sticky unchanged on InvalidSticky.
        assert_eq!(sticky, Some(ConflictDecision::Skip));
    }

    #[test]
    fn cancel_clears_sticky() {
        let mut sticky = Some(ConflictDecision::Overwrite);
        assert_eq!(
            apply_conflict_choice(ConflictChoice::cancel(), &mut sticky).unwrap(),
            ConflictOutcome::Cancel
        );
        assert!(sticky.is_none());
    }

    #[test]
    fn foreign_sticky_cleared_then_prompts() {
        let mut sticky = Some(ConflictDecision::Rename);
        let mut fake = FakeConflictOverlay::script([ConflictChoice::overwrite(false)]);
        let out =
            resolve_conflict_overlay(true, &ctx("a.txt", "/r/a.txt"), &mut sticky, &mut fake)
                .unwrap();
        assert_eq!(out, ConflictOutcome::Overwrite);
        assert_eq!(fake.prompt_count(), 1);
        assert!(sticky.is_none());
    }

    #[test]
    fn rename_via_suggest_helper() {
        let mut sticky = None;
        let name = suggest_rename_name("notes.md").expect("safe");
        let mut fake = FakeConflictOverlay::script([ConflictChoice::rename(name)]);
        let out =
            resolve_conflict_overlay(true, &ctx("notes.md", "/r/notes.md"), &mut sticky, &mut fake)
                .unwrap();
        assert_eq!(
            out,
            ConflictOutcome::Rename {
                new_name: "notes (1).md".into()
            }
        );
    }

    #[test]
    fn missing_destination_ignores_directory_flag() {
        let mut sticky = None;
        let mut fake = FakeConflictOverlay::new();
        let mut c = ctx("a.txt", "/r/a.txt");
        c.existing_is_directory = true;
        assert_eq!(
            resolve_conflict_overlay(false, &c, &mut sticky, &mut fake).unwrap(),
            ConflictOutcome::Proceed
        );
        assert_eq!(fake.prompt_count(), 0);
    }

    #[test]
    fn rename_requires_safe_non_empty_name() {
        let mut sticky = None;
        for bad in [None, Some("".into()), Some("   ".into()), Some("../x".into())] {
            let err = apply_conflict_choice(
                ConflictChoice {
                    decision: ConflictDecision::Rename,
                    apply_to_all: false,
                    rename_to: bad,
                },
                &mut sticky,
            )
            .unwrap_err();
            assert_eq!(err, ConflictOverlayError::InvalidRename);
        }
    }

    #[test]
    fn suggest_rename_inserts_before_extension() {
        assert_eq!(
            suggest_rename_name("report.txt").as_deref(),
            Some("report (1).txt")
        );
        assert_eq!(suggest_rename_name("README").as_deref(), Some("README (1)"));
        assert!(suggest_rename_name("").is_none());
        assert!(suggest_rename_name("a/b").is_none());
    }

    #[test]
    fn fake_prompt_exhausted_fail_closed() {
        let mut sticky = None;
        let mut fake = FakeConflictOverlay::new();
        let err =
            resolve_conflict_overlay(true, &ctx("a.txt", "/r/a.txt"), &mut sticky, &mut fake)
                .unwrap_err();
        assert_eq!(err, ConflictOverlayError::PromptExhausted);
        assert_eq!(fake.prompt_count(), 1);
    }

    #[test]
    fn errors_and_debug_omit_credential_shaped_text() {
        let err = ConflictOverlayError::InvalidRename;
        let text = format!("{err}{err:?}");
        assert!(!text.to_ascii_lowercase().contains("password"));
        assert!(!text.contains("hunter2"));

        let ctx = ConflictContext::new("secret-notes.txt", "/vault/secret-notes.txt", None, None);
        let dbg = format!("{ctx:?}");
        assert!(dbg.contains("secret-notes.txt"));
        assert!(!dbg.to_ascii_lowercase().contains("password"));
        assert!(!dbg.contains("credential"));
    }

    #[test]
    fn decision_as_str_stable() {
        assert_eq!(ConflictDecision::Skip.as_str(), "skip");
        assert_eq!(ConflictDecision::Overwrite.as_str(), "overwrite");
        assert_eq!(ConflictDecision::Rename.as_str(), "rename");
        assert_eq!(ConflictDecision::Cancel.as_str(), "cancel");
        assert!(ConflictDecision::Skip.may_stick());
        assert!(!ConflictDecision::Rename.may_stick());
        assert!(!ConflictDecision::Cancel.may_stick());
    }
}
