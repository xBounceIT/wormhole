//! Credential binding service UI glue — pure state, no GPUI.
//!
//! Mirrors `Services/ConnectionCredentialBindingService.cs` + `Models/CredentialBindingMode.cs`
//! and the Inherit / None / Saved radio semantics of `ConnectionEditorViewModel` /
//! `FolderEditorViewModel`. The VM is pure state: it never holds passwords or secret bodies —
//! only credential *ids* and mode labels — so [`Debug`] cannot leak credentials.
//!
//! Fail-closed table (`ValidationReport`-shaped; the editor's own report type can't be
//! extended without touching its source file, so this local report carries the same
//! fail-closed spirit):
//!
//! | Condition | Result |
//! |---|---|
//! | `Inherit` selected with no parent context | error [`CredentialBindingError::InheritNeedsParent`] |
//! | `Inherit` selected where inheritance is unsupported (Quick Connect) | error [`CredentialBindingError::InheritUnavailable`] (C# collapses Inherit → None) |
//! | `Saved` selected with no credential | error [`CredentialBindingError::SavedNeedsCredential`] |
//! | `Saved` credential id is nil / a sentinel bucket id | error [`CredentialBindingError::CredentialIdInvalid`] |
//! | `Saved` id missing from the catalog (glue) | error [`CredentialBindingError::CredentialNotFound`] — dangling id never applies |
//! | empty / whitespace typed credential id | **fail closed** — never resolves to a selection; C# `ResolveCredentialForCommit` clear parity |
//! | leaf already binds an inline password + `Saved`/`Inherit` | error [`CredentialBindingError::InlineExcludesSavedBinding`] (C# `UseInlinePassword` suppresses the inherited/saved credential) |
//! | `None` on a node whose parent would otherwise resolve a credential | warning [`CredentialBindingWarning::NoneOverridesInheritedCredential`] (legal override — the resolver stops here with no credential) |
//!
//! Modes are mutually exclusive radio choices: switching modes clears the selected saved
//! id (C# picker sets `CredentialId = null` for Inherit/None) and any inline password flag
//! (C# `SaveCredentialBindingAsync` writes `UseInlinePassword = false`); choosing an inline
//! password clears the Saved/Inherit binding (`SaveInlinePasswordAsync` parity).
//!
//! Legacy (pre-migration `0012_credential_inheritance`) null-mode shapes are re-interpreted
//! by [`CredentialBindingVm::from_legacy`] exactly like the resolver: null mode + `Some(id)`
//! ⇒ `Saved`; null mode + no id ⇒ `Inherit` (persistent) / `None` (Quick Connect).
//!
//! Saved-credential catalog rows come from [`CredentialProfileSource`] /
//! [`FakeCredentialList`] (metadata only — re-used from [`crate::credential_picker`]);
//! no CredMgr / DPAPI reads here.
//!
//! `Debug` never contains credentials — there are none in the model, only ids / mode labels
//! / booleans, and the glue never echoes catalog rows.

use std::fmt;
use std::sync::Arc;

use uuid::Uuid;
use wormhole_domain::{CredentialBindingMode, CredentialBindingSentinelIds};

use crate::credential_picker::{
    profile_matches_query, CredentialPickerError, CredentialProfileRow, CredentialProfileSource,
    FakeCredentialList,
};

/// Parent folder context the binding can (or cannot) inherit from.
///
/// The host supplies this after inspecting the node's ancestor chain: a node with no parent
/// at all is `None`; a node whose parent exists but resolves no saved credential is
/// `NoCredential`; a node whose parent chain *does* resolve a saved credential is
/// `ResolvesCredential`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParentBindingContext {
    /// No parent — `Inherit` can resolve nothing.
    None,
    /// Parent chain exists but resolves no saved credential.
    NoCredential,
    /// Parent chain exists and resolves a saved credential the leaf can inherit.
    ResolvesCredential,
}

/// Deterministic validation failure from the binding VM / glue.
///
/// Mirrors the fail-closed spirit of [`crate::connection_editor::ValidationError`] — a
/// report with any of these is never applied as a binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialBindingError {
    /// `Inherit` selected but this context has no folder inheritance (Quick Connect).
    InheritUnavailable,
    /// `Inherit` selected on a node with no parent to inherit from.
    InheritNeedsParent,
    /// `Saved` selected without a saved credential id.
    SavedNeedsCredential,
    /// The selected id is empty (nil) or a sentinel bucket id — never a real credential.
    CredentialIdInvalid,
    /// The selected id does not exist in the catalog (deleted / never loaded).
    CredentialNotFound,
    /// A leaf inline password and a `Saved`/`Inherit` binding cannot coexist.
    InlineExcludesSavedBinding,
}

impl CredentialBindingError {
    /// UI-safe explanation for the error.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InheritUnavailable => {
                "Inherit is not available here — this context has no folder inheritance."
            }
            Self::InheritNeedsParent => {
                "Inherit requires a parent folder to inherit from; this node has no parent."
            }
            Self::SavedNeedsCredential => "Pick a saved credential for this binding.",
            Self::CredentialIdInvalid => "The selected credential id is empty or invalid.",
            Self::CredentialNotFound => {
                "The saved credential no longer exists — pick it again."
            }
            Self::InlineExcludesSavedBinding => {
                "An inline password and a saved/inherited binding cannot be used together."
            }
        }
    }
}

/// Non-fatal condition surfaced by validation (state stays valid).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialBindingWarning {
    /// `None` explicitly overrides a credential the parent would otherwise inherit.
    NoneOverridesInheritedCredential,
}

impl CredentialBindingWarning {
    /// UI-safe explanation for the warning.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoneOverridesInheritedCredential => {
                "This node's 'None' overrides the credential its parent would otherwise provide."
            }
        }
    }
}

/// Report mirroring [`crate::connection_editor::ValidationReport`]'s shape plus warnings.
///
/// Validity is fail-closed: any [`error`](CredentialBindingReport::errors) entry invalidates
/// the binding; warnings never do but are surfaced for the UI to explain.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CredentialBindingReport {
    /// Blocking errors (stable order — mirrors `ValidationReport.errors`).
    pub errors: Vec<CredentialBindingError>,
    /// Non-blocking conditions the UI may surface.
    pub warnings: Vec<CredentialBindingWarning>,
}

impl CredentialBindingReport {
    /// No errors — the binding may be planned/applied.
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }

    /// No errors and no warnings.
    pub fn is_clean(&self) -> bool {
        self.is_valid() && self.warnings.is_empty()
    }
}

/// What `CredentialBindingService.Save*` would persist — the pure node-field plan.
///
/// Mirrors C#: `Saved` → `CredentialMode = Saved` + id, `UseInlinePassword = false`;
/// `Inherit`/`None` → id cleared; inline → `CredentialMode = None`, id cleared, inline kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialBindingPlan {
    /// Binding mode for the node (`mode` + `credential_id` are the node fields to set).
    pub mode: CredentialBindingMode,
    /// Saved credential id when [`mode`](Self::mode) is `Saved`.
    pub credential_id: Option<Uuid>,
    /// Whether the leaf carries an inline password (`UseInlinePassword`).
    pub use_inline_password: bool,
}

/// Pure credential-binding radio state.
///
/// Modes are mutually exclusive; transitions clear conflicting sibling state (see module
/// docs). `Debug` contains only ids / mode labels — never credentials.
#[derive(Clone)]
pub struct CredentialBindingVm {
    /// Persistent tree edit (folder inheritance allowed) vs Quick Connect.
    pub supports_inheritance: bool,
    /// Parent context (`None` for a root / orphan node).
    pub parent: ParentBindingContext,
    /// Radio selection; `None` = no explicit choice yet (derive from legacy / effective).
    pub mode: Option<CredentialBindingMode>,
    /// Selected saved credential id (only meaningful for `Saved`).
    pub selected_credential_id: Option<Uuid>,
    /// The leaf already binds an inline password (SSH/RDP leaf-only) — excludes Saved/Inherit.
    pub use_inline_password: bool,
}

impl fmt::Debug for CredentialBindingVm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Explicit: mode labels / ids / booleans only. No secret-shaped field exists.
        f.debug_struct("CredentialBindingVm")
            .field("supports_inheritance", &self.supports_inheritance)
            .field("parent", &self.parent)
            .field("mode", &self.mode)
            .field("selected_credential_id", &self.selected_credential_id)
            .field("use_inline_password", &self.use_inline_password)
            .finish()
    }
}

impl CredentialBindingVm {
    /// New editor binding: `Inherit` when folder inheritance is supported, else `None`
    /// (C# `ConnectionEditorState::new` / `ConnectionEditorViewModel` default parity).
    pub fn new(supports_inheritance: bool, parent: ParentBindingContext) -> Self {
        Self {
            supports_inheritance,
            parent,
            mode: Some(if supports_inheritance {
                CredentialBindingMode::Inherit
            } else {
                CredentialBindingMode::None
            }),
            selected_credential_id: None,
            use_inline_password: false,
        }
    }

    /// Interpret a legacy (pre-migration `0012_credential_inheritance`) null-mode node.
    ///
    /// Mirrors `InheritanceResolver` / `ConnectionEditorViewModel.LoadFrom`: a present
    /// `credential_id` means `Saved` (with that id); otherwise `Inherit` when folder
    /// inheritance is supported, `None` for Quick Connect.
    ///
    /// Legacy nodes that already carry an inline password must be loaded through
    /// [`Self::set_inline_password`] (not `from_legacy` + a direct field write): a leaf inline
    /// password and a `Saved`/`Inherit` binding never coexist (exclusivity rule), and
    /// [`Self::validate`] rejects that combination fail-closed. Loading a null-mode, no-id
    /// inline node via `from_legacy` then `set_inline_password(true)` reproduces the `None` +
    /// inline shape C# writes on save.
    pub fn from_legacy(
        supports_inheritance: bool,
        parent: ParentBindingContext,
        credential_id: Option<Uuid>,
    ) -> Self {
        let mode = if credential_id.is_some() {
            CredentialBindingMode::Saved
        } else if supports_inheritance {
            CredentialBindingMode::Inherit
        } else {
            CredentialBindingMode::None
        };
        Self {
            supports_inheritance,
            parent,
            mode: Some(mode),
            selected_credential_id: credential_id,
            use_inline_password: false,
        }
    }

    /// C# `EffectiveCredentialMode` parity: an `Inherit` selection collapses to `None` when
    /// inheritance is unsupported (Quick Connect), and no explicit mode is derived from the
    /// legacy shape (id present ⇒ `Saved`, else `Inherit`/`None` by context).
    pub fn effective_mode(&self) -> CredentialBindingMode {
        let mode = match self.mode {
            Some(m) => m,
            None => {
                if self.selected_credential_id.is_some() {
                    CredentialBindingMode::Saved
                } else if self.supports_inheritance {
                    CredentialBindingMode::Inherit
                } else {
                    CredentialBindingMode::None
                }
            }
        };
        if !self.supports_inheritance && mode == CredentialBindingMode::Inherit {
            CredentialBindingMode::None
        } else {
            mode
        }
    }

    /// Radio switch. Modes are mutually exclusive: choosing `Inherit`/`None` clears the
    /// selected saved id (C# picker parity); choosing any mode clears the inline password
    /// (a binding and an inline password never coexist). `Saved` keeps the current selection
    /// — the caller picks one explicitly with [`select_credential`](Self::select_credential).
    pub fn select_mode(&mut self, mode: CredentialBindingMode) {
        self.mode = Some(mode);
        if mode != CredentialBindingMode::Saved {
            self.selected_credential_id = None;
        }
        self.use_inline_password = false;
    }

    /// Select a saved credential id (`SaveCredentialBindingAsync` parity): clears the inline
    /// password, and any id implies `Saved`. `None` clears the binding to an explicit `None`
    /// (the C# "(None) — prompt every time" sentinel path).
    pub fn select_credential(&mut self, id: Option<Uuid>) {
        self.selected_credential_id = id;
        self.use_inline_password = false;
        self.mode = Some(if id.is_some() {
            CredentialBindingMode::Saved
        } else {
            CredentialBindingMode::None
        });
    }

    /// Type-to-search commit for a saved credential id. Empty / whitespace / unparseable
    /// text **fails closed** to no selection and clears the binding to `None` (C#
    /// `ResolveCredentialForCommit` clear parity — an empty commit never binds).
    pub fn select_credential_id_from_text(&mut self, text: &str) {
        self.select_credential(parse_credential_id_text(text));
    }

    /// Leaf inline-password path (`SaveInlinePasswordAsync` parity): clears the Saved/Inherit
    /// binding and selects `None`, keeping the inline flag. Turning it off just clears the flag.
    pub fn set_inline_password(&mut self, inline: bool) {
        self.use_inline_password = inline;
        if inline {
            self.mode = Some(CredentialBindingMode::None);
            self.selected_credential_id = None;
        }
    }

    /// Pure validation — `Saved` id membership in a catalog is the glue's job (no source here).
    ///
    /// `Inherit`/`None`/`Saved` constrains the **raw** selection (a Quick Connect node that
    /// somehow holds an `Inherit` radio choice is rejected fail-closed rather than silently
    /// collapsed); [`effective_mode`](Self::effective_mode) still drives what gets written.
    pub fn validate(&self) -> CredentialBindingReport {
        let mut report = CredentialBindingReport::default();
        let primary = match self.mode {
            Some(m) => m,
            None => self.effective_mode(),
        };

        if self.use_inline_password
            && matches!(
                primary,
                CredentialBindingMode::Saved | CredentialBindingMode::Inherit
            )
        {
            // Unreachable via the transition helpers, but fail closed on hand-built /
            // loaded state so an inline password can never coexist with a binding.
            report
                .errors
                .push(CredentialBindingError::InlineExcludesSavedBinding);
        }

        match self.mode {
            Some(CredentialBindingMode::Inherit) => {
                if !self.supports_inheritance {
                    report
                        .errors
                        .push(CredentialBindingError::InheritUnavailable);
                } else if self.parent == ParentBindingContext::None {
                    report.errors.push(CredentialBindingError::InheritNeedsParent);
                }
            }
            Some(CredentialBindingMode::Saved) => {
                Self::check_saved(self, &mut report);
            }
            Some(CredentialBindingMode::None) => {
                if !self.use_inline_password
                    && self.parent == ParentBindingContext::ResolvesCredential
                {
                    report
                        .warnings
                        .push(CredentialBindingWarning::NoneOverridesInheritedCredential);
                }
            }
            None => {
                // No explicit choice — derive the legacy default (C# `EffectiveCredentialMode`)
                // and run the same checks that apply to the resolved mode.
                match self.effective_mode() {
                    CredentialBindingMode::Inherit => {
                        if self.parent == ParentBindingContext::None {
                            report
                                .errors
                                .push(CredentialBindingError::InheritNeedsParent);
                        }
                    }
                    CredentialBindingMode::Saved => Self::check_saved(self, &mut report),
                    CredentialBindingMode::None => {
                        if !self.use_inline_password
                            && self.parent == ParentBindingContext::ResolvesCredential
                        {
                            report.warnings.push(
                                CredentialBindingWarning::NoneOverridesInheritedCredential,
                            );
                        }
                    }
                }
            }
        }

        report
    }

    fn check_saved(&self, report: &mut CredentialBindingReport) {
        match self.selected_credential_id {
            None => report
                .errors
                .push(CredentialBindingError::SavedNeedsCredential),
            Some(id) if CredentialBindingSentinelIds::is_sentinel(id) => report
                .errors
                .push(CredentialBindingError::CredentialIdInvalid),
            Some(_) => {}
        }
    }

    /// Fail-closed validity: no errors means the binding may be applied.
    pub fn is_valid(&self) -> bool {
        self.validate().is_valid()
    }

    /// Plan the node fields to persist, or `None` when invalid (never plan an invalid binding).
    pub fn plan(&self) -> Option<CredentialBindingPlan> {
        if !self.is_valid() {
            return None;
        }
        let effective = self.effective_mode();
        Some(CredentialBindingPlan {
            mode: effective,
            credential_id: if effective == CredentialBindingMode::Saved {
                self.selected_credential_id
            } else {
                None
            },
            use_inline_password: self.use_inline_password,
        })
    }
}

/// Parse typed credential-id text into a `Uuid`.
///
/// Empty / whitespace / unparseable text **fails closed** to `None` — it can never select a
/// credential. (Whitespace-only ids are treated as "no credential", not as a lookup.)
pub fn parse_credential_id_text(text: &str) -> Option<Uuid> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        trimmed.parse().ok()
    }
}

/// Resolve picker commit text to a saved credential id (C# `ResolveCredentialForCommit`).
///
/// Exact case-insensitive name match wins; otherwise a **unique** case-insensitive substring
/// match on name / username / domain among non-sentinel rows; ambiguous / empty / whitespace
/// fails closed to `None`. Sentinel rows (a catalog seeded with the "(Inherit from folder)" /
/// "(None)" placeholders) never resolve here — this path selects **saved credentials only**,
/// so the returned id is always a real credential id or `None`. C# `ResolveExact` would match a
/// sentinel by name and route it to a mode via the picker setter; the Rust VM expresses mode
/// changes through [`CredentialBindingVm::select_mode`] instead, so the commit path stays
/// sentinel-free (fail-closed).
pub fn resolve_commit_credential<S: CredentialProfileSource + ?Sized>(
    source: &S,
    text: &str,
) -> Result<Option<Uuid>, CredentialPickerError> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let rows = source.list_all()?;
    let query_lower = trimmed.to_lowercase();

    // Exact match first (C# `ResolveExact`), sentinel-excluded and Unicode-aware to mirror
    // `StringComparison.OrdinalIgnoreCase` more closely than the ASCII-only comparison.
    if let Some(row) = rows.iter().find(|r| {
        !CredentialBindingSentinelIds::is_sentinel(r.id) && r.name.to_lowercase() == query_lower
    }) {
        return Ok(Some(row.id));
    }

    let subset: Vec<&CredentialProfileRow> = rows
        .iter()
        .filter(|r| {
            !CredentialBindingSentinelIds::is_sentinel(r.id)
                && profile_matches_query(r, trimmed)
        })
        .collect();
    match subset.as_slice() {
        [one] => Ok(Some(one.id)),
        _ => Ok(None),
    }
}

/// Fake-first binding glue: pure [`CredentialBindingVm`] state + a saved-credential catalog.
///
/// The glue adds the catalog-dependent rule the pure VM can't: a `Saved` id that no longer
/// exists in the catalog is rejected fail-closed ([`CredentialBindingError::CredentialNotFound`]),
/// and commit-text resolution is delegated to [`resolve_commit_credential`].
pub struct CredentialBindingGlue<S: CredentialProfileSource = Arc<FakeCredentialList>> {
    vm: CredentialBindingVm,
    source: S,
}

impl<S: CredentialProfileSource> CredentialBindingGlue<S> {
    /// Compose a VM with the saved-credential catalog source.
    pub fn new(vm: CredentialBindingVm, source: S) -> Self {
        Self { vm, source }
    }

    /// Borrow the pure VM state.
    pub fn vm(&self) -> &CredentialBindingVm {
        &self.vm
    }

    /// Mutable VM state (radio / inline / text transitions).
    pub fn vm_mut(&mut self) -> &mut CredentialBindingVm {
        &mut self.vm
    }

    /// Borrow the catalog source (hosts).
    pub fn source(&self) -> &S {
        &self.source
    }

    /// Validate VM state plus catalog membership for a `Saved` selection. A catalog load
    /// failure is an `Err` (fail closed — never report valid on an unknown catalog).
    pub fn validate(&self) -> Result<CredentialBindingReport, CredentialPickerError> {
        let mut report = self.vm.validate();
        if report.is_valid()
            && self.vm.effective_mode() == CredentialBindingMode::Saved
            && let Some(id) = self.vm.selected_credential_id
            && !CredentialBindingSentinelIds::is_sentinel(id)
        {
            let rows = self.source.list_all()?;
            if !rows.iter().any(|r| r.id == id) {
                report.errors.push(CredentialBindingError::CredentialNotFound);
            }
        }
        Ok(report)
    }

    /// Fail-closed validity against the catalog (never true on a catalog error).
    pub fn is_valid(&self) -> Result<bool, CredentialPickerError> {
        Ok(self.validate()?.is_valid())
    }

    /// Plan the node fields, or `None` when invalid (catalog-aware).
    pub fn plan(&self) -> Result<Option<CredentialBindingPlan>, CredentialPickerError> {
        if !self.validate()?.is_valid() {
            return Ok(None);
        }
        Ok(self.vm.plan())
    }

    /// Resolve typed picker commit text against the catalog and apply the selection.
    ///
    /// C# `CommitCredential` parity: empty / whitespace text clears to the picker's null
    /// behavior; a resolved name selects that credential (`Saved`); text that matches nothing
    /// unambiguous leaves the current selection untouched (the stray text is a revert, never
    /// a destructive un-bind). Returns whether a credential was selected.
    pub fn select_credential_by_commit_key(
        &mut self,
        text: &str,
    ) -> Result<bool, CredentialPickerError> {
        let trimmed = text.trim();
        let id = resolve_commit_credential(&self.source, text)?;
        if trimmed.is_empty() {
            self.vm.select_credential(None);
            return Ok(false);
        }
        if let Some(id) = id {
            self.vm.select_credential(Some(id));
            return Ok(true);
        }
        Ok(false)
    }
}

impl<S: CredentialProfileSource> fmt::Debug for CredentialBindingGlue<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never echo catalog rows (names can look secret-shaped); VM has ids/labels only.
        f.debug_struct("CredentialBindingGlue")
            .field("vm", &self.vm)
            .field("source", &"<CredentialProfileSource>")
            .finish()
    }
}

impl CredentialBindingGlue<Arc<FakeCredentialList>> {
    /// Lab harness over the shared Fake catalog (tests / headless demos).
    ///
    /// `supports_inheritance` + `parent` seed the VM via [`CredentialBindingVm::new`]; the
    /// returned lab shares the catalog with the glue so tests can seed / mutate rows.
    pub fn with_fake_lab(
        supports_inheritance: bool,
        parent: ParentBindingContext,
    ) -> (Self, FakeCredentialBindingLab) {
        let vm = CredentialBindingVm::new(supports_inheritance, parent);
        let store = Arc::new(FakeCredentialList::new());
        let glue = Self::new(vm, Arc::clone(&store));
        (glue, FakeCredentialBindingLab { store })
    }
}

impl CredentialProfileSource for Arc<FakeCredentialList> {
    fn list_all(&self) -> Result<Vec<CredentialProfileRow>, CredentialPickerError> {
        (**self).list_all()
    }
}

/// Shared Fake catalog handle for the binding glue lab.
///
/// `Debug` is deliberately opaque — the catalog is metadata, but we never let a Debug dump
/// echo row names (defense in depth, matching the rest of the Fake glue modules).
pub struct FakeCredentialBindingLab {
    /// Shared Fake catalog the glue resolves `Saved` ids against.
    pub store: Arc<FakeCredentialList>,
}

impl fmt::Debug for FakeCredentialBindingLab {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeCredentialBindingLab").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(bytes: [u8; 16]) -> Uuid {
        Uuid::from_bytes(bytes)
    }

    /// Stable (deterministic) credential ids for tests.
    const CRED_A_BYTES: [u8; 16] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
        0x01,
    ];
    const CRED_B_BYTES: [u8; 16] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
        0x02,
    ];
    const CRED_C_BYTES: [u8; 16] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
        0x03,
    ];

    fn cred_a() -> CredentialProfileRow {
        CredentialProfileRow::new(id(CRED_A_BYTES), "prod-db", Some("alice".into()), None)
    }

    fn cred_b() -> CredentialProfileRow {
        CredentialProfileRow::new(id(CRED_B_BYTES), "prd-backup", Some("bob".into()), None)
    }

    #[test]
    fn inherit_without_parent_is_rejected() {
        let vm = CredentialBindingVm::new(true, ParentBindingContext::None);
        assert_eq!(vm.mode, Some(CredentialBindingMode::Inherit));
        let report = vm.validate();
        assert!(!report.is_valid());
        assert_eq!(
            report.errors,
            vec![CredentialBindingError::InheritNeedsParent]
        );
        assert_eq!(
            CredentialBindingError::InheritNeedsParent.as_str(),
            "Inherit requires a parent folder to inherit from; this node has no parent."
        );
    }

    #[test]
    fn inherit_rejected_when_inheritance_unsupported() {
        // Quick Connect: no folder inheritance, even with a resolving parent.
        let vm = CredentialBindingVm::new(
            false,
            ParentBindingContext::ResolvesCredential,
        );
        let mut vm = vm;
        vm.select_mode(CredentialBindingMode::Inherit);
        assert_eq!(vm.effective_mode(), CredentialBindingMode::None);
        let report = vm.validate();
        assert!(!report.is_valid());
        assert_eq!(
            report.errors,
            vec![CredentialBindingError::InheritUnavailable]
        );
    }

    #[test]
    fn inherit_valid_with_resolving_parent() {
        let vm = CredentialBindingVm::new(true, ParentBindingContext::ResolvesCredential);
        let report = vm.validate();
        assert!(report.is_valid());
        assert!(report.is_clean());
        let plan = vm.plan().expect("valid inherit plans");
        assert_eq!(plan.mode, CredentialBindingMode::Inherit);
        assert_eq!(plan.credential_id, None);
        assert!(!plan.use_inline_password);
    }

    #[test]
    fn inherit_valid_with_parent_that_resolves_nothing() {
        // A parent chain exists but no credential resolves: Inherit still walks the chain
        // and (like C#) resolves to "prompt every time" — not an error.
        let vm = CredentialBindingVm::new(true, ParentBindingContext::NoCredential);
        let report = vm.validate();
        assert!(report.is_valid());
        assert!(report.is_clean());
    }

    #[test]
    fn saved_without_selection_is_rejected() {
        let mut vm = CredentialBindingVm::new(true, ParentBindingContext::NoCredential);
        vm.select_mode(CredentialBindingMode::Saved);
        assert_eq!(vm.selected_credential_id, None);
        let report = vm.validate();
        assert!(!report.is_valid());
        assert_eq!(
            report.errors,
            vec![CredentialBindingError::SavedNeedsCredential]
        );
    }

    #[test]
    fn saved_with_sentinel_or_nil_id_is_rejected() {
        let mut vm = CredentialBindingVm::new(true, ParentBindingContext::NoCredential);
        // nil = CredentialBindingSentinelIds::CONNECTION_NONE ("empty" id).
        vm.select_credential(Some(Uuid::nil()));
        let report = vm.validate();
        assert!(!report.is_valid());
        assert_eq!(report.errors, vec![CredentialBindingError::CredentialIdInvalid]);

        // The Inherit sentinel must never be accepted as a real saved selection.
        let mut vm = CredentialBindingVm::new(true, ParentBindingContext::NoCredential);
        vm.select_credential(Some(CredentialBindingSentinelIds::INHERIT));
        assert_eq!(
            vm.validate().errors,
            vec![CredentialBindingError::CredentialIdInvalid]
        );
    }

    #[test]
    fn saved_valid_with_selected_credential() {
        let mut vm = CredentialBindingVm::new(true, ParentBindingContext::NoCredential);
        vm.select_mode(CredentialBindingMode::Saved);
        vm.select_credential(Some(id(CRED_A_BYTES)));
        let report = vm.validate();
        assert!(report.is_valid());
        assert!(report.is_clean());
        let plan = vm.plan().expect("valid saved plans");
        assert_eq!(plan.mode, CredentialBindingMode::Saved);
        assert_eq!(plan.credential_id, Some(id(CRED_A_BYTES)));
        assert!(!plan.use_inline_password);
    }

    #[test]
    fn empty_or_whitespace_id_text_fails_closed() {
        // The parse helper can never hand back a credential for whitespace.
        assert_eq!(parse_credential_id_text(""), None);
        assert_eq!(parse_credential_id_text("   "), None);
        assert_eq!(parse_credential_id_text("\t\n"), None);
        assert_eq!(parse_credential_id_text("not-a-guid"), None);
        // And a whitespace commit clears to None — flesh never gets bound by empty text.
        let mut vm = CredentialBindingVm::new(true, ParentBindingContext::NoCredential);
        vm.select_credential(Some(id(CRED_A_BYTES)));
        vm.select_credential_id_from_text("   ");
        assert_eq!(vm.selected_credential_id, None);
        assert_eq!(vm.mode, Some(CredentialBindingMode::None));
        // The result is a clean "None" binding, not a bogus Saved with an empty id.
        assert!(vm.validate().is_clean());
        // A nil GUID typed as text is still rejected as an invalid id under Saved.
        let mut vm = CredentialBindingVm::new(true, ParentBindingContext::NoCredential);
        vm.select_mode(CredentialBindingMode::Saved);
        vm.select_credential_id_from_text("00000000-0000-0000-0000-000000000000");
        assert_eq!(
            vm.validate().errors,
            vec![CredentialBindingError::CredentialIdInvalid]
        );
    }

    #[test]
    fn none_without_parent_is_clean() {
        let mut vm = CredentialBindingVm::new(false, ParentBindingContext::None);
        vm.select_mode(CredentialBindingMode::None);
        let report = vm.validate();
        assert!(report.is_valid());
        assert!(report.is_clean());
    }

    #[test]
    fn none_overrides_inherited_parent_warns() {
        let mut vm = CredentialBindingVm::new(true, ParentBindingContext::ResolvesCredential);
        vm.select_mode(CredentialBindingMode::None);
        let report = vm.validate();
        assert!(report.is_valid());
        assert!(!report.is_clean());
        assert_eq!(
            report.warnings,
            vec![CredentialBindingWarning::NoneOverridesInheritedCredential]
        );
        // Legal: a plan is still produced.
        assert!(vm.plan().is_some());
    }

    #[test]
    fn none_override_warning_suppressed_when_inline_password() {
        // C# `UseInlinePassword` suppresses the inherited credential by design — not a
        // deliberate None-vs-inherit conflict, so no warning.
        let mut vm = CredentialBindingVm::new(true, ParentBindingContext::ResolvesCredential);
        vm.set_inline_password(true);
        assert_eq!(vm.effective_mode(), CredentialBindingMode::None);
        let report = vm.validate();
        assert!(report.is_valid());
        assert!(report.is_clean());
    }

    #[test]
    fn mode_switch_radio_clears_sibling_state() {
        let mut vm = CredentialBindingVm::new(true, ParentBindingContext::ResolvesCredential);
        vm.select_credential(Some(id(CRED_A_BYTES)));
        assert_eq!(vm.mode, Some(CredentialBindingMode::Saved));
        assert_eq!(vm.selected_credential_id, Some(id(CRED_A_BYTES)));

        // Switching to Inherit / None clears the saved id (C# picker sets CredentialId = null).
        vm.select_mode(CredentialBindingMode::Inherit);
        assert_eq!(vm.selected_credential_id, None);
        vm.select_credential(Some(id(CRED_A_BYTES)));
        vm.select_mode(CredentialBindingMode::None);
        assert_eq!(vm.selected_credential_id, None);
        assert_eq!(vm.mode, Some(CredentialBindingMode::None));

        // Switching to Saved keeps the (explicit) selection — the caller picks it.
        vm.select_mode(CredentialBindingMode::Saved);
        vm.select_credential(Some(id(CRED_A_BYTES)));
        assert_eq!(vm.selected_credential_id, Some(id(CRED_A_BYTES)));
    }

    #[test]
    fn radio_journey_is_mutually_exclusive_end_to_end() {
        // The full radio lifecycle on a persistent node: every transition keeps the state
        // valid (or fail-closed invalid only when the caller must still supply a Saved id),
        // and sibling state is always cleared — no mode ever coexists with another.
        let mut vm = CredentialBindingVm::new(true, ParentBindingContext::ResolvesCredential);
        assert_eq!(vm.mode, Some(CredentialBindingMode::Inherit));
        assert!(vm.is_valid());

        // Inherit -> Saved: pick an id; the inline flag was already clear.
        vm.select_mode(CredentialBindingMode::Saved);
        assert_eq!(vm.selected_credential_id, None);
        assert!(!vm.is_valid()); // Saved still needs a credential.
        vm.select_credential(Some(id(CRED_A_BYTES)));
        assert!(vm.is_valid());
        assert_eq!(vm.plan().map(|p| p.credential_id), Some(Some(id(CRED_A_BYTES))));

        // Saved -> inline: mode collapses to None, id cleared, inline set.
        vm.set_inline_password(true);
        assert_eq!(vm.mode, Some(CredentialBindingMode::None));
        assert_eq!(vm.selected_credential_id, None);
        assert!(vm.use_inline_password);
        assert!(vm.is_valid());
        assert!(vm.plan().map(|p| p.use_inline_password) == Some(true));

        // Inline -> Saved again: a mode switch clears the inline flag (exclusivity both ways).
        vm.select_mode(CredentialBindingMode::Saved);
        assert!(!vm.use_inline_password);
        assert!(!vm.is_valid()); // no id picked yet — fail-closed, not a half-applied binding.
        vm.select_credential(Some(id(CRED_A_BYTES)));
        assert!(vm.is_valid());

        // Saved -> None: id cleared, explicit None on a resolving parent is a legal override.
        vm.select_mode(CredentialBindingMode::None);
        assert_eq!(vm.selected_credential_id, None);
        assert!(vm.is_valid());
        assert_eq!(
            vm.validate().warnings,
            vec![CredentialBindingWarning::NoneOverridesInheritedCredential]
        );
        let plan = vm.plan().expect("None override still plans");
        assert_eq!(plan.mode, CredentialBindingMode::None);
        assert_eq!(plan.credential_id, None);

        // None -> Inherit round-trip: back to a clean inherit.
        vm.select_mode(CredentialBindingMode::Inherit);
        assert_eq!(vm.mode, Some(CredentialBindingMode::Inherit));
        assert!(vm.validate().is_clean());
    }

    #[test]
    fn selecting_credential_clears_inline_password() {
        let mut vm = CredentialBindingVm::new(true, ParentBindingContext::NoCredential);
        vm.set_inline_password(true);
        assert!(vm.validate().is_clean());
        vm.select_credential(Some(id(CRED_A_BYTES)));
        assert!(!vm.use_inline_password);
        assert_eq!(vm.mode, Some(CredentialBindingMode::Saved));
        assert!(vm.validate().is_valid());
    }

    #[test]
    fn inline_password_clears_saved_binding() {
        let mut vm = CredentialBindingVm::new(true, ParentBindingContext::NoCredential);
        vm.select_credential(Some(id(CRED_A_BYTES)));
        assert_eq!(vm.mode, Some(CredentialBindingMode::Saved));
        vm.set_inline_password(true);
        assert_eq!(vm.mode, Some(CredentialBindingMode::None));
        assert_eq!(vm.selected_credential_id, None);
        assert!(vm.use_inline_password);
        let plan = vm.plan().expect("inline plans");
        assert_eq!(plan.mode, CredentialBindingMode::None);
        assert_eq!(plan.credential_id, None);
        assert!(plan.use_inline_password);
    }

    #[test]
    fn inline_and_saved_cannot_coexist() {
        // Hand-built hostile/loaded state: the transitions never reach it, but validation
        // still fails closed.
        let mut vm = CredentialBindingVm::new(true, ParentBindingContext::NoCredential);
        vm.mode = Some(CredentialBindingMode::Saved);
        vm.selected_credential_id = Some(id(CRED_A_BYTES));
        vm.use_inline_password = true;
        let report = vm.validate();
        assert!(!report.is_valid());
        assert_eq!(
            report.errors,
            vec![CredentialBindingError::InlineExcludesSavedBinding]
        );
        assert_eq!(vm.plan(), None);
    }

    #[test]
    fn legacy_null_mode_with_id_means_saved() {
        let vm = CredentialBindingVm::from_legacy(
            true,
            ParentBindingContext::NoCredential,
            Some(id(CRED_A_BYTES)),
        );
        assert_eq!(vm.mode, Some(CredentialBindingMode::Saved));
        assert_eq!(vm.selected_credential_id, Some(id(CRED_A_BYTES)));
        assert!(vm.validate().is_valid());
    }

    #[test]
    fn legacy_null_mode_without_id_means_inherit() {
        let vm = CredentialBindingVm::from_legacy(true, ParentBindingContext::NoCredential, None);
        assert_eq!(vm.mode, Some(CredentialBindingMode::Inherit));
        assert!(vm.validate().is_valid());
    }

    #[test]
    fn legacy_null_mode_quick_connect_without_id_means_none() {
        let vm = CredentialBindingVm::from_legacy(
            false,
            ParentBindingContext::NoCredential,
            None,
        );
        assert_eq!(vm.mode, Some(CredentialBindingMode::None));
        assert!(vm.validate().is_valid());
    }

    #[test]
    fn plan_fails_closed_for_invalid_state() {
        let mut vm = CredentialBindingVm::new(true, ParentBindingContext::None);
        vm.select_mode(CredentialBindingMode::Inherit);
        assert!(!vm.is_valid());
        assert_eq!(vm.plan(), None);

        let mut vm = CredentialBindingVm::new(true, ParentBindingContext::NoCredential);
        vm.select_mode(CredentialBindingMode::Saved);
        assert_eq!(vm.plan(), None);
    }

    #[test]
    fn glue_rejects_dangling_saved_credential() {
        let (glue, _lab) = CredentialBindingGlue::with_fake_lab(
            true,
            ParentBindingContext::NoCredential,
        );
        let mut glue = glue;
        glue.vm_mut().select_credential(Some(id(CRED_A_BYTES)));
        let report = glue.validate().expect("catalog load succeeds");
        assert!(!report.is_valid());
        assert_eq!(report.errors, vec![CredentialBindingError::CredentialNotFound]);
        assert_eq!(glue.is_valid().expect("no error"), false);
        assert_eq!(glue.plan().expect("no error"), None);
    }

    #[test]
    fn glue_accepts_catalog_saved_credential() {
        let (glue, lab) =
            CredentialBindingGlue::with_fake_lab(true, ParentBindingContext::NoCredential);
        lab.store.set_profiles([cred_a()]);
        let mut glue = glue;
        glue.vm_mut().select_mode(CredentialBindingMode::Saved);
        glue.vm_mut().select_credential(Some(id(CRED_A_BYTES)));
        let report = glue.validate().expect("catalog load succeeds");
        assert!(report.is_valid());
        assert_eq!(report.warnings, vec![]);
        let plan = glue.plan().expect("catalog resolves").expect("valid plan");
        assert_eq!(plan.credential_id, Some(id(CRED_A_BYTES)));
        assert_eq!(plan.mode, CredentialBindingMode::Saved);

        // A selected id that is dropped from the catalog afterwards fails closed.
        lab.store.set_profiles([]);
        assert_eq!(
            glue.validate().expect("load ok").errors,
            vec![CredentialBindingError::CredentialNotFound]
        );
    }

    #[test]
    fn glue_source_error_fails_closed() {
        let (glue, lab) =
            CredentialBindingGlue::with_fake_lab(true, ParentBindingContext::NoCredential);
        lab.store.set_profiles([cred_a()]);
        let mut glue = glue;
        glue.vm_mut().select_mode(CredentialBindingMode::Saved);
        glue.vm_mut().select_credential(Some(id(CRED_A_BYTES)));

        let failing = FakeCredentialList::failing("catalog down");
        let glue = CredentialBindingGlue::new(glue.vm().clone(), failing);
        assert!(matches!(
            glue.validate(),
            Err(CredentialPickerError::Load(_))
        ));
        // Never "valid" on an unknown catalog.
        assert!(glue.is_valid().is_err());
    }

    #[test]
    fn commit_resolution_exact_name() {
        let source = FakeCredentialList::with_profiles([cred_a(), cred_b()]);
        // Case-insensitive exact name match wins over the substring that would also match.
        assert_eq!(
            resolve_commit_credential(&source, "PROD-DB").unwrap(),
            Some(id(CRED_A_BYTES))
        );
    }

    #[test]
    fn commit_resolution_unique_substring() {
        let source = FakeCredentialList::with_profiles([cred_b(), cred_a()]);
        // "back" uniquely matches prd-backup.
        assert_eq!(
            resolve_commit_credential(&source, "back").unwrap(),
            Some(id(CRED_B_BYTES))
        );
    }

    #[test]
    fn commit_resolution_ambiguous_fails_closed() {
        let source = FakeCredentialList::with_profiles([cred_a(), cred_b()]);
        // "pr" matches both prod-db and prd-backup -> ambiguous, never binds.
        assert_eq!(resolve_commit_credential(&source, "pr").unwrap(), None);
    }

    #[test]
    fn commit_resolution_whitespace_fails_closed() {
        let source = FakeCredentialList::with_profiles([cred_a(), cred_b()]);
        assert_eq!(resolve_commit_credential(&source, "").unwrap(), None);
        assert_eq!(resolve_commit_credential(&source, "   ").unwrap(), None);
        // Empty commit text never selects a credential through the glue either.
        let (glue, lab) =
            CredentialBindingGlue::with_fake_lab(true, ParentBindingContext::NoCredential);
        lab.store.set_profiles([cred_a()]);
        let mut glue = glue;
        let selected = glue
            .select_credential_by_commit_key("   ")
            .expect("load ok");
        assert!(!selected);
        assert_eq!(glue.vm().selected_credential_id, None);
        assert_eq!(glue.vm().mode, Some(CredentialBindingMode::None));
    }

    #[test]
    fn commit_resolution_matches_username_and_domain() {
        // C# `Matches` looks at Name / Username / Domain — a unique username or domain
        // fragment commits too, not just the name.
        let mut source = FakeCredentialList::with_profiles([
            cred_a(),
            cred_b(),
            CredentialProfileRow::new(
                id(CRED_C_BYTES),
                "legacy",
                None,
                Some("CORP.local".into()),
            ),
        ]);
        assert_eq!(
            resolve_commit_credential(&source, "alice").unwrap(),
            Some(id(CRED_A_BYTES))
        );
        assert_eq!(
            resolve_commit_credential(&source, "BOB").unwrap(),
            Some(id(CRED_B_BYTES))
        );
        assert_eq!(
            resolve_commit_credential(&source, "prd").unwrap(),
            Some(id(CRED_B_BYTES))
        );
        // "corp" matches the domain-only row (nothing else) -> unique, resolves.
        assert_eq!(
            resolve_commit_credential(&source, "corp").unwrap(),
            Some(id(CRED_C_BYTES))
        );
        // "pr" still hits both names (prod-db / prd-backup) -> ambiguous.
        assert_eq!(resolve_commit_credential(&source, "pr").unwrap(), None);
        // A non-ASCII exact name must still match case-insensitively (OrdinalIgnoreCase parity).
        source.set_profiles([CredentialProfileRow::new(
            id(CRED_A_BYTES),
            "café",
            None,
            None,
        )]);
        assert_eq!(
            resolve_commit_credential(&source, "CAFÉ").unwrap(),
            Some(id(CRED_A_BYTES))
        );
    }

    #[test]
    fn commit_resolution_never_returns_sentinel_rows() {
        // A catalog seeded with the picker placeholders must not resolve to a sentinel id —
        // the commit path is saved-credentials-only, so a sentinel name never becomes a
        // `Saved` binding (which validation would reject as CredentialIdInvalid).
        let source = FakeCredentialList::with_profiles([
            cred_a(),
            CredentialProfileRow::new(
                CredentialBindingSentinelIds::INHERIT,
                "(Inherit from folder)",
                None,
                None,
            ),
            CredentialProfileRow::new(
                CredentialBindingSentinelIds::CONNECTION_NONE,
                "(None — prompt every time)",
                None,
                None,
            ),
        ]);
        assert_eq!(
            resolve_commit_credential(&source, "(Inherit from folder)").unwrap(),
            None
        );
        assert_eq!(
            resolve_commit_credential(&source, "(None — prompt every time)").unwrap(),
            None
        );
        assert_eq!(
            resolve_commit_credential(&source, "(none)").unwrap(),
            None
        );
        // Real rows still resolve next to the placeholders.
        assert_eq!(
            resolve_commit_credential(&source, "prod-db").unwrap(),
            Some(id(CRED_A_BYTES))
        );
    }

    #[test]
    fn glue_commit_no_match_keeps_current_selection() {
        // C# `CommitCredential` reverts text that matches nothing unambiguous — the current
        // selection is preserved, never destructively cleared to None.
        let (glue, lab) =
            CredentialBindingGlue::with_fake_lab(true, ParentBindingContext::NoCredential);
        lab.store.set_profiles([cred_a()]);
        let mut glue = glue;
        glue.vm_mut().select_credential(Some(id(CRED_A_BYTES)));
        assert!(glue.vm().is_valid());

        let selected = glue
            .select_credential_by_commit_key("no-such-credential")
            .expect("load ok");
        assert!(!selected);
        assert_eq!(glue.vm().selected_credential_id, Some(id(CRED_A_BYTES)));
        assert_eq!(glue.vm().mode, Some(CredentialBindingMode::Saved));
        assert!(glue.vm().is_valid());
    }

    #[test]
    fn glue_plan_fails_closed_on_catalog_error() {
        let failing = FakeCredentialList::failing("catalog down");
        let vm = CredentialBindingVm::new(true, ParentBindingContext::NoCredential);
        let mut vm = vm;
        vm.select_mode(CredentialBindingMode::Saved);
        vm.select_credential(Some(id(CRED_A_BYTES)));
        let glue = CredentialBindingGlue::new(vm, failing);
        assert!(matches!(glue.plan(), Err(CredentialPickerError::Load(_))));
        assert!(matches!(glue.is_valid(), Err(CredentialPickerError::Load(_))));
    }

    #[test]
    fn legacy_null_mode_with_sentinel_id_fails_closed() {
        // A corrupt legacy node whose null-mode id is a sentinel must never become a real
        // `Saved` binding — validation rejects it instead of applying a fake credential.
        let vm = CredentialBindingVm::from_legacy(
            true,
            ParentBindingContext::NoCredential,
            Some(CredentialBindingSentinelIds::INHERIT),
        );
        assert_eq!(vm.mode, Some(CredentialBindingMode::Saved));
        assert_eq!(
            vm.validate().errors,
            vec![CredentialBindingError::CredentialIdInvalid]
        );
        assert_eq!(vm.plan(), None);
    }

    #[test]
    fn legacy_inline_node_loads_via_transition_not_from_legacy() {
        // A legacy null-mode, no-id node that carries an inline password must load through
        // `set_inline_password(true)`: `from_legacy` alone derives `Inherit`, and an inline
        // password + `Inherit` never coexist (validate fails closed). The transition yields
        // the exact `None` + inline shape C# writes on save.
        let mut vm = CredentialBindingVm::from_legacy(
            true,
            ParentBindingContext::ResolvesCredential,
            None,
        );
        assert_eq!(vm.mode, Some(CredentialBindingMode::Inherit));
        vm.set_inline_password(true);
        assert_eq!(vm.mode, Some(CredentialBindingMode::None));
        assert_eq!(vm.selected_credential_id, None);
        assert!(vm.validate().is_clean());
        let plan = vm.plan().expect("inline legacy loads cleanly");
        assert_eq!(plan.mode, CredentialBindingMode::None);
        assert!(plan.use_inline_password);
    }

    #[test]
    fn apply_commit_selects_saved_and_clears_inline() {
        let (glue, lab) =
            CredentialBindingGlue::with_fake_lab(true, ParentBindingContext::NoCredential);
        lab.store.set_profiles([cred_a()]);
        let mut glue = glue;
        glue.vm_mut().set_inline_password(true);
        let selected = glue
            .select_credential_by_commit_key("prod-db")
            .expect("load ok");
        assert!(selected);
        assert_eq!(glue.vm().selected_credential_id, Some(id(CRED_A_BYTES)));
        assert_eq!(glue.vm().mode, Some(CredentialBindingMode::Saved));
        assert!(!glue.vm().use_inline_password);
        assert!(glue.is_valid().expect("catalog ok"));
    }

    #[test]
    fn debug_never_echoes_catalog_or_credentials() {
        let (glue, lab) =
            CredentialBindingGlue::with_fake_lab(true, ParentBindingContext::NoCredential);
        let row = CredentialProfileRow::new(
            id(CRED_A_BYTES),
            "s3cret-very-sensitive-cred",
            Some("p@ssw0rd-looking-user".into()),
            None,
        );
        lab.store.set_profiles([row]);
        let mut glue = glue;
        glue.vm_mut().select_mode(CredentialBindingMode::Saved);
        glue.vm_mut().select_credential(Some(id(CRED_A_BYTES)));

        let glue_debug = format!("{glue:?}");
        assert!(!glue_debug.contains("s3cret-very-sensitive-cred"));
        assert!(!glue_debug.contains("p@ssw0rd"));
        let lab_debug = format!("{lab:?}");
        assert!(!lab_debug.contains("s3cret-very-sensitive-cred"));
        let vm_debug = format!("{:?}", glue.vm());
        assert!(!vm_debug.contains("s3cret-very-sensitive-cred"));
        // Ids and mode labels are the only content (safe).
        assert!(vm_debug.contains("mode"));
    }
}
