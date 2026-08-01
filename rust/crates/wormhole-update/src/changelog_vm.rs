//! Changelog selection state VM — C# `UpdateViewModel.ApplyChangelog` /
//! `UpdateChangelogView` parity, Fake-first, no live HTTP.
//!
//! The WebView rendering (`UpdateChangelogFormatter.ToHtmlDocument`) stays with the
//! host; this VM owns the **list-releases → select → changelog text** state that
//! feeds it. Releases come from a local list ([`crate::ChangelogDocument::from_manifest`],
//! no network); selecting one yields the markdown text + display title.
//!
//! | Condition | Result |
//! |---|---|
//! | no releases loaded | `has_changelog == false`, empty title/text |
//! | no release selected | empty (fail closed) |
//! | [`Select`](UpdateChangelogVm::select) unknown / empty tag | cleared |
//! | [`SelectIndex`](UpdateChangelogVm::select_index) out of bounds | cleared |
//! | [`SetReleases`](UpdateChangelogVm::set_releases) without the selected tag | selection cleared |
//! | release with empty / whitespace-only notes | `has_changelog == false` (C# whitespace → clear) |
//! | [`clear`](UpdateChangelogVm::clear) / deselection | empty |
//!
//! No secrets: [`Debug`] prints tags/names and *lengths* only — never markdown
//! bodies — so attacker-controlled release notes cannot leak through logging.

use std::fmt;

use crate::changelog::ChangelogDocument;
use crate::github::is_allowed_http_url;

/// One selectable release shown in the list UI (tag + display name).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseOption {
    /// Release tag (stable select key).
    pub tag: String,
    /// Display name when known.
    pub name: Option<String>,
}

/// Derived changelog presentation for the currently selected release.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SelectedChangelog {
    /// `true` when a selected release has usable notes.
    pub has_changelog: bool,
    /// `"Changelog - <ReleaseName|Tag|Wormhole>"` (C# `ChangelogTitle`).
    pub title: String,
    /// Raw markdown release notes (C# `ReleaseNotes`; rendered by the host WebView).
    pub text: String,
    /// http(s) release URL when known (never `file://` — see [`crate::changelog`]).
    pub release_url: Option<String>,
}

impl SelectedChangelog {
    /// C# `ShowChangelog => HasChangelog && IsUpdateAvailable` binding.
    pub fn show_changelog(&self, is_update_available: bool) -> bool {
        self.has_changelog && is_update_available
    }
}

/// Changelog state machine: local release list → select → changelog text.
///
/// Fail-closed: no selection (or a selection that no longer resolves) yields an
/// empty [`SelectedChangelog`]. `Debug` never prints markdown bodies or tokens.
#[derive(Default)]
pub struct UpdateChangelogVm {
    releases: Vec<ChangelogDocument>,
    selected_tag: Option<String>,
    changelog: SelectedChangelog,
}

impl fmt::Debug for UpdateChangelogVm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Tag/name summaries only; never the markdown body (may be attacker text).
        let options: Vec<(String, Option<String>)> = self
            .releases
            .iter()
            .map(|r| (r.tag.clone(), r.title.clone()))
            .collect();
        f.debug_struct("UpdateChangelogVm")
            .field("releases", &options)
            .field("selected_tag", &self.selected_tag)
            .field("has_changelog", &self.changelog.has_changelog)
            .field("title", &self.changelog.title)
            .field("text_len", &self.changelog.text.len())
            .field("release_url_present", &self.changelog.release_url.is_some())
            .finish()
    }
}

impl UpdateChangelogVm {
    /// Empty VM — fail-closed (nothing selected).
    pub fn new() -> Self {
        Self::default()
    }

    /// Substitute the local release list; keeps the current selection when its
    /// tag is still present, otherwise clears it (fail closed).
    pub fn set_releases(&mut self, releases: Vec<ChangelogDocument>) {
        self.releases = releases;
        match self.selected_tag.clone() {
            Some(tag) => self.select(&tag),
            None => self.deselect(),
        }
    }

    /// Select a release by tag, populating the changelog text from its notes.
    ///
    /// Unknown / empty tags clear the changelog ([`UpdateError`]-free fail closed);
    /// empty or whitespace-only notes keep the selection but yield no changelog
    /// (C# `ApplyChangelog` → `ClearChangelog`).
    pub fn select(&mut self, tag: &str) {
        if tag.is_empty() {
            self.deselect();
            return;
        }
        // Clone so `self.apply_changelog` can take `&mut self` below.
        let Some(release) = self.releases.iter().find(|r| r.tag == tag).cloned() else {
            self.deselect();
            return;
        };
        self.selected_tag = Some(release.tag.clone());
        self.apply_changelog(&release);
    }

    /// Select by list index (out of bounds clears — fail closed).
    pub fn select_index(&mut self, index: usize) {
        let tag = self.releases.get(index).map(|r| r.tag.clone());
        match tag {
            Some(tag) => self.select(&tag),
            None => self.deselect(),
        }
    }

    /// Clear selection and changelog.
    pub fn clear(&mut self) {
        self.deselect();
    }

    /// Currently selected tag, if any.
    pub fn selected_tag(&self) -> Option<&str> {
        self.selected_tag.as_deref()
    }

    /// Selectable release list (tags + names) for the list UI — never bodies.
    pub fn release_options(&self) -> Vec<ReleaseOption> {
        self.releases
            .iter()
            .map(|r| ReleaseOption {
                tag: r.tag.clone(),
                name: r.title.clone(),
            })
            .collect()
    }

    /// Borrow the derived changelog presentation.
    pub fn changelog(&self) -> &SelectedChangelog {
        &self.changelog
    }

    /// C# `HasChangelog`.
    pub fn has_changelog(&self) -> bool {
        self.changelog.has_changelog
    }

    /// C# `ShowChangelog` (depends on the host's update-availability flag).
    pub fn show_changelog(&self, is_update_available: bool) -> bool {
        self.changelog.show_changelog(is_update_available)
    }

    fn apply_changelog(&mut self, release: &ChangelogDocument) {
        let notes = release.markdown.trim();
        if notes.is_empty() {
            // C# whitespace/empty notes render to an empty document -> clear.
            self.changelog = SelectedChangelog::default();
            return;
        }
        // Defense in depth: re-filter http(s) so a host-constructed document cannot
        // smuggle a `file://` (or other non-http) URL past `from_manifest`.
        let release_url = release
            .release_url
            .as_deref()
            .filter(|u| is_allowed_http_url(u))
            .map(str::to_string);
        self.changelog = SelectedChangelog {
            has_changelog: true,
            title: changelog_title(release),
            text: release.markdown.clone(),
            release_url,
        };
    }

    fn deselect(&mut self) {
        self.selected_tag = None;
        self.changelog = SelectedChangelog::default();
    }
}

/// C# `ChangelogTitle = "Changelog - " + (ReleaseName ?? ReleaseTag ?? $"Wormhole {version}")`.
///
/// `ChangelogDocument` carries `tag` + optional `name`; the version-string fallback
/// degrades to `"Wormhole"` (no version is stored on the document).
fn changelog_title(release: &ChangelogDocument) -> String {
    let display = release
        .title
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(release.tag.as_str());
    let display = if display.is_empty() { "Wormhole" } else { display };
    format!("Changelog - {display}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(tag: &str, name: Option<&str>, notes: Option<&str>) -> ChangelogDocument {
        ChangelogDocument {
            tag: tag.into(),
            title: name.map(str::to_string),
            markdown: notes.unwrap_or_default().into(),
            release_url: Some("https://example/releases/".to_owned() + tag),
        }
    }

    #[test]
    fn select_populates_changelog_and_show_requires_availability() {
        let mut vm = UpdateChangelogVm::new();
        vm.set_releases(vec![doc("v9.9.9", Some("Release v9.9.9"), Some("## Notes\n- item"))]);
        vm.select("v9.9.9");

        assert!(vm.has_changelog());
        assert_eq!(vm.changelog().title, "Changelog - Release v9.9.9");
        assert_eq!(vm.changelog().text, "## Notes\n- item");
        assert_eq!(vm.selected_tag(), Some("v9.9.9"));
        assert!(vm.show_changelog(true));
        assert!(!vm.show_changelog(false), "C# ShowChangelog requires availability");
    }

    #[test]
    fn no_selection_fail_closed_empty() {
        let vm = UpdateChangelogVm::new();
        assert!(!vm.has_changelog());
        assert_eq!(vm.changelog(), &SelectedChangelog::default());
        assert_eq!(vm.selected_tag(), None);
        assert!(!vm.show_changelog(true));
    }

    #[test]
    fn select_unknown_or_empty_tag_fail_closed() {
        let mut vm = UpdateChangelogVm::new();
        vm.set_releases(vec![doc("v9.9.9", Some("r"), Some("notes"))]);
        vm.select("v-missing");
        assert!(!vm.has_changelog());
        assert_eq!(vm.selected_tag(), None);

        vm.select("");
        assert!(!vm.has_changelog());
    }

    #[test]
    fn select_empty_tag_never_selects_even_an_empty_tagged_release() {
        let mut vm = UpdateChangelogVm::new();
        vm.set_releases(vec![doc("", Some("r"), Some("notes"))]);
        vm.select("");
        assert!(!vm.has_changelog());
        assert_eq!(vm.selected_tag(), None, "empty tag must always clear (fail closed)");

        let mut via_index = UpdateChangelogVm::new();
        via_index.set_releases(vec![doc("", Some("r"), Some("notes"))]);
        via_index.select_index(0);
        assert_eq!(via_index.selected_tag(), None);
        assert!(!via_index.has_changelog());
    }

    #[test]
    fn select_index_out_of_bounds_clears() {
        let mut vm = UpdateChangelogVm::new();
        vm.set_releases(vec![doc("v9.9.9", Some("r"), Some("notes"))]);
        vm.select_index(5);
        assert!(!vm.has_changelog());
        assert_eq!(vm.selected_tag(), None);
        vm.select_index(0);
        assert!(vm.has_changelog());
        assert_eq!(vm.selected_tag(), Some("v9.9.9"));
    }

    #[test]
    fn empty_notes_fail_closed_cleared() {
        let mut vm = UpdateChangelogVm::new();
        vm.set_releases(vec![doc("v9.9.9", None, Some("   \n\t  "))]);
        vm.select("v9.9.9");
        assert_eq!(vm.selected_tag(), Some("v9.9.9"), "release still selected in list");
        assert!(!vm.has_changelog(), "whitespace notes -> no changelog (C# parity)");
        assert_eq!(vm.changelog(), &SelectedChangelog::default());
    }

    #[test]
    fn non_http_release_url_dropped_fail_closed() {
        let mut vm = UpdateChangelogVm::new();
        let mut hostile = doc("v9.9.9", Some("r"), Some("notes"));
        hostile.release_url = Some("file:///etc/passwd".into());
        vm.set_releases(vec![hostile]);
        vm.select("v9.9.9");
        assert!(vm.has_changelog(), "notes still render");
        assert!(
            vm.changelog().release_url.is_none(),
            "file:// must never surface past the VM"
        );
    }

    #[test]
    fn set_releases_keeps_or_clears_selection() {
        let mut vm = UpdateChangelogVm::new();
        vm.set_releases(vec![doc("v1", None, Some("one")), doc("v2", None, Some("two"))]);
        vm.select("v2");
        assert_eq!(vm.selected_tag(), Some("v2"));

        // Keep when tag still present.
        vm.set_releases(vec![doc("v2", Some("Two"), Some("two-again"))]);
        assert_eq!(vm.selected_tag(), Some("v2"));
        assert!(vm.has_changelog());
        assert_eq!(vm.changelog().title, "Changelog - Two");

        // Drop selection (fail closed) when tag disappears.
        vm.set_releases(vec![doc("v3", None, Some("three"))]);
        assert_eq!(vm.selected_tag(), None);
        assert!(!vm.has_changelog());
    }

    #[test]
    fn clear_deselects_and_empties() {
        let mut vm = UpdateChangelogVm::new();
        vm.set_releases(vec![doc("v9.9.9", Some("r"), Some("notes"))]);
        vm.select("v9.9.9");
        assert!(vm.has_changelog());

        vm.clear();
        assert!(!vm.has_changelog());
        assert_eq!(vm.selected_tag(), None);
        assert_eq!(vm.changelog().text, "");
        assert_eq!(vm.changelog().title, "");
    }

    #[test]
    fn tag_fallback_title_and_option_list() {
        let mut vm = UpdateChangelogVm::new();
        vm.set_releases(vec![doc("v9.9.9", None, Some("notes"))]);
        vm.select("v9.9.9");
        assert_eq!(vm.changelog().title, "Changelog - v9.9.9");

        let opts = vm.release_options();
        assert_eq!(opts.len(), 1);
        assert_eq!(opts[0].tag, "v9.9.9");
        assert_eq!(opts[0].name, None);
    }

    #[test]
    fn debug_omits_markdown_bodies_and_tokens() {
        let secret = "ghp_release_notes_must_not_leak_via_debug";
        let mut vm = UpdateChangelogVm::new();
        vm.set_releases(vec![doc("v9.9.9", Some("r"), Some(&format!("notes\nsecret is {secret}")))]);
        vm.select("v9.9.9");

        let dbg = format!("{vm:?}");
        assert!(dbg.contains("UpdateChangelogVm"), "{dbg}");
        assert!(!dbg.contains(secret), "{dbg}");
        assert!(!dbg.contains("ghp_"), "{dbg}");
        assert!(!dbg.contains("notes"), "{dbg}: body must not appear in Debug");
        assert!(dbg.contains("text_len"), "{dbg}");
        // The summary shows the tag, not the body.
        assert!(dbg.contains("v9.9.9"), "{dbg}: tag visible in Debug");
    }
}
