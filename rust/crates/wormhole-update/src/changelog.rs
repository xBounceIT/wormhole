//! Changelog / release-notes fetch stub (WebView changelog UX is out of scope).

use crate::error::{Result, UpdateError};
use crate::github::{is_allowed_http_url, ReleaseManifest};

/// Normalized changelog payload for UI binding (markdown body + metadata).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangelogDocument {
    /// Release tag.
    pub tag: String,
    /// Optional title.
    pub title: Option<String>,
    /// Markdown body (may be empty).
    pub markdown: String,
    /// HTML release URL when known (http(s) only).
    pub release_url: Option<String>,
}

impl ChangelogDocument {
    /// Build from an already-fetched [`ReleaseManifest`] (no network).
    ///
    /// Non-http(s) `html_url` values (e.g. `file://`) are dropped.
    pub fn from_manifest(release: &ReleaseManifest) -> Self {
        let release_url = release
            .html_url
            .as_deref()
            .filter(|u| is_allowed_http_url(u))
            .map(str::to_string);
        Self {
            tag: release.tag_name.clone(),
            title: release.name.clone(),
            markdown: release.body.clone().unwrap_or_default(),
            release_url,
        }
    }
}

/// Live changelog fetch stub — always returns [`UpdateError::ChangelogFetchStub`].
///
/// C# shows notes via `UpdateChangelogView` (WebView2). Rust host should fetch the GitHub
/// release body (or use [`ChangelogDocument::from_manifest`]) and render in GPUI later.
pub fn fetch_changelog_live_stub(_owner: &str, _repo: &str, _tag: &str) -> Result<ChangelogDocument> {
    Err(UpdateError::ChangelogFetchStub)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github::ReleaseManifest;

    #[test]
    fn from_manifest_copies_body() {
        let release = ReleaseManifest {
            tag_name: "v1.0.0".into(),
            name: Some("1.0".into()),
            html_url: Some("https://example/r".into()),
            body: Some("## Hi".into()),
            draft: false,
            prerelease: false,
            assets: vec![],
        };
        let doc = ChangelogDocument::from_manifest(&release);
        assert_eq!(doc.markdown, "## Hi");
        assert_eq!(doc.tag, "v1.0.0");
        assert_eq!(doc.release_url.as_deref(), Some("https://example/r"));
    }

    #[test]
    fn from_manifest_drops_file_scheme_url() {
        let release = ReleaseManifest {
            tag_name: "v1.0.0".into(),
            name: None,
            html_url: Some("file:///etc/passwd".into()),
            body: None,
            draft: false,
            prerelease: false,
            assets: vec![],
        };
        let doc = ChangelogDocument::from_manifest(&release);
        assert!(doc.release_url.is_none());
    }

    #[test]
    fn live_stub_errors() {
        assert!(matches!(
            fetch_changelog_live_stub("o", "r", "v1"),
            Err(UpdateError::ChangelogFetchStub)
        ));
    }
}
