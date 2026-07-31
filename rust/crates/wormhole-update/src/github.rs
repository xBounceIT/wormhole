//! GitHub URL / asset / SHA sidecar helpers (mirrors `UpdateService` statics).

use crate::error::{Result, UpdateError};

/// Parse `https://github.com/{owner}/{repo}(.git)?/?` → `(owner, repo)`.
///
/// Only `http://` / `https://` GitHub hosts are accepted (rejects `file://`, userinfo tricks,
/// and non-github hosts). Matches C# `GithubUrlPattern`.
pub fn try_parse_repo_url(url: &str) -> Option<(String, String)> {
    let trimmed = url.trim();
    if trimmed.is_empty() || trimmed.contains('\0') {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    let rest = if let Some(r) = lower.strip_prefix("https://github.com/") {
        r
    } else if let Some(r) = lower.strip_prefix("http://github.com/") {
        r
    } else {
        return None;
    };
    // Use original casing from trimmed for owner/repo slices via byte offsets.
    let prefix_len = trimmed.len() - rest.len();
    let path = &trimmed[prefix_len..];
    let path = path.trim_end_matches('/');
    let path = path.strip_suffix(".git").unwrap_or(path);
    let mut parts = path.split('/');
    let owner = parts.next()?.trim();
    let repo = parts.next()?.trim();
    if owner.is_empty() || repo.is_empty() || parts.next().is_some() {
        return None;
    }
    // Reject empty path segments with reserved chars lightly — C# regex is `[^/]+`.
    if owner.contains('/') || repo.contains('/') {
        return None;
    }
    Some((owner.to_string(), repo.to_string()))
}

/// Fallible wrapper.
pub fn parse_repo_url(url: &str) -> Result<(String, String)> {
    try_parse_repo_url(url).ok_or_else(|| UpdateError::InvalidRepository(UpdateError::clip_ctx(url)))
}

/// Whether `url` is an http(s) URL with a non-empty host (SSRF floor for stubs / hosts).
///
/// C# download `HttpClient` has no host allow-list; we still reject `file://`, `javascript:`,
/// `data:`, and other non-http(s) schemes so a hostile manifest cannot coerce a future HTTP
/// layer into opening local paths.
pub fn is_allowed_http_url(url: &str) -> bool {
    try_validate_http_url(url).is_ok()
}

/// Fallible URL scheme/host floor used by check / changelog evaluation.
pub fn try_validate_http_url(url: &str) -> Result<()> {
    let trimmed = url.trim();
    if trimmed.is_empty() || trimmed.contains('\0') {
        return Err(UpdateError::DisallowedUrl(UpdateError::clip_ctx(trimmed)));
    }
    let lower = trimmed.to_ascii_lowercase();
    let rest = if let Some(r) = lower.strip_prefix("https://") {
        r
    } else if let Some(r) = lower.strip_prefix("http://") {
        r
    } else {
        return Err(UpdateError::DisallowedUrl(UpdateError::clip_ctx(trimmed)));
    };
    // Host must be non-empty and must not start with `/` (rejects `file:`-style `///`).
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    // Strip optional userinfo (`user:pass@host`).
    let host = host.rsplit('@').next().unwrap_or(host);
    if host.is_empty() || host == "." || host == ".." {
        return Err(UpdateError::DisallowedUrl(UpdateError::clip_ctx(trimmed)));
    }
    // Reject bare IPv6 brackets emptiness and whitespace hosts.
    if host.chars().any(|c| c.is_whitespace()) {
        return Err(UpdateError::DisallowedUrl(UpdateError::clip_ctx(trimmed)));
    }
    Ok(())
}

/// Installer asset metadata from a GitHub release JSON (subset).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseAsset {
    /// Asset file name.
    pub name: String,
    /// `browser_download_url`.
    pub browser_download_url: String,
    /// Reported size in bytes (0 = unknown).
    pub size: u64,
}

/// Minimal release manifest used by check / changelog stubs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseManifest {
    /// `tag_name`.
    pub tag_name: String,
    /// Display name.
    pub name: Option<String>,
    /// HTML URL for the release page.
    pub html_url: Option<String>,
    /// Markdown body (release notes).
    pub body: Option<String>,
    /// Draft releases are ignored by check.
    pub draft: bool,
    /// Prerelease tags are ignored by check.
    pub prerelease: bool,
    /// Attached assets.
    pub assets: Vec<ReleaseAsset>,
}

/// Find `Wormhole-*-win-{arch}-setup.exe` (case-insensitive), excluding `.sha256` sidecars.
pub fn find_installer_asset<'a>(
    release: &'a ReleaseManifest,
    arch: &str,
) -> Option<&'a ReleaseAsset> {
    let suffix = format!("-win-{arch}-setup.exe");
    let suffix_lower = suffix.to_ascii_lowercase();
    release.assets.iter().find(|asset| {
        let name_lower = asset.name.to_ascii_lowercase();
        name_lower.starts_with("wormhole-") && name_lower.ends_with(&suffix_lower)
    })
}

/// Extract a 64-char hex SHA-256 from a sidecar file body (first token on first non-empty line).
pub fn parse_sha_sidecar(raw: &str) -> Option<String> {
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let token = line.split(|c: char| c == ' ' || c == '\t').next()?;
        return normalize_sha256_token(token);
    }
    None
}

/// Normalize a 64-char hex digest to lowercase; reject malformed input.
pub fn normalize_sha256_token(token: &str) -> Option<String> {
    if token.len() != 64 {
        return None;
    }
    if !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(token.to_ascii_lowercase())
}

/// Host architecture string for installer asset matching (`x64` / `arm64`).
pub fn target_architecture() -> Option<&'static str> {
    match std::env::consts::ARCH {
        "x86_64" => Some("x64"),
        "aarch64" => Some("arm64"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_repo_url_ok() {
        let (o, r) =
            try_parse_repo_url("https://github.com/wormhole-project/wormhole").unwrap();
        assert_eq!(o, "wormhole-project");
        assert_eq!(r, "wormhole");
        let (o, r) =
            try_parse_repo_url("https://github.com/wormhole-project/wormhole.git").unwrap();
        assert_eq!(o, "wormhole-project");
        assert_eq!(r, "wormhole");
        let (o, r) = try_parse_repo_url("https://github.com/Some-Org/Repo-Name/").unwrap();
        assert_eq!(o, "Some-Org");
        assert_eq!(r, "Repo-Name");
        let (o, r) = try_parse_repo_url("HTTP://GITHUB.COM/o/r").unwrap();
        assert_eq!(o, "o");
        assert_eq!(r, "r");
    }

    #[test]
    fn parse_repo_url_rejects() {
        assert!(try_parse_repo_url("").is_none());
        assert!(try_parse_repo_url("not-a-url").is_none());
        assert!(try_parse_repo_url("https://gitlab.com/foo/bar").is_none());
        assert!(try_parse_repo_url("file://github.com/foo/bar").is_none());
        assert!(try_parse_repo_url("https://github.com.evil.com/foo/bar").is_none());
        assert!(try_parse_repo_url("https://github.com/foo/bar/baz").is_none());
        assert!(try_parse_repo_url("https://user:pass@github.com/foo/bar").is_none());
        assert!(try_parse_repo_url("javascript:github.com/foo/bar").is_none());
    }

    #[test]
    fn http_url_allows_https_with_host() {
        assert!(is_allowed_http_url(
            "https://github.com/o/r/releases/download/v1/Wormhole-setup.exe"
        ));
        assert!(is_allowed_http_url(
            "https://objects.githubusercontent.com/github-production-release-asset/1"
        ));
        assert!(is_allowed_http_url("http://example.invalid/installer.exe"));
    }

    #[test]
    fn http_url_rejects_weird_schemes() {
        assert!(!is_allowed_http_url("file:///C:/Windows/system32/calc.exe"));
        assert!(!is_allowed_http_url("file://github.com/o/r"));
        assert!(!is_allowed_http_url("javascript:alert(1)"));
        assert!(!is_allowed_http_url("data:text/plain,hi"));
        assert!(!is_allowed_http_url("ftp://github.com/o/r"));
        assert!(!is_allowed_http_url("https://"));
        assert!(!is_allowed_http_url("http:///no-host"));
        assert!(!is_allowed_http_url(""));
        assert!(!is_allowed_http_url("not-a-url"));
    }

    #[test]
    fn find_installer_by_arch() {
        let release = ReleaseManifest {
            tag_name: "v0.2.0".into(),
            name: None,
            html_url: None,
            body: None,
            draft: false,
            prerelease: false,
            assets: vec![
                ReleaseAsset {
                    name: "Wormhole-0.2.0-win-x64-setup.exe".into(),
                    browser_download_url: "https://example/x64".into(),
                    size: 1,
                },
                ReleaseAsset {
                    name: "Wormhole-0.2.0-win-arm64-setup.exe".into(),
                    browser_download_url: "https://example/arm64".into(),
                    size: 1,
                },
                ReleaseAsset {
                    name: "Wormhole-0.2.0-win-x64-setup.exe.sha256".into(),
                    browser_download_url: "https://example/x64sha".into(),
                    size: 1,
                },
            ],
        };
        assert_eq!(
            find_installer_asset(&release, "x64").unwrap().name,
            "Wormhole-0.2.0-win-x64-setup.exe"
        );
        assert_eq!(
            find_installer_asset(&release, "arm64").unwrap().name,
            "Wormhole-0.2.0-win-arm64-setup.exe"
        );
    }

    #[test]
    fn parse_sha_sidecar_extracts() {
        assert_eq!(
            parse_sha_sidecar(
                "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
            )
            .as_deref(),
            Some("abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234")
        );
        assert_eq!(
            parse_sha_sidecar(
                "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234  Wormhole-0.2.0-win-x64-setup.exe\n"
            )
            .as_deref(),
            Some("abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234")
        );
        assert_eq!(
            parse_sha_sidecar(
                "  ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234  "
            )
            .as_deref(),
            Some("abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234")
        );
        assert!(parse_sha_sidecar("").is_none());
        assert!(parse_sha_sidecar("not-hex-stuff").is_none());
        assert!(parse_sha_sidecar("abcd").is_none());
    }
}
