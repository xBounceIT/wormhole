//! `System.Version`–style version parse + compare (mirrors `UpdateService.TryParseTagVersion`).

use std::cmp::Ordering;
use std::fmt;

use crate::error::{Result, UpdateError};

/// Four-component app version matching .NET `System.Version` comparison rules used by updates.
///
/// Undefined build/revision use `-1` (same as `Version` when fewer components are supplied).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppVersion {
    /// Major component (≥ 0).
    pub major: u32,
    /// Minor component (≥ 0).
    pub minor: u32,
    /// Build component, or `-1` when absent.
    pub build: i32,
    /// Revision component, or `-1` when absent.
    pub revision: i32,
}

impl AppVersion {
    /// Construct from major.minor (build/revision undefined).
    pub const fn new(major: u32, minor: u32) -> Self {
        Self {
            major,
            minor,
            build: -1,
            revision: -1,
        }
    }

    /// Construct from major.minor.build (revision undefined).
    pub const fn with_build(major: u32, minor: u32, build: u32) -> Self {
        Self {
            major,
            minor,
            build: build as i32,
            revision: -1,
        }
    }

    /// Construct from major.minor.build.revision.
    pub const fn with_revision(major: u32, minor: u32, build: u32, revision: u32) -> Self {
        Self {
            major,
            minor,
            build: build as i32,
            revision: revision as i32,
        }
    }
}

impl PartialOrd for AppVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AppVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        // Mirrors System.Version: compare defined components; undefined (-1) sorts before 0.
        self.major
            .cmp(&other.major)
            .then(self.minor.cmp(&other.minor))
            .then(self.build.cmp(&other.build))
            .then(self.revision.cmp(&other.revision))
    }
}

impl fmt::Display for AppVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)?;
        if self.build >= 0 {
            write!(f, ".{}", self.build)?;
            if self.revision >= 0 {
                write!(f, ".{}", self.revision)?;
            }
        }
        Ok(())
    }
}

/// Parse a GitHub release tag into [`AppVersion`] (optional leading `v`/`V`, trim whitespace).
///
/// Rejects pre-release suffixes (`v1.2.3-rc1`) — same as C# `Version.TryParse` after stripping `v`.
pub fn try_parse_tag_version(tag: &str) -> Option<AppVersion> {
    let trimmed = tag.trim();
    if trimmed.is_empty() {
        return None;
    }
    let without_v = match trimmed.as_bytes()[0] {
        b'v' | b'V' => &trimmed[1..],
        _ => trimmed,
    };
    parse_dotnet_version(without_v)
}

/// Fallible wrapper returning [`UpdateError::InvalidVersion`].
pub fn parse_tag_version(tag: &str) -> Result<AppVersion> {
    try_parse_tag_version(tag)
        .ok_or_else(|| UpdateError::InvalidVersion(UpdateError::clip_ctx(tag)))
}

/// Compare `latest` to `current`: `Greater` means an update is available.
pub fn compare_versions(current: &AppVersion, latest: &AppVersion) -> Ordering {
    latest.cmp(current)
}

/// `true` when `latest` is strictly newer than `current`.
pub fn is_newer(current: &AppVersion, latest: &AppVersion) -> bool {
    matches!(compare_versions(current, latest), Ordering::Greater)
}

fn parse_dotnet_version(s: &str) -> Option<AppVersion> {
    // System.Version.TryParse: 2–4 non-negative `int` components separated by '.'.
    let parts: Vec<&str> = s.split('.').collect();
    if !(2..=4).contains(&parts.len()) {
        return None;
    }
    let mut nums = [0u32; 4];
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        // System.Version components are signed 32-bit; reject values > i32::MAX.
        let n: u32 = part.parse().ok()?;
        if n > i32::MAX as u32 {
            return None;
        }
        nums[i] = n;
    }
    Some(match parts.len() {
        2 => AppVersion::new(nums[0], nums[1]),
        3 => AppVersion::with_build(nums[0], nums[1], nums[2]),
        4 => AppVersion::with_revision(nums[0], nums[1], nums[2], nums[3]),
        _ => unreachable!(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_prefixes_and_whitespace() {
        assert_eq!(
            try_parse_tag_version("v1.2.3").unwrap(),
            AppVersion::with_build(1, 2, 3)
        );
        assert_eq!(
            try_parse_tag_version("1.2.3").unwrap(),
            AppVersion::with_build(1, 2, 3)
        );
        assert_eq!(
            try_parse_tag_version("V1.2.3.4").unwrap(),
            AppVersion::with_revision(1, 2, 3, 4)
        );
        assert_eq!(
            try_parse_tag_version("  v0.1.0  ").unwrap(),
            AppVersion::with_build(0, 1, 0)
        );
    }

    #[test]
    fn rejects_invalid() {
        assert!(try_parse_tag_version("").is_none());
        assert!(try_parse_tag_version("not-a-version").is_none());
        assert!(try_parse_tag_version("v1.2.3-rc1").is_none());
        assert!(try_parse_tag_version("v1.2.3+meta").is_none());
        assert!(try_parse_tag_version("1").is_none());
        assert!(try_parse_tag_version("vv1.2.3").is_none());
        assert!(try_parse_tag_version("1.2.").is_none());
        assert!(try_parse_tag_version(".1.2").is_none());
        assert!(try_parse_tag_version("1..2").is_none());
        assert!(try_parse_tag_version("1.2.3.4.5").is_none());
        // System.Version uses Int32 components — overflow must fail closed.
        assert!(try_parse_tag_version("2147483648.0").is_none());
        assert!(try_parse_tag_version("1.2147483648").is_none());
    }

    #[test]
    fn accepts_i32_max_component() {
        assert_eq!(
            try_parse_tag_version("2147483647.0").unwrap(),
            AppVersion::new(2_147_483_647, 0)
        );
    }

    #[test]
    fn compare_orders_like_system_version() {
        let cur = AppVersion::with_build(0, 9, 0);
        let newer = AppVersion::with_build(0, 9, 1);
        let older = AppVersion::with_build(0, 8, 9);
        assert!(is_newer(&cur, &newer));
        assert!(!is_newer(&cur, &older));
        assert!(!is_newer(&cur, &cur));
        assert_eq!(compare_versions(&cur, &newer), Ordering::Greater);
        assert_eq!(compare_versions(&cur, &older), Ordering::Less);
    }

    #[test]
    fn four_component_beats_three_when_prefix_equal() {
        // 1.2.3.0 > 1.2.3 because revision 0 > undefined (-1).
        let three = AppVersion::with_build(1, 2, 3);
        let four = AppVersion::with_revision(1, 2, 3, 0);
        assert!(is_newer(&three, &four));
    }

    #[test]
    fn three_component_beats_two_when_prefix_equal() {
        // 1.0.0 > 1.0 because build 0 > undefined (-1).
        let two = AppVersion::new(1, 0);
        let three = AppVersion::with_build(1, 0, 0);
        assert!(is_newer(&two, &three));
    }
}
