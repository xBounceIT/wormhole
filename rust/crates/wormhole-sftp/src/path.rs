//! Remote path / name safety — mirrors `SftpSession.IsSafeRemoteName`.

/// Reject names that would escape a local `Path::join` destination (path separators,
/// NUL, NTFS ADS `:` sigil) or that are `.` / `..`.
pub fn is_safe_remote_name(name: &str) -> bool {
    if name.is_empty() || name == "." || name == ".." {
        return false;
    }
    !name
        .chars()
        .any(|c| matches!(c, '/' | '\\' | ':' | '\0'))
}

/// Join a POSIX remote directory and a single path component.
pub fn remote_join(parent: &str, name: &str) -> String {
    if parent.is_empty() || parent == "/" {
        format!("/{name}")
    } else if parent.ends_with('/') {
        format!("{parent}{name}")
    } else {
        format!("{parent}/{name}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_separators_and_dot_entries() {
        assert!(!is_safe_remote_name(""));
        assert!(!is_safe_remote_name("."));
        assert!(!is_safe_remote_name(".."));
        assert!(!is_safe_remote_name("a/b"));
        assert!(!is_safe_remote_name("a\\b"));
        assert!(!is_safe_remote_name("notes:hidden"));
        assert!(!is_safe_remote_name("a\0b"));
        assert!(is_safe_remote_name("readme.txt"));
    }

    #[test]
    fn remote_join_posix() {
        assert_eq!(remote_join("/", "a"), "/a");
        assert_eq!(remote_join("/home", "bob"), "/home/bob");
        assert_eq!(remote_join("/home/", "bob"), "/home/bob");
    }
}
