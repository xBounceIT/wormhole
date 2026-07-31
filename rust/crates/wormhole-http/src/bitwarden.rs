//! Bitwarden HTTPS WebView2 profile helpers.
//!
//! Pure port of path/arg fingerprinting from
//! `Services/BitwardenBrowser/BitwardenBrowserWebViewProfile.cs`.
//!
//! **Non-goals:** extension download/install, shared-storage sync protocol,
//! cookie/IndexedDB seeding. Those stay in the C# app (or a later crate).
//! Absolute profile roots live in `wormhole-secrets-win`
//! (`bitwarden_browser_webview2_root` / `bitwarden_browser_webview2_user_data`).

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::browser_args::build_browser_arguments;
use crate::target::Socks5Proxy;
use crate::HttpError;

/// Marker file written into a profile folder (`wormhole-bitwarden-route-key.txt`).
pub const PERSISTENT_ROUTE_KEY_FILE_NAME: &str = "wormhole-bitwarden-route-key.txt";

/// True when the *logical* target is HTTPS (prefer `original_uri` for loopback forwarders).
pub fn is_https_target(navigate_uri: &str, original_uri: Option<&str>) -> bool {
    let logical = original_uri.unwrap_or(navigate_uri);
    scheme_of(logical).is_some_and(|s| s.eq_ignore_ascii_case("https"))
}

/// Fail closed unless the logical Bitwarden target is HTTPS.
///
/// Loopback forwarders must pass `original_uri` with an `https://` origin.
pub fn ensure_https_bitwarden_target(
    navigate_uri: &str,
    original_uri: Option<&str>,
) -> Result<(), HttpError> {
    if is_https_target(navigate_uri, original_uri) {
        Ok(())
    } else {
        Err(HttpError::BitwardenRequiresHttps)
    }
}

/// Compose AdditionalBrowserArguments (same hardening + optional SOCKS as other WebView2 surfaces).
///
/// Arguments carry only SOCKS endpoint + hardening switches — never session tokens or passwords.
pub fn build_bitwarden_browser_arguments(socks5: Option<Socks5Proxy>) -> String {
    build_browser_arguments(socks5)
}

/// Stable route key for cookie migration across SOCKS port rebinds.
///
/// `None` when `tunnel_config_id` is absent (no tunnel identity) **or** the logical
/// target is not HTTPS (Bitwarden profiles are HTTPS-only).
/// Material: `{guid:N}\0{socks5|forwarder}\0{authority-lowercase}` → SHA-256 hex.
pub fn build_persistent_route_key(
    navigate_uri: &str,
    original_uri: Option<&str>,
    tunnel_config_id: Option<Uuid>,
) -> Option<String> {
    if !is_https_target(navigate_uri, original_uri) {
        return None;
    }
    let config_id = tunnel_config_id?;
    let route_kind = if original_uri.is_none() {
        "socks5"
    } else {
        "forwarder"
    };
    let logical = original_uri.unwrap_or(navigate_uri);
    let target_origin = left_part_authority(logical).to_ascii_lowercase();
    let material = format!("{}\0{route_kind}\0{target_origin}", config_id.simple());
    Some(hex_lower(&Sha256::digest(material.as_bytes())))
}

/// `profile-` + first 16 hex chars of SHA-256(`browserArguments + "\0cert=" + 0|1`).
pub fn build_context_folder_name(browser_arguments: &str, ignore_certificate_errors: bool) -> String {
    let cert = if ignore_certificate_errors { "1" } else { "0" };
    let material = format!("{browser_arguments}\0cert={cert}");
    let hash = hex_lower(&Sha256::digest(material.as_bytes()));
    format!("profile-{}", &hash[..16])
}

/// Join `profile_root` with [`build_context_folder_name`] (C# `GetUserDataFolder(args, ignoreCert)`).
///
/// The folder name is always `profile-` + hex (no caller-controlled path segments).
pub fn user_data_folder(
    profile_root: &Path,
    browser_arguments: &str,
    ignore_certificate_errors: bool,
) -> PathBuf {
    profile_root.join(build_context_folder_name(
        browser_arguments,
        ignore_certificate_errors,
    ))
}

/// Full profile folder including route / forwarded-target context (C# overload with URIs + tunnel id).
///
/// Rejects non-HTTPS logical targets ([`HttpError::BitwardenRequiresHttps`]).
pub fn user_data_folder_for_target(
    profile_root: &Path,
    browser_arguments: &str,
    ignore_certificate_errors: bool,
    navigate_uri: &str,
    original_uri: Option<&str>,
    tunnel_config_id: Option<Uuid>,
) -> Result<PathBuf, HttpError> {
    ensure_https_bitwarden_target(navigate_uri, original_uri)?;
    let persistent_route_key =
        build_persistent_route_key(navigate_uri, original_uri, tunnel_config_id);
    let context_material = if let Some(ref route_key) = persistent_route_key {
        // Keep concrete proxy args in the runtime profile key: WebView2 rejects one
        // user-data folder opened concurrently with different browser arguments.
        format!("{browser_arguments}\0route-key={route_key}")
    } else if is_loopback_uri(navigate_uri) {
        if let Some(original) = original_uri {
            // Loopback-forwarded targets share 127.0.0.1 cookies by port; isolate by real origin.
            format!(
                "{browser_arguments}\0forwarded-target={}",
                left_part_authority(original).to_ascii_lowercase()
            )
        } else {
            browser_arguments.to_string()
        }
    } else {
        browser_arguments.to_string()
    };

    Ok(user_data_folder(
        profile_root,
        &context_material,
        ignore_certificate_errors,
    ))
}

fn scheme_of(uri: &str) -> Option<&str> {
    let idx = uri.find("://")?;
    Some(&uri[..idx])
}

/// `.NET Uri.GetLeftPart(UriPartial.Authority)` — `scheme://host[:port]` without path/query.
fn left_part_authority(uri: &str) -> &str {
    let Some(scheme_sep) = uri.find("://") else {
        return uri;
    };
    let after_scheme = scheme_sep + 3;
    let rest = &uri[after_scheme..];
    let end = rest
        .find(['/', '?', '#'])
        .map(|i| after_scheme + i)
        .unwrap_or(uri.len());
    &uri[..end]
}

fn host_of(uri: &str) -> Option<&str> {
    let auth = left_part_authority(uri);
    let after = auth.find("://").map(|i| i + 3)?;
    let authority = &auth[after..];
    // Strip userinfo if present.
    let authority = authority.rsplit_once('@').map(|(_, h)| h).unwrap_or(authority);
    if authority.starts_with('[') {
        let end = authority.find(']')?;
        return Some(&authority[1..end]);
    }
    Some(authority.split(':').next().unwrap_or(authority))
}

fn is_loopback_uri(uri: &str) -> bool {
    let Some(host) = host_of(uri) else {
        return false;
    };
    host.eq_ignore_ascii_case("localhost")
        || host == "127.0.0.1"
        || host.eq_ignore_ascii_case("::1")
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browser_args::HARDENING_BROWSER_ARGS;

    fn loopback_proxy(port: u16) -> Socks5Proxy {
        Socks5Proxy::loopback(port).unwrap()
    }

    #[test]
    fn is_https_target_prefers_original_for_forwarder() {
        assert!(is_https_target("https://router.example/login", None));
        assert!(is_https_target(
            "http://127.0.0.1:54321",
            Some("https://router.example/login")
        ));
        assert!(!is_https_target("http://router.example/login", None));
        assert!(!is_https_target(
            "http://127.0.0.1:54321",
            Some("http://router.example/login")
        ));
        assert!(is_https_target("HTTPS://Router.Example/", None));
    }

    #[test]
    fn ensure_https_rejects_plain_http_and_non_http_schemes() {
        assert_eq!(
            ensure_https_bitwarden_target("http://router.example/", None),
            Err(HttpError::BitwardenRequiresHttps)
        );
        assert_eq!(
            ensure_https_bitwarden_target("http://127.0.0.1:9", Some("http://router.example/")),
            Err(HttpError::BitwardenRequiresHttps)
        );
        assert_eq!(
            ensure_https_bitwarden_target("javascript:alert(1)", None),
            Err(HttpError::BitwardenRequiresHttps)
        );
        assert!(ensure_https_bitwarden_target("https://router.example/", None).is_ok());
        assert!(ensure_https_bitwarden_target(
            "http://127.0.0.1:9",
            Some("https://router.example/")
        )
        .is_ok());
    }

    #[test]
    fn context_folder_changes_for_proxy_and_cert() {
        let direct = build_bitwarden_browser_arguments(None);
        let proxy = build_bitwarden_browser_arguments(Some(loopback_proxy(1080)));
        assert_eq!(direct, HARDENING_BROWSER_ARGS);

        let d = build_context_folder_name(&direct, false);
        let d_cert = build_context_folder_name(&direct, true);
        let p = build_context_folder_name(&proxy, false);

        assert!(d.starts_with("profile-"));
        assert_eq!(d.len(), "profile-".len() + 16);
        assert!(d.chars().skip(8).all(|c| c.is_ascii_hexdigit()));
        assert_ne!(d, d_cert);
        assert_ne!(d, p);
        // Golden: hardening + cert=0
        assert_eq!(d, "profile-b7ab518aadff9ca3");
    }

    #[test]
    fn browser_args_do_not_embed_secrets() {
        let args = build_bitwarden_browser_arguments(Some(loopback_proxy(1080)));
        for needle in [
            "password",
            "BW_SESSION",
            "WORMHOLE_BW_PASSWORD",
            "--code",
            "--session",
        ] {
            assert!(
                !args.to_ascii_lowercase().contains(&needle.to_ascii_lowercase()),
                "args unexpectedly mention {needle}: {args}"
            );
        }
        // Proxy endpoint only — no credentials in socks5:// URL.
        assert!(args.contains("socks5://127.0.0.1:1080"));
        assert!(!args.contains('@'));
    }

    #[test]
    fn user_data_folder_without_route_includes_socks_port() {
        let root = Path::new(r"C:\fake\bitwarden-browser-webview2");
        let first = build_bitwarden_browser_arguments(Some(loopback_proxy(12000)));
        let second = build_bitwarden_browser_arguments(Some(loopback_proxy(23000)));
        assert_ne!(first, second);

        let a = user_data_folder(root, &first, false);
        let b = user_data_folder(root, &second, false);
        let direct = user_data_folder(root, &build_bitwarden_browser_arguments(None), false);
        let ignore = user_data_folder(root, &first, true);

        assert_ne!(a, b);
        assert_ne!(a, direct);
        assert_ne!(a, ignore);
        assert!(a.starts_with(root));
        // Folder name is a single safe segment (no traversal).
        let name = a.file_name().unwrap().to_string_lossy();
        assert!(name.starts_with("profile-"));
        assert!(!name.contains(".."));
        assert!(!name.contains('/') && !name.contains('\\'));
    }

    #[test]
    fn persistent_route_key_stable_across_port_rebind() {
        let tunnel = Uuid::parse_str("a7f3c1e2-9b6d-4e8a-bf21-7c0d2e5a4b91").unwrap();
        let other = Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap();
        let target = "https://router.example/login";

        let route = build_persistent_route_key(target, None, Some(tunnel)).unwrap();
        let rebound = build_persistent_route_key(target, None, Some(tunnel)).unwrap();
        let other_target =
            build_persistent_route_key("https://firewall.example/login", None, Some(tunnel))
                .unwrap();
        let other_tunnel = build_persistent_route_key(target, None, Some(other)).unwrap();
        let forwarder = build_persistent_route_key(
            "http://127.0.0.1:12000",
            Some(target),
            Some(tunnel),
        )
        .unwrap();

        assert_eq!(route, rebound);
        assert_ne!(route, other_target);
        assert_ne!(route, other_tunnel);
        assert_ne!(route, forwarder);
        assert_eq!(
            route,
            "0256ea8f5f6e744a34fe548fc124a96805ef734d4275ce2192b7206548ec98fe"
        );
        assert!(build_persistent_route_key(target, None, None).is_none());
        assert!(build_persistent_route_key("http://router.example/", None, Some(tunnel)).is_none());
    }

    #[test]
    fn user_data_folder_socks_keeps_runtime_args_and_route_identity() {
        let root = Path::new(r"C:\fake\bitwarden-browser-webview2");
        let tunnel = Uuid::new_v4();
        let target = "https://router.example/login";
        let first_args = build_bitwarden_browser_arguments(Some(loopback_proxy(12000)));
        let rebound_args = build_bitwarden_browser_arguments(Some(loopback_proxy(23000)));

        let first =
            user_data_folder_for_target(root, &first_args, false, target, None, Some(tunnel))
                .unwrap();
        let rebound =
            user_data_folder_for_target(root, &rebound_args, false, target, None, Some(tunnel))
                .unwrap();
        let other_target = user_data_folder_for_target(
            root,
            &first_args,
            false,
            "https://firewall.example/login",
            None,
            Some(tunnel),
        )
        .unwrap();
        let other_tunnel = user_data_folder_for_target(
            root,
            &first_args,
            false,
            target,
            None,
            Some(Uuid::new_v4()),
        )
        .unwrap();
        let forwarder = user_data_folder_for_target(
            root,
            &build_bitwarden_browser_arguments(None),
            false,
            "http://127.0.0.1:12000",
            Some(target),
            Some(tunnel),
        )
        .unwrap();

        assert_ne!(first, rebound);
        assert_ne!(first, other_target);
        assert_ne!(first, other_tunnel);
        assert_ne!(first, forwarder);
        assert!(first.starts_with(root));
    }

    #[test]
    fn user_data_folder_for_target_rejects_http() {
        let root = Path::new(r"C:\fake\bitwarden-browser-webview2");
        let args = build_bitwarden_browser_arguments(None);
        let err = user_data_folder_for_target(
            root,
            &args,
            false,
            "http://router.example/login",
            None,
            None,
        )
        .unwrap_err();
        assert_eq!(err, HttpError::BitwardenRequiresHttps);
        assert!(!format!("{err}").contains("router.example"));
    }

    #[test]
    fn loopback_forwarders_isolated_by_original_origin_when_no_tunnel() {
        let root = Path::new(r"C:\fake\bitwarden-browser-webview2");
        let args = build_bitwarden_browser_arguments(None);
        let original = "https://router.example/login";

        // With tunnel id, route key ignores navigate port — equal across rebinds.
        let tunnel = Uuid::new_v4();
        let first = user_data_folder_for_target(
            root,
            &args,
            true,
            "http://127.0.0.1:12000",
            Some(original),
            Some(tunnel),
        )
        .unwrap();
        let rebound = user_data_folder_for_target(
            root,
            &args,
            true,
            "http://127.0.0.1:23000",
            Some(original),
            Some(tunnel),
        )
        .unwrap();
        assert_eq!(first, rebound);

        // Without tunnel id, forwarded-target key also ignores navigate port.
        let a = user_data_folder_for_target(
            root,
            &args,
            true,
            "http://127.0.0.1:12000",
            Some(original),
            None,
        )
        .unwrap();
        let b = user_data_folder_for_target(
            root,
            &args,
            true,
            "http://127.0.0.1:23000",
            Some(original),
            None,
        )
        .unwrap();
        let other = user_data_folder_for_target(
            root,
            &args,
            true,
            "http://127.0.0.1:12000",
            Some("https://firewall.example/login"),
            None,
        )
        .unwrap();
        let direct = user_data_folder_for_target(root, &args, true, original, None, None).unwrap();

        assert_eq!(a, b);
        assert_ne!(a, other);
        assert_ne!(a, direct);
    }

    #[test]
    fn left_part_authority_strips_path() {
        assert_eq!(
            left_part_authority("https://router.example/login"),
            "https://router.example"
        );
        assert_eq!(
            left_part_authority("http://127.0.0.1:12000/"),
            "http://127.0.0.1:12000"
        );
    }
}
