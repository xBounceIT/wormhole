//! Custom-protocol asset serving for `http://wormhole.localhost/…`.

use std::borrow::Cow;
use std::fs;
use std::path::{Component, Path};

use wry::http::{header, Request, Response, StatusCode};

/// Virtual host wry binds to the `wormhole` custom protocol on Windows.
pub const WORMHOLE_VIRTUAL_HOST: &str = "wormhole.localhost";

/// Serve a custom-protocol request only for the Wormhole virtual host.
///
/// Rejects foreign hosts, path traversal (`..`, absolute / drive paths), and
/// paths that escape `root` after canonicalize.
pub fn serve_protocol_request(
    root: &Path,
    request: &Request<Vec<u8>>,
) -> Response<Cow<'static, [u8]>> {
    serve_protocol_uri(root, request.uri())
}

/// Serve `uri` when it targets [`WORMHOLE_VIRTUAL_HOST`] (or the `wormhole` scheme).
pub fn serve_protocol_uri(root: &Path, uri: &wry::http::Uri) -> Response<Cow<'static, [u8]>> {
    if !is_wormhole_virtual_host(uri) {
        return not_found();
    }
    serve_local(root, uri.path())
}

/// True when `uri` is allowed to read the Assets/web custom-protocol root.
pub fn is_wormhole_virtual_host(uri: &wry::http::Uri) -> bool {
    is_wormhole_virtual_host_parts(uri.scheme_str(), uri.host())
}

/// Scheme/host gate used by [`is_wormhole_virtual_host`] (testable without exotic URIs).
pub fn is_wormhole_virtual_host_parts(scheme: Option<&str>, host: Option<&str>) -> bool {
    match scheme {
        // Scheme is registered exclusively for this handler.
        Some("wormhole") => true,
        Some("http") | Some("https") => {
            host.is_some_and(|h| h.eq_ignore_ascii_case(WORMHOLE_VIRTUAL_HOST))
        }
        _ => false,
    }
}

/// Serve a file under `root` for a custom-protocol request path.
///
/// Rejects path traversal (`..`, absolute escapes) via safe relative checks
/// plus canonicalize + prefix check.
pub fn serve_local(root: &Path, path: &str) -> Response<Cow<'static, [u8]>> {
    let Some(rel) = normalize_protocol_path(path) else {
        return not_found();
    };
    let full = root.join(rel);
    let Ok(canon_root) = root.canonicalize() else {
        return not_found();
    };
    let Ok(canon_file) = full.canonicalize() else {
        return not_found();
    };
    if !canon_file.starts_with(&canon_root) {
        return not_found();
    }
    match fs::read(&canon_file) {
        Ok(bytes) => {
            let mime = mime_for(rel);
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, mime)
                .body(Cow::Owned(bytes))
                .unwrap_or_else(|_| not_found())
        }
        Err(_) => not_found(),
    }
}

/// Map wry custom-protocol paths onto files under the assets root.
///
/// Returns `None` when the path is unsafe (traversal, absolute, empty segments).
pub fn normalize_protocol_path(path: &str) -> Option<&str> {
    let mut rel = path.trim_start_matches('/');
    if rel.is_empty() || rel == "localhost" {
        return Some("terminal.html");
    }
    if let Some(stripped) = rel.strip_prefix("localhost/") {
        rel = stripped;
    }
    if rel.is_empty() {
        return Some("terminal.html");
    }
    if !is_safe_relative_asset_path(rel) {
        return None;
    }
    Some(rel)
}

/// True when `rel` has no `..`, `.`, empty segments, or absolute/drive form.
pub fn is_safe_relative_asset_path(rel: &str) -> bool {
    if rel.is_empty() {
        return false;
    }
    // Windows drive / UNC / rooted paths must never be joined as relatives.
    if Path::new(rel).is_absolute()
        || rel.starts_with('\\')
        || rel.starts_with("//")
        || (rel.len() >= 2 && rel.as_bytes()[1] == b':')
    {
        return false;
    }
    for comp in rel.split(['/', '\\']) {
        if comp.is_empty() || comp == "." || comp == ".." {
            return false;
        }
    }
    true
}

/// True when `root` looks like repo `Assets/web` (leaf names after canonicalize).
pub fn is_assets_web_layout(root: &Path) -> bool {
    if !root.join("terminal.html").is_file() {
        return false;
    }
    let Ok(canon) = root.canonicalize() else {
        // Best-effort: require the path to end with `…/Assets/web` components.
        return path_ends_with_assets_web(root);
    };
    path_ends_with_assets_web(&canon)
}

fn path_ends_with_assets_web(path: &Path) -> bool {
    let mut comps = path.components().rev().filter_map(|c| match c {
        Component::Normal(s) => s.to_str(),
        _ => None,
    });
    let web = comps.next();
    let assets = comps.next();
    matches!(
        (web, assets),
        (Some(w), Some(a)) if w.eq_ignore_ascii_case("web") && a.eq_ignore_ascii_case("Assets")
    )
}

fn not_found() -> Response<Cow<'static, [u8]>> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Cow::Borrowed(b"not found" as &[u8]))
        .unwrap_or_else(|_| Response::new(Cow::Borrowed(b"not found" as &[u8])))
}

/// MIME type from a relative asset path extension.
pub fn mime_for(path: &str) -> &'static str {
    match Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
    {
        "html" | "htm" => "text/html; charset=utf-8",
        "js" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "woff2" => "font/woff2",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::path::PathBuf;

    #[test]
    fn normalize_defaults_and_strips_localhost_prefix() {
        assert_eq!(normalize_protocol_path(""), Some("terminal.html"));
        assert_eq!(normalize_protocol_path("/"), Some("terminal.html"));
        assert_eq!(normalize_protocol_path("/localhost"), Some("terminal.html"));
        assert_eq!(
            normalize_protocol_path("/localhost/bridge.js"),
            Some("bridge.js")
        );
        assert_eq!(
            normalize_protocol_path("/vendor/xterm/xterm.js"),
            Some("vendor/xterm/xterm.js")
        );
    }

    #[test]
    fn normalize_rejects_traversal_and_absolute() {
        assert_eq!(normalize_protocol_path("/../../Windows/win.ini"), None);
        assert_eq!(normalize_protocol_path("/vendor/../../../etc/passwd"), None);
        assert_eq!(normalize_protocol_path("/C:/Windows/win.ini"), None);
        assert_eq!(normalize_protocol_path("/vendor/./xterm.js"), None);
        assert_eq!(normalize_protocol_path("/vendor//xterm.js"), None);
    }

    #[test]
    fn mime_for_known_extensions() {
        assert!(mime_for("a.html").starts_with("text/html"));
        assert!(mime_for("a.js").starts_with("text/javascript"));
        assert_eq!(mime_for("a.bin"), "application/octet-stream");
    }

    #[test]
    fn serve_local_rejects_traversal() {
        let dir = tempfile_dir();
        let mut f = fs::File::create(dir.join("ok.txt")).expect("create");
        writeln!(f, "ok").expect("write");
        drop(f);

        let resp = serve_local(&dir, "/../../Windows/win.ini");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let resp_abs = serve_local(&dir, "/C:/Windows/win.ini");
        assert_eq!(resp_abs.status(), StatusCode::NOT_FOUND);

        let resp_ok = serve_local(&dir, "/ok.txt");
        assert_eq!(resp_ok.status(), StatusCode::OK);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn virtual_host_allows_only_wormhole_localhost() {
        let ok: wry::http::Uri = "http://wormhole.localhost/terminal.html".parse().unwrap();
        assert!(is_wormhole_virtual_host(&ok));
        let ok_case: wry::http::Uri = "http://Wormhole.LocalHost/bridge.js".parse().unwrap();
        assert!(is_wormhole_virtual_host(&ok_case));
        assert!(is_wormhole_virtual_host_parts(Some("wormhole"), None));
        assert!(is_wormhole_virtual_host_parts(
            Some("wormhole"),
            Some("localhost")
        ));

        let evil: wry::http::Uri = "http://evil.localhost/terminal.html".parse().unwrap();
        assert!(!is_wormhole_virtual_host(&evil));
        assert!(!is_wormhole_virtual_host_parts(Some("file"), Some("localhost")));
        assert!(!is_wormhole_virtual_host_parts(
            Some("http"),
            Some("evil.localhost")
        ));
        assert!(!is_wormhole_virtual_host_parts(
            None,
            Some(WORMHOLE_VIRTUAL_HOST)
        ));
    }

    #[test]
    fn serve_protocol_uri_rejects_foreign_host() {
        let dir = tempfile_dir();
        let mut f = fs::File::create(dir.join("ok.txt")).expect("create");
        writeln!(f, "ok").expect("write");
        drop(f);

        let evil: wry::http::Uri = "http://evil.localhost/ok.txt".parse().unwrap();
        assert_eq!(serve_protocol_uri(&dir, &evil).status(), StatusCode::NOT_FOUND);

        let ok: wry::http::Uri = "http://wormhole.localhost/ok.txt".parse().unwrap();
        assert_eq!(serve_protocol_uri(&dir, &ok).status(), StatusCode::OK);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn assets_web_layout_requires_assets_web_leaf_names() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let base = std::env::temp_dir().join(format!("wormhole-assets-layout-{nanos}"));
        let web = base.join("Assets").join("web");
        fs::create_dir_all(&web).expect("mkdir");
        fs::write(web.join("terminal.html"), b"<html></html>").expect("write");
        assert!(is_assets_web_layout(&web));

        let other = base.join("Other").join("web");
        fs::create_dir_all(&other).expect("mkdir");
        fs::write(other.join("terminal.html"), b"<html></html>").expect("write");
        assert!(!is_assets_web_layout(&other));
        let _ = fs::remove_dir_all(&base);
    }

    fn tempfile_dir() -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("wormhole-assets-test-{nanos}"));
        fs::create_dir_all(&dir).expect("mkdir");
        dir
    }
}
