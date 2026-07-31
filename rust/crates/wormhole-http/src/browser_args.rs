//! WebView2 additional browser arguments (from `Helpers/WebViewBrowserArguments.cs`).

use crate::target::Socks5Proxy;

/// Hardening switches shared by all Wormhole WebView2 environments.
pub const HARDENING_BROWSER_ARGS: &str =
    "--disable-background-networking --disable-component-update --disable-domain-reliability --no-pings";

/// Compose AdditionalBrowserArguments; prepend SOCKS when routing through a tunnel.
pub fn build_browser_arguments(socks5: Option<Socks5Proxy>) -> String {
    match socks5 {
        None => HARDENING_BROWSER_ARGS.to_string(),
        Some(proxy) => format!(
            "--proxy-server=socks5://{} --proxy-bypass-list=<-loopback> {HARDENING_BROWSER_ARGS}",
            proxy.proxy_server_endpoint()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::Socks5Proxy;

    #[test]
    fn hardening_only_without_proxy() {
        assert_eq!(build_browser_arguments(None), HARDENING_BROWSER_ARGS);
    }

    #[test]
    fn socks_prepends_proxy_and_bypass() {
        let args = build_browser_arguments(Some(Socks5Proxy::loopback(58921).unwrap()));
        assert!(args.starts_with("--proxy-server=socks5://127.0.0.1:58921 "));
        assert!(args.contains("--proxy-bypass-list=<-loopback>"));
        assert!(args.contains(HARDENING_BROWSER_ARGS));
    }
}
