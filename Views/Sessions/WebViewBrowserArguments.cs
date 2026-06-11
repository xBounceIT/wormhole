using System.Net;

namespace Wormhole.Views.Sessions;

/// <summary>
/// Builds the <c>AdditionalBrowserArguments</c> for every WebView2 environment
/// <see cref="WebBrowserView"/> creates. Kept WinUI-free so the argument composition is unit-testable
/// (the test project re-compiles this file; the XAML code-behind itself can't be).
/// </summary>
internal static class WebViewBrowserArguments
{
    /// <summary>
    /// Switches that stop the embedded browser's background services from generating network traffic
    /// of their own. Wormhole's web tabs render private appliance/firewall GUIs; none of Chromium's
    /// background machinery is wanted there — and on a SOCKS-proxied (tunneled) tab every one of those
    /// requests would otherwise be sent through the customer's VPN, observed live as a flood of
    /// "[ovpnproxy] dial edge.microsoft.com:443 failed: resolve ... through tunnel DNS" sidecar noise.
    ///
    /// <list type="bullet">
    ///   <item><c>--disable-background-networking</c> — master switch for the periodic background
    ///   fetches (variations/experiment config such as config.edge.skype.com, safe-browsing list
    ///   updates, metrics uploads, update pings to edge.microsoft.com).</item>
    ///   <item><c>--disable-component-update</c> — no component-updater downloads (Widevine,
    ///   certificate/trust lists, etc.); the appliance pages don't use them.</item>
    ///   <item><c>--disable-domain-reliability</c> — no domain-reliability beacon uploads.</item>
    ///   <item><c>--no-pings</c> — no hyperlink auditing (&lt;a ping&gt;) requests.</item>
    /// </list>
    ///
    /// SmartScreen reputation checks (the remaining built-in source of per-navigation Microsoft
    /// traffic) are turned off via the supported <c>CoreWebView2Settings.IsReputationCheckingRequired</c>
    /// API instead of <c>--disable-features=msSmartScreenProtection</c>: a <c>--disable-features</c>
    /// switch here would silently REPLACE any feature list the WebView2 runtime sets for itself
    /// (Chromium takes the last occurrence), which is exactly the kind of fragility the browser-flags
    /// docs warn about.
    /// </summary>
    internal const string Hardening =
        "--disable-background-networking --disable-component-update --disable-domain-reliability --no-pings";

    /// <summary>
    /// Compose the full argument string: the hardening set, plus the SOCKS5 proxy switch when the tab
    /// routes through a tunnel. Chromium does remote DNS for <c>socks5://</c>, so the appliance
    /// hostname is resolved on the far side of the VPN.
    /// </summary>
    internal static string Build(IPEndPoint? socks5Proxy) =>
        socks5Proxy is null ? Hardening : $"--proxy-server=socks5://{socks5Proxy} {Hardening}";
}
