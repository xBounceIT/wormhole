using System;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace Wormhole.Helpers;

/// <summary>
/// Composes the <c>AdditionalBrowserArguments</c> for every WebView2 environment the app creates —
/// web session tabs (<c>WebBrowserView</c>), the SSH terminal (<c>SshTerminalView</c>), and the
/// WatchGuard SAML / Azure VPN sign-in popups — plus the argument-fingerprinted folder naming that
/// keeps fixed-path environments compatible across app versions. Kept WinUI-free so the composition
/// is unit-testable (the test project re-compiles this file; XAML code-behind can't be).
/// </summary>
internal static class WebViewBrowserArguments
{
    /// <summary>
    /// Switches that stop the embedded browser's background services from generating network traffic
    /// of their own. No Wormhole surface needs them, and on a SOCKS-proxied (tunneled) web tab every
    /// such request would otherwise be sent through the customer's VPN:
    /// <list type="bullet">
    ///   <item><c>--disable-background-networking</c> — master switch for periodic background fetches
    ///   (variations/experiment config, safe-browsing list updates, metrics uploads, update pings).</item>
    ///   <item><c>--disable-component-update</c> — no component-updater downloads. Deliberate tradeoff:
    ///   browser-channel certificate-revocation lists (CRLSet-style components) stop refreshing mid-run
    ///   too; a baseline still ships with the WebView2 Runtime, which OS-level Edge Update keeps
    ///   current independently of this switch.</item>
    ///   <item><c>--disable-domain-reliability</c> — no domain-reliability beacon uploads.</item>
    ///   <item><c>--no-pings</c> — no hyperlink-auditing (&lt;a ping&gt;) requests.</item>
    /// </list>
    /// SmartScreen reputation checks are per-WebView state, not a switch: surfaces that render private
    /// appliance pages opt out via <c>CoreWebView2Settings.IsReputationCheckingRequired</c> (see
    /// WebBrowserView); the sign-in popups keep it on, since their IdP redirects navigate the open
    /// web. The supported setting is used instead of <c>--disable-features=msSmartScreenProtection</c>
    /// because WebView2 browser flags are documented dev/test-only and may be removed at any time —
    /// (not because of switch collisions: the docs state feature lists are merged by union with the
    /// runtime's own).
    /// </summary>
    internal const string Hardening =
        "--disable-background-networking --disable-component-update --disable-domain-reliability --no-pings";

    /// <summary>
    /// The hardening set, plus the SOCKS5 proxy switch when the surface routes through a tunnel.
    /// Chromium does remote DNS for <c>socks5://</c>, so the appliance hostname is resolved on the
    /// far side of the VPN. The explicit bypass subtraction keeps tunneled web sessions from
    /// bypassing the proxy for IP-literal targets on overlapping private subnets.
    /// </summary>
    internal static string Build(IPEndPoint? socks5Proxy) =>
        socks5Proxy is null
            ? Hardening
            : $"--proxy-server=socks5://{socks5Proxy} --proxy-bypass-list=<-loopback> {Hardening}";

    /// <summary>
    /// Folder name for a fixed-path (shared/persistent) environment, fingerprinted by the browser
    /// arguments it runs with. WebView2 requires every environment over one user-data folder — across
    /// processes and app versions — to use identical browser arguments; a mismatch fails environment
    /// creation with ERROR_INVALID_STATE. Keying the folder name by the arguments gives builds with
    /// different arguments disjoint folders instead of a startup race (e.g. an installed older build
    /// running side by side with a dev build). Per-tab isolated web environments use unique GUID
    /// folders and don't need this.
    /// </summary>
    internal static string KeyedSharedFolderName { get; } =
        "shared-" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Hardening)))[..8].ToLowerInvariant();

    /// <summary>
    /// Best-effort removal of keyed shared folders under <paramref name="parent"/> left behind by
    /// builds with a different argument set (their fingerprint differs from the current one). A folder
    /// locked by a still-running older build is skipped and swept on a later launch. Call before
    /// creating a fixed-path environment whose root is not already wiped at startup.
    /// </summary>
    internal static void SweepStaleKeyedFolders(string parent)
    {
        try
        {
            if (!Directory.Exists(parent)) return;
            foreach (var dir in Directory.GetDirectories(parent, "shared-*"))
            {
                if (string.Equals(Path.GetFileName(dir), KeyedSharedFolderName, StringComparison.OrdinalIgnoreCase))
                    continue;
                try { Directory.Delete(dir, recursive: true); }
                catch (Exception) { /* locked by a running older build — a later launch retries */ }
            }
        }
        catch (Exception)
        {
            // Enumeration failure is non-fatal: stale folders cost disk space, not correctness.
        }
    }
}
