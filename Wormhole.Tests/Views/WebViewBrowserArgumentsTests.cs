using System.Net;
using Wormhole.Views.Sessions;
using Xunit;

namespace Wormhole.Tests.Views;

public class WebViewBrowserArgumentsTests
{
    [Fact]
    public void Build_WithoutProxy_IsExactlyTheHardeningSet()
    {
        Assert.Equal(WebViewBrowserArguments.Hardening, WebViewBrowserArguments.Build(socks5Proxy: null));
    }

    [Fact]
    public void Build_WithProxy_PrependsSocks5Switch_AndKeepsHardening()
    {
        var args = WebViewBrowserArguments.Build(new IPEndPoint(IPAddress.Loopback, 58921));

        Assert.StartsWith("--proxy-server=socks5://127.0.0.1:58921 ", args);
        Assert.EndsWith(WebViewBrowserArguments.Hardening, args);
    }

    [Fact]
    public void Hardening_DisablesTheBackgroundTrafficSources()
    {
        // The load-bearing switches: background fetches (variations/safe-browsing/update pings),
        // component-updater downloads, domain-reliability uploads, hyperlink-auditing pings.
        Assert.Contains("--disable-background-networking", WebViewBrowserArguments.Hardening);
        Assert.Contains("--disable-component-update", WebViewBrowserArguments.Hardening);
        Assert.Contains("--disable-domain-reliability", WebViewBrowserArguments.Hardening);
        Assert.Contains("--no-pings", WebViewBrowserArguments.Hardening);
    }

    [Fact]
    public void Hardening_NeverUsesDisableFeatures()
    {
        // A --disable-features switch would REPLACE (not merge with) any feature list the WebView2
        // runtime sets for itself — Chromium takes the last occurrence of the switch. SmartScreen is
        // turned off via the supported CoreWebView2Settings.IsReputationCheckingRequired API instead.
        Assert.DoesNotContain("--disable-features", WebViewBrowserArguments.Hardening);
        Assert.DoesNotContain("--enable-features", WebViewBrowserArguments.Hardening);
    }
}
