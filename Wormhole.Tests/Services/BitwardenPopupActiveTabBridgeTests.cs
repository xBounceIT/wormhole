using System.Net;
using System.Text.Json;
using Wormhole.Services.BitwardenBrowser;
using Wormhole.ViewModels.Sessions;
using Xunit;

namespace Wormhole.Tests.Services;

public sealed class BitwardenPopupActiveTabBridgeTests
{
    [Fact]
    public void CreateContext_DirectTarget_UsesCurrentPageUrl()
    {
        var target = new HttpConnectionTarget(
            new Uri("https://fw.local/"),
            Socks5Proxy: null,
            IgnoreCertErrors: false);

        var context = BitwardenPopupActiveTabBridge.CreateContext(
            target,
            "https://fw.local/admin/page.html?section=users#selected");

        Assert.NotNull(context);
        Assert.Equal("https://fw.local/admin/page.html?section=users#selected", context.PhysicalUrl);
        Assert.Equal(context.PhysicalUrl, context.LogicalUrl);
    }

    [Fact]
    public void CreateContext_DirectRedirect_UsesLiveRedirectUrl()
    {
        var target = new HttpConnectionTarget(
            new Uri("https://fw.local/"),
            Socks5Proxy: null,
            IgnoreCertErrors: false);

        var context = BitwardenPopupActiveTabBridge.CreateContext(
            target,
            "https://login.fw.local/sso/callback#complete");

        Assert.NotNull(context);
        Assert.Equal("https://login.fw.local/sso/callback#complete", context.LogicalUrl);
    }

    [Fact]
    public void CreateContext_SocksTarget_UsesRealCurrentUrl()
    {
        var target = new HttpConnectionTarget(
            new Uri("https://fw.local/"),
            new IPEndPoint(IPAddress.Loopback, 1080),
            IgnoreCertErrors: false);

        var context = BitwardenPopupActiveTabBridge.CreateContext(
            target,
            "https://fw.local/dashboard?via=tunnel#status");

        Assert.NotNull(context);
        Assert.Equal(context.PhysicalUrl, context.LogicalUrl);
        Assert.Equal("https://fw.local/dashboard?via=tunnel#status", context.LogicalUrl);
    }

    [Fact]
    public void CreateContext_LoopbackForwarder_ExposesOriginalAuthorityAndLiveSuffix()
    {
        var target = new HttpConnectionTarget(
            new Uri("https://127.0.0.1:51515/"),
            Socks5Proxy: null,
            IgnoreCertErrors: true,
            OriginalUri: new Uri("https://fw.local:8443/"));

        var context = BitwardenPopupActiveTabBridge.CreateContext(
            target,
            "https://127.0.0.1:51515/admin/page.html?section=vpn#status");

        Assert.NotNull(context);
        Assert.Equal(
            "https://127.0.0.1:51515/admin/page.html?section=vpn#status",
            context.PhysicalUrl);
        Assert.Equal(
            "https://fw.local:8443/admin/page.html?section=vpn#status",
            context.LogicalUrl);
    }

    [Fact]
    public void CreateContext_NonWebCurrentSource_FallsBackToNavigationTarget()
    {
        var target = new HttpConnectionTarget(
            new Uri("https://fw.local/"),
            Socks5Proxy: null,
            IgnoreCertErrors: false);

        var context = BitwardenPopupActiveTabBridge.CreateContext(
            target,
            "chrome-extension://extension-id/popup/index.html");

        Assert.NotNull(context);
        Assert.Equal("https://fw.local/", context.PhysicalUrl);
        Assert.Equal(context.PhysicalUrl, context.LogicalUrl);
    }

    [Fact]
    public void CreateContext_NonWebTargetAndSource_ReturnsNull()
    {
        var target = new HttpConnectionTarget(
            new Uri("file:///C:/temp/page.html"),
            Socks5Proxy: null,
            IgnoreCertErrors: false);

        Assert.Null(BitwardenPopupActiveTabBridge.CreateContext(target, "about:blank"));
    }

    [Fact]
    public void BuildScript_JsonSerializesUntrustedUrls()
    {
        var context = new BitwardenActiveTabContext(
            "https://fw.local/path/\"quoted\"?value=</script>",
            "https://appliancé.local/path/\"quoted\"?line=one\r\ntwo");

        var script = BitwardenPopupActiveTabBridge.BuildScript(context);
        var payload = JsonSerializer.Serialize(context);

        Assert.Contains($"const context = {payload};", script);
        Assert.DoesNotContain("</script>", script, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("queryInfo?.active === true", script);
        Assert.Contains("queryInfo?.currentWindow === true", script);
    }

    [Fact]
    public void BuildScript_PreservesNativePromiseOverloadForOtherQueries()
    {
        var context = new BitwardenActiveTabContext(
            "https://fw.local/physical",
            "https://fw.local/logical");

        var script = BitwardenPopupActiveTabBridge.BuildScript(context);

        Assert.Contains(
            """
            return typeof callback === "function"
                            ? nativeQuery(queryInfo, callback)
                            : nativeQuery(queryInfo);
            """,
            script);
    }
}
