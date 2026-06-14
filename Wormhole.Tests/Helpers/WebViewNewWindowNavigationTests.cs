using System;
using Wormhole.Helpers;
using Xunit;

namespace Wormhole.Tests.Helpers;

public class WebViewNewWindowNavigationTests
{
    [Theory]
    [InlineData("https://fw.local/dashboard", "https://fw.local/dashboard")]
    [InlineData("http://fw.local/help", "http://fw.local/help")]
    [InlineData("  https://fw.local/dashboard  ", "https://fw.local/dashboard")]
    public void GetInSessionNavigationUri_TargetUrl_ReturnsNavigation(string rawUri, string expected)
    {
        var navigationUri = WebViewNewWindowNavigation.GetInSessionNavigationUri(rawUri);

        Assert.Equal(expected, navigationUri);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData(null)]
    [InlineData("about:blank")]
    [InlineData("ABOUT:blank")]
    [InlineData("about:blank#blocked")]
    [InlineData("about:blank?popup")]
    public void GetInSessionNavigationUri_BlankTarget_SuppressesOnly(string? rawUri)
    {
        var navigationUri = WebViewNewWindowNavigation.GetInSessionNavigationUri(rawUri);

        Assert.Null(navigationUri);
    }

    [Fact]
    public void GetInSessionNavigationUri_ForwarderTarget_RewritesOriginalOriginThroughForwarder()
    {
        var navigationUri = WebViewNewWindowNavigation.GetInSessionNavigationUri(
            "https://fw.local:443/dashboard?tab=vpn#status",
            routedBaseUri: new Uri("https://127.0.0.1:51515/"),
            originalBaseUri: new Uri("https://fw.local:443/"));

        Assert.Equal("https://127.0.0.1:51515/dashboard?tab=vpn#status", navigationUri);
    }

    [Fact]
    public void GetInSessionNavigationUri_ForwarderTarget_AllowsAlreadyRoutedPopupUri()
    {
        var navigationUri = WebViewNewWindowNavigation.GetInSessionNavigationUri(
            "https://127.0.0.1:51515/dashboard",
            routedBaseUri: new Uri("https://127.0.0.1:51515/"),
            originalBaseUri: new Uri("https://fw.local:443/"));

        Assert.Equal("https://127.0.0.1:51515/dashboard", navigationUri);
    }

    [Theory]
    [InlineData("https://docs.example.com/")]
    [InlineData("https://fw.local:8443/dashboard")]
    [InlineData("/relative-popup")]
    public void GetInSessionNavigationUri_ForwarderTarget_SuppressesUnroutableTargets(string rawUri)
    {
        var navigationUri = WebViewNewWindowNavigation.GetInSessionNavigationUri(
            rawUri,
            routedBaseUri: new Uri("https://127.0.0.1:51515/"),
            originalBaseUri: new Uri("https://fw.local:443/"));

        Assert.Null(navigationUri);
    }
}
