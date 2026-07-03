using System.Net;
using Wormhole.Services.BitwardenBrowser;
using Xunit;

namespace Wormhole.Tests.Services;

public sealed class BitwardenBrowserWebViewProfileTests
{
    [Fact]
    public void IsHttpsTarget_UsesOriginalHttpsUriForLoopbackForwarderTargets()
    {
        Assert.True(BitwardenBrowserWebViewProfile.IsHttpsTarget(new Uri("https://router.example/login"), originalUri: null));
        Assert.True(BitwardenBrowserWebViewProfile.IsHttpsTarget(new Uri("http://127.0.0.1:54321"), new Uri("https://router.example/login")));
        Assert.False(BitwardenBrowserWebViewProfile.IsHttpsTarget(new Uri("http://router.example/login"), originalUri: null));
        Assert.False(BitwardenBrowserWebViewProfile.IsHttpsTarget(new Uri("http://127.0.0.1:54321"), new Uri("http://router.example/login")));
    }

    [Fact]
    public void ContextFolderName_ChangesForProxyAndCertificatePolicy()
    {
        var directArgs = BitwardenBrowserWebViewProfile.BuildBrowserArguments(null);
        var proxyArgs = BitwardenBrowserWebViewProfile.BuildBrowserArguments(new IPEndPoint(IPAddress.Loopback, 1080));

        var direct = BitwardenBrowserWebViewProfile.BuildContextFolderName(directArgs, ignoreCertificateErrors: false);
        var directIgnoreCert = BitwardenBrowserWebViewProfile.BuildContextFolderName(directArgs, ignoreCertificateErrors: true);
        var proxy = BitwardenBrowserWebViewProfile.BuildContextFolderName(proxyArgs, ignoreCertificateErrors: false);

        Assert.StartsWith("profile-", direct, StringComparison.Ordinal);
        Assert.NotEqual(direct, directIgnoreCert);
        Assert.NotEqual(direct, proxy);
    }

    [Fact]
    public void PendingWebDataOrigins_RoundTripsNormalizedHttpOrigins()
    {
        var profile = Path.Combine(Path.GetTempPath(), "wormhole-bitwarden-webview-" + Guid.NewGuid().ToString("N"));
        try
        {
            BitwardenBrowserWebViewProfile.AddPendingWebDataOrigins(profile,
            [
                "https://Example.test/login",
                "https://example.test/other",
                "http://127.0.0.1:54321/path",
                "chrome-extension://abcdef/popup.html",
                "not a uri",
            ]);

            var origins = BitwardenBrowserWebViewProfile.ReadPendingWebDataOrigins(profile)
                .Order(StringComparer.Ordinal)
                .ToArray();

            Assert.Equal(["http://127.0.0.1:54321", "https://example.test"], origins);
        }
        finally
        {
            if (Directory.Exists(profile)) Directory.Delete(profile, recursive: true);
        }
    }

    [Fact]
    public void RemovePendingWebDataOrigins_RemovesOnlyClearedOrigins()
    {
        var profile = Path.Combine(Path.GetTempPath(), "wormhole-bitwarden-webview-" + Guid.NewGuid().ToString("N"));
        try
        {
            BitwardenBrowserWebViewProfile.AddPendingWebDataOrigins(profile,
            [
                "https://first.example",
                "https://second.example",
            ]);

            BitwardenBrowserWebViewProfile.RemovePendingWebDataOrigins(profile, ["https://first.example/path"]);

            Assert.Equal(["https://second.example"], BitwardenBrowserWebViewProfile.ReadPendingWebDataOrigins(profile));

            BitwardenBrowserWebViewProfile.RemovePendingWebDataOrigins(profile, ["https://second.example"]);

            Assert.Empty(BitwardenBrowserWebViewProfile.ReadPendingWebDataOrigins(profile));
        }
        finally
        {
            if (Directory.Exists(profile)) Directory.Delete(profile, recursive: true);
        }
    }
}
