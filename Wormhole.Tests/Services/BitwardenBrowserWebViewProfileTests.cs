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
    public void EphemeralWebDataPaths_ClearWebStateWithoutExtensionStorage()
    {
        var profile = Path.Combine(Path.GetTempPath(), "wormhole-bitwarden-webview-" + Guid.NewGuid().ToString("N"));
        var siteIndexedDb = Path.Combine(profile, "Default", "IndexedDB", "https_example.test_0.indexeddb.leveldb");
        var extensionIndexedDb = Path.Combine(profile, "Default", "IndexedDB", "chrome-extension_abc_0.indexeddb.leveldb");
        try
        {
            Directory.CreateDirectory(siteIndexedDb);
            Directory.CreateDirectory(extensionIndexedDb);

            var paths = BitwardenBrowserWebViewProfile.GetEphemeralWebDataPaths(profile);

            Assert.Contains(Path.Combine(profile, "Default", "Network", "Cookies"), paths);
            Assert.Contains(Path.Combine(profile, "Default", "Local Storage"), paths);
            Assert.Contains(Path.Combine(profile, "Default", "Session Storage"), paths);
            Assert.Contains(Path.Combine(profile, "Default", "Cache"), paths);
            Assert.Contains(siteIndexedDb, paths);
            Assert.DoesNotContain(extensionIndexedDb, paths);
            Assert.DoesNotContain(Path.Combine(profile, "Default", "IndexedDB"), paths);
            Assert.DoesNotContain(paths, path => path.Contains("Extension", StringComparison.OrdinalIgnoreCase));
            Assert.DoesNotContain(paths, path => path.Contains("Local Extension Settings", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            if (Directory.Exists(profile)) Directory.Delete(profile, recursive: true);
        }
    }
}
