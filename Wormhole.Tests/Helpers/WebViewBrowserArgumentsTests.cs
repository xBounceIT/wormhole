using System;
using System.IO;
using System.Net;
using Wormhole.Helpers;
using Xunit;

namespace Wormhole.Tests.Helpers;

public class WebViewBrowserArgumentsTests
{
    [Fact]
    public void Build_WithoutProxy_IsTheExactHardeningSet()
    {
        // Golden literal (not a reference to the const): pins switch content, ordering, and the
        // absence of extras in one assertion — a change to the const must consciously update this.
        Assert.Equal(
            "--disable-background-networking --disable-component-update --disable-domain-reliability --no-pings",
            WebViewBrowserArguments.Build(socks5Proxy: null));
    }

    [Fact]
    public void Build_WithProxy_PrependsSocks5Switch_AndKeepsHardening()
    {
        var args = WebViewBrowserArguments.Build(new IPEndPoint(IPAddress.Loopback, 58921));

        Assert.StartsWith("--proxy-server=socks5://127.0.0.1:58921 ", args);
        Assert.EndsWith(WebViewBrowserArguments.Hardening, args);
    }

    [Fact]
    public void Hardening_NeverUsesFeatureSwitches()
    {
        // Policy: feature toggles (e.g. SmartScreen) go through supported per-WebView APIs, never
        // --enable/--disable-features — browser flags are documented dev/test-only and may be
        // removed at any time. (Per the WebView2 docs, feature lists ARE merged by union with the
        // runtime's own, so collision is not the concern; supportability is.)
        Assert.DoesNotContain("--disable-features", WebViewBrowserArguments.Hardening);
        Assert.DoesNotContain("--enable-features", WebViewBrowserArguments.Hardening);
    }

    [Fact]
    public void KeyedSharedFolderName_IsAStableArgsFingerprint()
    {
        // Shared user-data folders are keyed by the browser arguments so builds with different
        // arguments use disjoint folders (WebView2 fails creation with ERROR_INVALID_STATE on an
        // argument mismatch over a shared folder).
        var name = WebViewBrowserArguments.KeyedSharedFolderName;

        Assert.Matches("^shared-[0-9a-f]{8}$", name);
        Assert.Equal(name, WebViewBrowserArguments.KeyedSharedFolderName);
    }

    [Fact]
    public void SweepStaleKeyedFolders_RemovesOtherKeys_KeepsCurrentAndForeignFolders()
    {
        var root = Directory.CreateTempSubdirectory("wh-keyed-sweep-test").FullName;
        try
        {
            var current = Path.Combine(root, WebViewBrowserArguments.KeyedSharedFolderName);
            var stale = Path.Combine(root, "shared-deadbeef");
            var foreign = Path.Combine(root, "env-1234"); // isolated-tab folders must never be touched
            Directory.CreateDirectory(current);
            Directory.CreateDirectory(stale);
            Directory.CreateDirectory(foreign);

            WebViewBrowserArguments.SweepStaleKeyedFolders(root);

            Assert.True(Directory.Exists(current));
            Assert.False(Directory.Exists(stale));
            Assert.True(Directory.Exists(foreign));
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch (IOException) { }
        }
    }

    [Fact]
    public void SweepStaleKeyedFolders_MissingRoot_IsANoOp()
    {
        var missing = Path.Combine(Path.GetTempPath(), "wh-keyed-sweep-missing-" + Guid.NewGuid().ToString("N"));
        WebViewBrowserArguments.SweepStaleKeyedFolders(missing); // must not throw
        Assert.False(Directory.Exists(missing));
    }
}
