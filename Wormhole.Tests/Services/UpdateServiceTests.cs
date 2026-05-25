using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Models;
using Wormhole.Services;
using Xunit;

namespace Wormhole.Tests.Services;

public class UpdateServiceTests
{
    [Theory]
    [InlineData("v1.2.3", "1.2.3")]
    [InlineData("1.2.3", "1.2.3")]
    [InlineData("V1.2.3.4", "1.2.3.4")]
    [InlineData("  v0.1.0  ", "0.1.0")]
    public void TryParseTagVersion_HandlesPrefixesAndWhitespace(string tag, string expected)
    {
        Assert.True(UpdateService.TryParseTagVersion(tag, out var v));
        Assert.Equal(Version.Parse(expected), v);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-a-version")]
    [InlineData("v1.2.3-rc1")]
    public void TryParseTagVersion_RejectsInvalid(string? tag)
    {
        Assert.False(UpdateService.TryParseTagVersion(tag, out _));
    }

    [Theory]
    [InlineData("https://github.com/wormhole-project/wormhole", "wormhole-project", "wormhole")]
    [InlineData("https://github.com/wormhole-project/wormhole.git", "wormhole-project", "wormhole")]
    [InlineData("https://github.com/Some-Org/Repo-Name/", "Some-Org", "Repo-Name")]
    public void TryParseRepoUrl_HandlesValidUrls(string url, string expectedOwner, string expectedRepo)
    {
        Assert.True(UpdateService.TryParseRepoUrl(url, out var owner, out var repo));
        Assert.Equal(expectedOwner, owner);
        Assert.Equal(expectedRepo, repo);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-a-url")]
    [InlineData("https://gitlab.com/foo/bar")]
    public void TryParseRepoUrl_RejectsInvalid(string? url)
    {
        Assert.False(UpdateService.TryParseRepoUrl(url, out _, out _));
    }

    [Fact]
    public void FindInstallerAsset_MatchesByArchSuffix()
    {
        var release = new GitHubRelease();
        release.Assets.Add(new GitHubReleaseAsset
        {
            Name = "Wormhole-0.2.0-win-x64-setup.exe",
            BrowserDownloadUrl = "https://example/x64",
        });
        release.Assets.Add(new GitHubReleaseAsset
        {
            Name = "Wormhole-0.2.0-win-arm64-setup.exe",
            BrowserDownloadUrl = "https://example/arm64",
        });
        release.Assets.Add(new GitHubReleaseAsset
        {
            Name = "Wormhole-0.2.0-win-x64-setup.exe.sha256",
            BrowserDownloadUrl = "https://example/x64sha",
        });

        var x64 = UpdateService.FindInstallerAsset(release, "x64");
        Assert.NotNull(x64);
        Assert.Equal("Wormhole-0.2.0-win-x64-setup.exe", x64!.Name);

        var arm = UpdateService.FindInstallerAsset(release, "arm64");
        Assert.NotNull(arm);
        Assert.Equal("Wormhole-0.2.0-win-arm64-setup.exe", arm!.Name);
    }

    [Fact]
    public void FindInstallerAsset_ReturnsNullWhenNoMatch()
    {
        var release = new GitHubRelease();
        release.Assets.Add(new GitHubReleaseAsset
        {
            Name = "Wormhole-0.2.0-win-arm64-setup.exe",
            BrowserDownloadUrl = "x",
        });

        Assert.Null(UpdateService.FindInstallerAsset(release, "x64"));
    }

    [Theory]
    [InlineData(
        "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
        "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234")]
    [InlineData(
        "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234  Wormhole-0.2.0-win-x64-setup.exe\n",
        "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234")]
    [InlineData(
        "  ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234  ",
        "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234")]
    public void ParseShaSidecar_ExtractsHexDigest(string raw, string expected)
    {
        Assert.Equal(expected, UpdateService.ParseShaSidecar(raw));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-hex-stuff")]
    [InlineData("abcd")]
    public void ParseShaSidecar_RejectsInvalid(string? raw)
    {
        Assert.Null(UpdateService.ParseShaSidecar(raw!));
    }

    [Fact]
    public async Task CheckAsync_FlagsUpdate_WhenVersionHigher()
    {
        UpdateService.TryGetTargetArchitecture(out var arch);
        var json = MakeReleaseJson(
            tag: "v9.9.9",
            draft: false,
            prerelease: false,
            assets: new[]
            {
                ("Wormhole-9.9.9-win-" + arch + "-setup.exe", "https://example.invalid/installer.exe"),
            });

        var service = NewService(req => OkJson(json));
        var result = await service.CheckAsync();

        Assert.True(result.IsUpdateAvailable);
        Assert.Equal(new Version(9, 9, 9), result.LatestVersion);
        Assert.Equal("https://example.invalid/installer.exe", result.InstallerUrl);
        Assert.Equal($"Wormhole-9.9.9-win-{arch}-setup.exe", result.InstallerFileName);
    }

    [Fact]
    public async Task CheckAsync_NoUpdate_WhenVersionEqual()
    {
        UpdateService.TryGetTargetArchitecture(out var arch);
        var current = UpdateService.GetCurrentVersion();
        var tag = $"v{current.Major}.{current.Minor}.{Math.Max(0, current.Build)}";
        var json = MakeReleaseJson(
            tag: tag,
            draft: false,
            prerelease: false,
            assets: new[] { ($"Wormhole-{current}-win-{arch}-setup.exe", "https://x") });

        var service = NewService(req => OkJson(json));
        var result = await service.CheckAsync();

        Assert.False(result.IsUpdateAvailable);
    }

    [Fact]
    public async Task CheckAsync_NoUpdate_OnDraftRelease()
    {
        var service = NewService(req => OkJson(MakeReleaseJson(
            tag: "v9.9.9", draft: true, prerelease: false,
            assets: Array.Empty<(string, string)>())));
        var result = await service.CheckAsync();
        Assert.False(result.IsUpdateAvailable);
    }

    [Fact]
    public async Task CheckAsync_NoUpdate_OnPrerelease()
    {
        var service = NewService(req => OkJson(MakeReleaseJson(
            tag: "v9.9.9", draft: false, prerelease: true,
            assets: Array.Empty<(string, string)>())));
        var result = await service.CheckAsync();
        Assert.False(result.IsUpdateAvailable);
    }

    [Fact]
    public async Task CheckAsync_NoUpdate_WhenAssetMissingForArch()
    {
        UpdateService.TryGetTargetArchitecture(out var arch);
        var wrongArch = arch == "x64" ? "arm64" : "x64";
        var json = MakeReleaseJson(
            tag: "v9.9.9", draft: false, prerelease: false,
            assets: new[] { ($"Wormhole-9.9.9-win-{wrongArch}-setup.exe", "https://x") });

        var service = NewService(req => OkJson(json));
        var result = await service.CheckAsync();

        Assert.False(result.IsUpdateAvailable);
    }

    [Fact]
    public async Task CheckAsync_PersistsLastUpdateCheck()
    {
        var settings = new FakeAppSettingsService();
        var service = NewService(
            req => OkJson(MakeReleaseJson(
                tag: "v0.0.1", draft: false, prerelease: false,
                assets: Array.Empty<(string, string)>())),
            settings: settings);

        Assert.Null(settings.Current.LastUpdateCheck);
        await service.CheckAsync();
        Assert.NotNull(settings.Current.LastUpdateCheck);
    }

    [Fact]
    public async Task CheckAsync_ReportsFailure_OnHttpError()
    {
        var service = NewService(req => new HttpResponseMessage(HttpStatusCode.NotFound));
        var result = await service.CheckAsync();
        Assert.False(result.IsUpdateAvailable);
        Assert.True(result.CheckFailed);
    }

    [Fact]
    public async Task CheckAsync_DoesNotPersistLastCheck_OnHttpError()
    {
        var settings = new FakeAppSettingsService();
        var service = NewService(
            req => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable),
            settings: settings);

        await service.CheckAsync();
        Assert.Null(settings.Current.LastUpdateCheck);
    }

    [Fact]
    public async Task CheckAsync_DoesNotPersistLastCheck_OnTransportException()
    {
        var settings = new FakeAppSettingsService();
        var service = NewService(
            req => throw new HttpRequestException("network is down"),
            settings: settings);

        var result = await service.CheckAsync();
        Assert.True(result.CheckFailed);
        Assert.Null(settings.Current.LastUpdateCheck);
    }

    [Fact]
    public async Task CheckAsync_DoesNotPersistLastCheck_OnMalformedJson()
    {
        var settings = new FakeAppSettingsService();
        var service = NewService(
            req => new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("this is not json", Encoding.UTF8, "application/json"),
            },
            settings: settings);

        var result = await service.CheckAsync();
        Assert.True(result.CheckFailed);
        Assert.Null(settings.Current.LastUpdateCheck);
    }

    [Fact]
    public async Task CheckAsync_PreservesLatestKnown_AcrossFailure()
    {
        UpdateService.TryGetTargetArchitecture(out var arch);
        var goodJson = MakeReleaseJson(
            tag: "v9.9.9",
            draft: false,
            prerelease: false,
            assets: new[] { ($"Wormhole-9.9.9-win-{arch}-setup.exe", "https://example.invalid/installer.exe") });

        var attempt = 0;
        var service = NewService(req =>
        {
            attempt++;
            return attempt == 1
                ? OkJson(goodJson)
                : new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
        });

        var first = await service.CheckAsync();
        Assert.True(first.IsUpdateAvailable);

        var second = await service.CheckAsync();
        Assert.True(second.CheckFailed);

        // LatestKnown must still reflect the earlier successful update so the user can
        // still install it from the InfoBar / Settings card.
        Assert.NotNull(service.LatestKnown);
        Assert.True(service.LatestKnown!.IsUpdateAvailable);
        Assert.Equal(new Version(9, 9, 9), service.LatestKnown.LatestVersion);
    }

    [Fact]
    public async Task LaunchInstallerAndExitAsync_DoesNothing_WhenFileMissing()
    {
        var launcher = new FakeInstallerLauncher();
        var service = NewService(req => OkJson("{}"), launcher: launcher);
        await service.LaunchInstallerAndExitAsync(Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".exe"));
        Assert.Null(launcher.LastArgs);
        Assert.False(launcher.Exited);
    }

    [Fact]
    public async Task LaunchInstallerAndExitAsync_CallsLauncherAndExits_WhenFilePresent()
    {
        var temp = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".exe");
        File.WriteAllText(temp, "stub");
        try
        {
            var launcher = new FakeInstallerLauncher();
            var service = NewService(req => OkJson("{}"), launcher: launcher);
            await service.LaunchInstallerAndExitAsync(temp);
            Assert.Equal(temp, launcher.LastPath);
            Assert.Equal("/SILENT /RESTARTAPP", launcher.LastArgs);
            Assert.True(launcher.Exited);
        }
        finally
        {
            if (File.Exists(temp)) File.Delete(temp);
        }
    }

    [Fact]
    public void RotateInstallerCache_DeletesOlderInstallers_KeepsCurrent()
    {
        using var tmp = new TempDir();
        File.WriteAllText(Path.Combine(tmp.Path, "Wormhole-0.1.0-win-x64-setup.exe"), "old");
        File.WriteAllText(Path.Combine(tmp.Path, "Wormhole-0.2.0-win-x64-setup.exe"), "old");
        File.WriteAllText(Path.Combine(tmp.Path, "Wormhole-0.3.0-win-x64-setup.exe"), "new");

        UpdateService.RotateInstallerCache(tmp.Path, "Wormhole-0.3.0-win-x64-setup.exe");

        var remaining = Directory.EnumerateFiles(tmp.Path).Select(Path.GetFileName).OrderBy(n => n).ToArray();
        Assert.Single(remaining, "Wormhole-0.3.0-win-x64-setup.exe");
    }

    [Fact]
    public void RotateInstallerCache_IgnoresUnrelatedFiles()
    {
        using var tmp = new TempDir();
        File.WriteAllText(Path.Combine(tmp.Path, "readme.txt"), "x");
        File.WriteAllText(Path.Combine(tmp.Path, "Wormhole-0.1.0-win-x64-setup.exe.part"), "x");
        File.WriteAllText(Path.Combine(tmp.Path, "Wormhole-0.1.0-win-x64-setup.exe"), "old");
        File.WriteAllText(Path.Combine(tmp.Path, "Wormhole-0.2.0-win-x64-setup.exe"), "new");

        UpdateService.RotateInstallerCache(tmp.Path, "Wormhole-0.2.0-win-x64-setup.exe");

        var remaining = Directory.EnumerateFiles(tmp.Path).Select(Path.GetFileName).ToHashSet();
        Assert.Contains("Wormhole-0.2.0-win-x64-setup.exe", remaining);
        Assert.Contains("Wormhole-0.1.0-win-x64-setup.exe.part", remaining);
        Assert.Contains("readme.txt", remaining);
        Assert.DoesNotContain("Wormhole-0.1.0-win-x64-setup.exe", remaining);
    }

    [Fact]
    public void RotateInstallerCache_DoesNotThrow_WhenDirectoryMissing()
    {
        var missing = Path.Combine(Path.GetTempPath(), "wormhole-rotate-" + Guid.NewGuid());
        UpdateService.RotateInstallerCache(missing, "Wormhole-0.2.0-win-x64-setup.exe");
        Assert.False(Directory.Exists(missing));
    }

    private sealed class TempDir : IDisposable
    {
        public string Path { get; }

        public TempDir()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "wormhole-rotate-" + Guid.NewGuid());
            Directory.CreateDirectory(Path);
        }

        public void Dispose()
        {
            try { Directory.Delete(Path, recursive: true); } catch { }
        }
    }

    private static UpdateService NewService(
        Func<HttpRequestMessage, HttpResponseMessage> handler,
        FakeAppSettingsService? settings = null,
        FakeInstallerLauncher? launcher = null)
    {
        var factory = new FakeHttpClientFactory(new TestHttpMessageHandler(handler));
        return new UpdateService(
            factory,
            settings ?? new FakeAppSettingsService(),
            NullLogger<UpdateService>.Instance,
            launcher ?? new FakeInstallerLauncher());
    }

    private static HttpResponseMessage OkJson(string json) =>
        new(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json"),
        };

    private static string MakeReleaseJson(
        string tag,
        bool draft,
        bool prerelease,
        IReadOnlyList<(string Name, string Url)> assets)
    {
        var doc = new
        {
            tag_name = tag,
            name = "Release " + tag,
            body = "Release notes.",
            html_url = "https://github.com/x/x/releases/" + tag,
            draft,
            prerelease,
            assets = assets.Select(a => new
            {
                name = a.Name,
                browser_download_url = a.Url,
                size = 1234L,
                content_type = "application/octet-stream",
            }).ToArray(),
        };
        return JsonSerializer.Serialize(doc);
    }

    private sealed class TestHttpMessageHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _handler;
        public TestHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> handler) => _handler = handler;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(_handler(request));
    }

    private sealed class FakeHttpClientFactory : IHttpClientFactory
    {
        private readonly HttpMessageHandler _handler;
        public FakeHttpClientFactory(HttpMessageHandler handler) => _handler = handler;
        public HttpClient CreateClient(string name) =>
            new(_handler, disposeHandler: false) { BaseAddress = new Uri("https://api.github.com/") };
    }

    private sealed class FakeAppSettingsService : IAppSettingsService
    {
        public AppSettings Current { get; } = new();
        public event EventHandler? SettingsChanged;
        public void Save() => SettingsChanged?.Invoke(this, EventArgs.Empty);
    }

    private sealed class FakeInstallerLauncher : IInstallerLauncher
    {
        public string? LastPath { get; private set; }
        public string? LastArgs { get; private set; }
        public bool Exited { get; private set; }

        public void Launch(string installerPath, string arguments)
        {
            LastPath = installerPath;
            LastArgs = arguments;
        }

        public void ExitApp() => Exited = true;
    }
}
