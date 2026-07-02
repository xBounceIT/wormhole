using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Models;
using Wormhole.Services;
using Wormhole.Services.Bitwarden;
using Xunit;

namespace Wormhole.Tests.Services;

public sealed class BitwardenCliInstallerTests
{
    [Fact]
    public async Task InstallLatestAsync_PrefersOfficialWindowsZip_VerifiesDigest_AndPersistsPath()
    {
        using var temp = TempInstall.Create();
        var zipBytes = CreateCliZip();
        var sha256 = ComputeSha256(zipBytes);
        var settings = new FakeAppSettingsService();
        var handler = new DelegateHandler(request =>
        {
            if (request.RequestUri?.Host == "api.github.com")
            {
                return ReleaseResponse("cli-v2026.6.0", "bw-windows-2026.6.0.zip", "https://downloads.example/bw.zip", sha256);
            }

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(zipBytes)
            };
        });
        var installer = CreateInstaller(temp, settings, handler);

        var install = await installer.InstallLatestAsync();

        Assert.Equal("2026.6.0", install.Version);
        Assert.EndsWith("bw.exe", install.ExecutablePath, StringComparison.OrdinalIgnoreCase);
        Assert.True(File.Exists(install.ExecutablePath));
        Assert.StartsWith(temp.InstallRoot, install.ExecutablePath, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(install.ExecutablePath, settings.Current.BitwardenCliPath);
        Assert.Equal("bw-windows-2026.6.0.zip", settings.Current.BitwardenCliAssetName);
        Assert.Equal(sha256, settings.Current.BitwardenCliSha256);
        Assert.Equal(1, settings.SaveCount);
    }

    [Fact]
    public async Task InstallLatestAsync_BlocksZipSlip_AndDoesNotPersistSettings()
    {
        using var temp = TempInstall.Create();
        var zipPath = Path.Combine(temp.DirectoryPath, "unsafe.zip");
        CreateZip(zipPath, archive => WriteEntry(archive, "../bw.exe", "bad"));
        var zipBytes = await File.ReadAllBytesAsync(zipPath);
        var settings = new FakeAppSettingsService();
        var handler = new DelegateHandler(request =>
        {
            if (request.RequestUri?.Host == "api.github.com")
            {
                return ReleaseResponse("cli-v2026.6.0", "bw-windows-2026.6.0.zip", "https://downloads.example/bw.zip", ComputeSha256(zipBytes));
            }

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(zipBytes)
            };
        });
        var installer = CreateInstaller(temp, settings, handler);

        var ex = await Assert.ThrowsAsync<BitwardenCliInstallException>(() => installer.InstallLatestAsync());

        Assert.Contains("unsafe path", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("bw", settings.Current.BitwardenCliPath);
        Assert.Equal(0, settings.SaveCount);
    }

    [Fact]
    public async Task EnsureInstalledAsync_UsesConfiguredInstall_WithoutDownloading()
    {
        using var temp = TempInstall.Create();
        var exe = Path.Combine(temp.DirectoryPath, "bw.exe");
        File.WriteAllText(exe, "fake");
        var settings = new FakeAppSettingsService();
        settings.Current.BitwardenCliPath = exe;
        var requestCount = 0;
        var installer = CreateInstaller(temp, settings, new DelegateHandler(_ =>
        {
            requestCount++;
            return new HttpResponseMessage(HttpStatusCode.InternalServerError);
        }));

        var install = await installer.EnsureInstalledAsync();

        Assert.Equal("external", install.Version);
        Assert.Equal(Path.GetFullPath(exe), install.ExecutablePath);
        Assert.Equal(0, requestCount);
        Assert.Equal(0, settings.SaveCount);
    }

    [Fact]
    public void ReleaseHelpers_FilterCliRelease_AndPreferNonOssWindowsZip()
    {
        var release = new GitHubRelease
        {
            TagName = "cli-v2026.6.0",
            Assets =
            [
                new GitHubReleaseAsset { Name = "bw-oss-windows-2026.6.0.zip", BrowserDownloadUrl = "https://example/oss.zip" },
                new GitHubReleaseAsset { Name = "bw-windows-2026.6.0.zip", BrowserDownloadUrl = "https://example/windows.zip" }
            ]
        };

        Assert.True(BitwardenCliInstaller.IsCliRelease(release));
        Assert.Equal("bw-windows-2026.6.0.zip", BitwardenCliInstaller.FindWindowsAsset(release)?.Name);
        Assert.Equal("2026.6.0", BitwardenCliInstaller.ParseCliVersion("cli-v2026.6.0"));
        Assert.Equal("2026.6.0", BitwardenCliInstaller.ParseCliVersion("bw-windows-2026.6.0.zip"));
    }

    [Fact]
    public void GetConfiguredInstall_ResolvesExplicitExistingPath()
    {
        using var temp = TempInstall.Create();
        var exe = Path.Combine(temp.DirectoryPath, "bw.exe");
        File.WriteAllText(exe, "fake");
        var settings = new FakeAppSettingsService();
        settings.Current.BitwardenCliPath = exe;
        var installer = CreateInstaller(temp, settings, new DelegateHandler(_ => new HttpResponseMessage(HttpStatusCode.NotFound)));

        var install = installer.GetConfiguredInstall();

        Assert.NotNull(install);
        Assert.Equal("external", install!.Version);
        Assert.Equal(Path.GetFullPath(exe), install.ExecutablePath);
    }

    private static BitwardenCliInstaller CreateInstaller(
        TempInstall temp,
        FakeAppSettingsService settings,
        HttpMessageHandler handler) =>
        new(
            new FakeHttpClientFactory(handler),
            settings,
            NullLogger<BitwardenCliInstaller>.Instance,
            temp.InstallRoot,
            temp.DownloadRoot);

    private static HttpResponseMessage ReleaseResponse(string tagName, string assetName, string downloadUrl, string? digest)
    {
        var digestJson = digest is null ? string.Empty : $",\n                        \"digest\": \"sha256:{digest}\"";
        var releaseJson = $$"""
        [
          {
            "tag_name": "{{tagName}}",
            "draft": false,
            "prerelease": false,
            "assets": [
              {
                "name": "{{assetName}}",
                "browser_download_url": "{{downloadUrl}}"{{digestJson}}
              }
            ]
          }
        ]
        """;
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(releaseJson, Encoding.UTF8, "application/json")
        };
    }

    private static byte[] CreateCliZip()
    {
        using var memory = new MemoryStream();
        using (var archive = new ZipArchive(memory, ZipArchiveMode.Create, leaveOpen: true))
        {
            WriteEntry(archive, "bw.exe", "fake executable");
        }
        return memory.ToArray();
    }

    private static void CreateZip(string path, Action<ZipArchive> configure)
    {
        using var file = File.Create(path);
        using var archive = new ZipArchive(file, ZipArchiveMode.Create);
        configure(archive);
    }

    private static void WriteEntry(ZipArchive archive, string path, string content)
    {
        var entry = archive.CreateEntry(path);
        using var writer = new StreamWriter(entry.Open(), Encoding.UTF8);
        writer.Write(content);
    }

    private static string ComputeSha256(byte[] bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private sealed class FakeHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name)
        {
            var client = new HttpClient(handler, disposeHandler: false);
            if (name == BitwardenCliInstaller.ReleaseHttpClientName)
            {
                client.BaseAddress = new Uri("https://api.github.com/");
            }
            return client;
        }
    }

    private sealed class DelegateHandler(Func<HttpRequestMessage, HttpResponseMessage> responder) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(responder(request));
    }

    private sealed class FakeAppSettingsService : IAppSettingsService
    {
        public AppSettings Current { get; } = new();
        public int SaveCount { get; private set; }
        public event EventHandler? SettingsChanged;

        public void Save()
        {
            SaveCount++;
            SettingsChanged?.Invoke(this, EventArgs.Empty);
        }
    }

    private sealed class TempInstall : IDisposable
    {
        private TempInstall(string directoryPath)
        {
            DirectoryPath = directoryPath;
            InstallRoot = Path.Combine(directoryPath, "install");
            DownloadRoot = Path.Combine(directoryPath, "download");
        }

        public string DirectoryPath { get; }
        public string InstallRoot { get; }
        public string DownloadRoot { get; }

        public static TempInstall Create()
        {
            var directory = Path.Combine(Path.GetTempPath(), "Wormhole.Tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            return new TempInstall(directory);
        }

        public void Dispose()
        {
            if (Directory.Exists(DirectoryPath)) Directory.Delete(DirectoryPath, recursive: true);
        }
    }
}
