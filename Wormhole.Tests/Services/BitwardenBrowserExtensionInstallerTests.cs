using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Models;
using Wormhole.Services;
using Wormhole.Services.BitwardenBrowser;
using Xunit;

namespace Wormhole.Tests.Services;

public sealed class BitwardenBrowserExtensionInstallerTests
{
    [Fact]
    public async Task InstallLatestAsync_PrefersEdgeAsset_VerifiesDigest_AndPersistsInstall()
    {
        using var temp = TempInstall.Create();
        var zipBytes = CreateExtensionZip();
        var sha256 = ComputeSha256(zipBytes);
        var settings = new FakeAppSettingsService();
        var handler = new DelegateHandler(request =>
        {
            if (request.RequestUri?.Host == "api.github.com")
            {
                var releaseJson = $$"""
                [
                  {
                    "tag_name": "browser-v2026.6.1",
                    "draft": false,
                    "prerelease": false,
                    "assets": [
                      {
                        "name": "dist-chrome-2026.6.1.zip",
                        "browser_download_url": "https://downloads.example/chrome.zip"
                      },
                      {
                        "name": "dist-edge-2026.6.1.zip",
                        "browser_download_url": "https://downloads.example/edge.zip",
                        "digest": "sha256:{{sha256}}"
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

            Assert.Equal("https://downloads.example/edge.zip", request.RequestUri?.ToString());
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(zipBytes)
            };
        });
        var installer = CreateInstaller(temp, settings, handler);

        var install = await installer.InstallLatestAsync();

        Assert.Equal("2026.6.1", install.Version);
        Assert.Equal("dist-edge-2026.6.1.zip", install.AssetName);
        Assert.Equal("https://downloads.example/edge.zip", install.DownloadUrl);
        Assert.Equal(sha256, install.Sha256);
        Assert.True(File.Exists(Path.Combine(install.ExtensionPath, "manifest.json")));
        Assert.Equal(install.ExtensionPath, settings.Current.BitwardenBrowserExtensionPath);
        Assert.Equal(1, settings.SaveCount);
    }

    [Fact]
    public async Task InstallLatestAsync_ReinstallPreservesConfiguredPath()
    {
        using var temp = TempInstall.Create();
        var currentPath = CreateInstalledExtension(temp, "2026.5.1");
        var oldOnlyFile = Path.Combine(currentPath, "old-only.txt");
        await File.WriteAllTextAsync(oldOnlyFile, "old");
        var zipBytes = CreateExtensionZip();
        var sha256 = ComputeSha256(zipBytes);
        var settings = new FakeAppSettingsService();
        settings.Current.BitwardenBrowserExtensionSource = BitwardenBrowserExtensionSource.OfficialGitHub;
        settings.Current.BitwardenBrowserExtensionVersion = "2026.5.1";
        settings.Current.BitwardenBrowserExtensionPath = currentPath;
        var handler = new DelegateHandler(request =>
        {
            if (request.RequestUri?.Host == "api.github.com")
            {
                return ReleaseResponse(
                    "browser-v2026.6.1",
                    "dist-edge-2026.6.1.zip",
                    "https://downloads.example/edge.zip",
                    sha256);
            }

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(zipBytes)
            };
        });
        var installer = CreateInstaller(temp, settings, handler);

        var install = await installer.InstallLatestAsync();

        Assert.Equal(currentPath, install.ExtensionPath);
        Assert.Equal(currentPath, settings.Current.BitwardenBrowserExtensionPath);
        Assert.True(File.Exists(Path.Combine(currentPath, "popup.html")));
        Assert.False(File.Exists(oldOnlyFile));
        Assert.Empty(Directory.EnumerateDirectories(temp.InstallRoot, ".backup-*"));
    }

    [Fact]
    public async Task InstallLatestAsync_SaveFailureKeepsReplacementAtStablePath()
    {
        using var temp = TempInstall.Create();
        var currentPath = CreateInstalledExtension(temp, "2026.5.1");
        var oldOnlyFile = Path.Combine(currentPath, "old-only.txt");
        await File.WriteAllTextAsync(oldOnlyFile, "old");
        var zipBytes = CreateExtensionZip();
        var sha256 = ComputeSha256(zipBytes);
        var settings = new FakeAppSettingsService { SaveException = new IOException("settings unavailable") };
        settings.Current.BitwardenBrowserExtensionSource = BitwardenBrowserExtensionSource.OfficialGitHub;
        settings.Current.BitwardenBrowserExtensionVersion = "2026.5.1";
        settings.Current.BitwardenBrowserExtensionPath = currentPath;
        var handler = new DelegateHandler(request =>
        {
            if (request.RequestUri?.Host == "api.github.com")
            {
                return ReleaseResponse(
                    "browser-v2026.6.1",
                    "dist-edge-2026.6.1.zip",
                    "https://downloads.example/edge.zip",
                    sha256);
            }

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(zipBytes)
            };
        });
        var installer = CreateInstaller(temp, settings, handler);

        var exception = await Assert.ThrowsAsync<BitwardenBrowserExtensionException>(
            () => installer.InstallLatestAsync());

        Assert.IsType<IOException>(exception.InnerException);
        Assert.Equal(currentPath, settings.Current.BitwardenBrowserExtensionPath);
        Assert.Equal("2026.6.1", settings.Current.BitwardenBrowserExtensionVersion);
        Assert.True(File.Exists(Path.Combine(currentPath, "popup.html")));
        Assert.False(File.Exists(oldOnlyFile));
        Assert.Empty(Directory.EnumerateDirectories(temp.InstallRoot, ".backup-*"));
        Assert.Equal(1, settings.SaveCount);
    }

    [Fact]
    public async Task InstallLatestAsync_RejectsDigestMismatch()
    {
        using var temp = TempInstall.Create();
        var zipBytes = CreateExtensionZip();
        var settings = new FakeAppSettingsService();
        var handler = new DelegateHandler(request =>
        {
            if (request.RequestUri?.Host == "api.github.com")
            {
                var releaseJson = """
                [
                  {
                    "tag_name": "browser-v2026.6.1",
                    "draft": false,
                    "prerelease": false,
                    "assets": [
                      {
                        "name": "dist-edge-2026.6.1.zip",
                        "browser_download_url": "https://downloads.example/edge.zip",
                        "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
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

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(zipBytes)
            };
        });
        var installer = CreateInstaller(temp, settings, handler);

        var ex = await Assert.ThrowsAsync<BitwardenBrowserExtensionException>(() => installer.InstallLatestAsync());

        Assert.Contains("checksum", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Null(settings.Current.BitwardenBrowserExtensionPath);
        Assert.Equal(0, settings.SaveCount);
    }

    [Fact]
    public async Task ImportZipAsync_BlocksZipSlipEntries()
    {
        using var temp = TempInstall.Create();
        var zipPath = Path.Combine(temp.DirectoryPath, "unsafe.zip");
        CreateZip(zipPath, archive =>
        {
            WriteEntry(archive, "manifest.json", ValidManifest);
            WriteEntry(archive, "../outside.txt", "nope");
        });
        var settings = new FakeAppSettingsService();
        var installer = CreateInstaller(temp, settings, new DelegateHandler(_ => new HttpResponseMessage(HttpStatusCode.NotFound)));

        var ex = await Assert.ThrowsAsync<BitwardenBrowserExtensionException>(() => installer.ImportZipAsync(zipPath));

        Assert.Contains("unsafe path", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.False(File.Exists(Path.Combine(temp.DirectoryPath, "outside.txt")));
        Assert.Equal(0, settings.SaveCount);
    }

    [Fact]
    public async Task ImportUnpackedAsync_CopiesFolder_ValidatesManifest_AndPersistsReference()
    {
        using var temp = TempInstall.Create();
        var source = Path.Combine(temp.DirectoryPath, "source-extension");
        Directory.CreateDirectory(source);
        await File.WriteAllTextAsync(Path.Combine(source, "manifest.json"), ValidManifest);
        await File.WriteAllTextAsync(Path.Combine(source, "popup.html"), "<html></html>");
        var settings = new FakeAppSettingsService();
        settings.Current.BitwardenBrowserExtensionSource = BitwardenBrowserExtensionSource.OfficialGitHub;
        settings.Current.BitwardenBrowserExtensionLastUpdateCheckUtc = DateTimeOffset.UtcNow - TimeSpan.FromHours(1);
        var installer = CreateInstaller(temp, settings, new DelegateHandler(_ => new HttpResponseMessage(HttpStatusCode.NotFound)));

        var install = await installer.ImportUnpackedAsync(source);

        Assert.Equal("2026.6.1", install.Version);
        Assert.NotEqual(source, install.ExtensionPath);
        Assert.True(File.Exists(Path.Combine(install.ExtensionPath, "manifest.json")));
        Assert.True(File.Exists(Path.Combine(install.ExtensionPath, "popup.html")));
        Assert.StartsWith(temp.InstallRoot, install.ExtensionPath, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(install.ExtensionPath, settings.Current.BitwardenBrowserExtensionPath);
        Assert.Equal(BitwardenBrowserExtensionSource.ManualFolder, settings.Current.BitwardenBrowserExtensionSource);
        Assert.Null(settings.Current.BitwardenBrowserExtensionLastUpdateCheckUtc);
        Assert.Equal(1, settings.SaveCount);
    }

    [Fact]
    public async Task ImportUnpackedAsync_ReimportPreservesConfiguredPath()
    {
        using var temp = TempInstall.Create();
        var currentPath = CreateInstalledExtension(temp, "2026.5.1");
        var oldOnlyFile = Path.Combine(currentPath, "old-only.txt");
        await File.WriteAllTextAsync(oldOnlyFile, "old");
        var source = Path.Combine(temp.DirectoryPath, "source-extension");
        Directory.CreateDirectory(source);
        await File.WriteAllTextAsync(Path.Combine(source, "manifest.json"), ValidManifest);
        await File.WriteAllTextAsync(Path.Combine(source, "popup.html"), "<html></html>");
        var settings = new FakeAppSettingsService();
        settings.Current.BitwardenBrowserExtensionSource = BitwardenBrowserExtensionSource.ManualFolder;
        settings.Current.BitwardenBrowserExtensionVersion = "2026.5.1";
        settings.Current.BitwardenBrowserExtensionPath = currentPath;
        var installer = CreateInstaller(temp, settings, new DelegateHandler(_ => new HttpResponseMessage(HttpStatusCode.NotFound)));

        var install = await installer.ImportUnpackedAsync(source);

        Assert.Equal(currentPath, install.ExtensionPath);
        Assert.Equal(currentPath, settings.Current.BitwardenBrowserExtensionPath);
        Assert.True(File.Exists(Path.Combine(currentPath, "popup.html")));
        Assert.False(File.Exists(oldOnlyFile));
        Assert.Empty(Directory.EnumerateDirectories(temp.InstallRoot, ".backup-*"));
    }

    [Fact]
    public void ReleaseHelpers_FilterBrowserRelease_AndPreferEdgeZip()
    {
        var release = new GitHubRelease
        {
            TagName = "browser-v2026.6.1",
            Assets =
            [
                new GitHubReleaseAsset { Name = "dist-chrome-2026.6.1.zip", BrowserDownloadUrl = "https://example/chrome.zip" },
                new GitHubReleaseAsset { Name = "dist-edge-2026.6.1.zip", BrowserDownloadUrl = "https://example/edge.zip" }
            ]
        };

        Assert.True(BitwardenBrowserExtensionInstaller.IsBrowserRelease(release));
        Assert.Equal("dist-edge-2026.6.1.zip", BitwardenBrowserExtensionInstaller.FindPreferredAsset(release)?.Name);
        Assert.Equal("2026.6.1", BitwardenBrowserExtensionInstaller.ParseBrowserVersion("browser-v2026.6.1"));
        Assert.Equal(new string('a', 64), BitwardenBrowserExtensionInstaller.ParseGitHubSha256("sha256:" + new string('A', 64)));
    }
    [Fact]
    public async Task ManifestRead_ResolvesPreferredActionIconPath()
    {
        using var temp = TempInstall.Create();
        var extensionPath = Path.Combine(temp.DirectoryPath, "manifest-extension");
        Directory.CreateDirectory(extensionPath);
        await File.WriteAllTextAsync(Path.Combine(extensionPath, "manifest.json"), """
        {
          "manifest_version": 3,
          "name": "Bitwarden Password Manager",
          "version": "2026.6.1",
          "action": {
            "default_popup": "popup.html",
            "default_icon": {
              "16": "images/icon-16.png",
              "32": "images/icon-32.png"
            }
          },
          "icons": {
            "128": "images/icon-128.png"
          }
        }
        """);

        var manifest = BitwardenBrowserExtensionManifest.Read(extensionPath);

        Assert.Equal(Path.GetFullPath(Path.Combine(extensionPath, "images", "icon-32.png")), manifest.IconPath);
    }


    [Fact]
    public async Task UpdateIfAvailableAsync_InstallsNewerOfficialRelease()
    {
        using var temp = TempInstall.Create();
        var currentPath = CreateInstalledExtension(temp, "2026.6.1");
        var oldOnlyFile = Path.Combine(currentPath, "old-only.txt");
        await File.WriteAllTextAsync(oldOnlyFile, "old");
        var zipBytes = CreateExtensionZip();
        var sha256 = ComputeSha256(zipBytes);
        var settings = new FakeAppSettingsService();
        settings.Current.BitwardenBrowserExtensionSource = BitwardenBrowserExtensionSource.OfficialGitHub;
        settings.Current.BitwardenBrowserExtensionVersion = "2026.6.1";
        settings.Current.BitwardenBrowserExtensionPath = currentPath;
        var handler = new DelegateHandler(request =>
        {
            if (request.RequestUri?.Host == "api.github.com")
            {
                return ReleaseResponse("browser-v2026.6.2", "dist-edge-2026.6.2.zip", "https://downloads.example/edge-2026.6.2.zip", sha256);
            }

            Assert.Equal("https://downloads.example/edge-2026.6.2.zip", request.RequestUri?.ToString());
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(zipBytes)
            };
        });
        var installer = CreateInstaller(temp, settings, handler);

        var result = await installer.UpdateIfAvailableAsync();

        Assert.True(result.WasUpdated);
        Assert.True(result.Check.IsUpdateAvailable);
        Assert.Equal("2026.6.2", result.Install?.Version);
        Assert.Equal(BitwardenBrowserExtensionSource.OfficialGitHub, settings.Current.BitwardenBrowserExtensionSource);
        Assert.Equal("2026.6.2", settings.Current.BitwardenBrowserExtensionVersion);
        Assert.Equal(currentPath, settings.Current.BitwardenBrowserExtensionPath);
        Assert.Equal(currentPath, result.Install?.ExtensionPath);
        Assert.True(File.Exists(Path.Combine(currentPath, "popup.html")));
        Assert.False(File.Exists(oldOnlyFile));
        Assert.Empty(Directory.EnumerateDirectories(temp.InstallRoot, ".backup-*"));
        Assert.Equal(1, settings.SaveCount);
    }

    [Fact]
    public async Task UpdateIfAvailableAsync_SkipsWhenLatestIsNotNewer()
    {
        using var temp = TempInstall.Create();
        var currentPath = CreateInstalledExtension(temp, "2026.6.2");
        var settings = new FakeAppSettingsService();
        settings.Current.BitwardenBrowserExtensionSource = BitwardenBrowserExtensionSource.OfficialGitHub;
        settings.Current.BitwardenBrowserExtensionVersion = "2026.6.2";
        settings.Current.BitwardenBrowserExtensionPath = currentPath;
        var handler = new DelegateHandler(request =>
        {
            Assert.Equal("api.github.com", request.RequestUri?.Host);
            return ReleaseResponse("browser-v2026.6.2", "dist-edge-2026.6.2.zip", "https://downloads.example/edge.zip", digest: null);
        });
        var installer = CreateInstaller(temp, settings, handler);

        var result = await installer.UpdateIfAvailableAsync();

        Assert.False(result.WasUpdated);
        Assert.False(result.Check.IsUpdateAvailable);
        Assert.Equal(currentPath, settings.Current.BitwardenBrowserExtensionPath);
        Assert.Equal("2026.6.2", settings.Current.BitwardenBrowserExtensionVersion);
        Assert.Equal(0, settings.SaveCount);
    }

    [Fact]
    public async Task UpdateIfAvailableAsync_RejectsDigestMismatch_AndPreservesConfiguredInstall()
    {
        using var temp = TempInstall.Create();
        var currentPath = CreateInstalledExtension(temp, "2026.6.1");
        var settings = new FakeAppSettingsService();
        settings.Current.BitwardenBrowserExtensionSource = BitwardenBrowserExtensionSource.OfficialGitHub;
        settings.Current.BitwardenBrowserExtensionVersion = "2026.6.1";
        settings.Current.BitwardenBrowserExtensionPath = currentPath;
        var handler = new DelegateHandler(request =>
        {
            if (request.RequestUri?.Host == "api.github.com")
            {
                return ReleaseResponse(
                    "browser-v2026.6.2",
                    "dist-edge-2026.6.2.zip",
                    "https://downloads.example/edge.zip",
                    new string('0', 64));
            }

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(CreateExtensionZip())
            };
        });
        var installer = CreateInstaller(temp, settings, handler);

        var ex = await Assert.ThrowsAsync<BitwardenBrowserExtensionException>(() => installer.UpdateIfAvailableAsync());

        Assert.Contains("checksum", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(currentPath, settings.Current.BitwardenBrowserExtensionPath);
        Assert.Equal("2026.6.1", settings.Current.BitwardenBrowserExtensionVersion);
        Assert.Equal(0, settings.SaveCount);
    }

    [Fact]
    public void CompareBrowserVersions_UsesNumericSegments()
    {
        Assert.True(BitwardenBrowserExtensionInstaller.CompareBrowserVersions("2026.6.10", "2026.6.2") > 0);
        Assert.Equal(0, BitwardenBrowserExtensionInstaller.CompareBrowserVersions("browser-v2026.6.0", "2026.6"));
        Assert.True(BitwardenBrowserExtensionInstaller.CompareBrowserVersions("2026.7", "2026.6.99") > 0);
    }
    private const string ValidManifest = """
    {
      "manifest_version": 3,
      "name": "Bitwarden Password Manager",
      "version": "2026.6.1",
      "action": {
        "default_popup": "popup.html"
      }
    }
    """;

    private static BitwardenBrowserExtensionInstaller CreateInstaller(
        TempInstall temp,
        FakeAppSettingsService settings,
        HttpMessageHandler handler) =>
        new(
            new FakeHttpClientFactory(handler),
            settings,
            NullLogger<BitwardenBrowserExtensionInstaller>.Instance,
            temp.InstallRoot,
            temp.DownloadRoot);


    private static string CreateInstalledExtension(TempInstall temp, string version)
    {
        var path = Path.Combine(temp.InstallRoot, "installed-" + version);
        Directory.CreateDirectory(path);
        File.WriteAllText(Path.Combine(path, "manifest.json"), ValidManifest.Replace("2026.6.1", version, StringComparison.Ordinal));
        return path;
    }

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

    private static byte[] CreateExtensionZip()
    {
        using var memory = new MemoryStream();
        using (var archive = new ZipArchive(memory, ZipArchiveMode.Create, leaveOpen: true))
        {
            WriteEntry(archive, "extension/manifest.json", ValidManifest);
            WriteEntry(archive, "extension/popup.html", "<html></html>");
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
            if (name == BitwardenBrowserExtensionInstaller.ReleaseHttpClientName)
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
        public Exception? SaveException { get; init; }
        public event EventHandler? SettingsChanged;

        public void Save()
        {
            SaveCount++;
            if (SaveException is not null) throw SaveException;
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
            if (Directory.Exists(DirectoryPath))
            {
                Directory.Delete(DirectoryPath, recursive: true);
            }
        }
    }
}
