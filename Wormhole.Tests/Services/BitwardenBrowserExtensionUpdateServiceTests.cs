using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Models;
using Wormhole.Services;
using Wormhole.Services.BitwardenBrowser;
using Xunit;

namespace Wormhole.Tests.Services;

public sealed class BitwardenBrowserExtensionUpdateServiceTests
{
    [Fact]
    public async Task UpdateIfStaleAsync_DoesNothing_WhenExtensionDisabled()
    {
        var settings = new FakeAppSettingsService();
        settings.Current.EnableBitwardenBrowserExtension = false;
        var installer = new FakeInstaller { ConfiguredInstall = Install("2026.6.1") };
        var service = CreateService(settings, installer);

        await service.UpdateIfStaleAsync();

        Assert.Equal(0, installer.UpdateCalls);
        Assert.Equal(0, settings.SaveCount);
    }

    [Fact]
    public async Task UpdateIfStaleAsync_DoesNothing_ForManualInstall()
    {
        var settings = EnabledOfficialSettings();
        settings.Current.BitwardenBrowserExtensionSource = BitwardenBrowserExtensionSource.ManualZip;
        var installer = new FakeInstaller { ConfiguredInstall = Install("2026.6.1") };
        var service = CreateService(settings, installer);

        await service.UpdateIfStaleAsync();

        Assert.Equal(0, installer.UpdateCalls);
        Assert.Equal(0, settings.SaveCount);
    }

    [Fact]
    public async Task UpdateIfStaleAsync_DoesNothing_WhenLastCheckIsFresh()
    {
        var settings = EnabledOfficialSettings();
        settings.Current.BitwardenBrowserExtensionLastUpdateCheckUtc = DateTimeOffset.UtcNow;
        var installer = new FakeInstaller { ConfiguredInstall = Install("2026.6.1") };
        var service = CreateService(settings, installer);

        await service.UpdateIfStaleAsync();

        Assert.Equal(0, installer.GetConfiguredInstallCalls);
        Assert.Equal(0, installer.UpdateCalls);
        Assert.Equal(0, settings.SaveCount);
    }

    [Fact]
    public async Task UpdateIfStaleAsync_UpdatesOfficialInstall_AndStoresCompactStatus()
    {
        var settings = EnabledOfficialSettings();
        settings.Current.BitwardenBrowserExtensionLastUpdateCheckUtc = DateTimeOffset.UtcNow - TimeSpan.FromDays(2);
        var installer = new FakeInstaller
        {
            ConfiguredInstall = Install("2026.6.1"),
            NextResult = UpdatedResult("2026.6.1", "2026.6.2")
        };
        var service = CreateService(settings, installer);

        await service.UpdateIfStaleAsync();

        Assert.Equal(1, installer.UpdateCalls);
        Assert.NotNull(settings.Current.BitwardenBrowserExtensionLastUpdateCheckUtc);
        Assert.Null(settings.Current.BitwardenBrowserExtensionLastUpdateError);
        Assert.Contains("Auto-updated", settings.Current.BitwardenBrowserExtensionLastUpdateStatus);
        Assert.Null(settings.Current.BitwardenBrowserExtensionAvailableVersion);
        Assert.Equal(1, settings.SaveCount);
    }

    [Fact]
    public async Task UpdateIfStaleAsync_CoalescesConcurrentChecks()
    {
        var settings = EnabledOfficialSettings();
        settings.Current.BitwardenBrowserExtensionLastUpdateCheckUtc = DateTimeOffset.UtcNow - TimeSpan.FromDays(2);
        var installer = new FakeInstaller
        {
            ConfiguredInstall = Install("2026.6.1"),
            Delay = TimeSpan.FromMilliseconds(50),
            NextResult = UpToDateResult("2026.6.1")
        };
        var service = CreateService(settings, installer);

        await Task.WhenAll(service.UpdateIfStaleAsync(), service.UpdateIfStaleAsync(), service.UpdateIfStaleAsync());

        Assert.Equal(1, installer.UpdateCalls);
        Assert.Equal(1, settings.SaveCount);
    }

    [Fact]
    public async Task UpdateIfStaleAsync_RecordsError_AndPreservesConfiguredInstall()
    {
        var settings = EnabledOfficialSettings();
        settings.Current.BitwardenBrowserExtensionLastUpdateCheckUtc = DateTimeOffset.UtcNow - TimeSpan.FromDays(2);
        settings.Current.BitwardenBrowserExtensionVersion = "2026.6.1";
        settings.Current.BitwardenBrowserExtensionPath = "current-path";
        var installer = new FakeInstaller
        {
            ConfiguredInstall = Install("2026.6.1"),
            NextException = new BitwardenBrowserExtensionException("download failed")
        };
        var service = CreateService(settings, installer);

        await service.UpdateIfStaleAsync();

        Assert.Equal(1, installer.UpdateCalls);
        Assert.Equal("2026.6.1", settings.Current.BitwardenBrowserExtensionVersion);
        Assert.Equal("current-path", settings.Current.BitwardenBrowserExtensionPath);
        Assert.Contains("failed", settings.Current.BitwardenBrowserExtensionLastUpdateError);
        Assert.Equal("Auto-update check failed.", settings.Current.BitwardenBrowserExtensionLastUpdateStatus);
        Assert.Equal(1, settings.SaveCount);
    }

    private static BitwardenBrowserExtensionUpdateService CreateService(
        FakeAppSettingsService settings,
        FakeInstaller installer) =>
        new(settings, installer, NullLogger<BitwardenBrowserExtensionUpdateService>.Instance);

    private static FakeAppSettingsService EnabledOfficialSettings()
    {
        var settings = new FakeAppSettingsService();
        settings.Current.EnableBitwardenBrowserExtension = true;
        settings.Current.BitwardenBrowserExtensionSource = BitwardenBrowserExtensionSource.OfficialGitHub;
        return settings;
    }

    private static BitwardenBrowserExtensionInstall Install(string version) =>
        new(version, "path-" + version, Sha256: null, AssetName: "dist-edge-" + version + ".zip", DownloadUrl: "https://example/" + version + ".zip");

    private static BitwardenBrowserExtensionUpdateResult UpdatedResult(string currentVersion, string latestVersion) =>
        new(
            new BitwardenBrowserExtensionUpdateCheck(
                currentVersion,
                latestVersion,
                IsUpdateAvailable: true,
                AssetName: "dist-edge-" + latestVersion + ".zip",
                DownloadUrl: "https://example/" + latestVersion + ".zip",
                ExpectedSha256: null),
            Install(latestVersion),
            WasUpdated: true);

    private static BitwardenBrowserExtensionUpdateResult UpToDateResult(string version) =>
        new(
            new BitwardenBrowserExtensionUpdateCheck(
                version,
                version,
                IsUpdateAvailable: false,
                AssetName: "dist-edge-" + version + ".zip",
                DownloadUrl: "https://example/" + version + ".zip",
                ExpectedSha256: null),
            Install: null,
            WasUpdated: false);

    private sealed class FakeInstaller : IBitwardenBrowserExtensionInstaller
    {
        public BitwardenBrowserExtensionInstall? ConfiguredInstall { get; set; }
        public BitwardenBrowserExtensionUpdateResult NextResult { get; set; } = UpToDateResult("2026.6.1");
        public Exception? NextException { get; set; }
        public TimeSpan Delay { get; set; }
        public int UpdateCalls { get; private set; }
        public int GetConfiguredInstallCalls { get; private set; }

        public BitwardenBrowserExtensionInstall? GetConfiguredInstall()
        {
            GetConfiguredInstallCalls++;
            return ConfiguredInstall;
        }

        public Task<BitwardenBrowserExtensionUpdateCheck> CheckForUpdateAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(NextResult.Check);

        public async Task<BitwardenBrowserExtensionUpdateResult> UpdateIfAvailableAsync(
            IProgress<string>? progress = null,
            CancellationToken cancellationToken = default)
        {
            UpdateCalls++;
            if (Delay > TimeSpan.Zero) await Task.Delay(Delay, cancellationToken);
            if (NextException is not null) throw NextException;
            ConfiguredInstall = NextResult.Install ?? ConfiguredInstall;
            return NextResult;
        }

        public Task<BitwardenBrowserExtensionInstall> InstallLatestAsync(
            IProgress<string>? progress = null,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(ConfiguredInstall ?? Install("2026.6.1"));

        public Task<BitwardenBrowserExtensionInstall> ImportZipAsync(
            string zipPath,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(ConfiguredInstall ?? Install("2026.6.1"));

        public Task<BitwardenBrowserExtensionInstall> ImportUnpackedAsync(
            string extensionFolderPath,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(ConfiguredInstall ?? Install("2026.6.1"));
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
}
