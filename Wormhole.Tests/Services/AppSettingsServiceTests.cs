using System.Text.Json;
using Wormhole.Models;
using Wormhole.Services;
using Xunit;

namespace Wormhole.Tests.Services;

public sealed class AppSettingsServiceTests
{
    [Fact]
    public void AppSettings_DefaultsPromptBeforeTunnelConnectOn()
    {
        var settings = new AppSettings();

        Assert.True(settings.PromptBeforeTunnelConnect);
        Assert.Equal(AppSettings.CurrentSchemaVersion, settings.SettingsSchemaVersion);
    }

    [Fact]
    public void LegacySettings_MigratesPromptBeforeTunnelConnectOn()
    {
        using var temp = TempSettingsFile.Create();
        File.WriteAllText(temp.FilePath, """
        {
          "PromptBeforeTunnelConnect": false
        }
        """);

        var service = new AppSettingsService(temp.FilePath);

        Assert.True(service.Current.PromptBeforeTunnelConnect);
        Assert.Equal(1, service.Current.BitwardenOnboardingNoticePendingVersion);
        Assert.Equal(AppSettings.CurrentSchemaVersion, service.Current.SettingsSchemaVersion);

        var saved = JsonSerializer.Deserialize<AppSettings>(File.ReadAllBytes(temp.FilePath));
        Assert.NotNull(saved);
        Assert.True(saved!.PromptBeforeTunnelConnect);
        Assert.Equal(1, saved.BitwardenOnboardingNoticePendingVersion);
        Assert.Equal(AppSettings.CurrentSchemaVersion, saved.SettingsSchemaVersion);
    }

    [Fact]
    public void VersionedSettings_PreservesPromptBeforeTunnelConnectOff()
    {
        using var temp = TempSettingsFile.Create();
        File.WriteAllText(temp.FilePath, """
        {
          "SettingsSchemaVersion": 1,
          "PromptBeforeTunnelConnect": false
        }
        """);

        var service = new AppSettingsService(temp.FilePath);

        Assert.False(service.Current.PromptBeforeTunnelConnect);
        Assert.Equal(AppSettings.CurrentSchemaVersion, service.Current.SettingsSchemaVersion);

        var saved = JsonSerializer.Deserialize<AppSettings>(File.ReadAllBytes(temp.FilePath));
        Assert.NotNull(saved);
        Assert.False(saved!.PromptBeforeTunnelConnect);
        Assert.Equal(AppSettings.CurrentSchemaVersion, saved.SettingsSchemaVersion);
    }

    [Fact]
    public void LegacySettings_MigratesBitwardenBrowserExtensionReleaseUrl()
    {
        using var temp = TempSettingsFile.Create();
        File.WriteAllText(temp.FilePath, """
        {
          "SettingsSchemaVersion": 2,
          "BitwardenBrowserExtensionReleasesUrl": ""
        }
        """);

        var service = new AppSettingsService(temp.FilePath);

        Assert.Equal("repos/bitwarden/clients/releases?per_page=20", service.Current.BitwardenBrowserExtensionReleasesUrl);
        Assert.Equal(AppSettings.CurrentSchemaVersion, service.Current.SettingsSchemaVersion);

        var saved = JsonSerializer.Deserialize<AppSettings>(File.ReadAllBytes(temp.FilePath));
        Assert.NotNull(saved);
        Assert.Equal("repos/bitwarden/clients/releases?per_page=20", saved!.BitwardenBrowserExtensionReleasesUrl);
        Assert.Equal(AppSettings.CurrentSchemaVersion, saved.SettingsSchemaVersion);
    }


    [Fact]
    public void LegacySettings_MigratesOfficialBitwardenExtensionSourceFromDownloadUrl()
    {
        using var temp = TempSettingsFile.Create();
        File.WriteAllText(temp.FilePath, """
        {
          "SettingsSchemaVersion": 3,
          "BitwardenBrowserExtensionPath": "C:\\Wormhole\\extensions\\bitwarden\\2026.6.1",
          "BitwardenBrowserExtensionVersion": "2026.6.1",
          "BitwardenBrowserExtensionAssetName": "dist-edge-2026.6.1.zip",
          "BitwardenBrowserExtensionDownloadUrl": "https://github.com/bitwarden/clients/releases/download/browser-v2026.6.1/dist-edge-2026.6.1.zip"
        }
        """);

        var service = new AppSettingsService(temp.FilePath);

        Assert.Equal(BitwardenBrowserExtensionSource.OfficialGitHub, service.Current.BitwardenBrowserExtensionSource);
        Assert.Equal(AppSettings.CurrentSchemaVersion, service.Current.SettingsSchemaVersion);
    }

    [Fact]
    public void LegacySettings_MigratesManualBitwardenExtensionSources()
    {
        using var zipTemp = TempSettingsFile.Create();
        File.WriteAllText(zipTemp.FilePath, """
        {
          "SettingsSchemaVersion": 3,
          "BitwardenBrowserExtensionPath": "C:\\Wormhole\\extensions\\bitwarden\\manual-zip",
          "BitwardenBrowserExtensionAssetName": "bitwarden.zip"
        }
        """);

        using var folderTemp = TempSettingsFile.Create();
        File.WriteAllText(folderTemp.FilePath, """
        {
          "SettingsSchemaVersion": 3,
          "BitwardenBrowserExtensionPath": "C:\\Wormhole\\extensions\\bitwarden\\manual-folder"
        }
        """);

        var zipService = new AppSettingsService(zipTemp.FilePath);
        var folderService = new AppSettingsService(folderTemp.FilePath);

        Assert.Equal(BitwardenBrowserExtensionSource.ManualZip, zipService.Current.BitwardenBrowserExtensionSource);
        Assert.Equal(BitwardenBrowserExtensionSource.ManualFolder, folderService.Current.BitwardenBrowserExtensionSource);
    }
    [Fact]
    public void LegacySettings_MigratesBitwardenCliReleaseUrl()
    {
        using var temp = TempSettingsFile.Create();
        File.WriteAllText(temp.FilePath, """
        {
          "SettingsSchemaVersion": 4,
          "BitwardenCliReleasesUrl": ""
        }
        """);

        var service = new AppSettingsService(temp.FilePath);

        Assert.Equal("repos/bitwarden/clients/releases?per_page=20", service.Current.BitwardenCliReleasesUrl);
        Assert.Equal(AppSettings.CurrentSchemaVersion, service.Current.SettingsSchemaVersion);

        var saved = JsonSerializer.Deserialize<AppSettings>(File.ReadAllBytes(temp.FilePath));
        Assert.NotNull(saved);
        Assert.Equal("repos/bitwarden/clients/releases?per_page=20", saved!.BitwardenCliReleasesUrl);
        Assert.Equal(AppSettings.CurrentSchemaVersion, saved.SettingsSchemaVersion);
    }

    [Fact]
    public void LegacySettings_BeforeBitwardenSchema_MarksBitwardenOnboardingPending()
    {
        using var temp = TempSettingsFile.Create();
        File.WriteAllText(temp.FilePath, """
        {
          "SettingsSchemaVersion": 5
        }
        """);

        var service = new AppSettingsService(temp.FilePath);

        Assert.Equal(1, service.Current.BitwardenOnboardingNoticePendingVersion);
        Assert.Equal(AppSettings.CurrentSchemaVersion, service.Current.SettingsSchemaVersion);

        var saved = JsonSerializer.Deserialize<AppSettings>(File.ReadAllBytes(temp.FilePath));
        Assert.NotNull(saved);
        Assert.Equal(1, saved!.BitwardenOnboardingNoticePendingVersion);
        Assert.Equal(AppSettings.CurrentSchemaVersion, saved.SettingsSchemaVersion);
    }

    [Fact]
    public void BitwardenSchemaSettings_DoesNotMarkBitwardenOnboardingPending()
    {
        using var temp = TempSettingsFile.Create();
        File.WriteAllText(temp.FilePath, """
        {
          "SettingsSchemaVersion": 6
        }
        """);

        var service = new AppSettingsService(temp.FilePath);

        Assert.Equal(0, service.Current.BitwardenOnboardingNoticePendingVersion);
        Assert.Equal(AppSettings.CurrentSchemaVersion, service.Current.SettingsSchemaVersion);

        var saved = JsonSerializer.Deserialize<AppSettings>(File.ReadAllBytes(temp.FilePath));
        Assert.NotNull(saved);
        Assert.Equal(0, saved!.BitwardenOnboardingNoticePendingVersion);
        Assert.Equal(AppSettings.CurrentSchemaVersion, saved.SettingsSchemaVersion);
    }

    [Fact]
    public void MissingSettings_DoesNotMarkBitwardenOnboardingPending()
    {
        using var temp = TempSettingsFile.Create();

        var service = new AppSettingsService(temp.FilePath);

        Assert.Equal(0, service.Current.BitwardenOnboardingNoticePendingVersion);
        Assert.Equal(AppSettings.CurrentSchemaVersion, service.Current.SettingsSchemaVersion);
        Assert.False(File.Exists(temp.FilePath));
    }

    private sealed class TempSettingsFile : IDisposable
    {
        private TempSettingsFile(string directory)
        {
            DirectoryPath = directory;
            FilePath = Path.Combine(directory, "settings.json");
        }

        public string DirectoryPath { get; }
        public string FilePath { get; }

        public static TempSettingsFile Create()
        {
            var directory = Path.Combine(
                Path.GetTempPath(),
                "Wormhole.Tests",
                Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            return new TempSettingsFile(directory);
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
