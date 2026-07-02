using System.Text.Json;
using Wormhole.Models;
using Xunit;

namespace Wormhole.Tests.Models;

public class AppSettingsTests
{
    [Fact]
    public void Deserialize_Missing_LogRetentionDays_Uses_Default()
    {
        var settings = JsonSerializer.Deserialize<AppSettings>("{}");

        Assert.NotNull(settings);
        Assert.Equal(14, settings!.LogRetentionDays);
    }

    [Fact]
    public void Deserialize_Missing_BitwardenBrowserExtensionSettings_Uses_Defaults()
    {
        var settings = JsonSerializer.Deserialize<AppSettings>("{}");

        Assert.NotNull(settings);
        Assert.False(settings!.EnableBitwardenVault);
        Assert.Equal("bw", settings.BitwardenCliPath);
        Assert.Equal("repos/bitwarden/clients/releases?per_page=20", settings.BitwardenCliReleasesUrl);
        Assert.Null(settings.BitwardenCliVersion);
        Assert.Null(settings.BitwardenCliInstallStatus);
        Assert.Null(settings.BitwardenCliInstallError);
        Assert.False(settings.EnableBitwardenBrowserExtension);
        Assert.Equal(BitwardenBrowserExtensionSource.OfficialGitHub, settings.BitwardenBrowserExtensionSource);
        Assert.Equal("repos/bitwarden/clients/releases?per_page=20", settings.BitwardenBrowserExtensionReleasesUrl);
        Assert.Null(settings.BitwardenBrowserExtensionPath);
        Assert.Null(settings.BitwardenBrowserExtensionVersion);
        Assert.Null(settings.BitwardenBrowserExtensionLastUpdateCheckUtc);
        Assert.Null(settings.BitwardenBrowserExtensionLastUpdateStatus);
        Assert.Null(settings.BitwardenBrowserExtensionLastUpdateError);
        Assert.Null(settings.BitwardenBrowserExtensionAvailableVersion);
        Assert.Equal(0, settings.BitwardenOnboardingNoticeSeenVersion);
    }
}
