using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Models;
using Wormhole.Services;
using Wormhole.Tests.Fakes;
using Xunit;

namespace Wormhole.Tests.Services;

public sealed class BitwardenOnboardingNoticeServiceTests
{
    [Fact]
    public async Task ShowIfNeededAsync_ShowsNoticeAndMarksSeen_WhenPendingOnVersion07()
    {
        var settings = new FakeSettings
        {
            Current = { BitwardenOnboardingNoticePendingVersion = BitwardenOnboardingNoticeService.CurrentBitwardenOnboardingNoticeVersion },
        };
        var dialog = new RecordingDialogService();
        var service = NewService(settings, dialog, new Version(0, 7, 1));

        await service.ShowIfNeededAsync();

        Assert.Equal(1, dialog.ShowMessageCount);
        Assert.Equal("New Bitwarden integration", dialog.LastTitle);
        Assert.Equal(
            "Wormhole now supports Bitwarden as an optional vault for credentials and as a browser extension in HTTPS windows. Enable it from Settings > Extensions > Bitwarden.",
            dialog.LastMessage);
        Assert.Equal(
            BitwardenOnboardingNoticeService.CurrentBitwardenOnboardingNoticeVersion,
            settings.Current.BitwardenOnboardingNoticeSeenVersion);
        Assert.Equal(0, settings.Current.BitwardenOnboardingNoticePendingVersion);
        Assert.Equal(1, settings.SaveCount);
    }

    [Fact]
    public async Task ShowIfNeededAsync_DoesNothingWhenPendingOnVersion08()
    {
        var settings = new FakeSettings
        {
            Current = { BitwardenOnboardingNoticePendingVersion = BitwardenOnboardingNoticeService.CurrentBitwardenOnboardingNoticeVersion },
        };
        var dialog = new RecordingDialogService();
        var service = NewService(settings, dialog, new Version(0, 8, 0));

        await service.ShowIfNeededAsync();

        Assert.Equal(0, dialog.ShowMessageCount);
        Assert.Equal(0, settings.Current.BitwardenOnboardingNoticeSeenVersion);
        Assert.Equal(BitwardenOnboardingNoticeService.CurrentBitwardenOnboardingNoticeVersion, settings.Current.BitwardenOnboardingNoticePendingVersion);
        Assert.Equal(0, settings.SaveCount);
    }

    [Fact]
    public async Task ShowIfNeededAsync_DoesNothingWithoutPendingNotice()
    {
        var settings = new FakeSettings();
        var dialog = new RecordingDialogService();
        var service = NewService(settings, dialog, new Version(0, 7, 1));

        await service.ShowIfNeededAsync();

        Assert.Equal(0, dialog.ShowMessageCount);
        Assert.Equal(0, settings.Current.BitwardenOnboardingNoticeSeenVersion);
        Assert.Equal(0, settings.Current.BitwardenOnboardingNoticePendingVersion);
        Assert.Equal(0, settings.SaveCount);
    }

    [Fact]
    public async Task ShowIfNeededAsync_DoesNothingWhenAlreadySeen()
    {
        var settings = new FakeSettings
        {
            Current =
            {
                BitwardenOnboardingNoticeSeenVersion = BitwardenOnboardingNoticeService.CurrentBitwardenOnboardingNoticeVersion,
                BitwardenOnboardingNoticePendingVersion = BitwardenOnboardingNoticeService.CurrentBitwardenOnboardingNoticeVersion,
            },
        };
        var dialog = new RecordingDialogService();
        var service = NewService(settings, dialog, new Version(0, 7, 1));

        await service.ShowIfNeededAsync();

        Assert.Equal(0, dialog.ShowMessageCount);
        Assert.Equal(BitwardenOnboardingNoticeService.CurrentBitwardenOnboardingNoticeVersion, settings.Current.BitwardenOnboardingNoticePendingVersion);
        Assert.Equal(0, settings.SaveCount);
    }

    [Fact]
    public async Task ShowIfNeededAsync_DoesNotMarkSeenWhenDialogFails()
    {
        var settings = new FakeSettings
        {
            Current = { BitwardenOnboardingNoticePendingVersion = BitwardenOnboardingNoticeService.CurrentBitwardenOnboardingNoticeVersion },
        };
        var dialog = new RecordingDialogService { ThrowOnShow = true };
        var service = NewService(settings, dialog, new Version(0, 7, 1));

        await service.ShowIfNeededAsync();

        Assert.Equal(1, dialog.ShowMessageCount);
        Assert.Equal(0, settings.Current.BitwardenOnboardingNoticeSeenVersion);
        Assert.Equal(BitwardenOnboardingNoticeService.CurrentBitwardenOnboardingNoticeVersion, settings.Current.BitwardenOnboardingNoticePendingVersion);
        Assert.Equal(0, settings.SaveCount);
    }

    private static BitwardenOnboardingNoticeService NewService(
        FakeSettings settings,
        RecordingDialogService dialog,
        Version currentVersion) =>
        new(settings, dialog, NullLogger<BitwardenOnboardingNoticeService>.Instance, currentVersion);

    private sealed class RecordingDialogService : FakeDialogService
    {
        public int ShowMessageCount { get; private set; }
        public string? LastTitle { get; private set; }
        public string? LastMessage { get; private set; }
        public bool ThrowOnShow { get; set; }

        public override Task ShowMessageAsync(string title, string message) =>
            throw new InvalidOperationException("The onboarding notice must use the Bitwarden-specific dialog.");

        public override Task ShowBitwardenOnboardingNoticeAsync(string title, string message)
        {
            ShowMessageCount++;
            LastTitle = title;
            LastMessage = message;
            if (ThrowOnShow) throw new InvalidOperationException("dialog failed");
            return Task.CompletedTask;
        }
    }

    private sealed class FakeSettings : IAppSettingsService
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
