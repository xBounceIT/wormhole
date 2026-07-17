using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Models;
using Wormhole.Services;
using Wormhole.ViewModels;
using Xunit;

namespace Wormhole.Tests.ViewModels;

public class UpdateViewModelTests
{
    [Fact]
    public void ApplyResult_UpdateWithReleaseNotes_PopulatesChangelog()
    {
        var (vm, updates) = NewHarness();

        updates.Raise(UpdateWithNotes("## Changes\n\n- Fixed update checks"));

        Assert.True(vm.HasChangelog);
        Assert.True(vm.ShowChangelog);
        Assert.Equal("Changelog - Release v9.9.9", vm.ChangelogTitle);
        Assert.Contains("<h2", vm.ChangelogHtml);
        Assert.Contains("<li>Fixed update checks</li>", vm.ChangelogHtml);
    }

    [Fact]
    public void ApplyResult_UpdateWithoutReleaseNotes_DoesNotShowChangelog()
    {
        var (vm, updates) = NewHarness();

        updates.Raise(UpdateWithNotes("   "));

        Assert.False(vm.HasChangelog);
        Assert.False(vm.ShowChangelog);
        Assert.Equal(string.Empty, vm.ChangelogTitle);
        Assert.Equal(string.Empty, vm.ChangelogHtml);
    }

    [Fact]
    public void ApplyResult_RenderEmptyReleaseNotes_DoesNotShowChangelog()
    {
        var (vm, updates) = NewHarness();

        updates.Raise(UpdateWithNotes("[release]: https://example.com"));

        Assert.False(vm.HasChangelog);
        Assert.False(vm.ShowChangelog);
        Assert.Equal(string.Empty, vm.ChangelogTitle);
        Assert.Equal(string.Empty, vm.ChangelogHtml);
    }

    [Fact]
    public void ApplyResult_NoUpdate_ClearsPreviousChangelog()
    {
        var (vm, updates) = NewHarness();
        updates.Raise(UpdateWithNotes("## Changes\n\n- Fixed update checks"));

        updates.Raise(UpdateCheckResult.NoUpdate(new Version(0, 4, 0), new Version(0, 4, 0)));

        Assert.False(vm.HasChangelog);
        Assert.False(vm.ShowChangelog);
        Assert.Equal(string.Empty, vm.ChangelogTitle);
        Assert.Equal(string.Empty, vm.ChangelogHtml);
    }

    [Fact]
    public void ApplyResult_FailedCheck_PreservesPreviousChangelog()
    {
        var (vm, updates) = NewHarness();
        updates.Raise(UpdateWithNotes("## Changes\n\n- Fixed update checks"));

        updates.Raise(UpdateCheckResult.Failed(new Version(0, 4, 0)));

        Assert.True(vm.HasChangelog);
        Assert.True(vm.ShowChangelog);
        Assert.Equal("Changelog - Release v9.9.9", vm.ChangelogTitle);
        Assert.Contains("<li>Fixed update checks</li>", vm.ChangelogHtml);
    }

    [Fact]
    public void Dismiss_ClearsVisibleChangelogForSkippedUpdate()
    {
        var (vm, updates) = NewHarness();
        updates.Raise(UpdateWithNotes("## Changes\n\n- Fixed update checks"));

        vm.DismissCommand.Execute(null);

        Assert.False(vm.IsUpdateAvailable);
        Assert.False(vm.HasChangelog);
        Assert.False(vm.ShowChangelog);
        Assert.Equal(string.Empty, vm.ChangelogTitle);
        Assert.Equal(string.Empty, vm.ChangelogHtml);
    }

    [Fact]
    public async Task RunStartupCheckAsync_RecentLastCheck_ChecksAnyway()
    {
        var updates = new FakeUpdateService();
        var settings = new FakeAppSettingsService();
        settings.Current.LastUpdateCheck = DateTimeOffset.UtcNow;
        var vm = new UpdateViewModel(updates, settings, NullLogger<UpdateViewModel>.Instance, isDevelopmentBuild: false);

        await vm.RunStartupCheckAsync();

        Assert.Equal(1, updates.CheckCount);
    }

    [Fact]
    public async Task RunStartupCheckAsync_AutoCheckDisabled_DoesNotCheck()
    {
        var updates = new FakeUpdateService();
        var settings = new FakeAppSettingsService();
        settings.Current.AutoCheckForUpdates = false;
        var vm = new UpdateViewModel(updates, settings, NullLogger<UpdateViewModel>.Instance, isDevelopmentBuild: false);

        await vm.RunStartupCheckAsync();

        Assert.Equal(0, updates.CheckCount);
    }

    [Fact]
    public async Task RunStartupCheckAsync_DevelopmentBuild_DoesNotCheck()
    {
        var updates = new FakeUpdateService();
        var vm = new UpdateViewModel(updates, new FakeAppSettingsService(), NullLogger<UpdateViewModel>.Instance, isDevelopmentBuild: true);

        await vm.RunStartupCheckAsync();

        Assert.Equal(0, updates.CheckCount);
        Assert.Equal("Update checks are disabled in development builds.", vm.Status);
    }

    [Fact]
    public async Task RunStartupCheckAsync_UpdateAvailable_ShowsInfoBar()
    {
        var updates = new FakeUpdateService { NextResult = UpdateWithNotes("## Changes\n\n- Startup checks") };
        var vm = new UpdateViewModel(updates, new FakeAppSettingsService(), NullLogger<UpdateViewModel>.Instance, isDevelopmentBuild: false);

        await vm.RunStartupCheckAsync();

        Assert.Equal(1, updates.CheckCount);
        Assert.True(vm.IsUpdateAvailable);
        Assert.Equal("Wormhole 9.9.9 is available.", vm.InfoBarMessage);
        Assert.Equal("Update available: 9.9.9", vm.Status);
    }

    [Fact]
    public async Task InstallAsync_PreparesOpenSessionsBeforeLaunchingInstaller()
    {
        var (vm, updates) = NewHarness();
        updates.Raise(UpdateWithNotes("update"));
        var prepared = false;
        vm.PrepareForInstallAsync = () =>
        {
            prepared = true;
            return Task.CompletedTask;
        };
        updates.OnLaunch = () => Assert.True(prepared);

        await vm.InstallCommand.ExecuteAsync(null);

        Assert.True(prepared);
        Assert.Equal(1, updates.LaunchCount);
    }

    private static (UpdateViewModel ViewModel, FakeUpdateService Updates) NewHarness()
    {
        var updates = new FakeUpdateService();
        var vm = new UpdateViewModel(updates, new FakeAppSettingsService(), NullLogger<UpdateViewModel>.Instance);
        return (vm, updates);
    }

    private static UpdateCheckResult UpdateWithNotes(string? notes) =>
        new(
            CurrentVersion: new Version(0, 4, 0),
            LatestVersion: new Version(9, 9, 9),
            IsUpdateAvailable: true,
            CheckFailed: false,
            ReleaseTag: "v9.9.9",
            ReleaseName: "Release v9.9.9",
            ReleaseUrl: "https://example.invalid/releases/v9.9.9",
            ReleaseNotes: notes,
            InstallerUrl: "https://example.invalid/installer.exe",
            InstallerFileName: "Wormhole-9.9.9-win-x64-setup.exe",
            InstallerSize: 1234,
            InstallerSha256: null);

    private sealed class FakeUpdateService : IUpdateService
    {
        public UpdateCheckResult? LatestKnown { get; private set; }
        public int CheckCount { get; private set; }
        public int LaunchCount { get; private set; }
        public Action? OnLaunch { get; set; }
        public UpdateCheckResult NextResult { get; set; } = UpdateCheckResult.NoUpdate(new Version(0, 4, 0));
        public event EventHandler<UpdateCheckResult>? UpdateAvailable;
        public void Raise(UpdateCheckResult result)
        {
            if (!result.CheckFailed)
                LatestKnown = result;
            UpdateAvailable?.Invoke(this, result);
        }
        public Task<UpdateCheckResult> CheckAsync(CancellationToken cancellationToken = default)
        {
            CheckCount++;
            if (!NextResult.CheckFailed)
                LatestKnown = NextResult;
            return Task.FromResult(NextResult);
        }
        public Task<string> DownloadInstallerAsync(UpdateCheckResult update, IProgress<double>? progress, CancellationToken cancellationToken = default) =>
            Task.FromResult(string.Empty);
        public Task LaunchInstallerAndExitAsync(string installerPath)
        {
            OnLaunch?.Invoke();
            LaunchCount++;
            return Task.CompletedTask;
        }
    }

    private sealed class FakeAppSettingsService : IAppSettingsService
    {
        public AppSettings Current { get; } = new();
        public event EventHandler? SettingsChanged { add { } remove { } }
        public void Save() { }
    }
}
