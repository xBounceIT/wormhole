using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Models;
using Wormhole.Services;
using Wormhole.ViewModels;
using Wormhole.ViewModels.Sessions;
using Xunit;

namespace Wormhole.Tests.ViewModels;

public class ShellViewModelTests
{
    [Fact]
    public async Task CloseAllSessionsAsync_ClosesEveryTabAndClearsCollection()
    {
        var vm = CreateShell();
        var first = new TestSessionTab("first");
        var second = new TestSessionTab("second");
        vm.Tabs.Add(first);
        vm.Tabs.Add(second);
        vm.SelectedTab = second;

        await vm.CloseAllSessionsAsync();

        Assert.Equal(1, first.CloseCount);
        Assert.Equal(1, second.CloseCount);
        Assert.Empty(vm.Tabs);
        Assert.Null(vm.SelectedTab);
        Assert.True(vm.IsEmpty);
        Assert.False(vm.HasTabs);
    }

    [Fact]
    public async Task CloseAllSessionsAsync_ContinuesAfterTabCloseFailure()
    {
        var vm = CreateShell();
        var failing = new TestSessionTab("failing") { ThrowOnClose = true };
        var survivor = new TestSessionTab("survivor");
        vm.Tabs.Add(failing);
        vm.Tabs.Add(survivor);

        await vm.CloseAllSessionsAsync();

        Assert.Equal(1, failing.CloseCount);
        Assert.Equal(1, survivor.CloseCount);
        Assert.Empty(vm.Tabs);
    }

    private static ShellViewModel CreateShell() =>
        new(
            tree: null!,
            update: null!,
            settings: new FakeAppSettingsService(),
            logger: NullLogger<ShellViewModel>.Instance);

    private sealed class TestSessionTab : SessionTabViewModel
    {
        public TestSessionTab(string title)
        {
            Title = title;
        }

        public int CloseCount { get; private set; }
        public bool ThrowOnClose { get; init; }
        public override ProtocolType Protocol => ProtocolType.Ssh;

        public override ValueTask CloseAsync()
        {
            CloseCount++;
            if (ThrowOnClose)
            {
                throw new InvalidOperationException("simulated close failure");
            }
            return ValueTask.CompletedTask;
        }
    }

    private sealed class FakeAppSettingsService : IAppSettingsService
    {
        public AppSettings Current { get; } = new();
        public event EventHandler? SettingsChanged;
        public void Save() => SettingsChanged?.Invoke(this, EventArgs.Empty);
    }
}
