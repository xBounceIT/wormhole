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

    [Fact]
    public async Task CloseAllSessionsAsync_ClearsTabsBeforeTeardownCompletes()
    {
        var vm = CreateShell();
        var slow = new TestSessionTab("slow")
        {
            CloseCompletion = new TaskCompletionSource<object?>(TaskCreationOptions.RunContinuationsAsynchronously),
        };
        vm.Tabs.Add(slow);
        vm.SelectedTab = slow;

        var closeTask = vm.CloseAllSessionsAsync();

        await slow.CloseStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.Empty(vm.Tabs);
        Assert.Null(vm.SelectedTab);
        Assert.True(vm.IsEmpty);
        Assert.False(vm.HasTabs);
        Assert.False(closeTask.IsCompleted);

        slow.CloseCompletion!.SetResult(null);
        await closeTask;
    }

    [Fact]
    public async Task CloseAllSessionsAsync_StartsAllTabClosesBeforeAwaiting()
    {
        var vm = CreateShell();
        var first = new TestSessionTab("first")
        {
            CloseCompletion = new TaskCompletionSource<object?>(TaskCreationOptions.RunContinuationsAsynchronously),
        };
        var second = new TestSessionTab("second")
        {
            CloseCompletion = new TaskCompletionSource<object?>(TaskCreationOptions.RunContinuationsAsynchronously),
        };
        vm.Tabs.Add(first);
        vm.Tabs.Add(second);

        var closeTask = vm.CloseAllSessionsAsync();

        await Task.WhenAll(first.CloseStarted.Task, second.CloseStarted.Task)
            .WaitAsync(TimeSpan.FromSeconds(1));
        Assert.False(closeTask.IsCompleted);

        first.CloseCompletion!.SetResult(null);
        second.CloseCompletion!.SetResult(null);
        await closeTask;

        Assert.Equal(1, first.CloseCount);
        Assert.Equal(1, second.CloseCount);
    }

    [Theory]
    [InlineData(SessionStatus.Connected, 1)]
    [InlineData(SessionStatus.Connecting, 1)]
    [InlineData(SessionStatus.Disconnected, 0)]
    [InlineData(SessionStatus.Failed, 0)]
    public void ActiveSessionCount_CountsOnlyLiveSessions(SessionStatus status, int expected)
    {
        var vm = CreateShell();
        vm.Tabs.Add(new TestSessionTab("tab") { Status = status });

        Assert.Equal(expected, vm.ActiveSessionCount);
    }

    [Fact]
    public void ActiveSessionCount_ExcludesSessionsThatSurviveAppClose()
    {
        var vm = CreateShell();
        vm.Tabs.Add(new TestSessionTab("embedded") { Status = SessionStatus.Connected });
        vm.Tabs.Add(new TestSessionTab("external") { Status = SessionStatus.Connected, SurvivesAppClose = true });

        // Closing the app tears down the embedded session but not the handed-off external one,
        // so only the embedded session should drive the confirmation prompt.
        Assert.Equal(1, vm.ActiveSessionCount);
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
        public TaskCompletionSource<object?> CloseStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource<object?>? CloseCompletion { get; init; }

        /// <summary>
        /// Simulates a session that closing the app won't actually disconnect (e.g. an RDP tab
        /// handed off to an external mstsc.exe), so it is excluded from the close-warning count
        /// even when its <see cref="SessionTabViewModel.Status"/> is live.
        /// </summary>
        public bool SurvivesAppClose { get; init; }

        public override ProtocolType Protocol => ProtocolType.Ssh;

        public override bool WillDisconnectOnAppClose => !SurvivesAppClose && base.WillDisconnectOnAppClose;

        public override async ValueTask CloseAsync()
        {
            CloseCount++;
            CloseStarted.TrySetResult(null);
            if (ThrowOnClose)
            {
                throw new InvalidOperationException("simulated close failure");
            }
            if (CloseCompletion is not null)
            {
                await CloseCompletion.Task;
            }
        }
    }

    private sealed class FakeAppSettingsService : IAppSettingsService
    {
        public AppSettings Current { get; } = new();
        public event EventHandler? SettingsChanged;
        public void Save() => SettingsChanged?.Invoke(this, EventArgs.Empty);
    }
}
