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

    [Fact]
    public void RemovingSelectedLastTab_ClearsSelectedTab()
    {
        var vm = CreateShell();
        var tab = new TestSessionTab("only");
        vm.Tabs.Add(tab);
        vm.SelectedTab = tab;

        vm.Tabs.Remove(tab);

        Assert.Null(vm.SelectedTab);
        Assert.True(vm.IsEmpty);
        Assert.False(vm.HasTabs);
    }

    [Fact]
    public void RemovingSelectedTab_SelectsClosestRemainingNeighbour()
    {
        var vm = CreateShell();
        var first = new TestSessionTab("first");
        var second = new TestSessionTab("second");
        var third = new TestSessionTab("third");
        vm.Tabs.Add(first);
        vm.Tabs.Add(second);
        vm.Tabs.Add(third);
        vm.SelectedTab = second;

        vm.Tabs.Remove(second);

        Assert.Same(third, vm.SelectedTab);
    }

    [Fact]
    public void SelectedTab_CannotPointAtTabOutsideCollection()
    {
        var vm = CreateShell();
        var open = new TestSessionTab("open");
        var closed = new TestSessionTab("closed");
        vm.Tabs.Add(open);

        vm.SelectedTab = closed;

        Assert.Same(open, vm.SelectedTab);
    }

    [Fact]
    public void SelectedTab_NullWhileTabsRemain_RestoresLastValidSelection()
    {
        var vm = CreateShell();
        var first = new TestSessionTab("first");
        var second = new TestSessionTab("second");
        vm.Tabs.Add(first);
        vm.Tabs.Add(second);
        vm.SelectedTab = first;

        vm.SelectedTab = null;

        Assert.Same(first, vm.SelectedTab);
    }

    [Fact]
    public void SelectedTab_StaleRemovedTabAfterRemoval_KeepsClosestNeighbour()
    {
        var vm = CreateShell();
        var first = new TestSessionTab("first");
        var second = new TestSessionTab("second");
        var third = new TestSessionTab("third");
        var fourth = new TestSessionTab("fourth");
        vm.Tabs.Add(first);
        vm.Tabs.Add(second);
        vm.Tabs.Add(third);
        vm.Tabs.Add(fourth);
        vm.SelectedTab = second;
        vm.Tabs.Remove(second);
        Assert.Same(third, vm.SelectedTab);

        vm.SelectedTab = second;

        Assert.Same(third, vm.SelectedTab);
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

    [Fact]
    public void RemovingEphemeralTab_ReleasesTransientPassword()
    {
        var store = new TransientSessionCredentialStore();
        var vm = CreateShell(store);
        var nodeId = Guid.NewGuid();
        store.Store(nodeId, "session-secret");
        var tab = new TestSessionTab("quick");
        tab.Initialize(CreateProfile(nodeId, isEphemeral: true));
        vm.Tabs.Add(tab);

        vm.Tabs.Remove(tab);

        Assert.Null(store.Read(nodeId));
    }

    [Fact]
    public async Task CloseAllSessionsAsync_ClearsAllTransientPasswords()
    {
        var store = new TransientSessionCredentialStore();
        var vm = CreateShell(store);
        var firstId = Guid.NewGuid();
        var secondId = Guid.NewGuid();
        store.Store(firstId, "first");
        store.Store(secondId, "second");
        var tab = new TestSessionTab("quick");
        tab.Initialize(CreateProfile(firstId, isEphemeral: true));
        vm.Tabs.Add(tab);

        await vm.CloseAllSessionsAsync();

        Assert.Null(store.Read(firstId));
        Assert.Null(store.Read(secondId));
    }

    private static ShellViewModel CreateShell(ITransientSessionCredentialStore? transientCredentials = null) =>
        new(
            tree: null!,
            update: null!,
            settings: new FakeAppSettingsService(),
            logger: NullLogger<ShellViewModel>.Instance,
            transientCredentials: transientCredentials);

    private static ConnectionProfile CreateProfile(Guid nodeId, bool isEphemeral) => new()
    {
        NodeId = nodeId,
        Name = "quick",
        Protocol = ProtocolType.Ssh,
        Host = "target.example.com",
        Port = 22,
        IsEphemeral = isEphemeral,
    };

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
