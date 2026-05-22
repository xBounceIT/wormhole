using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Data.Repositories;
using Wormhole.Models;
using Wormhole.Services;
using Wormhole.Services.Ssh;
using Wormhole.ViewModels.Sessions;
using Xunit;

namespace Wormhole.Tests.ViewModels;

public sealed class SshSessionViewModelTests
{
    [Fact]
    public void ConnectedSession_StartsWithoutReceivedOutput()
    {
        var vm = CreateViewModel();
        vm.Initialize(CreateProfile());

        vm.AttachConnectedSessionForTesting(new FakeSshSession());

        Assert.Equal(SessionStatus.Connected, vm.Status);
        Assert.False(vm.HasReceivedOutput);
        Assert.False(vm.IsWaitingForRemoteOutput);
    }

    [Fact]
    public void FirstDataReceived_MarksOutputReceived()
    {
        var vm = CreateViewModel();
        vm.Initialize(CreateProfile());
        var session = new FakeSshSession();
        vm.AttachConnectedSessionForTesting(session);

        session.RaiseData(0x1b, (byte)'[', (byte)'2', (byte)'J');

        Assert.True(vm.HasReceivedOutput);
        Assert.False(vm.IsWaitingForRemoteOutput);
    }

    [Fact]
    public void Reconnect_ResetsReceivedOutputState()
    {
        var vm = CreateViewModel();
        vm.Initialize(CreateProfile());
        var first = new FakeSshSession();
        vm.AttachConnectedSessionForTesting(first);
        first.RaiseData((byte)'$');
        Assert.True(vm.HasReceivedOutput);

        var second = new FakeSshSession();
        vm.AttachConnectedSessionForTesting(second);

        Assert.Equal(SessionStatus.Connected, vm.Status);
        Assert.False(vm.HasReceivedOutput);
        Assert.False(vm.IsWaitingForRemoteOutput);
    }

    [Fact]
    public void Reconnect_IgnoresLateOutputFromPreviousSession()
    {
        var vm = CreateViewModel();
        vm.Initialize(CreateProfile());
        var first = new FakeSshSession();
        var second = new FakeSshSession();
        vm.AttachConnectedSessionForTesting(first);

        vm.AttachConnectedSessionForTesting(second);
        first.RaiseData((byte)'$');

        Assert.False(vm.HasReceivedOutput);
        Assert.False(vm.IsWaitingForRemoteOutput);
    }

    [Fact]
    public void DetachView_DoesNotDisposeSshSession()
    {
        var vm = CreateViewModel();
        vm.Initialize(CreateProfile());
        var session = new FakeSshSession();
        vm.AttachConnectedSessionForTesting(session);

        vm.DetachView();

        Assert.Equal(0, session.DisposeCount);
        Assert.Equal(SessionStatus.Connected, vm.Status);
    }

    [Fact]
    public void CanReconnect_IsTrue_ForSshSession()
    {
        var vm = CreateViewModel();

        Assert.True(vm.CanReconnect);
        Assert.NotNull(vm.ReconnectCommand);
    }

    [Fact]
    public void CanReconnect_IsTrue_ForRdpSession()
    {
        // RDP exposes RetryCommand via the SessionTabViewModel.ReconnectCommand surface so
        // the SessionsPage tab context menu's Reconnect entry shows up for RDP tabs the same
        // way it does for SSH.
        var vm = new RdpSessionViewModel(
            new NullRdpSessionService(),
            new Fakes.FakeCredentialService(),
            new NullCredentialRepository(),
            new Fakes.FakeDialogService(),
            NullLoggerFactory.Instance);

        Assert.True(vm.CanReconnect);
        Assert.NotNull(vm.ReconnectCommand);
    }

    private sealed class NullRdpSessionService : IRdpSessionService
    {
        public Task<IRdpSession> ConnectAsync(
            ConnectionProfile profile, string? password, IntPtr ownerHwnd,
            string? gatewayUsername = null, string? gatewayPassword = null,
            Action<IRdpSession>? onSessionReady = null,
            CancellationToken cancellationToken = default)
            => throw new NotImplementedException();
    }

    private sealed class NullCredentialRepository : ICredentialRepository
    {
        public Task<IReadOnlyList<CredentialProfile>> GetAllAsync(CancellationToken ct = default)
            => Task.FromResult<IReadOnlyList<CredentialProfile>>(Array.Empty<CredentialProfile>());
        public Task<CredentialProfile?> GetByIdAsync(Guid id, CancellationToken ct = default) => Task.FromResult<CredentialProfile?>(null);
        public Task AddAsync(CredentialProfile profile, CancellationToken ct = default) => Task.CompletedTask;
        public Task UpdateAsync(CredentialProfile profile, CancellationToken ct = default) => Task.CompletedTask;
        public Task DeleteAsync(Guid id, CancellationToken ct = default) => Task.CompletedTask;
    }

    [Fact]
    public void CanReconnect_IsFalse_ForSftpSession()
    {
        var vm = new SftpSessionViewModel();

        Assert.False(vm.CanReconnect);
        Assert.Null(vm.ReconnectCommand);
    }

    [Fact]
    public void RetryCommand_CanExecute_IsFalse_WhileConnecting()
    {
        var vm = CreateViewModel();
        vm.Initialize(CreateProfile());

        vm.Status = SessionStatus.Connecting;

        Assert.False(vm.RetryCommand.CanExecute(null));
    }

    [Fact]
    public void RetryCommand_CanExecute_TracksStatusTransitions()
    {
        var vm = CreateViewModel();
        vm.Initialize(CreateProfile());

        vm.Status = SessionStatus.Failed;
        Assert.True(vm.RetryCommand.CanExecute(null));

        vm.Status = SessionStatus.Connecting;
        Assert.False(vm.RetryCommand.CanExecute(null));

        vm.Status = SessionStatus.Connected;
        Assert.True(vm.RetryCommand.CanExecute(null));

        vm.Status = SessionStatus.Disconnected;
        Assert.True(vm.RetryCommand.CanExecute(null));
    }

    [Fact]
    public async Task RetryAsync_WithDetachedViewAndNoSubscribers_PreservesSession()
    {
        var vm = CreateViewModel();
        vm.Initialize(CreateProfile());
        var session = new FakeSshSession();
        vm.AttachConnectedSessionForTesting(session);
        vm.DetachView();

        await vm.RetryAsync();

        // Background-tab case: the session is left alive so AttachAsync can tear it down
        // and reconnect when the tab activates and its view re-Loads.
        Assert.Equal(0, session.DisposeCount);
    }

    [Fact]
    public async Task RetryAsync_WithDetachedViewAndSubscriber_FiresInitializationRetry()
    {
        var vm = CreateViewModel();
        vm.Initialize(CreateProfile());
        var raised = 0;
        vm.InitializationRetryRequested += () => raised++;

        await vm.RetryAsync();

        // View-loaded-but-WebView2-init-failed case: existing fan-out is preserved.
        Assert.Equal(1, raised);
    }

    [Fact]
    public async Task DetachAsync_DisposesSessionAndIgnoresLateOutput()
    {
        var vm = CreateViewModel();
        vm.Initialize(CreateProfile());
        var session = new FakeSshSession();
        vm.AttachConnectedSessionForTesting(session);

        await vm.DetachAsync();
        session.RaiseData((byte)'$');

        Assert.Equal(1, session.DisposeCount);
        Assert.Equal(SessionStatus.Disconnected, vm.Status);
        Assert.False(vm.HasReceivedOutput);
        Assert.False(vm.IsWaitingForRemoteOutput);
    }

    private static SshSessionViewModel CreateViewModel() =>
        new(
            new FakeSshSessionService(),
            new FakeCredentialResolver(),
            new FakeConnectionRepository(),
            new FakeAppSettingsService(),
            NullLoggerFactory.Instance);

    private static ConnectionProfile CreateProfile() =>
        new()
        {
            NodeId = Guid.NewGuid(),
            Name = "test",
            Protocol = ProtocolType.Ssh,
            Host = "192.0.2.10",
            Port = 22,
            Username = "daniel",
        };

    private sealed class FakeSshSessionService : ISshSessionService
    {
        public Task<ISshSession> ConnectAsync(
            ConnectionProfile profile,
            SshCredentials credentials,
            TerminalSize initialSize,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException("Tests attach fake sessions directly.");
    }

    private sealed class FakeCredentialResolver : ISshCredentialResolver
    {
        public Task<SshCredentials> ResolveAsync(
            ConnectionProfile profile,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(SshCredentials.Empty);
    }

    private sealed class FakeAppSettingsService : IAppSettingsService
    {
        public AppSettings Current { get; } = new();
        public event EventHandler? SettingsChanged { add { } remove { } }
        public void Save() { }
    }

    private sealed class FakeConnectionRepository : IConnectionRepository
    {
        public Task<IReadOnlyList<ConnectionNode>> GetAllAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<ConnectionNode>>(Array.Empty<ConnectionNode>());

        public Task<ConnectionNode?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default) =>
            Task.FromResult<ConnectionNode?>(null);

        public Task AddAsync(ConnectionNode node, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;

        public Task UpdateAsync(ConnectionNode node, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;

        public Task UpdateManyAsync(IReadOnlyCollection<ConnectionNode> nodes, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;

        public Task UpdateHostFingerprintAsync(Guid nodeId, string fingerprint, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;

        public Task DeleteAsync(Guid id, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
    }

    private sealed class FakeSshSession : ISshSession
    {
        public string? HostFingerprint { get; init; } = "SHA256:test";

        public int DisposeCount { get; private set; }

        public event EventHandler<ReadOnlyMemory<byte>>? DataReceived;
        public event EventHandler? Closed;

        public void Start()
        {
        }

        public Task WriteAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;

        public Task ResizeAsync(uint columns, uint rows) =>
            Task.CompletedTask;

        public void RaiseData(params byte[] data) =>
            DataReceived?.Invoke(this, data);

        public void RaiseClosed() =>
            Closed?.Invoke(this, EventArgs.Empty);

        public ValueTask DisposeAsync()
        {
            DisposeCount++;
            return ValueTask.CompletedTask;
        }
    }
}
