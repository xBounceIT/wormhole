using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Data.Repositories;
using Wormhole.Models;
using Wormhole.Services;
using Wormhole.Services.Ssh;
using Wormhole.Services.Tunneling;
using Wormhole.Tests.Fakes;
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
        // RDP surfaces RetryCommand on the ReconnectCommand override so the tab context
        // menu's Reconnect entry shows up — the assertion the SSH counterpart already makes.
        var vm = new RdpSessionViewModel(
            new NullRdpSessionService(),
            new Fakes.FakeCredentialService(),
            new NullCredentialRepository(),
            CreateTunnelManager(),
            new Fakes.FakeDialogService(),
            new Fakes.FakeRdpCrashSentinelService(),
            NullLoggerFactory.Instance);

        Assert.True(vm.CanReconnect);
        Assert.NotNull(vm.ReconnectCommand);
    }

    [Fact]
    public void RdpRetryCommand_CanExecute_TracksStatusTransitions()
    {
        var vm = new RdpSessionViewModel(
            new NullRdpSessionService(),
            new Fakes.FakeCredentialService(),
            new NullCredentialRepository(),
            CreateTunnelManager(),
            new Fakes.FakeDialogService(),
            new Fakes.FakeRdpCrashSentinelService(),
            NullLoggerFactory.Instance);

        vm.Status = SessionStatus.Failed;
        Assert.True(vm.RetryCommand.CanExecute(null));

        vm.Status = SessionStatus.Connecting;
        Assert.False(vm.RetryCommand.CanExecute(null));

        vm.Status = SessionStatus.Connected;
        Assert.True(vm.RetryCommand.CanExecute(null));
    }

    private sealed class NullRdpSessionService : IRdpSessionService
    {
        public Task<IRdpSession> ConnectAsync(
            ConnectionProfile profile, string? password, IntPtr ownerHwnd,
            string? gatewayUsername = null, string? gatewayPassword = null,
            HostBounds initialBounds = default,
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

    private static TunnelManager CreateTunnelManager()
    {
        var credentials = new Fakes.FakeCredentialService();
        return new TunnelManager(
            Array.Empty<ITunnelProvider>(),
            new FakeTunnelConfigRepository(),
            credentials,
            NullLoggerFactory.Instance.CreateLogger<TunnelManager>());
    }

    [Fact]
    public void CanReconnect_IsFalse_ByDefault()
    {
        var vm = new BareSessionTab();

        Assert.False(vm.CanReconnect);
        Assert.Null(vm.ReconnectCommand);
    }

    // CanOpenFileTransfer should only be true once the SSH session is Connected — the
    // SFTP service opens a fresh authenticated channel that piggybacks on the same
    // credentials, so showing the menu item before auth completes would surface an
    // immediate "no credentials" error.

    [Fact]
    public void CanOpenFileTransfer_IsFalse_BeforeConnected()
    {
        var vm = CreateViewModel();
        vm.Initialize(CreateProfile());

        Assert.False(vm.CanOpenFileTransfer);
    }

    [Fact]
    public void CanOpenFileTransfer_FlipsWithStatus()
    {
        var vm = CreateViewModel();
        vm.Initialize(CreateProfile());

        vm.Status = SessionStatus.Connecting;
        Assert.False(vm.CanOpenFileTransfer);

        vm.Status = SessionStatus.Connected;
        Assert.True(vm.CanOpenFileTransfer);

        vm.Status = SessionStatus.Failed;
        Assert.False(vm.CanOpenFileTransfer);

        vm.Status = SessionStatus.Disconnected;
        Assert.False(vm.CanOpenFileTransfer);
    }

    [Fact]
    public void CanOpenFileTransfer_NotifiesOnStatusChange()
    {
        var vm = CreateViewModel();
        vm.Initialize(CreateProfile());
        int notifications = 0;
        vm.PropertyChanged += (_, args) =>
        {
            if (args.PropertyName == nameof(vm.CanOpenFileTransfer)) notifications++;
        };

        vm.Status = SessionStatus.Connected;
        vm.Status = SessionStatus.Failed;

        Assert.Equal(2, notifications);
    }

    [Fact]
    public void CanOpenFileTransfer_IsFalse_ForRdpSession()
    {
        var vm = new RdpSessionViewModel(
            new NullRdpSessionService(),
            new Fakes.FakeCredentialService(),
            new NullCredentialRepository(),
            CreateTunnelManager(),
            new Fakes.FakeDialogService(),
            new Fakes.FakeRdpCrashSentinelService(),
            NullLoggerFactory.Instance);

        Assert.False(vm.CanOpenFileTransfer);
    }

    [Fact]
    public void CanOpenFileTransfer_IsFalse_ByDefault()
    {
        var vm = new BareSessionTab();
        Assert.False(vm.CanOpenFileTransfer);
    }

    // Minimal concrete SessionTabViewModel that overrides nothing, so the base-class
    // defaults (no reconnect command, no file-transfer entry) can be asserted directly.
    private sealed class BareSessionTab : SessionTabViewModel
    {
        public override ProtocolType Protocol => ProtocolType.Ssh;
    }

    // === SFTP pre-warm =====================================================
    // When the shell session reaches Connected, the VM opens an SFTP session in the
    // background so the file-transfer dialog can hand off a warm session instead of
    // running an ~800ms SSH/SFTP connect on every click. The tests below cover the
    // state machine: kicks off, cancels on disconnect, returns null before ready,
    // consume + re-warm, and silent failure.

    [Fact]
    public async Task Prewarm_KicksOff_OnConnectedTransition()
    {
        var sftp = new FakeSftpService();
        var vm = CreateViewModel(sftp);
        vm.Initialize(CreateProfile());
        var creds = new SshCredentials("pwd", null, null);
        vm.PrimeCredentialsForTesting(creds);

        vm.AttachConnectedSessionForTesting(new FakeSshSession());

        await WaitForAsync(() => vm.HasPrewarmedSftpForTesting());
        Assert.Equal(1, sftp.ConnectCallCount);
        Assert.Same(creds, sftp.LastCredentials);
    }

    [Fact]
    public async Task Prewarm_Cancels_OnDisconnect()
    {
        var sftp = new FakeSftpService();
        var cancelObserved = new TaskCompletionSource();
        sftp.ConnectImpl = async (_, _, _, ct) =>
        {
            try { await Task.Delay(Timeout.Infinite, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { cancelObserved.TrySetResult(); throw; }
            return new FakeSftpSession();
        };
        var vm = CreateViewModel(sftp);
        vm.Initialize(CreateProfile());
        vm.PrimeCredentialsForTesting(new SshCredentials("pwd", null, null));

        vm.AttachConnectedSessionForTesting(new FakeSshSession());
        await WaitForAsync(() => vm.HasInFlightPrewarmForTesting());

        await vm.DetachAsync();

        await cancelObserved.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await WaitForAsync(() => !vm.HasInFlightPrewarmForTesting());
        Assert.False(vm.HasPrewarmedSftpForTesting());
    }

    [Fact]
    public async Task TryConsumePrewarmedSftp_ReturnsNull_BeforeReady()
    {
        var sftp = new FakeSftpService();
        // Never completes so the cache stays empty.
        sftp.ConnectImpl = (_, _, _, _) => new TaskCompletionSource<ISftpSession>().Task;
        var vm = CreateViewModel(sftp);
        vm.Initialize(CreateProfile());
        vm.PrimeCredentialsForTesting(new SshCredentials("pwd", null, null));

        vm.AttachConnectedSessionForTesting(new FakeSshSession());
        await WaitForAsync(() => vm.HasInFlightPrewarmForTesting());

        Assert.Null(vm.TryConsumePrewarmedSftp());
    }

    [Fact]
    public async Task TryConsumePrewarmedSftp_ReturnsSessionOnce_AndReWarms()
    {
        // Use gated TCSs so the test can deterministically observe both prewarm
        // attempts: the first to fill the cache, the second kicked off by the
        // consume call.
        var firstGate = new TaskCompletionSource<ISftpSession>();
        var secondGate = new TaskCompletionSource<ISftpSession>();
        var sftp = new FakeSftpService();
        sftp.ConnectImpl = (_, _, _, _) =>
            sftp.ConnectCallCount == 1 ? firstGate.Task : secondGate.Task;

        var vm = CreateViewModel(sftp);
        vm.Initialize(CreateProfile());
        vm.PrimeCredentialsForTesting(new SshCredentials("pwd", null, null));

        vm.AttachConnectedSessionForTesting(new FakeSshSession());
        await WaitForAsync(() => sftp.ConnectCallCount == 1);

        var fakeFirst = new FakeSftpSession();
        firstGate.SetResult(fakeFirst);
        await WaitForAsync(() => vm.HasPrewarmedSftpForTesting());

        var consumed = vm.TryConsumePrewarmedSftp();
        Assert.NotNull(consumed);
        Assert.Same(fakeFirst, consumed!.Value.Session);

        // Consuming kicks off a fresh prewarm; while it's in flight the cache
        // must be empty.
        await WaitForAsync(() => sftp.ConnectCallCount == 2);
        Assert.False(vm.HasPrewarmedSftpForTesting());
        Assert.Null(vm.TryConsumePrewarmedSftp());

        var fakeSecond = new FakeSftpSession();
        secondGate.SetResult(fakeSecond);
        await WaitForAsync(() => vm.HasPrewarmedSftpForTesting());

        var second = vm.TryConsumePrewarmedSftp();
        Assert.NotNull(second);
        Assert.Same(fakeSecond, second!.Value.Session);
    }

    [Fact]
    public async Task Prewarm_Failure_LeavesCacheEmpty()
    {
        var sftp = new FakeSftpService();
        sftp.ConnectImpl = (_, _, _, _) =>
            Task.FromException<ISftpSession>(new InvalidOperationException("simulated"));
        var vm = CreateViewModel(sftp);
        vm.Initialize(CreateProfile());
        vm.PrimeCredentialsForTesting(new SshCredentials("pwd", null, null));

        vm.AttachConnectedSessionForTesting(new FakeSshSession());

        // Failure path clears _prewarmCts and leaves the cache empty without
        // bubbling the exception — wait for the in-flight slot to drain.
        await WaitForAsync(() => !vm.HasInFlightPrewarmForTesting());
        Assert.False(vm.HasPrewarmedSftpForTesting());
        Assert.Null(vm.TryConsumePrewarmedSftp());
        Assert.Equal(1, sftp.ConnectCallCount);
    }

    [Fact]
    public async Task TryConsumePrewarmedSftp_DropsStaleSession_AndReturnsNull()
    {
        // A cached session whose underlying transport idled out must not be handed to
        // the dialog — return null so the caller falls back to a fresh on-demand connect.
        var staleSession = new FakeSftpSession { IsConnected = false };
        var sftp = new FakeSftpService();
        sftp.ConnectImpl = (_, _, _, _) => Task.FromResult<ISftpSession>(staleSession);
        var vm = CreateViewModel(sftp);
        vm.Initialize(CreateProfile());
        vm.PrimeCredentialsForTesting(new SshCredentials("pwd", null, null));

        vm.AttachConnectedSessionForTesting(new FakeSshSession());
        await WaitForAsync(() => vm.HasPrewarmedSftpForTesting());

        var consumed = vm.TryConsumePrewarmedSftp();

        Assert.Null(consumed);
        // Stale session must be disposed so its socket isn't leaked.
        await WaitForAsync(() => staleSession.DisposeCount > 0);
    }

    [Fact]
    public void Prewarm_DoesNotKickOff_WithoutCapturedCredentials()
    {
        // Defense: if a transition to Connected happens via a path that didn't run
        // ConnectAsync (e.g. the testing helper without PrimeCredentialsForTesting),
        // we must NOT try to connect with a null credentials object.
        var sftp = new FakeSftpService();
        var vm = CreateViewModel(sftp);
        vm.Initialize(CreateProfile());

        vm.AttachConnectedSessionForTesting(new FakeSshSession());

        Assert.Equal(0, sftp.ConnectCallCount);
        Assert.False(vm.HasInFlightPrewarmForTesting());
        Assert.False(vm.HasPrewarmedSftpForTesting());
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

    [Fact]
    public void ReplayBuffer_CapturesDataReceivedFromSession()
    {
        var (vm, session) = CreateConnectedVm();

        session.RaiseData((byte)'h', (byte)'i', (byte)'\n');
        session.RaiseData((byte)'$', (byte)' ');

        Assert.Equal(
            new byte[] { (byte)'h', (byte)'i', (byte)'\n', (byte)'$', (byte)' ' },
            vm.PeekReplayBufferForTesting());
    }

    [Fact]
    public void ReplayBuffer_ClearsOnSessionSwap()
    {
        var (vm, first) = CreateConnectedVm();
        first.RaiseData((byte)'a', (byte)'b', (byte)'c');

        var second = new FakeSshSession();
        vm.AttachConnectedSessionForTesting(second);

        Assert.Empty(vm.PeekReplayBufferForTesting());

        second.RaiseData((byte)'x', (byte)'y');
        Assert.Equal(new byte[] { (byte)'x', (byte)'y' }, vm.PeekReplayBufferForTesting());
    }

    [Fact]
    public void ReplayBuffer_IgnoresLateDataFromPreviousSession()
    {
        var (vm, first) = CreateConnectedVm();
        var second = new FakeSshSession();
        vm.AttachConnectedSessionForTesting(second);

        first.RaiseData((byte)'$');

        Assert.Empty(vm.PeekReplayBufferForTesting());
    }

    [Fact]
    public void ReplayBuffer_PreservedAcrossDetachView()
    {
        // DetachView is the view-only teardown — preserving the buffer across the
        // detach window is the whole reason it exists.
        var (vm, session) = CreateConnectedVm();
        session.RaiseData((byte)'h', (byte)'i');

        vm.DetachView();

        Assert.Equal(new byte[] { (byte)'h', (byte)'i' }, vm.PeekReplayBufferForTesting());
    }

    [Fact]
    public async Task ReplayBuffer_ClearedOnDetachAsync()
    {
        // DetachAsync tears down the session; the next session must start clean.
        var (vm, session) = CreateConnectedVm();
        session.RaiseData((byte)'h', (byte)'i');

        await vm.DetachAsync();

        Assert.Empty(vm.PeekReplayBufferForTesting());
    }

    [Fact]
    public void RegisterAttachedWebView_FirstCall_ReportsFresh()
    {
        var vm = CreateViewModel();

        Assert.True(vm.RegisterAttachedWebView(new object()));
    }

    [Fact]
    public void RegisterAttachedWebView_SameInstance_ReportsNotFresh()
    {
        // Tab-switch case: same WebView2 reattaches; replay would duplicate the
        // already-rendered screen, so the decision is "not fresh, skip replay".
        var vm = CreateViewModel();
        var webView = new object();
        vm.RegisterAttachedWebView(webView);

        Assert.False(vm.RegisterAttachedWebView(webView));
    }

    [Fact]
    public void RegisterAttachedWebView_DifferentInstance_ReportsFresh()
    {
        // Sessions↔Settings nav case: new WebView2 with an empty xterm.js; replay
        // restores the prior screen, so the decision is "fresh, replay scrollback".
        var vm = CreateViewModel();
        vm.RegisterAttachedWebView(new object());

        Assert.True(vm.RegisterAttachedWebView(new object()));
    }

    [Fact]
    public async Task EnsureMcpApproved_Approved_IsMemoized_NoSecondDialog()
    {
        var vm = CreateViewModel();
        vm.Initialize(CreateProfile());
        var dialog = new FakeDialogService { ConfirmResult = true };

        Assert.True(await vm.EnsureMcpApprovedAsync(dialog));
        Assert.True(await vm.EnsureMcpApprovedAsync(dialog));

        // The decision is cached, so the user is only prompted once for the session's life.
        Assert.Equal(1, dialog.ConfirmCount);
    }

    [Fact]
    public async Task EnsureMcpApproved_Denied_IsStickyAndMemoized()
    {
        var vm = CreateViewModel();
        vm.Initialize(CreateProfile());
        var dialog = new FakeDialogService { ConfirmResult = false };

        Assert.False(await vm.EnsureMcpApprovedAsync(dialog));
        Assert.False(await vm.EnsureMcpApprovedAsync(dialog));

        // Denial is remembered without re-prompting.
        Assert.Equal(1, dialog.ConfirmCount);
    }

    private static (SshSessionViewModel Vm, FakeSshSession Session) CreateConnectedVm()
    {
        var vm = CreateViewModel();
        vm.Initialize(CreateProfile());
        var session = new FakeSshSession();
        vm.AttachConnectedSessionForTesting(session);
        return (vm, session);
    }

    private static SshSessionViewModel CreateViewModel(FakeSftpService? sftp = null)
    {
        var credService = new FakeCredentialService();
        var configs = new FakeTunnelConfigRepository();
        var tunnels = new TunnelManager(
            Array.Empty<ITunnelProvider>(),
            configs,
            credService,
            NullLoggerFactory.Instance.CreateLogger<TunnelManager>());
        return new SshSessionViewModel(
            new FakeSshSessionService(),
            new FakeCredentialResolver(),
            new FakeConnectionRepository(),
            new FakeAppSettingsService(),
            tunnels,
            sftp ?? new FakeSftpService(),
            NullLoggerFactory.Instance);
    }

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
            ITunnelInstance? tunnel = null,
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

        public Task<IReadOnlyList<(Guid Id, string Name)>> GetByTunnelConfigIdAsync(Guid tunnelConfigId, int limit, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<(Guid, string)>>(Array.Empty<(Guid, string)>());

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

    private sealed class FakeSftpService : ISftpService
    {
        public Func<ConnectionProfile, SshCredentials, ITunnelInstance?, CancellationToken, Task<ISftpSession>>? ConnectImpl { get; set; }
        public int ConnectCallCount;
        public SshCredentials? LastCredentials;

        public Task<ISftpSession> ConnectAsync(
            ConnectionProfile profile,
            SshCredentials credentials,
            ITunnelInstance? tunnel = null,
            CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref ConnectCallCount);
            LastCredentials = credentials;
            if (ConnectImpl is not null) return ConnectImpl(profile, credentials, tunnel, cancellationToken);
            return Task.FromResult<ISftpSession>(new FakeSftpSession());
        }
    }

    private static async Task WaitForAsync(Func<bool> condition, TimeSpan? timeout = null)
    {
        var deadline = DateTime.UtcNow + (timeout ?? TimeSpan.FromSeconds(5));
        while (DateTime.UtcNow < deadline)
        {
            if (condition()) return;
            await Task.Delay(20).ConfigureAwait(false);
        }
        throw new TimeoutException("Condition not satisfied within timeout.");
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
