using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Data;
using Wormhole.Data.Repositories;
using Wormhole.Models;
using Wormhole.Services;
using Wormhole.Services.Ssh;
using Wormhole.Services.Tunneling;
using Wormhole.Tests.Fakes;
using Wormhole.Tests.Services.Tunneling;
using Wormhole.ViewModels.Sessions;
using Xunit;

namespace Wormhole.Tests.ViewModels;

public sealed class SshSessionViewModelTests
{
    // Mirrors SshSessionViewModel.MaxAutoReconnectAttempts (private there). Used both as the loop
    // bound and to build the expected exhaustion message, so the two stay in lockstep.
    private const int MaxAutoReconnectAttemptsUnderTest = 3;

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
            CreateTunnelRoutePrompter(),
            NoopProfileResolver(),
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
            CreateTunnelRoutePrompter(),
            NoopProfileResolver(),
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

    // Default route prompter for tests that don't exercise the tunnel-routing prompt:
    // explicitly disable it so ResolveRouteAsync returns the profile unchanged.
    private static TunnelRoutePrompter CreateTunnelRoutePrompter()
    {
        var settings = new FakeAppSettingsService();
        settings.Current.PromptBeforeTunnelConnect = false;
        return new(
            settings,
            new Fakes.FakeDialogService(),
            new FakeTunnelConfigRepository(),
            NullLoggerFactory.Instance.CreateLogger<TunnelRoutePrompter>());
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

    // The SFTP on-demand fallback (FileTransferDialogService) establishes against
    // RoutedProfileForSubsession when there's no live tunnel to borrow, so a terminal that went
    // "direct" doesn't get a silently-tunneled file transfer. These pin that contract; the full
    // ConnectAsync routing path itself is WebView2-bound and covered via TunnelRoutePrompter +
    // the RDP integration tests.
    [Fact]
    public void RoutedProfileForSubsession_FallsBackToProfile_WhenNoRouteResolved()
    {
        var vm = CreateViewModel();
        vm.Initialize(CreateProfile());

        // No connect has resolved a route yet → SFTP sub-sessions see the saved profile.
        Assert.Same(vm.Profile, vm.RoutedProfileForSubsession);
    }

    [Fact]
    public void RoutedProfileForSubsession_ReflectsDirectRoute_ThenFallsBackWhenCleared()
    {
        var vm = CreateViewModel();
        vm.Initialize(CreateProfile() with { TunnelEnabled = true, TunnelConfigId = Guid.NewGuid() });

        // Simulate a connect where the user chose "connect directly": TunnelEnabled forced off.
        var direct = vm.Profile! with { TunnelEnabled = false };
        vm.PrimeRoutedProfileForTesting(direct);
        Assert.Same(direct, vm.RoutedProfileForSubsession);
        Assert.False(vm.RoutedProfileForSubsession!.TunnelEnabled);

        // Teardown clears the routed profile → fall back to the saved (tunnel-enabled) profile so a
        // later VPN-required transfer stays on the VPN rather than silently going direct.
        vm.PrimeRoutedProfileForTesting(null);
        Assert.Same(vm.Profile, vm.RoutedProfileForSubsession);
        Assert.True(vm.RoutedProfileForSubsession!.TunnelEnabled);
    }

    [Fact]
    public void CanOpenFileTransfer_IsFalse_ForRdpSession()
    {
        var vm = new RdpSessionViewModel(
            new NullRdpSessionService(),
            new Fakes.FakeCredentialService(),
            new NullCredentialRepository(),
            CreateTunnelManager(),
            CreateTunnelRoutePrompter(),
            NoopProfileResolver(),
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
    public async Task Prewarm_BorrowsSessionTunnel_AndDoesNotDisposeIt()
    {
        // Regression: prewarm must NOT establish a second tunnel (which, for an OTP-interactive VPN, would
        // pop a surprise second OTP prompt and burn the code). It borrows the shell's tunnel instead, and
        // disposing the borrow must leave the real tunnel — owned by the SSH session — alive.
        var sftp = new FakeSftpService();
        ITunnelInstance? handedToSftp = null;
        sftp.ConnectImpl = (_, _, tunnel, _) =>
        {
            handedToSftp = tunnel;
            return Task.FromResult<ISftpSession>(new FakeSftpSession());
        };
        var vm = CreateViewModel(sftp);
        vm.Initialize(CreateProfile());
        vm.PrimeCredentialsForTesting(new SshCredentials("pwd", null, null));

        var shellTunnel = new RecordingTunnel();
        vm.AttachConnectedSessionForTesting(new FakeSshSession(), shellTunnel);

        await WaitForAsync(() => vm.HasPrewarmedSftpForTesting());

        var borrowed = Assert.IsType<BorrowedTunnelInstance>(handedToSftp);
        await borrowed.DisposeAsync();
        Assert.Equal(0, shellTunnel.DisposeCount); // the borrow never tears down the session's tunnel
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
    public void RetryCommand_CanExecute_IsFalse_WhileConnectGateHeldAfterFailure()
    {
        var vm = CreateViewModel();
        vm.Initialize(CreateProfile());

        vm.Status = SessionStatus.Failed;
        vm.SetConnectInFlightForTesting(1);

        Assert.False(vm.RetryCommand.CanExecute(null));

        vm.SetConnectInFlightForTesting(0);
        Assert.True(vm.RetryCommand.CanExecute(null));
    }

    [Fact]
    public void MarkConnecting_FlipsDisconnectedToConnecting_WhenIdle()
    {
        // The back-to-back-open repro: a freshly-opened tab whose view was unloaded mid-init sits
        // in Disconnected behind the opaque black base cover. The view's re-init calls MarkConnecting
        // so the Connecting spinner shows during the deferred first connect instead of a dead screen.
        var vm = CreateViewModel();
        vm.Initialize(CreateProfile());
        Assert.Equal(SessionStatus.Disconnected, vm.Status);

        vm.MarkConnecting();

        Assert.Equal(SessionStatus.Connecting, vm.Status);
    }

    [Fact]
    public void MarkConnecting_NoOps_WhenSessionIsLive()
    {
        // Sessions↔Settings nav-back rebinds a still-Connected session through the same re-init
        // path; MarkConnecting must not slap a phantom Connecting spinner over a live terminal.
        var vm = CreateViewModel();
        vm.Initialize(CreateProfile());
        vm.AttachConnectedSessionForTesting(new FakeSshSession());

        vm.MarkConnecting();

        Assert.Equal(SessionStatus.Connected, vm.Status);
    }

    [Fact]
    public void MarkConnecting_NoOps_WhenFailed()
    {
        // A Failed tab shows the error + Retry overlay; MarkConnecting must leave it alone so the
        // user keeps their recovery affordance rather than seeing it replaced by a spinner.
        var vm = CreateViewModel();
        vm.Initialize(CreateProfile());
        vm.Status = SessionStatus.Failed;

        vm.MarkConnecting();

        Assert.Equal(SessionStatus.Failed, vm.Status);
    }

    [Theory]
    [InlineData(SessionStatus.Failed, true)]         // dropped/failed tab keeps its in-pane Retry overlay — no silent reconnect
    [InlineData(SessionStatus.Disconnected, false)]  // interrupted-connect tab must still recover (SSH has no Disconnected overlay)
    [InlineData(SessionStatus.Connecting, false)]    // a connect already in flight — let it proceed
    [InlineData(SessionStatus.Connected, false)]     // (defensive: a live tab reattaches before reaching this guard)
    public void ShouldDeferAutoConnectOnReattach_OnlyDefersWhenFailed(SessionStatus status, bool expected)
    {
        // The middle-click-close repro: closing the active tab redirects to a neighbour whose view
        // reloads and re-enters AttachAsync's connect tail. A neighbour that had quietly dropped in
        // the background is Failed — it must NOT silently reconnect (a tunnel-route prompt over a
        // blank pane); it keeps its in-pane Retry. Disconnected is deliberately NOT deferred: SSH
        // renders no Disconnected overlay, so deferring there would strand an interrupted-connect tab
        // in a blank black pane instead of letting it recover.
        var vm = CreateViewModel();
        vm.Initialize(CreateProfile());
        vm.Status = status;

        Assert.Equal(expected, vm.ShouldDeferAutoConnectOnReattach());
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
    public async Task RetryAsync_AfterInitFailure_MovesToConnecting_SoReattachReconnects()
    {
        // Regression guard for the AttachAsync reattach-defer change: a WebView2-init / "ready"-
        // handshake failure on a fresh tab leaves _webView null and Status=Failed, and recovery
        // routes back THROUGH AttachAsync (Retry → InitializationRetryRequested → re-init →
        // handshake → AttachAsync). RetryAsync must flip to Connecting so AttachAsync's
        // ShouldDeferAutoConnectOnReattach() (which defers a sessionless Failed tab) doesn't suppress
        // this user-requested retry and strand the tab on the Failed overlay with a dead Retry button.
        var vm = CreateViewModel();
        vm.Initialize(CreateProfile());
        vm.Status = SessionStatus.Failed; // init/handshake failure: _webView never assigned
        var raised = 0;
        vm.InitializationRetryRequested += () => raised++;

        await vm.RetryAsync();

        Assert.Equal(1, raised);                               // re-init fan-out still fires
        Assert.Equal(SessionStatus.Connecting, vm.Status);     // so the follow-up AttachAsync connects…
        Assert.False(vm.ShouldDeferAutoConnectOnReattach());   // …rather than deferring on Failed
    }

    [Fact]
    public async Task RetryAsync_ReResolvesProfileFromRepository_PicksUpTunnelDisabledAfterOpen()
    {
        // Repro for "retry still uses the earlier tunnel after editing it out": the tab cached the
        // profile resolved at open time, and ConnectAsync re-establishes the tunnel from it.
        var nodeId = Guid.NewGuid();
        var stale = CreateProfile() with
        {
            NodeId = nodeId,
            TunnelEnabled = true,
            TunnelConfigId = Guid.NewGuid(),
        };
        // The user has since edited the connection to drop the tunnel; the resolver reflects the DB.
        var edited = stale with { TunnelEnabled = false, TunnelConfigId = null };
        var resolver = new StubProfileResolver(edited);
        var vm = CreateViewModel(profileResolver: resolver);
        vm.Initialize(stale);

        // Detached view (background tab): RetryAsync refreshes the profile before stashing the
        // deferred reconnect intent, so the next AttachAsync→ConnectAsync establishes no tunnel.
        await vm.RetryAsync();

        Assert.Equal(nodeId, resolver.RequestedNodeId);
        Assert.False(vm.Profile!.TunnelEnabled);
        Assert.Null(vm.Profile.TunnelConfigId);
    }

    [Fact]
    public async Task RetryAsync_WhenSavedProtocolChanged_KeepsCachedProfile()
    {
        // The SSH tab's view is fixed to SSH; if the saved connection was switched to RDP while
        // the tab is open, the resolved RDP profile is unusable here, so it must be ignored.
        var stale = CreateProfile() with { Protocol = ProtocolType.Ssh };
        var nowRdp = stale with { Protocol = ProtocolType.Rdp, Host = "elsewhere" };
        var vm = CreateViewModel(profileResolver: new StubProfileResolver(nowRdp));
        vm.Initialize(stale);

        await vm.RetryAsync();

        Assert.Equal(ProtocolType.Ssh, vm.Profile!.Protocol);
        Assert.Equal(stale.Host, vm.Profile.Host);
    }

    [Fact]
    public async Task RetryAsync_PreservesSessionPinnedHostKey_WhenRefreshedProfileHasNone()
    {
        // A host key pinned this session must not be silently dropped on retry just because the
        // best-effort DB persist failed (so the re-resolved profile carries no fingerprint) —
        // otherwise the reconnect would TOFU-accept whatever the server now presents.
        var nodeId = Guid.NewGuid();
        var pinned = CreateProfile() with { NodeId = nodeId, SshKnownHostFingerprint = "SHA256:pinned" };
        // Resolver reflects a DB row with no pin, but the user also disabled the tunnel.
        var edited = pinned with { SshKnownHostFingerprint = null, TunnelEnabled = false };
        var vm = CreateViewModel(profileResolver: new StubProfileResolver(edited));
        vm.Initialize(pinned);

        await vm.RetryAsync();

        Assert.Equal("SHA256:pinned", vm.Profile!.SshKnownHostFingerprint);
        Assert.False(vm.Profile.TunnelEnabled);
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

    // === Auto-reconnect after an unexpected drop =========================
    // A dropped established session (host reboot, network blip — now detectable via the SSH
    // keep-alive) auto-reconnects up to 3× before surfacing the Failed overlay. The foreground retry
    // *loop* drives ConnectAsync (which needs a live WebView2 and so isn't unit-testable); these tests
    // cover the shared budget/decision logic via the detached path the test harness exercises (no
    // WebView → OnSessionClosed defers each attempt to the next AttachAsync, counting it the same way).

    [Fact]
    public void RemoteDrop_WithBudgetRemaining_AttemptsReconnectInsteadOfFailing()
    {
        var vm = CreateViewModel();
        vm.Initialize(CreateProfile());
        var session = new FakeSshSession();
        vm.AttachConnectedSessionForTesting(session);

        session.RaiseClosed();

        // Not Failed — the drop schedules a reconnect (deferred to the next attach, since the test
        // harness has no WebView) and shows the connecting overlay instead of the dead-end error.
        Assert.Equal(SessionStatus.Connecting, vm.Status);
        Assert.Equal(1, vm.AutoReconnectAttemptsForTesting);
        Assert.True(vm.ReconnectRequestedWhileDetachedForTesting);
        Assert.Equal(1, session.DisposeCount);
        Assert.Null(vm.ErrorMessage);
    }

    [Fact]
    public void RemoteDrop_ExhaustsBudget_SurfacesFailedAfterThreeAttempts()
    {
        var vm = CreateViewModel();
        vm.Initialize(CreateProfile());

        // Drops 1–3 each schedule a reconnect (Connecting); re-attach a session between them to
        // simulate a reconnect that came up and then dropped again before producing any output.
        for (var i = 1; i <= MaxAutoReconnectAttemptsUnderTest; i++)
        {
            var session = new FakeSshSession();
            vm.AttachConnectedSessionForTesting(session);
            session.RaiseClosed();
            Assert.Equal(SessionStatus.Connecting, vm.Status);
            Assert.Equal(i, vm.AutoReconnectAttemptsForTesting);
        }

        // The 4th drop finds the budget spent → Failed overlay with the Retry button.
        var last = new FakeSshSession();
        vm.AttachConnectedSessionForTesting(last);
        last.RaiseClosed();

        Assert.Equal(SessionStatus.Failed, vm.Status);
        Assert.Contains($"Reconnection failed after {MaxAutoReconnectAttemptsUnderTest} attempts", vm.ErrorMessage);
    }

    [Fact]
    public void RemoteDrop_UserDisconnectsDuringDisposal_DoesNotAutoReconnect()
    {
        // TOCTOU guard: SafeDisposeSessionAsync yields on the real socket close, and a user
        // Disconnect / tab close can land during that window. OnSessionClosed must re-check Status
        // after the await and NOT resurrect the session the user just dropped. We simulate the
        // interleaving by flipping Status to Disconnected from inside the session's DisposeAsync.
        var vm = CreateViewModel();
        vm.Initialize(CreateProfile());
        var session = new FakeSshSession();
        vm.AttachConnectedSessionForTesting(session);
        session.OnDisposing = () => vm.Status = SessionStatus.Disconnected;

        session.RaiseClosed();

        Assert.Equal(SessionStatus.Disconnected, vm.Status);        // user's teardown preserved
        Assert.Equal(0, vm.AutoReconnectAttemptsForTesting);        // no reconnect scheduled
        Assert.False(vm.ReconnectRequestedWhileDetachedForTesting);
    }

    [Fact]
    public void OutputAlone_DoesNotResetAutoReconnectBudget()
    {
        // Regression guard: a server that emits a banner/prompt then immediately closes the shell
        // (forced-command accounts, a crashing login script) must NOT have its budget reset by that
        // output — otherwise it would reset every cycle and auto-reconnect forever. Output is no longer
        // the health signal; sustained connection is (see StableConnection_ResetsAutoReconnectBudget).
        var vm = CreateViewModel();
        vm.Initialize(CreateProfile());
        var first = new FakeSshSession();
        vm.AttachConnectedSessionForTesting(first);
        first.RaiseClosed();
        Assert.Equal(1, vm.AutoReconnectAttemptsForTesting);

        var second = new FakeSshSession();
        vm.AttachConnectedSessionForTesting(second);
        second.RaiseData((byte)'$', (byte)' ');

        Assert.Equal(1, vm.AutoReconnectAttemptsForTesting); // output did NOT reset the budget
    }

    [Fact]
    public async Task StableConnection_ResetsAutoReconnectBudget()
    {
        // A reconnect that stays Connected past the stability window is healthy, so the budget clears
        // and a later, unrelated drop gets a fresh set of attempts.
        var vm = CreateViewModel();
        vm.Initialize(CreateProfile());
        vm.SetAutoReconnectStabilityWindowForTesting(TimeSpan.FromMilliseconds(50));
        var first = new FakeSshSession();
        vm.AttachConnectedSessionForTesting(first);
        first.RaiseClosed();
        Assert.Equal(1, vm.AutoReconnectAttemptsForTesting);

        // The reconnect comes up and stays up (we never close `second`) -> after the tiny window the
        // stability timer fires and clears the budget.
        var second = new FakeSshSession();
        vm.AttachConnectedSessionForTesting(second); // arms the stability timer (attempts > 0)

        await WaitForAsync(() => vm.AutoReconnectAttemptsForTesting == 0);
    }

    [Fact]
    public async Task UserDisconnect_CancelsPendingAutoReconnect()
    {
        var vm = CreateViewModel();
        vm.Initialize(CreateProfile());
        var session = new FakeSshSession();
        vm.AttachConnectedSessionForTesting(session);
        session.RaiseClosed();
        Assert.Equal(SessionStatus.Connecting, vm.Status); // auto-reconnect pending

        await vm.DisconnectAsync();

        // The explicit Disconnect wins: no lingering reconnect intent, budget cleared, ends Disconnected.
        Assert.Equal(SessionStatus.Disconnected, vm.Status);
        Assert.False(vm.ReconnectRequestedWhileDetachedForTesting);
        Assert.Equal(0, vm.AutoReconnectAttemptsForTesting);
    }

    [Fact]
    public async Task RemoteClose_AfterUserDisconnect_IsIgnored()
    {
        // Teardown already ran (user closed the tab / hit Disconnect), so _session is null and a
        // late Closed from the old read pump must be ignored rather than scheduling a reconnect or
        // raising a Failed overlay. Guards the ReferenceEquals + status check in OnSessionClosed.
        var vm = CreateViewModel();
        vm.Initialize(CreateProfile());
        var session = new FakeSshSession();
        vm.AttachConnectedSessionForTesting(session);

        await vm.DisconnectAsync();
        session.RaiseClosed();

        Assert.Equal(SessionStatus.Disconnected, vm.Status);
        Assert.Null(vm.ErrorMessage);
        Assert.Equal(0, vm.AutoReconnectAttemptsForTesting);
    }

    [Theory]
    [InlineData(SessionStatus.Failed, true, true)]        // transient failure (host still down) → keep retrying
    [InlineData(SessionStatus.Failed, false, false)]      // auth / host-key / notice → stop, leave Failed
    [InlineData(SessionStatus.Connected, true, false)]    // success → stop
    [InlineData(SessionStatus.Connected, false, false)]   // (retryable flag is irrelevant unless Failed)
    [InlineData(SessionStatus.Disconnected, true, false)] // cancelled mid-connect (user/nav-away) → stop
    [InlineData(SessionStatus.Disconnected, false, false)]// "
    [InlineData(SessionStatus.Connecting, true, false)]   // (defensive) not a terminal outcome → stop
    public void ShouldContinueAutoReconnect_OnlyOnTransientFailure(SessionStatus status, bool retryable, bool expected)
    {
        Assert.Equal(expected, SshSessionViewModel.ShouldContinueAutoReconnect(status, retryable));
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

    [Fact]
    public async Task RunCommandAsync_ReplayBufferShowsCleanCommandAndOutputWithoutMcpMarkers()
    {
        var (vm, session) = CreateConnectedVm();
        session.EchoShellCommandWrites = true;
        session.CommandOutput = "hello\r\n";

        var result = await vm.RunCommandAsync("echo hello", TimeSpan.FromSeconds(5), CancellationToken.None);

        Assert.Equal("hello", result.Output);
        Assert.Equal(0, result.ExitCode);

        var replay = Encoding.UTF8.GetString(vm.PeekReplayBufferForTesting());
        Assert.Equal("echo hello\r\nhello\r\n", replay);
        Assert.DoesNotContain("@@WHS", replay);
        Assert.DoesNotContain("@@WHE", replay);
        Assert.DoesNotContain("printf", replay);
    }

    private static (SshSessionViewModel Vm, FakeSshSession Session) CreateConnectedVm()
    {
        var vm = CreateViewModel();
        vm.Initialize(CreateProfile());
        var session = new FakeSshSession();
        vm.AttachConnectedSessionForTesting(session);
        return (vm, session);
    }

    private static SshSessionViewModel CreateViewModel(
        FakeSftpService? sftp = null,
        IConnectionProfileResolver? profileResolver = null,
        FakeAppSettingsService? settings = null,
        Fakes.FakeDialogService? dialog = null,
        FakeTunnelConfigRepository? configs = null)
    {
        var credService = new FakeCredentialService();
        configs ??= new FakeTunnelConfigRepository();
        var tunnels = new TunnelManager(
            Array.Empty<ITunnelProvider>(),
            configs,
            credService,
            NullLoggerFactory.Instance.CreateLogger<TunnelManager>());
        settings ??= new FakeAppSettingsService();
        dialog ??= new Fakes.FakeDialogService();
        var prompter = new TunnelRoutePrompter(
            settings,
            dialog,
            configs,
            NullLoggerFactory.Instance.CreateLogger<TunnelRoutePrompter>());
        return new SshSessionViewModel(
            new FakeSshSessionService(),
            new FakeCredentialResolver(),
            new FakeConnectionRepository(),
            settings,
            tunnels,
            prompter,
            profileResolver ?? NoopProfileResolver(),
            sftp ?? new FakeSftpService(),
            NullLoggerFactory.Instance);
    }

    // Default resolver for tests that don't exercise profile-refresh-on-retry: backed by an empty
    // repository, so ResolveAsync returns null and RetryAsync keeps the tab's cached profile —
    // i.e. behavior identical to before the refresh hook existed.
    private static ConnectionProfileResolver NoopProfileResolver() =>
        new(
            new FakeConnectionRepository(),
            new InheritanceResolver(),
            NullLoggerFactory.Instance.CreateLogger<ConnectionProfileResolver>());

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

    // Returns a fixed profile (or null) from ResolveAsync and records the node id requested, so a
    // test can assert RetryAsync re-resolved the right connection before reconnecting.
    private sealed class StubProfileResolver : IConnectionProfileResolver
    {
        private readonly ConnectionProfile? _result;
        public Guid? RequestedNodeId { get; private set; }
        public StubProfileResolver(ConnectionProfile? result) => _result = result;

        public Task<ConnectionProfile?> ResolveAsync(Guid nodeId, CancellationToken cancellationToken = default)
        {
            RequestedNodeId = nodeId;
            return Task.FromResult(_result);
        }
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
        private static readonly Regex TokenRegex = new("[0-9a-f]{16}", RegexOptions.Compiled);

        public string? HostFingerprint { get; init; } = "SHA256:test";

        public int DisposeCount { get; private set; }
        public bool EchoShellCommandWrites { get; set; }
        public string CommandOutput { get; set; } = string.Empty;
        public int CommandExitCode { get; set; }

        public event EventHandler<ReadOnlyMemory<byte>>? DataReceived;
        public event EventHandler? Closed;

        public void Start()
        {
        }

        public Task WriteAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
        {
            if (!EchoShellCommandWrites) return Task.CompletedTask;

            var payload = Encoding.UTF8.GetString(data.Span);
            var match = TokenRegex.Match(payload);
            if (!match.Success) return Task.CompletedTask;

            var token = match.Value;
            Emit(payload.Replace("\r", string.Empty) + "\r\n");
            Emit($"@@WHS_{token}@@\r\n");
            if (CommandOutput.Length > 0) Emit(CommandOutput);
            Emit($"@@WHE_{token}_{CommandExitCode}@@\r\n");
            return Task.CompletedTask;
        }

        public Task ResizeAsync(uint columns, uint rows) =>
            Task.CompletedTask;

        public int PauseReadingCount { get; private set; }
        public int ResumeReadingCount { get; private set; }

        public void PauseReading() => PauseReadingCount++;
        public void ResumeReading() => ResumeReadingCount++;

        public void RaiseData(params byte[] data) =>
            DataReceived?.Invoke(this, data);

        private void Emit(string text) =>
            DataReceived?.Invoke(this, Encoding.UTF8.GetBytes(text));

        public void RaiseClosed() =>
            Closed?.Invoke(this, EventArgs.Empty);

        // Runs synchronously inside DisposeAsync — lets a test simulate a concurrent teardown landing
        // during the VM's `await SafeDisposeSessionAsync()` window.
        public Action? OnDisposing { get; set; }

        public ValueTask DisposeAsync()
        {
            DisposeCount++;
            OnDisposing?.Invoke();
            return ValueTask.CompletedTask;
        }
    }
}
