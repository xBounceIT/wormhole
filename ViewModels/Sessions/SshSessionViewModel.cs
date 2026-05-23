using System.Windows.Input;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using Microsoft.Web.WebView2.Core;
using Renci.SshNet.Common;
using Wormhole.Data.Repositories;
using Wormhole.Interop.Terminal;
using Wormhole.Models;
using Wormhole.Services;
using Wormhole.Services.Ssh;
using Wormhole.Services.Tunneling;

namespace Wormhole.ViewModels.Sessions;

// CA1001 (owns IDisposable _bridge but isn't IDisposable) is suppressed deliberately:
// the VM is registered as transient in DI ([App.xaml.cs] AddTransient<SshSessionViewModel>),
// and Microsoft.Extensions.DependencyInjection captures every transient IDisposable in the
// root scope's _disposables list for the entire app lifetime — implementing IDisposable
// here would pin every closed-tab VM (~256 KiB replay buffer each) until process exit.
// The bridge / session / tunnel / CTS pair are torn down explicitly via DetachAsync /
// SafeDisposeSessionAsync / CancelRemoteOutputWaitTimer on the documented teardown path.
#pragma warning disable CA1001
public sealed partial class SshSessionViewModel : SessionTabViewModel
#pragma warning restore CA1001
{
    private static readonly TimeSpan RemoteOutputWaitDelay = TimeSpan.FromSeconds(2);

    private readonly ISshSessionService _sshService;
    private readonly ISshCredentialResolver _credentialResolver;
    private readonly IConnectionRepository _connectionRepo;
    private readonly IAppSettingsService _settingsService;
    private readonly TunnelManager _tunnels;
    private readonly ISftpService _sftpService;
    private readonly ILoggerFactory _loggerFactory;
    private readonly ILogger<SshSessionViewModel> _logger;

    private ISshSession? _session;
    private TerminalBridge? _bridge;
    private CancellationTokenSource? _cts;
    private CoreWebView2? _webView;
    // Survives DetachView so AttachAsync can tell a same-WebView reattach (tab
    // switch — xterm.js still rendering) from a fresh-WebView attach (Sessions ↔
    // Settings nav — new control). Used by ReferenceEquals only.
    private object? _lastAttachedWebView;
    // UI dispatcher lives on the SessionTabViewModel base class (captured via
    // EnsureDispatcher in AttachAsync) — there's no local field here on this branch.
    private string? _initialKnownFingerprint;
    private TerminalSize _initialSize = TerminalSize.Default;
    private CancellationTokenSource? _outputWaitCts;
    private int _connectInFlight;
    private ITunnelInstance? _tunnel;
    private bool _reconnectRequestedWhileDetached;

    // SFTP pre-warm: as soon as the shell session reaches Connected we open an SFTP
    // session in the background using the *same* creds the shell successfully used. The
    // file-transfer dialog hands off this cached session in TryConsumePrewarmedSftp,
    // turning the previously ~800 ms click into an instant open. SSH.NET 2025.1.0 has no
    // public API to share a transport between SshClient and SftpClient (see plan doc), so
    // this is a second SSH connection — paid in the background, invisible to the user.
    //
    // All mutable state is guarded by _prewarmLock. Disposal is fire-and-forget on the
    // status-leaves-Connected path; we don't await it during DetachAsync so the UI tear-
    // down isn't blocked on a remote socket close.
    private readonly object _prewarmLock = new();
    private SshCredentials? _capturedCredentials;
    private CancellationTokenSource? _prewarmCts;
    private ISftpSession? _prewarmedSftpSession;
    private ITunnelInstance? _prewarmedSftpTunnel;

    // The VM outlives the view: when SshTerminalView is unloaded and a fresh one is
    // created (Sessions ↔ Settings navigation), the new xterm.js has no scrollback,
    // and an idle prompt sends nothing new. AttachAsync's rebind path replays this
    // buffer so the user doesn't see a black void.
    private readonly TerminalReplayBuffer _replayBuffer = new(256 * 1024);

    public SshSessionViewModel(
        ISshSessionService sshService,
        ISshCredentialResolver credentialResolver,
        IConnectionRepository connectionRepo,
        IAppSettingsService settingsService,
        TunnelManager tunnels,
        ISftpService sftpService,
        ILoggerFactory loggerFactory)
    {
        _sshService = sshService;
        _credentialResolver = credentialResolver;
        _connectionRepo = connectionRepo;
        _settingsService = settingsService;
        _tunnels = tunnels;
        _sftpService = sftpService;
        _loggerFactory = loggerFactory;
        _logger = loggerFactory.CreateLogger<SshSessionViewModel>();
        PropertyChanged += (_, args) =>
        {
            if (args.PropertyName == nameof(Status))
            {
                OnPropertyChanged(nameof(IsConnecting));
                OnPropertyChanged(nameof(IsConnected));
                OnPropertyChanged(nameof(IsFailed));
                OnPropertyChanged(nameof(CanOpenFileTransfer));
                RetryCommand.NotifyCanExecuteChanged();
                HandlePrewarmStatusTransition();
            }
        };
    }

    public override ProtocolType Protocol => ProtocolType.Ssh;

    public override ICommand? ReconnectCommand => RetryCommand;

    // Gating for the "File transfer" tab context menu entry. The SFTP service opens a
    // fresh SSH/SFTP channel separate from this VM's shell session, but it reuses the
    // same credentials and host-key pin — only meaningful once we've successfully
    // authenticated, so the entry stays hidden until Status flips to Connected.
    public override bool CanOpenFileTransfer => Status == SessionStatus.Connected;

    [ObservableProperty]
    private string? errorMessage;

    [ObservableProperty]
    private bool hasReceivedOutput;

    [ObservableProperty]
    private bool isWaitingForRemoteOutput;

    public bool IsConnecting => Status == SessionStatus.Connecting;
    public bool IsConnected => Status == SessionStatus.Connected;
    public bool IsFailed => Status == SessionStatus.Failed;

    /// <summary>
    /// Surfaces dropped UI updates (dispatcher rejected the work). The most common case is
    /// OnSessionDataReceived's MarkOutputReceived enqueue — without this log a closed/shutting-
    /// down dispatcher would silently swallow the state transition.
    /// </summary>
    protected override void OnDispatchEnqueueFailed()
    {
        _logger.LogWarning("Failed to enqueue SSH UI update — dispatcher queue may be shutting down.");
    }

    public override void Initialize(ConnectionProfile profile)
    {
        base.Initialize(profile);
        _initialKnownFingerprint = profile.SshKnownHostFingerprint;
    }

    public async Task AttachAsync(CoreWebView2 webView, TerminalSize initialSize)
    {
        if (Profile is null)
            throw new InvalidOperationException("Initialize must be called before AttachAsync.");

        // A fresh WebView2 (new control after Sessions↔Settings nav) means xterm.js
        // was just navigated to terminal.html and has an empty screen. A same-WebView
        // reattach (tab switch) means xterm.js is still rendering the prior session;
        // replaying onto it would duplicate every byte the user already sees.
        var xtermIsFresh = RegisterAttachedWebView(webView);
        _webView = webView;
        _initialSize = initialSize;
        // AttachAsync is called from the UI thread (SshTerminalView's ready handler);
        // capture the dispatcher now so background callbacks (Closed) can marshal back.
        EnsureDispatcher();

        // Reconnect was requested from the tab context menu while the view was unloaded
        // (background tab) — RetryAsync couldn't fan out to the now-unsubscribed init
        // event, so it stashed the intent here. Honor it before the "session alive →
        // just rebind bridge" path below.
        if (_reconnectRequestedWhileDetached)
        {
            _reconnectRequestedWhileDetached = false;
            await DetachAsync().ConfigureAwait(true);
            await ConnectAsync().ConfigureAwait(true);
            return;
        }

        // VM survives view rebuilds while the SSH pump keeps running. Skip credential
        // prompt + connect — rebind the bridge to the (possibly new) WebView and
        // resync geometry. Replay only when xterm.js is fresh; same-WebView reattach
        // already shows the prior render.
        if (_session is not null)
        {
            // Snapshot BEFORE subscribing the new bridge: a byte that lands on the SSH
            // read pump after the new bridge subscribes would otherwise be rendered
            // live AND included in the snapshot, duplicating on replay (e.g. tail -f
            // mid-reattach). The reverse race — bytes between snapshot and subscribe —
            // stays in the ring buffer and surfaces on the next reattach; a far less
            // visible cosmetic issue than the duplicated stream.
            var snapshot = xtermIsFresh ? _replayBuffer.Snapshot() : null;
            var oldBridge = _bridge;
            _bridge = new TerminalBridge(webView, _session, _loggerFactory.CreateLogger<TerminalBridge>(), _settingsService);
            oldBridge?.Dispose();
            if (snapshot is not null) _bridge.Replay(snapshot);
            await _session.ResizeAsync(initialSize.Columns, initialSize.Rows).ConfigureAwait(true);
            _bridge.RequestFocus();
            EnsureRemoteOutputWaitTimer();
            return;
        }

        await ConnectAsync().ConfigureAwait(true);
    }

    /// <summary>
    /// Raised when <see cref="RetryAsync"/> is invoked but the view's WebView2 never
    /// finished initializing. The view subscribes and re-runs its init path so the
    /// Retry button isn't dead in WebView2-failure scenarios.
    /// </summary>
    public event Action? InitializationRetryRequested;

    [RelayCommand(AllowConcurrentExecutions = false, CanExecute = nameof(CanRetry))]
    public async Task RetryAsync()
    {
        ErrorMessage = null;
        ResetOutputState();
        if (_webView is null)
        {
            // A null handler means the view is unloaded (background tab): OnUnloaded
            // already detached it, so firing the event would no-op. Stash the intent
            // for the next AttachAsync. A non-null handler means the view is loaded
            // but WebView2 init failed — preserve the existing "retry init" fan-out.
            var handler = InitializationRetryRequested;
            if (handler is not null) handler();
            else _reconnectRequestedWhileDetached = true;
            return;
        }
        await DetachAsync().ConfigureAwait(true);
        ErrorMessage = null;
        await ConnectAsync().ConfigureAwait(true);
    }

    // While Connecting, an in-flight ConnectAsync still holds _connectInFlight; a second one from RetryAsync would silently no-op.
    private bool CanRetry() => Status != SessionStatus.Connecting;

    [RelayCommand]
    public Task DisconnectAsync() => DetachAsync();

    public override async ValueTask CloseAsync()
    {
        await DetachAsync().ConfigureAwait(true);
    }

    public async Task DetachAsync()
    {
        // Signal cancel to any in-flight ConnectAsync; do NOT Dispose() — the awaiter still
        // holds the token. The CTS is GC-eligible once both sides drop their references.
        var cts = _cts;
        _cts = null;
        try { cts?.Cancel(); } catch { /* already disposed */ }

        await SafeDisposeSessionAsync().ConfigureAwait(true);
        Status = SessionStatus.Disconnected;
    }

    public void ReportFailure(string message)
    {
        CancelRemoteOutputWaitTimer();
        IsWaitingForRemoteOutput = false;
        ErrorMessage = message;
        Status = SessionStatus.Failed;
    }

    /// <summary>
    /// Called by the view on Unloaded — releases the WebView2 binding without tearing
    /// down the SSH session. Background SSH output still arrives on the read pump but
    /// the bridge is gone, so it isn't routed to a disposed WebView2 (no more
    /// repeated InvalidOperationException spam). The next AttachAsync rebinds.
    /// </summary>
    public void DetachView()
    {
        var bridge = _bridge;
        _bridge = null;
        if (bridge is not null)
        {
            try { bridge.Dispose(); }
            catch (Exception ex) { _logger.LogWarning(ex, "Error disposing TerminalBridge on view unload."); }
        }
        _webView = null;
    }

    internal void AttachConnectedSessionForTesting(ISshSession session)
    {
        ResetOutputState();
        _replayBuffer.Clear();
        if (_session is not null)
        {
            _session.DataReceived -= OnSessionDataReceived;
            _session.Closed -= OnSessionClosed;
        }

        _session = session;
        _session.DataReceived += OnSessionDataReceived;
        _session.Closed += OnSessionClosed;
        Status = SessionStatus.Connected;
        StartRemoteOutputWaitTimer();
    }

    private void OnSessionClosed(object? sender, EventArgs e)
    {
        // Fired from the SSH read-pump thread; marshal to the UI dispatcher before
        // touching observable properties or disposing the session.
        var closedSession = sender as ISshSession;
        MarshalToUi(async () =>
        {
            // _session being null means we've already disposed (consumer-initiated
            // tear-down ran first). Failed/Disconnected from a prior path also means
            // we're already in the right terminal state. Otherwise: tear down the
            // dead transport and surface the failure overlay. Status==Connecting can
            // happen if the server immediately closes the shell after auth (e.g.
            // forced-command accounts).
            if (!ReferenceEquals(closedSession, _session)) return;
            if (Status == SessionStatus.Failed || Status == SessionStatus.Disconnected) return;
            await SafeDisposeSessionAsync().ConfigureAwait(true);
            // Use Failed (not Disconnected) so the in-tab failure overlay with the
            // Retry button becomes visible — otherwise users have no recovery path
            // after a transient network drop without closing the tab.
            ReportFailure("Remote session closed.");
        });
    }

    private async Task ConnectAsync()
    {
        var profile = Profile;
        if (profile is null || _webView is null) return;
        if (Interlocked.CompareExchange(ref _connectInFlight, 1, 0) != 0) return;

        Status = SessionStatus.Connecting;
        ErrorMessage = null;
        ResetOutputState();
        var cts = new CancellationTokenSource();
        _cts = cts;
        var token = cts.Token;

        try
        {
            var creds = await _credentialResolver.ResolveAsync(profile, token).ConfigureAwait(true);
            if (!creds.HasAny)
            {
                ReportFailure("No credentials provided.");
                return;
            }
            // Cache the successfully-resolved credentials so the SFTP pre-warm (kicked off
            // when Status flips to Connected below) and the on-demand file-transfer path
            // can both skip a re-resolve — which would otherwise re-prompt for a key
            // passphrase or password and break the "instant click" UX.
            _capturedCredentials = creds;

            _tunnel = await _tunnels.EstablishAsync(profile, token).ConfigureAwait(true);
            _session = await _sshService.ConnectAsync(profile, creds, _initialSize, _tunnel, token).ConfigureAwait(true);
            // Re-read _webView after the awaits: if the user navigated away and back
            // during credential prompt / SSH connect, AttachAsync swapped _webView to the
            // freshly-created control but bailed on _connectInFlight, so the original
            // local would bind the bridge to a stale/disposed WebView.
            var liveWebView = _webView;
            if (liveWebView is null)
            {
                await SafeDisposeSessionAsync().ConfigureAwait(true);
                Status = SessionStatus.Disconnected;
                return;
            }
            // Subscribe BEFORE Start() so we don't miss a Closed that fires immediately
            // (forced-command accounts, EOF-on-connect, etc.).
            _session.DataReceived += OnSessionDataReceived;
            _session.Closed += OnSessionClosed;
            _bridge = new TerminalBridge(liveWebView, _session, _loggerFactory.CreateLogger<TerminalBridge>(), _settingsService);
            _session.Start();

            // Mirror SshHostKeyValidator.Decide which treats null *and* empty as unpinned —
            // otherwise a profile with SshKnownHostFingerprint == "" (e.g. from imported
            // data) would never pin and continue to TOFU-accept on every reconnect.
            if (string.IsNullOrEmpty(_initialKnownFingerprint) && !string.IsNullOrEmpty(_session.HostFingerprint))
            {
                // Pin the captured fingerprint on the in-memory profile *before* any retry so a
                // disconnect/reconnect inside this tab actually validates against it instead of
                // TOFU-accepting whatever the server presents.
                profile = profile with { SshKnownHostFingerprint = _session.HostFingerprint };
                Profile = profile;
                _initialKnownFingerprint = _session.HostFingerprint;
                try
                {
                    await _connectionRepo.UpdateHostFingerprintAsync(profile.NodeId, _session.HostFingerprint, token).ConfigureAwait(true);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Could not persist host fingerprint for {Host}.", profile.Host);
                }
            }

            // Guard against an immediate remote close (forced-command / EOF) that
            // already ran OnSessionClosed while we were awaiting fingerprint
            // persistence — that handler will have set Status to Failed. Don't flip
            // it back to Connected and lie about a dead tab being active.
            if (_session is not null && Status == SessionStatus.Connecting)
            {
                Status = SessionStatus.Connected;
                _bridge?.RequestFocus();
                StartRemoteOutputWaitTimer();
            }
        }
        catch (OperationCanceledException)
        {
            await SafeDisposeSessionAsync().ConfigureAwait(true);
            Status = SessionStatus.Disconnected;
        }
        catch (SshHostKeyMismatchException ex)
        {
            await SafeDisposeSessionAsync().ConfigureAwait(true);
            ReportFailure(ex.Message);
            _logger.LogWarning("Host key mismatch for {Host}.", profile.Host);
        }
        catch (SshAuthenticationException ex)
        {
            await SafeDisposeSessionAsync().ConfigureAwait(true);
            ReportFailure("Authentication failed: " + ex.Message);
        }
        catch (Exception ex)
        {
            await SafeDisposeSessionAsync().ConfigureAwait(true);
            ReportFailure(ex.Message);
            _logger.LogError(ex, "SSH connect failed for {Host}.", profile.Host);
        }
        finally
        {
            Interlocked.Exchange(ref _connectInFlight, 0);
        }
    }

    private void OnSessionDataReceived(object? sender, ReadOnlyMemory<byte> data)
    {
        if (data.Length == 0) return;
        var sourceSession = sender as ISshSession;
        // Drop callbacks from a session we've already swapped out. The read of _session
        // is unbarriered on the SSH pump thread, so a stale-true result can still slip
        // through; the Append lands in a buffer about to be cleared by teardown, and
        // MarkOutputReceived re-checks identity under the UI dispatcher.
        if (!ReferenceEquals(sourceSession, _session)) return;

        _replayBuffer.Append(data.Span);

        if (HasReceivedOutput) return;

        // MarshalToUi (base class) handles dispatcher null and enqueue-failure logging.
        MarshalToUi(() => MarkOutputReceived(sourceSession));
    }

    private void MarkOutputReceived(ISshSession? sourceSession)
    {
        if (!ReferenceEquals(sourceSession, _session)) return;
        if (HasReceivedOutput) return;
        CancelRemoteOutputWaitTimer();
        HasReceivedOutput = true;
        IsWaitingForRemoteOutput = false;
    }

    private void ResetOutputState()
    {
        CancelRemoteOutputWaitTimer();
        HasReceivedOutput = false;
        IsWaitingForRemoteOutput = false;
    }

    private void EnsureRemoteOutputWaitTimer()
    {
        if (Status != SessionStatus.Connected) return;
        if (HasReceivedOutput || IsWaitingForRemoteOutput || _outputWaitCts is not null) return;
        StartRemoteOutputWaitTimer();
    }

    private void StartRemoteOutputWaitTimer()
    {
        CancelRemoteOutputWaitTimer();
        if (Status != SessionStatus.Connected || HasReceivedOutput) return;

        IsWaitingForRemoteOutput = false;
        var cts = new CancellationTokenSource();
        _outputWaitCts = cts;
        _ = WaitForRemoteOutputAsync(cts.Token);
    }

    private async Task WaitForRemoteOutputAsync(CancellationToken cancellationToken)
    {
        try
        {
            await Task.Delay(RemoteOutputWaitDelay, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return;
        }

        MarshalToUi(() =>
        {
            if (cancellationToken.IsCancellationRequested) return;
            if (Status != SessionStatus.Connected || HasReceivedOutput) return;
            _outputWaitCts = null;
            IsWaitingForRemoteOutput = true;
        });
    }

    private void CancelRemoteOutputWaitTimer()
    {
        var cts = _outputWaitCts;
        _outputWaitCts = null;
        if (cts is null) return;
        try { cts.Cancel(); }
        catch (ObjectDisposedException) { /* already disposed */ }
    }

    private async Task SafeDisposeSessionAsync()
    {
        CancelRemoteOutputWaitTimer();
        IsWaitingForRemoteOutput = false;

        var bridge = _bridge;
        _bridge = null;
        if (bridge is not null)
        {
            try { bridge.Dispose(); }
            catch (Exception ex) { _logger.LogWarning(ex, "Error disposing TerminalBridge."); }
        }

        var session = _session;
        _session = null;
        if (session is not null)
        {
            session.DataReceived -= OnSessionDataReceived;
            session.Closed -= OnSessionClosed;
            try { await session.DisposeAsync().ConfigureAwait(true); }
            catch (Exception ex) { _logger.LogWarning(ex, "Error disposing SSH session."); }
        }

        var tunnel = _tunnel;
        _tunnel = null;
        if (tunnel is not null)
        {
            try { await tunnel.DisposeAsync().ConfigureAwait(true); }
            catch (Exception ex) { _logger.LogWarning(ex, "Error tearing down session tunnel."); }
        }

        // DetachView (view-only teardown) deliberately keeps the buffer — replaying
        // across the detach window is the whole point. Session teardown clears it so
        // a same-VM reconnect doesn't bleed the old session's output into the new one.
        _replayBuffer.Clear();

        // Drop the cached creds: a future reconnect will re-resolve via ConnectAsync so
        // a rotated password / removed key / revoked credential doesn't get silently
        // reused by a prewarm kicked off after the next Connected transition.
        _capturedCredentials = null;
    }

    // === SFTP pre-warm =====================================================
    //
    // Called from the Status PropertyChanged handler. Status==Connected starts a
    // background prewarm; any other Status cancels in-flight prewarm and disposes any
    // cached pair. Idempotent: repeat calls in the same Status are no-ops.
    private void HandlePrewarmStatusTransition()
    {
        if (Status == SessionStatus.Connected)
        {
            StartPrewarm();
        }
        else
        {
            CancelAndDisposePrewarm();
        }
    }

    private void StartPrewarm()
    {
        var profile = Profile;
        var creds = _capturedCredentials;
        // No captured creds means we reached Connected via a code path that didn't run
        // ConnectAsync (test harness AttachConnectedSessionForTesting). Silent no-op —
        // tests that want to exercise prewarm prime creds via the testing helper.
        if (profile is null || creds is null) return;

        CancellationTokenSource cts;
        lock (_prewarmLock)
        {
            if (_prewarmCts is not null) return;             // already in-flight
            if (_prewarmedSftpSession is not null) return;   // cache already warm
            cts = new CancellationTokenSource();
            _prewarmCts = cts;
        }

        // Fire-and-forget. PrewarmAsync owns its own error handling — failure logs a
        // Warning and leaves the cache empty so the next click falls back to the
        // on-demand path with no observable change to the user. Capture profile + creds
        // by value so a later disconnect's clear of _capturedCredentials doesn't race.
        // Pass `cts` (not its Token, which is a struct) so the worker can detect a
        // CancelAndDisposePrewarm-driven swap via reference identity on the CTS itself.
        _ = PrewarmAsync(profile, creds, cts);
    }

    private async Task PrewarmAsync(ConnectionProfile profile, SshCredentials creds, CancellationTokenSource cts)
    {
        var ct = cts.Token;
        ITunnelInstance? tunnel = null;
        ISftpSession? session = null;
        try
        {
            tunnel = await _tunnels.EstablishAsync(profile, ct).ConfigureAwait(false);
            session = await _sftpService.ConnectAsync(profile, creds, tunnel, ct).ConfigureAwait(false);

            bool stash;
            lock (_prewarmLock)
            {
                // Lost the race to a disconnect / re-warm cancellation: another path
                // cleared _prewarmCts under the lock or swapped in a different CTS. Don't
                // stash — the caller is in the middle of tear-down and we'd leak this
                // session. Compare CTS references (CancellationToken is a struct, so
                // identity comparisons on tokens are unreliable due to boxing).
                stash = !ct.IsCancellationRequested && ReferenceEquals(_prewarmCts, cts);
                if (stash)
                {
                    _prewarmedSftpSession = session;
                    _prewarmedSftpTunnel = tunnel;
                    // Successful prewarm clears the in-flight slot so a subsequent
                    // TryConsumePrewarmedSftp can start a fresh prewarm without waiting.
                    _prewarmCts = null;
                }
            }

            if (!stash)
            {
                await DisposePairAsync(session, tunnel).ConfigureAwait(false);
                cts.Dispose();
                return;
            }

            cts.Dispose();
            _logger.LogDebug("SFTP prewarm ready for {Host}.", profile.Host);
        }
        catch (OperationCanceledException)
        {
            await DisposePairAsync(session, tunnel).ConfigureAwait(false);
            ClearOwnCtsIfCurrent(cts);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "SFTP prewarm failed for {Host}; on-demand path will be used.", profile.Host);
            await DisposePairAsync(session, tunnel).ConfigureAwait(false);
            ClearOwnCtsIfCurrent(cts);
        }
    }

    private void ClearOwnCtsIfCurrent(CancellationTokenSource cts)
    {
        bool owned;
        lock (_prewarmLock)
        {
            owned = ReferenceEquals(_prewarmCts, cts);
            if (owned) _prewarmCts = null;
        }
        // Dispose outside the lock to keep critical sections minimal. The CTS hasn't been
        // disposed if the cancel-path was reached via our own .Cancel() in CancelAndDisposePrewarm
        // (that path already disposes it and nulls the field, so `owned` is false here).
        if (owned) cts.Dispose();
    }

    /// <summary>
    /// Returns the credentials successfully used by the live shell connection, so the
    /// on-demand file-transfer fallback can reuse them instead of re-resolving (which
    /// would re-prompt for a key passphrase the user already entered). Null when the
    /// shell is not currently connected.
    /// </summary>
    internal SshCredentials? GetCapturedCredentialsForSftp() => _capturedCredentials;

    /// <summary>
    /// Atomically transfers ownership of any cached SFTP pre-warm pair to the caller and
    /// schedules a fresh prewarm so a subsequent file-transfer open is also instant.
    /// Returns <c>null</c> when no prewarm has succeeded yet (still in flight or failed),
    /// in which case the caller must fall back to its on-demand connect path.
    /// </summary>
    internal (ISftpSession Session, ITunnelInstance? Tunnel)? TryConsumePrewarmedSftp()
    {
        ISftpSession? session;
        ITunnelInstance? tunnel;
        lock (_prewarmLock)
        {
            session = _prewarmedSftpSession;
            tunnel = _prewarmedSftpTunnel;
            _prewarmedSftpSession = null;
            _prewarmedSftpTunnel = null;
        }
        if (session is null) return null;

        // Liveness gate: a session can be stashed for hours; idle TCP eviction or sshd
        // ClientAliveCountMax-exceed can leave it disconnected without us ever observing
        // it (no read pump on the SFTP side). Hand back null + dispose the corpse, so
        // the caller falls back to the on-demand path and opens a fresh session rather
        // than crashing on its first ListDirectoryAsync.
        if (!session.IsConnected)
        {
            _logger.LogDebug("Discarding stale prewarmed SFTP session for {Host}; will reconnect on demand.", Profile?.Host);
            _ = DisposePairAsync(session, tunnel);
            if (Status == SessionStatus.Connected) StartPrewarm();
            return null;
        }

        // Re-warm only while the shell is still Connected — pulling a session out at the
        // same moment a disconnect lands would otherwise spawn a doomed prewarm against
        // an about-to-be-cleared profile.
        if (Status == SessionStatus.Connected) StartPrewarm();
        return (session, tunnel);
    }

    private void CancelAndDisposePrewarm()
    {
        CancellationTokenSource? cts;
        ISftpSession? session;
        ITunnelInstance? tunnel;
        lock (_prewarmLock)
        {
            cts = _prewarmCts;
            _prewarmCts = null;
            session = _prewarmedSftpSession;
            tunnel = _prewarmedSftpTunnel;
            _prewarmedSftpSession = null;
            _prewarmedSftpTunnel = null;
        }
        if (cts is not null)
        {
            try { cts.Cancel(); } catch (ObjectDisposedException) { /* raced */ }
            cts.Dispose();
        }
        // Fire-and-forget: UI teardown must not block on a remote-socket close.
        _ = DisposePairAsync(session, tunnel);
    }

    private async Task DisposePairAsync(ISftpSession? session, ITunnelInstance? tunnel)
    {
        if (session is not null)
        {
            try { await session.DisposeAsync().ConfigureAwait(false); }
            catch (Exception ex) { _logger.LogWarning(ex, "Error disposing prewarmed SFTP session."); }
        }
        if (tunnel is not null)
        {
            try { await tunnel.DisposeAsync().ConfigureAwait(false); }
            catch (Exception ex) { _logger.LogWarning(ex, "Error disposing prewarmed SFTP tunnel."); }
        }
    }

    /// <summary>
    /// Test hook — primes <c>_capturedCredentials</c> so a subsequent
    /// <see cref="AttachConnectedSessionForTesting"/> triggers the prewarm code path
    /// without going through the real <c>ConnectAsync</c> flow.
    /// </summary>
    internal void PrimeCredentialsForTesting(SshCredentials credentials)
    {
        _capturedCredentials = credentials;
    }

    internal bool HasPrewarmedSftpForTesting()
    {
        lock (_prewarmLock) return _prewarmedSftpSession is not null;
    }

    internal bool HasInFlightPrewarmForTesting()
    {
        lock (_prewarmLock) return _prewarmCts is not null;
    }

    internal byte[] PeekReplayBufferForTesting() => _replayBuffer.Snapshot();

    // Records the just-attached WebView2 (or any object identity in tests) and
    // returns whether it differs from the previous attach — used by AttachAsync
    // to decide whether to replay scrollback.
    internal bool RegisterAttachedWebView(object webView)
    {
        var isFresh = !ReferenceEquals(webView, _lastAttachedWebView);
        _lastAttachedWebView = webView;
        return isFresh;
    }
}
