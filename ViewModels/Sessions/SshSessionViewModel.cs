using System;
using System.Threading;
using System.Threading.Tasks;
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

namespace Wormhole.ViewModels.Sessions;

public sealed partial class SshSessionViewModel : SessionTabViewModel
{
    private static readonly TimeSpan RemoteOutputWaitDelay = TimeSpan.FromSeconds(2);

    private readonly ISshSessionService _sshService;
    private readonly ISshCredentialResolver _credentialResolver;
    private readonly IConnectionRepository _connectionRepo;
    private readonly IAppSettingsService _settingsService;
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
    private Microsoft.UI.Dispatching.DispatcherQueue? _uiDispatcher;
    private string? _initialKnownFingerprint;
    private TerminalSize _initialSize = TerminalSize.Default;
    private CancellationTokenSource? _outputWaitCts;
    private int _connectInFlight;
    private bool _reconnectRequestedWhileDetached;

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
        ILoggerFactory loggerFactory)
    {
        _sshService = sshService;
        _credentialResolver = credentialResolver;
        _connectionRepo = connectionRepo;
        _settingsService = settingsService;
        _loggerFactory = loggerFactory;
        _logger = loggerFactory.CreateLogger<SshSessionViewModel>();
        PropertyChanged += (_, args) =>
        {
            if (args.PropertyName == nameof(Status))
            {
                OnPropertyChanged(nameof(IsConnecting));
                OnPropertyChanged(nameof(IsConnected));
                OnPropertyChanged(nameof(IsFailed));
                RetryCommand.NotifyCanExecuteChanged();
            }
        };
    }

    public override ProtocolType Protocol => ProtocolType.Ssh;

    public override ICommand? ReconnectCommand => RetryCommand;

    [ObservableProperty]
    private string? errorMessage;

    [ObservableProperty]
    private bool hasReceivedOutput;

    [ObservableProperty]
    private bool isWaitingForRemoteOutput;

    public bool IsConnecting => Status == SessionStatus.Connecting;
    public bool IsConnected => Status == SessionStatus.Connected;
    public bool IsFailed => Status == SessionStatus.Failed;

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
        _uiDispatcher ??= Microsoft.UI.Dispatching.DispatcherQueue.GetForCurrentThread();

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
        // Fired from the SSH read-pump thread; marshal to the captured UI dispatcher
        // before touching observable properties or disposing the session.
        var dispatcher = _uiDispatcher;
        if (dispatcher is null) return;
        var closedSession = sender as ISshSession;
        dispatcher.TryEnqueue(async () =>
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

            _session = await _sshService.ConnectAsync(profile, creds, _initialSize, token).ConfigureAwait(true);
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

        var dispatcher = _uiDispatcher;
        if (dispatcher is null)
        {
            MarkOutputReceived(sourceSession);
            return;
        }

        if (!dispatcher.TryEnqueue(() => MarkOutputReceived(sourceSession)))
        {
            _logger.LogWarning("Failed to enqueue SSH output state update.");
        }
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

        void ShowWaiting()
        {
            if (cancellationToken.IsCancellationRequested) return;
            if (Status != SessionStatus.Connected || HasReceivedOutput) return;
            _outputWaitCts = null;
            IsWaitingForRemoteOutput = true;
        }

        var dispatcher = _uiDispatcher;
        if (dispatcher is null)
        {
            ShowWaiting();
        }
        else if (!dispatcher.TryEnqueue(ShowWaiting))
        {
            _outputWaitCts = null;
            _logger.LogWarning("Failed to enqueue SSH no-output state update.");
        }
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

        // DetachView (view-only teardown) deliberately keeps the buffer — replaying
        // across the detach window is the whole point. Session teardown clears it so
        // a same-VM reconnect doesn't bleed the old session's output into the new one.
        _replayBuffer.Clear();
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
