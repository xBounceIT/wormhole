using System.Windows.Input;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using Microsoft.Web.WebView2.Core;
using Renci.SshNet.Common;
using Wormhole.Data.Repositories;
using Wormhole.Helpers;
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
// here would pin every closed-tab VM and up to ~2 MiB of lazily allocated replay storage
// after terminal use until process exit.
// The bridge / session / tunnel / CTS pair are torn down explicitly via DetachAsync /
// SafeDisposeSessionAsync / CancelRemoteOutputWaitTimer on the documented teardown path.
#pragma warning disable CA1001
public sealed partial class SshSessionViewModel : SessionTabViewModel, ITerminalSessionViewModel
#pragma warning restore CA1001
{
    private static readonly TimeSpan RemoteOutputWaitDelay = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan RemoteCloseOutputFlushTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan TerminalBridgeRetirementTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan AuthenticationFailureEndpointProbeTimeout = TimeSpan.FromSeconds(2);

    // Wait between automatic reconnect attempts after an unexpected drop. Fixed (not escalating) so a
    // brief blip recovers quickly; a host reboot typically returns within a couple of these.
    private static readonly TimeSpan AutoReconnectDelay = TimeSpan.FromSeconds(10);
    private const int MaxAutoReconnectAttempts = 3;
    internal const int TerminalReplayCapacityBytes = 1024 * 1024;
    // A reconnect earns its retry budget back only by staying Connected this long. Resetting the
    // budget on first output instead would let a server that emits a banner then immediately closes
    // the shell (forced-command accounts, a crashing MOTD/login script) reset the budget every cycle
    // and reconnect forever. Longer than AutoReconnectDelay so a session that re-drops between attempts
    // never counts as "stable".
    private static readonly TimeSpan AutoReconnectStabilityWindow = TimeSpan.FromSeconds(30);

    private readonly ISshSessionService _sshService;
    private readonly ISshCredentialResolver _credentialResolver;
    private readonly IConnectionRepository _connectionRepo;
    private readonly IAppSettingsService _settingsService;
    private readonly TunnelManager _tunnels;
    private readonly ITunnelRoutePrompter _tunnelPrompter;
    private readonly IConnectionProfileResolver _profileResolver;
    private readonly ISftpService _sftpService;
    private readonly ILoggerFactory _loggerFactory;
    private readonly ILogger<SshSessionViewModel> _logger;

    private ISshSession? _session;
    private ITerminalOutputSink? _bridge;
    private object? _bridgeRendererIdentity;
    private long _terminalFocusGeneration;
    private TerminalInputWriter? _terminalInputWriter;
    private SshAutoSudoDriver? _autoSudo;
    private CancellationTokenSource? _cts;
    private CoreWebView2? _webView;
    // Survives DetachView only while terminal contents are preserved, so AttachAsync can
    // tell a same-WebView reattach (tab
    // switch — xterm.js still owns the same buffer) from a fresh-WebView attach (Sessions ↔
    // Settings nav — new control). Used by ReferenceEquals only.
    private object? _lastAttachedWebView;
    // UI dispatcher lives on the SessionTabViewModel base class (captured via
    // EnsureDispatcher in AttachAsync) — there's no local field here on this branch.
    private string? _initialKnownFingerprint;
    private TerminalSize _initialSize = TerminalSize.Default;
    private CancellationTokenSource? _outputWaitCts;
    private int _connectInFlight;
    private readonly object _connectCompletionLock = new();
    private Task? _activeConnectCompletion;
    private int _teardownGeneration;
    private ITunnelInstance? _tunnel;
    // The profile actually used for the live connection's tunnel routing. TunnelEnabled reflects
    // the user's per-connect "use tunnel / go direct" choice; SFTP sub-sessions read it (via
    // RoutedProfileForSubsession) so a terminal that went direct doesn't get a silently-tunneled
    // file transfer. Null until a connect resolves a route; cleared on teardown.
    private ConnectionProfile? _activeRoutedProfile;
    private bool _reconnectRequestedWhileDetached;
    private bool _suppressAutoConnectOnReattach;
    // Set when a connect reaches Connected while no view is attached (tab backgrounded mid-connect):
    // the session's banner/prompt lands only in _replayBuffer, so the live xterm.js — cleared at
    // connect start and never fed since — is empty. The next AttachAsync must replay even on a
    // same-WebView reattach (where it normally skips replay because xterm.js already owns the
    // session buffer and the focus request can repaint it). Cleared once a bridge is rebound, and
    // reset whenever the buffer is cleared on teardown.
    private bool _connectedWhileDetached;

    // Auto-reconnect after an UNEXPECTED drop of an already-established session (host reboot, network
    // blip — now detectable via the SSH keep-alive). On such a drop the VM silently retries the
    // connect up to MaxAutoReconnectAttempts times, AutoReconnectDelay apart, before surfacing the
    // Failed overlay. The budget resets once a reconnect stays up for a stability window (proving it's
    // healthy) or on a manual Retry, so an unrelated later drop gets a fresh budget; a connection that
    // flaps before then exhausts the budget and stops. Auth failures, host-key mismatches, and
    // user-initiated teardown are never auto-retried. All access is on the UI thread
    // (OnSessionClosed marshals there; the loop awaits with ConfigureAwait(true)).
    private int _autoReconnectAttempts;
    private CancellationTokenSource? _autoReconnectCts;
    // Fires AutoReconnectStabilityWindow after a connect succeeds; if still Connected then, the
    // attempt budget resets. Cancelled the moment the session is torn down (SafeDisposeSessionAsync),
    // so a session that drops before the window keeps its consumed budget — that's what bounds a
    // flapping/banner-then-close server. Overridable in tests via _autoReconnectStabilityWindow.
    private CancellationTokenSource? _stabilityResetCts;
    private TimeSpan _autoReconnectStabilityWindow = AutoReconnectStabilityWindow;
    private TimeSpan _autoReconnectDelay = AutoReconnectDelay;
    private Func<Task>? _autoReconnectConnectOverrideForTesting;
    // Set by ConnectAsync to categorize its terminal outcome for the auto-reconnect loop: false after a
    // non-retryable failure (auth, host-key, cancelled prompt, missing creds, recoverable tunnel
    // notice), true otherwise. Read only by the loop, immediately after its ConnectAsync call.
    private bool _lastConnectRetryable = true;

    private readonly object _mcpPresentationLock = new();
    private ShellCommandPresentationFilter? _mcpPresentationFilter;
    private ISshSession? _mcpPresentationSession;
    private int _mcpPresentationGeneration = -1;

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
    private readonly TerminalReplayBuffer _replayBuffer = new(TerminalReplayCapacityBytes);
    // Bytes that arrived while no TerminalBridge was attached. Same-WebView tab reattach keeps
    // xterm.js alive, so only this delta should be replayed; full _replayBuffer replay would
    // duplicate already-visible output.
    private readonly TerminalReplayBuffer _detachedReplayBuffer = new(TerminalReplayCapacityBytes);
    private readonly object _terminalReplayLock = new();
    private object? _pendingRendererRecoveryIdentity;
    private string? _pendingRendererRecoveryMessage;
    private ITerminalOutputSink? _pendingRendererRecoverySourceSink;
    private int _pendingRendererRecoveryGeneration = -1;
    private TerminalSize _replayGeometry = TerminalSize.Default;
    private bool _replayHasOutput;
    private bool _replayGeometryChanged;
    private bool _detachedReplayGeometryChanged;
    private bool _replayHasUnacknowledgedOutput;
    private bool _replayRetirementFailed;
    private bool _sessionlessRendererRecoveryAttempted;
    private Task _terminalSinkRetirement = Task.CompletedTask;
    private object? _terminalSinkRetirementIdentity;

    public SshSessionViewModel(
        ISshSessionService sshService,
        ISshCredentialResolver credentialResolver,
        IConnectionRepository connectionRepo,
        IAppSettingsService settingsService,
        TunnelManager tunnels,
        ITunnelRoutePrompter tunnelPrompter,
        IConnectionProfileResolver profileResolver,
        ISftpService sftpService,
        ILoggerFactory loggerFactory)
    {
        _sshService = sshService;
        _credentialResolver = credentialResolver;
        _connectionRepo = connectionRepo;
        _settingsService = settingsService;
        _tunnels = tunnels;
        _tunnelPrompter = tunnelPrompter;
        _profileResolver = profileResolver;
        _sftpService = sftpService;
        _loggerFactory = loggerFactory is NonThrowingLoggerFactory
            ? loggerFactory
            : new NonThrowingLoggerFactory(loggerFactory);
        _logger = _loggerFactory.CreateLogger<SshSessionViewModel>();
        PropertyChanged += (_, args) =>
        {
            if (args.PropertyName == nameof(Status))
            {
                OnPropertyChanged(nameof(IsConnecting));
                OnPropertyChanged(nameof(IsConnected));
                OnPropertyChanged(nameof(IsDisconnected));
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

    // True when the Failed overlay is showing a benign, recoverable NOTICE (e.g. a tunnel downloaded a fresh
    // profile and now needs a new one-time code) rather than a hard failure. Drives the overlay to a
    // success/info presentation — checkmark + positive title — instead of the red "Connection failed" error.
    [ObservableProperty]
    private bool isRecoverableNotice;

    // Heading shown on the recoverable-notice overlay (carried from the notice exception, e.g. "Profile
    // downloaded"). Only displayed while IsRecoverableNotice is true.
    [ObservableProperty]
    private string? noticeTitle;

    [ObservableProperty]
    private bool hasReceivedOutput;

    [ObservableProperty]
    private bool isWaitingForRemoteOutput;

    public bool IsConnecting => Status == SessionStatus.Connecting;
    public bool IsConnected => Status == SessionStatus.Connected;
    public bool IsDisconnected => Status == SessionStatus.Disconnected;
    public bool IsFailed => Status == SessionStatus.Failed;

    /// <summary>
    /// Text shown under the connecting spinner. Normally "Connecting…"; during an automatic reconnect
    /// it names the attempt in flight so the overlay reads as recovering rather than as a silent hang.
    /// </summary>
    public string ConnectingMessage =>
        _autoReconnectAttempts > 0
            ? $"Reconnecting — attempt {_autoReconnectAttempts} of {MaxAutoReconnectAttempts}…"
            : "Connecting…";

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
        _suppressAutoConnectOnReattach = false;
    }

    public void UpdateTerminalSize(TerminalSize size) =>
        UpdateTerminalSizeCore(size, sourceSession: null, sourceGeneration: null, geometryIsUncertain: false);

    private void UpdateTerminalSizeFromBridge(
        ISshSession sourceSession,
        int sourceGeneration,
        TerminalSize size,
        bool geometryIsUncertain) =>
        UpdateTerminalSizeCore(size, sourceSession, sourceGeneration, geometryIsUncertain);

    private void UpdateTerminalSizeCore(
        TerminalSize size,
        ISshSession? sourceSession,
        int? sourceGeneration,
        bool geometryIsUncertain)
    {
        if (size.Columns == 0 || size.Rows == 0) return;
        lock (_terminalReplayLock)
        {
            if (sourceSession is not null &&
                (!sourceGeneration.HasValue ||
                 !IsAttemptCurrent(sourceGeneration.Value) ||
                 (!ReferenceEquals(sourceSession, _session) && _session is not null)))
            {
                return;
            }

            var changed = size != _initialSize;
            var belongsToReplayEpoch =
                sourceSession is not null ||
                _session is not null ||
                _replayHasOutput ||
                _replayBuffer.Count > 0;
            if (belongsToReplayEpoch &&
                (geometryIsUncertain ||
                 (changed &&
                  (_bridge is null || sourceSession?.IsClosing == true || _session?.IsClosing == true))))
            {
                // The renderer and PTY may have crossed this boundary at different instants. Even
                // if the final dimensions later match again, raw TUI bytes are no longer exact.
                _detachedReplayGeometryChanged = true;
            }

            _initialSize = size;
            if (_session is null || size == _replayGeometry) return;

            if (_replayHasOutput)
            {
                _replayGeometryChanged = true;
            }
            else
            {
                _replayGeometry = size;
            }
        }
    }

    public TerminalRendererRecoveryLease CaptureTerminalRendererRecoveryLease() =>
        new(Volatile.Read(ref _teardownGeneration));

    public async Task<TerminalRendererRecoveryLease> HandleTerminalRendererFailureAsync(string message)
    {
        var preserveExplicitDisconnect =
            _suppressAutoConnectOnReattach &&
            Status == SessionStatus.Disconnected;
        CancelAutoReconnect();
        SetAutoReconnectAttempts(0);
        bool preserveSessionlessOutput;
        lock (_terminalReplayLock)
        {
            preserveSessionlessOutput =
                _session is null &&
                (_replayHasOutput || _replayBuffer.Count > 0);
        }
        var teardownGeneration = await TearDownSessionAsync(
            preserveSessionlessOutput).ConfigureAwait(true);
        if (IsAttemptCurrent(teardownGeneration) &&
            !preserveExplicitDisconnect &&
            !(_suppressAutoConnectOnReattach && Status == SessionStatus.Disconnected))
        {
            ReportFailure(message);
        }
        return new TerminalRendererRecoveryLease(teardownGeneration);
    }

    public async Task<TerminalRendererRecoveryLease?> TryHandleTerminalRendererFailureAsync(
        object? rendererIdentity,
        string message)
    {
        Task<TerminalRendererRecoveryLease> recoveryTask;
        lock (_terminalReplayLock)
        {
            // A view with no registered renderer may own first-start failure reporting. Once a
            // renderer is registered, only that exact page may tear down the protocol session.
            if (_lastAttachedWebView is not null &&
                !ReferenceEquals(rendererIdentity, _lastAttachedWebView))
            {
                return null;
            }

            // HandleTerminalRendererFailureAsync advances the lifecycle synchronously before its
            // first await. Starting it under the renderer lock makes authorization + teardown
            // reservation atomic with RegisterAttachedWebView and scoped DetachView.
            recoveryTask = HandleTerminalRendererFailureAsync(message);
        }

        return await recoveryTask.ConfigureAwait(true);
    }

    public bool IsTerminalRendererRecoveryCurrent(TerminalRendererRecoveryLease lease) =>
        IsAttemptCurrent(lease.LifecycleGeneration);

    public async Task AttachAsync(CoreWebView2 webView, TerminalSize initialSize)
    {
        if (Profile is null)
            throw new InvalidOperationException("Initialize must be called before AttachAsync.");

        // A fresh WebView2 (new control after Sessions↔Settings nav) means xterm.js
        // was just navigated to terminal.html and has an empty screen. A same-WebView
        // reattach (tab switch) means xterm.js still owns the prior session buffer;
        // replaying onto it would duplicate bytes, so the focus request repaints it instead.
        var xtermIsFresh = RegisterAttachedWebView(webView);
        _webView = webView;
        if (xtermIsFresh)
        {
            UpdateTerminalSize(initialSize);
        }
        // AttachAsync is called from the UI thread (SshTerminalView's ready handler);
        // capture the dispatcher now so background callbacks (Closed) can marshal back.
        EnsureDispatcher();

        // Detach seals the old bridge but deliberately keeps its WebView listener alive until
        // xterm has parsed every accepted frame and emitted any DA/DSR/CPR reply. Do not replay
        // or publish a replacement bridge until that exact retirement result is committed.
        await AwaitPendingTerminalSinkRetirementAsync().ConfigureAwait(true);
        if (!IsRendererBindingCurrent(webView)) return;

        if (_session is null)
        {
            // A remote close may have happened while this page was absent. Reconstruct the final
            // transcript before either a deferred reconnect clears it or a Failed tab returns.
            if (!await RestoreSessionlessTerminalAsync(
                    webView,
                    xtermIsFresh).ConfigureAwait(true))
            {
                return;
            }
        }

        // Reconnect was requested from the tab context menu while the view was unloaded
        // (background tab) — RetryAsync couldn't fan out to the now-unsubscribed init
        // event, so it stashed the intent here. Honor it before the "session alive →
        // just rebind bridge" path below.
        if (_reconnectRequestedWhileDetached)
        {
            _reconnectRequestedWhileDetached = false;
            // Same reasoning as RetryAsync: skip the Disconnected interlude that
            // DetachAsync would introduce, so the connecting overlay is up for
            // the entire teardown→reconnect window and no phantom text flashes
            // through. ConnectAsync clears xterm only after teardown, keeping the
            // reset ordered behind every frame already posted by the old bridge.
            Status = SessionStatus.Connecting;
            // Blank the stepper now (synchronously, before the teardown await below) so the prior
            // attempt's stale steps — a red Failed step, or an all-completed run — don't render in
            // the connecting overlay during the (100s-of-ms) session/tunnel teardown. ConnectAsync's
            // InitializeProgress rebuilds it fresh. Mirrors RDP's FullTeardownAsync, which resets first.
            Progress.Reset();
            var reconnectGeneration = await TearDownSessionAsync().ConfigureAwait(true);
            if (!IsAttemptCurrent(reconnectGeneration)) return;
            await ConnectAsync().ConfigureAwait(true);

            // This single connect realized the attempt that the background drop deferred while the view
            // was unloaded. If it was an AUTO-reconnect episode (attempts already consumed) and the
            // connect failed transiently, hand off to the retry loop for the remaining budget — now that
            // a view is attached the loop can run, so a backgrounded drop gets the same 3 attempts a
            // foreground one does instead of stopping after one. A deferred MANUAL Retry has
            // _autoReconnectAttempts == 0 (RetryAsync reset it), so it's left at Failed here, matching how
            // a foreground manual Retry behaves. Connected / non-retryable Failed outcomes also fall through.
            if (_autoReconnectAttempts > 0 && ShouldContinueAutoReconnect(Status, _lastConnectRetryable))
            {
                BeginAutoReconnectLoop();
            }
            return;
        }

        // VM survives view rebuilds while the SSH pump keeps running. Skip credential
        // prompt + connect — rebind the bridge to the (possibly new) WebView and
        // resync geometry. Replay only when xterm.js is fresh; same-WebView reattach
        // keeps the prior buffer and lets the focus request repaint its existing canvas.
        if (_session is { } attachedSession)
        {
            var attachGeneration = Volatile.Read(ref _teardownGeneration);
            if (_connectedWhileDetached)
            {
                try
                {
                    await TerminalBridge.ResetSessionlessAsync(webView).ConfigureAwait(true);
                }
                catch (Exception) when (!IsRendererBindingCurrent(
                    attachGeneration,
                    attachedSession,
                    webView))
                {
                    return;
                }
                if (!IsRendererBindingCurrent(
                        attachGeneration,
                        attachedSession,
                        webView))
                {
                    return;
                }
            }

            await RetireCurrentTerminalOutputSinkAsync(
                preserveSessionOutput: true).ConfigureAwait(true);
            if (!IsRendererBindingCurrent(
                    attachGeneration,
                    attachedSession,
                    webView))
            {
                return;
            }

            // Snapshot and enqueue replay before publishing the new bridge: bytes before
            // the lock are replayed first, while bytes after the lock render live through
            // the new bridge and cannot overtake the older replay batch.
            //
            // Replay the full buffer for a fresh WebView (empty xterm.js) or a session that
            // connected while detached. For a normal same-WebView tab switch, replay only
            // bytes captured while no bridge existed; replaying the full buffer would duplicate
            // output that xterm.js already rendered before the tab was hidden.
            var newBridge = CreateTerminalBridge(webView);
            var replayIsExact = false;
            lock (_terminalReplayLock)
            {
                replayIsExact = TryTakeReattachReplaySnapshotUnderLock(
                    xtermIsFresh,
                    out var historicalReplay,
                    out var liveDetachedReplay);
                if (replayIsExact)
                {
                    ReplayAndPublishTerminalOutputSinkUnderLock(
                        newBridge,
                        webView,
                        historicalReplay,
                        liveDetachedReplay);
                }
            }
            if (!replayIsExact)
            {
                newBridge.Dispose();
                // Exact history is unavailable (resize after output, truncated ring, inexact
                // retirement). Keep the live protocol session and rebind a clean xterm instead of
                // closing the connection — scrollback is lost, but the shell/serial line stays up.
                await SoftRebindLiveSessionWithoutExactHistoryAsync(
                        webView,
                        attachedSession,
                        attachGeneration)
                    .ConfigureAwait(true);
                return;
            }

            await CompleteLiveTerminalAttachmentAsync(
                    webView,
                    attachedSession,
                    attachGeneration,
                    newBridge,
                    resizePty: xtermIsFresh)
                .ConfigureAwait(true);
            return;
        }

        // No live session to reattach to. A genuine first show connects below; but an incidental
        // view reload (Sessions<->Settings nav, a manual tab switch, or the closest-neighbour
        // selection SessionsPage drives when the active tab is closed) must not silently restart a
        // tab whose bounded auto-reconnect budget ended in Failed. Leave its Retry overlay standing
        // and let the user choose. Transient drops remain Connecting and recover automatically.
        // Disconnected reattaches still auto-recover because
        // the usual post-attempt Disconnected path is a connect interrupted by a nav-away, unless
        // an explicit cancellation/disconnect set the suppression flag handled below.
        if (ShouldDeferAutoConnectOnReattach())
        {
            _logger.LogDebug("SSH attach: sessionless tab is waiting for explicit reconnect; leaving its overlay up.");
            return;
        }

        await ConnectAsync().ConfigureAwait(true);
    }

    /// <summary>
    /// Rebinds a live SSH session to a fresh/empty xterm when exact scrollback reconstruction is
    /// impossible. Clears poisoned replay checkpoints, publishes a new bridge with no historical
    /// replay, and resizes the PTY — the protocol session stays Connected.
    /// </summary>
    private async Task SoftRebindLiveSessionWithoutExactHistoryAsync(
        CoreWebView2 webView,
        ISshSession attachedSession,
        int attachGeneration)
    {
        _logger.LogWarning(
            "Exact terminal replay is unavailable; rebinding the live SSH session without scrollback.");

        try
        {
            await TerminalBridge.ResetSessionlessAsync(webView).ConfigureAwait(true);
        }
        catch (Exception) when (!IsRendererBindingCurrent(
            attachGeneration,
            attachedSession,
            webView))
        {
            return;
        }
        if (!IsRendererBindingCurrent(attachGeneration, attachedSession, webView)) return;

        var newBridge = CreateTerminalBridge(webView);
        // Clear + publish under one lock so bytes that arrive after the clear cannot linger in the
        // detached buffer while a live bridge is already published.
        lock (_terminalReplayLock)
        {
            ClearTerminalReplayBuffersUnderLock();
            ReplayAndPublishTerminalOutputSinkUnderLock(
                newBridge,
                webView,
                historicalReplay: null,
                liveDetachedReplay: null);
        }

        await CompleteLiveTerminalAttachmentAsync(
                webView,
                attachedSession,
                attachGeneration,
                newBridge,
                resizePty: true)
            .ConfigureAwait(true);
    }

    private async Task CompleteLiveTerminalAttachmentAsync(
        CoreWebView2 webView,
        ISshSession attachedSession,
        int attachGeneration,
        ITerminalOutputSink newBridge,
        bool resizePty)
    {
        try
        {
            if (!IsTerminalAttachmentCurrent(
                    attachGeneration,
                    attachedSession,
                    newBridge,
                    webView))
            {
                return;
            }
            if (resizePty)
            {
                await attachedSession.ResizeAsync(_initialSize.Columns, _initialSize.Rows)
                    .ConfigureAwait(true);
                if (!IsTerminalAttachmentCurrent(
                        attachGeneration,
                        attachedSession,
                        newBridge,
                        webView))
                {
                    return;
                }
            }
            await newBridge.RequestFocusAsync().ConfigureAwait(true);
            if (!IsTerminalAttachmentCurrent(
                    attachGeneration,
                    attachedSession,
                    newBridge,
                    webView))
            {
                return;
            }
            ConfirmRetiredTerminalOutputParsed(newBridge);
            TryPublishConnectedAfterTerminalFocus(
                attachGeneration,
                attachedSession,
                newBridge,
                webView);
        }
        catch (Exception) when (!IsTerminalAttachmentCurrent(
            attachGeneration,
            attachedSession,
            newBridge,
            webView))
        {
            // The session, page, or bridge was retired while resize/focus awaited.
            return;
        }

        EnsureRemoteOutputWaitTimer();
    }

    // Failed tabs and user-cancelled/disconnected tabs keep their in-pane recovery affordance on an
    // incidental view rebuild. Other Disconnected tabs still auto-connect so an interrupted connect
    // can recover through the normal attach path.
    internal bool ShouldDeferAutoConnectOnReattach() =>
        Status == SessionStatus.Failed ||
        _suppressAutoConnectOnReattach;

    /// <summary>
    /// Raised when <see cref="RetryAsync"/> is invoked but the view's WebView2 never
    /// finished initializing. The view subscribes and re-runs its init path so the
    /// Retry button isn't dead in WebView2-failure scenarios.
    /// </summary>
    public event Action? InitializationRetryRequested;
    public event Action? TerminalRendererRecoveryRequested;

    public bool OwnsTerminalRenderer(object? rendererIdentity)
    {
        if (rendererIdentity is null) return false;
        lock (_terminalReplayLock)
        {
            return ReferenceEquals(rendererIdentity, _lastAttachedWebView);
        }
    }

    public bool TryTakeTerminalRendererRecoveryRequest(object? rendererIdentity, out string message)
    {
        lock (_terminalReplayLock)
        {
            if (_pendingRendererRecoveryIdentity is null)
            {
                message = string.Empty;
                return false;
            }

            if (_pendingRendererRecoveryGeneration != Volatile.Read(ref _teardownGeneration) ||
                (_pendingRendererRecoverySourceSink is { } sourceSink &&
                 !IsTerminalOutputFailureCurrentUnderLock(
                     sourceSink,
                     _pendingRendererRecoveryIdentity,
                     _pendingRendererRecoveryGeneration)) ||
                !ReferenceEquals(_pendingRendererRecoveryIdentity, rendererIdentity))
            {
                // A retired bridge, lifecycle, or WebView page cannot poison its replacement.
                ClearPendingRendererRecoveryUnderLock();
                message = string.Empty;
                return false;
            }

            message = _pendingRendererRecoveryMessage ??
                "The terminal renderer stopped responding. Reconnect to restore a clean terminal state.";
            ClearPendingRendererRecoveryUnderLock();
            return true;
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false, CanExecute = nameof(CanRetry))]
    public async Task RetryAsync()
    {
        if (Volatile.Read(ref _connectInFlight) != 0) return;
        var retryGeneration = Interlocked.Increment(ref _teardownGeneration);

        // A manual Retry supersedes any pending automatic reconnect and starts a fresh budget — the
        // user is explicitly driving now, so cancel the loop/deferred intent so they can't race.
        CancelAutoReconnect();
        SetAutoReconnectAttempts(0);

        ErrorMessage = null;
        ResetOutputState();

        // Re-read the connection's current saved settings before reconnecting. The tab caches
        // the profile resolved at open time, and ConnectAsync re-establishes the VPN tunnel from
        // it — so without this, disabling the tunnel (or any other edit) after the tab was opened
        // would be ignored on Retry. Done before the detached-view branch below so the deferred
        // background-tab reconnect path (AttachAsync) also uses the refreshed profile.
        if (!await RefreshProfileFromRepositoryAsync(retryGeneration).ConfigureAwait(true) ||
            !IsAttemptCurrent(retryGeneration))
        {
            return;
        }
        _suppressAutoConnectOnReattach = false;

        if (_webView is null)
        {
            // A null handler means the view is unloaded (background tab): OnUnloaded
            // already detached it, so firing the event would no-op. Stash the intent
            // for the next AttachAsync. A non-null handler means the view is loaded
            // but WebView2 init failed — preserve the existing "retry init" fan-out.
            var handler = InitializationRetryRequested;
            if (handler is not null)
            {
                // Re-running WebView2 init routes back through AttachAsync while Status is still
                // Failed (the init/handshake failure happened before _webView was ever assigned, so
                // there's no live session and no reconnect-while-detached intent). Flip to Connecting
                // first so AttachAsync's ShouldDeferAutoConnectOnReattach() — which defers a
                // sessionless Failed tab to avoid auto-reconnecting an incidental reattach — doesn't
                // suppress THIS user-requested retry and strand the tab on the Failed overlay. Mirrors
                // the foreground path below, which also moves to Connecting before reconnecting.
                Status = SessionStatus.Connecting;
                handler();
            }
            else
            {
                _reconnectRequestedWhileDetached = true;
            }
            return;
        }

        // Flip to Connecting BEFORE the teardown so the failed (or live) overlay
        // hands off directly to the opaque connecting overlay — going through
        // DetachAsync's Status=Disconnected interlude would otherwise leave a
        // sub-frame window with no overlay, exposing the prior session's text as
        // a brief phantom flash. ConnectAsync clears xterm after the old bridge is
        // disposed, so the reset cannot be overtaken by pending old-session output.
        Status = SessionStatus.Connecting;
        // See the reconnect-while-detached branch in AttachAsync: reset the stepper before the
        // teardown await so the failed/completed steps from the previous attempt don't linger in
        // the connecting overlay while the old session + tunnel are torn down.
        Progress.Reset();
        var reconnectGeneration = await TearDownSessionAsync().ConfigureAwait(true);
        if (!IsAttemptCurrent(reconnectGeneration)) return;
        ErrorMessage = null;
        await ConnectAsync().ConfigureAwait(true);
    }

    // While Connecting, an in-flight ConnectAsync still holds _connectInFlight; a second one from RetryAsync would silently no-op.
    private bool CanRetry() =>
        Status != SessionStatus.Connecting &&
        Volatile.Read(ref _connectInFlight) == 0;

    /// <summary>
    /// Re-resolve <see cref="SessionTabViewModel.Profile"/> from the repository (through folder
    /// inheritance) so a reconnect honors edits made after the tab was opened. Keeps the cached
    /// profile when the node was deleted or can't be resolved. Runs on the UI thread (RetryAsync
    /// is a UI-invoked command), so <see cref="SessionTabViewModel.UpdateProfile"/> is safe here.
    /// </summary>
    private async Task<bool> RefreshProfileFromRepositoryAsync(int lifecycleGeneration)
    {
        var current = Profile;
        if (current is null) return IsAttemptCurrent(lifecycleGeneration);
        if (current.IsEphemeral) return IsAttemptCurrent(lifecycleGeneration);

        var refreshed = await _profileResolver.ResolveAsync(current.NodeId).ConfigureAwait(true);
        if (!IsAttemptCurrent(lifecycleGeneration)) return false;
        if (refreshed is null) return true;

        // This tab's view is fixed to its protocol at open time. If the saved connection's
        // protocol was switched (e.g. SSH→RDP) while the tab is open, the resolved profile is
        // unusable here — keep the cached one rather than SSH-connecting to an RDP profile.
        if (refreshed.Protocol != Protocol) return true;

        // Never silently drop a host key we already pinned this session. The resolver reads the
        // DB, where a pin written by this tab's connect normally lives — but if that best-effort
        // write had failed, the refreshed copy would be empty and the retry would re-TOFU against
        // whatever the server now presents. Carry the in-memory pin forward in that case.
        if (string.IsNullOrEmpty(refreshed.SshKnownHostFingerprint) &&
            !string.IsNullOrEmpty(current.SshKnownHostFingerprint))
        {
            refreshed = refreshed with { SshKnownHostFingerprint = current.SshKnownHostFingerprint };
        }

        UpdateProfile(refreshed);
        _initialKnownFingerprint = refreshed.SshKnownHostFingerprint;
        return true;
    }

    [RelayCommand]
    public Task DisconnectAsync() => DetachAsync();

    public override async ValueTask CloseAsync()
    {
        await DetachAsync().ConfigureAwait(true);
    }

    public async Task DetachAsync()
    {
        // Explicit user teardown (Disconnect / tab close) — stop any pending auto-reconnect and clear
        // the budget so a loop or deferred intent can't resurrect a connection the user just dropped.
        _suppressAutoConnectOnReattach = true;
        CancelAutoReconnect();
        SetAutoReconnectAttempts(0);
        bool preserveSessionlessOutput;
        lock (_terminalReplayLock)
        {
            preserveSessionlessOutput =
                _session is null &&
                (_replayHasOutput || _replayBuffer.Count > 0);
        }
        var teardownGeneration = await TearDownSessionAsync(
            preserveSessionlessOutput).ConfigureAwait(true);
        if (!IsAttemptCurrent(teardownGeneration)) return;
        Progress.Reset();
        Status = SessionStatus.Disconnected;
    }

    // Session teardown WITHOUT a Status change — used by RetryAsync / AttachAsync's
    // reconnect-while-detached branch so the overlay can stay on Connecting through
    // the whole flow. Going through Disconnected (as DetachAsync does) creates a
    // sub-frame window where neither the failed nor the connecting overlay is
    // showing, and the user sees the prior session's text flash through. Public
    // DetachAsync is the explicit "user hit Disconnect" path — it still ends in
    // Disconnected and is the only place that should.
    private async Task<int> TearDownSessionAsync(bool preserveTerminalOutput = false)
    {
        var teardownGeneration = Interlocked.Increment(ref _teardownGeneration);
        // Signal cancel to any in-flight ConnectAsync; do NOT Dispose() — the awaiter still
        // holds the token. The CTS is GC-eligible once both sides drop their references.
        var cts = _cts;
        _cts = null;
        try { cts?.Cancel(); } catch { /* already disposed */ }

        await SafeDisposeSessionAsync(preserveTerminalOutput).ConfigureAwait(true);
        return teardownGeneration;
    }

    public void ReportFailure(string message)
    {
        CancelRemoteOutputWaitTimer();
        IsWaitingForRemoteOutput = false;
        Progress.Fail();
        IsRecoverableNotice = false;
        ErrorMessage = message;
        Status = SessionStatus.Failed;
    }

    /// <summary>
    /// End the connect attempt on a benign, recoverable outcome that is NOT a failure — the tunnel did the
    /// right thing but needs the user to reconnect (e.g. it spent the one-time code downloading a fresh
    /// profile, or rejected a re-entered just-spent code). Reuses the Failed overlay so the message +
    /// Reconnect button stay available, but flags it as a notice so the view renders it as success/info, and
    /// does NOT mark a progress step failed — the step it stopped on actually succeeded.
    /// </summary>
    public void ReportNotice(string title, string message)
    {
        CancelRemoteOutputWaitTimer();
        IsWaitingForRemoteOutput = false;
        Progress.Reset();
        IsRecoverableNotice = true;
        NoticeTitle = title;
        ErrorMessage = message;
        Status = SessionStatus.Failed;
    }

    /// <summary>
    /// Seed the connecting stepper for this attempt. Tunneled connections get numbered phases
    /// (VPN tunnel → connect); direct connections clear the steps so the overlay falls back to its
    /// plain spinner.
    /// </summary>
    private void InitializeProgress(ConnectionProfile profile)
    {
        if (profile.TunnelEnabled)
        {
            Progress.Initialize(new (ConnectionPhase, string)[]
            {
                (ConnectionPhase.Tunnel, "VPN tunnel"),
                (ConnectionPhase.Connect, "Connect"),
            });
        }
        else
        {
            Progress.Reset();
        }
    }

    // Runs on the UI thread (CreateUiProgress marshals the provider's background-thread report).
    private void OnTunnelProgress(TunnelProgress progress) =>
        Progress.Detail = ConnectionProgress.DescribeTunnelPhase(progress);

    /// <summary>
    /// Surface the connecting spinner while the view (re)initializes its WebView2 ahead of the
    /// first connect. A freshly-opened tab whose view is unloaded mid-init — e.g. the user opens a
    /// second connection back-to-back and selection moves to it before this tab's xterm.js "ready"
    /// handshake fires — sits in <see cref="SessionStatus.Disconnected"/> until the tab is brought
    /// forward again and the deferred connect lands. Flipping to Connecting here makes that recovery
    /// window explicit (and removes the illusion that a keystroke is what "reconnects" it).
    /// <para>
    /// Strictly Disconnected → Connecting with no live/in-flight session and no explicit user
    /// cancellation to preserve. This never disturbs a connected session's Sessions↔Settings
    /// nav-back rebind, a Failed tab's Retry overlay, or a Disconnected tab waiting for Reconnect.
    /// Called from <c>SshTerminalView.InitializeWebViewAsync</c> on the UI thread once that path has
    /// committed to navigating.
    /// </para>
    /// </summary>
    public void MarkConnecting()
    {
        if (!_suppressAutoConnectOnReattach &&
            Status == SessionStatus.Disconnected &&
            _session is null &&
            Volatile.Read(ref _connectInFlight) == 0)
        {
            Status = SessionStatus.Connecting;
        }
    }

    /// <summary>
    /// Called by the view on Unloaded — releases the WebView2 binding without tearing
    /// down the SSH session. DataContext rebinding also calls it before repurposing the page.
    /// Background SSH output still arrives on the read pump, but the missing bridge prevents
    /// routing it to a disposed WebView2. The next AttachAsync rebinds.
    /// </summary>
    public void DetachView(bool preserveTerminalContents = true)
    {
        lock (_terminalReplayLock)
        {
            DetachViewUnderLock(preserveTerminalContents);
        }
    }

    public void DetachView(object? rendererIdentity, bool preserveTerminalContents = true)
    {
        if (rendererIdentity is null) return;
        lock (_terminalReplayLock)
        {
            if (!ReferenceEquals(rendererIdentity, _lastAttachedWebView)) return;
            DetachViewUnderLock(preserveTerminalContents);
        }
    }

    public async Task DetachViewAsync(
        object? rendererIdentity,
        bool preserveTerminalContents = true)
    {
        if (rendererIdentity is null) return;

        Task retirement;
        lock (_terminalReplayLock)
        {
            if (ReferenceEquals(rendererIdentity, _lastAttachedWebView))
            {
                DetachViewUnderLock(preserveTerminalContents);
            }
            else if (!ReferenceEquals(
                         rendererIdentity,
                         _terminalSinkRetirementIdentity))
            {
                return;
            }
            retirement = _terminalSinkRetirement;
        }

        await retirement.ConfigureAwait(true);
    }

    private void DetachViewUnderLock(bool preserveTerminalContents)
    {
        RetireTerminalOutputSinkUnderLock(preserveSessionOutput: true);
        _webView = null;
        if (!preserveTerminalContents)
        {
            _lastAttachedWebView = null;
        }
    }

    internal void AttachConnectedSessionForTesting(ISshSession session, ITunnelInstance? tunnel = null)
    {
        Interlocked.Increment(ref _teardownGeneration);
        ResetOutputState();
        ClearTerminalReplayBuffers();
        if (_session is not null)
        {
            _session.DataReceived -= OnSessionDataReceived;
            _session.Closed -= OnSessionClosed;
        }

        // Lets a test exercise the SFTP-borrows-the-session-tunnel path (BorrowTunnelForSftp), which the
        // real ConnectAsync would normally populate.
        _tunnel = tunnel;
        _terminalInputWriter?.Dispose();
        lock (_terminalReplayLock)
        {
            _session = session;
            ResetReplayCheckpointUnderLock();
        }
        _terminalInputWriter = CreateTerminalInputWriter(session);
        _session.DataReceived += OnSessionDataReceived;
        _session.Closed += OnSessionClosed;
        Status = SessionStatus.Connected;
        StartRemoteOutputWaitTimer();
        // Mirror ConnectAsync's success path so tests can exercise the stability-based budget reset.
        StartAutoReconnectStabilityTimer();
    }

    private bool TryCreateSessionlessReplaySnapshotUnderLock(
        bool xtermIsFresh,
        out byte[]? replay)
    {
        replay = null;
        var hasOutput = _replayHasOutput || _replayBuffer.Count > 0;
        if (!hasOutput) return true;

        var needsReconstruction =
            xtermIsFresh ||
            _connectedWhileDetached ||
            _detachedReplayBuffer.Count > 0 ||
            _detachedReplayGeometryChanged ||
            _replayHasUnacknowledgedOutput ||
            _replayRetirementFailed;
        if (!needsReconstruction) return true;

        if (_replayBuffer.HasTruncated ||
            _replayGeometryChanged ||
            _detachedReplayGeometryChanged ||
            _initialSize != _replayGeometry)
        {
            return false;
        }

        replay = _replayBuffer.Snapshot();
        return true;
    }

    private async Task<bool> RestoreSessionlessTerminalAsync(
        CoreWebView2 webView,
        bool xtermIsFresh,
        TimeSpan? timeout = null)
    {
        var restoreGeneration = Volatile.Read(ref _teardownGeneration);
        byte[]? replay;
        bool isExact;
        lock (_terminalReplayLock)
        {
            if (_session is not null || !ReferenceEquals(webView, _webView)) return false;
            isExact = TryCreateSessionlessReplaySnapshotUnderLock(xtermIsFresh, out replay);
        }

        if (!isExact)
        {
            _logger.LogWarning(
                "Could not reconstruct preserved SSH output because its exact history or geometry expired.");
            if (Status != SessionStatus.Disconnected)
            {
                ReportFailure(
                    "The final terminal output could not be restored exactly. Reconnect to start a clean session.");
            }
            return false;
        }
        if (replay is null) return true;

        try
        {
            await TerminalBridge.ReplaySessionlessAsync(
                webView,
                replay,
                timeout).ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not render preserved output from the closed SSH session.");
            if (IsAttemptCurrent(restoreGeneration) &&
                _session is null &&
                ReferenceEquals(webView, _webView))
            {
                // Keep every replay buffer intact and recreate this exact renderer. Returning false
                // prevents Attach/auto-reconnect from installing a new session on the broken page.
                RequestSessionlessRendererRecovery(
                    webView,
                    restoreGeneration,
                    "The terminal renderer could not restore the final SSH output.");
            }
            return false;
        }

        lock (_terminalReplayLock)
        {
            if (!IsAttemptCurrent(restoreGeneration) ||
                _session is not null ||
                !ReferenceEquals(webView, _webView))
            {
                return false;
            }

            _detachedReplayBuffer.Clear();
            _connectedWhileDetached = false;
            _replayHasUnacknowledgedOutput = false;
            _replayRetirementFailed = false;
            _sessionlessRendererRecoveryAttempted = false;
        }
        return true;
    }

    private async Task FlushTerminalOutputBeforeRemoteCloseAsync(
        ISshSession? closedSession,
        int closeGeneration,
        long outputDeadline)
    {
        while (true)
        {
            ITerminalOutputSink? sink;
            lock (_terminalReplayLock)
            {
                if (!IsAttemptCurrent(closeGeneration) ||
                    !ReferenceEquals(closedSession, _session))
                {
                    return;
                }
                sink = _bridge;
            }
            if (sink is null) return;

            var remaining = TimeSpan.FromMilliseconds(outputDeadline - Environment.TickCount64);
            if (remaining <= TimeSpan.Zero)
            {
                _logger.LogWarning(
                    "Timed out preserving terminal output before the remote SSH session closed.");
                return;
            }

            var flushed = false;
            try
            {
                flushed = await sink.FlushOutputAsync(remaining).ConfigureAwait(true);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(
                    ex,
                    "Could not confirm terminal output delivery before the remote SSH session closed.");
            }

            lock (_terminalReplayLock)
            {
                if (!IsAttemptCurrent(closeGeneration) ||
                    !ReferenceEquals(closedSession, _session))
                {
                    return;
                }
                if (!ReferenceEquals(sink, _bridge))
                {
                    // Renderer recovery replaced the sink while the close was being drained. Flush
                    // the replacement within the same overall deadline before retiring it.
                    continue;
                }
            }

            if (!flushed)
            {
                _logger.LogWarning(
                    "Terminal output could not be acknowledged before the remote SSH session closed; " +
                    "unposted bytes will be retained in the replay checkpoint.");
            }
            return;
        }
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
            // dead transport and try to recover. Status==Connecting can happen if the
            // server immediately closes the shell after auth (e.g. forced-command accounts).
            if (!ReferenceEquals(closedSession, _session)) return;
            if (Status == SessionStatus.Failed || Status == SessionStatus.Disconnected) return;
            var closeGeneration = Volatile.Read(ref _teardownGeneration);
            var outputDeadline = Environment.TickCount64 +
                (long)RemoteCloseOutputFlushTimeout.TotalMilliseconds;
            // The remote endpoint is already closing. Hide the interactive surface immediately so
            // keystrokes cannot appear accepted while the protocol writer is discarding them.
            Status = SessionStatus.Connecting;
            await FlushTerminalOutputBeforeRemoteCloseAsync(
                closedSession,
                closeGeneration,
                outputDeadline).ConfigureAwait(true);
            if (!IsAttemptCurrent(closeGeneration) || !ReferenceEquals(closedSession, _session)) return;

            // Preserve the replay checkpoint while the dead connection is visible. A foreground
            // reconnect deliberately clears it when the next lifecycle begins; until then, any
            // unposted fallback bytes remain recoverable if the view is recreated.
            await SafeDisposeSessionAsync(preserveTerminalOutput: true).ConfigureAwait(true);

            if (!IsAttemptCurrent(closeGeneration) || _session is not null) return;
            // SafeDisposeSessionAsync seals the bridge synchronously, but ordered retirement remains
            // asynchronous while xterm parses its accepted prefix and returns any parser replies. Do
            // not clear/replay the page from a sessionless snapshot until the latest published sink
            // retirement has completed; otherwise late d: frames can land after the q: reconstruction.
            await AwaitPendingTerminalSinkRetirementAsync().ConfigureAwait(true);
            if (!IsAttemptCurrent(closeGeneration) || _session is not null) return;
            var remainingOutputBudget = TimeSpan.FromMilliseconds(
                outputDeadline - Environment.TickCount64);
            if (_webView is { } closedSessionWebView)
            {
                // A timed-out/failed live flush leaves an exact full checkpoint. Reconstruct it on
                // the still-current page now, but never extend the close's one shared output deadline.
                if (!await RestoreSessionlessTerminalAsync(
                        closedSessionWebView,
                        xtermIsFresh: false,
                        remainingOutputBudget).ConfigureAwait(true))
                {
                    return;
                }
                if (!IsAttemptCurrent(closeGeneration) || _session is not null) return;
            }

            // Re-check after the await: SafeDisposeSessionAsync yields on the real socket close, and a
            // user teardown (Disconnect / tab close → DetachAsync) can land during that window and move
            // us to a terminal state. Without this, the auto-reconnect below would resurrect a session
            // the user just explicitly dropped. (The same guard runs before the await for the pre-await case.)
            if (Status == SessionStatus.Failed || Status == SessionStatus.Disconnected) return;

            // An established session dropped unexpectedly. Rather than going straight to the Failed
            // overlay, attempt an automatic reconnect a bounded number of times (host reboots and
            // transient blips usually recover within a couple of attempts) before giving up.
            if (_autoReconnectAttempts >= MaxAutoReconnectAttempts)
            {
                // Budget spent — surface the Failed overlay with the explanatory exhaustion message
                // instead of the generic Disconnected fallback. Mark this outcome terminal so an
                // active loop cannot classify it as transient and prefix the exhaustion note again.
                _lastConnectRetryable = false;
                ReportFailure($"Remote session closed. {ReconnectExhaustedNote}");
                return;
            }

            if (_webView is null)
            {
                // Background tab (view unloaded): we can't connect without a WebView. Count one attempt
                // and defer it to the next AttachAsync via the existing detached-reconnect intent —
                // exactly how a manual Retry issued while detached behaves. The connecting overlay shows
                // when the tab is brought forward; AttachAsync then tears down and reconnects.
                SetAutoReconnectAttempts(_autoReconnectAttempts + 1);
                _reconnectRequestedWhileDetached = true;
                Status = SessionStatus.Connecting;
                return;
            }

            // Foreground tab: drive the retry loop (wait, connect, repeat until success/budget/teardown).
            BeginAutoReconnectLoop();
        });
    }

    private void OnTerminalOutputTransportFailed(
        ITerminalOutputSink? sourceSink,
        object rendererIdentity,
        string message)
    {
        if (sourceSink is null) return;
        var failureGeneration = Volatile.Read(ref _teardownGeneration);
        lock (_terminalReplayLock)
        {
            if (!IsTerminalOutputFailureCurrentUnderLock(
                    sourceSink,
                    rendererIdentity,
                    failureGeneration))
            {
                return;
            }

            _pendingRendererRecoveryIdentity = rendererIdentity;
            _pendingRendererRecoveryMessage = message;
            _pendingRendererRecoverySourceSink = sourceSink;
            _pendingRendererRecoveryGeneration = failureGeneration;
        }

        MarshalToUi(async () =>
        {
            lock (_terminalReplayLock)
            {
                if (!IsTerminalOutputFailureCurrentUnderLock(
                        sourceSink,
                        rendererIdentity,
                        failureGeneration) ||
                    !ReferenceEquals(_pendingRendererRecoverySourceSink, sourceSink) ||
                    _pendingRendererRecoveryGeneration != failureGeneration)
                {
                    if (ReferenceEquals(_pendingRendererRecoverySourceSink, sourceSink) &&
                        _pendingRendererRecoveryGeneration == failureGeneration)
                    {
                        ClearPendingRendererRecoveryUnderLock();
                    }
                    return;
                }
            }

            var handler = TerminalRendererRecoveryRequested;
            if (handler is not null)
            {
                handler();
                return;
            }

            var teardownGeneration = await TearDownSessionAsync().ConfigureAwait(true);
            if (IsAttemptCurrent(teardownGeneration) && Status != SessionStatus.Disconnected)
            {
                ReportFailure(message);
            }
        });
    }

    private bool IsTerminalOutputFailureCurrentUnderLock(
        ITerminalOutputSink sourceSink,
        object rendererIdentity,
        int lifecycleGeneration) =>
        ReferenceEquals(sourceSink, _bridge) &&
        IsAttemptCurrent(lifecycleGeneration) &&
        (ReferenceEquals(rendererIdentity, _webView) ||
         ReferenceEquals(rendererIdentity, _lastAttachedWebView));

    private void RequestSessionlessRendererRecovery(
        object rendererIdentity,
        int lifecycleGeneration,
        string message)
    {
        Action? recoveryHandler = null;
        var recoveryBudgetExhausted = false;
        lock (_terminalReplayLock)
        {
            if (!IsAttemptCurrent(lifecycleGeneration) ||
                _session is not null ||
                !ReferenceEquals(rendererIdentity, _lastAttachedWebView))
            {
                return;
            }

            if (_sessionlessRendererRecoveryAttempted)
            {
                recoveryBudgetExhausted = true;
            }
            else
            {
                _sessionlessRendererRecoveryAttempted = true;
                _pendingRendererRecoveryIdentity = rendererIdentity;
                _pendingRendererRecoveryMessage = message;
                _pendingRendererRecoverySourceSink = null;
                _pendingRendererRecoveryGeneration = lifecycleGeneration;
                recoveryHandler = TerminalRendererRecoveryRequested;
            }
        }

        if (recoveryBudgetExhausted || recoveryHandler is null)
        {
            if (Status != SessionStatus.Disconnected)
            {
                ReportFailure(message + " Use Retry to start a clean session.");
            }
            return;
        }

        try { recoveryHandler(); }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not request terminal renderer recreation.");
            if (Status != SessionStatus.Disconnected) ReportFailure(message);
        }
    }
    private void ClearPendingRendererRecoveryUnderLock()
    {
        _pendingRendererRecoveryIdentity = null;
        _pendingRendererRecoveryMessage = null;
        _pendingRendererRecoverySourceSink = null;
        _pendingRendererRecoveryGeneration = -1;
    }

    // Both bridge sites — the initial connect below and the AttachAsync rebind after a view
    // reload — wire the same logger category and settings around the live session, so centralize
    // the construction here. Callers reach this only with a live _session (just connected, or
    // guarded by `_session is not null`); the surrounding snapshot/replay/resize/focus differs
    // per site and stays at the call site.
    private TerminalBridge CreateTerminalBridge(CoreWebView2 view)
    {
        var sourceSession = _session ??
            throw new InvalidOperationException("A live SSH session is required for the terminal bridge.");
        var sourceGeneration = Volatile.Read(ref _teardownGeneration);
        TerminalBridge? bridge = null;
        bridge = new TerminalBridge(
            view,
            sourceSession,
            _loggerFactory.CreateLogger<TerminalBridge>(),
            _settingsService,
            _initialSize,
            _terminalInputWriter ?? throw new InvalidOperationException("Terminal input writer is unavailable."),
            (size, geometryIsUncertain) =>
                UpdateTerminalSizeFromBridge(sourceSession, sourceGeneration, size, geometryIsUncertain),
            message => OnTerminalOutputTransportFailed(bridge, view, message));
        return bridge;
    }

    private TerminalInputWriter CreateTerminalInputWriter(ISshSession session)
    {
        TerminalInputWriter? writer = null;
        writer = new TerminalInputWriter(
            payload => session.WriteAsync(payload),
            exception => OnTerminalInputWriteFailed(writer, session, exception));
        return writer;
    }

    private void OnTerminalInputWriteFailed(
        TerminalInputWriter? source,
        ISshSession session,
        Exception exception)
    {
        if (source is null) return;
        lock (_terminalReplayLock)
        {
            if (!ReferenceEquals(_terminalInputWriter, source) ||
                !ReferenceEquals(_session, session))
            {
                return;
            }
        }

        if (session.IsClosing) return;

        _logger.LogError(exception, "Terminal input writer failed.");
        MarshalToUi(async () =>
        {
            lock (_terminalReplayLock)
            {
                if (!ReferenceEquals(_terminalInputWriter, source) ||
                    !ReferenceEquals(_session, session))
                {
                    return;
                }
            }
            if (session.IsClosing || Status is SessionStatus.Failed or SessionStatus.Disconnected) return;

            var teardownGeneration = await TearDownSessionAsync().ConfigureAwait(true);
            if (IsAttemptCurrent(teardownGeneration) && Status != SessionStatus.Disconnected)
            {
                ReportFailure("Terminal input failed: " + exception.Message);
            }
        });
    }

    /// <summary>
    /// Start the foreground auto-reconnect loop after an unexpected drop, unless one is already
    /// running. The loop owns the attempt counter and the connecting overlay until it reconnects,
    /// exhausts the budget, hits a non-retryable failure, or is cancelled by a user action.
    /// </summary>
    private void BeginAutoReconnectLoop()
    {
        if (_autoReconnectCts is not null) return; // a loop is already driving reconnects
        var cts = new CancellationTokenSource();
        _autoReconnectCts = cts;
        _ = RunAutoReconnectLoopAsync(cts);
    }

    private async Task RunAutoReconnectLoopAsync(CancellationTokenSource cts)
    {
        var token = cts.Token;
        try
        {
            while (_autoReconnectAttempts < MaxAutoReconnectAttempts)
            {
                // A remote close can arrive after session.Start() but before the original ConnectAsync
                // has unwound (for example while a first-seen host fingerprint is being persisted).
                // Do not let this reconnect attempt hit the connect gate and silently no-op: wait for
                // the owner to finish, without consuming an attempt or its delay budget.
                if (!await WaitForConnectOwnerAndShouldContinueAsync(token).ConfigureAwait(true)) return;

                SetAutoReconnectAttempts(_autoReconnectAttempts + 1);
                var attempt = _autoReconnectAttempts;

                // Hold the connecting overlay (showing the "Reconnecting — attempt N of M" message)
                // for the whole wait, and clear any prior attempt's failure chrome so it doesn't flash.
                Status = SessionStatus.Connecting;
                ErrorMessage = null;
                IsRecoverableNotice = false;
                Progress.Reset();

                // AttachAsync can realize this already-counted attempt while the loop is sleeping.
                // Snapshot before the delay so the second owner barrier can distinguish that connect
                // from a synthetic/no-op owner which never opened a lifecycle.
                var lifecycleBeforeRetryDelay = Volatile.Read(ref _teardownGeneration);
                try { await Task.Delay(_autoReconnectDelay, token).ConfigureAwait(true); }
                catch (OperationCanceledException) { return; }

                // AttachAsync can start its own connect while this loop is sleeping (for example after
                // an unload/reload). Await that exact owner too. Once this returns on the UI thread,
                // there is no yielding point before ConnectAsync acquires the gate below.
                if (!await WaitForConnectOwnerAndShouldContinueAsync(token).ConfigureAwait(true)) return;

                if (Volatile.Read(ref _teardownGeneration) != lifecycleBeforeRetryDelay)
                {
                    // The owner started during this attempt's delay/barrier and already produced the
                    // current retryable outcome. It consumes this attempt; start the next bounded wait
                    // instead of issuing a duplicate connect with the same counter and no delay.
                    continue;
                }

                // The view unloaded during the wait (Sessions↔Settings nav / tab backgrounded), so
                // there's no WebView2 to connect through. Defer to the next AttachAsync (same as a
                // background-tab drop) instead of calling ConnectAsync, which would just no-op on the
                // null _webView and silently burn this attempt. The overlay stays on Connecting.
                if (_webView is null && _autoReconnectConnectOverrideForTesting is null)
                {
                    _reconnectRequestedWhileDetached = true;
                    return;
                }

                _logger.LogInformation(
                    "SSH auto-reconnect attempt {Attempt}/{Max} for {Host}.",
                    attempt, MaxAutoReconnectAttempts, Profile?.Host);
                var lifecycleBeforeAttempt = Volatile.Read(ref _teardownGeneration);
                if (_autoReconnectConnectOverrideForTesting is { } connectOverride)
                {
                    await connectOverride().ConfigureAwait(true);
                }
                else
                {
                    await ConnectAsync().ConfigureAwait(true);
                }

                // If this exact attempt opened a lifecycle which then closed before ConnectAsync returned,
                // OnSessionClosed has already disposed it and left Connecting for the next bounded retry.
                // Its BeginAutoReconnectLoop call intentionally coalesces into this still-owned loop.
                var attemptStartedLifecycle =
                    Volatile.Read(ref _teardownGeneration) != lifecycleBeforeAttempt;
                if (!token.IsCancellationRequested &&
                    attemptStartedLifecycle &&
                    Status == SessionStatus.Connecting &&
                    _session is null)
                {
                    continue;
                }

                // ConnectAsync swallows every other outcome into Status (+ _lastConnectRetryable). Decide
                // whether to keep retrying from that, rather than threading a result through every caller.
                // Connected (success), Disconnected (cancelled mid-connect), or a non-retryable Failed
                // (auth / host-key / notice) all stop the loop; only a transient Failed loops again.
                if (!ShouldContinueAutoReconnect(Status, _lastConnectRetryable)) return;
            }

            // Budget exhausted on a retryable failure: ConnectAsync left Status=Failed with the real
            // error. Reframe it so the user sees this followed several automatic attempts.
            if (Status == SessionStatus.Failed && !IsRecoverableNotice)
            {
                ErrorMessage = $"{ReconnectExhaustedNote} {ErrorMessage}".Trim();
            }
        }
        finally
        {
            if (ReferenceEquals(_autoReconnectCts, cts)) _autoReconnectCts = null;
            cts.Dispose();
        }
    }

    private async Task<bool> WaitForConnectOwnerAndShouldContinueAsync(CancellationToken token)
    {
        try
        {
            while (true)
            {
                Task? activeConnect;
                lock (_connectCompletionLock)
                {
                    activeConnect = _activeConnectCompletion;
                }

                if (activeConnect is null || activeConnect.IsCompleted) break;
                await activeConnect.WaitAsync(token).ConfigureAwait(true);
            }
        }
        catch (OperationCanceledException)
        {
            return false;
        }

        return !token.IsCancellationRequested &&
            (Status == SessionStatus.Connecting ||
             ShouldContinueAutoReconnect(Status, _lastConnectRetryable));
    }

    /// <summary>
    /// Cancel a fire-and-forget timer's CTS and clear the field. Cancel-without-dispose by design: these
    /// CTSs hold no OS handle (no WaitHandle / linked-token use, only Task.Delay), so GC reclaims them,
    /// and disposing could make an in-flight await observe ObjectDisposedException instead of the
    /// expected OperationCanceledException. Shared by the reconnect, stability, and output-wait timers.
    /// </summary>
    private static void CancelTimer(ref CancellationTokenSource? cts)
    {
        var local = cts;
        cts = null;
        if (local is null) return;
        try { local.Cancel(); }
        catch (ObjectDisposedException) { /* already disposed */ }
    }

    /// <summary>
    /// Cancel any pending/in-flight auto-reconnect and drop a deferred detached-reconnect intent. Called
    /// when a user action (manual Retry, Disconnect, tab close) takes over so the loop can't fight it.
    /// </summary>
    private void CancelAutoReconnect()
    {
        CancelTimer(ref _autoReconnectCts);
        _reconnectRequestedWhileDetached = false;
    }

    // Shared wording for "gave up after N auto-reconnects", used by both the budget-already-spent path
    // (a fresh drop with no attempts left) and the loop's own exhaustion path, so the count and phrasing
    // stay in lockstep.
    private static string ReconnectExhaustedNote => $"Reconnection failed after {MaxAutoReconnectAttempts} attempts.";

    // Set the attempt counter and notify the connecting-overlay message (which is derived from it).
    private void SetAutoReconnectAttempts(int value)
    {
        if (_autoReconnectAttempts == value) return;
        _autoReconnectAttempts = value;
        OnPropertyChanged(nameof(ConnectingMessage));
    }

    /// <summary>
    /// Arm the "this reconnect proved stable" timer after a successful connect. If the session is
    /// still Connected when <see cref="AutoReconnectStabilityWindow"/> elapses, the retry budget is
    /// cleared so a later, unrelated drop gets a fresh set of attempts. A session that drops before
    /// then has its timer cancelled (see <see cref="SafeDisposeSessionAsync"/>) and keeps its consumed
    /// budget — which is what bounds a flapping or banner-then-close server.
    /// </summary>
    private void StartAutoReconnectStabilityTimer()
    {
        CancelAutoReconnectStabilityTimer();
        if (_autoReconnectAttempts == 0) return; // nothing to reset
        var cts = new CancellationTokenSource();
        _stabilityResetCts = cts;
        _ = ResetAutoReconnectBudgetAfterStabilityAsync(cts.Token);
    }

    private async Task ResetAutoReconnectBudgetAfterStabilityAsync(CancellationToken token)
    {
        try { await Task.Delay(_autoReconnectStabilityWindow, token).ConfigureAwait(true); }
        catch (OperationCanceledException) { return; }
        if (token.IsCancellationRequested) return;
        if (Status == SessionStatus.Connected) SetAutoReconnectAttempts(0);
    }

    private void CancelAutoReconnectStabilityTimer() => CancelTimer(ref _stabilityResetCts);

    /// <summary>
    /// Whether the auto-reconnect loop should keep retrying after a connect attempt with the given
    /// outcome. Only a transient failure (<see cref="SessionStatus.Failed"/> + retryable) loops again;
    /// success, a cancel-driven <see cref="SessionStatus.Disconnected"/>, or a non-retryable failure
    /// (auth, host-key, recoverable notice) all stop it. Pure so it can be unit-tested directly — the
    /// loop itself drives <see cref="ConnectAsync"/>, which requires a live WebView2.
    /// </summary>
    internal static bool ShouldContinueAutoReconnect(SessionStatus statusAfterConnect, bool lastConnectRetryable) =>
        statusAfterConnect == SessionStatus.Failed && lastConnectRetryable;

    private async Task ConnectAsync()
    {
        var profile = Profile;
        var connectingWebView = _webView;
        if (_suppressAutoConnectOnReattach || profile is null || connectingWebView is null) return;
        var connectCompletion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        lock (_connectCompletionLock)
        {
            if (_connectInFlight != 0) return;
            _connectInFlight = 1;
            _activeConnectCompletion = connectCompletion.Task;
        }
        // Starting a new connection defines a new lifecycle episode. This invalidates any
        // delayed teardown continuation from the previous transport before it can report or clear state.
        var teardownGeneration = Interlocked.Increment(ref _teardownGeneration);


        Status = SessionStatus.Connecting;
        ErrorMessage = null;
        IsRecoverableNotice = false;
        ResetOutputState();
        // Assume a failure here would be worth auto-retrying (network/host transient); the specific
        // catch blocks below flip this off for outcomes that retrying can't fix (auth, host key,
        // cancelled prompt, missing creds, recoverable tunnel notice). Read by the auto-reconnect loop.
        _lastConnectRetryable = true;
        var cts = new CancellationTokenSource();
        _cts = cts;
        var token = cts.Token;
        ITunnelInstance? pendingTunnel = null;
        ISshSession? pendingSession = null;

        async Task<bool> CleanupPendingConnectArtifactsAndIsCurrentAsync()
        {
            await DisposeSessionInstanceSilentlyAsync(pendingSession).ConfigureAwait(true);
            await DisposeTunnelInstanceSilentlyAsync(pendingTunnel).ConfigureAwait(true);
            return IsAttemptCurrent(teardownGeneration);
        }

        async Task HandleCancellationAsync()
        {
            if (ReferenceEquals(Interlocked.CompareExchange(ref _cts, null, cts), cts))
            {
                try { cts.Cancel(); } catch { /* already disposed */ }
            }
            if (!await CleanupPendingConnectArtifactsAndIsCurrentAsync().ConfigureAwait(true)) return;
            _suppressAutoConnectOnReattach = true;
            await SafeDisposeSessionAsync().ConfigureAwait(true);
            Progress.Reset();
            Status = SessionStatus.Disconnected;
        }

        try
        {
            await AwaitPendingTerminalSinkRetirementAsync().ConfigureAwait(true);
            if (!IsAttemptCurrent(teardownGeneration)) return;

            var initialRendererReset = await TryResetCurrentTerminalRendererForNewSessionAsync(
                teardownGeneration,
                token).ConfigureAwait(true);
            if (!initialRendererReset.Succeeded ||
                !IsAttemptCurrent(teardownGeneration))
            {
                return;
            }

            // The currently owned page (if any) acknowledged the ordered lifecycle boundary.
            // Only now may a checkpoint retained from an unexpected remote close be discarded.
            ClearTerminalReplayBuffers();

            // Per-connect tunnel routing: when the user has opted in (PromptBeforeTunnelConnect)
            // and this profile is configured for a tunnel, ask whether to route through it or
            // connect directly for THIS attempt. Done before credential resolution so a "Cancel"
            // doesn't make the user enter a password first. A null result means the user
            // cancelled — return silently to Disconnected (no error overlay). Only the tunnel
            // establish below consults `routed`; `profile` itself stays pristine so the
            // host-fingerprint pin doesn't persist the per-attempt choice (Retry re-resolves the
            // saved tunnel setting and re-asks after a network change).
            var routed = await _tunnelPrompter.ResolveRouteAsync(profile, token).ConfigureAwait(true);
            if (!IsAttemptCurrent(teardownGeneration)) return;
            if (routed is null)
            {
                // The user deliberately dismissed the route choice. This is not a failed connection
                // attempt; use the shared cancellation cleanup without auto-retrying.
                _lastConnectRetryable = false;
                await HandleCancellationAsync().ConfigureAwait(true);
                return;
            }
            _activeRoutedProfile = routed;

            // Build the stepper from the ROUTED decision, not the saved profile: if the user chose
            // "connect directly", routed.TunnelEnabled is false → no tunnel steps (plain spinner);
            // otherwise the VPN tunnel + Connect steps show. Credential resolution below is a quick
            // local step and deliberately NOT a phase — a completed "Credentials" step would imply
            // the target was authenticated before the tunnel was up; target auth happens in Connect.
            InitializeProgress(routed);

            var creds = await _credentialResolver.ResolveAsync(profile, token).ConfigureAwait(true);
            if (!IsAttemptCurrent(teardownGeneration)) return;
            if (!creds.HasAny)
            {
                // Not auto-retryable: no stored/entered credentials won't appear by retrying.
                _lastConnectRetryable = false;
                ReportFailure("No credentials provided.");
                return;
            }

            if (!string.IsNullOrWhiteSpace(creds.UsernameOverride))
            {
                var username = creds.UsernameOverride.Trim();
                if (!string.Equals(profile.Username, username, StringComparison.Ordinal))
                {
                    profile = profile with { Username = username };
                    Profile = profile;
                    if (_activeRoutedProfile is not null)
                    {
                        _activeRoutedProfile = _activeRoutedProfile with { Username = username };
                    }
                }
            }

            // Cache the successfully-resolved credentials so the SFTP pre-warm (kicked off
            // when Status flips to Connected below) and the on-demand file-transfer path
            // can both skip a re-resolve — which would otherwise re-prompt for a key
            // passphrase or password and break the "instant click" UX.
            _capturedCredentials = creds;

            Progress.Begin(ConnectionPhase.Tunnel);
            // Establish from the routed profile (TunnelEnabled forced off when the user chose
            // "connect directly"); the SSH service routes through the explicit _tunnel handle, so
            // the rest of the connect keeps using the unmodified profile. When routed has no tunnel,
            // EstablishAsync returns null and the Begin calls are no-ops (the stepper is empty).
            pendingTunnel = await _tunnels.EstablishAsync(
                routed, token, CreateUiProgress<TunnelProgress>(OnTunnelProgress)).ConfigureAwait(true);
            if (!IsAttemptCurrent(teardownGeneration))
            {
                await DisposeTunnelInstanceSilentlyAsync(pendingTunnel).ConfigureAwait(true);
                return;
            }
            _tunnel = pendingTunnel;
            pendingTunnel = null;

            Progress.Begin(ConnectionPhase.Connect);
            pendingSession = await _sshService.ConnectAsync(profile, creds, _initialSize, _tunnel, token).ConfigureAwait(true);
            if (!IsAttemptCurrent(teardownGeneration))
            {
                await DisposeSessionInstanceSilentlyAsync(pendingSession).ConfigureAwait(true);
                return;
            }
            // The browser can resize while credentials, VPN, or SSH negotiation is awaiting. Apply
            // the latest observed geometry before the read pump starts so banners and full-screen
            // programs never render at the stale size originally passed to ConnectAsync.
            await pendingSession.ResizeAsync(_initialSize.Columns, _initialSize.Rows).ConfigureAwait(true);
            if (!IsAttemptCurrent(teardownGeneration))
            {
                await DisposeSessionInstanceSilentlyAsync(pendingSession).ConfigureAwait(true);
                return;
            }

            // Reset the page that is owned now, not the one captured when ConnectAsync began.
            // A recycled WebView may already belong to another VM; a detached connection instead
            // buffers output and resets whichever page eventually reattaches.
            var terminalReset = await TryResetCurrentTerminalRendererForNewSessionAsync(
                teardownGeneration,
                token).ConfigureAwait(true);
            if (!terminalReset.Succeeded ||
                !IsAttemptCurrent(teardownGeneration))
            {
                await DisposeSessionInstanceSilentlyAsync(pendingSession).ConfigureAwait(true);
                pendingSession = null;
                if (IsAttemptCurrent(teardownGeneration))
                {
                    await SafeDisposeSessionAsync().ConfigureAwait(true);
                }
                return;
            }
            var liveWebView = terminalReset.Renderer;

            lock (_terminalReplayLock)
            {
                _session = pendingSession;
                ResetReplayCheckpointUnderLock();
            }
            pendingSession = null;
            _terminalInputWriter = CreateTerminalInputWriter(_session);

            // Only a real teardown (tab close, Disconnect, Retry) cancels the token — a plain tab
            // switch does not. Honor a cancellation here so a tab closed mid-connect unwinds through
            // the OperationCanceledException handler.
            token.ThrowIfCancellationRequested();

            _session.DataReceived += OnSessionDataReceived;
            _session.Closed += OnSessionClosed;

            if (liveWebView is not null)
            {
                var bridge = CreateTerminalBridge(liveWebView);
                lock (_terminalReplayLock)
                {
                    RetireTerminalOutputSinkUnderLock(preserveSessionOutput: false);
                    _bridge = bridge;
                    _bridgeRendererIdentity = liveWebView;
                    _terminalFocusGeneration++;
                }
            }
            else
            {
                lock (_terminalReplayLock)
                {
                    _connectedWhileDetached = true;
                }
            }

            // Auto sudo: once the shell is up, run "sudo su" and feed the saved password at the
            // sudo prompt. Only meaningful with a stored password — key-only logins and "prompt
            // every time" connections have nothing to send, so the option isn't even offered.
            // Subscribe BEFORE Start() (same reason as above): the shell's first output is
            // usually its only output until we send input, so a driver that subscribes after the
            // read pump starts can miss it and never fire on a fast/local connection.
            if (profile.SshAutoSudo && _capturedCredentials?.Password is { Length: > 0 } sudoPassword)
            {
                _autoSudo = new SshAutoSudoDriver(_session, sudoPassword, _loggerFactory.CreateLogger<SshAutoSudoDriver>());
                _autoSudo.Start();
            }

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
                    if (!profile.IsEphemeral)
                    {
                        await _connectionRepo.UpdateHostFingerprintAsync(profile.NodeId, _session.HostFingerprint, token).ConfigureAwait(true);
                    }
                    if (!IsAttemptCurrent(teardownGeneration)) return;
                }
                catch (Exception ex)
                {
                    if (!IsAttemptCurrent(teardownGeneration)) return;
                    _logger.LogWarning(ex, "Could not persist host fingerprint for {Host}.", profile.Host);
                }
            }

            if (!IsAttemptCurrent(teardownGeneration)) return;
            // Guard against an immediate remote close (forced-command / EOF) while fingerprint
            // persistence was pending. OnSessionClosed keeps the tab Connecting while it drains
            // the final output; the focus helper rechecks session identity and IsClosing before
            // it can publish Connected.
            if (_session is { } connectedSession && Status == SessionStatus.Connecting)
            {
                if (!await CompleteConnectedAfterCurrentTerminalFocusAsync(
                        teardownGeneration,
                        connectedSession).ConfigureAwait(true))
                {
                    return;
                }
            }
        }
        catch (OperationCanceledException)
        {
            await HandleCancellationAsync().ConfigureAwait(true);
        }
        catch (SshHostKeyMismatchException ex)
        {
            if (!await CleanupPendingConnectArtifactsAndIsCurrentAsync().ConfigureAwait(true)) return;
            // Never auto-retry a host-key mismatch — it's a security decision the user must make.
            _lastConnectRetryable = false;
            await SafeDisposeSessionAsync().ConfigureAwait(true);
            ReportFailure(ex.Message);
            _logger.LogWarning("Host key mismatch for {Host}.", profile.Host);
        }
        catch (SshAuthenticationException ex)
        {
            if (!await CleanupPendingConnectArtifactsAndIsCurrentAsync().ConfigureAwait(true)) return;
            var endpointReachable = await ProbeSshEndpointAsync(profile, _tunnel, token).ConfigureAwait(true);
            if (!IsAttemptCurrent(teardownGeneration)) return;
            var failure = BuildAuthenticationFailure(profile, ex, endpointReachable);
            _lastConnectRetryable = failure.Retryable;
            await SafeDisposeSessionAsync().ConfigureAwait(true);
            ReportFailure(failure.Message);
        }
        catch (TunnelRecoverableNoticeException ex)
        {
            if (!await CleanupPendingConnectArtifactsAndIsCurrentAsync().ConfigureAwait(true)) return;
            // Not a failure: the tunnel did the right thing but needs a reconnect (e.g. Stormshield downloaded
            // a fresh profile spending the one-time code, or rejected a re-entered just-spent code). Present
            // it as a success/notice with a Reconnect affordance, not a red error. Not auto-retryable: it
            // needs fresh user input (a new one-time code), so silently retrying would just burn codes.
            _lastConnectRetryable = false;
            await SafeDisposeSessionAsync().ConfigureAwait(true);
            ReportNotice(ex.NoticeTitle, ex.Message);
            _logger.LogInformation(
                "Recoverable tunnel notice for {Host} ({Title}); awaiting a reconnect.", profile.Host, ex.NoticeTitle);
        }
        catch (Exception ex)
        {
            if (!await CleanupPendingConnectArtifactsAndIsCurrentAsync().ConfigureAwait(true)) return;
            await SafeDisposeSessionAsync().ConfigureAwait(true);
            ReportFailure(ex.Message);
            _logger.LogError(ex, "SSH connect failed for {Host}.", profile.Host);
        }
        finally
        {
            lock (_connectCompletionLock)
            {
                _connectInFlight = 0;
                if (ReferenceEquals(_activeConnectCompletion, connectCompletion.Task))
                {
                    _activeConnectCompletion = null;
                }
            }
            try
            {
                RetryCommand.NotifyCanExecuteChanged();
            }
            finally
            {
                connectCompletion.TrySetResult();
            }
        }
    }

    private bool IsAttemptCurrent(int teardownGeneration) =>
        Volatile.Read(ref _teardownGeneration) == teardownGeneration;

    private async Task<bool> CompleteConnectedAfterCurrentTerminalFocusAsync(
        int teardownGeneration,
        ISshSession connectedSession)
    {
        while (true)
        {
            ITerminalOutputSink? focusSink;
            long focusGeneration;
            object? focusRendererIdentity;
            lock (_terminalReplayLock)
            {
                if (!IsConnectionAwaitingTerminalFocusUnderLock(
                        teardownGeneration,
                        connectedSession))
                {
                    return false;
                }

                focusSink = _bridge;
                focusRendererIdentity = _bridgeRendererIdentity;
                focusGeneration = _terminalFocusGeneration;
            }

            try
            {
                var focused = await TerminalFocusBarrier.WaitAsync(
                    focusSink,
                    () => IsTerminalFocusSnapshotCurrent(
                        teardownGeneration,
                        connectedSession,
                        focusSink,
                        focusRendererIdentity,
                        focusGeneration)).ConfigureAwait(true);
                if (!focused)
                {
                    if (!IsConnectionAwaitingTerminalFocus(
                            teardownGeneration,
                            connectedSession))
                    {
                        return false;
                    }
                    continue;
                }
            }
            catch (Exception ex)
            {
                if (!IsTerminalFocusSnapshotCurrent(
                        teardownGeneration,
                        connectedSession,
                        focusSink,
                        focusRendererIdentity,
                        focusGeneration))
                {
                    if (!IsConnectionAwaitingTerminalFocus(
                            teardownGeneration,
                            connectedSession))
                    {
                        return false;
                    }
                    continue;
                }

                // Rejection means a replacement renderer owns recovery; it is an intentional no-op.
                await TryHandleTerminalRendererFailureAsync(
                    focusRendererIdentity,
                    "Failed to attach the terminal renderer: " + ex.Message)
                    .ConfigureAwait(true);
                return false;
            }

            if (TryPublishConnectedAfterTerminalFocus(
                    teardownGeneration,
                    connectedSession,
                    focusSink,
                    focusRendererIdentity))
            {
                return true;
            }
            if (!IsConnectionAwaitingTerminalFocus(
                    teardownGeneration,
                    connectedSession))
            {
                return false;
            }
        }
    }

    private bool IsConnectionAwaitingTerminalFocus(
        int teardownGeneration,
        ISshSession connectedSession)
    {
        lock (_terminalReplayLock)
        {
            return IsConnectionAwaitingTerminalFocusUnderLock(
                teardownGeneration,
                connectedSession);
        }
    }

    private bool IsConnectionAwaitingTerminalFocusUnderLock(
        int teardownGeneration,
        ISshSession connectedSession) =>
        IsAttemptCurrent(teardownGeneration) &&
        ReferenceEquals(connectedSession, _session) &&
        !connectedSession.IsClosing &&
        (_bridge is null ||
         ReferenceEquals(_bridgeRendererIdentity, _lastAttachedWebView)) &&
        Status == SessionStatus.Connecting;

    private bool IsTerminalFocusSnapshotCurrent(
        int teardownGeneration,
        ISshSession connectedSession,
        ITerminalOutputSink? focusSink,
        object? focusRendererIdentity,
        long focusGeneration)
    {
        lock (_terminalReplayLock)
        {
            return IsConnectionAwaitingTerminalFocusUnderLock(
                    teardownGeneration,
                    connectedSession) &&
                focusGeneration == _terminalFocusGeneration &&
                ReferenceEquals(focusSink, _bridge) &&
                ReferenceEquals(focusRendererIdentity, _bridgeRendererIdentity);
        }
    }

    private bool TryPublishConnectedAfterTerminalFocus(
        int teardownGeneration,
        ISshSession connectedSession,
        ITerminalOutputSink? focusSink,
        object? focusRendererIdentity)
    {
        lock (_terminalReplayLock)
        {
            if (!IsConnectionAwaitingTerminalFocusUnderLock(
                    teardownGeneration,
                    connectedSession) ||
                !ReferenceEquals(focusSink, _bridge) ||
                !ReferenceEquals(focusRendererIdentity, _bridgeRendererIdentity) ||
                (focusSink is not null &&
                 !ReferenceEquals(focusRendererIdentity, _lastAttachedWebView)))
            {
                return false;
            }
        }

        Progress.CompleteAll();
        Status = SessionStatus.Connected;
        StartRemoteOutputWaitTimer();
        // A reconnect earns its retry budget back only after this focused session remains stable.
        StartAutoReconnectStabilityTimer();
        return true;
    }

    private bool IsRendererBindingCurrent(CoreWebView2 renderer)
    {
        lock (_terminalReplayLock)
        {
            return ReferenceEquals(_webView, renderer) &&
                   ReferenceEquals(_lastAttachedWebView, renderer);
        }
    }

    private bool IsRendererBindingCurrent(
        int teardownGeneration,
        ISshSession session,
        CoreWebView2 renderer)
    {
        if (!IsAttemptCurrent(teardownGeneration)) return false;
        lock (_terminalReplayLock)
        {
            return ReferenceEquals(_session, session) &&
                   ReferenceEquals(_webView, renderer) &&
                   ReferenceEquals(_lastAttachedWebView, renderer);
        }
    }

    private bool IsTerminalAttachmentCurrent(
        int teardownGeneration,
        ISshSession session,
        ITerminalOutputSink sink,
        CoreWebView2 renderer)
    {
        if (!IsAttemptCurrent(teardownGeneration)) return false;
        lock (_terminalReplayLock)
        {
            return ReferenceEquals(_session, session) &&
                   ReferenceEquals(_bridge, sink) &&
                   ReferenceEquals(_webView, renderer) &&
                   ReferenceEquals(_lastAttachedWebView, renderer);
        }
    }

    private async Task<bool> ProbeSshEndpointAsync(
        ConnectionProfile profile,
        ITunnelInstance? tunnel,
        CancellationToken cancellationToken)
    {
        using var timeout = new CancellationTokenSource(AuthenticationFailureEndpointProbeTimeout);
        using var probeCts = CancellationTokenSource.CreateLinkedTokenSource(timeout.Token, cancellationToken);
        var probeToken = probeCts.Token;
        try
        {
            if (tunnel?.Socks5Endpoint is { } socksEndpoint)
            {
                await using var stream = await Socks5Client.ConnectAsync(
                    socksEndpoint,
                    profile.Host,
                    profile.Port,
                    probeToken).ConfigureAwait(true);
                return true;
            }

            using var client = new System.Net.Sockets.TcpClient();
            await client.ConnectAsync(profile.Host, profile.Port, probeToken).ConfigureAwait(true);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "SSH endpoint probe failed for {Host}:{Port}.", profile.Host, profile.Port);
            return false;
        }
    }

    internal readonly record struct SshConnectFailure(string Message, bool Retryable);

    internal static SshConnectFailure BuildAuthenticationFailure(
        ConnectionProfile profile,
        SshAuthenticationException exception,
        bool endpointReachable)
    {
        if (!endpointReachable)
        {
            return new(BuildEndpointUnavailableMessage(profile), Retryable: true);
        }

        return new(
            $"Authentication failed: {exception.Message} SSH server responded at {FormatEndpoint(profile)}; " +
            "if this VM is powered off, verify that the address or VPN route is reaching the expected machine.",
            Retryable: false);
    }

    internal static string BuildEndpointUnavailableMessage(ConnectionProfile profile) =>
        $"Could not reach SSH server at {FormatEndpoint(profile)}. " +
        "Check that the VM is powered on and that the host, port, and VPN route are correct.";

    private static string FormatEndpoint(ConnectionProfile profile)
    {
        var host = profile.Host.Contains(':') &&
            !profile.Host.StartsWith('[')
                ? $"[{profile.Host}]"
                : profile.Host;
        return $"{host}:{profile.Port}";
    }

    private async Task DisposeSessionInstanceSilentlyAsync(ISshSession? session)
    {
        if (session is null) return;
        try { await session.DisposeAsync().ConfigureAwait(true); }
        catch (Exception ex) { _logger.LogWarning(ex, "Error disposing stale SSH session."); }
    }

    private async Task DisposeTunnelInstanceSilentlyAsync(ITunnelInstance? tunnel)
    {
        if (tunnel is null) return;
        try { await tunnel.DisposeAsync().ConfigureAwait(true); }
        catch (Exception ex) { _logger.LogWarning(ex, "Error tearing down stale SSH session tunnel."); }
    }

    private void OnSessionDataReceived(object? sender, ReadOnlyMemory<byte> data)
    {
        if (data.Length == 0) return;
        var sourceSession = sender as ISshSession;
        var appended = false;
        lock (_terminalReplayLock)
        {
            // Session retirement and replacement use this same lock. Keeping identity validation,
            // MCP filtering, replay append, and sink delivery in one critical section prevents a
            // delayed old read callback from crossing teardown and contaminating the new terminal.
            if (!ReferenceEquals(sourceSession, _session)) return;

            var filtered = FilterMcpPresentation(data.Span);
            if (filtered is null)
            {
                AppendVisibleTerminalDataUnderLock(data);
                appended = true;
            }
            else if (filtered.Length > 0)
            {
                AppendVisibleTerminalDataUnderLock(filtered);
                appended = true;
            }
        }

        if (appended) NotifyVisibleOutputReceived(sourceSession);
    }

    private byte[]? FilterMcpPresentation(ReadOnlySpan<byte> data)
    {
        lock (_mcpPresentationLock)
        {
            var filter = _mcpPresentationFilter;
            if (filter is null) return null;
            if (!ReferenceEquals(_mcpPresentationSession, _session) ||
                _mcpPresentationGeneration != Volatile.Read(ref _teardownGeneration))
            {
                ClearMcpCommandPresentationUnderLock();
                return null;
            }

            var visible = filter.Filter(data);
            if (filter.IsComplete)
            {
                ClearMcpCommandPresentationUnderLock();
            }
            return visible;
        }
    }

    private async Task<(bool Succeeded, CoreWebView2? Renderer)>
        TryResetCurrentTerminalRendererForNewSessionAsync(
            int teardownGeneration,
            CancellationToken cancellationToken)
    {
        var renderer = GetCurrentRenderer();
        while (renderer is not null)
        {
            try
            {
                await TerminalBridge.ResetSessionlessAsync(
                    renderer,
                    cancellationToken: cancellationToken).ConfigureAwait(true);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                if (!IsAttemptCurrent(teardownGeneration))
                {
                    return (false, null);
                }

                var latestRenderer = GetCurrentRenderer();
                if (!ReferenceEquals(renderer, latestRenderer))
                {
                    // The page changed while its reset was pending. It may now belong to another
                    // tab/VM, so never post another message to it; retry only the current owner.
                    renderer = latestRenderer;
                    continue;
                }

                _logger.LogWarning(ex, "Could not reset the owned SSH terminal renderer.");
                RequestSessionlessRendererRecovery(
                    renderer,
                    teardownGeneration,
                    "The terminal renderer could not be reset for a clean SSH session.");
                return (false, null);
            }

            if (!IsAttemptCurrent(teardownGeneration))
            {
                return (false, null);
            }

            var currentRenderer = GetCurrentRenderer();
            if (ReferenceEquals(renderer, currentRenderer))
            {
                return (true, renderer);
            }
            renderer = currentRenderer;
        }

        // Connecting while the view is detached is supported. The eventual reattach performs
        // the reset before replaying this new session's complete buffered output.
        return (true, null);
    }

    private CoreWebView2? GetCurrentRenderer()
    {
        lock (_terminalReplayLock)
        {
            return _webView is { } renderer &&
                ReferenceEquals(renderer, _lastAttachedWebView)
                ? renderer
                : null;
        }
    }


    private void AppendVisibleTerminalDataUnderLock(ReadOnlyMemory<byte> data)
    {
        _replayHasOutput = true;
        _replayBuffer.Append(data.Span);
        // DetachView removes and disposes the sink under this same lock. A live sink either
        // accepts the complete chunk here, or the chunk becomes detached replay data.
        if (_bridge is null || !_bridge.TryAppendOutput(data))
        {
            _detachedReplayBuffer.Append(data.Span);
        }
    }

    private void NotifyVisibleOutputReceived(ISshSession? sourceSession)
    {
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
        // NB: output does NOT reset the auto-reconnect budget — a server that banners then immediately
        // closes would otherwise reset every cycle and reconnect forever. The budget resets only once a
        // connection stays up (AutoReconnectStabilityWindow); see StartAutoReconnectStabilityTimer.
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

    private void CancelRemoteOutputWaitTimer() => CancelTimer(ref _outputWaitCts);

    private async Task SafeDisposeSessionAsync(bool preserveTerminalOutput = false)
    {
        CancelRemoteOutputWaitTimer();
        // The session is going away, so stop any pending "stayed stable long enough" timer — a session
        // that drops before the window must NOT have its retry budget reset (that's what bounds a
        // flapping/banner-then-close server).
        CancelAutoReconnectStabilityTimer();
        IsWaitingForRemoteOutput = false;
        CancelAndDisposePrewarm();

        // Tear the Auto sudo driver down first so it unsubscribes from DataReceived before the
        // session is disposed (and drops its in-memory copy of the password).
        var autoSudo = _autoSudo;
        _autoSudo = null;
        autoSudo?.Dispose();

        ISshSession? session;
        TerminalInputWriter? inputWriter;
        ITunnelInstance? tunnel;
        lock (_terminalReplayLock)
        {
            // Keep MCP filter retirement atomic with session retirement. Both this path and filter
            // installation take replay -> presentation locks, so a stale continuation can neither
            // reinstall after this clear nor invert the lock order used by DataReceived. Flush any
            // speculative prefix first so timeout/teardown never erases real terminal bytes.
            FlushAndClearMcpCommandPresentationUnderLock();

            // Move every session-owned artifact out of global state before the first await. A slow
            // socket disposal can overlap a user Retry; its continuation must never clear or dispose
            // artifacts that already belong to the replacement session.
            RetireTerminalOutputSinkUnderLock(preserveSessionOutput: preserveTerminalOutput);
            inputWriter = _terminalInputWriter;
            _terminalInputWriter = null;
            session = _session;
            _session = null;
            tunnel = _tunnel;
            _tunnel = null;
            _capturedCredentials = null;
            _activeRoutedProfile = null;

            if (!preserveTerminalOutput)
            {
                _replayBuffer.Clear();
                _detachedReplayBuffer.Clear();
                _connectedWhileDetached = false;
                _sessionlessRendererRecoveryAttempted = false;
                ResetReplayCheckpointUnderLock();
            }
        }
        inputWriter?.Dispose();

        if (session is not null)
        {
            session.DataReceived -= OnSessionDataReceived;
            session.Closed -= OnSessionClosed;
            try { await session.DisposeAsync().ConfigureAwait(true); }
            catch (Exception ex) { _logger.LogWarning(ex, "Error disposing SSH session."); }
        }

        if (tunnel is not null)
        {
            try { await tunnel.DisposeAsync().ConfigureAwait(true); }
            catch (Exception ex) { _logger.LogWarning(ex, "Error tearing down session tunnel."); }
        }
    }

    // === MCP (AI agent) control ============================================
    //
    // The MCP server drives the SAME live shell the user sees ("Option B"). These methods are
    // invoked from MCP tool calls via IMcpSessionRegistry. _commandGate serializes agent
    // commands so two run_command calls can't interleave their sentinels; the user's own
    // keystrokes are unaffected (they flow through ISshSession's own write lock). _commandGate
    // is intentionally never disposed — same convention as SshSession._writeLock (it holds no
    // OS handle unless AvailableWaitHandle is touched, which we never do).
    private readonly SemaphoreSlim _commandGate = new(1, 1);

    // Memoized per-session consent. Computed lazily on the first agent action and cached for the
    // tab's life (sticky allow/deny). Memoizing the TASK — not a bool flag — means concurrent
    // first-touch tool calls await one shared approval dialog instead of racing two ContentDialogs
    // (WinUI throws if a second dialog opens while one is showing). All access is on the UI thread
    // (the registry marshals there before calling), so the ??= needs no lock.
    private Task<bool>? _mcpApprovalTask;

    /// <summary>
    /// Stable, process-unique id for this SSH tab. The MCP server uses it to address a live
    /// session across tool calls (a <see cref="ConnectionProfile.NodeId"/> can't — multiple
    /// tabs may share one saved connection). Generated once and never reused.
    /// </summary>
    public Guid McpId { get; } = Guid.NewGuid();

    /// <summary>
    /// Per-session consent gate. The first agent action shows an approval dialog; the decision is
    /// remembered for the tab's lifetime. MUST be called on the UI thread (shows a ContentDialog).
    /// Concurrent callers share the single in-flight approval task; a failed dialog isn't cached,
    /// so a later call re-asks.
    /// </summary>
    internal Task<bool> EnsureMcpApprovedAsync(IDialogService dialog)
    {
        if (_mcpApprovalTask is { } existing && !existing.IsFaulted && !existing.IsCanceled)
            return existing;
        return _mcpApprovalTask = AskMcpApprovalAsync(dialog);
    }

    private async Task<bool> AskMcpApprovalAsync(IDialogService dialog)
    {
        var connectionTitle = Profile is { } profile ? GetProfileTitle(profile) : "(unknown connection)";
        return await dialog.ConfirmAsync(
            "Allow AI agent control?",
            $"An AI agent is requesting control of the SSH session \"{connectionTitle}\".\n\n" +
            "If you allow it, the agent can run commands and send keystrokes in this session for " +
            "as long as the tab stays open. Allow?",
            "Allow", "Deny").ConfigureAwait(true);
    }

    /// <summary>True when a command can currently be dispatched to the live shell.</summary>
    internal bool IsMcpConnected => Status == SessionStatus.Connected && _session is not null;

    /// <summary>
    /// Runs a command on the live interactive shell and captures its output + exit code (Option B).
    /// Serialized per session via <see cref="_commandGate"/>.
    /// </summary>
    internal async Task<ShellCommandResult> RunCommandAsync(string command, TimeSpan timeout, CancellationToken cancellationToken)
    {
        if (_session is null || Status != SessionStatus.Connected)
            throw new InvalidOperationException("SSH session is not connected.");

        await _commandGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var session = _session;
            var lifecycleGeneration = Volatile.Read(ref _teardownGeneration);
            if (session is null || Status != SessionStatus.Connected)
                throw new InvalidOperationException("SSH session is not connected.");

            var runner = new ShellCommandRunner(session);
            try
            {
                return await runner.RunAsync(
                    command,
                    timeout,
                    1_000_000,
                    (invocation, token) => BeginMcpCommandPresentationAsync(
                        session,
                        lifecycleGeneration,
                        invocation,
                        token),
                    cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                ClearMcpCommandPresentation();
            }
        }
        finally
        {
            _commandGate.Release();
        }
    }

    private Task BeginMcpCommandPresentationAsync(
        ISshSession session,
        int lifecycleGeneration,
        ShellCommandInvocation invocation,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_terminalReplayLock)
        {
            EnsureMcpPresentationCurrentUnderLock(session, lifecycleGeneration);
            lock (_mcpPresentationLock)
            {
                _mcpPresentationFilter = new ShellCommandPresentationFilter(
                    invocation.Command,
                    invocation.Payload,
                    invocation.StartMarker,
                    invocation.EndMarkerPrefix);
                _mcpPresentationSession = session;
                _mcpPresentationGeneration = lifecycleGeneration;
            }
        }
        return Task.CompletedTask;
    }

    private void ClearMcpCommandPresentation()
    {
        ISshSession? sourceSession;
        bool appended;
        lock (_terminalReplayLock)
        {
            sourceSession = _mcpPresentationSession;
            appended = FlushAndClearMcpCommandPresentationUnderLock();
        }

        if (appended) NotifyVisibleOutputReceived(sourceSession);
    }

    private bool FlushAndClearMcpCommandPresentationUnderLock()
    {
        lock (_mcpPresentationLock)
        {
            var appended = false;
            var filter = _mcpPresentationFilter;
            if (filter is not null &&
                ReferenceEquals(_mcpPresentationSession, _session) &&
                _mcpPresentationGeneration == Volatile.Read(ref _teardownGeneration))
            {
                var pending = filter.DrainPending();
                if (pending.Length > 0)
                {
                    AppendVisibleTerminalDataUnderLock(pending);
                    appended = true;
                }
            }

            ClearMcpCommandPresentationUnderLock();
            return appended;
        }
    }

    private void ClearMcpCommandPresentationUnderLock()
    {
        _mcpPresentationFilter = null;
        _mcpPresentationSession = null;
        _mcpPresentationGeneration = -1;
    }

    private void EnsureMcpPresentationCurrentUnderLock(
        ISshSession session,
        int lifecycleGeneration)
    {
        if (!ReferenceEquals(_session, session) || !IsAttemptCurrent(lifecycleGeneration))
        {
            throw new InvalidOperationException(
                "SSH session changed while presenting the MCP command.");
        }
    }
    /// <summary>Writes raw text to the live shell exactly as if the user had typed it.</summary>
    internal async Task SendTextAsync(string text, CancellationToken cancellationToken)
    {
        var session = _session;
        if (session is null || Status != SessionStatus.Connected)
            throw new InvalidOperationException("SSH session is not connected.");
        await session.WriteAsync(System.Text.Encoding.UTF8.GetBytes(text), cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Snapshot of recent terminal output bytes (the replay ring buffer) for read_terminal.</summary>
    internal byte[] SnapshotTerminal() => _replayBuffer.Snapshot();

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
            // Reuse the shell's already-established tunnel (as a non-owning borrow) rather than
            // establishing a SECOND one. A second establish re-runs the tunnel provider — which, for an
            // OTP-interactive VPN (e.g. Stormshield Automatic+OTP), would pop a surprise second OTP prompt
            // and burn the code. Null when the profile uses no tunnel (direct SFTP, unchanged).
            tunnel = BorrowTunnelForSftp();
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

    /// <summary>
    /// Lends this session's live tunnel to a sibling SFTP session (pre-warm or the on-demand file-transfer
    /// path) as a non-owning <see cref="BorrowedTunnelInstance"/>, so SFTP routes through the same VPN
    /// without establishing a second tunnel (which would re-prompt for / burn another OTP on an interactive
    /// tunnel). Returns <c>null</c> when the session has no tunnel (direct connection). The borrow must NOT
    /// be disposed by the borrower — this session owns and disposes the real instance on disconnect.
    /// </summary>
    internal ITunnelInstance? BorrowTunnelForSftp() => _tunnel is null ? null : new BorrowedTunnelInstance(_tunnel);

    /// <summary>
    /// The profile a sibling SFTP session should use when it has to establish its own tunnel
    /// (the on-demand fallback when there's no live tunnel to borrow). It carries this
    /// connection's per-connect routing choice: if the terminal went direct, TunnelEnabled is
    /// false here so the file transfer also goes direct instead of silently establishing — and
    /// possibly OTP-prompting for — the VPN the user just declined. Falls back to the saved
    /// profile before the first connect resolves a route.
    /// </summary>
    internal ConnectionProfile? RoutedProfileForSubsession => _activeRoutedProfile ?? Profile;

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

    /// <summary>
    /// Test hook — sets the per-connect routed profile that <see cref="RoutedProfileForSubsession"/>
    /// reports to the SFTP fallback, without driving the WebView2-bound <c>ConnectAsync</c>. Pass
    /// null to simulate the post-teardown state (falls back to <see cref="SessionTabViewModel.Profile"/>).
    /// </summary>
    internal void PrimeRoutedProfileForTesting(ConnectionProfile? routed) => _activeRoutedProfile = routed;

    internal bool HasPrewarmedSftpForTesting()
    {
        lock (_prewarmLock) return _prewarmedSftpSession is not null;
    }

    internal bool HasInFlightPrewarmForTesting()
    {
        lock (_prewarmLock) return _prewarmCts is not null;
    }

    internal void UpdateTerminalSizeFromBridgeForTesting(
        ISshSession sourceSession,
        int sourceGeneration,
        TerminalSize size,
        bool geometryIsUncertain = false) =>
        UpdateTerminalSizeFromBridge(
            sourceSession, sourceGeneration, size, geometryIsUncertain);

    internal byte[]? CreateSessionlessReplaySnapshotForTesting(bool xtermIsFresh)
    {
        lock (_terminalReplayLock)
        {
            if (!TryCreateSessionlessReplaySnapshotUnderLock(xtermIsFresh, out var replay))
            {
                throw new InvalidOperationException(
                    "The exact sessionless terminal replay history is unavailable.");
            }
            return replay;
        }
    }
    internal byte[] PeekReplayBufferForTesting() => _replayBuffer.Snapshot();
    internal byte[] PeekDetachedReplayBufferForTesting() => _detachedReplayBuffer.Snapshot();
    internal Task AwaitPendingTerminalSinkRetirementForTestingAsync() =>
        AwaitPendingTerminalSinkRetirementAsync();

    internal void ClearTerminalReplayBuffersForTesting() => ClearTerminalReplayBuffers();

    internal void AttachTerminalOutputSinkForTesting(
        ITerminalOutputSink sink,
        object? rendererIdentity = null)
    {
        ArgumentNullException.ThrowIfNull(sink);
        lock (_terminalReplayLock)
        {
            RetireTerminalOutputSinkUnderLock(preserveSessionOutput: false);
            _bridge = sink;
            if (rendererIdentity is not null)
            {
                _lastAttachedWebView = rendererIdentity;
            }
            _bridgeRendererIdentity = rendererIdentity ?? _lastAttachedWebView;
            _terminalFocusGeneration++;
        }
    }

    internal void ReplayAndPublishTerminalOutputSinkForTesting(
        ITerminalOutputSink sink,
        byte[]? historicalReplay,
        byte[]? liveDetachedReplay)
    {
        ArgumentNullException.ThrowIfNull(sink);
        lock (_terminalReplayLock)
        {
            ReplayAndPublishTerminalOutputSinkUnderLock(
                sink,
                _lastAttachedWebView,
                historicalReplay,
                liveDetachedReplay);
        }
    }

    internal void ReportTerminalOutputTransportFailureForTesting(
        ITerminalOutputSink sourceSink,
        object rendererIdentity,
        string message) =>
        OnTerminalOutputTransportFailed(sourceSink, rendererIdentity, message);

    internal void ReportTerminalInputWriteFailureForTesting(Exception exception)
    {
        TerminalInputWriter? source;
        ISshSession? session;
        lock (_terminalReplayLock)
        {
            source = _terminalInputWriter;
            session = _session;
        }

        if (source is null || session is null)
        {
            throw new InvalidOperationException("A connected terminal input writer is required.");
        }

        OnTerminalInputWriteFailed(source, session, exception);
    }

    internal Task<bool> CompleteConnectedAfterCurrentTerminalFocusForTestingAsync()
    {
        var session = _session ??
            throw new InvalidOperationException("A connected SSH session is required.");
        return CompleteConnectedAfterCurrentTerminalFocusAsync(
            Volatile.Read(ref _teardownGeneration),
            session);
    }

    /// <summary>
    /// Lets a fake sink verify that TryAppendOutput runs inside the terminal replay critical
    /// section shared with DetachView. Monitor ownership is thread-specific, so another thread
    /// cannot cause a false positive.
    /// </summary>
    internal bool IsTerminalReplayLockHeldForTesting => Monitor.IsEntered(_terminalReplayLock);

    internal void RequestSessionlessRendererRecoveryForTesting(
        object rendererIdentity,
        string message) =>
        RequestSessionlessRendererRecovery(
            rendererIdentity,
            Volatile.Read(ref _teardownGeneration),
            message);
    internal void SetPendingRendererRecoveryForTesting(object rendererIdentity, string message)
    {
        lock (_terminalReplayLock)
        {
            _lastAttachedWebView = rendererIdentity;
            _pendingRendererRecoveryIdentity = rendererIdentity;
            _pendingRendererRecoveryMessage = message;
            _pendingRendererRecoverySourceSink = _bridge;
            _pendingRendererRecoveryGeneration = Volatile.Read(ref _teardownGeneration);
        }
    }

    internal void AppendReplayBufferForTesting(params byte[] data)
    {
        lock (_terminalReplayLock)
        {
            _replayHasOutput = true;
            _replayBuffer.Append(data);
        }
    }

    internal void SetConnectedWhileDetachedForTesting()
    {
        lock (_terminalReplayLock)
        {
            _connectedWhileDetached = true;
        }
    }

    internal (byte[]? HistoricalReplay, byte[]? LiveDetachedReplay)
        TakeReattachReplayPlanForTesting(bool xtermIsFresh)
    {
        lock (_terminalReplayLock)
        {
            if (!TryTakeReattachReplaySnapshotUnderLock(
                    xtermIsFresh,
                    out var historicalReplay,
                    out var liveDetachedReplay))
            {
                throw new InvalidOperationException("Terminal replay history is not an exact terminal-state checkpoint.");
            }
            return (historicalReplay, liveDetachedReplay);
        }
    }

    internal byte[]? TakeReattachReplaySnapshotForTesting(bool xtermIsFresh)
    {
        var (historicalReplay, liveDetachedReplay) =
            TakeReattachReplayPlanForTesting(xtermIsFresh);
        if (historicalReplay is null) return liveDetachedReplay;
        if (liveDetachedReplay is null) return historicalReplay;

        var combined = new byte[historicalReplay.Length + liveDetachedReplay.Length];
        historicalReplay.CopyTo(combined, 0);
        liveDetachedReplay.CopyTo(combined, historicalReplay.Length);
        return combined;
    }

    internal int AutoReconnectAttemptsForTesting => _autoReconnectAttempts;
    internal bool AutoReconnectInProgressForTesting => _autoReconnectCts is not null;
    internal bool ReconnectRequestedWhileDetachedForTesting => _reconnectRequestedWhileDetached;
    internal void SetConnectInFlightForTesting(int value)
    {
        lock (_connectCompletionLock)
        {
            _connectInFlight = value;
        }
    }

    internal void SetActiveConnectCompletionForTesting(Task? completion)
    {
        lock (_connectCompletionLock)
        {
            _activeConnectCompletion = completion;
        }
    }

    internal void SetAutoReconnectDelayForTesting(TimeSpan delay) => _autoReconnectDelay = delay;
    internal void SetAutoReconnectConnectOverrideForTesting(Func<Task>? connect) =>
        _autoReconnectConnectOverrideForTesting = connect;
    internal void StartConnectLifecycleForTesting() =>
        Interlocked.Increment(ref _teardownGeneration);
    internal void BeginAutoReconnectLoopForTesting() => BeginAutoReconnectLoop();

    // Shrink the stability window so a test can observe the budget reset without a 30s wait. Set this
    // BEFORE AttachConnectedSessionForTesting, which arms the timer.
    internal void SetAutoReconnectStabilityWindowForTesting(TimeSpan window) => _autoReconnectStabilityWindow = window;

    // Records the just-attached WebView2 (or any object identity in tests) and
    // returns whether it differs from the previous attach — used by AttachAsync
    // to decide whether to replay scrollback.
    internal bool RegisterAttachedWebView(object webView)
    {
        lock (_terminalReplayLock)
        {
            var isFresh = !ReferenceEquals(webView, _lastAttachedWebView);
            _lastAttachedWebView = webView;
            return isFresh;
        }
    }

    private void ReplayAndPublishTerminalOutputSinkUnderLock(
        ITerminalOutputSink newSink,
        object? rendererIdentity,
        byte[]? historicalReplay,
        byte[]? liveDetachedReplay)
    {
        var published = false;
        try
        {
            if (historicalReplay is { Length: > 0 })
            {
                // Side-effect-free q: replay bypasses the live-output pump. Keep this checkpoint
                // conservative until a focus ACK or exact x/flush/k retirement proves xterm parsed it.
                _replayHasUnacknowledgedOutput = true;
                newSink.Replay(historicalReplay, suppressTerminalResponses: true);
            }
            if (liveDetachedReplay is not null)
                newSink.Replay(liveDetachedReplay, suppressTerminalResponses: false);
            _bridge = newSink;
            _bridgeRendererIdentity = rendererIdentity;
            _terminalFocusGeneration++;
            published = true;
        }
        finally
        {
            if (!published)
            {
                try { newSink.Dispose(); }
                catch (Exception ex) { _logger.LogWarning(ex, "Error disposing an uncommitted terminal output sink."); }
            }
        }
    }

    private void RetireTerminalOutputSinkUnderLock(bool preserveSessionOutput)
    {
        _terminalFocusGeneration++;
        var sink = _bridge;
        var retiringRendererIdentity = _bridgeRendererIdentity;
        _bridge = null;
        _bridgeRendererIdentity = null;
        if (sink is null) return;

        if (ReferenceEquals(_pendingRendererRecoverySourceSink, sink))
        {
            ClearPendingRendererRecoveryUnderLock();
        }

        // RetireAsync seals output immediately but keeps the stream-scoped input/ACK listener
        // subscribed until xterm parses the complete accepted prefix. New session bytes are routed
        // to the detached buffer while this task runs.
        _terminalSinkRetirementIdentity = retiringRendererIdentity;
        _terminalSinkRetirement = CompleteTerminalSinkRetirementAsync(
            sink,
            preserveSessionOutput,
            Volatile.Read(ref _teardownGeneration));
    }

    private async Task CompleteTerminalSinkRetirementAsync(
        ITerminalOutputSink sink,
        bool preserveSessionOutput,
        int retirementGeneration)
    {
        TerminalOutputRetirement retirement;
        try
        {
            retirement = await sink.RetireAsync(
                TerminalBridgeRetirementTimeout).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            lock (_terminalReplayLock)
            {
                if (preserveSessionOutput && IsAttemptCurrent(retirementGeneration))
                {
                    _replayRetirementFailed = true;
                    _detachedReplayGeometryChanged = true;
                }
            }
            _logger.LogWarning(ex, "Error completing ordered terminal output retirement.");
            try { sink.DisposeAndTakePendingOutput(); }
            catch (Exception disposeException)
            {
                _logger.LogWarning(disposeException, "Error disposing failed terminal output retirement.");
            }
            return;
        }

        if (!preserveSessionOutput) return;
        lock (_terminalReplayLock)
        {
            // A Retry/Disconnect that started while retirement was waiting owns the replay state now.
            // Its teardown clears the old checkpoint, so a late result from this sink must be discarded.
            if (!IsAttemptCurrent(retirementGeneration)) return;
            // Sink publication waits for the preceding retirement, so this result is the exact
            // acknowledgement boundary for the current renderer. An exact x/flush/k retirement
            // clears the conservative historical q: marker; an inexact one requires reconstruction.
            _replayHasUnacknowledgedOutput = retirement.HadUnacknowledgedOutput;
            _detachedReplayGeometryChanged |= retirement.HadUncertainGeometry;
            if (retirement.UnpostedOutput.Length > 0)
            {
                // These bytes precede every chunk captured after _bridge became null.
                _detachedReplayBuffer.Prepend(retirement.UnpostedOutput);
            }
        }
    }

    private async Task AwaitPendingTerminalSinkRetirementAsync()
    {
        while (true)
        {
            Task pending;
            lock (_terminalReplayLock)
            {
                pending = _terminalSinkRetirement;
            }

            await pending.ConfigureAwait(true);
            lock (_terminalReplayLock)
            {
                if (ReferenceEquals(pending, _terminalSinkRetirement)) return;
            }
        }
    }

    private async Task RetireCurrentTerminalOutputSinkAsync(bool preserveSessionOutput)
    {
        lock (_terminalReplayLock)
        {
            RetireTerminalOutputSinkUnderLock(preserveSessionOutput);
        }
        await AwaitPendingTerminalSinkRetirementAsync().ConfigureAwait(true);
    }

    private void ConfirmRetiredTerminalOutputParsed(ITerminalOutputSink sink)
    {
        lock (_terminalReplayLock)
        {
            // A focus acknowledgement is queued behind every older host-to-page message. For a
            // same-page rebind it proves the retired bridge's in-flight frames were parsed.
            if (ReferenceEquals(_bridge, sink))
            {
                _replayHasUnacknowledgedOutput = false;
            }
        }
    }

    private bool TryTakeReattachReplaySnapshotUnderLock(
        bool xtermIsFresh,
        out byte[]? historicalReplay,
        out byte[]? liveDetachedReplay)
    {
        var replayFull = xtermIsFresh || _connectedWhileDetached;
        _connectedWhileDetached = false;
        historicalReplay = null;
        liveDetachedReplay = null;

        if (_replayRetirementFailed ||
            _replayHasUnacknowledgedOutput ||
            (_detachedReplayGeometryChanged && _replayHasOutput) ||
            _detachedReplayBuffer.HasTruncated ||
            (replayFull &&
             (_replayBuffer.HasTruncated ||
              (_replayHasOutput &&
               (_replayGeometryChanged || _initialSize != _replayGeometry)))))
        {
            return false;
        }

        if (!replayFull)
        {
            liveDetachedReplay = EmptyToNull(_detachedReplayBuffer.Drain());
            _detachedReplayGeometryChanged = false;
            return true;
        }

        var fullReplay = _replayBuffer.Snapshot();
        var detachedReplay = _detachedReplayBuffer.Snapshot();
        if (detachedReplay.Length > fullReplay.Length ||
            !fullReplay.AsSpan(fullReplay.Length - detachedReplay.Length)
                .SequenceEqual(detachedReplay))
        {
            return false;
        }

        var historicalLength = fullReplay.Length - detachedReplay.Length;
        historicalReplay = historicalLength == 0
            ? null
            : fullReplay.AsSpan(0, historicalLength).ToArray();
        liveDetachedReplay = EmptyToNull(detachedReplay);
        _detachedReplayBuffer.Clear();
        _detachedReplayGeometryChanged = false;
        return true;
    }

    private void ClearTerminalReplayBuffers()
    {
        lock (_terminalReplayLock)
        {
            ClearTerminalReplayBuffersUnderLock();
        }
    }

    private void ClearTerminalReplayBuffersUnderLock()
    {
        _replayBuffer.Clear();
        _detachedReplayBuffer.Clear();
        // Buffers are empty now — nothing pending to replay on the next attach.
        _connectedWhileDetached = false;
        _sessionlessRendererRecoveryAttempted = false;
        ResetReplayCheckpointUnderLock();
    }

    private void ResetReplayCheckpointUnderLock()
    {
        _replayGeometry = _initialSize;
        _replayHasOutput = false;
        _replayGeometryChanged = false;
        _detachedReplayGeometryChanged = false;
        _replayHasUnacknowledgedOutput = false;
        _replayRetirementFailed = false;
    }

    private static byte[]? EmptyToNull(byte[] data) => data.Length == 0 ? null : data;
}
