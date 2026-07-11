using System.Windows.Input;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using Microsoft.Web.WebView2.Core;
using Wormhole.Helpers;
using Wormhole.Interop.Terminal;
using Wormhole.Models;
using Wormhole.Services;

namespace Wormhole.ViewModels.Sessions;

// See SshSessionViewModel for the DI-lifetime rationale: the bridge/session/CTS are torn
// down explicitly on tab close instead of making this transient VM IDisposable.
#pragma warning disable CA1001
public sealed partial class SerialSessionViewModel : SessionTabViewModel, ITerminalSessionViewModel
#pragma warning restore CA1001
{
    private static readonly TimeSpan RemoteOutputWaitDelay = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan RemoteCloseOutputFlushTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan TerminalBridgeRetirementTimeout = TimeSpan.FromSeconds(10);
    internal const int TerminalReplayCapacityBytes = 1024 * 1024;

    private readonly ISerialSessionService _serialService;
    private readonly IAppSettingsService _settingsService;
    private readonly IConnectionProfileResolver _profileResolver;
    private readonly ILoggerFactory _loggerFactory;
    private readonly ILogger<SerialSessionViewModel> _logger;

    private ITerminalSession? _session;
    private ITerminalOutputSink? _bridge;
    private object? _bridgeRendererIdentity;
    private long _terminalFocusGeneration;
    private TerminalInputWriter? _terminalInputWriter;
    private CancellationTokenSource? _cts;
    private CoreWebView2? _webView;
    private object? _lastAttachedWebView;
    private TerminalSize _initialSize = TerminalSize.Default;
    private CancellationTokenSource? _outputWaitCts;
    private int _connectInFlight;
    private int _teardownGeneration;
    private bool _reconnectRequestedWhileDetached;
    private bool _suppressAutoConnectOnReattach;
    private bool _connectedWhileDetached;

    private readonly TerminalReplayBuffer _replayBuffer = new(TerminalReplayCapacityBytes);
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

    public SerialSessionViewModel(
        ISerialSessionService serialService,
        IAppSettingsService settingsService,
        IConnectionProfileResolver profileResolver,
        ILoggerFactory loggerFactory)
    {
        _serialService = serialService;
        _settingsService = settingsService;
        _profileResolver = profileResolver;
        _loggerFactory = loggerFactory is NonThrowingLoggerFactory
            ? loggerFactory
            : new NonThrowingLoggerFactory(loggerFactory);
        _logger = _loggerFactory.CreateLogger<SerialSessionViewModel>();
        PropertyChanged += (_, args) =>
        {
            if (args.PropertyName == nameof(Status))
            {
                OnPropertyChanged(nameof(IsConnecting));
                OnPropertyChanged(nameof(IsConnected));
                OnPropertyChanged(nameof(IsDisconnected));
                OnPropertyChanged(nameof(IsFailed));
                RetryCommand.NotifyCanExecuteChanged();
            }
        };
    }

    public override ProtocolType Protocol => ProtocolType.Serial;

    public override ICommand? ReconnectCommand => RetryCommand;

    [ObservableProperty]
    private string? errorMessage;

    [ObservableProperty]
    private bool isRecoverableNotice;

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
    public string ConnectingMessage =>
        Profile is { Host.Length: > 0 } profile
            ? $"Opening {profile.Host}..."
            : "Opening serial port...";

    protected override void OnDispatchEnqueueFailed()
    {
        _logger.LogWarning("Failed to enqueue serial UI update; dispatcher queue may be shutting down.");
    }

    public void UpdateTerminalSize(TerminalSize size) =>
        UpdateTerminalSizeCore(size, sourceSession: null, sourceGeneration: null, geometryIsUncertain: false);

    private void UpdateTerminalSizeFromBridge(
        ITerminalSession sourceSession,
        int sourceGeneration,
        TerminalSize size,
        bool geometryIsUncertain) =>
        UpdateTerminalSizeCore(size, sourceSession, sourceGeneration, geometryIsUncertain);

    private void UpdateTerminalSizeCore(
        TerminalSize size,
        ITerminalSession? sourceSession,
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

        var xtermIsFresh = RegisterAttachedWebView(webView);
        _webView = webView;
        if (xtermIsFresh)
        {
            UpdateTerminalSize(initialSize);
        }
        EnsureDispatcher();

        await AwaitPendingTerminalSinkRetirementAsync().ConfigureAwait(true);
        if (!IsRendererBindingCurrent(webView)) return;

        if (_session is null)
        {
            if (!await RestoreSessionlessTerminalAsync(
                    webView,
                    xtermIsFresh).ConfigureAwait(true))
            {
                return;
            }
        }

        if (_reconnectRequestedWhileDetached)
        {
            _reconnectRequestedWhileDetached = false;
            Status = SessionStatus.Connecting;
            Progress.Reset();
            var reconnectGeneration = await TearDownSessionAsync().ConfigureAwait(true);
            if (!IsAttemptCurrent(reconnectGeneration)) return;
            await ConnectAsync().ConfigureAwait(true);
            return;
        }

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
                // Rejection means a replacement renderer owns recovery; it is an intentional no-op.
                await TryHandleTerminalRendererFailureAsync(
                    webView,
                    "The terminal view was recreated after its exact replay history expired. " +
                    "The serial session was closed to avoid corrupting terminal state; retry to reconnect.")
                    .ConfigureAwait(true);
                return;
            }

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
                if (xtermIsFresh)
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
            return;
        }

        if (ShouldDeferAutoConnectOnReattach())
        {
            _logger.LogDebug("Serial attach: sessionless tab is waiting for explicit reconnect; leaving its overlay up.");
            return;
        }

        await ConnectAsync().ConfigureAwait(true);
    }

    internal bool ShouldDeferAutoConnectOnReattach() =>
        Status == SessionStatus.Failed ||
        _suppressAutoConnectOnReattach;
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

        ErrorMessage = null;
        ResetOutputState();
        if (!await RefreshProfileFromRepositoryAsync(retryGeneration).ConfigureAwait(true) ||
            !IsAttemptCurrent(retryGeneration))
        {
            return;
        }
        _suppressAutoConnectOnReattach = false;

        if (_webView is null)
        {
            var handler = InitializationRetryRequested;
            if (handler is not null)
            {
                Status = SessionStatus.Connecting;
                handler();
            }
            else
            {
                _reconnectRequestedWhileDetached = true;
            }
            return;
        }

        Status = SessionStatus.Connecting;
        Progress.Reset();
        var reconnectGeneration = await TearDownSessionAsync().ConfigureAwait(true);
        if (!IsAttemptCurrent(reconnectGeneration)) return;
        ErrorMessage = null;
        await ConnectAsync().ConfigureAwait(true);
    }

    private bool CanRetry() =>
        Status != SessionStatus.Connecting &&
        Volatile.Read(ref _connectInFlight) == 0;

    private async Task<bool> RefreshProfileFromRepositoryAsync(int lifecycleGeneration)
    {
        var current = Profile;
        if (current is null) return IsAttemptCurrent(lifecycleGeneration);

        var refreshed = await _profileResolver.ResolveAsync(current.NodeId).ConfigureAwait(true);
        if (!IsAttemptCurrent(lifecycleGeneration)) return false;
        if (refreshed is not null && refreshed.Protocol == Protocol)
        {
            UpdateProfile(refreshed);
        }
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
        _reconnectRequestedWhileDetached = false;
        _suppressAutoConnectOnReattach = true;
        var teardownGeneration = await TearDownSessionAsync().ConfigureAwait(true);
        if (!IsAttemptCurrent(teardownGeneration)) return;
        Progress.Reset();
        Status = SessionStatus.Disconnected;
    }

    private async Task<int> TearDownSessionAsync(bool preserveTerminalOutput = false)
    {
        var teardownGeneration = Interlocked.Increment(ref _teardownGeneration);
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

    private async Task ConnectAsync()
    {
        var profile = Profile;
        var connectingWebView = _webView;
        if (_suppressAutoConnectOnReattach || profile is null || connectingWebView is null) return;
        if (Interlocked.CompareExchange(ref _connectInFlight, 1, 0) != 0) return;
        // Starting a new connection defines a new lifecycle episode. This invalidates any
        // delayed teardown continuation from the previous transport before it can report or clear state.
        var teardownGeneration = Interlocked.Increment(ref _teardownGeneration);

        Status = SessionStatus.Connecting;
        ErrorMessage = null;
        IsRecoverableNotice = false;
        ResetOutputState();
        Progress.Reset();

        var cts = new CancellationTokenSource();
        _cts = cts;
        var token = cts.Token;
        ITerminalSession? pendingSession = null;

        async Task<bool> CleanupPendingConnectArtifactsAndIsCurrentAsync()
        {
            await DisposeSessionInstanceSilentlyAsync(pendingSession).ConfigureAwait(true);
            return IsAttemptCurrent(teardownGeneration);
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

            ClearTerminalReplayBuffers();
            pendingSession = await _serialService.ConnectAsync(profile, _initialSize, token).ConfigureAwait(true);
            if (!IsAttemptCurrent(teardownGeneration))
            {
                await DisposeSessionInstanceSilentlyAsync(pendingSession).ConfigureAwait(true);
                return;
            }

            await pendingSession.ResizeAsync(_initialSize.Columns, _initialSize.Rows).ConfigureAwait(true);
            if (!IsAttemptCurrent(teardownGeneration))
            {
                await DisposeSessionInstanceSilentlyAsync(pendingSession).ConfigureAwait(true);
                return;
            }

            var terminalReset = await TryResetCurrentTerminalRendererForNewSessionAsync(
                teardownGeneration,
                token).ConfigureAwait(true);
            if (!terminalReset.Succeeded ||
                !IsAttemptCurrent(teardownGeneration))
            {
                await DisposeSessionInstanceSilentlyAsync(pendingSession).ConfigureAwait(true);
                pendingSession = null;
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

            _session.Start();

            if (!IsAttemptCurrent(teardownGeneration)) return;
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
            if (!await CleanupPendingConnectArtifactsAndIsCurrentAsync().ConfigureAwait(true)) return;
            await SafeDisposeSessionAsync().ConfigureAwait(true);
            Progress.Reset();
            Status = SessionStatus.Disconnected;
        }
        catch (Exception ex)
        {
            if (!await CleanupPendingConnectArtifactsAndIsCurrentAsync().ConfigureAwait(true)) return;
            await SafeDisposeSessionAsync().ConfigureAwait(true);
            ReportFailure(ex.Message);
            _logger.LogError(ex, "Serial connect failed for {PortName}.", profile.Host);
        }
        finally
        {
            Interlocked.Exchange(ref _connectInFlight, 0);
            RetryCommand.NotifyCanExecuteChanged();
        }
    }

    private bool IsAttemptCurrent(int teardownGeneration) =>
        Volatile.Read(ref _teardownGeneration) == teardownGeneration;

    private async Task<bool> CompleteConnectedAfterCurrentTerminalFocusAsync(
        int teardownGeneration,
        ITerminalSession connectedSession)
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
        ITerminalSession connectedSession)
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
        ITerminalSession connectedSession) =>
        IsAttemptCurrent(teardownGeneration) &&
        ReferenceEquals(connectedSession, _session) &&
        !connectedSession.IsClosing &&
        (_bridge is null ||
         ReferenceEquals(_bridgeRendererIdentity, _lastAttachedWebView)) &&
        Status == SessionStatus.Connecting;

    private bool IsTerminalFocusSnapshotCurrent(
        int teardownGeneration,
        ITerminalSession connectedSession,
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
        ITerminalSession connectedSession,
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

        Status = SessionStatus.Connected;
        StartRemoteOutputWaitTimer();
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
        ITerminalSession session,
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
        ITerminalSession session,
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

    private TerminalBridge CreateTerminalBridge(CoreWebView2 view)
    {
        var sourceSession = _session ??
            throw new InvalidOperationException("A live serial session is required for the terminal bridge.");
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

    private TerminalInputWriter CreateTerminalInputWriter(ITerminalSession session)
    {
        TerminalInputWriter? writer = null;
        writer = new TerminalInputWriter(
            payload => session.WriteAsync(payload),
            exception => OnTerminalInputWriteFailed(writer, session, exception));
        return writer;
    }

    private void OnTerminalInputWriteFailed(
        TerminalInputWriter? source,
        ITerminalSession session,
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

        _logger.LogError(exception, "Serial terminal input writer failed.");
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
                ReportFailure("Serial terminal input failed: " + exception.Message);
            }
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
            _logger.LogWarning(ex, "Could not request serial terminal renderer recreation.");
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

    private async Task DisposeSessionInstanceSilentlyAsync(ITerminalSession? session)
    {
        if (session is null) return;
        try { await session.DisposeAsync().ConfigureAwait(true); }
        catch (Exception ex) { _logger.LogWarning(ex, "Error disposing stale serial session."); }
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
                "Could not reconstruct preserved serial output because its exact history or geometry expired.");
            if (Status != SessionStatus.Disconnected)
            {
                ReportFailure(
                    "The final serial output could not be restored exactly. Reconnect to start a clean session.");
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
            _logger.LogWarning(ex, "Could not render preserved output from the closed serial session.");
            if (IsAttemptCurrent(restoreGeneration) &&
                _session is null &&
                ReferenceEquals(webView, _webView))
            {
                RequestSessionlessRendererRecovery(
                    webView,
                    restoreGeneration,
                    "The terminal renderer could not restore the final serial output.");
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
        ITerminalSession? closedSession,
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
                    "Timed out preserving terminal output before the serial session closed.");
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
                    "Could not confirm terminal output delivery before the serial session closed.");
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
                    continue;
                }
            }

            if (!flushed)
            {
                _logger.LogWarning(
                    "Terminal output could not be acknowledged before the serial session closed; " +
                    "unposted bytes will be retained in the replay checkpoint.");
            }
            return;
        }
    }

    private void OnSessionClosed(object? sender, EventArgs e)
    {
        var closedSession = sender as ITerminalSession;
        MarshalToUi(async () =>
        {
            if (!ReferenceEquals(closedSession, _session)) return;
            if (Status == SessionStatus.Failed || Status == SessionStatus.Disconnected) return;
            var closeGeneration = Volatile.Read(ref _teardownGeneration);
            var outputDeadline = Environment.TickCount64 +
                (long)RemoteCloseOutputFlushTimeout.TotalMilliseconds;
            Status = SessionStatus.Connecting;
            await FlushTerminalOutputBeforeRemoteCloseAsync(
                closedSession,
                closeGeneration,
                outputDeadline).ConfigureAwait(true);
            if (!IsAttemptCurrent(closeGeneration) || !ReferenceEquals(closedSession, _session)) return;

            await SafeDisposeSessionAsync(preserveTerminalOutput: true).ConfigureAwait(true);
            if (!IsAttemptCurrent(closeGeneration) || _session is not null) return;
            // Retiring the bridge is intentionally asynchronous: it remains subscribed until xterm
            // parses every accepted frame and emits any terminal response. Await the latest published
            // retirement before a sessionless clear/replay so no stale d: frame can follow its q: data.
            await AwaitPendingTerminalSinkRetirementAsync().ConfigureAwait(true);
            if (!IsAttemptCurrent(closeGeneration) || _session is not null) return;
            var remainingOutputBudget = TimeSpan.FromMilliseconds(
                outputDeadline - Environment.TickCount64);
            if (_webView is { } closedSessionWebView)
            {
                if (!await RestoreSessionlessTerminalAsync(
                        closedSessionWebView,
                        xtermIsFresh: false,
                        remainingOutputBudget).ConfigureAwait(true))
                {
                    return;
                }
                if (!IsAttemptCurrent(closeGeneration) || _session is not null) return;
            }
            if (Status == SessionStatus.Failed || Status == SessionStatus.Disconnected) return;
            ReportFailure("Serial session closed.");
        });
    }

    private void OnSessionDataReceived(object? sender, ReadOnlyMemory<byte> data)
    {
        if (data.Length == 0) return;
        var sourceSession = sender as ITerminalSession;
        lock (_terminalReplayLock)
        {
            if (!ReferenceEquals(sourceSession, _session)) return;
            AppendVisibleTerminalDataUnderLock(data);
        }

        NotifyVisibleOutputReceived(sourceSession);
    }

    private void AppendVisibleTerminalDataUnderLock(ReadOnlyMemory<byte> data)
    {
        _replayHasOutput = true;
        _replayBuffer.Append(data.Span);
        if (_bridge is null || !_bridge.TryAppendOutput(data))
        {
            _detachedReplayBuffer.Append(data.Span);
        }
    }

    private void NotifyVisibleOutputReceived(ITerminalSession? sourceSession)
    {
        if (HasReceivedOutput) return;
        MarshalToUi(() => MarkOutputReceived(sourceSession));
    }

    private void MarkOutputReceived(ITerminalSession? sourceSession)
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

    private void CancelRemoteOutputWaitTimer() => CancelTimer(ref _outputWaitCts);

    private static void CancelTimer(ref CancellationTokenSource? cts)
    {
        var local = cts;
        cts = null;
        if (local is null) return;
        try { local.Cancel(); }
        catch (ObjectDisposedException) { /* already disposed */ }
    }

    private async Task SafeDisposeSessionAsync(bool preserveTerminalOutput = false)
    {
        CancelRemoteOutputWaitTimer();
        IsWaitingForRemoteOutput = false;

        ITerminalSession? session;
        TerminalInputWriter? inputWriter;
        lock (_terminalReplayLock)
        {
            // Publish retirement and clear only old-session state before awaiting a possibly slow
            // COM driver close. A concurrent Retry may install a replacement while that close runs.
            RetireTerminalOutputSinkUnderLock(preserveSessionOutput: preserveTerminalOutput);
            inputWriter = _terminalInputWriter;
            _terminalInputWriter = null;
            session = _session;
            _session = null;

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
            catch (Exception ex) { _logger.LogWarning(ex, "Error disposing serial session."); }
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
                    renderer = latestRenderer;
                    continue;
                }

                _logger.LogWarning(ex, "Could not reset the owned serial terminal renderer.");
                RequestSessionlessRendererRecovery(
                    renderer,
                    teardownGeneration,
                    "The serial terminal renderer could not be reset for a clean session.");
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
                catch (Exception ex) { _logger.LogWarning(ex, "Error disposing an uncommitted serial terminal output sink."); }
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
            _logger.LogWarning(ex, "Error completing ordered serial terminal output retirement.");
            try { sink.DisposeAndTakePendingOutput(); }
            catch (Exception disposeException)
            {
                _logger.LogWarning(disposeException, "Error disposing failed serial terminal output retirement.");
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
            _replayBuffer.Clear();
            _detachedReplayBuffer.Clear();
            _connectedWhileDetached = false;
            _sessionlessRendererRecoveryAttempted = false;
            ResetReplayCheckpointUnderLock();
        }
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

    internal Task<bool> CompleteConnectedAfterCurrentTerminalFocusForTestingAsync()
    {
        var session = _session ??
            throw new InvalidOperationException("A connected serial session is required.");
        return CompleteConnectedAfterCurrentTerminalFocusAsync(
            Volatile.Read(ref _teardownGeneration),
            session);
    }

    internal void AttachConnectedSessionForTesting(ITerminalSession session)
    {
        Interlocked.Increment(ref _teardownGeneration);
        ResetOutputState();
        ClearTerminalReplayBuffers();
        if (_session is not null)
        {
            _session.DataReceived -= OnSessionDataReceived;
            _session.Closed -= OnSessionClosed;
        }

        _terminalInputWriter?.Dispose();
        lock (_terminalReplayLock)
        {
            _session = session;
            ResetReplayCheckpointUnderLock();
        }
        _terminalInputWriter = CreateTerminalInputWriter(session);
        session.DataReceived += OnSessionDataReceived;
        session.Closed += OnSessionClosed;
        Status = SessionStatus.Connected;
    }
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
        ITerminalSession? session;
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

    internal void AppendTerminalOutputForTesting(params byte[] data)
    {
        lock (_terminalReplayLock)
        {
            AppendVisibleTerminalDataUnderLock(data);
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

    internal void UpdateTerminalSizeFromBridgeForTesting(
        ITerminalSession sourceSession,
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

    internal void SetConnectedWhileDetachedForTesting()
    {
        lock (_terminalReplayLock)
        {
            _connectedWhileDetached = true;
        }
    }

    internal bool RegisterAttachedWebView(object webView)
    {
        lock (_terminalReplayLock)
        {
            var isFresh = !ReferenceEquals(webView, _lastAttachedWebView);
            _lastAttachedWebView = webView;
            return isFresh;
        }
    }
}
