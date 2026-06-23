using System.Windows.Input;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using Microsoft.Web.WebView2.Core;
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

    private readonly ISerialSessionService _serialService;
    private readonly IAppSettingsService _settingsService;
    private readonly IConnectionProfileResolver _profileResolver;
    private readonly ILoggerFactory _loggerFactory;
    private readonly ILogger<SerialSessionViewModel> _logger;

    private ITerminalSession? _session;
    private TerminalBridge? _bridge;
    private CancellationTokenSource? _cts;
    private CoreWebView2? _webView;
    private object? _lastAttachedWebView;
    private TerminalSize _initialSize = TerminalSize.Default;
    private CancellationTokenSource? _outputWaitCts;
    private int _connectInFlight;
    private int _teardownGeneration;
    private bool _reconnectRequestedWhileDetached;
    private bool _connectedWhileDetached;

    private readonly TerminalReplayBuffer _replayBuffer = new(256 * 1024);

    public SerialSessionViewModel(
        ISerialSessionService serialService,
        IAppSettingsService settingsService,
        IConnectionProfileResolver profileResolver,
        ILoggerFactory loggerFactory)
    {
        _serialService = serialService;
        _settingsService = settingsService;
        _profileResolver = profileResolver;
        _loggerFactory = loggerFactory;
        _logger = loggerFactory.CreateLogger<SerialSessionViewModel>();
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
    public bool IsFailed => Status == SessionStatus.Failed;
    public string ConnectingMessage =>
        Profile is { Host.Length: > 0 } profile
            ? $"Opening {profile.Host}..."
            : "Opening serial port...";

    protected override void OnDispatchEnqueueFailed()
    {
        _logger.LogWarning("Failed to enqueue serial UI update; dispatcher queue may be shutting down.");
    }

    public async Task AttachAsync(CoreWebView2 webView, TerminalSize initialSize)
    {
        if (Profile is null)
            throw new InvalidOperationException("Initialize must be called before AttachAsync.");

        var xtermIsFresh = RegisterAttachedWebView(webView);
        _webView = webView;
        _initialSize = initialSize;
        EnsureDispatcher();

        if (_reconnectRequestedWhileDetached)
        {
            _reconnectRequestedWhileDetached = false;
            Status = SessionStatus.Connecting;
            Progress.Reset();
            TryClearTerminal(webView);
            await TearDownSessionAsync().ConfigureAwait(true);
            await ConnectAsync().ConfigureAwait(true);
            return;
        }

        if (_session is not null)
        {
            var replayNeeded = xtermIsFresh || _connectedWhileDetached;
            _connectedWhileDetached = false;
            var snapshot = replayNeeded ? _replayBuffer.Snapshot() : null;
            var oldBridge = _bridge;
            _bridge = CreateTerminalBridge(webView);
            oldBridge?.Dispose();
            if (snapshot is not null) _bridge.Replay(snapshot);
            await _session.ResizeAsync(initialSize.Columns, initialSize.Rows).ConfigureAwait(true);
            _bridge.RequestFocus();
            EnsureRemoteOutputWaitTimer();
            return;
        }

        if (Status == SessionStatus.Failed)
        {
            _logger.LogDebug("Serial attach: tab is Failed and sessionless; leaving Retry overlay up.");
            return;
        }

        await ConnectAsync().ConfigureAwait(true);
    }

    public event Action? InitializationRetryRequested;

    [RelayCommand(AllowConcurrentExecutions = false, CanExecute = nameof(CanRetry))]
    public async Task RetryAsync()
    {
        if (Volatile.Read(ref _connectInFlight) != 0) return;

        ErrorMessage = null;
        ResetOutputState();
        await RefreshProfileFromRepositoryAsync().ConfigureAwait(true);

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
        TryClearTerminal(_webView);
        await TearDownSessionAsync().ConfigureAwait(true);
        ErrorMessage = null;
        await ConnectAsync().ConfigureAwait(true);
    }

    private bool CanRetry() =>
        Status != SessionStatus.Connecting &&
        Volatile.Read(ref _connectInFlight) == 0;

    private async Task RefreshProfileFromRepositoryAsync()
    {
        var current = Profile;
        if (current is null) return;

        var refreshed = await _profileResolver.ResolveAsync(current.NodeId).ConfigureAwait(true);
        if (refreshed is null || refreshed.Protocol != Protocol) return;
        UpdateProfile(refreshed);
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
        await TearDownSessionAsync().ConfigureAwait(true);
        Progress.Reset();
        Status = SessionStatus.Disconnected;
    }

    private async Task TearDownSessionAsync()
    {
        Interlocked.Increment(ref _teardownGeneration);
        var cts = _cts;
        _cts = null;
        try { cts?.Cancel(); } catch { /* already disposed */ }
        await SafeDisposeSessionAsync().ConfigureAwait(true);
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
        if (Status == SessionStatus.Disconnected && _session is null && Volatile.Read(ref _connectInFlight) == 0)
        {
            Status = SessionStatus.Connecting;
        }
    }

    public void DetachView()
    {
        var bridge = _bridge;
        _bridge = null;
        if (bridge is not null)
        {
            try { bridge.Dispose(); }
            catch (Exception ex) { _logger.LogWarning(ex, "Error disposing serial TerminalBridge on view unload."); }
        }
        _webView = null;
    }

    private async Task ConnectAsync()
    {
        var profile = Profile;
        if (profile is null || _webView is null) return;
        if (Interlocked.CompareExchange(ref _connectInFlight, 1, 0) != 0) return;
        var teardownGeneration = Volatile.Read(ref _teardownGeneration);

        TryClearTerminal(_webView);
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
            pendingSession = await _serialService.ConnectAsync(profile, _initialSize, token).ConfigureAwait(true);
            if (!IsAttemptCurrent(teardownGeneration))
            {
                await DisposeSessionInstanceSilentlyAsync(pendingSession).ConfigureAwait(true);
                return;
            }

            _session = pendingSession;
            pendingSession = null;
            token.ThrowIfCancellationRequested();

            _session.DataReceived += OnSessionDataReceived;
            _session.Closed += OnSessionClosed;

            var liveWebView = _webView;
            if (liveWebView is not null)
            {
                _bridge = CreateTerminalBridge(liveWebView);
            }
            else
            {
                _connectedWhileDetached = true;
            }

            _session.Start();

            if (!IsAttemptCurrent(teardownGeneration)) return;
            if (_session is not null && Status == SessionStatus.Connecting)
            {
                Status = SessionStatus.Connected;
                _bridge?.RequestFocus();
                StartRemoteOutputWaitTimer();
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

    private TerminalBridge CreateTerminalBridge(CoreWebView2 view) =>
        new(view, _session!, _loggerFactory.CreateLogger<TerminalBridge>(), _settingsService);

    private async Task DisposeSessionInstanceSilentlyAsync(ITerminalSession? session)
    {
        if (session is null) return;
        try { await session.DisposeAsync().ConfigureAwait(true); }
        catch (Exception ex) { _logger.LogWarning(ex, "Error disposing stale serial session."); }
    }

    private void OnSessionClosed(object? sender, EventArgs e)
    {
        var closedSession = sender as ITerminalSession;
        MarshalToUi(async () =>
        {
            if (!ReferenceEquals(closedSession, _session)) return;
            if (Status == SessionStatus.Failed || Status == SessionStatus.Disconnected) return;
            await SafeDisposeSessionAsync().ConfigureAwait(true);
            if (Status == SessionStatus.Failed || Status == SessionStatus.Disconnected) return;
            ReportFailure("Serial session closed.");
        });
    }

    private void OnSessionDataReceived(object? sender, ReadOnlyMemory<byte> data)
    {
        if (data.Length == 0) return;
        var sourceSession = sender as ITerminalSession;
        if (!ReferenceEquals(sourceSession, _session)) return;
        AppendVisibleTerminalData(data, sourceSession);
    }

    private void AppendVisibleTerminalData(ReadOnlyMemory<byte> data, ITerminalSession? sourceSession = null)
    {
        if (data.Length == 0) return;
        _replayBuffer.Append(data.Span);
        _bridge?.AppendOutput(data);

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

    private async Task SafeDisposeSessionAsync()
    {
        CancelRemoteOutputWaitTimer();
        IsWaitingForRemoteOutput = false;

        var bridge = _bridge;
        _bridge = null;
        if (bridge is not null)
        {
            try { bridge.Dispose(); }
            catch (Exception ex) { _logger.LogWarning(ex, "Error disposing serial TerminalBridge."); }
        }

        var session = _session;
        _session = null;
        if (session is not null)
        {
            session.DataReceived -= OnSessionDataReceived;
            session.Closed -= OnSessionClosed;
            try { await session.DisposeAsync().ConfigureAwait(true); }
            catch (Exception ex) { _logger.LogWarning(ex, "Error disposing serial session."); }
        }

        _replayBuffer.Clear();
        _connectedWhileDetached = false;
    }

    private void TryClearTerminal(CoreWebView2 webView)
    {
        try
        {
            webView.PostWebMessageAsString("clear:");
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Suppressed exception while clearing xterm.js before serial connect.");
        }
    }

    internal bool RegisterAttachedWebView(object webView)
    {
        var isFresh = !ReferenceEquals(webView, _lastAttachedWebView);
        _lastAttachedWebView = webView;
        return isFresh;
    }
}
