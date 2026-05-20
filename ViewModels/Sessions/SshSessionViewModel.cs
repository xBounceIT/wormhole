using System;
using System.Threading;
using System.Threading.Tasks;
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
    private readonly ISshSessionService _sshService;
    private readonly ISshCredentialResolver _credentialResolver;
    private readonly IConnectionRepository _connectionRepo;
    private readonly ILoggerFactory _loggerFactory;
    private readonly ILogger<SshSessionViewModel> _logger;

    private ISshSession? _session;
    private TerminalBridge? _bridge;
    private CancellationTokenSource? _cts;
    private CoreWebView2? _webView;
    private Microsoft.UI.Dispatching.DispatcherQueue? _uiDispatcher;
    private string? _initialKnownFingerprint;
    private TerminalSize _initialSize = TerminalSize.Default;
    private int _connectInFlight;

    public SshSessionViewModel(
        ISshSessionService sshService,
        ISshCredentialResolver credentialResolver,
        IConnectionRepository connectionRepo,
        ILoggerFactory loggerFactory)
    {
        _sshService = sshService;
        _credentialResolver = credentialResolver;
        _connectionRepo = connectionRepo;
        _loggerFactory = loggerFactory;
        _logger = loggerFactory.CreateLogger<SshSessionViewModel>();
        PropertyChanged += (_, args) =>
        {
            if (args.PropertyName == nameof(Status))
            {
                OnPropertyChanged(nameof(IsConnecting));
                OnPropertyChanged(nameof(IsConnected));
                OnPropertyChanged(nameof(IsFailed));
            }
        };
    }

    public override ProtocolType Protocol => ProtocolType.Ssh;

    [ObservableProperty]
    private string? errorMessage;

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

        _webView = webView;
        _initialSize = initialSize;
        // AttachAsync is called from the UI thread (SshTerminalView's ready handler);
        // capture the dispatcher now so background callbacks (Closed) can marshal back.
        _uiDispatcher ??= Microsoft.UI.Dispatching.DispatcherQueue.GetForCurrentThread();

        // Navigating away from Sessions and back rebuilds the tab content (new
        // UserControl + WebView2) while the VM stays alive in ShellViewModel.Tabs. Skip the
        // expensive credential prompt + SSH connect; just rebind the bridge to the new
        // WebView and resync the geometry. The terminal scrollback is lost (xterm.js is
        // fresh) but typing/output continue to work on the same SSH session. We don't
        // re-call Start() — the pump was already running from the first connect.
        if (_session is not null)
        {
            var oldBridge = _bridge;
            _bridge = new TerminalBridge(webView, _session, _loggerFactory.CreateLogger<TerminalBridge>());
            oldBridge?.Dispose();
            await _session.ResizeAsync(initialSize.Columns, initialSize.Rows).ConfigureAwait(true);
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

    [RelayCommand]
    public async Task RetryAsync()
    {
        ErrorMessage = null;
        if (_webView is null)
        {
            InitializationRetryRequested?.Invoke();
            return;
        }
        await DetachAsync().ConfigureAwait(true);
        ErrorMessage = null;
        await ConnectAsync().ConfigureAwait(true);
    }

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
        ErrorMessage = message;
        Status = SessionStatus.Failed;
    }

    private void OnSessionClosed(object? sender, EventArgs e)
    {
        // Fired from the SSH read-pump thread; marshal to the captured UI dispatcher
        // before touching observable properties or disposing the session.
        var dispatcher = _uiDispatcher;
        if (dispatcher is null) return;
        dispatcher.TryEnqueue(async () =>
        {
            // _session being null means we've already disposed (consumer-initiated
            // tear-down ran first). Failed/Disconnected from a prior path also means
            // we're already in the right terminal state. Otherwise: tear down the
            // dead transport and surface the failure overlay. Status==Connecting can
            // happen if the server immediately closes the shell after auth (e.g.
            // forced-command accounts).
            if (_session is null) return;
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
        var webView = _webView;
        if (profile is null || webView is null) return;
        if (Interlocked.CompareExchange(ref _connectInFlight, 1, 0) != 0) return;

        Status = SessionStatus.Connecting;
        ErrorMessage = null;
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
            // Subscribe BEFORE Start() so we don't miss a Closed that fires immediately
            // (forced-command accounts, EOF-on-connect, etc.).
            _session.Closed += OnSessionClosed;
            _bridge = new TerminalBridge(webView, _session, _loggerFactory.CreateLogger<TerminalBridge>());
            _session.Start();

            // Mirror SshHostKeyValidator.Decide which treats null *and* empty as unpinned —
            // otherwise a profile with SshKnownHostFingerprint == "" (e.g. from imported
            // data) would never pin and continue to TOFU-accept on every reconnect.
            if (string.IsNullOrEmpty(_initialKnownFingerprint) && _session is SshSession concrete && !string.IsNullOrEmpty(concrete.HostFingerprint))
            {
                // Pin the captured fingerprint on the in-memory profile *before* any retry so a
                // disconnect/reconnect inside this tab actually validates against it instead of
                // TOFU-accepting whatever the server presents.
                profile = profile with { SshKnownHostFingerprint = concrete.HostFingerprint };
                Profile = profile;
                _initialKnownFingerprint = concrete.HostFingerprint;
                try
                {
                    await _connectionRepo.UpdateHostFingerprintAsync(profile.NodeId, concrete.HostFingerprint, token).ConfigureAwait(true);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Could not persist host fingerprint for {Host}.", profile.Host);
                }
            }

            Status = SessionStatus.Connected;
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

    private async Task SafeDisposeSessionAsync()
    {
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
            try { await session.DisposeAsync().ConfigureAwait(true); }
            catch (Exception ex) { _logger.LogWarning(ex, "Error disposing SSH session."); }
        }
    }
}
