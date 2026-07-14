using System.Collections.Immutable;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MarcusW.VncClient.Rendering;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.UI.Dispatching;
using Wormhole.Data.Repositories;
using Wormhole.Models;
using Wormhole.Services;
using Wormhole.Services.Bitwarden;
using Wormhole.Services.Tunneling;
using VncScreen = MarcusW.VncClient.Screen;
using VncSize = MarcusW.VncClient.Size;

namespace Wormhole.ViewModels.Sessions;

public sealed partial class VncSessionViewModel : SessionTabViewModel
{
    private readonly IVncSessionService _vncService;
    private readonly ICredentialPasswordResolver _passwordResolver;
    private readonly IBitwardenCredentialCatalogService _credentialCatalog;
    private readonly IDialogService _dialog;
    private readonly TunnelManager _tunnels;
    private readonly ITunnelRoutePrompter _tunnelPrompter;
    private readonly IConnectionProfileResolver _profileResolver;
    private readonly ILogger<VncSessionViewModel> _logger;

    private IVncSession? _session;
    private ITunnelInstance? _tunnel;
    private CancellationTokenSource? _cts;
    private IVncRenderTarget? _renderTarget;
    private SwitchableVncRenderTarget? _sessionRenderTarget;
    private int _connectInFlight;
    private int _teardownGeneration;
    private bool _initialAutoConnectStarted;
    private bool _teardownRequested;

    public VncSessionViewModel(
        IVncSessionService vncService,
        ICredentialPasswordResolver passwordResolver,
        ICredentialRepository credentialRepository,
        IDialogService dialog,
        TunnelManager tunnels,
        ITunnelRoutePrompter tunnelPrompter,
        IConnectionProfileResolver profileResolver,
        ILoggerFactory loggerFactory)
        : this(
            vncService,
            passwordResolver,
            new RepositoryCredentialCatalogAdapter(credentialRepository),
            dialog,
            tunnels,
            tunnelPrompter,
            profileResolver,
            loggerFactory)
    {
    }

    [ActivatorUtilitiesConstructor]
    public VncSessionViewModel(
        IVncSessionService vncService,
        ICredentialPasswordResolver passwordResolver,
        IBitwardenCredentialCatalogService credentialCatalog,
        IDialogService dialog,
        TunnelManager tunnels,
        ITunnelRoutePrompter tunnelPrompter,
        IConnectionProfileResolver profileResolver,
        ILoggerFactory loggerFactory)
    {
        _vncService = vncService;
        _passwordResolver = passwordResolver;
        _credentialCatalog = credentialCatalog;
        _dialog = dialog;
        _tunnels = tunnels;
        _tunnelPrompter = tunnelPrompter;
        _profileResolver = profileResolver;
        _logger = loggerFactory.CreateLogger<VncSessionViewModel>();

        PropertyChanged += (_, args) =>
        {
            if (args.PropertyName == nameof(Status))
            {
                OnPropertyChanged(nameof(IsConnecting));
                OnPropertyChanged(nameof(IsConnected));
                OnPropertyChanged(nameof(IsDisconnected));
                OnPropertyChanged(nameof(IsFailed));
                OnPropertyChanged(nameof(CanDisconnect));
                OnPropertyChanged(nameof(CanTabDisconnect));
                RetryCommand.NotifyCanExecuteChanged();
            }
        };
    }

    public override ProtocolType Protocol => ProtocolType.Vnc;

    public override ICommand? ReconnectCommand => RetryCommand;
    public override ICommand? TabDisconnectCommand => DisconnectCommand;
    public override bool CanTabDisconnect => CanDisconnect;

    [ObservableProperty]
    private string? errorMessage;

    public bool IsConnecting => Status == SessionStatus.Connecting;
    public bool IsConnected => Status == SessionStatus.Connected;
    public bool IsDisconnected => Status == SessionStatus.Disconnected;
    public bool IsFailed => Status == SessionStatus.Failed;
    public bool CanDisconnect => Status is SessionStatus.Connecting or SessionStatus.Connected;

    protected override void OnDispatchEnqueueFailed() =>
        _logger.LogWarning("Failed to enqueue VNC-session UI update; dispatcher queue may be shutting down.");

    public override void Initialize(ConnectionProfile profile)
    {
        base.Initialize(profile);
        _initialAutoConnectStarted = false;
        Status = SessionStatus.Connecting;
    }

    public async Task AttachAsync(IVncRenderTarget renderTarget)
    {
        if (Profile is null)
            throw new InvalidOperationException("Initialize must be called before AttachAsync.");
        ArgumentNullException.ThrowIfNull(renderTarget);

        EnsureDispatcher();
        var previousRenderTarget = ReplaceRenderTarget(renderTarget);

        _sessionRenderTarget?.SetTarget(renderTarget);

        if (_session is not null)
        {
            _session.SetRenderTarget(renderTarget);
            _sessionRenderTarget = null;
            DisposeRenderTargetSilently(previousRenderTarget, "render target replacement");
            return;
        }

        DisposeRenderTargetSilently(previousRenderTarget, "render target replacement");

        if (_initialAutoConnectStarted)
        {
            return;
        }

        _initialAutoConnectStarted = true;
        await ConnectAsync(EnsureSessionRenderTarget(renderTarget)).ConfigureAwait(true);
    }

    [RelayCommand]
    public async Task DisconnectAsync()
    {
        await FullTeardownAsync().ConfigureAwait(true);
    }

    [RelayCommand(AllowConcurrentExecutions = false, CanExecute = nameof(CanRetry))]
    public async Task RetryAsync()
    {
        if (_renderTarget is null) return;
        if (Volatile.Read(ref _connectInFlight) != 0) return;

        await RefreshProfileFromRepositoryAsync().ConfigureAwait(true);
        await FullTeardownAsync().ConfigureAwait(true);
        Status = SessionStatus.Connecting;
        await ConnectAsync(EnsureSessionRenderTarget(_renderTarget)).ConfigureAwait(true);
    }

    private bool CanRetry() =>
        Status != SessionStatus.Connecting &&
        Volatile.Read(ref _connectInFlight) == 0;

    public override async ValueTask CloseAsync()
    {
        await FullTeardownAsync().ConfigureAwait(true);
        DisposeRenderTargetForClose();
    }

    public Task SendPointerAsync(int x, int y, VncPointerButtons buttons) =>
        _session?.SendPointerAsync(x, y, buttons) ?? Task.CompletedTask;

    public Task SendKeyAsync(bool isDown, int keySymbol) =>
        _session?.SendKeyAsync(isDown, keySymbol) ?? Task.CompletedTask;

    private async Task ConnectAsync(IVncRenderTarget renderTarget)
    {
        var profile = Profile;
        if (profile is null) return;
        if (Interlocked.CompareExchange(ref _connectInFlight, 1, 0) != 0) return;
        var teardownGeneration = Volatile.Read(ref _teardownGeneration);

        Status = SessionStatus.Connecting;
        ErrorMessage = null;
        _teardownRequested = false;

        var previousCts = _cts;
        var cts = new CancellationTokenSource();
        _cts = cts;
        previousCts?.Dispose();
        var token = cts.Token;
        ITunnelInstance? pendingTunnel = null;
        IVncSession? pendingSession = null;

        async Task HandleCancellationAsync()
        {
            if (ReferenceEquals(Interlocked.CompareExchange(ref _cts, null, cts), cts))
            {
                try { cts.Cancel(); } catch { /* already disposed */ }
                cts.Dispose();
            }
            await DisposeSessionSilentlyAsync(pendingSession).ConfigureAwait(true);
            await DisposeTunnelSilentlyAsync().ConfigureAwait(true);
            if (!IsAttemptCurrent(teardownGeneration)) return;
            Progress.Reset();
            Status = SessionStatus.Disconnected;
            ErrorMessage = null;
        }

        try
        {
            var routed = await _tunnelPrompter.ResolveRouteAsync(profile, token).ConfigureAwait(true);
            if (!IsAttemptCurrent(teardownGeneration)) return;
            if (routed is null)
            {
                await HandleCancellationAsync().ConfigureAwait(true);
                return;
            }
            profile = routed;
            if (profile.TunnelEnabled)
            {
                InitializeTunnelProgress();
                Progress.Begin(ConnectionPhase.Tunnel);
                pendingTunnel = await _tunnels.EstablishAsync(
                    profile,
                    token,
                    CreateUiProgress<TunnelProgress>(OnTunnelProgress)).ConfigureAwait(true);
                if (!IsAttemptCurrent(teardownGeneration))
                {
                    await DisposeTunnelInstanceSilentlyAsync(pendingTunnel).ConfigureAwait(true);
                    return;
                }
                _tunnel = pendingTunnel;
                pendingTunnel = null;
            }
            else
            {
                Progress.Reset();
            }

            Progress.Begin(ConnectionPhase.Connect);
            var passwordProvider = new PromptingVncPasswordProvider(
                profile,
                _passwordResolver,
                _credentialCatalog,
                _dialog,
                UiDispatcher,
                _logger);
            pendingSession = await _vncService.ConnectAsync(
                profile,
                passwordProvider,
                renderTarget,
                _tunnel,
                token).ConfigureAwait(true);
            if (!IsAttemptCurrent(teardownGeneration))
            {
                await DisposeSessionSilentlyAsync(pendingSession).ConfigureAwait(true);
                return;
            }

            if (_renderTarget is { } currentRenderTarget && !ReferenceEquals(currentRenderTarget, renderTarget))
            {
                pendingSession.SetRenderTarget(currentRenderTarget);
                _sessionRenderTarget = null;
            }

            AttachSession(pendingSession);
            pendingSession = null;
            Progress.CompleteAll();
            ErrorMessage = null;
            Status = SessionStatus.Connected;
        }
        catch (OperationCanceledException)
        {
            await HandleCancellationAsync().ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            await DisposeSessionSilentlyAsync(pendingSession).ConfigureAwait(true);
            await DisposeTunnelSilentlyAsync().ConfigureAwait(true);
            if (!IsAttemptCurrent(teardownGeneration)) return;
            ReportFailure(ex.Message);
            _logger.LogError(ex, "VNC connect failed for {Host}:{Port}.", profile.Host, profile.Port);
        }
        finally
        {
            await DisposeTunnelInstanceSilentlyAsync(pendingTunnel).ConfigureAwait(true);
            Interlocked.Exchange(ref _connectInFlight, 0);
            RetryCommand.NotifyCanExecuteChanged();
        }
    }

    private SwitchableVncRenderTarget EnsureSessionRenderTarget(IVncRenderTarget renderTarget)
    {
        if (_sessionRenderTarget is null)
        {
            _sessionRenderTarget = new SwitchableVncRenderTarget(renderTarget);
        }
        else
        {
            _sessionRenderTarget.SetTarget(renderTarget);
        }

        return _sessionRenderTarget;
    }

    private async Task RefreshProfileFromRepositoryAsync()
    {
        var current = Profile;
        if (current is null) return;

        var refreshed = await _profileResolver.ResolveAsync(current.NodeId).ConfigureAwait(true);
        if (refreshed is null || refreshed.Protocol != Protocol) return;

        UpdateProfile(refreshed);
    }

    private void AttachSession(IVncSession session)
    {
        _session = session;
        session.Closed += OnSessionClosed;
    }

    private void OnSessionClosed(object? sender, VncSessionClosedEventArgs args)
    {
        var session = sender as IVncSession;
        MarshalToUi(async () =>
        {
            if (session is null || !ReferenceEquals(_session, session)) return;
            if (_teardownRequested) return;
            _session = null;
            await DisposeSessionSilentlyAsync(session).ConfigureAwait(true);
            await DisposeTunnelSilentlyAsync().ConfigureAwait(true);
            var message = string.IsNullOrWhiteSpace(args.Message)
                ? "VNC connection closed by the remote host."
                : args.Message;
            ReportFailure(message);
            _logger.LogInformation(
                args.Exception,
                "VNC session closed unexpectedly. Clean={IsClean}",
                args.IsClean);
        });
    }

    private async Task FullTeardownAsync()
    {
        _teardownRequested = true;
        Interlocked.Increment(ref _teardownGeneration);
        var cts = _cts;
        _cts = null;
        try { cts?.Cancel(); } catch { /* already disposed */ }
        cts?.Dispose();

        var session = _session;
        _session = null;
        _sessionRenderTarget = null;
        if (session is not null)
        {
            await DisposeSessionSilentlyAsync(session).ConfigureAwait(true);
        }

        await DisposeTunnelSilentlyAsync().ConfigureAwait(true);
        Progress.Reset();
        ErrorMessage = null;
        Status = SessionStatus.Disconnected;
        _teardownRequested = false;
    }

    private async Task DisposeSessionSilentlyAsync(IVncSession? session)
    {
        if (session is null) return;
        session.Closed -= OnSessionClosed;
        try { await session.DisposeAsync().ConfigureAwait(true); }
        catch (Exception ex) { _logger.LogWarning(ex, "VNC session dispose threw during teardown."); }
    }

    private async Task DisposeTunnelSilentlyAsync()
    {
        var tunnel = Interlocked.Exchange(ref _tunnel, null);
        await DisposeTunnelInstanceSilentlyAsync(tunnel).ConfigureAwait(true);
    }

    private async Task DisposeTunnelInstanceSilentlyAsync(ITunnelInstance? tunnel)
    {
        if (tunnel is null) return;
        try { await tunnel.DisposeAsync().ConfigureAwait(true); }
        catch (Exception ex) { _logger.LogWarning(ex, "Tunnel dispose threw during VNC teardown."); }
    }

    private void DisposeRenderTargetForClose()
    {
        var renderTarget = Interlocked.Exchange(ref _renderTarget, null);
        _sessionRenderTarget = null;
        DisposeRenderTargetSilently(renderTarget, "tab close");
    }

    private IVncRenderTarget? ReplaceRenderTarget(IVncRenderTarget renderTarget)
    {
        var previous = Interlocked.Exchange(ref _renderTarget, renderTarget);
        return ReferenceEquals(previous, renderTarget) ? null : previous;
    }

    private void DisposeRenderTargetSilently(IVncRenderTarget? renderTarget, string context)
    {
        if (renderTarget is not IDisposable disposable) return;
        try { disposable.Dispose(); }
        catch (Exception ex) { _logger.LogWarning(ex, "VNC render target dispose threw during {Context}.", context); }
    }

    private bool IsAttemptCurrent(int teardownGeneration) =>
        Volatile.Read(ref _teardownGeneration) == teardownGeneration;

    public void ReportFailure(string message)
    {
        Progress.Fail();
        ErrorMessage = message;
        Status = SessionStatus.Failed;
    }

    private void InitializeTunnelProgress()
    {
        Progress.Initialize(new (ConnectionPhase, string)[]
        {
            (ConnectionPhase.Tunnel, "VPN tunnel"),
            (ConnectionPhase.Connect, "Connect"),
        });
    }

    private void OnTunnelProgress(TunnelProgress progress) =>
        Progress.Detail = ConnectionProgress.DescribeTunnelPhase(progress);

    private sealed class SwitchableVncRenderTarget : IVncRenderTarget
    {
        private IVncRenderTarget _current;

        public SwitchableVncRenderTarget(IVncRenderTarget current) => _current = current;

        public void SetTarget(IVncRenderTarget current) => Volatile.Write(ref _current, current);

        public IFramebufferReference GrabFramebufferReference(VncSize size, IImmutableSet<VncScreen> layout) =>
            Volatile.Read(ref _current).GrabFramebufferReference(size, layout);
    }

    private sealed class PromptingVncPasswordProvider : IVncPasswordProvider
    {
        private readonly ConnectionProfile _profile;
        private readonly ICredentialPasswordResolver _passwordResolver;
        private readonly IBitwardenCredentialCatalogService _credentialCatalog;
        private readonly IDialogService _dialog;
        private readonly DispatcherQueue? _dispatcher;
        private readonly ILogger _logger;
        private bool _resolved;
        private string? _password;

        public PromptingVncPasswordProvider(
            ConnectionProfile profile,
            ICredentialPasswordResolver passwordResolver,
            IBitwardenCredentialCatalogService credentialCatalog,
            IDialogService dialog,
            DispatcherQueue? dispatcher,
            ILogger logger)
        {
            _profile = profile;
            _passwordResolver = passwordResolver;
            _credentialCatalog = credentialCatalog;
            _dialog = dialog;
            _dispatcher = dispatcher;
            _logger = logger;
        }

        public async Task<string?> GetPasswordAsync(CancellationToken cancellationToken)
        {
            if (_resolved) return _password;
            _resolved = true;

            if (_profile.CredentialId is { } credentialId)
            {
                try
                {
                    var credential = await _credentialCatalog.GetByIdAsync(credentialId, cancellationToken).ConfigureAwait(true);
                    cancellationToken.ThrowIfCancellationRequested();
                    if (credential is null)
                    {
                        _logger.LogInformation("VNC credential {CredentialId} profile not found; prompting.", credentialId);
                    }
                    else if (credential.Protocol != ProtocolType.Vnc || credential.Kind != CredentialKind.Password)
                    {
                        _logger.LogInformation(
                            "Ignoring non-VNC password credential {CredentialId} for VNC auth: protocol={Protocol}, kind={Kind}; prompting.",
                            credentialId,
                            credential.Protocol,
                            credential.Kind);
                    }
                    else
                    {
                        _password = await _passwordResolver.ReadPasswordAsync(credential, PromptBitwardenUnlockOnUiAsync, cancellationToken).ConfigureAwait(true);
                        cancellationToken.ThrowIfCancellationRequested();
                        if (_password is not null) return _password;
                        _logger.LogInformation("VNC credential {CredentialId} password not found in Credential Manager; prompting.", credentialId);
                    }
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogWarning(ex, "Failed to read VNC credential {CredentialId}; prompting.", credentialId);
                }
            }

            _password = await PromptPasswordOnUiAsync(cancellationToken).ConfigureAwait(false);
            return _password;
        }

        private Task<string?> PromptBitwardenUnlockOnUiAsync(
            Func<string, CancellationToken, Task<string>> unlockAsync,
            CancellationToken cancellationToken) =>
            PromptOnUiAsync(
                () => _dialog.PromptBitwardenUnlockAsync(unlockAsync, cancellationToken),
                cancellationToken);

        private Task<string?> PromptPasswordOnUiAsync(CancellationToken cancellationToken) =>
            PromptPasswordOnUiAsync("VNC password", $"Enter the password for {_profile.Host}:{_profile.Port}.", cancellationToken);

        private Task<string?> PromptPasswordOnUiAsync(string title, string message, CancellationToken cancellationToken) =>
            PromptOnUiAsync(
                () => _dialog.PromptPasswordAsync(title, message, cancellationToken),
                cancellationToken);

        private async Task<string?> PromptOnUiAsync(
            Func<Task<string?>> promptAsync,
            CancellationToken cancellationToken)
        {
            if (_dispatcher is null || _dispatcher.HasThreadAccess)
            {
                return await promptAsync().ConfigureAwait(true);
            }

            var tcs = new TaskCompletionSource<string?>(TaskCreationOptions.RunContinuationsAsynchronously);
            using var registration = cancellationToken.Register(
                static state => ((TaskCompletionSource<string?>)state!).TrySetCanceled(),
                tcs);
            if (!_dispatcher.TryEnqueue(async () =>
            {
                try
                {
                    var result = await promptAsync().ConfigureAwait(true);
                    tcs.TrySetResult(result);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    tcs.TrySetCanceled();
                }
                catch (Exception ex)
                {
                    tcs.TrySetException(ex);
                }
            }))
            {
                throw new InvalidOperationException("Unable to show the VNC password prompt because the UI dispatcher is unavailable.");
            }

            return await tcs.Task.ConfigureAwait(false);
        }
    }
}
