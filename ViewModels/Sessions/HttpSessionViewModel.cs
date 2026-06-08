using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using Wormhole.Models;
using Wormhole.Services;
using Wormhole.Services.Tunneling;

namespace Wormhole.ViewModels.Sessions;

// CA1001 (owns the IDisposable _cts but isn't IDisposable) is suppressed deliberately, matching
// SshSessionViewModel: the VM is registered transient in DI, and Microsoft.Extensions.DependencyInjection
// pins every transient IDisposable in the root scope for the app lifetime — implementing IDisposable
// would keep every closed web tab alive until exit. The tunnel + CTS are torn down explicitly on the
// documented teardown path (DisconnectAsync / CloseAsync / RetryAsync).
#pragma warning disable CA1001
/// <summary>
/// Backs an embedded WebView2 "web browser" session tab for the <see cref="ProtocolType.Http"/> and
/// <see cref="ProtocolType.Https"/> protocols. The VM owns the connection lifecycle — per-connect VPN
/// route prompt, tunnel establishment, and computing the <see cref="HttpConnectionTarget"/> the view
/// navigates to — but NOT the WebView2 control itself. The view (<c>WebBrowserView</c>) subscribes to
/// <see cref="NavigateRequested"/>, creates/navigates the WebView2 with the right environment (a SOCKS5
/// proxy when the tunnel exposes one, else a plain navigation to a loopback port-forward), and reports
/// the navigation result back via <see cref="ReportNavigationSucceeded"/> / <see cref="ReportNavigationFailed"/>.
/// </summary>
public sealed partial class HttpSessionViewModel : SessionTabViewModel
#pragma warning restore CA1001
{
    private readonly TunnelManager _tunnels;
    private readonly ITunnelRoutePrompter _tunnelPrompter;
    private readonly IConnectionProfileResolver _profileResolver;
    private readonly ILogger<HttpSessionViewModel> _logger;

    private CancellationTokenSource? _cts;
    private ITunnelInstance? _tunnel;
    private int _connectInFlight;

    public HttpSessionViewModel(
        TunnelManager tunnels,
        ITunnelRoutePrompter tunnelPrompter,
        IConnectionProfileResolver profileResolver,
        ILoggerFactory loggerFactory)
    {
        _tunnels = tunnels;
        _tunnelPrompter = tunnelPrompter;
        _profileResolver = profileResolver;
        _logger = loggerFactory.CreateLogger<HttpSessionViewModel>();
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

    // The tab is bound to its protocol at open time; report whichever web protocol the profile uses
    // (defaulting to Https before Initialize runs) so the base-class refresh guard works.
    public override ProtocolType Protocol => Profile?.Protocol ?? ProtocolType.Https;

    public override ICommand? ReconnectCommand => RetryCommand;

    [ObservableProperty]
    private string? errorMessage;

    public bool IsConnecting => Status == SessionStatus.Connecting;
    public bool IsConnected => Status == SessionStatus.Connected;
    public bool IsFailed => Status == SessionStatus.Failed;

    /// <summary>
    /// The last computed navigation target (URL + optional SOCKS proxy + cert policy). The view reads
    /// this on a re-attach (Sessions↔Settings navigation rebuilds the view while the VM survives) to
    /// re-create its WebView2 without re-establishing the tunnel. Null until the first connect resolves.
    /// </summary>
    public HttpConnectionTarget? CurrentTarget { get; private set; }

    /// <summary>
    /// Raised on the UI thread when a fresh navigation target is ready (initial connect and Retry). The
    /// view handles it by (re)creating its WebView2 with the appropriate environment and navigating.
    /// </summary>
    public event Action<HttpConnectionTarget>? NavigateRequested;

    protected override void OnDispatchEnqueueFailed() =>
        _logger.LogWarning("Failed to enqueue web-session UI update — dispatcher queue may be shutting down.");

    public override void Initialize(ConnectionProfile profile)
    {
        base.Initialize(profile);
        // Surface the connecting spinner immediately. A freshly-opened tab whose view hasn't loaded yet
        // (e.g. two connections opened back-to-back, so this one isn't the realized/selected tab) would
        // otherwise sit in Disconnected behind the opaque base cover — a black pane with no spinner or
        // Retry — until brought forward. Mirrors SshSessionViewModel.MarkConnecting; safe because a web
        // VM has no live session at Initialize, and AttachAsync's ConnectAsync re-affirms Connecting.
        Status = SessionStatus.Connecting;
    }

    /// <summary>
    /// Entry point from the view's Loaded handler. Establishes the connection on first load; on a
    /// re-attach (the VM already resolved a target) re-raises <see cref="NavigateRequested"/> so the
    /// freshly-created WebView2 navigates to the existing target without re-establishing the tunnel.
    /// </summary>
    public async Task AttachAsync()
    {
        if (Profile is null)
            throw new InvalidOperationException("Initialize must be called before AttachAsync.");
        EnsureDispatcher();

        // A Failed tab's overlay (and its Retry button) owns the next action. Don't auto-reconnect or
        // re-navigate when the view is rebuilt (a Sessions↔Settings round-trip): falling through to
        // ConnectAsync here would silently re-run the connect — and re-prompt for the VPN route — on
        // every visit to a failed tab.
        if (Status == SessionStatus.Failed) return;

        if (CurrentTarget is { } target)
        {
            // Re-attach (the view was rebuilt while the VM survived): re-navigate the freshly-created
            // WebView2 to the existing target rather than starting a second connect or re-establishing
            // the tunnel.
            NavigateRequested?.Invoke(target);
            return;
        }

        await ConnectAsync().ConfigureAwait(true);
    }

    private async Task ConnectAsync()
    {
        var profile = Profile;
        if (profile is null) return;
        if (Interlocked.CompareExchange(ref _connectInFlight, 1, 0) != 0) return;

        Status = SessionStatus.Connecting;
        ErrorMessage = null;
        var cts = new CancellationTokenSource();
        _cts = cts;
        var token = cts.Token;

        try
        {
            // Per-connect tunnel routing: when the user opted in (PromptBeforeTunnelConnect) and the
            // profile is configured for a tunnel, ask whether to route through it or go direct for THIS
            // attempt. Null means the user cancelled — surface a recoverable Failed (the view's Retry
            // re-opens the prompt), mirroring SSH/RDP.
            var routed = await _tunnelPrompter.ResolveRouteAsync(profile, token).ConfigureAwait(true);
            if (routed is null)
            {
                ReportFailure("Connection cancelled.");
                return;
            }

            InitializeProgress(routed);

            Progress.Begin(ConnectionPhase.Tunnel);
            _tunnel = await _tunnels.EstablishAsync(
                routed, token, CreateUiProgress<TunnelProgress>(OnTunnelProgress)).ConfigureAwait(true);

            Progress.Begin(ConnectionPhase.Connect);
            var target = await BuildTargetAsync(routed, _tunnel, token).ConfigureAwait(true);
            token.ThrowIfCancellationRequested();

            CurrentTarget = target;
            // Status stays Connecting: the page hasn't loaded yet. The view drives the WebView2
            // navigation and calls back ReportNavigationSucceeded / ReportNavigationFailed.
            NavigateRequested?.Invoke(target);
        }
        catch (OperationCanceledException)
        {
            await TearDownTunnelAsync().ConfigureAwait(true);
            Progress.Reset();
            Status = SessionStatus.Disconnected;
        }
        catch (Exception ex)
        {
            await TearDownTunnelAsync().ConfigureAwait(true);
            ReportFailure(ex.Message);
            _logger.LogError(ex, "Web connect failed for {Host}.", profile.Host);
        }
        finally
        {
            Interlocked.Exchange(ref _connectInFlight, 0);
        }
    }

    /// <summary>
    /// Resolve the navigation target from the routed profile and the (optional) established tunnel:
    /// direct → the real URL; tunnel with a SOCKS5 endpoint → the real URL proxied through SOCKS
    /// (preserves the hostname so certificates/redirects behave); tunnel without SOCKS (e.g. WireGuard)
    /// → a 127.0.0.1 port-forward URL, the same mechanism RDP uses.
    /// </summary>
    private static async Task<HttpConnectionTarget> BuildTargetAsync(
        ConnectionProfile profile, ITunnelInstance? tunnel, CancellationToken token)
    {
        var scheme = profile.Protocol == ProtocolType.Https ? "https" : "http";
        var ignoreCert = profile.Protocol == ProtocolType.Https && profile.HttpIgnoreCertErrors;

        if (tunnel is null)
        {
            return new HttpConnectionTarget(BuildUri(scheme, profile.Host, profile.Port), null, ignoreCert);
        }

        if (tunnel.Socks5Endpoint is { } socks)
        {
            // SOCKS path: navigate to the REAL host (correct SNI / Host header / redirects); the view
            // configures the WebView2 environment to proxy through 127.0.0.1:<socksPort>.
            return new HttpConnectionTarget(BuildUri(scheme, profile.Host, profile.Port), socks, ignoreCert);
        }

        // Forwarder path: bind a loopback listener that bridges to host:port through the tunnel and
        // navigate there. The loopback name can't match the appliance certificate, so HTTPS over this
        // path needs "ignore certificate errors" enabled (surfaced to the user as a cert-error failure
        // otherwise).
        var localPort = await tunnel.BindLocalForwarderAsync(profile.Host, profile.Port, token).ConfigureAwait(true);
        return new HttpConnectionTarget(BuildUri(scheme, IPAddress.Loopback.ToString(), localPort), null, ignoreCert);
    }

    // UriBuilder brackets a bare IPv6 literal and normalizes the default port on Build (same convention
    // as StormshieldPortalClient / WatchguardPreAuthClient), so there's no hand-rolled authority string.
    private static Uri BuildUri(string scheme, string host, int port) =>
        new UriBuilder { Scheme = scheme, Host = host, Port = port, Path = "/" }.Uri;

    /// <summary>Called by the view when the top-level navigation completes successfully.</summary>
    public void ReportNavigationSucceeded()
    {
        if (Status != SessionStatus.Connecting) return;
        Progress.CompleteAll();
        ErrorMessage = null;
        Status = SessionStatus.Connected;
    }

    /// <summary>Called by the view when the top-level navigation fails (transport error, cert error with
    /// validation on, etc.).</summary>
    public void ReportNavigationFailed(string message)
    {
        // Only the initial connect (Status == Connecting) may fail the tab. A failure reported while
        // already Connected — e.g. a transient reload after a Sessions↔Settings re-navigation — must
        // not demote a healthy tab; and a late callback after teardown (Disconnected/Failed) is ignored.
        if (Status != SessionStatus.Connecting) return;
        ReportFailure(message);
    }

    public void ReportFailure(string message)
    {
        Progress.Fail();
        ErrorMessage = message;
        Status = SessionStatus.Failed;
    }

    [RelayCommand(AllowConcurrentExecutions = false, CanExecute = nameof(CanRetry))]
    public async Task RetryAsync()
    {
        ErrorMessage = null;
        // Re-read the saved settings (through folder inheritance) so a tunnel/host/ignore-cert edit made
        // after the tab opened is honored on Retry — mirrors SSH/RDP.
        await RefreshProfileFromRepositoryAsync().ConfigureAwait(true);
        Status = SessionStatus.Connecting;
        Progress.Reset();
        await TearDownTunnelAsync().ConfigureAwait(true);
        await ConnectAsync().ConfigureAwait(true);
    }

    // While Connecting, an in-flight ConnectAsync still holds _connectInFlight; a second one would no-op.
    private bool CanRetry() => Status != SessionStatus.Connecting;

    private async Task RefreshProfileFromRepositoryAsync()
    {
        var current = Profile;
        if (current is null) return;

        var refreshed = await _profileResolver.ResolveAsync(current.NodeId).ConfigureAwait(true);
        if (refreshed is null) return;

        // This tab's surface is fixed to web protocols at open time. If the saved connection's protocol
        // was switched to a non-web one while the tab is open, keep the cached profile rather than
        // driving the browser surface with an SSH/RDP profile. Switching between Http and Https is fine.
        if (refreshed.Protocol is not (ProtocolType.Http or ProtocolType.Https)) return;

        UpdateProfile(refreshed);
    }

    [RelayCommand]
    public Task DisconnectAsync() => TearDownToDisconnectedAsync();

    public override async ValueTask CloseAsync()
    {
        // Clear CurrentTarget and move to Disconnected (like DisconnectAsync) so any stray re-attach
        // after close can't navigate a fresh WebView2 at the now-disposed tunnel. The view's WebView2 is
        // released by GC once the closed tab's view is discarded (same as SshTerminalView).
        await TearDownToDisconnectedAsync().ConfigureAwait(true);
    }

    private async Task TearDownToDisconnectedAsync()
    {
        await TearDownTunnelAsync().ConfigureAwait(true);
        CurrentTarget = null;
        Progress.Reset();
        Status = SessionStatus.Disconnected;
    }

    private async Task TearDownTunnelAsync()
    {
        var cts = _cts;
        _cts = null;
        try { cts?.Cancel(); } catch { /* already disposed */ }

        var tunnel = _tunnel;
        _tunnel = null;
        if (tunnel is not null)
        {
            try { await tunnel.DisposeAsync().ConfigureAwait(true); }
            catch (Exception ex) { _logger.LogWarning(ex, "Error tearing down web-session tunnel."); }
        }
    }

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

    // === Test hooks ========================================================
#pragma warning disable CA1822 // kept as an instance method for test call-site ergonomics
    internal HttpConnectionTarget? BuildTargetForTesting(ConnectionProfile profile, ITunnelInstance? tunnel) =>
        BuildTargetAsync(profile, tunnel, CancellationToken.None).GetAwaiter().GetResult();
#pragma warning restore CA1822
}

/// <summary>
/// Immutable description of where and how a web session should navigate. <see cref="Socks5Proxy"/> is
/// non-null only when the session routes through a tunnel that exposes a SOCKS5 endpoint — in that case
/// the view must create a WebView2 environment proxied through it. <see cref="IgnoreCertErrors"/> tells
/// the view to accept certificate errors for this navigation (HTTPS + the user's opt-in).
/// </summary>
public sealed record HttpConnectionTarget(Uri NavigateUri, IPEndPoint? Socks5Proxy, bool IgnoreCertErrors);
