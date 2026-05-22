using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using Wormhole.Data.Repositories;
using Wormhole.Models;
using Wormhole.Services;

namespace Wormhole.ViewModels.Sessions;

public sealed partial class RdpSessionViewModel : SessionTabViewModel
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(30);

    private readonly IRdpSessionService _rdpService;
    private readonly ICredentialService _credentialService;
    private readonly ICredentialRepository _credentialRepository;
    private readonly IDialogService _dialog;
    private readonly ILogger<RdpSessionViewModel> _logger;

    private IRdpSession? _session;
    private CancellationTokenSource? _cts;
    private int _connectInFlight;
    private IntPtr _ownerHwnd;

    public RdpSessionViewModel(
        IRdpSessionService rdpService,
        ICredentialService credentialService,
        ICredentialRepository credentialRepository,
        IDialogService dialog,
        ILoggerFactory loggerFactory)
    {
        _rdpService = rdpService;
        _credentialService = credentialService;
        _credentialRepository = credentialRepository;
        _dialog = dialog;
        _logger = loggerFactory.CreateLogger<RdpSessionViewModel>();

        // Status lives on the base class — re-broadcast its dependents from the derived VM
        // since [NotifyPropertyChangedFor] only sees properties on its own partial class.
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

    public override ProtocolType Protocol => ProtocolType.Rdp;

    /// <summary>
    /// Surface <see cref="RetryCommand"/> to the SessionsPage tab context menu's Reconnect
    /// entry — which gates its visibility on <see cref="SessionTabViewModel.CanReconnect"/>
    /// (defaults to false when the base ReconnectCommand is null). Without this override,
    /// RDP tabs would lose the standard reconnect path that SSH tabs have.
    /// </summary>
    public override ICommand? ReconnectCommand => RetryCommand;

    [ObservableProperty]
    private string? errorMessage;

    /// <summary>Surface for the "Reconnecting…" status banner while ActiveX auto-reconnect is in flight.</summary>
    [ObservableProperty]
    private int reconnectAttempt;

    /// <summary>
    /// Set on logon failures (OnLogonError) so the failure overlay can show a "Re-enter credentials"
    /// affordance distinct from a plain transport-failure retry.
    /// </summary>
    [ObservableProperty]
    private bool failedDueToCredentials;

    public bool IsConnecting => Status == SessionStatus.Connecting;
    public bool IsConnected => Status == SessionStatus.Connected;
    public bool IsFailed => Status == SessionStatus.Failed;

    // Initialize inherits the base implementation: protocol-specific bootstrapping is done
    // lazily on AttachAsync once the surface host has the owner HWND.

    /// <summary>
    /// Called by RdpSurfaceHost on Loaded. If no session exists yet, resolves the credential and
    /// connects. If a session already exists (re-attach after nav-away/back, tab drag reorder),
    /// just makes the embedded host visible at the new bounds.
    /// </summary>
    public async Task AttachAsync(IntPtr ownerHwnd, HostBounds bounds)
    {
        if (Profile is null)
            throw new InvalidOperationException("Initialize must be called before AttachAsync.");

        _ownerHwnd = ownerHwnd;
        EnsureDispatcher();

        if (_session is not null)
        {
            // Re-attach path: surface host reloaded after nav-away. The session lives in
            // ShellViewModel.Tabs and the ActiveX is still connected.
            _session.SetBounds(bounds);
            _session.Show();
            return;
        }

        await ConnectAsync(ownerHwnd, bounds, forcePromptForPassword: false).ConfigureAwait(true);
    }

    public void SetBounds(HostBounds bounds) => _session?.SetBounds(bounds);

    public void DetachView()
    {
        // Hide rather than tear down — the VM survives navigation. SetParent-to-null risks
        // losing the ActiveX's internal device context; ShowWindow(SW_HIDE) is idempotent
        // so we don't need to track our own visibility flag.
        try { _session?.Hide(); }
        catch (Exception ex) { _logger.LogWarning(ex, "Hide failed during DetachView."); }
    }

    [RelayCommand]
    public Task DisconnectAsync()
    {
        FullTeardown();
        return Task.CompletedTask;
    }

    [RelayCommand]
    public async Task RetryAsync()
    {
        if (Profile is null || _ownerHwnd == IntPtr.Zero) return;

        var forcePrompt = FailedDueToCredentials;
        FullTeardown();

        // Geometry will be re-supplied by the surface host's first SetBounds after the new
        // session attaches; seed with a 1x1 so the form is valid until that arrives.
        await ConnectAsync(_ownerHwnd, HostBounds.Seed, forcePromptForPassword: forcePrompt).ConfigureAwait(true);
    }

    public override ValueTask CloseAsync()
    {
        FullTeardown();
        return ValueTask.CompletedTask;
    }

    private async Task ConnectAsync(IntPtr ownerHwnd, HostBounds initialBounds, bool forcePromptForPassword)
    {
        var profile = Profile;
        if (profile is null) return;
        if (Interlocked.CompareExchange(ref _connectInFlight, 1, 0) != 0) return;

        Status = SessionStatus.Connecting;
        ErrorMessage = null;
        FailedDueToCredentials = false;
        ReconnectAttempt = 0;

        // The CTS exists from the start so FullTeardown / Disconnect can cancel an in-flight
        // connect, but the ConnectTimeout itself only kicks in once we've actually started
        // the network handshake. Counting credential-entry time against the 30s budget would
        // make a slow typist's correct password expire before the OCX ever sees it.
        var cts = new CancellationTokenSource();
        _cts = cts;
        var token = cts.Token;

        try
        {
            var password = await ResolvePasswordAsync(profile, forcePromptForPassword, token).ConfigureAwait(true);
            if (token.IsCancellationRequested)
            {
                Status = SessionStatus.Disconnected;
                return;
            }

            // ResolvePasswordAsync returns null only when the user cancelled the prompt —
            // silent return to Disconnected, not Failed (no error message to show). This
            // covers both "no saved credential, user cancelled" and "credential pointed to
            // a deleted Credential Manager entry, ResolvePasswordAsync fell through to a
            // prompt, user cancelled that". Either way, the user said no.
            if (password is null)
            {
                Status = SessionStatus.Disconnected;
                return;
            }

            // Credentials are in hand — now bound the actual network handshake by the timeout.
            // The CTS firing is observed two ways:
            //   1. Anything still inside the `await _rdpService.ConnectAsync(...)` below picks
            //      it up via OperationCanceledException (only useful if Configure / SetParent
            //      stages somehow hang, since Start itself is synchronous).
            //   2. The Register callback below is the real watchdog: ConnectAsync returns
            //      immediately after kicking off the asynchronous OCX handshake, so without
            //      this we'd have no way to surface a "server never answered" timeout. When
            //      the token elapses while Status is still Connecting, we tear the session
            //      down ourselves and fail the VM with a timeout message.
            cts.CancelAfter(ConnectTimeout);
            // Capture the CTS in the closure and compare with _cts when the callback fires.
            // Without this, a watchdog from a previous attempt could still fire after the
            // user retried — the new connect flips Status back to Connecting, and the stale
            // callback would tear the new session down on the old 30s timer.
            var attemptCts = cts;
            cts.Token.Register(() => MarshalToUi(() =>
            {
                if (!ReferenceEquals(_cts, attemptCts)) return;
                if (Status == SessionStatus.Connecting)
                {
                    DisposeAndTransition("RDP server didn't respond within 30 seconds.", dueToCredentials: false);
                }
            }));

            var (gwUser, gwPassword) = await ResolveGatewayCredentialsAsync(profile, token).ConfigureAwait(true);
            // Subscribe via the onSessionReady hook (not after the await) so the VM is ready
            // to receive an immediate OnLogonError / OnDisconnected that the OCX may fire
            // synchronously during the Connect() inside form.Start(). Subscribing after the
            // returned Task completes would drop those events and strand us in Connecting.
            var session = await _rdpService.ConnectAsync(
                profile, password, ownerHwnd, gwUser, gwPassword,
                onSessionReady: s =>
                {
                    s.Connected += OnSessionConnected;
                    s.Disconnected += OnSessionDisconnected;
                    s.FatalError += OnSessionFatalError;
                    s.LogonError += OnSessionLogonError;
                    s.AutoReconnecting += OnSessionAutoReconnecting;
                },
                token).ConfigureAwait(true);
            _session = session;

            _session.SetBounds(initialBounds.IsDegenerate(minDim: 1) ? HostBounds.Seed : initialBounds);
            _session.Show();
        }
        catch (OperationCanceledException)
        {
            DisposeSessionSilently();
            Status = SessionStatus.Disconnected;
        }
        catch (System.Runtime.InteropServices.COMException ex) when ((uint)ex.HResult == 0x80040154)
        {
            // REGDB_E_CLASSNOTREG — mstscax not registered (Server Core, N edition).
            DisposeSessionSilently();
            ReportFailure(
                "Microsoft Remote Desktop ActiveX (mstscax.dll) is not registered on this system. " +
                "Install the Remote Desktop Connection client.",
                dueToCredentials: false);
            _logger.LogError(ex, "RDP ActiveX not registered.");
        }
        catch (Exception ex)
        {
            DisposeSessionSilently();
            ReportFailure(ex.Message, dueToCredentials: false);
            _logger.LogError(ex, "RDP connect failed for {Host}:{Port}.", profile.Host, profile.Port);
        }
        finally
        {
            Interlocked.Exchange(ref _connectInFlight, 0);
        }
    }

    private async Task<string?> ResolvePasswordAsync(ConnectionProfile profile, bool forcePrompt, CancellationToken token)
    {
        if (!forcePrompt && profile.CredentialId is { } credId)
        {
            try
            {
                var stored = await _credentialService.ReadPasswordAsync(credId).ConfigureAwait(true);
                if (!string.IsNullOrEmpty(stored)) return stored;
                // Stored credential profile points at a Credential Manager entry that was
                // deleted out-of-band; fall through to a prompt rather than crash.
                _logger.LogInformation("Credential {CredentialId} not found in Credential Manager — prompting.", credId);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to read credential {CredentialId} — prompting.", credId);
            }
        }
        token.ThrowIfCancellationRequested();

        var prefix = !string.IsNullOrEmpty(profile.RdpDomain)
            ? $"{profile.RdpDomain}\\{profile.Username ?? ""}"
            : (profile.Username ?? string.Empty);
        var promptMsg = string.IsNullOrEmpty(prefix)
            ? $"Enter password for {profile.Host}"
            : $"Enter password for {prefix}@{profile.Host}";

        return await _dialog.PromptPasswordAsync("RDP credentials", promptMsg).ConfigureAwait(true);
    }

    /// <summary>
    /// Look up the gateway credential profile (username + Credential-Manager password) when
    /// the connection routes through an RD Gateway. Returns nulls when no gateway is
    /// configured, no gateway credential is picked, or the profile/password is missing —
    /// callers pass the nulls through, and the OCX falls back to its own prompt if the
    /// gateway requires interactive auth.
    /// </summary>
    private async Task<(string? Username, string? Password)> ResolveGatewayCredentialsAsync(ConnectionProfile profile, CancellationToken token)
    {
        if (profile.RdpGatewayUsageMethod == 0) return (null, null);
        if (profile.RdpGatewayCredentialId is not { } gwCredId) return (null, null);

        CredentialProfile? gwProfile = null;
        try
        {
            gwProfile = await _credentialRepository.GetByIdAsync(gwCredId, token).ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to read gateway credential profile {CredentialId}.", gwCredId);
        }
        if (gwProfile is null) return (null, null);

        var username = string.IsNullOrEmpty(gwProfile.Domain)
            ? gwProfile.Username
            : $"{gwProfile.Domain}\\{gwProfile.Username}";

        string? password = null;
        try { password = await _credentialService.ReadPasswordAsync(gwCredId).ConfigureAwait(true); }
        catch (Exception ex) { _logger.LogWarning(ex, "Failed to read gateway credential password."); }

        return (username, password);
    }

    private void OnSessionConnected(object? sender, EventArgs e)
    {
        MarshalToUi(() =>
        {
            ReconnectAttempt = 0;
            Status = SessionStatus.Connected;
        });
    }

    private void OnSessionDisconnected(object? sender, RdpDisconnectInfo info)
    {
        MarshalToUi(() => DisposeAndTransition(
            failureMessage: info.IsClean ? null : info.Description,
            dueToCredentials: false));
    }

    private void OnSessionLogonError(object? sender, int code)
    {
        // Per the IMsTscAxEvents.OnLogonError docs, the documented codes are nuanced:
        //   -2 = the user cancelled the credentials dialog → not a failure, treat as cancel
        //   -3 = pre-authentication failed → credential issue, prompt for re-entry on retry
        //   -5 = an information dialog was displayed → not really an error
        // Unknown / other codes fall through to a generic credential-failure overlay so the
        // user still gets a recoverable retry path.
        if (code == -2)
        {
            // User dismissed the credentials prompt — silent disconnect, no failure UI.
            MarshalToUi(() => DisposeAndTransition(failureMessage: null, dueToCredentials: false));
            return;
        }
        var dueToCredentials = code != -5;
        MarshalToUi(() => DisposeAndTransition(
            failureMessage: RdpLogonErrors.Describe(code),
            dueToCredentials: dueToCredentials));
    }

    private void OnSessionFatalError(object? sender, int code)
    {
        MarshalToUi(() => DisposeAndTransition(
            failureMessage: $"RDP fatal error (code {code}).",
            dueToCredentials: false));
    }

    private void OnSessionAutoReconnecting(object? sender, RdpReconnectInfo info)
    {
        MarshalToUi(() =>
        {
            ReconnectAttempt = info.Attempt;
            Status = SessionStatus.Connecting;
        });
    }

    /// <summary>
    /// Recovery path for exceptions escaping the dispatched continuation in
    /// <see cref="SessionTabViewModel.MarshalToUi(Func{Task})"/>. Without this override the
    /// VM could remain in <see cref="SessionStatus.Connecting"/> if e.g. session teardown
    /// itself throws — leaving the user with a hanging spinner and no recovery affordance.
    /// </summary>
    protected override void OnDispatchedException(Exception ex)
    {
        _logger.LogError(ex, "RDP event handler threw on dispatched continuation.");
        if (Status == SessionStatus.Connecting || Status == SessionStatus.Connected)
        {
            ReportFailure(ex.Message, dueToCredentials: false);
        }
    }

    protected override void OnDispatchEnqueueFailed()
    {
        _logger.LogWarning("Failed to enqueue RDP UI update — dispatcher queue may be shutting down.");
    }

    private void ReportFailure(string message, bool dueToCredentials)
    {
        ErrorMessage = message;
        FailedDueToCredentials = dueToCredentials;
        Status = SessionStatus.Failed;
    }

    /// <summary>
    /// User-initiated teardown (Disconnect / Retry / tab close): cancel any in-flight
    /// connect, dispose the session, return to a clean Disconnected state.
    /// </summary>
    private void FullTeardown()
    {
        var cts = _cts;
        _cts = null;
        try { cts?.Cancel(); } catch { /* already disposed */ }

        DisposeSessionSilently();
        Status = SessionStatus.Disconnected;
        ErrorMessage = null;
        FailedDueToCredentials = false;
    }

    /// <summary>
    /// Event-driven teardown: dispose the dead session, then either flip to Disconnected
    /// (clean shutdown) or surface the failure overlay. Called from OnSessionDisconnected /
    /// OnSessionLogonError / OnSessionFatalError so the shape stays consistent.
    /// </summary>
    private void DisposeAndTransition(string? failureMessage, bool dueToCredentials)
    {
        DisposeSessionSilently();
        if (failureMessage is null)
        {
            Status = SessionStatus.Disconnected;
            ErrorMessage = null;
            FailedDueToCredentials = false;
        }
        else
        {
            ReportFailure(failureMessage, dueToCredentials);
        }
    }

    private void DisposeSessionSilently()
    {
        var session = _session;
        _session = null;
        if (session is null) return;

        session.Connected -= OnSessionConnected;
        session.Disconnected -= OnSessionDisconnected;
        session.FatalError -= OnSessionFatalError;
        session.LogonError -= OnSessionLogonError;
        session.AutoReconnecting -= OnSessionAutoReconnecting;

        try { session.Disconnect(); }
        catch (Exception ex) { _logger.LogWarning(ex, "Disconnect threw during teardown."); }

        try { session.Dispose(); }
        catch (Exception ex) { _logger.LogWarning(ex, "Dispose threw during teardown."); }
    }

    // Test-only hook mirroring the SSH pattern — lets unit tests bypass the real service.
    internal void AttachConnectedSessionForTesting(IRdpSession session)
    {
        _session = session;
        _session.Connected += OnSessionConnected;
        _session.Disconnected += OnSessionDisconnected;
        _session.FatalError += OnSessionFatalError;
        _session.LogonError += OnSessionLogonError;
        _session.AutoReconnecting += OnSessionAutoReconnecting;
        EnsureDispatcher();
        Status = SessionStatus.Connected;
    }

    /// <summary>
    /// Mappings for the OnLogonError codes the ActiveX may raise, taken from the
    /// IMsTscAxEvents.OnLogonError reference at
    /// learn.microsoft.com/windows/win32/termserv/imstscaxevents-onlogonerror. The published
    /// table only documents three values; an earlier revision had additional made-up mappings
    /// (account disabled / locked / expired) that misclassified errors. Unknown codes fall
    /// through to a generic message so the user still has something actionable.
    /// </summary>
    private static class RdpLogonErrors
    {
        private static readonly IReadOnlyDictionary<int, string> Descriptions = new Dictionary<int, string>
        {
            [-2] = "The credentials dialog was cancelled.",
            [-3] = "Pre-authentication failed.",
            [-5] = "An information dialog was displayed (e.g. Lock Workstation Failed).",
        };

        public static string Describe(int code) =>
            Descriptions.TryGetValue(code, out var msg) ? msg : $"Logon failed (code {code}).";
    }
}
