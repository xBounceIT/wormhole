using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using Wormhole.Data.Repositories;
using Wormhole.Helpers;
using Wormhole.Models;
using Wormhole.Services;
using Wormhole.Services.Rdp;
using Wormhole.Services.Tunneling;

namespace Wormhole.ViewModels.Sessions;

public sealed partial class RdpSessionViewModel : SessionTabViewModel
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(30);
    private static readonly string TimeoutMessage =
        $"RDP server didn't respond within {ConnectTimeout.TotalSeconds:0} seconds.";
    private const string TunnelExternalClientUnsupportedMessage =
        "The external Remote Desktop client cannot be used with a per-connection VPN tunnel because mstsc.exe would connect from the host network. Use embedded RDP without Azure AD/external-client routing, or disable the tunnel.";
    private const string TunnelGatewayUnsupportedMessage =
        "RD Gateway cannot be used with a per-connection VPN tunnel yet because the ActiveX control would open gateway traffic from the host network. Disable RD Gateway for this connection, or disable the tunnel.";
    private const string TunnelStrictServerAuthUnsupportedMessage =
        "Strict RDP server authentication cannot be used with the current per-connection VPN tunnel because the embedded ActiveX control validates the loopback forwarder name instead of the original server name. Set server authentication to Warn, or disable the tunnel.";

    private readonly IRdpSessionService _rdpService;
    private readonly ICredentialService _credentialService;
    private readonly ICredentialRepository _credentialRepository;
    private readonly TunnelManager _tunnels;
    private readonly IDialogService _dialog;
    private readonly IRdpCrashSentinelService _crashSentinel;
    private readonly ILogger<RdpSessionViewModel> _logger;

    private IRdpSession? _session;
    private ITunnelInstance? _tunnel;
    private CancellationTokenSource? _cts;
    private int _connectInFlight;
    private int _teardownGeneration;
    private IntPtr _ownerHwnd;
    private bool _initialAutoConnectStarted;
    private bool _hasLoggedOn;
    private bool _teardownRequested;
    private int? _lastLogonErrorCode;
    private HostBounds _lastMeasuredBounds = HostBounds.Empty;
    // Set when the profile (or the user via UseExternalClientCommand) routes this tab to
    // the system Remote Desktop client instead of the embedded ActiveX. Tracked so we can
    // clean up the Exited subscription on teardown without killing the user's session.
    private Process? _externalProcess;
    // True while THIS VM owns the active embedded-RDP crash sentinel — i.e. we wrote the
    // mark and the OCX handshake has not yet reached a terminal state. The flag exists so
    // that, in a multi-RDP-tab scenario where Tab A is external and Tab B is embedded, a
    // Status transition on Tab A doesn't clear the sentinel Tab B just wrote. Only the VM
    // that owns the mark may clear it.
    private bool _ownsCrashSentinel;

    public RdpSessionViewModel(
        IRdpSessionService rdpService,
        ICredentialService credentialService,
        ICredentialRepository credentialRepository,
        TunnelManager tunnels,
        IDialogService dialog,
        IRdpCrashSentinelService crashSentinel,
        ILoggerFactory loggerFactory)
    {
        _rdpService = rdpService;
        _credentialService = credentialService;
        _credentialRepository = credentialRepository;
        _tunnels = tunnels;
        _dialog = dialog;
        _crashSentinel = crashSentinel;
        _logger = loggerFactory.CreateLogger<RdpSessionViewModel>();

        // Status lives on the base class — re-broadcast its dependents from the derived VM
        // since [NotifyPropertyChangedFor] only sees properties on its own partial class.
        // We also use Status changes to clear the crash sentinel once the embedded session
        // is either terminal or has completed login. OnConnected now means native surface
        // ready, not authenticated, so Connected alone is not enough to close the WAM
        // delay-load danger window. Fire-and-forget is fine — the sentinel writes are small,
        // idempotent, and a missed clear just causes a benign auto-flag on the next launch.
        PropertyChanged += (_, args) =>
        {
            if (args.PropertyName == nameof(Status))
            {
                OnPropertyChanged(nameof(IsConnecting));
                OnPropertyChanged(nameof(IsConnected));
                OnPropertyChanged(nameof(IsDisconnected));
                OnPropertyChanged(nameof(IsFailed));
                OnPropertyChanged(nameof(CanDisconnect));
                RetryCommand.NotifyCanExecuteChanged();

                ClearCrashSentinelIfSafe();
            }
        };
    }

    public override ProtocolType Protocol => ProtocolType.Rdp;

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

    /// <summary>True while this tab is tracking an external mstsc.exe process instead of an embedded OCX surface.</summary>
    [ObservableProperty]
    private bool isExternalClientActive;

    public bool IsConnecting => Status == SessionStatus.Connecting;
    public bool IsConnected => Status == SessionStatus.Connected;
    public bool IsDisconnected => Status == SessionStatus.Disconnected;
    public bool IsFailed => Status == SessionStatus.Failed;
    public bool CanUseExternalClient => Profile?.TunnelEnabled != true && !IsExternalClientActive;
    public bool CanDisconnect => Status is SessionStatus.Connecting or SessionStatus.Connected || IsExternalClientActive;

    internal Func<ProcessStartInfo, Process?> ExternalProcessLauncher { get; set; } = Process.Start;

    public override void Initialize(ConnectionProfile profile)
    {
        base.Initialize(profile);
        _initialAutoConnectStarted = false;
        OnPropertyChanged(nameof(CanUseExternalClient));
        OnPropertyChanged(nameof(CanDisconnect));
        UseExternalClientCommand.NotifyCanExecuteChanged();
    }

    partial void OnIsExternalClientActiveChanged(bool value)
    {
        OnPropertyChanged(nameof(CanUseExternalClient));
        OnPropertyChanged(nameof(CanDisconnect));
        UseExternalClientCommand.NotifyCanExecuteChanged();
        RetryCommand.NotifyCanExecuteChanged();
    }

    // Protocol-specific bootstrapping is still done lazily on AttachAsync once the surface
    // host has the owner HWND; Initialize only refreshes command state derived from Profile.

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
        RememberMeasuredBounds(bounds);
        EnsureDispatcher();

        if (_session is not null)
        {
            // Re-attach path: surface host reloaded after nav-away. The session survives in
            // ShellViewModel.Tabs. Reveal the surface only when actually Connected — if the
            // session is mid-auto-reconnect (Status == Connecting), keep it hidden so the
            // ConnectingOverlay (spinner + Cancel) shows instead of a stale surface popping over
            // it (the native overlay is composited ABOVE the WinUI content).
            if (Status == SessionStatus.Connected)
            {
                try
                {
                    if (!bounds.IsDegenerate(minDim: 1)) _session.SetBounds(bounds);
                    _session.Show();
                    // Push Win32 keyboard focus back into the ActiveX HWND so the first keystroke
                    // after navigating back lands on the remote session rather than requiring a
                    // click. SetFocus is idempotent so this is safe to repeat.
                    TryFocusSession();
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "RDP surface reattach failed.");
                    await DisposeAndTransitionAsync("RDP surface reattach failed: " + ex.Message, dueToCredentials: false)
                        .ConfigureAwait(true);
                }
            }
            return;
        }

        // External-client re-attach: mstsc.exe runs in its own window outside the WinUI
        // surface, so there's nothing to re-bind here. We just need to NOT spawn a second
        // mstsc.exe — the surface host is recreated on every Sessions↔Settings nav, and
        // without this guard the VM would launch a duplicate every time the tab is shown.
        if (_externalProcess is { } externalProcess)
        {
            if (HasExternalProcessExited(externalProcess))
            {
                HandleExternalProcessExited(externalProcess, GetBaseTitle(Profile));
            }
            return;
        }

        // First view load auto-starts the tab. After a terminal state (failed,
        // disconnected, prompt-cancel, external mstsc exit), the overlay owns the next
        // action via Retry/Open External; navigating away and back must not silently
        // start a fresh RDP attempt.
        if (_initialAutoConnectStarted && Status is SessionStatus.Disconnected or SessionStatus.Failed)
        {
            return;
        }

        _initialAutoConnectStarted = true;
        await ConnectAsync(ownerHwnd, bounds, forcePromptForPassword: false).ConfigureAwait(true);
    }

    public void SetBounds(HostBounds bounds)
    {
        RememberMeasuredBounds(bounds);
        var session = _session;
        if (session is null) return;
        // Pushing bounds to the native host calls SetHostBounds → EnsureVisibleAndRedraw, which
        // forces the window visible. Only do that when Connected; during Connecting / auto-reconnect
        // a layout tick would otherwise reveal the surface over the WinUI ConnectingOverlay
        // (spinner + Cancel). The surface is shown explicitly on the Connected flip
        // (ResumeSurfaceForOverlay); here we only need to remember the latest measured bounds.
        if (Status != SessionStatus.Connected) return;

        try
        {
            session.SetBounds(bounds);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "RDP surface resize failed.");
            MarshalToUi(() => DisposeAndTransitionAsync("RDP surface resize failed: " + ex.Message, dueToCredentials: false));
        }
    }

    public void DetachView()
    {
        // Hide rather than tear down — the VM survives navigation. ShowWindow(SW_HIDE) is
        // idempotent so we don't need to track our own visibility flag.
        try { _session?.Hide(); }
        catch (Exception ex) { _logger.LogWarning(ex, "Hide failed during DetachView."); }
    }

    /// <summary>
    /// Hide the owned RDP overlay window while a modal WinUI dialog is shown over the tab (the
    /// top-level overlay would otherwise occlude the dialog) or while the main window is
    /// minimized. No-op when there is no live embedded session. Same native effect as
    /// <see cref="DetachView"/>; kept separate for intent / call-site clarity.
    /// </summary>
    public void SuspendSurfaceForOverlay()
    {
        try { _session?.Hide(); }
        catch (Exception ex) { _logger.LogDebug(ex, "RDP overlay suspend (Hide) suppressed."); }
    }

    /// <summary>
    /// Re-show the owned RDP overlay on the Connected transition, after a covering dialog closed,
    /// or after the main window was restored, re-applying the current surface bounds. No-op when
    /// there is no live embedded session or it isn't Connected. Deliberately does NOT push keyboard
    /// focus: this runs on every Status→Connected flip including auto-reconnect, and stealing focus
    /// there would defeat <see cref="OnSessionAutoReconnected"/>'s no-focus-steal design.
    /// Cold-connect focus is pushed by <see cref="OnSessionConnected"/>; nav-back focus by the
    /// AttachAsync re-attach branch. A genuine show failure is surfaced as a session failure.
    /// </summary>
    public void ResumeSurfaceForOverlay(HostBounds bounds)
    {
        var session = _session;
        if (session is null) return;
        // Only the Connected state may reveal the surface. During Connecting / auto-reconnect /
        // Failed / Disconnected the WinUI status overlays (spinner+Cancel, error+Retry) own the
        // tab, and the top-level surface — composited ABOVE the WinUI content — must stay hidden
        // so it doesn't occlude them.
        if (Status != SessionStatus.Connected) return;
        // If the freshly-computed bounds are degenerate (transient relayout / ClientToScreen
        // failure), fall back to the last good measured bounds so we still reveal the surface at
        // the right place — rather than flashing the 1x1 activation seed, or stranding it hidden
        // when a later cached SetBounds no-ops. Bail only if no valid bounds exist yet at all.
        if (bounds.IsDegenerate(minDim: 1))
        {
            if (_lastMeasuredBounds.IsDegenerate(minDim: 1)) return;
            bounds = _lastMeasuredBounds;
        }
        try
        {
            session.SetBounds(bounds);
            session.Show();
        }
        catch (Exception ex)
        {
            // A genuine failure to position/show the native surface leaves a blank tab — surface
            // it as a session failure (error overlay + Retry) instead of silently swallowing, the
            // same guarantee the old synchronous Show() in ConnectAsync provided.
            _logger.LogWarning(ex, "RDP overlay resume failed; surfacing as session failure.");
            MarshalToUi(() => DisposeAndTransitionAsync(
                "RDP surface failed to become visible: " + ex.Message, dueToCredentials: false));
        }
    }

    [RelayCommand]
    public async Task DisconnectAsync()
    {
        await FullTeardownAsync().ConfigureAwait(true);
    }

    /// <summary>
    /// User-initiated switch to the system mstsc.exe. Available regardless of the profile's
    /// RdpUseExternalClient setting so the failure overlay can offer it as a fallback after
    /// an embedded connection error. Tears down any in-flight embedded session first; the
    /// spawned mstsc.exe lives independently and survives a Wormhole Disconnect / tab close
    /// (we just stop tracking it — see FullTeardown).
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanUseExternalClient))]
    public async Task UseExternalClient()
    {
        var profile = Profile;
        if (profile is null) return;
        if (HasLiveExternalProcess(profile)) return;
        if (profile.TunnelEnabled)
        {
            if (Status is not SessionStatus.Connected and not SessionStatus.Connecting)
            {
                ReportFailure(TunnelExternalClientUnsupportedMessage, dueToCredentials: false);
            }
            return;
        }
        await FullTeardownAsync().ConfigureAwait(true);
        LaunchExternalProcess(profile);
    }

    [RelayCommand(AllowConcurrentExecutions = false, CanExecute = nameof(CanRetry))]
    public async Task RetryAsync()
    {
        if (Profile is null || _ownerHwnd == IntPtr.Zero) return;
        if (Volatile.Read(ref _connectInFlight) != 0) return;
        if (HasLiveExternalProcess(Profile)) return;

        var forcePrompt = FailedDueToCredentials;
        await FullTeardownAsync(fastTunnelTeardown: true).ConfigureAwait(true);

        // Reuse the last real layout bounds for desktop-size negotiation. Passing the 1x1
        // seed through here would make default/Full screen retries negotiate a 640x480
        // remote desktop that is only smart-sized inside the tab afterward.
        await ConnectAsync(_ownerHwnd, GetRetryInitialBounds(), forcePromptForPassword: forcePrompt).ConfigureAwait(true);
    }

    // Mirrors SshSessionViewModel: while Connecting, an in-flight ConnectAsync still holds
    // _connectInFlight; a second one from RetryAsync would silently no-op. Disabling the
    // command keeps the tab context menu / failure overlay in sync with the actual state.
    private bool CanRetry() =>
        Status != SessionStatus.Connecting &&
        !IsExternalClientActive &&
        Volatile.Read(ref _connectInFlight) == 0;

    public override async ValueTask CloseAsync()
    {
        await FullTeardownAsync().ConfigureAwait(true);
    }

    private async Task ConnectAsync(IntPtr ownerHwnd, HostBounds initialBounds, bool forcePromptForPassword)
    {
        var profile = Profile;
        if (profile is null) return;

        // Grab the in-flight gate FIRST so a Disconnect click during the routing decision
        // can't race past us. FullTeardown sets Status=Disconnected but doesn't touch
        // _connectInFlight; without acquiring this before the await on ShouldUseExternalClientAsync
        // (which may hit the DB to inspect the credential), the disconnect would be silently
        // ignored — ConnectAsync would resume and continue with a connect the user just
        // cancelled. The outer try/finally guarantees the gate is released on every exit
        // path including external-client early-return and any throw from Mark/LaunchExternalProcess.
        if (Interlocked.CompareExchange(ref _connectInFlight, 1, 0) != 0) return;
        var teardownGeneration = Volatile.Read(ref _teardownGeneration);
        try
        {
            Status = SessionStatus.Connecting;
            ErrorMessage = null;
            FailedDueToCredentials = false;
            IsExternalClientActive = false;
            ReconnectAttempt = 0;
            _hasLoggedOn = false;
            _lastLogonErrorCode = null;
            _teardownRequested = false;

            // External-client routing: opt-in flag OR auto-detected Azure-AD signal (saved
            // credential, node Username, node RdpDomain). The embedded mstscax delay-loads
            // WAM broker DLLs during AAD auth, which our unpackaged WinUI process can't
            // satisfy — the failure surfaces as SEH 0xC06D007F deep below any managed frame
            // and kills the process unrecoverably. mstsc.exe is a packaged-trusted system
            // binary that handles AAD cleanly. For AAD signals this branch fires
            // UNCONDITIONALLY so a user who clears the editor flag can't accidentally take
            // down the app.
            if (await ShouldUseExternalClientAsync(profile).ConfigureAwait(true))
            {
                if (!IsAttemptCurrent(teardownGeneration)) return;
                if (profile.TunnelEnabled)
                {
                    ReportFailure(TunnelExternalClientUnsupportedMessage, dueToCredentials: false);
                    return;
                }
                LaunchExternalProcess(profile);
                return;
            }
            if (!IsAttemptCurrent(teardownGeneration)) return;

            if (profile.TunnelEnabled && profile.RdpGatewayUsageMethod != 0)
            {
                ReportFailure(TunnelGatewayUnsupportedMessage, dueToCredentials: false);
                return;
            }
            if (profile.TunnelEnabled && profile.RdpServerAuthentication == 1)
            {
                ReportFailure(TunnelStrictServerAuthUnsupportedMessage, dueToCredentials: false);
                return;
            }

            // Write the crash sentinel before the OCX touches mstscax (where the native WAM
            // crash originates), so a process death in that window leaves the sentinel behind
            // for the next launch. The Status hook only clears a sentinel owned by this VM,
            // and _ownsCrashSentinel remains false until Mark succeeds, so it is safe for the
            // visible Connecting state to start before this disk write.
            // Inner try/catch keeps a Mark failure (file lock, disk full, ACL denial) from
            // poisoning the connect path: we log and proceed without the recovery breadcrumb
            // for this attempt. Without this, an IOException from Task.Run inside Mark would
            // escape, the outer finally would release _connectInFlight, but
            // _ownsCrashSentinel would stay true — the next legitimate Mark would then
            // race-clear a successful sentinel on the first Status transition.
            try
            {
                await _crashSentinel.MarkConnectInFlightAsync(profile.NodeId, profile.Host).ConfigureAwait(true);
                _ownsCrashSentinel = true;
                if (!IsAttemptCurrent(teardownGeneration))
                {
                    ClearOwnedCrashSentinel();
                    return;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to write RDP crash sentinel — proceeding without recovery breadcrumb for this attempt.");
                // _ownsCrashSentinel stays false. No file on disk means there's nothing for
                // the hook to clear; subsequent attempts behave normally.
            }

            // The CTS exists from the start so FullTeardown / Disconnect can cancel an in-flight
            // connect, but the ConnectTimeout itself only kicks in once we've actually started
            // the network handshake. Counting credential-entry time against the 30s budget would
            // make a slow typist's correct password expire before the OCX ever sees it.
            var previousCts = _cts;
            var cts = new CancellationTokenSource();
            _cts = cts;
            previousCts?.Dispose();
            var token = cts.Token;
            var timedOut = false;

            try
            {
                var resolved = await ResolveCredentialsAsync(profile, forcePromptForPassword, token).ConfigureAwait(true);
                if (!IsAttemptCurrent(teardownGeneration)) return;
                if (token.IsCancellationRequested)
                {
                    TransitionToDisconnectedIfCurrent(cts);
                    return;
                }

                // ResolveCredentialsAsync returns null only when the user cancelled the prompt —
                // silent return to Disconnected, not Failed (no error message to show). Covers
                // both "no saved credential" and "credential Id pointed at a deleted Credential
                // Manager entry, fell through to a prompt, user cancelled". Either way, no.
                if (resolved is not { } creds)
                {
                    ClearConnectWatchdog(cts);
                    Status = SessionStatus.Disconnected;
                    return;
                }
                var password = creds.Password;
                var resolvedProfile = profile with
                {
                    Username = creds.Username,
                    RdpDomain = creds.Domain,
                };
                _logger.LogInformation(
                    "RDP credentials resolved for {Host}:{Port}: hasUsername={HasUsername}, hasDomain={HasDomain}, passwordSource={PasswordSource}, usernameSource={UsernameSource}, domainSource={DomainSource}.",
                    profile.Host,
                    profile.Port,
                    !string.IsNullOrEmpty(resolvedProfile.Username),
                    !string.IsNullOrEmpty(resolvedProfile.RdpDomain),
                    creds.PasswordSource,
                    creds.UsernameSource,
                    creds.DomainSource);

                // Thread the resolved identity into the profile so PrepareConnectProfileAsync
                // and the OCX both see the same username/domain. This covers linked saved
                // credentials whose username/domain differ from the node's inherited fields.
                if (!string.Equals(resolvedProfile.Username, profile.Username, StringComparison.Ordinal) ||
                    !string.Equals(resolvedProfile.RdpDomain, profile.RdpDomain, StringComparison.Ordinal))
                {
                    profile = resolvedProfile;

                    // The external-client routing decision at the top of ConnectAsync ran with
                    // the pre-resolution identity, so an AAD-flavored username/domain supplied
                    // by a prompt or linked credential may not have triggered the auto-route to
                    // mstsc.exe. Re-evaluate the same guard with the late-bound identity.
                    if (await ShouldUseExternalClientAsync(profile).ConfigureAwait(true))
                    {
                        if (!IsAttemptCurrent(teardownGeneration)) return;
                        if (profile.TunnelEnabled)
                        {
                            ReportFailure(TunnelExternalClientUnsupportedMessage, dueToCredentials: false);
                            return;
                        }
                        LaunchExternalProcess(profile);
                        return;
                    }
                }

                var (gwUser, gwPassword) = await ResolveGatewayCredentialsAsync(profile, token).ConfigureAwait(true);
                if (!IsAttemptCurrent(teardownGeneration)) return;
                var connectProfile = await PrepareConnectProfileAsync(profile, token).ConfigureAwait(true);
                if (!IsAttemptCurrent(teardownGeneration)) return;
                token.ThrowIfCancellationRequested();

                // ConnectAsync returns immediately after kicking off the asynchronous OCX
                // handshake, so without a real watchdog there's no way to surface a "server
                // never answered" timeout. Start that watchdog only after gateway credential
                // lookup and tunnel startup: those have their own failure/cancel behavior, and
                // counting a slow VPN handshake against the RDP server response budget would
                // incorrectly report "RDP server didn't respond" before the ActiveX ever tried.
                cts.Token.Register(() =>
                {
                    // User-initiated cancels (FullTeardown) null _cts BEFORE calling Cancel,
                    // so this guard distinguishes timer-fire from user-fire.
                    if (!ReferenceEquals(_cts, cts)) return;
                    timedOut = true;
                    MarshalToUi(async () =>
                    {
                        if (!ReferenceEquals(_cts, cts)) return;
                        if (Status != SessionStatus.Connecting) return;
                        await DisposeAndTransitionAsync(TimeoutMessage, dueToCredentials: false).ConfigureAwait(true);
                    });
                });
                cts.CancelAfter(ConnectTimeout);

                // Subscribe via the onSessionReady hook (not after the await) so the VM is ready
                // to receive an immediate OnLogonError / OnDisconnected that the OCX may fire
                // synchronously during the Connect() inside form.Start(). Subscribing after the
                // returned Task completes would drop those events and strand us in Connecting.
                var session = await _rdpService.ConnectAsync(
                    connectProfile, password, ownerHwnd, gwUser, gwPassword,
                    initialBounds: initialBounds,
                    onSessionReady: s =>
                    {
                        AttachSession(s, hasLoggedOn: false);
                    },
                    cancellationToken: token).ConfigureAwait(true);
                if (!IsAttemptCurrent(teardownGeneration))
                {
                    try { session.Dispose(); }
                    catch (Exception ex) { _logger.LogWarning(ex, "Late RDP session dispose threw after stale connect attempt."); }
                    return;
                }
                if (!ReferenceEquals(_session, session))
                {
                    try { session.Dispose(); }
                    catch (Exception ex) { _logger.LogWarning(ex, "Late RDP session dispose threw after early terminal event."); }
                    return;
                }
                token.ThrowIfCancellationRequested();

                session.SetBounds(initialBounds.IsDegenerate(minDim: 1) ? HostBounds.Seed : initialBounds);
                // The overlay is now a top-level window composited ABOVE the WinUI content.
                // Status can already be Connected here only when the OnConnected→Status update ran
                // INLINE (e.g. the test harness with no UI dispatcher). In the running app,
                // OnSessionConnected is marshalled to a later UI turn, so Status is still Connecting
                // here and the else-branch keeps the surface hidden; RdpSurfaceHost reveals it on the
                // Connected flip via ResumeSurfaceForOverlay, which surfaces show failures the same way.
                if (Status == SessionStatus.Connected)
                {
                    session.Show();
                }
                else
                {
                    // Still handshaking: keep the surface hidden so the ConnectingOverlay (spinner
                    // + Cancel) stays visible.
                    session.Hide();
                }
            }
            catch (OperationCanceledException) when (timedOut)
            {
                DisposeSessionSilently();
                await DisposeTunnelSilentlyAsync().ConfigureAwait(true);
                if (ReferenceEquals(_cts, cts))
                {
                    ReportFailure(TimeoutMessage, dueToCredentials: false);
                }
            }
            catch (OperationCanceledException)
            {
                DisposeSessionSilently();
                await DisposeTunnelSilentlyAsync().ConfigureAwait(true);
                TransitionToDisconnectedIfCurrent(cts);
            }
            catch (Exception) when (token.IsCancellationRequested)
            {
                DisposeSessionSilently();
                await DisposeTunnelSilentlyAsync().ConfigureAwait(true);
                TransitionToDisconnectedIfCurrent(cts);
            }
            catch (System.Runtime.InteropServices.COMException ex) when ((uint)ex.HResult == 0x80040154)
            {
                // REGDB_E_CLASSNOTREG — mstscax not registered (Server Core, N edition).
                DisposeSessionSilently();
                await DisposeTunnelSilentlyAsync().ConfigureAwait(true);
                if (!IsAttemptCurrent(teardownGeneration)) return;
                ReportFailure(
                    "Microsoft Remote Desktop ActiveX (mstscax.dll) is not registered on this system. " +
                    "Install the Remote Desktop Connection client.",
                    dueToCredentials: false);
                _logger.LogError(ex, "RDP ActiveX not registered.");
            }
            catch (Exception ex)
            {
                DisposeSessionSilently();
                await DisposeTunnelSilentlyAsync().ConfigureAwait(true);
                if (!IsAttemptCurrent(teardownGeneration)) return;
                ReportFailure(ex.Message, dueToCredentials: false);
                _logger.LogError(ex, "RDP connect failed for {Host}:{Port}.", profile.Host, profile.Port);
            }
        }
        finally
        {
            // Single point of release for _connectInFlight, regardless of whether we took the
            // external-client early-return, the embedded path, or threw out of either.
            Interlocked.Exchange(ref _connectInFlight, 0);
            RetryCommand.NotifyCanExecuteChanged();
        }
    }

    private async Task<ConnectionProfile> PrepareConnectProfileAsync(ConnectionProfile profile, CancellationToken token)
    {
        var tunnel = await _tunnels.EstablishAsync(profile, token).ConfigureAwait(true);
        if (tunnel is null) return profile;
        if (token.IsCancellationRequested)
        {
            await DisposeTunnelInstanceSilentlyAsync(tunnel).ConfigureAwait(true);
            token.ThrowIfCancellationRequested();
        }

        var previousTunnel = Interlocked.Exchange(ref _tunnel, tunnel);
        if (previousTunnel is not null)
        {
            await DisposeTunnelInstanceSilentlyAsync(previousTunnel).ConfigureAwait(true);
        }

        try
        {
            var localPort = await tunnel.BindLocalForwarderAsync(profile.Host, profile.Port, token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            return profile with
            {
                Host = IPAddress.Loopback.ToString(),
                Port = localPort,
            };
        }
        catch
        {
            if (ReferenceEquals(Interlocked.CompareExchange(ref _tunnel, null, tunnel), tunnel))
            {
                await DisposeTunnelInstanceSilentlyAsync(tunnel).ConfigureAwait(true);
            }
            throw;
        }
    }

    /// <summary>
    /// Resolve the credentials needed for the RDP connection. Returns a fully resolved
    /// username/domain/password set on success or <c>null</c> if the user cancels a prompt.
    /// Identity precedence is explicit profile fields first, then the linked credential
    /// profile, then an interactive Wormhole prompt.
    /// </summary>
    private async Task<ResolvedRdpCredentials?> ResolveCredentialsAsync(ConnectionProfile profile, bool forcePrompt, CancellationToken token)
    {
        CredentialProfile? credential = null;
        if (profile.CredentialId is { } lookupId)
        {
            try
            {
                credential = await _credentialRepository.GetByIdAsync(lookupId, token).ConfigureAwait(true);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to read credential profile {CredentialId} for RDP identity resolution.", lookupId);
            }
        }
        token.ThrowIfCancellationRequested();

        var explicitUsername = NullIfWhiteSpace(profile.Username);
        var explicitDomain = NullIfWhiteSpace(profile.RdpDomain);
        var credentialUsername = NullIfWhiteSpace(credential?.Username);
        var credentialDomain = NullIfWhiteSpace(credential?.Domain);

        var username = explicitUsername ?? credentialUsername;
        var domain = explicitDomain ?? credentialDomain;
        var usernameSource = explicitUsername is not null
            ? RdpCredentialValueSource.Profile
            : credentialUsername is not null
                ? RdpCredentialValueSource.Credential
                : RdpCredentialValueSource.Prompt;
        var domainSource = explicitDomain is not null
            ? RdpCredentialValueSource.Profile
            : credentialDomain is not null
                ? RdpCredentialValueSource.Credential
                : RdpCredentialValueSource.None;

        if (username is not null)
        {
            var parsed = SplitDomainUsername(username, domain, allowDomainFromUsername: domain is null);
            username = parsed.Username;
            domain = parsed.Domain;
            if (parsed.DomainSourceWasPrompt)
            {
                domainSource = usernameSource;
            }
        }

        if (!forcePrompt && profile.CredentialId is { } credId)
        {
            try
            {
                var stored = await _credentialService.ReadPasswordAsync(credId).ConfigureAwait(true);
                if (stored is not null && username is not null)
                {
                    return new ResolvedRdpCredentials(
                        username,
                        domain,
                        stored,
                        usernameSource,
                        domainSource,
                        RdpCredentialPasswordSource.SavedCredential);
                }
                // Missing secret or missing identity: prompt rather than handing the OCX
                // partial credentials. Empty-string passwords are valid and already returned
                // above because only null means the Credential Manager entry is missing.
                if (stored is null)
                {
                    _logger.LogInformation("Credential {CredentialId} password not found in Credential Manager — prompting.", credId);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to read credential {CredentialId} — prompting.", credId);
            }
        }
        token.ThrowIfCancellationRequested();

        if (username is null)
        {
            var prompted = await _dialog.PromptCredentialsAsync(
                "RDP credentials",
                $"Enter credentials for {profile.Host}",
                initialUsername: null).ConfigureAwait(true);
            if (prompted is null) return null;

            var parsedPrompt = SplitDomainUsername(
                prompted.Value.Username,
                explicitDomain ?? credentialDomain,
                allowDomainFromUsername: explicitDomain is null && credentialDomain is null);
            return new ResolvedRdpCredentials(
                parsedPrompt.Username,
                parsedPrompt.Domain,
                prompted.Value.Password,
                RdpCredentialValueSource.Prompt,
                parsedPrompt.DomainSourceWasPrompt
                    ? RdpCredentialValueSource.Prompt
                    : explicitDomain is not null
                        ? RdpCredentialValueSource.Profile
                        : credentialDomain is not null
                            ? RdpCredentialValueSource.Credential
                            : RdpCredentialValueSource.None,
                RdpCredentialPasswordSource.Prompt);
        }

        var prefix = !string.IsNullOrEmpty(domain)
            ? $"{domain}\\{username}"
            : username;
        var promptMsg = $"Enter password for {prefix}@{profile.Host}";
        var password = await _dialog.PromptPasswordAsync("RDP credentials", promptMsg).ConfigureAwait(true);
        return password is null
            ? null
            : new ResolvedRdpCredentials(
                username,
                domain,
                password,
                usernameSource,
                domainSource,
                RdpCredentialPasswordSource.Prompt);
    }

    private static string? NullIfWhiteSpace(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static (string Username, string? Domain, bool DomainSourceWasPrompt) SplitDomainUsername(
        string rawUsername,
        string? existingDomain,
        bool allowDomainFromUsername)
    {
        var username = rawUsername.Trim();
        var domain = NullIfWhiteSpace(existingDomain);
        if (!allowDomainFromUsername) return (username, domain, false);

        var slash = username.IndexOf('\\');
        if (slash <= 0 || slash == username.Length - 1) return (username, domain, false);

        return (username[(slash + 1)..], username[..slash], true);
    }

    private sealed record ResolvedRdpCredentials(
        string Username,
        string? Domain,
        string Password,
        RdpCredentialValueSource UsernameSource,
        RdpCredentialValueSource DomainSource,
        RdpCredentialPasswordSource PasswordSource);

    private enum RdpCredentialValueSource
    {
        None,
        Profile,
        Credential,
        Prompt,
    }

    private enum RdpCredentialPasswordSource
    {
        SavedCredential,
        Prompt,
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
            if (!ReferenceEquals(_session, sender)) return;
            ClearConnectWatchdog();
            ReconnectAttempt = 0;
            Status = SessionStatus.Connected;
            ErrorMessage = null;
            // Push Win32 focus into the embedded ActiveX HWND once the native RDP surface
            // is ready. The Windows logon screen may still be ahead of LoginComplete, but
            // keyboard input should land in the ActiveX canvas immediately.
            TryFocusSession();
        });
    }

    private void OnSessionLoginComplete(object? sender, EventArgs e)
    {
        MarshalToUi(() =>
        {
            if (!ReferenceEquals(_session, sender)) return;
            ClearConnectWatchdog();
            _hasLoggedOn = true;
            _lastLogonErrorCode = null;
            ReconnectAttempt = 0;
            ErrorMessage = null;
            FailedDueToCredentials = false;
            Status = SessionStatus.Connected;
            ClearCrashSentinelIfSafe();
        });
    }

    private void OnSessionDisconnected(object? sender, RdpDisconnectInfo info)
    {
        MarshalToUi(() =>
        {
            if (!ReferenceEquals(_session, sender)) return Task.CompletedTask;
            var loggedOn = _hasLoggedOn || (sender as IRdpSession)?.IsLoggedOn == true;
            var (failureMessage, dueToCredentials) = BuildDisconnectFailure(info, loggedOn, _teardownRequested, _lastLogonErrorCode);
            return DisposeAndTransitionAsync(failureMessage, dueToCredentials);
        });
    }

    private void OnSessionLogonError(object? sender, int code)
    {
        MarshalToUi(() =>
        {
            if (!ReferenceEquals(_session, sender)) return;
            _lastLogonErrorCode = code;
            if (code == -2)
            {
                _logger.LogInformation("RDP OnLogonError reported continue-logon notification ({Code}); waiting for LoginComplete or Disconnected.", code);
            }
            else
            {
                _logger.LogInformation("RDP OnLogonError reported {Code}: {Description}", code, RdpLogonErrors.Describe(code));
            }
        });
    }

    private void OnSessionFatalError(object? sender, int code)
    {
        MarshalToUi(() =>
        {
            if (!ReferenceEquals(_session, sender)) return Task.CompletedTask;
            return DisposeAndTransitionAsync(
                failureMessage: $"RDP fatal error (code {code}).",
                dueToCredentials: false);
        });
    }

    private void OnSessionAutoReconnecting(object? sender, RdpReconnectInfo info)
    {
        MarshalToUi(() =>
        {
            if (!ReferenceEquals(_session, sender)) return;
            ReconnectAttempt = info.Attempt;
            Status = SessionStatus.Connecting;
        });
    }

    private void OnSessionAutoReconnected(object? sender, EventArgs e)
    {
        // Without this, OnAutoReconnecting drove Status to Connecting and no event would
        // ever drive it back — the user would see the reconnect banner indefinitely after
        // a transient drop recovered.
        //
        // Intentionally NOT calling TryFocusSession here: auto-reconnect is not user-
        // initiated, and the user may have moved focus elsewhere (different tab, search
        // box, even another app) during the reconnect banner. Pulling focus back to the
        // RDP surface mid-typing is worse than the original problem. The OCX retains its
        // own Win32 focus across most auto-reconnect cycles, so the natural outcome is
        // "focus stays where the user put it", which is the right default.
        MarshalToUi(() =>
        {
            if (!ReferenceEquals(_session, sender)) return;
            ClearConnectWatchdog();
            _hasLoggedOn = true;
            _lastLogonErrorCode = null;
            ReconnectAttempt = 0;
            Status = SessionStatus.Connected;
            ErrorMessage = null;
            FailedDueToCredentials = false;
            ClearCrashSentinelIfSafe();
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
        IsExternalClientActive = false;
        Status = SessionStatus.Failed;
    }

    private void TransitionToDisconnectedIfCurrent(CancellationTokenSource cts)
    {
        if (!ReferenceEquals(_cts, cts)) return;
        ClearConnectWatchdog(cts);
        IsExternalClientActive = false;
        Status = SessionStatus.Disconnected;
    }

    private bool IsAttemptCurrent(int teardownGeneration) =>
        Volatile.Read(ref _teardownGeneration) == teardownGeneration;

    private void RememberMeasuredBounds(HostBounds bounds)
    {
        if (!bounds.IsDegenerate())
        {
            _lastMeasuredBounds = bounds;
        }
    }

    private HostBounds GetRetryInitialBounds() =>
        _lastMeasuredBounds.IsDegenerate() ? HostBounds.Empty : _lastMeasuredBounds;

    private void ClearConnectWatchdog(CancellationTokenSource? expected = null)
    {
        CancellationTokenSource? cts;
        if (expected is null)
        {
            cts = Interlocked.Exchange(ref _cts, null);
        }
        else
        {
            cts = ReferenceEquals(Interlocked.CompareExchange(ref _cts, null, expected), expected)
                ? expected
                : null;
        }

        try { cts?.Dispose(); }
        catch (Exception ex) { _logger.LogDebug(ex, "RDP connect watchdog dispose threw (suppressed)."); }
    }

    private void ClearCrashSentinelIfSafe()
    {
        if (!_ownsCrashSentinel) return;
        if (Status == SessionStatus.Connecting) return;
        if (Status == SessionStatus.Connected && !_hasLoggedOn) return;

        ClearOwnedCrashSentinel();
    }

    private void ClearOwnedCrashSentinel()
    {
        if (!_ownsCrashSentinel) return;
        _ownsCrashSentinel = false;
        _ = _crashSentinel.ClearAsync();
    }

    /// <summary>
    /// Best-effort SetFocus into the embedded RDP ActiveX HWND. Wrapped so a teardown
    /// race (session disposed between status flip and focus push, or any future Win32
    /// quirk) can't escape into the dispatched continuation that called us and bubble
    /// up to <see cref="OnDispatchedException"/> as a fake failure overlay.
    /// </summary>
    private void TryFocusSession()
    {
        try { _session?.Focus(); }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "RDP session focus push suppressed (likely teardown race).");
        }
    }

    /// <summary>
    /// User-initiated teardown (Disconnect / Retry / tab close): cancel any in-flight
    /// connect, dispose the session, return to a clean Disconnected state. Awaits
    /// tunnel disposal so callers like <see cref="CloseAsync"/> can rely on the await
    /// meaning "everything is released" — pass <paramref name="fastTunnelTeardown"/>
    /// only from <see cref="RetryAsync"/> where the user wants PuTTY-instant feel.
    /// </summary>
    private async Task FullTeardownAsync(bool fastTunnelTeardown = false)
    {
        _teardownRequested = true;
        Interlocked.Increment(ref _teardownGeneration);
        var cts = _cts;
        _cts = null;
        try { cts?.Cancel(); } catch { /* already disposed */ }
        // Dispose so the underlying Timer (from CancelAfter) and any Register-callback
        // closures are released — otherwise every Retry leaks a CTS + timer + closure.
        cts?.Dispose();

        DisposeSessionSilently();
        DetachExternalProcess();
        ResetTitleToBaseProfile();
        Status = SessionStatus.Disconnected;
        ErrorMessage = null;
        FailedDueToCredentials = false;
        IsExternalClientActive = false;
        ReconnectAttempt = 0;
        _hasLoggedOn = false;
        _lastLogonErrorCode = null;

        if (fastTunnelTeardown)
        {
            // Reconnect path only: VPN sidecar shutdown can take 100s of ms and the
            // user has just asked for "kill and reconnect". The _tunnel field is
            // nulled atomically inside DisposeTunnelSilentlyAsync
            // (Interlocked.Exchange) before its await, so the fresh ConnectAsync
            // running immediately afterwards won't see the old reference.
            _ = DisposeTunnelSilentlyAsync();
        }
        else
        {
            await DisposeTunnelSilentlyAsync().ConfigureAwait(true);
        }
        _teardownRequested = false;
    }

    /// <summary>
    /// Stop tracking the spawned mstsc.exe without killing it. The external session is the
    /// user's RDP connection — they may still be using it after closing the Wormhole tab,
    /// so the right behaviour is "untrack and let it live" rather than Process.Kill. Setting
    /// EnableRaisingEvents=false drops the Exited subscription so we don't fire a stale
    /// state transition into a VM that's already being torn down.
    /// </summary>
    private void DetachExternalProcess()
    {
        var ext = _externalProcess;
        _externalProcess = null;
        IsExternalClientActive = false;
        if (ext is null) return;
        try { ext.EnableRaisingEvents = false; } catch { /* may have already exited */ }
        try { ext.Dispose(); } catch (Exception ex) { _logger.LogDebug(ex, "Disposing external mstsc.exe handle threw (suppressed)."); }
    }

    /// <summary>
    /// Decide whether to route this connect through the system mstsc.exe instead of the
    /// embedded mstscax host. Two triggers:
    /// <list type="number">
    ///   <item>The per-profile opt-in flag the editor lets users set for any reason.</item>
    ///   <item>The profile looks Azure-AD-joined per
    ///         <see cref="AzureAdCredentialDetector.IsAzureAd(ConnectionProfile, CredentialProfile?)"/>
    ///         — which considers both the linked saved credential AND the node's own
    ///         <c>Username</c>/<c>RdpDomain</c> fields. The latter matters for "Prompt
    ///         every time" connections where Wormhole has no saved credential to
    ///         inspect but the user typed "AzureAD" into the node's Domain field.</item>
    /// </list>
    /// The AAD branch fires regardless of the flag because the embedded path crashes the
    /// process from native code that managed handlers can't catch — honouring an explicit
    /// "uncheck to override" would let users deterministically crash the app. Internal so
    /// the test project (which links this source) can verify the decision without spawning
    /// mstsc.exe.
    /// </summary>
    internal async Task<bool> ShouldUseExternalClientAsync(ConnectionProfile profile)
    {
        if (profile.RdpUseExternalClient) return true;

        // Cheap node-side signals first — no DB round-trip needed. Covers users on
        // "Prompt every time" who typed AzureAD into the node's Domain/Username.
        if (AzureAdCredentialDetector.HasAzureAdDomain(profile.RdpDomain)) return true;
        if (AzureAdCredentialDetector.HasAzureAdPrefix(profile.Username)) return true;

        if (profile.CredentialId is not { } credId) return false;
        CredentialProfile? credential;
        try
        {
            credential = await _credentialRepository.GetByIdAsync(credId).ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            // A repository hiccup must not silently route to embedded for a possibly-AAD
            // credential — that's the crash-prone path. Fall back to mstsc.exe for normal
            // RDP, or to the tunnel/external-client guard for tunneled profiles.
            _logger.LogWarning(ex, "Credential lookup for AAD detection failed; routing RDP away from embedded mstscax.");
            return true;
        }
        return AzureAdCredentialDetector.IsAzureAd(credential);
    }

    /// <summary>
    /// Spawn mstsc.exe for the given profile. Synchronous (Process.Start returns immediately
    /// after CreateProcess). Sets the VM into Connected with a "(external)" title suffix and
    /// hooks Exited so the tab transitions to Disconnected when the user closes the mstsc
    /// window. Failure to launch (mstsc.exe not on PATH, etc.) flips to Failed with a clear
    /// message — no crash path.
    /// </summary>
    private void LaunchExternalProcess(ConnectionProfile profile)
    {
        ClearConnectWatchdog();
        ClearOwnedCrashSentinel();

        Status = SessionStatus.Connecting;
        ErrorMessage = null;
        FailedDueToCredentials = false;
        IsExternalClientActive = false;
        ReconnectAttempt = 0;

        Process? proc;
        try
        {
            // /v:host:port is the canonical way to point mstsc.exe at a target. We do NOT
            // try to pass a password — mstsc.exe's own UI handles credential entry (and for
            // AAD targets, the WAM broker flow) far more correctly than any flag we could
            // pass on the command line. The username/domain are intentionally omitted too;
            // mstsc.exe will use Windows credential roaming or prompt as appropriate.
            var psi = new ProcessStartInfo("mstsc.exe")
            {
                UseShellExecute = false,
                CreateNoWindow = false,
            };
            psi.ArgumentList.Add("/v:" + FormatMstscTarget(profile.Host, profile.Port));
            proc = ExternalProcessLauncher(psi);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to launch mstsc.exe for {Host}.", profile.Host);
            ReportFailure("Failed to launch mstsc.exe: " + ex.Message, dueToCredentials: false);
            return;
        }

        if (proc is null)
        {
            ReportFailure(
                "Could not launch mstsc.exe. Ensure the system Remote Desktop client is installed.",
                dueToCredentials: false);
            return;
        }

        _externalProcess = proc;
        var pid = 0;
        try { pid = proc.Id; }
        catch (Exception ex) { _logger.LogDebug(ex, "Could not read mstsc.exe process id after launch."); }
        try { proc.EnableRaisingEvents = true; }
        catch (Exception ex) { _logger.LogDebug(ex, "EnableRaisingEvents on external mstsc.exe threw (suppressed)."); }

        var baseTitle = GetBaseTitle(profile);
        proc.Exited += (_, _) =>
        {
            MarshalToUi(() => HandleExternalProcessExited(proc, baseTitle));
        };

        // If mstsc.exe rejects the launch and exits before EnableRaisingEvents/subscription
        // can observe it, do not leave the Wormhole tab in a phantom external-active state.
        if (HasExternalProcessExited(proc))
        {
            HandleExternalProcessExited(proc, baseTitle);
            return;
        }
        if (!ReferenceEquals(_externalProcess, proc)) return;

        IsExternalClientActive = true;
        Status = SessionStatus.Connected;
        Title = baseTitle + " (external)";
        if (!ReferenceEquals(_externalProcess, proc) || HasExternalProcessExited(proc))
        {
            IsExternalClientActive = false;
            Status = SessionStatus.Disconnected;
            ErrorMessage = null;
            FailedDueToCredentials = false;
            Title = baseTitle;
            if (ReferenceEquals(_externalProcess, proc))
            {
                HandleExternalProcessExited(proc, baseTitle);
            }
            return;
        }
        _logger.LogInformation(
            "Launched mstsc.exe (pid {Pid}) for {Host}:{Port} — external client mode.",
            pid, profile.Host, profile.Port);
    }

    private bool HasExternalProcessExited(Process proc)
    {
        try
        {
            if (proc.WaitForExit(milliseconds: 0)) return true;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not poll mstsc.exe process exit state.");
        }

        try
        {
            proc.Refresh();
            if (proc.HasExited) return true;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not read mstsc.exe HasExited state.");
        }

        try
        {
            _ = proc.ExitTime;
            return true;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not read mstsc.exe ExitTime state.");
            return false;
        }
    }

    private static string GetBaseTitle(ConnectionProfile profile) =>
        string.IsNullOrEmpty(profile.Name) ? profile.Host : profile.Name;

    private static string FormatMstscTarget(string host, int port)
    {
        if (IPAddress.TryParse(host, out var ip) &&
            ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            return $"[{host}]:{port}";
        }

        return $"{host}:{port}";
    }

    private bool HasLiveExternalProcess(ConnectionProfile profile)
    {
        if (_externalProcess is not { } externalProcess) return false;
        if (!HasExternalProcessExited(externalProcess)) return true;

        HandleExternalProcessExited(externalProcess, GetBaseTitle(profile));
        return false;
    }

    private void HandleExternalProcessExited(Process proc, string baseTitle)
    {
        // If FullTeardown / a Retry has already swapped or detached the tracked process,
        // ignore this late Exited — it is about a process we no longer own.
        if (!ReferenceEquals(_externalProcess, proc)) return;
        _externalProcess = null;
        IsExternalClientActive = false;
        Status = SessionStatus.Disconnected;
        ErrorMessage = null;
        FailedDueToCredentials = false;
        Title = baseTitle;
        try { proc.Dispose(); } catch { /* nothing to do */ }
    }

    private void ResetTitleToBaseProfile()
    {
        if (Profile is { } profile)
        {
            Title = GetBaseTitle(profile);
        }
    }

    /// <summary>
    /// Event-driven teardown: dispose the dead session, then either flip to Disconnected
    /// (clean shutdown) or surface the failure overlay. Called from OnSessionDisconnected /
    /// OnSessionFatalError so the shape stays consistent.
    /// </summary>
    private async Task DisposeAndTransitionAsync(string? failureMessage, bool dueToCredentials)
    {
        ClearConnectWatchdog();
        DisposeSessionSilently();
        if (failureMessage is null)
        {
            IsExternalClientActive = false;
            Status = SessionStatus.Disconnected;
            ErrorMessage = null;
            FailedDueToCredentials = false;
        }
        else
        {
            ReportFailure(failureMessage, dueToCredentials);
        }
        await DisposeTunnelSilentlyAsync().ConfigureAwait(true);
    }

    private async Task DisposeTunnelSilentlyAsync()
    {
        var tunnel = Interlocked.Exchange(ref _tunnel, null);
        if (tunnel is null) return;

        await DisposeTunnelInstanceSilentlyAsync(tunnel).ConfigureAwait(false);
    }

    private async Task DisposeTunnelInstanceSilentlyAsync(ITunnelInstance tunnel)
    {
        try { await tunnel.DisposeAsync().ConfigureAwait(false); }
        catch (Exception ex) { _logger.LogWarning(ex, "Tunnel dispose threw during RDP teardown."); }
    }

    private void DisposeSessionSilently()
    {
        var session = _session;
        _session = null;
        _hasLoggedOn = false;
        _lastLogonErrorCode = null;
        if (session is null) return;

        session.Connected -= OnSessionConnected;
        session.LoginComplete -= OnSessionLoginComplete;
        session.Disconnected -= OnSessionDisconnected;
        session.FatalError -= OnSessionFatalError;
        session.LogonError -= OnSessionLogonError;
        session.AutoReconnecting -= OnSessionAutoReconnecting;
        session.AutoReconnected -= OnSessionAutoReconnected;

        // No explicit session.Disconnect() — RdpHostForm.Dispose itself no longer
        // calls the OCX's polite MCS termination (see comment there), so Dispose
        // tears the OCX down via AxHost without blocking the UI/STA thread on a
        // server ack. Events were unsubscribed above, so any late OnDisconnected
        // from the OCX during teardown is safely dropped.
        try { session.Dispose(); }
        catch (Exception ex) { _logger.LogWarning(ex, "Dispose threw during teardown."); }
    }

    // Test-only hook mirroring the SSH pattern — lets unit tests bypass the real service.
    internal void AttachConnectedSessionForTesting(IRdpSession session, bool hasLoggedOn = true)
    {
        AttachSession(session, hasLoggedOn);
        EnsureDispatcher();
        Status = SessionStatus.Connected;
    }

    private void AttachSession(IRdpSession session, bool hasLoggedOn)
    {
        _session = session;
        _hasLoggedOn = hasLoggedOn || session.IsLoggedOn;
        _lastLogonErrorCode = null;
        session.Connected += OnSessionConnected;
        session.LoginComplete += OnSessionLoginComplete;
        session.Disconnected += OnSessionDisconnected;
        session.FatalError += OnSessionFatalError;
        session.LogonError += OnSessionLogonError;
        session.AutoReconnecting += OnSessionAutoReconnecting;
        session.AutoReconnected += OnSessionAutoReconnected;
    }

    private static (string? FailureMessage, bool DueToCredentials) BuildDisconnectFailure(
        RdpDisconnectInfo info,
        bool loggedOn,
        bool teardownRequested,
        int? lastLogonErrorCode)
    {
        if (teardownRequested) return (null, false);
        if (loggedOn && info.IsClean) return (null, false);

        var dueToCredentials =
            (lastLogonErrorCode is { } logonCode && RdpLogonErrors.IsCredentialRelated(logonCode)) ||
            RdpDisconnectReasons.IsCredentialRelated(info.Code) ||
            RdpDisconnectReasons.IsCredentialRelated(info.ExtendedCode);
        var message = RdpLogonErrors.BuildDisconnectMessage(lastLogonErrorCode, info);
        return (message, dueToCredentials);
    }

    /// <summary>
    /// Credential-related OnDisconnected codes from the IMsTscAxEvents.OnDisconnected
    /// reference. These can arrive without a preceding OnLogonError on some NLA/CredSSP
    /// paths, so they must still force the next Retry through the credential prompt.
    /// </summary>
    private static class RdpDisconnectReasons
    {
        public static bool IsCredentialRelated(int code) =>
            code is
                2055 or // SSL_ERR_LOGON_FAILURE
                2567 or // SSL_ERR_NO_SUCH_USER
                2823 or // SSL_ERR_ACCOUNT_DISABLED
                3079 or // SSL_ERR_ACCOUNT_RESTRICTION
                3335 or // SSL_ERR_ACCOUNT_LOCKED_OUT
                3591 or // SSL_ERR_ACCOUNT_EXPIRED
                3847 or // SSL_ERR_PASSWORD_EXPIRED
                4615 or // SSL_ERR_PASSWORD_MUST_CHANGE
                5639 or // SSL_ERR_DELEGATION_POLICY
                5895 or // SSL_ERR_POLICY_NTLM_ONLY
                6151 or // SSL_ERR_NO_AUTHENTICATING_AUTHORITY
                8455;   // SSL_ERR_FRESH_CRED_REQUIRED_BY_SERVER
    }

    /// <summary>
    /// Mappings for the OnLogonError codes the ActiveX may raise, taken from the
    /// IMsTscAxEvents.OnLogonError reference at
    /// learn.microsoft.com/windows/win32/termserv/imstscaxevents-onlogonerror. The published
    /// table includes both errors and non-terminal logon notifications; OnLogonError alone
    /// never decides terminal state because the OCX may still proceed to LoginComplete.
    /// </summary>
    private static class RdpLogonErrors
    {
        private static readonly Dictionary<int, string> Descriptions = new Dictionary<int, string>
        {
            [-1073741715] = "The attempted logon is not valid. Check the username and password.",
            [-1073741714] = "The account was blocked by logon restrictions.",
            [-1073741276] = "The password is expired and must be changed.",
            [-7] = "Winlogon displayed the Disconnect Refused dialog.",
            [-6] = "Winlogon displayed the No Permissions dialog.",
            [-5] = "Winlogon displayed the Session Contention dialog.",
            [-4] = "Winlogon displayed the Reconnect dialog.",
            [-3] = "Winlogon ended silently.",
            [-2] = "Winlogon is continuing with the logon process.",
            [-1] = "Access denied.",
            [0] = "The logon credentials are not valid.",
            [1] = "The password is expired and must be changed.",
            [2] = "Another logon or post-logon error occurred.",
            [3] = "The Remote Desktop client displayed a logon warning.",
        };

        public static string Describe(int code) =>
            Descriptions.TryGetValue(code, out var msg) ? msg : $"Logon failed (code {code}).";

        public static bool IsCredentialRelated(int code) =>
            code is -1073741715 or -1073741714 or -1073741276 or -6 or -1 or 0 or 1;

        public static string BuildDisconnectMessage(int? logonCode, RdpDisconnectInfo info)
        {
            if (logonCode is null or -2)
            {
                return string.IsNullOrWhiteSpace(info.Description)
                    ? $"RDP disconnected before login completed (reason {info.Code})."
                    : info.Description;
            }

            var logonDescription = Describe(logonCode.Value);
            if (string.IsNullOrWhiteSpace(info.Description))
            {
                return logonDescription;
            }
            if (string.Equals(logonDescription, info.Description, StringComparison.OrdinalIgnoreCase))
            {
                return info.Description;
            }

            return $"{logonDescription} {info.Description}";
        }
    }
}
