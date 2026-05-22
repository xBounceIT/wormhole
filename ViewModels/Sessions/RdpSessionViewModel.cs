using System;
using System.Collections.Generic;
using System.Diagnostics;
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

namespace Wormhole.ViewModels.Sessions;

public sealed partial class RdpSessionViewModel : SessionTabViewModel
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(30);
    private static readonly string TimeoutMessage =
        $"RDP server didn't respond within {ConnectTimeout.TotalSeconds:0} seconds.";

    private readonly IRdpSessionService _rdpService;
    private readonly ICredentialService _credentialService;
    private readonly ICredentialRepository _credentialRepository;
    private readonly IDialogService _dialog;
    private readonly IRdpCrashSentinelService _crashSentinel;
    private readonly ILogger<RdpSessionViewModel> _logger;

    private IRdpSession? _session;
    private CancellationTokenSource? _cts;
    private int _connectInFlight;
    private IntPtr _ownerHwnd;
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
        IDialogService dialog,
        IRdpCrashSentinelService crashSentinel,
        ILoggerFactory loggerFactory)
    {
        _rdpService = rdpService;
        _credentialService = credentialService;
        _credentialRepository = credentialRepository;
        _dialog = dialog;
        _crashSentinel = crashSentinel;
        _logger = loggerFactory.CreateLogger<RdpSessionViewModel>();

        // Status lives on the base class — re-broadcast its dependents from the derived VM
        // since [NotifyPropertyChangedFor] only sees properties on its own partial class.
        // We also use the Status change to clear the crash sentinel: once the embedded
        // session reaches any non-Connecting state, the WAM delay-load danger window has
        // closed (either we made it past the auth handshake, or we got a managed failure
        // we can recover from cleanly). Fire-and-forget is fine — the sentinel writes are
        // small, idempotent, and a missed clear just causes a benign auto-flag on the next
        // launch (the user can uncheck if they disagree).
        PropertyChanged += (_, args) =>
        {
            if (args.PropertyName == nameof(Status))
            {
                OnPropertyChanged(nameof(IsConnecting));
                OnPropertyChanged(nameof(IsConnected));
                OnPropertyChanged(nameof(IsFailed));
                RetryCommand.NotifyCanExecuteChanged();

                if (Status != SessionStatus.Connecting && _ownsCrashSentinel)
                {
                    _ownsCrashSentinel = false;
                    _ = _crashSentinel.ClearAsync();
                }
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

        // External-client re-attach: mstsc.exe runs in its own window outside the WinUI
        // surface, so there's nothing to re-bind here. We just need to NOT spawn a second
        // mstsc.exe — the surface host is recreated on every Sessions↔Settings nav, and
        // without this guard the VM would launch a duplicate every time the tab is shown.
        if (_externalProcess is { HasExited: false })
        {
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

    /// <summary>
    /// User-initiated switch to the system mstsc.exe. Available regardless of the profile's
    /// RdpUseExternalClient setting so the failure overlay can offer it as a fallback after
    /// an embedded connection error. Tears down any in-flight embedded session first; the
    /// spawned mstsc.exe lives independently and survives a Wormhole Disconnect / tab close
    /// (we just stop tracking it — see FullTeardown).
    /// </summary>
    [RelayCommand]
    public void UseExternalClient()
    {
        var profile = Profile;
        if (profile is null) return;
        FullTeardown();
        LaunchExternalProcess(profile);
    }

    [RelayCommand(AllowConcurrentExecutions = false, CanExecute = nameof(CanRetry))]
    public async Task RetryAsync()
    {
        if (Profile is null || _ownerHwnd == IntPtr.Zero) return;

        var forcePrompt = FailedDueToCredentials;
        FullTeardown();

        // Geometry will be re-supplied by the surface host's first SetBounds after the new
        // session attaches; seed with a 1x1 so the form is valid until that arrives.
        await ConnectAsync(_ownerHwnd, HostBounds.Seed, forcePromptForPassword: forcePrompt).ConfigureAwait(true);
    }

    // Mirrors SshSessionViewModel: while Connecting, an in-flight ConnectAsync still holds
    // _connectInFlight; a second one from RetryAsync would silently no-op. Disabling the
    // command keeps the tab context menu / failure overlay in sync with the actual state.
    private bool CanRetry() => Status != SessionStatus.Connecting;

    public override ValueTask CloseAsync()
    {
        FullTeardown();
        return ValueTask.CompletedTask;
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
        try
        {
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
                LaunchExternalProcess(profile);
                return;
            }

            // Write the crash sentinel BEFORE flipping Status — the PropertyChanged hook
            // clears the sentinel on any non-Connecting transition when _ownsCrashSentinel
            // is true. Both the file write and the ownership flag must be in place before
            // the OCX touches mstscax (where the native WAM crash originates) so a process
            // death in that window leaves the sentinel behind for the next launch to read.
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
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to write RDP crash sentinel — proceeding without recovery breadcrumb for this attempt.");
                // _ownsCrashSentinel stays false. No file on disk means there's nothing for
                // the hook to clear; subsequent attempts behave normally.
            }

            Status = SessionStatus.Connecting;
            ErrorMessage = null;
            FailedDueToCredentials = false;
            ReconnectAttempt = 0;

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
                var password = await ResolvePasswordAsync(profile, forcePromptForPassword, token).ConfigureAwait(true);
                if (token.IsCancellationRequested)
                {
                    Status = SessionStatus.Disconnected;
                    return;
                }

                // ResolvePasswordAsync returns null only when the user cancelled the prompt —
                // silent return to Disconnected, not Failed (no error message to show). Covers
                // both "no saved credential" and "credential Id pointed at a deleted Credential
                // Manager entry, fell through to a prompt, user cancelled". Either way, no.
                if (password is null)
                {
                    Status = SessionStatus.Disconnected;
                    return;
                }

                // ConnectAsync returns immediately after kicking off the asynchronous OCX
                // handshake, so without a real watchdog there's no way to surface a "server
                // never answered" timeout. The Register callback drives both legs: it flips
                // the captured timedOut flag so the inline OCE catch can distinguish a
                // watchdog-cancel from a user-cancel (FullTeardown), and it posts to the UI
                // thread to fail the VM if the await already returned and the OCX is sitting
                // mid-handshake. The registration's lifetime is the CTS's lifetime — the
                // previousCts?.Dispose() above and FullTeardown's Dispose release it.
                cts.CancelAfter(ConnectTimeout);
                cts.Token.Register(() =>
                {
                    // User-initiated cancels (FullTeardown) null _cts BEFORE calling Cancel,
                    // so this guard distinguishes timer-fire from user-fire.
                    if (!ReferenceEquals(_cts, cts)) return;
                    timedOut = true;
                    MarshalToUi(() =>
                    {
                        if (!ReferenceEquals(_cts, cts)) return;
                        if (Status != SessionStatus.Connecting) return;
                        DisposeAndTransition(TimeoutMessage, dueToCredentials: false);
                    });
                });

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
                        s.AutoReconnected += OnSessionAutoReconnected;
                    },
                    token).ConfigureAwait(true);
                _session = session;

                _session.SetBounds(initialBounds.IsDegenerate(minDim: 1) ? HostBounds.Seed : initialBounds);
                _session.Show();
            }
            catch (OperationCanceledException) when (timedOut)
            {
                DisposeSessionSilently();
                ReportFailure(TimeoutMessage, dueToCredentials: false);
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
        }
        finally
        {
            // Single point of release for _connectInFlight, regardless of whether we took the
            // external-client early-return, the embedded path, or threw out of either.
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

    private void OnSessionAutoReconnected(object? sender, EventArgs e)
    {
        // Without this, OnAutoReconnecting drove Status to Connecting and no event would
        // ever drive it back — the user would see the reconnect banner indefinitely after
        // a transient drop recovered.
        MarshalToUi(() =>
        {
            ReconnectAttempt = 0;
            Status = SessionStatus.Connected;
            ErrorMessage = null;
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
        // Dispose so the underlying Timer (from CancelAfter) and any Register-callback
        // closures are released — otherwise every Retry leaks a CTS + timer + closure.
        cts?.Dispose();

        DisposeSessionSilently();
        DetachExternalProcess();
        Status = SessionStatus.Disconnected;
        ErrorMessage = null;
        FailedDueToCredentials = false;
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
            // A repository hiccup must not silently route to embedded for an AAD credential —
            // that's a crash. Log and assume non-AAD; the user can still set the flag manually
            // if they hit issues.
            _logger.LogWarning(ex, "Credential lookup for AAD detection failed; assuming non-AAD.");
            return false;
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
        Status = SessionStatus.Connecting;
        ErrorMessage = null;
        FailedDueToCredentials = false;
        ReconnectAttempt = 0;

        Process? proc;
        try
        {
            // /v:host:port is the canonical way to point mstsc.exe at a target. We do NOT
            // try to pass a password — mstsc.exe's own UI handles credential entry (and for
            // AAD targets, the WAM broker flow) far more correctly than any flag we could
            // pass on the command line. The username/domain are intentionally omitted too;
            // mstsc.exe will use Windows credential roaming or prompt as appropriate.
            var psi = new ProcessStartInfo("mstsc.exe", $"/v:\"{profile.Host}:{profile.Port}\"")
            {
                UseShellExecute = false,
                CreateNoWindow = false,
            };
            proc = Process.Start(psi);
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
        try { proc.EnableRaisingEvents = true; }
        catch (Exception ex) { _logger.LogDebug(ex, "EnableRaisingEvents on external mstsc.exe threw (suppressed)."); }

        var baseTitle = string.IsNullOrEmpty(profile.Name) ? profile.Host : profile.Name;
        proc.Exited += (_, _) =>
        {
            MarshalToUi(() =>
            {
                // If FullTeardown / a Retry has already swapped or detached the tracked
                // process, ignore this late Exited — it's about a process we no longer own.
                if (!ReferenceEquals(_externalProcess, proc)) return;
                _externalProcess = null;
                Status = SessionStatus.Disconnected;
                Title = baseTitle;
                try { proc.Dispose(); } catch { /* nothing to do */ }
            });
        };

        Status = SessionStatus.Connected;
        Title = baseTitle + " (external)";
        _logger.LogInformation(
            "Launched mstsc.exe (pid {Pid}) for {Host}:{Port} — external client mode.",
            proc.Id, profile.Host, profile.Port);
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
        session.AutoReconnected -= OnSessionAutoReconnected;

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
        _session.AutoReconnected += OnSessionAutoReconnected;
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
