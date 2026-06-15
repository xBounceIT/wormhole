using Microsoft.Extensions.Logging;
using Microsoft.UI.Xaml;
using Wormhole.Data.Repositories;
using Wormhole.Models;
using Wormhole.Services.Sftp;
using Wormhole.Services.Ssh;
using Wormhole.Services.Tunneling;
using Wormhole.ViewModels.Sessions;
using Wormhole.ViewModels.Sessions.Transfer;
using Wormhole.Views.Dialogs;

namespace Wormhole.Services;

public sealed class FileTransferDialogService : IFileTransferDialogService
{
    private readonly ISftpService _sftp;
    private readonly ISshCredentialResolver _credentials;
    private readonly TunnelManager _tunnels;
    private readonly IDialogService _dialogs;
    private readonly IConnectionRepository _connectionRepo;
    private readonly ILoggerFactory _loggerFactory;
    private readonly ILogger<FileTransferDialogService> _logger;

    public FileTransferDialogService(
        ISftpService sftp,
        ISshCredentialResolver credentials,
        TunnelManager tunnels,
        IDialogService dialogs,
        IConnectionRepository connectionRepo,
        ILoggerFactory loggerFactory)
    {
        _sftp = sftp;
        _credentials = credentials;
        _tunnels = tunnels;
        _dialogs = dialogs;
        _connectionRepo = connectionRepo;
        _loggerFactory = loggerFactory;
        _logger = loggerFactory.CreateLogger<FileTransferDialogService>();
    }

    public async Task ShowAsync(SessionTabViewModel sourceTab)
    {
        if (sourceTab.Profile is null)
        {
            await _dialogs.ShowMessageAsync("File transfer", "This session has no connection profile.").ConfigureAwait(true);
            return;
        }
        var profile = sourceTab.Profile;

        ISftpSession? session = null;
        ITunnelInstance? tunnel = null;

        // Fast path — SshSessionViewModel keeps an SFTP session warm in the background
        // once the shell reaches Connected (see SshSessionViewModel.StartPrewarm). When
        // available we skip the credential resolve + tunnel + SFTP connect block entirely
        // and the dialog appears instantly. Falls through on RDP/SFTP source tabs, on
        // prewarm-in-flight, and on prewarm-failed.
        if (sourceTab is SshSessionViewModel sshTab)
        {
            var prewarmed = sshTab.TryConsumePrewarmedSftp();
            if (prewarmed is { } p)
            {
                session = p.Session;
                tunnel = p.Tunnel;
                try
                {
                    profile = await PinHostFingerprintIfNeededAsync(sourceTab, profile, session).ConfigureAwait(true);
                }
                catch (Exception ex)
                {
                    // Defensive: PinHostFingerprintIfNeededAsync swallows its own DB-write
                    // failures, but if anything else throws here (e.g. UpdateProfile fan-out)
                    // we still own the prewarmed pair and must release it before propagating.
                    _logger.LogWarning(ex, "Unexpected error pinning host fingerprint from prewarmed SFTP for {Host}.", profile.Host);
                    try { await session.DisposeAsync().ConfigureAwait(true); } catch { /* best effort */ }
                    if (tunnel is not null) try { await tunnel.DisposeAsync().ConfigureAwait(true); } catch { /* best effort */ }
                    await _dialogs.ShowMessageAsync("File transfer", "Could not open SFTP session: " + ex.Message).ConfigureAwait(true);
                    return;
                }
            }
        }

        if (session is null)
        {
            // On-demand path — used for the race window between Status→Connected and
            // prewarm completion, and any pre-warm failure. Prefer the credentials the
            // live shell already authenticated with (SshSessionViewModel caches them on
            // successful ConnectAsync); only fall back to ResolveAsync if none cached.
            // This keeps the documented contract that file-transfer never re-prompts for
            // a key passphrase the user already entered at terminal connect time.
            try
            {
                SshCredentials? creds = sourceTab is SshSessionViewModel sshTabForCreds
                    ? sshTabForCreds.GetCapturedCredentialsForSftp()
                    : null;
                if (creds is null || !creds.HasAny)
                {
                    creds = await _credentials.ResolveAsync(profile, CancellationToken.None).ConfigureAwait(true);
                }
                if (!creds.HasAny)
                {
                    await _dialogs.ShowMessageAsync("File transfer", "No credentials provided.").ConfigureAwait(true);
                    return;
                }

                // Reuse the live shell's tunnel (a non-owning borrow) rather than establishing a second
                // one: for an OTP-interactive VPN a second establish would re-prompt for / burn another
                // one-time code, and it is a redundant VPN connection for any tunnel. The SSH session owns
                // disposal of the real instance. If there is no live shell tunnel to borrow — a non-SSH
                // source tab, or an SSH session that has since disconnected and torn its tunnel down — fall
                // back to establishing one. That keeps a VPN-required transfer ON the VPN (rather than
                // silently connecting direct) at the cost of re-establishing it; and for a no-VPN profile
                // EstablishAsync returns null → direct SFTP, unchanged.
                var sshSource = sourceTab as SshSessionViewModel;
                var borrowed = sshSource?.BorrowTunnelForSftp();
                // When there's no live tunnel to borrow, establish against the terminal's routed
                // profile rather than the saved one: if the user chose "connect directly" for the
                // shell, RoutedProfileForSubsession has TunnelEnabled=false → EstablishAsync
                // returns null → direct SFTP, instead of silently bringing up the declined VPN.
                var establishProfile = sshSource?.RoutedProfileForSubsession ?? profile;
                tunnel = borrowed ?? await _tunnels.EstablishAsync(establishProfile, CancellationToken.None).ConfigureAwait(true);
                session = await _sftp.ConnectAsync(profile, creds, tunnel, CancellationToken.None).ConfigureAwait(true);

                profile = await PinHostFingerprintIfNeededAsync(sourceTab, profile, session).ConfigureAwait(true);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to open SFTP for {Host}.", profile.Host);
                if (session is not null) try { await session.DisposeAsync().ConfigureAwait(true); } catch { /* best effort */ }
                if (tunnel is not null) try { await tunnel.DisposeAsync().ConfigureAwait(true); } catch { /* best effort */ }
                await _dialogs.ShowMessageAsync("File transfer", "Could not open SFTP session: " + ex.Message).ConfigureAwait(true);
                return;
            }
        }

        // Everything from here through the modal lifetime must be enclosed in a single
        // try block: orchestrator is the LAST owner of `session`, and if any ctor or
        // modal setup throws (e.g. XamlRoot null-coalesce at line ~108)
        // before we enter the try/finally, the session + tunnel would leak.
        FileTransferOrchestrator? orchestrator = null;
        FileTransferViewModel? vm = null;
        try
        {
            orchestrator = new FileTransferOrchestrator(session, _loggerFactory.CreateLogger<FileTransferOrchestrator>());
            // Initial local path: user's profile directory is a sensible default since the
            // user is unlikely to want to start in C:\Windows\System32 or similar.
            var initialLocal = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            if (string.IsNullOrEmpty(initialLocal)) initialLocal = Path.GetPathRoot(Environment.SystemDirectory) ?? "C:\\";
            var initialRemote = session.WorkingDirectory;

            vm = new FileTransferViewModel(
                orchestrator,
                connectionTitle: profile.Name,
                remoteHost: profile.Host,
                initialLocalPath: initialLocal,
                initialRemotePath: initialRemote);

            var view = new FileTransferDialog();
            var mainWindow = App.Current.MainWindow
                ?? throw new InvalidOperationException("No active window to host dialog.");
            var xamlRoot = mainWindow.Content?.XamlRoot
                ?? throw new InvalidOperationException("No active window to host dialog.");
            var closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            void OnCloseRequested(object? sender, EventArgs args) => closed.TrySetResult();
            view.CloseRequested += OnCloseRequested;

            // Target ~85% of the host window, with sensible bounds. If the user's window
            // is narrower than the minimum, the XamlRoot clips naturally.
            var rootSize = xamlRoot.Size;
            var targetWidth = Math.Clamp(rootSize.Width * 0.85, 900.0, 1400.0);
            var targetHeight = Math.Clamp(rootSize.Height * 0.85, 560.0, 900.0);

            // Initialize before ShowAsync so panes have entries by the time the dialog
            // renders. Observe the task so a synchronous throw or failed pane load
            // surfaces in logs rather than disappearing as an UnobservedTaskException.
            _ = SafeInitializeAsync(view, vm);
            // Suppress any connected RDP overlay (top-level window above the WinUI content) so it
            // can't occlude this dialog while an RDP tab is the active, visible one.
            using (Wormhole.Helpers.RdpOverlayCoordinator.Suppress())
            {
                try
                {
                    mainWindow.ShowModalOverlay(view, targetWidth, targetHeight);
                    await closed.Task.ConfigureAwait(true);
                }
                finally
                {
                    view.CloseRequested -= OnCloseRequested;
                    mainWindow.HideModalOverlay();
                }
            }
        }
        finally
        {
            // Dispose the VM (which disposes the orchestrator which disposes the SFTP
            // session) on EVERY exit path: dialog closed, ShowAsync threw, or any of
            // the constructions above threw. If vm wasn't built, still dispose the
            // orchestrator we did construct (if any); otherwise dispose the bare session.
            // Wrap each branch so a throw from DisposeAsync (e.g., a faulting logger sink
            // inside FileTransferOrchestrator's catch paths) does NOT abort the finally
            // before the tunnel-dispose block below runs — that would leak the prewarm
            // tunnel since each prewarm/on-demand connect owns its own ITunnelInstance.
            if (vm is not null)
            {
                try { await vm.DisposeAsync().ConfigureAwait(true); }
                catch (Exception ex) { _logger.LogWarning(ex, "Error disposing file-transfer VM in cleanup path."); }
            }
            else if (orchestrator is not null)
            {
                try { await orchestrator.DisposeAsync().ConfigureAwait(true); }
                catch (Exception ex) { _logger.LogWarning(ex, "Error disposing file-transfer orchestrator in cleanup path."); }
            }
            else
            {
                try { await session.DisposeAsync().ConfigureAwait(true); } catch (Exception ex) { _logger.LogWarning(ex, "Error disposing SFTP session in cleanup path."); }
            }
            if (tunnel is not null)
            {
                // The orchestrator's session disposal does not cover the tunnel because
                // tunnels are owned per-connect by the caller. The SSH terminal tab still
                // holds its own tunnel reference; dispose ours independently.
                try { await tunnel.DisposeAsync().ConfigureAwait(true); }
                catch (Exception ex) { _logger.LogWarning(ex, "Error tearing down file-transfer tunnel."); }
            }
        }
    }

    /// <summary>
    /// TOFU persistence used by both the prewarmed and on-demand paths: if the profile
    /// has no pinned host fingerprint but the session captured one, store it on the
    /// in-memory profile and best-effort write it to the connection repository so the
    /// next reconnect detects an MITM key swap instead of TOFU-accepting whatever the
    /// server presents. Returns the (possibly updated) profile so the caller can keep
    /// using the same local variable.
    /// <para>
    /// Updates the in-memory profile FIRST so a persist failure does not leave the same
    /// tab's next reconnect re-TOFUing against an empty pin. The DB write is best-effort.
    /// </para>
    /// </summary>
    private async Task<ConnectionProfile> PinHostFingerprintIfNeededAsync(SessionTabViewModel sourceTab, ConnectionProfile profile, ISftpSession session)
    {
        if (!string.IsNullOrEmpty(profile.SshKnownHostFingerprint)) return profile;
        if (string.IsNullOrEmpty(session.HostFingerprint)) return profile;

        var pinned = profile with { SshKnownHostFingerprint = session.HostFingerprint };
        sourceTab.UpdateProfile(pinned);
        try
        {
            await _connectionRepo.UpdateHostFingerprintAsync(pinned.NodeId, session.HostFingerprint!, CancellationToken.None).ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not persist SFTP-side host fingerprint for {Host}.", pinned.Host);
        }
        return pinned;
    }

    /// <summary>
    /// Initialize the dialog VM with the captured logger so any pane-load failure or
    /// binding-wire-up throw is recorded instead of vanishing into the task scheduler.
    /// </summary>
    private async Task SafeInitializeAsync(FileTransferDialog view, FileTransferViewModel vm)
    {
        try { await view.InitializeAsync(vm).ConfigureAwait(true); }
        catch (OperationCanceledException)
        {
            // Expected: user closed the dialog while initial pane loads were still in
            // flight. Cancellation cascades through the orchestrator's _shutdown.Token
            // into the pane VMs. Not an error.
        }
        catch (Exception ex) { _logger.LogWarning(ex, "FileTransferDialog InitializeAsync failed."); }
    }

}
