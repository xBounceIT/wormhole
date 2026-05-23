using Microsoft.Extensions.Logging;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Wormhole.Data.Repositories;
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

        // Re-resolve credentials independently of the SSH terminal's session. For
        // password creds stored in Credential Manager this is silent; for keys without
        // a stored passphrase the user is prompted once. The session VM does not cache
        // credentials so we cannot bypass this step yet — see plan notes for a v2
        // caching improvement.
        ISftpSession? session = null;
        ITunnelInstance? tunnel = null;
        try
        {
            var creds = await _credentials.ResolveAsync(profile, CancellationToken.None).ConfigureAwait(true);
            if (!creds.HasAny)
            {
                await _dialogs.ShowMessageAsync("File transfer", "No credentials provided.").ConfigureAwait(true);
                return;
            }

            tunnel = await _tunnels.EstablishAsync(profile, CancellationToken.None).ConfigureAwait(true);
            session = await _sftp.ConnectAsync(profile, creds, tunnel, CancellationToken.None).ConfigureAwait(true);

            // TOFU persistence: mirror SshSessionViewModel.ConnectAsync's behavior so a
            // user who first reaches the SFTP path (rather than the SSH terminal) still
            // gets the captured fingerprint pinned. SshHostKeyValidator.Decide already
            // accepted the key (TofuAccept) inside SftpService; we now record it so the
            // next open can detect a MITM swap. Empty/null both treated as unpinned.
            //
            // Update in-memory FIRST so a persist failure does NOT leave the same tab's
            // next reconnect re-TOFUing against an empty pin. The DB write is best-effort;
            // the in-memory pin is what protects this tab's subsequent SFTP/SSH opens
            // within the current session.
            if (string.IsNullOrEmpty(profile.SshKnownHostFingerprint) && !string.IsNullOrEmpty(session.HostFingerprint))
            {
                var pinned = profile with { SshKnownHostFingerprint = session.HostFingerprint };
                sourceTab.UpdateProfile(pinned);
                profile = pinned;
                try
                {
                    await _connectionRepo.UpdateHostFingerprintAsync(profile.NodeId, session.HostFingerprint!, CancellationToken.None).ConfigureAwait(true);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Could not persist SFTP-side host fingerprint for {Host}.", profile.Host);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to open SFTP for {Host}.", profile.Host);
            if (session is not null) try { await session.DisposeAsync().ConfigureAwait(true); } catch { /* best effort */ }
            if (tunnel is not null) try { await tunnel.DisposeAsync().ConfigureAwait(true); } catch { /* best effort */ }
            await _dialogs.ShowMessageAsync("File transfer", "Could not open SFTP session: " + ex.Message).ConfigureAwait(true);
            return;
        }

        // Everything from here through dialog.ShowAsync must be enclosed in a single
        // try block: orchestrator is the LAST owner of `session`, and if any ctor or
        // ContentDialog property throws (e.g. XamlRoot null-coalesce at line ~108)
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
            var xamlRoot = App.Current.MainWindow?.Content?.XamlRoot
                ?? throw new InvalidOperationException("No active window to host dialog.");
            // Note: no CloseButtonText. ContentDialog's built-in buttons stretch to fill
            // their grid column via a template LOCAL-VALUE HorizontalAlignment=Stretch
            // that Style setters cannot override. Instead, FileTransferDialog hosts its
            // own compact Close button in its content; we subscribe to CloseRequested
            // and call Hide() below.
            var dialog = new ContentDialog
            {
                Title = $"File transfer — {profile.Name}",
                Content = view,
                XamlRoot = xamlRoot,
            };
            view.CloseRequested += (_, _) => dialog.Hide();
            // ContentDialog's default ContentDialogMaxWidth theme resource is ~548 px —
            // phone-friendly sizing that clamps a two-pane file browser to a single
            // visible pane. FullSizeDesired does NOT lift this cap in WinUI 3; it only
            // adjusts inner spacing. Override the theme resources at the dialog instance
            // level so the dialog can grow to host the UserControl's MinWidth=900.
            //
            // Set Min == Max so the dialog is LOCKED at this width: by default
            // ContentDialog sizes to its content's measured width within the [Min,Max]
            // bounds, which makes the dialog visibly grow/shrink as the user navigates
            // into folders with longer/shorter filenames. Locking both to the same value
            // gives a stable size that doesn't oscillate with content changes.
            //
            // Target ~85% of the host window, with sensible bounds. If the user's window
            // is narrower than the minimum, the XamlRoot clips naturally.
            var rootSize = xamlRoot.Size;
            var targetWidth = Math.Clamp(rootSize.Width * 0.85, 900.0, 1400.0);
            var targetHeight = Math.Clamp(rootSize.Height * 0.85, 560.0, 900.0);
            dialog.Resources["ContentDialogMinWidth"] = targetWidth;
            dialog.Resources["ContentDialogMaxWidth"] = targetWidth;
            dialog.Resources["ContentDialogMinHeight"] = targetHeight;
            dialog.Resources["ContentDialogMaxHeight"] = targetHeight;
            // FullSizeDesired keeps dynamic spacing in the content area for big content.
            dialog.SetValue(ContentDialog.FullSizeDesiredProperty, true);

            // Light-dismiss on outside click: ContentDialog doesn't ship with this by
            // default (modal). Hook the template's outer root in Opened and close if
            // the pointer-press hit lands on the smoke layer rather than the dialog
            // body. Escape continues to work via ContentDialog's built-in handling for
            // CloseButton.
            dialog.Opened += (sender, _) => AttachLightDismiss(sender);

            // Initialize before ShowAsync so panes have entries by the time the dialog
            // renders. Observe the task so a synchronous throw or failed pane load
            // surfaces in logs rather than disappearing as an UnobservedTaskException.
            _ = SafeInitializeAsync(view, vm);
            await dialog.ShowAsync();
        }
        finally
        {
            // Dispose the VM (which disposes the orchestrator which disposes the SFTP
            // session) on EVERY exit path: dialog closed, ShowAsync threw, or any of
            // the constructions above threw. If vm wasn't built, still dispose the
            // orchestrator we did construct (if any); otherwise dispose the bare session.
            if (vm is not null)
            {
                await vm.DisposeAsync().ConfigureAwait(true);
            }
            else if (orchestrator is not null)
            {
                await orchestrator.DisposeAsync().ConfigureAwait(true);
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

    /// <summary>
    /// Attach a PointerPressed handler to the ContentDialog's template root so a click
    /// on the smoke-layer region (outside the dialog body) dismisses the dialog.
    /// <para>
    /// Uses <c>AddHandler(..., handledEventsToo: true)</c> because the dialog body
    /// elements (ListView items, buttons, etc.) mark their PointerPressed events as
    /// handled — without the bool, our handler never sees clicks. We resolve the
    /// dialog-body Border (<c>BackgroundElement</c> in WinUI 3's ContentDialog
    /// template) once at attach time and check ancestor-or-self against that
    /// specific reference, so a misnamed inner element cannot accidentally suppress
    /// dismissal and a template change in a future WinUI release fails safe (no
    /// dismiss) rather than dismissing on every click.
    /// </para>
    /// </summary>
    private static void AttachLightDismiss(ContentDialog dialog)
    {
        if (VisualTreeHelper.GetChildrenCount(dialog) == 0) return;
        if (VisualTreeHelper.GetChild(dialog, 0) is not FrameworkElement templateRoot) return;

        // Capture the dialog body reference now. The previous implementation matched
        // by name and also accepted "LayoutRoot", but LayoutRoot IS the outermost
        // template grid that contains both the smoke layer and the dialog body, so
        // every click's ancestor chain reached it and dismissal never fired. Walking
        // up looking for the captured BackgroundElement instance is unambiguous.
        var body = FindDescendantByName(templateRoot, "BackgroundElement");
        if (body is null) return;

        templateRoot.AddHandler(UIElement.PointerPressedEvent, new PointerEventHandler((_, e) =>
        {
            if (IsAncestorOrSelf(e.OriginalSource as DependencyObject, body)) return;
            dialog.Hide();
        }), handledEventsToo: true);
    }

    /// <summary>
    /// Depth-first descendant search by Name. Used to locate the ContentDialog
    /// template's <c>BackgroundElement</c> Border once at attach time.
    /// </summary>
    private static FrameworkElement? FindDescendantByName(DependencyObject root, string name)
    {
        var count = VisualTreeHelper.GetChildrenCount(root);
        for (int i = 0; i < count; i++)
        {
            var child = VisualTreeHelper.GetChild(root, i);
            if (child is FrameworkElement fe && fe.Name == name) return fe;
            if (FindDescendantByName(child, name) is { } match) return match;
        }
        return null;
    }

    /// <summary>
    /// True if <paramref name="hit"/> is <paramref name="ancestor"/> itself or any
    /// of its visual-tree ancestors. Reference comparison so unrelated elements
    /// sharing a name cannot match.
    /// </summary>
    private static bool IsAncestorOrSelf(DependencyObject? hit, DependencyObject ancestor)
    {
        while (hit is not null)
        {
            if (ReferenceEquals(hit, ancestor)) return true;
            hit = VisualTreeHelper.GetParent(hit);
        }
        return false;
    }
}
