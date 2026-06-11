using System;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using Microsoft.UI.Dispatching;
using Wormhole.Models;
using Wormhole.Services.Tunneling;
using Wormhole.ViewModels.Sessions;

namespace Wormhole.ViewModels;

/// <summary>
/// Drives <see cref="Views.Dialogs.TunnelTestDialog"/>: establishes a saved tunnel config once as a
/// diagnostic, streaming each <see cref="TunnelProgress"/> phase into a live, timestamped log and
/// surfacing the eventual success/failure. The established tunnel is closed immediately — the test
/// only proves the tunnel can come up and must never leave a diagnostic tunnel running.
/// State machine: idle -> IsBusy (log streams) -> result (<see cref="Succeeded"/> non-null).
/// </summary>
public sealed partial class TunnelTestDialogViewModel : ObservableObject, IDisposable
{
    private readonly TunnelManager _tunnelManager;
    private readonly ILogger<TunnelTestDialogViewModel> _logger;
    private CancellationTokenSource? _cts;
    private TaskCompletionSource? _runTcs;
    // Captured on the UI thread when RunAsync starts so progress callbacks (which arrive on the
    // provider's background thread) can hop back before touching the bound Log/Status. Null in unit
    // tests, where the marshal falls through to synchronous execution. Mirrors SessionTabViewModel.
    private DispatcherQueue? _dispatcher;
    // Latest phase, written synchronously inside Report (before the UI hop) so a failure can name the
    // last step even if the marshalled log update hasn't run yet.
    private TunnelProgress? _lastProgress;

    public TunnelTestDialogViewModel(
        TunnelManager tunnelManager,
        ILogger<TunnelTestDialogViewModel> logger)
    {
        _tunnelManager = tunnelManager;
        _logger = logger;
    }

    /// <summary>Timestamped log lines, oldest first. Bound to the dialog's log list.</summary>
    public ObservableCollection<string> Log { get; } = new();

    /// <summary>Dialog title, e.g. "Test tunnel: corp-vpn". Set when the run starts.</summary>
    [ObservableProperty]
    private string headerText = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanClose))]
    [NotifyCanExecuteChangedFor(nameof(CancelCommand))]
    private bool isBusy;

    [ObservableProperty]
    private string status = string.Empty;

    // null while running / not started; true on success; false on failure or cancellation. Drives
    // the result InfoBar's visibility (HasResult) and severity (IsSuccess).
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasResult))]
    [NotifyPropertyChangedFor(nameof(IsSuccess))]
    private bool? succeeded;

    [ObservableProperty]
    private string resultTitle = string.Empty;

    [ObservableProperty]
    private string resultMessage = string.Empty;

    // Distinguishes a user cancel from a real failure so the result InfoBar can render it as
    // informational rather than an alarming error (both leave Succeeded == false).
    [ObservableProperty]
    private bool wasCancelled;

    // Distinguishes a benign, recoverable outcome (Stormshield downloaded a fresh profile and now needs a
    // new one-time code) from a real failure, so the result InfoBar renders it as informational rather than
    // an alarming error (also leaves Succeeded == false).
    [ObservableProperty]
    private bool wasInformational;

    public bool CanClose => !IsBusy;
    public bool HasResult => Succeeded.HasValue;
    public bool IsSuccess => Succeeded == true;

    /// <summary>
    /// Run the diagnostic for <paramref name="config"/>. Invoked once when the dialog opens. Never
    /// throws — every outcome (success, cancel, failure) is reported through the bound state.
    /// </summary>
    public async Task RunAsync(TunnelConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);
        if (IsBusy) return;

        _dispatcher = TryGetDispatcher();
        HeaderText = $"Test tunnel: {config.Name}";
        IsBusy = true;
        Succeeded = null;
        WasCancelled = false;
        WasInformational = false;
        ResultTitle = string.Empty;
        ResultMessage = string.Empty;
        Volatile.Write(ref _lastProgress, null);
        Log.Clear();
        Status = "Starting tunnel test…";
        AppendLog($"Testing '{config.Name}' ({DescribeKind(config.Kind)})…");

        _cts?.Dispose();
        _cts = new CancellationTokenSource();
        _runTcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var token = _cts.Token;

        var progress = new ProgressBridge(Report);
        try
        {
            await using (await _tunnelManager.EstablishConfigAsync(config, token, progress).ConfigureAwait(true))
            {
                // Reaching here means the tunnel came up. Closing the instance immediately (the
                // using scope) tears it down so the diagnostic never leaves a tunnel running.
            }

            Status = "Tunnel test succeeded.";
            AppendLog("Tunnel established successfully. Test tunnel closed.");
            ResultTitle = "Tunnel test succeeded";
            ResultMessage = $"'{config.Name}' started successfully. The test tunnel has been closed.";
            Succeeded = true;
        }
        catch (OperationCanceledException)
        {
            Status = "Tunnel test cancelled.";
            AppendLog("Test cancelled.");
            ResultTitle = "Tunnel test cancelled";
            ResultMessage = $"The test for '{config.Name}' was cancelled before it finished.";
            WasCancelled = true;
            Succeeded = false;
        }
        catch (TunnelRecoverableNoticeException ex)
        {
            // Not a failure: the tunnel did the right thing (e.g. auth + profile download succeeded, spending
            // the one-time code, or a re-entered just-spent code was rejected) and just needs a reconnect.
            // Render it as an informational result, not an alarming error.
            Status = $"{ex.NoticeTitle}.";
            AppendLog(ex.Message);
            ResultTitle = ex.NoticeTitle;
            ResultMessage = ex.Message;
            WasInformational = true;
            Succeeded = false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Tunnel test failed for '{Name}'", config.Name);
            var lastStep = DescribeLastProgress(Volatile.Read(ref _lastProgress));
            Status = "Tunnel test failed.";
            AppendLog($"Failed: {ex.Message}{lastStep}");
            ResultTitle = "Tunnel test failed";
            ResultMessage = $"'{config.Name}' failed to start: {ex.Message}{lastStep}";
            Succeeded = false;
        }
        finally
        {
            IsBusy = false;
            _runTcs.TrySetResult();
        }
    }

    [RelayCommand(CanExecute = nameof(IsBusy))]
    private void Cancel() => SafeCancel();

    /// <summary>Called by the host dialog when the user tries to close mid-run.</summary>
    public void RequestCancelForClose() => SafeCancel();

    /// <summary>Completes once <see cref="RunAsync"/> has fully unwound (success, cancel, or error).</summary>
    public Task WaitForRunEnd() => _runTcs?.Task ?? Task.CompletedTask;

    /// <summary>Cancel the in-flight establish without crashing on a Cancel/Dispose race (CTS throws
    /// ObjectDisposedException if Cancel observes a freshly-disposed source).</summary>
    private void SafeCancel()
    {
        try { _cts?.Cancel(); }
        catch (ObjectDisposedException) { /* race with Dispose; nothing to cancel anyway */ }
    }

    // Invoked synchronously from the provider's (possibly background) thread. Capture the phase
    // first so a subsequent failure can name the last step, then hop the bound-state update onto the
    // UI thread.
    private void Report(TunnelProgress progress)
    {
        Volatile.Write(ref _lastProgress, progress);
        var line = ConnectionProgress.DescribeTunnelPhase(progress);
        MarshalToUi(() =>
        {
            Status = line;
            AppendLog(line);
        });
    }

    private void AppendLog(string line) =>
        Log.Add($"[{DateTime.Now.ToString("HH:mm:ss", CultureInfo.CurrentCulture)}] {line}");

    private void MarshalToUi(Action action)
    {
        var dispatcher = _dispatcher;
        // No dispatcher captured (unit tests): run synchronously. Best-effort fall back to direct
        // execution if TryEnqueue is rejected (queue shutting down) so a log line is never silently
        // dropped while still showing the right final result.
        if (dispatcher is null || !dispatcher.TryEnqueue(() => action()))
        {
            action();
        }
    }

    private static DispatcherQueue? TryGetDispatcher()
    {
        try { return DispatcherQueue.GetForCurrentThread(); }
        catch (COMException) { return null; }
        catch (TypeInitializationException) { return null; }
    }

    private static string DescribeKind(TunnelKind kind) => kind switch
    {
        TunnelKind.WireGuard => "WireGuard",
        TunnelKind.OpenVpn => "OpenVPN",
        TunnelKind.Fortinet => "Fortinet",
        TunnelKind.Watchguard => "WatchGuard",
        TunnelKind.Stormshield => "Stormshield",
        TunnelKind.AzureVpn => "Azure VPN",
        TunnelKind.CiscoSecureClient => "Cisco Secure Client",
        _ => kind.ToString(),
    };

    // Terse trailing " Last step: …" suffix appended to a failure message, naming the last phase the
    // provider reached before throwing. Mirrors the phrasing the settings-page test used before this
    // dialog existed.
    private static string DescribeLastProgress(TunnelProgress? progress)
    {
        if (progress is null) return string.Empty;
        var detail = string.IsNullOrWhiteSpace(progress.Detail)
            ? progress.Phase switch
            {
                TunnelPhase.Preparing => "preparing tunnel",
                TunnelPhase.Authenticating => "authenticating",
                TunnelPhase.DownloadingConfiguration => "downloading configuration",
                TunnelPhase.StartingTunnel => "starting tunnel",
                _ => progress.Phase.ToString(),
            }
            : progress.Detail.Trim();
        return $" Last step: {detail}.";
    }

    public void Dispose()
    {
        _cts?.Dispose();
        _cts = null;
        _runTcs?.TrySetResult();
    }

    // Forwards IProgress<TunnelProgress>.Report straight to the owner synchronously. Unlike
    // System.Progress<T>, it does NOT capture/post to a SynchronizationContext — the owner does its
    // own dispatcher hop — so the last-step capture stays synchronous and unit tests are deterministic.
    private sealed class ProgressBridge : IProgress<TunnelProgress>
    {
        private readonly Action<TunnelProgress> _onReport;
        public ProgressBridge(Action<TunnelProgress> onReport) => _onReport = onReport;
        public void Report(TunnelProgress value) => _onReport(value);
    }
}
