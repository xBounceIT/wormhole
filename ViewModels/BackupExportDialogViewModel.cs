using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using Wormhole.Models.Backup;
using Wormhole.Services.Backup;

namespace Wormhole.ViewModels;

// Drives BackupExportDialog. Same state-machine shape as MRemoteNgImportDialogViewModel:
//   1. picking file       (idle, no Result, IsBusy=false)
//   2. exporting          (IsBusy=true, Percent climbs)
//   3. result              (Result is non-null)
//
// Password is OPTIONAL — leaving it blank produces a plaintext JSON file. The UI shows an
// inline warning in that case so the user makes a conscious choice.
public sealed partial class BackupExportDialogViewModel : ObservableObject, IDisposable
{
    private readonly IBackupService _backupService;
    private readonly ILogger<BackupExportDialogViewModel> _logger;
    private CancellationTokenSource? _cts;
    private TaskCompletionSource? _runTcs;

    public BackupExportDialogViewModel(
        IBackupService backupService,
        ILogger<BackupExportDialogViewModel> logger)
    {
        _backupService = backupService;
        _logger = logger;
    }

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(StartExportCommand))]
    [NotifyPropertyChangedFor(nameof(CanStartExport))]
    private string? selectedPath;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(StartExportCommand))]
    [NotifyCanExecuteChangedFor(nameof(CancelCommand))]
    [NotifyPropertyChangedFor(nameof(CanStartExport))]
    [NotifyPropertyChangedFor(nameof(CanClose))]
    [NotifyPropertyChangedFor(nameof(CanPickFile))]
    private bool isBusy;

    [ObservableProperty]
    private string? password;

    [ObservableProperty]
    private int percent;

    [ObservableProperty]
    private string status = string.Empty;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(StartExportCommand))]
    [NotifyPropertyChangedFor(nameof(CanStartExport))]
    [NotifyPropertyChangedFor(nameof(HasResult))]
    private BackupExportResult? result;

    public bool CanStartExport =>
        !IsBusy && Result is null && !string.IsNullOrWhiteSpace(SelectedPath);
    public bool CanClose => !IsBusy;
    public bool CanPickFile => !IsBusy;
    public bool HasResult => Result is not null;

    [RelayCommand(CanExecute = nameof(CanStartExport))]
    private async Task StartExportAsync()
    {
        if (string.IsNullOrWhiteSpace(SelectedPath)) return;

        IsBusy = true;
        Percent = 0;
        Status = "Starting export...";
        Result = null;
        _cts?.Dispose();
        _cts = new CancellationTokenSource();
        _runTcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var token = _cts.Token;

        try
        {
            var progress = new Progress<BackupProgress>(p =>
            {
                Percent = p.Percent;
                Status = p.Status;
            });
            var result = await _backupService.ExportAsync(SelectedPath, Password, progress, token);
            Result = result;
            Percent = 100;
            Status = SummarizeResult(result);
            // Hygiene wipe ONLY on the success path. On a failure/cancel, we MUST leave
            // Password populated so a retry uses the user's typed value — otherwise:
            //   1. user types password, clicks Export
            //   2. export fails (disk full, etc.); finally wipes Password to null
            //   3. PasswordBox is a one-way control; its visible dots remain
            //   4. user re-clicks Export — VM.Password is null → BackupService writes a
            //      PLAINTEXT file containing every credential, with no warning
            // The transient VM lifetime (Disposed by DialogService when the modal closes)
            // already bounds heap residency to the user's interaction window.
            Password = null;
        }
        catch (OperationCanceledException)
        {
            Status = "Export cancelled.";
            Percent = 0;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Backup export failed for {Path}", SelectedPath);
            Status = $"Export failed: {ex.Message}";
            Percent = 0;
        }
        finally
        {
            IsBusy = false;
            _runTcs!.TrySetResult();
        }
    }

    [RelayCommand(CanExecute = nameof(IsBusy))]
    private void Cancel() => SafeCancel();

    public void RequestCancelForClose() => SafeCancel();
    public Task WaitForRunEnd() => _runTcs?.Task ?? Task.CompletedTask;

    /// <summary>CTS.Cancel throws ObjectDisposedException if it races a Dispose; the dialog
    /// teardown can call RequestCancelForClose() while the VM's finally block has already
    /// disposed _cts. Swallow it — there's nothing left to cancel anyway.</summary>
    private void SafeCancel()
    {
        try { _cts?.Cancel(); }
        catch (ObjectDisposedException) { }
    }

    public void ResetForNewFile(string path)
    {
        SelectedPath = path;
        Result = null;
        Status = string.Empty;
        Percent = 0;
    }

    private static string SummarizeResult(BackupExportResult r)
    {
        var enc = r.Encrypted ? " (encrypted)" : " (plaintext)";
        return $"Exported {r.NodeCount} nodes, {r.CredentialCount} credentials, " +
               $"{r.TunnelCount} tunnels, {r.PasswordCount} passwords, " +
               $"{r.PrivateKeyCount} private keys, {r.TunnelPayloadCount} tunnel payloads{enc}.";
    }

    public void Dispose()
    {
        _cts?.Dispose();
        _cts = null;
        _runTcs?.TrySetResult();
    }
}
