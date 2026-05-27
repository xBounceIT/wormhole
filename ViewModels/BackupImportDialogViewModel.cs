using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using Wormhole.Models.Backup;
using Wormhole.Services.Backup;

namespace Wormhole.ViewModels;

// Drives BackupImportDialog. State machine:
//   1. picking file                (idle)
//   2. inspecting file              (Inspecting=true briefly)
//   3. password-required pause       (NeedsPassword=true if file is encrypted)
//   4. importing                    (IsBusy=true, Percent climbs)
//   5. result                        (Result is non-null)
public sealed partial class BackupImportDialogViewModel : ObservableObject, IDisposable
{
    private readonly IBackupService _backupService;
    private readonly ILogger<BackupImportDialogViewModel> _logger;
    private CancellationTokenSource? _cts;
    private TaskCompletionSource? _runTcs;
    // Bumped every time the user picks a new file. A stale InspectAsync continuation that
    // resolves for a previously-picked file must NOT overwrite the IsEncrypted/Status set by
    // the newer pick. Compared atomically inside ResetForNewFileAsync.
    private int _resetGeneration;

    public BackupImportDialogViewModel(
        IBackupService backupService,
        ILogger<BackupImportDialogViewModel> logger)
    {
        _backupService = backupService;
        _logger = logger;
    }

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(StartImportCommand))]
    [NotifyPropertyChangedFor(nameof(CanStartImport))]
    private string? selectedPath;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(StartImportCommand))]
    [NotifyCanExecuteChangedFor(nameof(CancelCommand))]
    [NotifyPropertyChangedFor(nameof(CanStartImport))]
    [NotifyPropertyChangedFor(nameof(CanClose))]
    [NotifyPropertyChangedFor(nameof(CanPickFile))]
    private bool isBusy;

    // Set after a successful InspectAsync says "this file is encrypted". The UI reveals the
    // PasswordBox when this is true. We DO NOT block StartImportCommand on this — the user
    // can re-pick a different file (plaintext), and StartImportAsync will re-inspect and
    // either skip password handling or surface the prompt fresh.
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(FileIsEncryptedMessage))]
    private bool isEncrypted;

    [ObservableProperty]
    private string? password;

    [ObservableProperty]
    private string? passwordError;

    [ObservableProperty]
    private int percent;

    [ObservableProperty]
    private string status = string.Empty;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(StartImportCommand))]
    [NotifyPropertyChangedFor(nameof(CanStartImport))]
    [NotifyPropertyChangedFor(nameof(HasResult))]
    private BackupImportResult? result;

    public bool CanStartImport =>
        !IsBusy && Result is null && !string.IsNullOrWhiteSpace(SelectedPath);
    public bool CanClose => !IsBusy;
    public bool CanPickFile => !IsBusy;
    public bool HasResult => Result is not null;
    public string? FileIsEncryptedMessage =>
        IsEncrypted
            ? "This backup is encrypted. Enter the password used at export time."
            : null;

    [RelayCommand(CanExecute = nameof(CanStartImport))]
    private async Task StartImportAsync()
    {
        if (string.IsNullOrWhiteSpace(SelectedPath)) return;

        IsBusy = true;
        Percent = 0;
        Status = "Reading backup...";
        Result = null;
        PasswordError = null;
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
            var result = await _backupService.ImportAsync(SelectedPath, Password, progress, token);
            Result = result;
            Percent = 100;
            Status = SummarizeResult(result);
            // Hygiene wipe on success only — see BackupExportDialogViewModel for why we keep
            // Password populated on failure paths.
            Password = null;
        }
        catch (BackupPasswordRequiredException)
        {
            // We didn't have a password and the file turned out to be encrypted — flip the
            // UI into password-prompt mode and let the user retry. Status assignment first
            // so the prompt's helper text shows before NeedsPassword toggles the panel in.
            Status = "This backup is encrypted. Enter the password and click Import.";
            Percent = 0;
            IsEncrypted = true;
        }
        catch (BackupBadPasswordException)
        {
            PasswordError = "Wrong password (or the file is corrupted). Try again.";
            Status = string.Empty;
            Percent = 0;
            IsEncrypted = true;
        }
        catch (OperationCanceledException)
        {
            Status = "Import cancelled. Some items may already have been saved.";
            Percent = 0;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Backup import failed for {Path}", SelectedPath);
            Status = $"Import failed: {ex.Message}";
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

    /// <summary>Cancel the in-flight import without crashing on a Cancel/Dispose race. CTS
    /// throws ObjectDisposedException if Cancel observes a freshly-disposed source; the
    /// finally block in StartImportAsync and our own Dispose() race against Closing-deferred
    /// cancellations, so the catch is load-bearing.</summary>
    private void SafeCancel()
    {
        try { _cts?.Cancel(); }
        catch (ObjectDisposedException) { /* race with Dispose; nothing to cancel anyway */ }
    }

    public async Task ResetForNewFileAsync(string path)
    {
        var generation = Interlocked.Increment(ref _resetGeneration);
        SelectedPath = path;
        Result = null;
        Status = string.Empty;
        Percent = 0;
        PasswordError = null;
        Password = null;
        IsEncrypted = false;
        // Run a lightweight inspect so the password field becomes visible up-front if the file
        // is encrypted. Swallow exceptions — a malformed file will produce the real error when
        // the user clicks Import, which is also where the rest of the error UI lives. Compare
        // the generation token so a stale inspect for a previous file can't overwrite the
        // state for the current pick.
        try
        {
            var info = await _backupService.InspectAsync(path);
            if (generation != Volatile.Read(ref _resetGeneration)) return;
            IsEncrypted = info.Encrypted;
            if (info.Encrypted) Status = "Encrypted backup. Enter the password and click Import.";
        }
        catch
        {
            if (generation != Volatile.Read(ref _resetGeneration)) return;
            IsEncrypted = false;
        }
    }

    private static string SummarizeResult(BackupImportResult r)
    {
        var summary =
            $"{r.NodesImported} nodes imported ({r.NodesSkipped} skipped), " +
            $"{r.CredentialsImported} credentials imported ({r.CredentialsSkipped} skipped), " +
            $"{r.TunnelsImported} tunnels imported ({r.TunnelsSkipped} skipped).";
        if (r.Warnings.Count > 0)
        {
            const int warningPreviewCount = 3;
            var shownCount = Math.Min(r.Warnings.Count, warningPreviewCount);
            summary += $" Warnings ({r.Warnings.Count}): {JoinFirstWarnings(r.Warnings, shownCount, " ")}";
            if (r.Warnings.Count > shownCount)
            {
                summary += $" (+{r.Warnings.Count - shownCount} more; see logs.)";
            }
        }
        return summary;
    }

    private static string JoinFirstWarnings(List<string> warnings, int count, string separator)
    {
        if (count <= 0) return string.Empty;
        if (count == 1) return warnings[0];

        return string.Create(EstimateJoinedLength(warnings, count, separator.Length), (warnings, count, separator), static (destination, state) =>
        {
            var offset = 0;
            for (var i = 0; i < state.count; i++)
            {
                if (i > 0)
                {
                    state.separator.AsSpan().CopyTo(destination[offset..]);
                    offset += state.separator.Length;
                }

                state.warnings[i].AsSpan().CopyTo(destination[offset..]);
                offset += state.warnings[i].Length;
            }
        });
    }

    private static int EstimateJoinedLength(List<string> values, int count, int separatorLength)
    {
        var length = separatorLength * (count - 1);
        for (var i = 0; i < count; i++)
        {
            length += values[i].Length;
        }
        return length;
    }

    public void Dispose()
    {
        _cts?.Dispose();
        _cts = null;
        _runTcs?.TrySetResult();
    }
}
