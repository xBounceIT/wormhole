using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using Wormhole.Models;
using Wormhole.Services.MRemoteNg;

namespace Wormhole.ViewModels;

// Drives the MRemoteNgImportDialog. Owns the per-import cancellation token source and
// flips through these observable states the view binds to:
//   1. picking a file        (idle, no NeedsPassword, no Result, IsBusy=false)
//   2. importing              (IsBusy=true, Percent climbs)
//   3. password prompt        (NeedsPassword=true, after the default failed)
//   4. final result           (Result is not null)
public sealed partial class MRemoteNgImportDialogViewModel : ObservableObject, IDisposable
{
    // The well-known mRemoteNG default — used silently first so users who never customized
    // the password don't see the prompt at all.
    public const string DefaultPassword = "mR3m";

    private readonly IMRemoteNgImportService _importService;
    private readonly ILogger<MRemoteNgImportDialogViewModel> _logger;
    private CancellationTokenSource? _cts;
    // Signaled when the in-flight import task ends (success/fail/cancel). DialogService.OnClosing
    // awaits this so an Esc/Close while IsBusy doesn't tear the dialog down before the success
    // path can assign Result. Reset every time RunImportAsync starts.
    private TaskCompletionSource? _runTcs;

    public MRemoteNgImportDialogViewModel(
        IMRemoteNgImportService importService,
        ILogger<MRemoteNgImportDialogViewModel> logger)
    {
        _importService = importService;
        _logger = logger;
    }

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(StartImportCommand))]
    [NotifyPropertyChangedFor(nameof(CanStartImport))]
    private string? selectedPath;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(StartImportCommand))]
    [NotifyCanExecuteChangedFor(nameof(SubmitPasswordCommand))]
    [NotifyCanExecuteChangedFor(nameof(CancelCommand))]
    [NotifyPropertyChangedFor(nameof(CanStartImport))]
    [NotifyPropertyChangedFor(nameof(CanClose))]
    [NotifyPropertyChangedFor(nameof(CanPickFile))]
    private bool isBusy;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(StartImportCommand))]
    [NotifyCanExecuteChangedFor(nameof(SubmitPasswordCommand))]
    [NotifyPropertyChangedFor(nameof(CanStartImport))]
    private bool needsPassword;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SubmitPasswordCommand))]
    private string? enteredPassword;

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
    private MRemoteNgImportResult? result;

    // Start Import is gated on three things: not currently importing, no prior result, and
    // — crucially — not currently in the password-prompt phase, otherwise the user can click
    // it and re-trigger the default-password attempt while their typed password is ignored.
    public bool CanStartImport =>
        !IsBusy && Result is null && !NeedsPassword && !string.IsNullOrWhiteSpace(SelectedPath);
    public bool CanClose => !IsBusy;
    public bool CanPickFile => !IsBusy;
    public bool HasResult => Result is not null;

    [RelayCommand(CanExecute = nameof(CanStartImport))]
    private Task StartImportAsync() => RunImportAsync(DefaultPassword, isRetryWithUserPassword: false);

    [RelayCommand(CanExecute = nameof(CanSubmitPassword))]
    private Task SubmitPasswordAsync() =>
        RunImportAsync(EnteredPassword ?? string.Empty, isRetryWithUserPassword: true);

    private bool CanSubmitPassword =>
        !IsBusy && NeedsPassword && !string.IsNullOrEmpty(EnteredPassword);

    [RelayCommand(CanExecute = nameof(IsBusy))]
    private void Cancel() => _cts?.Cancel();

    /// <summary>Called by the dialog's Closing handler when the modal is going away. Triggers
    /// cancellation of the in-flight import; callers may await <see cref="WaitForImportEnd"/>
    /// to ensure the success path (Result assignment) has finished before reading it.</summary>
    public void RequestCancelForClose() => _cts?.Cancel();

    /// <summary>Returns a Task that completes when any in-flight RunImportAsync has finished
    /// (success / fail / cancel). Already-completed Task if nothing is running.</summary>
    public Task WaitForImportEnd() => _runTcs?.Task ?? Task.CompletedTask;

    /// <summary>Called by the picker code-behind when the user selects a new file. Resets
    /// every per-import bit of state so a second import on the same dialog doesn't carry
    /// stale UI flags, stale password, or a stale Result.</summary>
    public void ResetForNewFile(string path)
    {
        SelectedPath = path;
        Result = null;
        NeedsPassword = false;
        PasswordError = null;
        // CRITICAL: clear EnteredPassword too, otherwise the next NeedsPassword prompt
        // would have a stale value backing the (visually empty) PasswordBox and Continue
        // would silently submit the prior file's password.
        EnteredPassword = null;
        Status = string.Empty;
        Percent = 0;
    }

    private async Task RunImportAsync(string password, bool isRetryWithUserPassword)
    {
        if (string.IsNullOrWhiteSpace(SelectedPath)) return;

        IsBusy = true;
        PasswordError = null;
        Percent = 0;
        Status = "Reading file...";
        Result = null;
        _cts?.Dispose();
        _cts = new CancellationTokenSource();
        _runTcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var token = _cts.Token;

        try
        {
            await _importService.InspectAsync(SelectedPath, token);

            var ok = await _importService.VerifyPasswordAsync(SelectedPath, password, token);
            if (!ok)
            {
                if (!isRetryWithUserPassword)
                {
                    // Default failed — flip into prompt mode and stop. The user re-runs us via
                    // SubmitPasswordCommand once they've typed something.
                    NeedsPassword = true;
                    Status = "The default mRemoteNG password didn't unlock this file. " +
                            "Enter the password you set when exporting.";
                    Percent = 0;
                    return;
                }

                PasswordError = "That password didn't work. Try again or cancel.";
                Status = string.Empty;
                Percent = 0;
                return;
            }

            // Password is correct; clear any prior prompt state so a successful retry doesn't
            // leave the warning banner lingering.
            NeedsPassword = false;
            PasswordError = null;

            var progress = new Progress<MRemoteNgImportProgress>(p =>
            {
                Percent = p.Percent;
                Status = p.Status;
            });

            var plan = await _importService.PlanAsync(SelectedPath, password, progress, token);
            var result = await _importService.CommitAsync(plan, progress, token);

            Result = result;
            Percent = 100;
            Status = SummarizeResult(result);
            // Hygiene: now that we've successfully imported, drop the cleartext password
            // from the observable property's backing field so it doesn't sit in heap for
            // the VM's lifetime (which is "until app shutdown" because of DI root tracking).
            EnteredPassword = null;
        }
        catch (OperationCanceledException)
        {
            Status = "Import cancelled. No changes were saved.";
            Percent = 0;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "mRemoteNG import failed for {Path}", SelectedPath);
            Status = $"Import failed: {ex.Message}";
            Percent = 0;
        }
        finally
        {
            IsBusy = false;
            _runTcs.TrySetResult();
        }
    }

    private static string SummarizeResult(MRemoteNgImportResult r)
    {
        var parts = new List<string>
        {
            $"{r.FoldersCreated} folder{Pluralize(r.FoldersCreated)}",
            $"{r.ConnectionsCreated} connection{Pluralize(r.ConnectionsCreated)}",
            $"{r.CredentialsCreated} credential{Pluralize(r.CredentialsCreated)}",
        };
        var s = "Imported " + string.Join(", ", parts) + ".";
        if (r.SkippedUnsupportedProtocols > 0)
        {
            s += $" Skipped {r.SkippedUnsupportedProtocols} unsupported connection" +
                 Pluralize(r.SkippedUnsupportedProtocols) + ".";
        }
        if (r.Warnings.Count > 0 || r.DroppedWarningCount > 0)
        {
            // Show the first two warnings inline; a longer list would make the InfoBar
            // unreadable. The full list is in the logs for power users. `DroppedWarningCount`
            // covers anything past the soft cap in the importer, so the "+N more" number is
            // honest even for pathological files with hundreds of warnings.
            var shown = r.Warnings.Take(2).ToList();
            s += " Warnings: " + string.Join("; ", shown);
            var listOverflow = r.Warnings.Count - shown.Count;
            var totalOverflow = listOverflow + r.DroppedWarningCount;
            if (totalOverflow > 0)
            {
                s += $"; +{totalOverflow} more (see logs).";
            }
            else
            {
                s += ".";
            }
        }
        return s;
    }

    private static string Pluralize(int n) => n == 1 ? string.Empty : "s";

    public void Dispose()
    {
        _cts?.Dispose();
        _cts = null;
        _runTcs?.TrySetResult();
    }
}
