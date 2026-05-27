using System.Collections.ObjectModel;
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

    // Passwords we try silently before prompting the user. The mRemoteNG Export dialog
    // has no password field — the encryption key is always the GLOBAL setting from
    // mRemoteNG's Tools → Options → Security. Two values cover the vast majority of users:
    //   "mR3m"  — the factory default; what the file uses when the user has never touched
    //             the encryption-password setting.
    //   ""      — what mRemoteNG writes when the user has explicitly cleared the password
    //             field in Options.
    // Only users who set a CUSTOM password in Options will fall through to the manual
    // prompt below. Because the silent path covers empty, the manual prompt still requires
    // non-empty input — a user typing Enter on a blank PasswordBox would otherwise re-run
    // a verify that's guaranteed to fail and produce a confusing "wrong password" error
    // for zero keystrokes.
    // Wrapped in ReadOnlyCollection so callers can't cast the IReadOnlyList back to string[]
    // and mutate the shared static.
    public static readonly IReadOnlyList<string> SilentDefaultPasswords =
        new ReadOnlyCollection<string>(new[] { DefaultPassword, string.Empty });

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
    [NotifyCanExecuteChangedFor(nameof(ImportStructureOnlyCommand))]
    [NotifyCanExecuteChangedFor(nameof(CancelCommand))]
    [NotifyPropertyChangedFor(nameof(CanStartImport))]
    [NotifyPropertyChangedFor(nameof(CanClose))]
    [NotifyPropertyChangedFor(nameof(CanPickFile))]
    private bool isBusy;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(StartImportCommand))]
    [NotifyCanExecuteChangedFor(nameof(SubmitPasswordCommand))]
    [NotifyCanExecuteChangedFor(nameof(ImportStructureOnlyCommand))]
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
    private Task StartImportAsync() => RunImportAsync(SilentDefaultPasswords, isRetryWithUserPassword: false);

    [RelayCommand(CanExecute = nameof(CanSubmitPassword))]
    private Task SubmitPasswordAsync() =>
        RunImportAsync(new[] { EnteredPassword ?? string.Empty }, isRetryWithUserPassword: true);

    // The silent path already tried "" before flipping NeedsPassword on, so accepting empty
    // here would just re-run a verify guaranteed to fail and surface a misleading
    // "wrong password" error for input the user never typed.
    private bool CanSubmitPassword =>
        !IsBusy && NeedsPassword && !string.IsNullOrEmpty(EnteredPassword);

    // Escape hatch for users who can't recover their custom master password: skip the
    // Protected-verifier check entirely and run Plan+Commit with the default key. Leaves
    // whose Password encrypted with a non-default master will fail GCM and surface as
    // per-leaf warnings (the existing PlanCoreAsync flow), but the connection structure
    // — folders, hostnames, ports, usernames, domains, protocols, inheritance — still
    // imports. Users can re-add passwords manually afterwards.
    [RelayCommand(CanExecute = nameof(CanImportStructureOnly))]
    private Task ImportStructureOnlyAsync() => RunPlanAndCommitAsync(DefaultPassword);

    private bool CanImportStructureOnly =>
        !IsBusy && NeedsPassword;

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

    private async Task RunImportAsync(IReadOnlyList<string> candidates, bool isRetryWithUserPassword)
    {
        ArgumentNullException.ThrowIfNull(candidates);
        if (string.IsNullOrWhiteSpace(SelectedPath)) return;
        if (candidates.Count == 0) return;

        BeginImportState();
        var token = _cts!.Token;

        try
        {
            var fileInfo = await _importService.InspectAsync(SelectedPath, token);
            if (!fileInfo.HasPasswordPayloads)
            {
                NeedsPassword = false;
                PasswordError = null;
                await PlanAndCommitAsync(DefaultPassword, token);
                return;
            }

            // Try each candidate in order. For the silent default path this is ("mR3m", "")
            // — covering both the well-known default and "no password" exports. For the
            // user-retry path it's a single entry. ThrowIfCancellationRequested at the top
            // of every iteration so a Cancel that arrives between candidates doesn't burn
            // an extra ~100ms PBKDF2 round before honoring it.
            string? matched = null;
            foreach (var candidate in candidates)
            {
                token.ThrowIfCancellationRequested();
                if (await _importService.VerifyPasswordAsync(SelectedPath, candidate, token))
                {
                    matched = candidate;
                    break;
                }
            }

            if (matched is null)
            {
                if (!isRetryWithUserPassword)
                {
                    // Silent defaults all failed — flip into prompt mode and stop. The user
                    // re-runs us via SubmitPasswordCommand once they've typed something, or
                    // bails out via ImportStructureOnlyCommand if they can't recover their
                    // master password.
                    // Assign Status BEFORE NeedsPassword so the InfoBar's x:Bind on Message
                    // doesn't briefly render the prior "Reading file..." text in the frame
                    // between the two property-changed notifications.
                    Status = "None of the default mRemoteNG passwords unlocked this file. " +
                            "Enter the encryption password configured in mRemoteNG (set via " +
                            "the connections-file context menu → Set Password), or import " +
                            "the structure without passwords.";
                    Percent = 0;
                    NeedsPassword = true;
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

            // Hygiene wipe of EnteredPassword lives inside PlanAndCommitAsync so both this
            // path and the structure-only escape hatch get the same scrubbing.
            await PlanAndCommitAsync(matched, token);
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
            _runTcs!.TrySetResult();
        }
    }

    /// <summary>Bypasses VerifyPasswordAsync entirely and runs Plan+Commit with the supplied
    /// per-leaf password. Used by the "Import structure only" escape hatch for users whose
    /// master password is unrecoverable — per-leaf decryption failures are surfaced as
    /// warnings via the existing PlanCoreAsync flow, but folders/hosts/ports/usernames still
    /// land in the database.</summary>
    private async Task RunPlanAndCommitAsync(string passwordForLeaves)
    {
        if (string.IsNullOrWhiteSpace(SelectedPath)) return;

        BeginImportState();
        var token = _cts!.Token;
        // Clear the prompt state up front so the InfoBar dismisses immediately on click —
        // the user doesn't need to see "Password required" overlapping the progress bar.
        NeedsPassword = false;
        Status = "Importing structure without password verification...";

        try
        {
            await PlanAndCommitAsync(passwordForLeaves, token);
        }
        catch (OperationCanceledException)
        {
            Status = "Import cancelled. No changes were saved.";
            Percent = 0;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "mRemoteNG structure-only import failed for {Path}", SelectedPath);
            Status = $"Import failed: {ex.Message}";
            Percent = 0;
        }
        finally
        {
            IsBusy = false;
            _runTcs!.TrySetResult();
        }
    }

    /// <summary>Shared Plan/Commit + Result assignment used by both the password-verified
    /// import path and the structure-only escape hatch. Re-throws so the caller's catch
    /// block handles OperationCanceledException / generic failures uniformly.</summary>
    private async Task PlanAndCommitAsync(string password, CancellationToken token)
    {
        var progress = new Progress<MRemoteNgImportProgress>(p =>
        {
            Percent = p.Percent;
            Status = p.Status;
        });

        var plan = await _importService.PlanAsync(SelectedPath!, password, progress, token);
        var result = await _importService.CommitAsync(plan, progress, token);

        Result = result;
        Percent = 100;
        Status = SummarizeResult(result);
        // Hygiene: once the import has actually persisted, drop the cleartext password from
        // the observable property's backing field so it doesn't sit in heap for the VM's
        // lifetime (which is "until app shutdown" because of DI root tracking). Lives here
        // rather than in the caller so the structure-only escape hatch — which can run AFTER
        // the user has typed and aborted — gets the same wipe instead of leaving the typed
        // secret retained.
        EnteredPassword = null;
    }

    /// <summary>Resets per-import observable state and rebuilds the cancellation source +
    /// run-completion TCS. Centralized so RunImportAsync and RunPlanAndCommitAsync can't
    /// drift on which fields they reset.</summary>
    private void BeginImportState()
    {
        IsBusy = true;
        PasswordError = null;
        Percent = 0;
        Status = "Reading file...";
        Result = null;
        _cts?.Dispose();
        _cts = new CancellationTokenSource();
        _runTcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    private static string SummarizeResult(MRemoteNgImportResult r)
    {
        var s =
            $"Imported {r.FoldersCreated} folder{Pluralize(r.FoldersCreated)}, " +
            $"{r.ConnectionsCreated} connection{Pluralize(r.ConnectionsCreated)}, " +
            $"{r.CredentialsCreated} credential{Pluralize(r.CredentialsCreated)}.";
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
            const int warningPreviewCount = 2;
            var shownCount = Math.Min(r.Warnings.Count, warningPreviewCount);
            s += " Warnings: " + JoinFirstWarnings(r.Warnings, shownCount, "; ");
            var listOverflow = r.Warnings.Count - shownCount;
            var totalOverflow = listOverflow + r.DroppedWarningCount;
            if (totalOverflow > 0)
            {
                if (shownCount > 0) s += "; ";
                s += $"+{totalOverflow} more (see logs).";
            }
            else
            {
                s += ".";
            }
        }
        return s;
    }

    private static string Pluralize(int n) => n == 1 ? string.Empty : "s";

    private static string JoinFirstWarnings(IReadOnlyList<string> warnings, int count, string separator)
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

    private static int EstimateJoinedLength(IReadOnlyList<string> values, int count, int separatorLength)
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
