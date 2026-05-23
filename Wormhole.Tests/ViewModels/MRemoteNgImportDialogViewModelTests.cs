using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Models;
using Wormhole.Tests.Fakes;
using Wormhole.ViewModels;
using Xunit;

namespace Wormhole.Tests.ViewModels;

public class MRemoteNgImportDialogViewModelTests
{
    [Fact]
    public async Task StartImport_WithDefaultPassword_ProducesResultAndNoPrompt()
    {
        var svc = new FakeMRemoteNgImportService { ExpectedPassword = "mR3m" };
        var vm = CreateVm(svc);
        vm.SelectedPath = @"X:\fake.xml";

        await vm.StartImportCommand.ExecuteAsync(null);

        Assert.False(vm.IsBusy);
        Assert.False(vm.NeedsPassword);
        Assert.NotNull(vm.Result);
        Assert.Equal(100, vm.Percent);
        // The default password is tried first; we should NOT see any retry call.
        Assert.Single(svc.VerifyCalls);
        Assert.Equal("mR3m", svc.VerifyCalls[0]);
    }

    [Fact]
    public async Task StartImport_WithEmptyMasterPassword_SilentlySucceedsAfterTryingDefault()
    {
        // Regression: exporting from mRemoteNG with the "no password" option produces a file
        // whose Protected attribute verifies against the empty string. The old VM only tried
        // "mR3m" silently, then prompted — but the password prompt blocked empty submission,
        // making such exports literally unimportable. Now we silently try "" after "mR3m".
        var svc = new FakeMRemoteNgImportService { ExpectedPassword = string.Empty };
        var vm = CreateVm(svc);
        vm.SelectedPath = @"X:\fake.xml";

        await vm.StartImportCommand.ExecuteAsync(null);

        Assert.False(vm.NeedsPassword);
        Assert.NotNull(vm.Result);
        // Both candidates were tried in order: default first, then empty.
        Assert.Equal(2, svc.VerifyCalls.Count);
        Assert.Equal("mR3m", svc.VerifyCalls[0]);
        Assert.Equal(string.Empty, svc.VerifyCalls[1]);
        // The matched empty password — NOT the EnteredPassword (which is null) — is what
        // gets piped into Plan/Commit. Use Assert.Single before indexing so a regression
        // where Plan is skipped yields a diagnostic xUnit failure instead of a confusing
        // LINQ "Sequence contains no elements" exception.
        Assert.Single(svc.PlanCalls);
        Assert.Equal(string.Empty, svc.PlanCalls[0]);
    }

    [Fact]
    public async Task StartImport_CancelBetweenCandidates_StopsBeforeRunningNextVerify()
    {
        // Regression: the silent-retry foreach iterated over candidates without checking the
        // cancellation token between iterations. If Cancel arrived during/after the first
        // verify, the second candidate's ~100ms PBKDF2 round would still run before honoring
        // the cancel. The fix is `token.ThrowIfCancellationRequested()` at the top of every
        // iteration.
        var svc = new FakeMRemoteNgImportService { ExpectedPassword = "never-match" };
        var vm = CreateVm(svc);
        vm.SelectedPath = @"X:\fake.xml";

        // Trigger cancel after the first verify call completes. The VM should observe the
        // cancellation at the top of the second iteration and skip the empty-password verify.
        svc.OnVerifyCalled = () =>
        {
            if (svc.VerifyCalls.Count == 1)
            {
                vm.CancelCommand.Execute(null);
            }
        };

        await vm.StartImportCommand.ExecuteAsync(null);

        // Only the "mR3m" verify ran. The empty-password candidate was skipped because the
        // loop-top ThrowIfCancellationRequested honored the cancel before re-entering Verify.
        Assert.Single(svc.VerifyCalls);
        Assert.Equal("mR3m", svc.VerifyCalls[0]);
        Assert.Contains("cancel", vm.Status, StringComparison.OrdinalIgnoreCase);
        Assert.False(vm.IsBusy);
        Assert.Null(vm.Result);
    }

    [Fact]
    public async Task ImportStructureOnly_BypassesVerifyAndRunsPlanCommit()
    {
        // Escape hatch for users with an unrecoverable custom master password: the silent
        // path fails, NeedsPassword flips on, user clicks "Import structure without
        // passwords". We must skip VerifyPasswordAsync entirely (no extra Verify call after
        // the silent attempts) and run Plan+Commit with the default key so the connection
        // structure lands even if per-leaf passwords don't decrypt.
        var svc = new FakeMRemoteNgImportService { ExpectedPassword = "custom-unknown" };
        var vm = CreateVm(svc);
        vm.SelectedPath = @"X:\fake.xml";
        await vm.StartImportCommand.ExecuteAsync(null);
        Assert.True(vm.NeedsPassword);
        var verifyCallsBefore = svc.VerifyCalls.Count;

        await vm.ImportStructureOnlyCommand.ExecuteAsync(null);

        // No additional Verify calls — the escape hatch bypasses verification.
        Assert.Equal(verifyCallsBefore, svc.VerifyCalls.Count);
        // Plan ran with the default password so leaves encrypted with mR3m still decrypt;
        // ones encrypted with a custom master become per-leaf warnings inside PlanCoreAsync.
        Assert.Single(svc.PlanCalls);
        Assert.Equal("mR3m", svc.PlanCalls[0]);
        Assert.Single(svc.CommitCalls);
        // Prompt dismisses, result lands, no spurious error.
        Assert.False(vm.NeedsPassword);
        Assert.False(vm.IsBusy);
        Assert.NotNull(vm.Result);
        Assert.Null(vm.PasswordError);
    }

    [Fact]
    public async Task ImportStructureOnly_ScrubsEnteredPasswordAfterSuccess()
    {
        // Regression (codex review P2): if the user typed a custom password into the prompt
        // and then bailed out via "Import structure without passwords", the typed secret used
        // to sit in EnteredPassword for the VM's lifetime — the verified path scrubbed it but
        // the new escape hatch didn't. The wipe now lives in PlanAndCommitAsync so both paths
        // get it.
        var svc = new FakeMRemoteNgImportService { ExpectedPassword = "custom-unknown" };
        var vm = CreateVm(svc);
        vm.SelectedPath = @"X:\fake.xml";
        await vm.StartImportCommand.ExecuteAsync(null);
        Assert.True(vm.NeedsPassword);
        // User types a guess, then changes their mind and clicks "Import structure only".
        vm.EnteredPassword = "guess-typed-then-abandoned";

        await vm.ImportStructureOnlyCommand.ExecuteAsync(null);

        Assert.NotNull(vm.Result);
        // The typed guess must be scrubbed from the VM after successful structure-only
        // import — same hygiene contract as the verified path.
        Assert.Null(vm.EnteredPassword);
    }

    [Fact]
    public void CanImportStructureOnly_FalseUntilPromptAppears()
    {
        // Regression guard: the escape-hatch button must NOT be clickable in the idle /
        // picking-file state, otherwise it would race the silent path and double-import.
        var svc = new FakeMRemoteNgImportService();
        var vm = CreateVm(svc);

        Assert.False(vm.ImportStructureOnlyCommand.CanExecute(null));
        vm.SelectedPath = @"X:\fake.xml";
        Assert.False(vm.ImportStructureOnlyCommand.CanExecute(null));
        // Only after NeedsPassword flips (which only RunImportAsync does) is the command
        // executable. Mimic that here by setting NeedsPassword directly via the observable
        // property — exercises the [NotifyCanExecuteChangedFor] wiring.
        vm.NeedsPassword = true;
        Assert.True(vm.ImportStructureOnlyCommand.CanExecute(null));
        // And busy state disables it again so the user can't fire two imports concurrently.
        vm.IsBusy = true;
        Assert.False(vm.ImportStructureOnlyCommand.CanExecute(null));
    }

    [Fact]
    public async Task SubmitPassword_RejectsEmptyEntry()
    {
        // The silent path already tried "" before flipping NeedsPassword on, so accepting an
        // empty manual submission would just re-run a verify guaranteed to fail and surface
        // a misleading "wrong password" error for input the user never typed. Continue must
        // stay disabled until the user actually types something.
        var svc = new FakeMRemoteNgImportService { ExpectedPassword = "real-password" };
        var vm = CreateVm(svc);
        vm.SelectedPath = @"X:\fake.xml";
        await vm.StartImportCommand.ExecuteAsync(null);
        Assert.True(vm.NeedsPassword);

        // EnteredPassword stays null (user hasn't typed anything) — Continue is disabled.
        Assert.False(vm.SubmitPasswordCommand.CanExecute(null));
        // Typing flips it on.
        vm.EnteredPassword = "x";
        Assert.True(vm.SubmitPasswordCommand.CanExecute(null));
        // Clearing flips it back off — exercises the [NotifyCanExecuteChangedFor] wiring on
        // EnteredPassword so a future refactor that drops the attribute is caught.
        vm.EnteredPassword = string.Empty;
        Assert.False(vm.SubmitPasswordCommand.CanExecute(null));
    }

    [Fact]
    public async Task StartImport_DefaultPasswordFails_PromptsForCustom()
    {
        var svc = new FakeMRemoteNgImportService { ExpectedPassword = "real-password" };
        var vm = CreateVm(svc);
        vm.SelectedPath = @"X:\fake.xml";

        await vm.StartImportCommand.ExecuteAsync(null);

        // Default attempt failed → we're now waiting for a custom password.
        Assert.False(vm.IsBusy);
        Assert.True(vm.NeedsPassword);
        Assert.Null(vm.Result);
        Assert.Equal(0, vm.Percent);
        // We haven't committed anything yet because the password was wrong.
        Assert.Empty(svc.CommitCalls);
    }

    [Fact]
    public async Task SubmitPassword_WithCorrectCustomPassword_CompletesImport()
    {
        var svc = new FakeMRemoteNgImportService { ExpectedPassword = "real-password" };
        var vm = CreateVm(svc);
        vm.SelectedPath = @"X:\fake.xml";
        await vm.StartImportCommand.ExecuteAsync(null);
        Assert.True(vm.NeedsPassword);

        vm.EnteredPassword = "real-password";
        await vm.SubmitPasswordCommand.ExecuteAsync(null);

        Assert.False(vm.IsBusy);
        Assert.NotNull(vm.Result);
        // PasswordError should be cleared on success.
        Assert.Null(vm.PasswordError);
        Assert.False(vm.NeedsPassword);
    }

    [Fact]
    public async Task SubmitPassword_WithWrongCustomPassword_SetsPasswordError()
    {
        var svc = new FakeMRemoteNgImportService { ExpectedPassword = "real-password" };
        var vm = CreateVm(svc);
        vm.SelectedPath = @"X:\fake.xml";
        await vm.StartImportCommand.ExecuteAsync(null);
        Assert.True(vm.NeedsPassword);

        vm.EnteredPassword = "still-wrong";
        await vm.SubmitPasswordCommand.ExecuteAsync(null);

        Assert.False(vm.IsBusy);
        Assert.True(vm.NeedsPassword);  // still prompting
        Assert.NotNull(vm.PasswordError);
        Assert.Null(vm.Result);
    }

    [Fact]
    public async Task Cancel_MidImport_StopsImportAndClearsProgress()
    {
        var svc = new FakeMRemoteNgImportService
        {
            VerifyAlwaysTrue = true,
            CommitGate = new TaskCompletionSource(),
        };
        var vm = CreateVm(svc);
        vm.SelectedPath = @"X:\fake.xml";

        // Kick off the import without awaiting — it parks inside Commit waiting on the gate.
        var task = vm.StartImportCommand.ExecuteAsync(null);

        // Spin a moment so the VM actually reaches Commit. A short busy-wait keeps the test
        // deterministic without depending on Task.Delay timing in the SUT.
        for (var i = 0; i < 50 && !vm.IsBusy; i++) await Task.Yield();
        Assert.True(vm.IsBusy);

        vm.CancelCommand.Execute(null);
        await task;

        Assert.False(vm.IsBusy);
        Assert.Null(vm.Result);
        // Cancellation status is set; specific string isn't important as long as we don't
        // leave the VM in a busy/half-imported state.
        Assert.Contains("cancel", vm.Status, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CanStartImport_RequiresSelectedPath()
    {
        var svc = new FakeMRemoteNgImportService();
        var vm = CreateVm(svc);

        Assert.False(vm.CanStartImport);
        vm.SelectedPath = @"X:\fake.xml";
        Assert.True(vm.CanStartImport);
    }

    [Fact]
    public async Task CanStartImport_FalseAfterResult()
    {
        var svc = new FakeMRemoteNgImportService { ExpectedPassword = "mR3m" };
        var vm = CreateVm(svc);
        vm.SelectedPath = @"X:\fake.xml";
        await vm.StartImportCommand.ExecuteAsync(null);

        // Once an import completes, the VM blocks re-runs on the same instance so the user
        // can't accidentally double-import. Picking a new file (via the dialog code-behind)
        // clears Result.
        Assert.False(vm.CanStartImport);
    }

    [Fact]
    public async Task CanStartImport_FalseDuringPasswordPrompt()
    {
        // Regression: clicking Start Import while NeedsPassword=true would re-fire the default
        // password attempt and ignore whatever the user typed. CanStartImport must therefore
        // exclude the NeedsPassword phase.
        var svc = new FakeMRemoteNgImportService { ExpectedPassword = "real-password" };
        var vm = CreateVm(svc);
        vm.SelectedPath = @"X:\fake.xml";
        await vm.StartImportCommand.ExecuteAsync(null);

        Assert.True(vm.NeedsPassword);
        Assert.False(vm.CanStartImport);
        Assert.False(vm.StartImportCommand.CanExecute(null));
    }

    [Fact]
    public void ResetForNewFile_ClearsEnteredPasswordAndState()
    {
        // Regression: OnPickFile cleared most fields but left EnteredPassword, so a second
        // import could submit file A's password against file B silently. ResetForNewFile is
        // the single VM entry point that has to wipe ALL per-import state.
        var svc = new FakeMRemoteNgImportService();
        var vm = CreateVm(svc);
        vm.SelectedPath = @"X:\old.xml";
        vm.EnteredPassword = "stale-from-prior-file";
        vm.NeedsPassword = true;
        vm.PasswordError = "old error";
        vm.Status = "old status";
        vm.Percent = 50;
        vm.Result = new MRemoteNgImportResult(0, 0, 0, 0, Array.Empty<string>());

        vm.ResetForNewFile(@"X:\new.xml");

        Assert.Equal(@"X:\new.xml", vm.SelectedPath);
        Assert.Null(vm.EnteredPassword);  // crucial — the bug fix
        Assert.False(vm.NeedsPassword);
        Assert.Null(vm.PasswordError);
        Assert.Equal(string.Empty, vm.Status);
        Assert.Equal(0, vm.Percent);
        Assert.Null(vm.Result);
    }

    [Fact]
    public async Task WaitForImportEnd_CompletesWhenRunFinishes()
    {
        // DialogService.OnClosing awaits this to know when the import has fully unwound,
        // so closing the dialog mid-import can still let the success path assign Result.
        var svc = new FakeMRemoteNgImportService
        {
            ExpectedPassword = "mR3m",
            CommitGate = new TaskCompletionSource(),
        };
        var vm = CreateVm(svc);
        vm.SelectedPath = @"X:\fake.xml";

        var runTask = vm.StartImportCommand.ExecuteAsync(null);
        for (var i = 0; i < 50 && !vm.IsBusy; i++) await Task.Yield();
        var waitTask = vm.WaitForImportEnd();
        Assert.False(waitTask.IsCompleted);

        svc.CommitGate.SetResult();
        await runTask;
        // Once the import finishes, WaitForImportEnd's task should be completed.
        Assert.True(waitTask.IsCompleted);
        Assert.NotNull(vm.Result);
    }

    [Fact]
    public async Task WaitForImportEnd_Idle_ReturnsCompletedTask()
    {
        // Closing the dialog when no import is in flight must not deadlock or hang.
        var svc = new FakeMRemoteNgImportService();
        var vm = CreateVm(svc);

        var task = vm.WaitForImportEnd();

        Assert.True(task.IsCompleted);
    }

    [Fact]
    public async Task SuccessfulImport_ClearsEnteredPasswordForHygiene()
    {
        // The master password lingers in the VM's observable backing field until app shutdown
        // because of the DI root provider tracking transient disposables. Drop it after success.
        var svc = new FakeMRemoteNgImportService { ExpectedPassword = "the-real-one" };
        var vm = CreateVm(svc);
        vm.SelectedPath = @"X:\fake.xml";
        await vm.StartImportCommand.ExecuteAsync(null);  // default fails -> NeedsPassword

        vm.EnteredPassword = "the-real-one";
        await vm.SubmitPasswordCommand.ExecuteAsync(null);

        Assert.NotNull(vm.Result);
        Assert.Null(vm.EnteredPassword);  // hygiene wipe after success
    }

    [Fact]
    public async Task SummarizeResult_IncludesWarningsWhenPresent()
    {
        var svc = new FakeMRemoteNgImportService
        {
            ExpectedPassword = "mR3m",
            NextResult = new MRemoteNgImportResult(
                FoldersCreated: 1,
                ConnectionsCreated: 2,
                CredentialsCreated: 1,
                SkippedUnsupportedProtocols: 0,
                Warnings: new[] { "Could not decrypt password for 'leaf-x'" }),
        };
        var vm = CreateVm(svc);
        vm.SelectedPath = @"X:\fake.xml";
        await vm.StartImportCommand.ExecuteAsync(null);

        Assert.Contains("leaf-x", vm.Status, StringComparison.Ordinal);
    }

    private static MRemoteNgImportDialogViewModel CreateVm(FakeMRemoteNgImportService svc) =>
        new(svc, NullLogger<MRemoteNgImportDialogViewModel>.Instance);
}
