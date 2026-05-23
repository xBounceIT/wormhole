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
