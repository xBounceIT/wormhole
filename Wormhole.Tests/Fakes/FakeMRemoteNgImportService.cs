using Wormhole.Models;
using Wormhole.Services.MRemoteNg;

namespace Wormhole.Tests.Fakes;

/// <summary>
/// In-memory <see cref="IMRemoteNgImportService"/> for testing the dialog VM. Each method's
/// behavior is driven by simple properties so individual tests can simulate the four notable
/// branches: (1) default password works, (2) default fails / user password works,
/// (3) user password fails, (4) cancellation mid-Commit.
/// </summary>
public sealed class FakeMRemoteNgImportService : IMRemoteNgImportService
{
    public string ExpectedPassword { get; set; } = "mR3m";
    public bool VerifyAlwaysTrue { get; set; }
    public MRemoteNgImportResult NextResult { get; set; } = new(1, 2, 3, 0, Array.Empty<string>());
    public MRemoteNgFileInfo NextFileInfo { get; set; } =
        new("2.7", "AES", "GCM", "fake-verifier", false, 10000, true);

    /// <summary>If non-null, CommitAsync awaits this before completing — used to test cancel
    /// behavior with a controlled gating point.</summary>
    public TaskCompletionSource? CommitGate { get; set; }

    public List<string> InspectCalls { get; } = new();
    public List<string> VerifyCalls { get; } = new();
    public List<string> PlanCalls { get; } = new();
    public List<MRemoteNgImportPlan> CommitCalls { get; } = new();

    public Task<MRemoteNgFileInfo> InspectAsync(string path, CancellationToken cancellationToken = default)
    {
        InspectCalls.Add(path);
        return Task.FromResult(NextFileInfo);
    }

    /// <summary>Invoked synchronously inside VerifyPasswordAsync, after the call is recorded
    /// but before the result is returned. Tests can use it to fire side effects (e.g.
    /// cancelling the VM mid-loop) at a deterministic point in the verify pipeline.</summary>
    public Action? OnVerifyCalled { get; set; }

    public Task<bool> VerifyPasswordAsync(string path, string password, CancellationToken cancellationToken = default)
    {
        VerifyCalls.Add(password);
        OnVerifyCalled?.Invoke();
        return Task.FromResult(VerifyAlwaysTrue || password == ExpectedPassword);
    }

    public Task<MRemoteNgImportPlan> PlanAsync(
        string path, string password,
        IProgress<MRemoteNgImportProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        PlanCalls.Add(password);
        progress?.Report(new MRemoteNgImportProgress(15, "Planning..."));
        return Task.FromResult(new MRemoteNgImportPlan(
            Array.Empty<ConnectionNode>(), Array.Empty<CredentialProfile>(),
            new Dictionary<Guid, string>(), 0, 0, 0,
            Array.Empty<string>(), Array.Empty<string>(), 0));
    }

    public async Task<MRemoteNgImportResult> CommitAsync(
        MRemoteNgImportPlan plan,
        IProgress<MRemoteNgImportProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        CommitCalls.Add(plan);
        progress?.Report(new MRemoteNgImportProgress(50, "Saving..."));
        if (CommitGate is not null)
        {
            // Await on cancellation: if the test cancels via the token, we throw, mirroring
            // production where Dapper's ExecuteAsync would throw OperationCanceledException.
            using var registration = cancellationToken.Register(() => CommitGate.TrySetCanceled());
            await CommitGate.Task;
        }
        cancellationToken.ThrowIfCancellationRequested();
        progress?.Report(new MRemoteNgImportProgress(100, "Done."));
        return NextResult;
    }
}
