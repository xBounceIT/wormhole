using System.Collections.ObjectModel;
using Wormhole.Models;
using Wormhole.Services;
using Wormhole.ViewModels.Sessions.Transfer;

namespace Wormhole.Services.Sftp;

public enum ConflictDecision
{
    Overwrite,
    Skip,
}

public sealed record ConflictContext(string ItemName, string DestinationPath, long? IncomingSize, long? ExistingSize, bool ExistingIsDirectory);

/// <summary>
/// Async callback the dialog supplies to resolve overwrite conflicts. The orchestrator
/// invokes it once per conflicting destination; returning <see cref="ConflictDecision.Skip"/>
/// for the second tuple of a (decision, applyToAll) result causes the orchestrator to
/// auto-apply that decision to every remaining conflict in the same batch — no extra
/// callback invocations.
/// </summary>
public delegate Task<(ConflictDecision Decision, bool ApplyToAll)> ConflictResolver(ConflictContext context, CancellationToken cancellationToken);

public interface IFileTransferOrchestrator : IAsyncDisposable
{
    /// <summary>The owned SFTP session. Pane VMs that need to call SFTP operations
    /// should NOT use this directly — go through <see cref="RunSerializedAsync"/> so
    /// the SSH.NET single-thread invariant holds.</summary>
    ISftpSession Session { get; }

    /// <summary>The bound queue surface for the UI's transfer strip.</summary>
    ObservableCollection<TransferItemViewModel> Transfers { get; }

    /// <summary>Run an SFTP operation under the shared serialization lock. Pane refresh,
    /// rename, create-folder all funnel through here so they cannot interleave with an
    /// in-flight upload/download.</summary>
    Task RunSerializedAsync(Func<Task> action);

    Task EnqueueAsync(TransferRequest request, ConflictResolver resolver, CancellationToken cancellationToken = default);
}
