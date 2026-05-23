namespace Wormhole.Models;

/// <summary>
/// One source item to transfer. <see cref="SourcePath"/> is absolute (POSIX for remote,
/// Win32 for local). <see cref="IsDirectory"/> tells the orchestrator to recurse.
/// </summary>
public sealed record TransferItem(string SourcePath, string Name, bool IsDirectory);

/// <summary>
/// A batch of items to move in one direction. Built by a pane's drop handler and
/// handed to <c>IFileTransferOrchestrator.EnqueueAsync</c>. The orchestrator is the
/// only component that knows how to walk source/destination filesystems — pane VMs
/// never reach across into each other.
/// </summary>
public sealed record TransferRequest(
    TransferDirection Direction,
    string DestinationDirectory,
    IReadOnlyList<TransferItem> Items);
