using System.Collections.ObjectModel;
using Microsoft.Extensions.Logging;
using Microsoft.UI.Dispatching;
using Wormhole.Models;
using Wormhole.Services;
using Wormhole.ViewModels.Sessions.Transfer;

namespace Wormhole.Services.Sftp;

/// <summary>
/// Owns the SFTP session for one file-transfer dialog. Serializes every SFTP call via
/// a single <see cref="SemaphoreSlim"/>: SSH.NET's <c>SftpClient</c> is not safe for
/// concurrent use, and a refresh interleaved with an in-flight upload corrupts the
/// session state. Also maintains a temp directory for drag-out exports.
/// </summary>
public sealed class FileTransferOrchestrator : IFileTransferOrchestrator
{
    private readonly ILogger<FileTransferOrchestrator> _logger;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly CancellationTokenSource _shutdown = new();
    private readonly DispatcherQueue? _uiDispatcher;
    private string? _exportTempDir;
    private int _disposed;

    public FileTransferOrchestrator(ISftpSession session, ILogger<FileTransferOrchestrator> logger)
    {
        Session = session;
        _logger = logger;
        // Capture once on the UI thread (dialog construction) so background transfer
        // completions can marshal observable-collection edits back instead of throwing
        // COM apartment errors. In test contexts the WinUI activation factory isn't
        // registered, so GetForCurrentThread throws COMException — null is fine, the
        // orchestrator's AddToTransfers handles the absence by adding inline.
        try { _uiDispatcher = DispatcherQueue.GetForCurrentThread(); }
        catch (System.Runtime.InteropServices.COMException) { _uiDispatcher = null; }
    }

    public ISftpSession Session { get; }
    public ObservableCollection<TransferItemViewModel> Transfers { get; } = new();

    public async Task RunSerializedAsync(Func<Task> action)
    {
        ThrowIfDisposed();
        await _gate.WaitAsync(_shutdown.Token).ConfigureAwait(false);
        try { await action().ConfigureAwait(false); }
        finally { _gate.Release(); }
    }

    public async Task EnqueueAsync(TransferRequest request, ConflictResolver resolver, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _shutdown.Token);
        var token = linked.Token;

        // Per-batch "apply to all" state — the user's decision on the first conflict can
        // suppress prompts for the rest of THIS request. Two intentionally separate
        // sticky values so "apply to all" only covers what the user actually saw.
        ConflictDecision? stickyDecision = null;

        // Flatten directories. Doing it once up front gives the user a single progress
        // bar per file rather than per source root, and makes total-bytes prediction
        // possible for the queue strip. Wrap with try/catch so a flatten-time failure
        // (cancellation via _shutdown.Cancel, server I/O error during WalkRemoteAsync's
        // ListDirectoryAsync) is logged and surfaces to the orchestrator caller instead
        // of vanishing as an UnobservedTaskException through HandleTransferAsync.
        var flattened = new List<FlattenedItem>();
        try
        {
            foreach (var item in request.Items)
            {
                token.ThrowIfCancellationRequested();
                await FlattenAsync(request.Direction, item, request.DestinationDirectory, flattened, token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // Dialog closing or user cancel during a deep remote listing — silent.
            return;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Flatten phase failed for transfer batch ({Direction}).", request.Direction);
            return;
        }

        foreach (var file in flattened)
        {
            token.ThrowIfCancellationRequested();

            // Conflict check: peek the destination before creating the row so a "skip"
            // doesn't leave a ghost row in the queue.
            var exists = await DestinationExistsAsync(request.Direction, file.DestinationPath, token).ConfigureAwait(false);
            ConflictDecision decision = ConflictDecision.Overwrite;
            if (exists)
            {
                if (stickyDecision is { } sticky)
                {
                    decision = sticky;
                }
                else
                {
                    var existingSize = await GetSizeAsync(request.Direction, file.DestinationPath, token).ConfigureAwait(false);
                    var ctx = new ConflictContext(file.RelativeName, file.DestinationPath, file.IncomingSize, existingSize, ExistingIsDirectory: false);
                    // EnqueueAsync has crossed ConfigureAwait(false) boundaries by this
                    // point, so the resolver would otherwise run on a thread-pool thread.
                    // The default WinUI implementation constructs a ContentDialog whose
                    // XamlRoot getter is UI-affine — invoking it off-thread throws
                    // RPC_E_WRONG_THREAD on the first overwrite. Marshal back.
                    var (chosen, applyAll) = await InvokeResolverOnUiAsync(resolver, ctx, token).ConfigureAwait(false);
                    decision = chosen;
                    if (applyAll) stickyDecision = chosen;
                }
                if (decision == ConflictDecision.Skip) continue;
            }

            // Ensure parent directory exists on the destination side (transfer of nested
            // directories means a deeper file may arrive before its parent has been
            // mkdir'd by a directory entry).
            await EnsureDestinationParentAsync(request.Direction, file.DestinationPath, token).ConfigureAwait(false);

            var row = new TransferItemViewModel(file.RelativeName, request.Direction, file.IncomingSize ?? 0, token);
            if (!AddToTransfers(row))
            {
                // Row could not be surfaced to the UI (dispatcher refusing during dialog
                // tear-down). Skip the transfer entirely rather than touching row.Token
                // on a CTS that nothing observes — the user is closing the dialog.
                row.DisposeToken();
                continue;
            }
            try
            {
                MutateRowOnUi(row, r => r.State = TransferState.Running);
                await TransferOneAsync(request.Direction, file, row, row.Token).ConfigureAwait(false);
                MutateRowOnUi(row, r =>
                {
                    r.State = TransferState.Completed;
                    // Snap the progress bar to 100% even if the source reported fewer bytes
                    // than expected (sparse files, EOF before predicted length).
                    r.BytesTransferred = r.ExpectedBytes;
                });
            }
            catch (OperationCanceledException)
            {
                MutateRowOnUi(row, r => r.State = TransferState.Cancelled);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Transfer of {Path} failed.", file.SourcePath);
                MutateRowOnUi(row, r => { r.State = TransferState.Failed; r.ErrorMessage = ex.Message; });
            }
            finally
            {
                // Release the row's linked CTS at the end of EACH iteration so a long
                // batch doesn't accumulate registrations on _shutdown.Token. The token
                // was used by TransferOneAsync; after that completes (success, cancel,
                // or fail) the CTS has no remaining consumer.
                row.DisposeToken();
            }
        }
    }

    public async Task<IReadOnlyList<string>> StageForExportAsync(IReadOnlyList<TransferItem> items, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _shutdown.Token);
        var token = linked.Token;

        _exportTempDir ??= Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "Wormhole-DragOut-" + Guid.NewGuid().ToString("N"))).FullName;

        var staged = new List<string>(items.Count);
        var flattened = new List<FlattenedItem>();
        foreach (var item in items)
        {
            token.ThrowIfCancellationRequested();
            await FlattenAsync(TransferDirection.RemoteToLocal, item, _exportTempDir, flattened, token).ConfigureAwait(false);
        }

        foreach (var file in flattened)
        {
            token.ThrowIfCancellationRequested();
            Directory.CreateDirectory(Path.GetDirectoryName(file.DestinationPath)!);
            var row = new TransferItemViewModel(file.RelativeName, TransferDirection.RemoteToLocal, file.IncomingSize ?? 0, token);
            if (!AddToTransfers(row))
            {
                row.DisposeToken();
                continue;
            }
            try
            {
                MutateRowOnUi(row, r => r.State = TransferState.Running);
                await TransferOneAsync(TransferDirection.RemoteToLocal, file, row, row.Token).ConfigureAwait(false);
                MutateRowOnUi(row, r =>
                {
                    r.State = TransferState.Completed;
                    r.BytesTransferred = r.ExpectedBytes;
                });
            }
            catch (OperationCanceledException)
            {
                MutateRowOnUi(row, r => r.State = TransferState.Cancelled);
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Drag-out staging failed for {Path}.", file.SourcePath);
                MutateRowOnUi(row, r => { r.State = TransferState.Failed; r.ErrorMessage = ex.Message; });
                throw;
            }
            finally
            {
                row.DisposeToken();
            }
        }

        // Return the top-level paths the OS DataPackage should reference — for a
        // directory the StorageItem is the root directory in temp, not every flat file.
        foreach (var item in items)
        {
            staged.Add(Path.Combine(_exportTempDir!, item.Name));
        }
        return staged;
    }

    // === flattening ===========================================================

    private readonly record struct FlattenedItem(
        string SourcePath,
        string DestinationPath,
        string RelativeName,
        long? IncomingSize,
        bool SourceIsLocal);

    private async Task FlattenAsync(TransferDirection direction, TransferItem item, string destDir, List<FlattenedItem> acc, CancellationToken token)
    {
        bool sourceIsLocal = direction == TransferDirection.LocalToRemote;
        if (!item.IsDirectory)
        {
            long? size = sourceIsLocal ? SafeFileLength(item.SourcePath) : await SafeRemoteSizeAsync(item.SourcePath, token).ConfigureAwait(false);
            // destDir always belongs to the destination side: POSIX for LocalToRemote,
            // Win32 for RemoteToLocal. Picking the wrong joiner here would silently
            // corrupt the path (e.g. backslashes in a remote SFTP write).
            var dest = sourceIsLocal
                ? Services.Sftp.RemotePath.Join(destDir, item.Name)
                : Path.Combine(destDir, item.Name);
            acc.Add(new FlattenedItem(item.SourcePath, dest, item.Name, size, sourceIsLocal));
            return;
        }

        // Directory: walk it and append every leaf with its relative-from-root name.
        if (sourceIsLocal)
        {
            foreach (var fi in new DirectoryInfo(item.SourcePath).EnumerateFiles("*", SearchOption.AllDirectories))
            {
                token.ThrowIfCancellationRequested();
                var rel = Path.GetRelativePath(item.SourcePath, fi.FullName);
                var destRel = item.Name + "/" + rel.Replace(Path.DirectorySeparatorChar, '/');
                var dest = direction == TransferDirection.LocalToRemote
                    ? Services.Sftp.RemotePath.Join(destDir, destRel)
                    : Path.Combine(destDir, destRel.Replace('/', Path.DirectorySeparatorChar));
                acc.Add(new FlattenedItem(fi.FullName, dest, destRel, fi.Length, SourceIsLocal: true));
            }
        }
        else
        {
            await WalkRemoteAsync(item.SourcePath, item.Name, destDir, direction, acc, token).ConfigureAwait(false);
        }
    }

    private async Task WalkRemoteAsync(string remoteRoot, string relRoot, string destDir, TransferDirection direction, List<FlattenedItem> acc, CancellationToken token)
    {
        // ONE ListDirectory call per level holds the gate; recursion happens OUTSIDE
        // the lock. The original code wrapped the entire foreach (including recursive
        // WalkRemoteAsync calls) in a single RunSerializedAsync, which deadlocked on
        // any nested directory because SemaphoreSlim(1,1) is not re-entrant.
        IReadOnlyList<SftpEntry> entries = null!;
        await RunSerializedAsync(async () =>
        {
            entries = await Session.ListDirectoryAsync(remoteRoot, token).ConfigureAwait(false);
        }).ConfigureAwait(false);

        foreach (var e in entries)
        {
            token.ThrowIfCancellationRequested();
            // Defense against malicious / compromised SFTP servers: a server-returned
            // Name containing '/', '\\', or ".." would let Path.Combine on the
            // RemoteToLocal side escape the user's chosen destination and write into
            // arbitrary local paths (e.g. the Startup folder). Reject and log.
            if (!IsSafeRemoteName(e.Name))
            {
                _logger.LogWarning("Skipping remote entry with unsafe name in {Root}: {Name}", remoteRoot, e.Name);
                continue;
            }
            var childRel = relRoot + "/" + e.Name;
            if (e.IsDirectory && !e.IsSymbolicLink)
            {
                await WalkRemoteAsync(e.FullPath, childRel, destDir, direction, acc, token).ConfigureAwait(false);
            }
            else
            {
                var dest = direction == TransferDirection.RemoteToLocal
                    ? Path.Combine(destDir, childRel.Replace('/', Path.DirectorySeparatorChar))
                    : Services.Sftp.RemotePath.Join(destDir, childRel);
                acc.Add(new FlattenedItem(e.FullPath, dest, childRel, e.Size, SourceIsLocal: false));
            }
        }
    }

    /// <summary>
    /// Names from a remote directory listing must be single POSIX segments. Anything
    /// containing a path separator (forward OR backward — servers occasionally return
    /// Windows-style on misconfigured platforms), a colon, a NUL, or ".."/"." gets
    /// rejected to prevent local-side path-traversal during RemoteToLocal transfers.
    /// </summary>
    private static bool IsSafeRemoteName(string name)
    {
        if (string.IsNullOrEmpty(name)) return false;
        if (name == "." || name == "..") return false;
        foreach (var c in name)
        {
            if (c == '/' || c == '\\' || c == ':' || c == '\0') return false;
        }
        return true;
    }

    // === one-file transfer ====================================================

    private async Task TransferOneAsync(TransferDirection direction, FlattenedItem file, TransferItemViewModel row, CancellationToken token)
    {
        // Progress<T> captures SynchronizationContext.Current at CONSTRUCTION; by the
        // time TransferOneAsync runs, EnqueueAsync has crossed multiple
        // ConfigureAwait(false) hops and the context is the thread pool's null one.
        // Build a custom IProgress that dispatches via the captured UI dispatcher so
        // BytesTransferred mutations (and the downstream PropertyChanged for the bound
        // ProgressBar) land on the UI thread.
        IProgress<long> progress = new DispatchedProgress(_uiDispatcher, b => row.BytesTransferred = b);

        if (direction == TransferDirection.LocalToRemote)
        {
            await using var src = new FileStream(file.SourcePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            await RunSerializedAsync(() => Session.UploadAsync(src, file.DestinationPath, progress, token)).ConfigureAwait(false);
        }
        else if (direction == TransferDirection.RemoteToLocal)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(file.DestinationPath)!);
            await using var dst = new FileStream(file.DestinationPath, FileMode.Create, FileAccess.Write, FileShare.None);
            await RunSerializedAsync(() => Session.DownloadAsync(file.SourcePath, dst, progress, token)).ConfigureAwait(false);
        }
        else
        {
            throw new NotSupportedException($"Same-pane transfer ({direction}) is not supported.");
        }
    }

    // === destination probes ===================================================

    private async Task<bool> DestinationExistsAsync(TransferDirection direction, string destination, CancellationToken token)
    {
        if (direction == TransferDirection.LocalToRemote)
        {
            bool exists = false;
            await RunSerializedAsync(async () => exists = await Session.ExistsAsync(destination, token).ConfigureAwait(false)).ConfigureAwait(false);
            return exists;
        }
        return File.Exists(destination) || Directory.Exists(destination);
    }

    private async Task<long?> GetSizeAsync(TransferDirection direction, string path, CancellationToken token)
    {
        if (direction == TransferDirection.LocalToRemote)
        {
            SftpEntry? entry = null;
            await RunSerializedAsync(async () => entry = await Session.GetAttributesAsync(path, token).ConfigureAwait(false)).ConfigureAwait(false);
            return entry?.IsDirectory == true ? null : entry?.Size;
        }
        return SafeFileLength(path);
    }

    private async Task EnsureDestinationParentAsync(TransferDirection direction, string destination, CancellationToken token)
    {
        if (direction == TransferDirection.LocalToRemote)
        {
            var parent = Services.Sftp.RemotePath.Parent(destination);
            if (string.IsNullOrEmpty(parent) || parent == "/") return;
            await RunSerializedAsync(async () =>
            {
                if (!await Session.ExistsAsync(parent, token).ConfigureAwait(false))
                {
                    // Recursive mkdir: walk up to find the deepest existing ancestor,
                    // then create down. Servers vary on whether mkdir -p is supported
                    // via SFTP — we do it ourselves.
                    var stack = new Stack<string>();
                    var p = parent;
                    while (!string.IsNullOrEmpty(p) && p != "/" && !await Session.ExistsAsync(p, token).ConfigureAwait(false))
                    {
                        stack.Push(p);
                        p = Services.Sftp.RemotePath.Parent(p);
                    }
                    while (stack.Count > 0)
                    {
                        await Session.CreateDirectoryAsync(stack.Pop(), token).ConfigureAwait(false);
                    }
                }
            }).ConfigureAwait(false);
        }
        else
        {
            var parent = Path.GetDirectoryName(destination);
            if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);
        }
    }

    // === helpers ==============================================================

    private static long? SafeFileLength(string path)
    {
        try { return new FileInfo(path).Length; }
        catch { return null; }
    }

    private async Task<long?> SafeRemoteSizeAsync(string path, CancellationToken token)
    {
        SftpEntry? e = null;
        try
        {
            await RunSerializedAsync(async () => e = await Session.GetAttributesAsync(path, token).ConfigureAwait(false)).ConfigureAwait(false);
        }
        catch { return null; }
        return e?.IsDirectory == true ? null : e?.Size;
    }

    /// <summary>
    /// Try to add a row to the UI-bound Transfers collection. Returns false if the
    /// dispatcher refused to enqueue (shutdown in progress); the caller must skip the
    /// rest of the loop iteration in that case — do NOT proceed to read row.Token or
    /// MutateRowOnUi(row, ...) because (a) the row isn't visible anyway and (b) MutateRowOnUi
    /// would also be dropped. The row's CTS is NOT disposed here so a still-in-flight
    /// transfer (if any) can finish naturally; the GC reclaims the unobserved row.
    /// </summary>
    private bool AddToTransfers(TransferItemViewModel row)
    {
        if (_uiDispatcher is null) { Transfers.Add(row); return true; }
        if (_uiDispatcher.TryEnqueue(() => Transfers.Add(row))) return true;
        _logger.LogDebug("Dispatcher refused enqueue for new transfer row; skipping.");
        return false;
    }

    /// <summary>
    /// Marshal a ConflictResolver invocation back to the UI dispatcher so the resolver
    /// is free to construct WinUI controls (ContentDialog, etc.). If no dispatcher was
    /// captured (test path), call inline.
    /// </summary>
    private async Task<(ConflictDecision Decision, bool ApplyToAll)> InvokeResolverOnUiAsync(
        ConflictResolver resolver, ConflictContext ctx, CancellationToken token)
    {
        if (_uiDispatcher is null || _uiDispatcher.HasThreadAccess)
        {
            return await resolver(ctx, token).ConfigureAwait(false);
        }
        var tcs = new TaskCompletionSource<(ConflictDecision, bool)>(TaskCreationOptions.RunContinuationsAsynchronously);

        // Register cancellation on the linked token so a dialog tear-down that drops
        // the queued lambda before it runs unwedges this wait — otherwise we'd sit on
        // tcs.Task forever while the orchestrator's outer SemaphoreSlim stays held.
        using var ctReg = token.Register(() => tcs.TrySetResult((ConflictDecision.Skip, false)));

        if (!_uiDispatcher.TryEnqueue(async () =>
        {
            try
            {
                var result = await resolver(ctx, token).ConfigureAwait(true);
                tcs.TrySetResult(result);
            }
            catch (OperationCanceledException) { tcs.TrySetResult((ConflictDecision.Skip, false)); }
            catch (Exception ex) { tcs.TrySetException(ex); }
        }))
        {
            // Dispatcher gone — treat as Skip so the batch falls through cleanly.
            return (ConflictDecision.Skip, false);
        }
        return await tcs.Task.ConfigureAwait(false);
    }

    /// <summary>
    /// IProgress<long> that posts its callback onto the captured UI dispatcher. SSH.NET
    /// fires the upload/download callback synchronously on its I/O thread; without this
    /// wrapper the bound ProgressBar would receive a cross-thread PropertyChanged.
    /// Dropped reports (TryEnqueue refused during shutdown) are intentional: the
    /// transfer's final-state mutation in EnqueueAsync snaps BytesTransferred to
    /// ExpectedBytes at completion, so the only consequence of a missed mid-stream
    /// report is a slightly less smooth progress animation.
    /// </summary>
    private sealed class DispatchedProgress : IProgress<long>
    {
        private readonly DispatcherQueue? _dispatcher;
        private readonly Action<long> _onReport;

        public DispatchedProgress(DispatcherQueue? dispatcher, Action<long> onReport)
        {
            _dispatcher = dispatcher;
            _onReport = onReport;
        }

        public void Report(long value)
        {
            // Test context (no dispatcher captured): invoke inline so the orchestrator
            // tests can observe progress. Production: marshal to UI.
            if (_dispatcher is null) { _onReport(value); return; }
            if (_dispatcher.HasThreadAccess) { _onReport(value); return; }
            // Ignore the TryEnqueue bool: dropping a single progress tick during teardown
            // is the desired behavior. Logging here would spam the dropped-tick rate.
            _dispatcher.TryEnqueue(() => _onReport(value));
        }
    }

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposed) != 0) throw new ObjectDisposedException(nameof(FileTransferOrchestrator));
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        try { _shutdown.Cancel(); } catch { /* already disposed */ }

        // Snapshot before iterating: a background completion can still post
        // AddToTransfers via TryEnqueue, and iterating live would race with the add.
        TransferItemViewModel[] rowsSnapshot;
        try { rowsSnapshot = Transfers.ToArray(); }
        catch { rowsSnapshot = Array.Empty<TransferItemViewModel>(); }
        foreach (var row in rowsSnapshot) row.DisposeToken();

        // Coordinate with the SFTP gate before disposing the session: SSH.NET's
        // SftpClient is not thread-safe, and Session.DisposeAsync calls Disconnect()
        // + Dispose() on a worker thread. If we tear down while a ListDirectory is
        // mid-call inside another worker, the two collide. Acquire the gate with a
        // short timeout (don't wait forever — a hung remote call would block close).
        // If we can't acquire, dispose anyway and accept the race; better a transient
        // exception than a hung dialog.
        var acquiredGate = false;
        try
        {
            acquiredGate = await _gate.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
        }
        catch { /* gate may be disposed by a future change; ignore */ }
        try
        {
            await Session.DisposeAsync().ConfigureAwait(false);
        }
        catch (Exception ex) { _logger.LogWarning(ex, "Error disposing SFTP session."); }
        finally
        {
            if (acquiredGate) { try { _gate.Release(); } catch { /* idempotent */ } }
        }

        if (_exportTempDir is not null)
        {
            try { Directory.Delete(_exportTempDir, recursive: true); }
            catch (Exception ex) { _logger.LogWarning(ex, "Could not clean drag-out temp dir {Dir}.", _exportTempDir); }
        }

        // Intentionally NOT calling _gate.Dispose(): an in-flight RunSerializedAsync
        // caller still needs to Release() the gate in its finally, and Release on a
        // disposed SemaphoreSlim throws ObjectDisposedException into an unobserved
        // task. SemaphoreSlim doesn't hold an OS handle when its AvailableWaitHandle
        // hasn't been touched (which we never do), so finalization is harmless.
        // _shutdown is also kept alive — _shutdown.Token may be linked into outstanding
        // CTSes the rows hold; disposing it underneath them risks ObjectDisposedException
        // on token check. GC will reclaim once references drop.
    }

    /// <summary>
    /// Set a row's observable state from any thread, marshaling through the captured
    /// dispatcher when necessary. Mutating <see cref="TransferItemViewModel"/>'s
    /// observable properties from a worker thread otherwise pushes a non-UI-thread
    /// PropertyChanged at any UI binding (ProgressBar, status text).
    /// </summary>
    private void MutateRowOnUi(TransferItemViewModel row, Action<TransferItemViewModel> mutate)
    {
        if (_uiDispatcher is null || _uiDispatcher.HasThreadAccess) { mutate(row); return; }
        // When TryEnqueue refuses (dispatcher tearing down), DROP the mutation rather
        // than applying it inline on the worker thread. Inline would re-introduce the
        // cross-thread PropertyChanged that AddToTransfers' fix already avoids. The row
        // is closing-time-only state anyway; nothing watches a Completed/Failed/Cancelled
        // transition during dialog close.
        if (!_uiDispatcher.TryEnqueue(() => mutate(row)))
        {
            _logger.LogDebug("Dispatcher refused row mutation during teardown; dropping.");
        }
    }
}
