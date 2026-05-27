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
/// session state.
/// </summary>
public sealed class FileTransferOrchestrator : IFileTransferOrchestrator
{
    private const int TransferBufferSize = 128 * 1024;

    private readonly ILogger<FileTransferOrchestrator> _logger;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly CancellationTokenSource _shutdown = new();
    private readonly DispatcherQueue? _uiDispatcher;
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

        var ensuredRemoteDirectories = new HashSet<string>(StringComparer.Ordinal);
        var ensuredLocalDirectories = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var file in flattened)
        {
            token.ThrowIfCancellationRequested();

            if (file.IsDirectory)
            {
                // Directory entry: mkdir at destination so empty (or to-be-populated)
                // folders survive the trip. No conflict prompt (overwriting a directory
                // doesn't make sense in this UI) and no queue row (mkdir is too cheap to
                // surface). Non-directory descendants will see the dir already present
                // by the time their EnsureDestinationParentAsync runs.
                try
                {
                    await EnsureDestinationDirectoryAsync(
                        request.Direction,
                        file.DestinationPath,
                        ensuredRemoteDirectories,
                        ensuredLocalDirectories,
                        token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to create destination directory {Path}.", file.DestinationPath);
                }
                continue;
            }

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
            await EnsureDestinationParentAsync(
                request.Direction,
                file.DestinationPath,
                ensuredRemoteDirectories,
                ensuredLocalDirectories,
                token).ConfigureAwait(false);

            var row = new TransferItemViewModel(file.RelativeName, request.Direction, file.IncomingSize ?? 0, token, RemoveRow);
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

    // === flattening ===========================================================

    private readonly record struct FlattenedItem(
        string SourcePath,
        string DestinationPath,
        string RelativeName,
        long? IncomingSize,
        bool SourceIsLocal,
        bool IsDirectory);

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
            acc.Add(new FlattenedItem(item.SourcePath, dest, item.Name, size, sourceIsLocal, IsDirectory: false));
            return;
        }

        // Directory: walk it and emit every directory + file, each with its
        // relative-from-root name. Emitting the directories explicitly (not just files)
        // is what preserves empty subtrees: without their own entry, an empty folder
        // would never appear in the plan and silently vanish at the destination.
        // EnsureDestinationParentAsync would only create ancestors of files it sees.
        if (sourceIsLocal)
        {
            // Root directory of this drag — emit before children so it exists before
            // anything inside it lands. mkdir is idempotent in both EnsureDestinationDirectoryAsync
            // and System.IO.Directory.CreateDirectory, so duplicate emissions for the
            // same dir are safe.
            var rootDest = Services.Sftp.RemotePath.Join(destDir, item.Name);
            acc.Add(new FlattenedItem(item.SourcePath, rootDest, item.Name, IncomingSize: null, SourceIsLocal: true, IsDirectory: true));

            var root = new DirectoryInfo(item.SourcePath);
            var rootPrefixLength = GetChildPathPrefixLength(root.FullName);
            foreach (var entry in root.EnumerateFileSystemInfos("*", SearchOption.AllDirectories))
            {
                token.ThrowIfCancellationRequested();
                var destRel = JoinRemoteRootAndLocalRelative(item.Name, entry.FullName, rootPrefixLength);
                var dest = Services.Sftp.RemotePath.Join(destDir, destRel);
                if (entry is DirectoryInfo)
                {
                    acc.Add(new FlattenedItem(entry.FullName, dest, destRel, IncomingSize: null, SourceIsLocal: true, IsDirectory: true));
                }
                else if (entry is FileInfo fi)
                {
                    acc.Add(new FlattenedItem(entry.FullName, dest, destRel, fi.Length, SourceIsLocal: true, IsDirectory: false));
                }
            }
        }
        else
        {
            await WalkRemoteAsync(item.SourcePath, item.Name, destDir, direction, acc, token).ConfigureAwait(false);
        }
    }

    private async Task WalkRemoteAsync(string remoteRoot, string relRoot, string destDir, TransferDirection direction, List<FlattenedItem> acc, CancellationToken token)
    {
        // Emit this directory itself before listing its children, so empty remote
        // subtrees (no files in their descendants) are still represented in the plan
        // and the destination tree shape is preserved. Recursive calls below emit
        // their own directory entries the same way; the result is one entry per dir
        // in pre-order.
        var rootDest = direction == TransferDirection.RemoteToLocal
            ? JoinLocalRootAndRemoteRelative(destDir, relRoot)
            : Services.Sftp.RemotePath.Join(destDir, relRoot);
        acc.Add(new FlattenedItem(remoteRoot, rootDest, relRoot, IncomingSize: null, SourceIsLocal: false, IsDirectory: true));

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
                    ? JoinLocalRootAndRemoteRelative(destDir, childRel)
                    : Services.Sftp.RemotePath.Join(destDir, childRel);
                acc.Add(new FlattenedItem(e.FullPath, dest, childRel, e.Size, SourceIsLocal: false, IsDirectory: false));
            }
        }
    }

    private static int GetChildPathPrefixLength(string rootPath)
    {
        var trimmedLength = rootPath.Length;
        while (trimmedLength > 0 &&
               (rootPath[trimmedLength - 1] == Path.DirectorySeparatorChar ||
                rootPath[trimmedLength - 1] == Path.AltDirectorySeparatorChar))
        {
            trimmedLength--;
        }
        return trimmedLength + 1;
    }

    private static string JoinRemoteRootAndLocalRelative(
        string rootName,
        string childPath,
        int rootPrefixLength)
    {
        var relativeLength = Math.Max(0, childPath.Length - rootPrefixLength);
        var length = rootName.Length + 1 + relativeLength;
        return string.Create(length, (rootName, childPath, rootPrefixLength), static (destination, state) =>
        {
            state.rootName.AsSpan().CopyTo(destination);
            destination[state.rootName.Length] = Services.Sftp.RemotePath.Separator;
            var target = destination[(state.rootName.Length + 1)..];
            var child = state.rootPrefixLength < state.childPath.Length
                ? state.childPath.AsSpan(state.rootPrefixLength)
                : ReadOnlySpan<char>.Empty;
            for (var i = 0; i < child.Length; i++)
            {
                var ch = child[i];
                target[i] = ch == Path.DirectorySeparatorChar || ch == Path.AltDirectorySeparatorChar
                    ? Services.Sftp.RemotePath.Separator
                    : ch;
            }
        });
    }

    private static string JoinLocalRootAndRemoteRelative(string localRoot, string remoteRelative)
    {
        if (string.IsNullOrEmpty(localRoot))
            return RemoteRelativeToLocalPath(remoteRelative);

        var needsSeparator = !EndsInLocalDirectorySeparator(localRoot);
        var separatorLength = needsSeparator ? 1 : 0;
        return string.Create(localRoot.Length + separatorLength + remoteRelative.Length, (localRoot, remoteRelative, needsSeparator), static (destination, state) =>
        {
            state.localRoot.AsSpan().CopyTo(destination);
            var offset = state.localRoot.Length;
            if (state.needsSeparator)
            {
                destination[offset] = Path.DirectorySeparatorChar;
                offset++;
            }

            CopyRemoteRelativeAsLocal(state.remoteRelative, destination[offset..]);
        });
    }

    private static string RemoteRelativeToLocalPath(string remoteRelative) =>
        string.Create(remoteRelative.Length, remoteRelative, static (destination, source) =>
            CopyRemoteRelativeAsLocal(source, destination));

    private static void CopyRemoteRelativeAsLocal(ReadOnlySpan<char> remoteRelative, Span<char> destination)
    {
        for (var i = 0; i < remoteRelative.Length; i++)
        {
            destination[i] = remoteRelative[i] == Services.Sftp.RemotePath.Separator
                ? Path.DirectorySeparatorChar
                : remoteRelative[i];
        }
    }

    private static bool EndsInLocalDirectorySeparator(string path)
    {
        var last = path[^1];
        return last == Path.DirectorySeparatorChar || last == Path.AltDirectorySeparatorChar;
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
            await using var src = new FileStream(file.SourcePath, new FileStreamOptions
            {
                Mode = FileMode.Open,
                Access = FileAccess.Read,
                Share = FileShare.Read,
                BufferSize = TransferBufferSize,
                Options = FileOptions.Asynchronous | FileOptions.SequentialScan,
            });
            await RunSerializedAsync(() => Session.UploadAsync(src, file.DestinationPath, progress, token)).ConfigureAwait(false);
        }
        else if (direction == TransferDirection.RemoteToLocal)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(file.DestinationPath)!);
            await using var dst = new FileStream(file.DestinationPath, new FileStreamOptions
            {
                Mode = FileMode.Create,
                Access = FileAccess.Write,
                Share = FileShare.None,
                BufferSize = TransferBufferSize,
                Options = FileOptions.Asynchronous | FileOptions.SequentialScan,
            });
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

    private async Task EnsureDestinationParentAsync(
        TransferDirection direction,
        string destination,
        HashSet<string> ensuredRemoteDirectories,
        HashSet<string> ensuredLocalDirectories,
        CancellationToken token)
    {
        if (direction == TransferDirection.LocalToRemote)
        {
            var parent = Services.Sftp.RemotePath.Parent(destination);
            if (string.IsNullOrEmpty(parent) || parent == "/") return;
            await EnsureRemoteDirectoryAsync(parent, ensuredRemoteDirectories, token).ConfigureAwait(false);
        }
        else
        {
            var parent = Path.GetDirectoryName(destination);
            if (!string.IsNullOrEmpty(parent)) EnsureLocalDirectory(parent, ensuredLocalDirectories);
        }
    }

    /// <summary>
    /// Ensure a directory (not its parent) exists at the destination. Used by the
    /// directory-entry branch in the transfer loop so empty subtrees survive the
    /// copy. Idempotent on both sides: a path that already exists is a no-op.
    /// </summary>
    private async Task EnsureDestinationDirectoryAsync(
        TransferDirection direction,
        string destination,
        HashSet<string> ensuredRemoteDirectories,
        HashSet<string> ensuredLocalDirectories,
        CancellationToken token)
    {
        if (direction == TransferDirection.LocalToRemote)
        {
            if (string.IsNullOrEmpty(destination) || destination == "/") return;
            await EnsureRemoteDirectoryAsync(destination, ensuredRemoteDirectories, token).ConfigureAwait(false);
        }
        else
        {
            EnsureLocalDirectory(destination, ensuredLocalDirectories);
        }
    }

    /// <summary>
    /// Recursive mkdir on the remote side: walks up to find the deepest existing
    /// ancestor, then creates downward. Servers vary on whether SFTP exposes a
    /// native mkdir -p, so we do it ourselves under the session gate.
    /// </summary>
    private Task EnsureRemoteDirectoryAsync(
        string remotePath,
        HashSet<string> ensuredRemoteDirectories,
        CancellationToken token)
    {
        if (string.IsNullOrEmpty(remotePath) || remotePath == "/") return Task.CompletedTask;
        if (ensuredRemoteDirectories.Contains(remotePath)) return Task.CompletedTask;

        return EnsureRemoteDirectoryCoreAsync(remotePath, ensuredRemoteDirectories, token);
    }

    private Task EnsureRemoteDirectoryCoreAsync(
        string remotePath,
        HashSet<string> ensuredRemoteDirectories,
        CancellationToken token) =>
        RunSerializedAsync(async () =>
        {
            if (ensuredRemoteDirectories.Contains(remotePath)) return;

            var stack = new Stack<string>();
            var p = remotePath;
            while (!string.IsNullOrEmpty(p) && p != "/" && !ensuredRemoteDirectories.Contains(p))
            {
                if (await Session.ExistsAsync(p, token).ConfigureAwait(false))
                {
                    ensuredRemoteDirectories.Add(p);
                    break;
                }

                stack.Push(p);
                p = Services.Sftp.RemotePath.Parent(p);
            }
            while (stack.Count > 0)
            {
                var dir = stack.Pop();
                if (ensuredRemoteDirectories.Contains(dir)) continue;
                await Session.CreateDirectoryAsync(dir, token).ConfigureAwait(false);
                ensuredRemoteDirectories.Add(dir);
            }
        });

    private static void EnsureLocalDirectory(string path, HashSet<string> ensuredLocalDirectories)
    {
        if (ensuredLocalDirectories.Contains(path)) return;
        Directory.CreateDirectory(path);
        ensuredLocalDirectories.Add(path);
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
    /// Bound to each row as its remove-callback so clicking the X on the queue strip
    /// drops it from the UI collection regardless of state. Marshaled through the
    /// captured dispatcher because <see cref="ObservableCollection{T}.Remove"/> emits
    /// CollectionChanged synchronously and the bound ListView is UI-affine.
    /// </summary>
    private void RemoveRow(TransferItemViewModel row)
    {
        if (_uiDispatcher is null || _uiDispatcher.HasThreadAccess) { Transfers.Remove(row); return; }
        if (!_uiDispatcher.TryEnqueue(() => Transfers.Remove(row)))
        {
            _logger.LogDebug("Dispatcher refused row removal during teardown; dropping.");
        }
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
        private long _latestValue;
        private int _queued;

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
            Interlocked.Exchange(ref _latestValue, value);
            if (Interlocked.CompareExchange(ref _queued, 1, 0) != 0) return;
            // Ignore the TryEnqueue bool: dropping progress during teardown is the desired
            // behavior. Logging here would spam at the transfer callback rate.
            if (!_dispatcher.TryEnqueue(Drain))
            {
                Interlocked.Exchange(ref _queued, 0);
            }
        }

        private void Drain()
        {
            var value = Interlocked.Read(ref _latestValue);
            Interlocked.Exchange(ref _queued, 0);
            _onReport(value);

            if (Interlocked.Read(ref _latestValue) == value) return;
            if (Interlocked.CompareExchange(ref _queued, 1, 0) == 0)
            {
                if (_dispatcher?.TryEnqueue(Drain) != true)
                {
                    Interlocked.Exchange(ref _queued, 0);
                }
            }
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
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
        //
        // No "skip if row removed" guard: the orchestrator's snap-to-100% mutation
        // (BytesTransferred = ExpectedBytes) MUST land or the ProgressBar gets frozen
        // at the last reported byte count, which is typically a tick or two short of
        // the file size. A removed row receiving a stray PropertyChanged is harmless
        // (no live binding listens) — a snapped row that never reaches 100% is the
        // bug the user actually sees.
        if (!_uiDispatcher.TryEnqueue(() => mutate(row)))
        {
            _logger.LogDebug("Dispatcher refused row mutation during teardown; dropping.");
        }
    }
}
