using Microsoft.Extensions.Logging;
using Renci.SshNet;
using Renci.SshNet.Sftp;
using Wormhole.Services.Sftp;

namespace Wormhole.Services.Ssh;

internal sealed class SftpSession : ISftpSession
{
    private readonly SftpClient _client;
    private readonly ILogger<SftpSession> _logger;
    private int _disposed;

    public SftpSession(SftpClient client, string? hostFingerprint, ILogger<SftpSession> logger)
    {
        _client = client;
        _logger = logger;
        HostFingerprint = hostFingerprint;
        // Cache once — SftpClient's WorkingDirectory hits the network on read in some
        // SSH.NET versions; freeze at connect time for predictable "go home" behavior.
        WorkingDirectory = SafeReadWorkingDirectory(client);
    }

    public string WorkingDirectory { get; }
    public string? HostFingerprint { get; }

    private bool IsDisposed => Volatile.Read(ref _disposed) != 0;

    public Task<IReadOnlyList<SftpEntry>> ListDirectoryAsync(string path, CancellationToken cancellationToken = default) =>
        RunAsync(() =>
        {
            var entries = new List<SftpEntry>();
            foreach (var file in _client.ListDirectory(path))
            {
                // Self/parent entries are noisy in a two-pane browser; the pane VM
                // navigates via a dedicated "up" button instead.
                if (file.Name == "." || file.Name == "..") continue;
                // Defense against malicious / compromised servers: a Name containing a
                // path separator or NUL would let downstream Path.Combine escape the
                // user's chosen local destination on drag-out. Skip and log. Real-world
                // POSIX filenames may legally contain '\\' but the false-positive rate
                // there is acceptable next to the security upside.
                if (!IsSafeRemoteName(file.Name))
                {
                    _logger.LogWarning("Skipping remote entry with unsafe name in {Path}: {Name}", path, file.Name);
                    continue;
                }
                entries.Add(ToEntry(file));
            }
            return (IReadOnlyList<SftpEntry>)entries;
        }, cancellationToken);

    // Filter aligned with FileTransferOrchestrator.IsSafeRemoteName so a name that
    // passes this gate is also accepted by downstream Path.Combine on the local side.
    // Rejects '/' '\\' '\0' (path separators / NUL) and ':' which on NTFS is the
    // alternate-data-stream sigil — a server-supplied name like "notes:hidden" would
    // otherwise let the orchestrator's Path.Combine build a path that refers to an ADS
    // on the user's drag-out temp dir. Also rejects "." / "..": even though
    // ListDirectory's own filter at line 37 strips the literal entries, a name like
    // ".." with trailing whitespace from a buggy/malicious server would slip past.
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

    public Task<SftpEntry?> GetAttributesAsync(string path, CancellationToken cancellationToken = default) =>
        RunAsync(() =>
        {
            try
            {
                var file = _client.Get(path);
                return (SftpEntry?)ToEntry(file);
            }
            catch (Renci.SshNet.Common.SftpPathNotFoundException)
            {
                return null;
            }
        }, cancellationToken);

    public Task<bool> ExistsAsync(string path, CancellationToken cancellationToken = default) =>
        RunAsync(() => _client.Exists(path), cancellationToken);

    public Task UploadAsync(Stream source, string remotePath, IProgress<long>? progress, CancellationToken cancellationToken = default) =>
        RunAsync(() =>
        {
            // UploadFile's callback fires with the cumulative byte count. Wrap once;
            // SSH.NET catches subscriber exceptions but treats them as transfer errors.
            Action<ulong>? cb = progress is null ? null : total =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                progress.Report((long)total);
            };
            // canOverride: true so an existing file is replaced atomically by SSH.NET's
            // SFTP layer. The orchestrator already prompted for overwrite confirmation
            // before this point — re-checking here would race anyway. The two-/three-arg
            // UploadFile overloads default canOverride to false, which raises
            // SftpPermissionDeniedException on any path that already exists — confirmed
            // overwrites would otherwise be marked Failed in the queue.
            if (cb is null) _client.UploadFile(source, remotePath, canOverride: true);
            else _client.UploadFile(source, remotePath, canOverride: true, uploadCallback: cb);
        }, cancellationToken);

    public Task DownloadAsync(string remotePath, Stream destination, IProgress<long>? progress, CancellationToken cancellationToken = default) =>
        RunAsync(() =>
        {
            Action<ulong>? cb = progress is null ? null : total =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                progress.Report((long)total);
            };
            if (cb is null) _client.DownloadFile(remotePath, destination);
            else _client.DownloadFile(remotePath, destination, cb);
        }, cancellationToken);

    public Task CreateDirectoryAsync(string remotePath, CancellationToken cancellationToken = default) =>
        RunAsync(() => _client.CreateDirectory(remotePath), cancellationToken);

    public Task CreateEmptyFileAsync(string remotePath, CancellationToken cancellationToken = default) =>
        RunAsync(() =>
        {
            // SftpClient.Create opens a new file for writing; Dispose closes it leaving
            // a zero-byte file. UploadFile with Stream.Null would work too but does an
            // extra round-trip.
            using var s = _client.Create(remotePath);
        }, cancellationToken);

    public Task DeleteFileAsync(string remotePath, CancellationToken cancellationToken = default) =>
        RunAsync(() => _client.DeleteFile(remotePath), cancellationToken);

    public Task DeleteDirectoryAsync(string remotePath, bool recursive, CancellationToken cancellationToken = default) =>
        RunAsync(() =>
        {
            if (!recursive)
            {
                _client.DeleteDirectory(remotePath);
                return;
            }

            // SFTP has no native recursive delete — walk manually. The orchestrator
            // already serializes calls via SemaphoreSlim, so nested ListDirectory/Delete
            // inside this lambda runs single-threaded against the same client. Pass
            // the CT so a huge tree can be aborted between entries rather than running
            // to completion regardless of user cancel.
            DeleteRecursive(remotePath, cancellationToken);
        }, cancellationToken);

    public Task RenameAsync(string oldPath, string newPath, CancellationToken cancellationToken = default) =>
        RunAsync(() => _client.RenameFile(oldPath, newPath), cancellationToken);

    private void DeleteRecursive(string remotePath, CancellationToken cancellationToken)
    {
        foreach (var file in _client.ListDirectory(remotePath))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (file.Name == "." || file.Name == "..") continue;
            var childPath = RemotePath.Join(remotePath, file.Name);
            if (file.IsDirectory && !file.IsSymbolicLink)
            {
                DeleteRecursive(childPath, cancellationToken);
            }
            else
            {
                _client.DeleteFile(childPath);
            }
        }
        _client.DeleteDirectory(remotePath);
    }

    // Removed the previous `Task.Run(action, ct).WaitAsync(ct)` form: WaitAsync would
    // return to the caller on cancel but leave the inner action still running on the
    // thread pool, holding _client. The orchestrator's outer SemaphoreSlim.Release()
    // would then fire while a now-orphaned worker continued to issue SSH.NET calls on
    // the same SftpClient (which is NOT thread-safe). The next serialized op would race
    // against the orphan and corrupt the channel.
    //
    // The current form awaits the Task to its natural completion. Cancellation for
    // Upload/Download is honored mid-stream via the progress callback that throws
    // OperationCanceledException — the action's exception propagates out cleanly with
    // no orphaned worker. ListDirectory / Rename / DeleteRecursive have a coarser
    // cancellation surface (between iterations for DeleteRecursive; not at all for
    // the others) but the gate is reliably released only after the worker is done.
    private async Task RunAsync(Action action, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(IsDisposed, this);
        await Task.Run(action, cancellationToken).ConfigureAwait(false);
    }

    private async Task<T> RunAsync<T>(Func<T> action, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(IsDisposed, this);
        return await Task.Run(action, cancellationToken).ConfigureAwait(false);
    }

    private static SftpEntry ToEntry(ISftpFile file)
    {
        var perms = 0;
        try
        {
            // Attributes.Permissions on SSH.NET is a struct that decomposes the octal mode;
            // OthersCanRead etc are bools. Reconstruct the standard Unix nine-bit mode so
            // the UI layer can render rwxrwxrwx without depending on SSH.NET types.
            var a = file.Attributes;
            if (a.OwnerCanRead) perms |= 0b100_000_000;
            if (a.OwnerCanWrite) perms |= 0b010_000_000;
            if (a.OwnerCanExecute) perms |= 0b001_000_000;
            if (a.GroupCanRead) perms |= 0b000_100_000;
            if (a.GroupCanWrite) perms |= 0b000_010_000;
            if (a.GroupCanExecute) perms |= 0b000_001_000;
            if (a.OthersCanRead) perms |= 0b000_000_100;
            if (a.OthersCanWrite) perms |= 0b000_000_010;
            if (a.OthersCanExecute) perms |= 0b000_000_001;
        }
        catch { /* permissions optional */ }

        return new SftpEntry(
            Name: file.Name,
            FullPath: file.FullName,
            IsDirectory: file.IsDirectory,
            IsSymbolicLink: file.IsSymbolicLink,
            Size: file.IsDirectory ? 0 : file.Length,
            LastModifiedUtc: file.LastWriteTimeUtc,
            PermissionBits: perms);
    }

    private static string SafeReadWorkingDirectory(SftpClient client)
    {
        try { return client.WorkingDirectory ?? "/"; }
        catch { return "/"; }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        try
        {
            await Task.Run(() =>
            {
                if (_client.IsConnected) _client.Disconnect();
                _client.Dispose();
            }).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error disposing SFTP client.");
        }
    }
}
