using System.Collections.Concurrent;
using System.IO;
using Wormhole.Services;

namespace Wormhole.Tests.Fakes;

/// <summary>
/// In-memory <see cref="ISftpSession"/> for tests. Files live in a thread-safe dictionary
/// keyed by POSIX path; directories are tracked separately. Sufficient for orchestrator
/// and pane tests — does NOT simulate latency, partial writes, or permission errors.
/// </summary>
public sealed class FakeSftpSession : ISftpSession
{
    public ConcurrentDictionary<string, byte[]> Files { get; } = new();
    public ConcurrentDictionary<string, bool> Directories { get; } = new();
    public int DisposeCount { get; private set; }

    /// <summary>Counts how many SFTP calls are "in flight" at once. The orchestrator
    /// holds a SemaphoreSlim(1,1); this value must never exceed 1 in those tests.</summary>
    public int MaxConcurrency { get; private set; }
    private int _concurrency;

    public FakeSftpSession(string workingDirectory = "/home/user")
    {
        WorkingDirectory = workingDirectory;
        Directories[workingDirectory] = true;
        Directories["/"] = true;
    }

    public string WorkingDirectory { get; }
    public string? HostFingerprint { get; init; } = "SHA256:fake";

    private IDisposable Enter()
    {
        var n = Interlocked.Increment(ref _concurrency);
        if (n > MaxConcurrency) MaxConcurrency = n;
        return new Token(this);
    }

    private sealed class Token : IDisposable
    {
        private readonly FakeSftpSession _owner;
        public Token(FakeSftpSession o) { _owner = o; }
        public void Dispose() => Interlocked.Decrement(ref _owner._concurrency);
    }

    public Task<IReadOnlyList<SftpEntry>> ListDirectoryAsync(string path, CancellationToken cancellationToken = default)
    {
        using var guard = Enter();
        var entries = new List<SftpEntry>();
        var prefix = path.EndsWith('/') ? path : path + "/";
        foreach (var d in Directories.Keys)
        {
            if (d == path || d == "/") continue;
            if (!d.StartsWith(prefix, StringComparison.Ordinal)) continue;
            var rest = d.Substring(prefix.Length);
            if (rest.Contains('/')) continue;
            entries.Add(new SftpEntry(rest, d, true, false, 0, DateTime.UtcNow, 0));
        }
        foreach (var f in Files.Keys)
        {
            if (!f.StartsWith(prefix, StringComparison.Ordinal)) continue;
            var rest = f.Substring(prefix.Length);
            if (rest.Contains('/')) continue;
            entries.Add(new SftpEntry(rest, f, false, false, Files[f].Length, DateTime.UtcNow, 0));
        }
        return Task.FromResult<IReadOnlyList<SftpEntry>>(entries);
    }

    public Task<SftpEntry?> GetAttributesAsync(string path, CancellationToken cancellationToken = default)
    {
        using var guard = Enter();
        if (Directories.ContainsKey(path))
            return Task.FromResult<SftpEntry?>(new SftpEntry(LeafName(path), path, true, false, 0, DateTime.UtcNow, 0));
        if (Files.TryGetValue(path, out var bytes))
            return Task.FromResult<SftpEntry?>(new SftpEntry(LeafName(path), path, false, false, bytes.Length, DateTime.UtcNow, 0));
        return Task.FromResult<SftpEntry?>(null);
    }

    public Task<bool> ExistsAsync(string path, CancellationToken cancellationToken = default)
    {
        using var guard = Enter();
        return Task.FromResult(Directories.ContainsKey(path) || Files.ContainsKey(path));
    }

    public async Task UploadAsync(Stream source, string remotePath, IProgress<long>? progress, CancellationToken cancellationToken = default)
    {
        using var guard = Enter();
        using var ms = new MemoryStream();
        await source.CopyToAsync(ms, cancellationToken).ConfigureAwait(false);
        Files[remotePath] = ms.ToArray();
        progress?.Report(ms.Length);
    }

    public Task DownloadAsync(string remotePath, Stream destination, IProgress<long>? progress, CancellationToken cancellationToken = default)
    {
        using var guard = Enter();
        if (!Files.TryGetValue(remotePath, out var bytes))
            throw new FileNotFoundException(remotePath);
        destination.Write(bytes, 0, bytes.Length);
        progress?.Report(bytes.Length);
        return Task.CompletedTask;
    }

    public Task CreateDirectoryAsync(string remotePath, CancellationToken cancellationToken = default)
    {
        using var guard = Enter();
        Directories[remotePath] = true;
        return Task.CompletedTask;
    }

    public Task CreateEmptyFileAsync(string remotePath, CancellationToken cancellationToken = default)
    {
        using var guard = Enter();
        Files[remotePath] = Array.Empty<byte>();
        return Task.CompletedTask;
    }

    public Task DeleteFileAsync(string remotePath, CancellationToken cancellationToken = default)
    {
        using var guard = Enter();
        Files.TryRemove(remotePath, out _);
        return Task.CompletedTask;
    }

    public Task DeleteDirectoryAsync(string remotePath, bool recursive, CancellationToken cancellationToken = default)
    {
        using var guard = Enter();
        if (recursive)
        {
            var prefix = remotePath.EndsWith('/') ? remotePath : remotePath + "/";
            foreach (var f in Files.Keys.Where(k => k.StartsWith(prefix, StringComparison.Ordinal)).ToList()) Files.TryRemove(f, out _);
            foreach (var d in Directories.Keys.Where(k => k.StartsWith(prefix, StringComparison.Ordinal)).ToList()) Directories.TryRemove(d, out _);
        }
        Directories.TryRemove(remotePath, out _);
        return Task.CompletedTask;
    }

    public Task RenameAsync(string oldPath, string newPath, CancellationToken cancellationToken = default)
    {
        using var guard = Enter();
        if (Files.TryRemove(oldPath, out var bytes)) Files[newPath] = bytes;
        else if (Directories.TryRemove(oldPath, out _)) Directories[newPath] = true;
        return Task.CompletedTask;
    }

    public ValueTask DisposeAsync()
    {
        DisposeCount++;
        return ValueTask.CompletedTask;
    }

    private static string LeafName(string path)
    {
        var i = path.LastIndexOf('/');
        return i < 0 ? path : path.Substring(i + 1);
    }
}
