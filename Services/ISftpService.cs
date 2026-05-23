using Wormhole.Models;
using Wormhole.Services.Ssh;
using Wormhole.Services.Tunneling;

namespace Wormhole.Services;

public interface ISftpService
{
    Task<ISftpSession> ConnectAsync(
        ConnectionProfile profile,
        SshCredentials credentials,
        ITunnelInstance? tunnel = null,
        CancellationToken cancellationToken = default);
}

public interface ISftpSession : IAsyncDisposable
{
    /// <summary>The server-reported working directory at connect time. Use as the initial
    /// "home" path. POSIX, always starts with '/'.</summary>
    string WorkingDirectory { get; }

    /// <summary>SHA256 fingerprint of the SSH host key, captured at connect.</summary>
    string? HostFingerprint { get; }

    /// <summary>
    /// Whether the underlying SSH/SFTP transport is still believed to be alive. Used by
    /// callers that cache a session across time (the SFTP pre-warm) to detect a socket
    /// idle-eviction / server-side keepalive-exceed and fall back to a fresh connect
    /// instead of handing a dead session to the dialog. Cheap, non-blocking.
    /// </summary>
    bool IsConnected { get; }

    Task<IReadOnlyList<SftpEntry>> ListDirectoryAsync(string path, CancellationToken cancellationToken = default);
    Task<SftpEntry?> GetAttributesAsync(string path, CancellationToken cancellationToken = default);
    Task<bool> ExistsAsync(string path, CancellationToken cancellationToken = default);

    Task UploadAsync(Stream source, string remotePath, IProgress<long>? progress, CancellationToken cancellationToken = default);
    Task DownloadAsync(string remotePath, Stream destination, IProgress<long>? progress, CancellationToken cancellationToken = default);

    Task CreateDirectoryAsync(string remotePath, CancellationToken cancellationToken = default);
    Task CreateEmptyFileAsync(string remotePath, CancellationToken cancellationToken = default);
    Task DeleteFileAsync(string remotePath, CancellationToken cancellationToken = default);
    Task DeleteDirectoryAsync(string remotePath, bool recursive, CancellationToken cancellationToken = default);
    Task RenameAsync(string oldPath, string newPath, CancellationToken cancellationToken = default);
}

public sealed record SftpEntry(
    string Name,
    string FullPath,
    bool IsDirectory,
    bool IsSymbolicLink,
    long Size,
    DateTime LastModifiedUtc,
    int PermissionBits);
