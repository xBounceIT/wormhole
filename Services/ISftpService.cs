using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Wormhole.Models;

namespace Wormhole.Services;

public interface ISftpService
{
    Task<ISftpSession> ConnectAsync(ConnectionProfile profile, string? password, byte[]? privateKey, CancellationToken cancellationToken = default);
}

public interface ISftpSession : IAsyncDisposable
{
    Task<IReadOnlyList<SftpEntry>> ListDirectoryAsync(string path, CancellationToken cancellationToken = default);
    Task UploadAsync(Stream source, string remotePath, IProgress<long>? progress, CancellationToken cancellationToken = default);
    Task DownloadAsync(string remotePath, Stream destination, IProgress<long>? progress, CancellationToken cancellationToken = default);
    Task DeleteAsync(string remotePath, CancellationToken cancellationToken = default);
}

public sealed record SftpEntry(string Name, string FullPath, bool IsDirectory, long Size, DateTime LastModifiedUtc);
