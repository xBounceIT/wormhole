using System;
using System.Threading;
using System.Threading.Tasks;
using Wormhole.Models;

namespace Wormhole.Services;

public interface ISshSessionService
{
    Task<ISshSession> ConnectAsync(ConnectionProfile profile, string? password, byte[]? privateKey, CancellationToken cancellationToken = default);
}

public interface ISshSession : IAsyncDisposable
{
    event EventHandler<ReadOnlyMemory<byte>>? DataReceived;
    Task WriteAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default);
    Task ResizeAsync(uint columns, uint rows);
}
