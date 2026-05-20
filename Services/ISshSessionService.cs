using System;
using System.Threading;
using System.Threading.Tasks;
using Wormhole.Models;
using Wormhole.Services.Ssh;

namespace Wormhole.Services;

public readonly record struct TerminalSize(uint Columns, uint Rows)
{
    public static TerminalSize Default { get; } = new(80, 24);
}

public interface ISshSessionService
{
    Task<ISshSession> ConnectAsync(
        ConnectionProfile profile,
        SshCredentials credentials,
        TerminalSize initialSize,
        CancellationToken cancellationToken = default);
}

public interface ISshSession : IAsyncDisposable
{
    event EventHandler<ReadOnlyMemory<byte>>? DataReceived;
    Task WriteAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default);
    Task ResizeAsync(uint columns, uint rows);
}
