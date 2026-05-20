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
    /// <summary>
    /// Raised once when the underlying SSH stream closes (EOF, network drop, or remote
    /// shell exit) — distinct from disposal initiated by the consumer. Fires from a
    /// background thread; subscribers must marshal to the UI thread if they touch UI.
    /// </summary>
    event EventHandler? Closed;
    Task WriteAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default);
    Task ResizeAsync(uint columns, uint rows);
}
