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
    string? HostFingerprint { get; }

    event EventHandler<ReadOnlyMemory<byte>>? DataReceived;
    /// <summary>
    /// Raised once when the underlying SSH stream closes (EOF, network drop, or remote
    /// shell exit) — distinct from disposal initiated by the consumer. Fires from a
    /// background thread; subscribers must marshal to the UI thread if they touch UI.
    /// </summary>
    event EventHandler? Closed;
    /// <summary>
    /// Starts the background read pump. The session does NOT auto-start so consumers
    /// have a chance to subscribe to <see cref="DataReceived"/> and <see cref="Closed"/>
    /// before any events can fire — otherwise a server that closes immediately after
    /// auth (forced-command, EOF accounts) would race past unsubscribed handlers.
    /// Idempotent: a second call is a no-op.
    /// </summary>
    void Start();
    Task WriteAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default);
    Task ResizeAsync(uint columns, uint rows);
}
