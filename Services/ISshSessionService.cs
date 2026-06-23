using Wormhole.Models;
using Wormhole.Services.Ssh;
using Wormhole.Services.Tunneling;

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
        ITunnelInstance? tunnel = null,
        CancellationToken cancellationToken = default);
}

public interface ITerminalSession : IAsyncDisposable
{
    /// <summary>
    /// Raised synchronously from the terminal read pump with the bytes just read.
    /// The memory is valid only for the duration of the event callback; subscribers that need
    /// to retain data must copy it before returning.
    /// </summary>
    event EventHandler<ReadOnlyMemory<byte>>? DataReceived;
    /// <summary>
    /// Raised once when the underlying terminal stream closes — distinct from disposal initiated by the consumer. Fires from a
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

    /// <summary>
    /// Pauses the background read pump: it holds before the next read until <see cref="ResumeReading"/>
    /// is called. Used for terminal flow control so a torrential remote producer (e.g. a flooding
    /// <c>tcpdump</c>) can't outrun xterm.js and overflow its write buffer — not reading lets the SSH
    /// channel window fill, which back-pressures the remote. Writes (keystrokes) are unaffected, so the
    /// user can still send Ctrl+C to stop the flood. Idempotent and safe to call from any thread.
    /// </summary>
    void PauseReading();

    /// <summary>
    /// Resumes a pump previously parked by <see cref="PauseReading"/>. Idempotent and safe to call
    /// from any thread; a no-op if the pump is not paused.
    /// </summary>
    void ResumeReading();
}

public interface ISshSession : ITerminalSession
{
    string? HostFingerprint { get; }
}
