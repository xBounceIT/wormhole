using System;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Wormhole.Models;

namespace Wormhole.Services.Tunneling;

public interface ITunnelInstance : IAsyncDisposable
{
    TunnelState State { get; }
    event EventHandler<TunnelStateChangedEventArgs>? StateChanged;

    /// <summary>
    /// The tunnel's local SOCKS5 endpoint if it exposes one, else <c>null</c>. SSH.NET's
    /// built-in SOCKS5 proxy support consumes this directly; for protocols without proxy
    /// awareness, prefer <see cref="DialAsync"/> or <see cref="BindLocalForwarderAsync"/>.
    /// </summary>
    IPEndPoint? Socks5Endpoint { get; }

    /// <summary>Open a stream-like connection to <paramref name="host"/>:<paramref name="port"/> through the tunnel.</summary>
    Task<Stream> DialAsync(string host, int port, CancellationToken cancellationToken);

    /// <summary>
    /// Bind a TCP listener on 127.0.0.1 that forwards every accepted client through the tunnel to
    /// <paramref name="host"/>:<paramref name="port"/>. Returns the chosen port. Used for the RDP
    /// ActiveX control which opens its own socket from a hostname.
    /// Implementations must be idempotent per (host, port): instances are shared across sessions
    /// (<see cref="TunnelManager"/> pools one per tunnel config), so repeated binds for the same
    /// target should return the existing live listener's port rather than accumulating one
    /// listener per connect for the tunnel's lifetime.
    /// </summary>
    Task<int> BindLocalForwarderAsync(string host, int port, CancellationToken cancellationToken);
}

public sealed class TunnelStateChangedEventArgs : EventArgs
{
    public TunnelStateChangedEventArgs(TunnelState state, string? message = null, System.Exception? error = null)
    {
        State = state;
        Message = message;
        Error = error;
    }

    public TunnelState State { get; }
    public string? Message { get; }
    public System.Exception? Error { get; }
}
