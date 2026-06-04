using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Wormhole.Models;

namespace Wormhole.Services.Tunneling;

/// <summary>
/// A non-owning view over an existing <see cref="ITunnelInstance"/>. Every operation forwards to the
/// inner tunnel, but <see cref="DisposeAsync"/> is a no-op — so a consumer can route through a tunnel
/// that someone else owns without tearing it down.
///
/// <para>Used so a sibling SFTP session (the file-transfer dialog / the SSH session's SFTP pre-warm) can
/// reuse the SSH session's already-established tunnel instead of establishing a second one. Establishing
/// a second tunnel would, for an OTP-interactive VPN, re-prompt for and burn another single-use code; and
/// is a redundant VPN connection for any tunnel. The SSH session remains the sole owner and disposes the
/// real instance exactly once when it disconnects.</para>
/// </summary>
internal sealed class BorrowedTunnelInstance : ITunnelInstance
{
    private readonly ITunnelInstance _inner;
    private readonly object _gate = new();
    // Handlers a borrower subscribed THROUGH this wrapper, tracked so DisposeAsync can detach them from
    // the longer-lived inner tunnel — otherwise a borrower's handler would outlive the borrow (the inner
    // is not disposed here), keeping the borrower alive and firing into it after it's logically done.
    private List<EventHandler<TunnelStateChangedEventArgs>>? _forwarded;

    public BorrowedTunnelInstance(ITunnelInstance inner) =>
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));

    public TunnelState State => _inner.State;

    public event EventHandler<TunnelStateChangedEventArgs>? StateChanged
    {
        add
        {
            if (value is null) return;
            lock (_gate) { (_forwarded ??= new()).Add(value); }
            _inner.StateChanged += value;
        }
        remove
        {
            if (value is null) return;
            lock (_gate) { _forwarded?.Remove(value); }
            _inner.StateChanged -= value;
        }
    }

    public IPEndPoint? Socks5Endpoint => _inner.Socks5Endpoint;

    public Task<Stream> DialAsync(string host, int port, CancellationToken cancellationToken) =>
        _inner.DialAsync(host, port, cancellationToken);

    public Task<int> BindLocalForwarderAsync(string host, int port, CancellationToken cancellationToken) =>
        _inner.BindLocalForwarderAsync(host, port, cancellationToken);

    // Non-owning: deliberately does NOT dispose the inner instance — but DOES detach any handlers this
    // borrow forwarded onto it, so disposing the borrow cleanly unsubscribes the borrower while the
    // inner tunnel lives on under its real owner.
    public ValueTask DisposeAsync()
    {
        EventHandler<TunnelStateChangedEventArgs>[] handlers;
        lock (_gate)
        {
            if (_forwarded is null || _forwarded.Count == 0) return ValueTask.CompletedTask;
            handlers = _forwarded.ToArray();
            _forwarded.Clear();
        }
        foreach (var handler in handlers) _inner.StateChanged -= handler;
        return ValueTask.CompletedTask;
    }
}
