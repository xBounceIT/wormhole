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
/// inner tunnel, but <see cref="DisposeAsync"/> never disposes it — so a consumer can route through a
/// tunnel that someone else owns without tearing it down.
///
/// <para>Two users: a sibling SFTP session (the file-transfer dialog / the SSH session's SFTP pre-warm)
/// borrows the SSH session's tunnel handle instead of establishing a second one — establishing a second
/// tunnel would, for an OTP-interactive VPN, re-prompt for and burn another single-use code. And
/// <see cref="TunnelManager"/> hands every caller one of these as a lease over its shared per-config
/// tunnel, passing <c>onDispose</c> to get notified (exactly once) when the lease is released so it can
/// ref-count the real instance and dispose it after the last lease goes.</para>
/// </summary>
internal sealed class BorrowedTunnelInstance : ITunnelInstance
{
    private readonly ITunnelInstance _inner;
    private readonly Func<ValueTask>? _onDispose;
    private readonly object _gate = new();
    private int _disposed;
    // Handlers a borrower subscribed THROUGH this wrapper, tracked so DisposeAsync can detach them from
    // the longer-lived inner tunnel — otherwise a borrower's handler would outlive the borrow (the inner
    // is not disposed here), keeping the borrower alive and firing into it after it's logically done.
    private List<EventHandler<TunnelStateChangedEventArgs>>? _forwarded;

    public BorrowedTunnelInstance(ITunnelInstance inner, Func<ValueTask>? onDispose = null)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        _onDispose = onDispose;
    }

    public TunnelState State => _inner.State;

    public event EventHandler<TunnelStateChangedEventArgs>? StateChanged
    {
        add
        {
            if (value is null) return;
            // Track and attach under one gate, and refuse after dispose: a subscribe racing (or
            // arriving after) DisposeAsync must never reach the inner tunnel — the pooled inner can
            // outlive this handle by hours, and a handler attached outside the tracking window
            // would never be detached (exactly the leak the tracking exists to prevent).
            lock (_gate)
            {
                if (Volatile.Read(ref _disposed) != 0) return;
                (_forwarded ??= new()).Add(value);
                _inner.StateChanged += value;
            }
        }
        remove
        {
            if (value is null) return;
            lock (_gate)
            {
                _forwarded?.Remove(value);
                _inner.StateChanged -= value;
            }
        }
    }

    public IPEndPoint? Socks5Endpoint => _inner.Socks5Endpoint;

    public Task<Stream> DialAsync(string host, int port, CancellationToken cancellationToken) =>
        _inner.DialAsync(host, port, cancellationToken);

    public Task<int> BindLocalForwarderAsync(string host, int port, CancellationToken cancellationToken) =>
        _inner.BindLocalForwarderAsync(host, port, cancellationToken);

    // Non-owning: deliberately does NOT dispose the inner instance — but DOES detach any handlers this
    // borrow forwarded onto it, so disposing the borrow cleanly unsubscribes the borrower while the
    // inner tunnel lives on under its real owner. The Interlocked guard makes the dispose idempotent:
    // onDispose carries TunnelManager's ref-count release, which must run exactly once no matter how
    // many teardown paths (disconnect + close, retry + close) dispose the same handle.
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;

        // Detach under the same gate the add path attaches under (the flag set above stops any
        // add that hasn't taken the gate yet), so no handler can slip onto the inner after this.
        lock (_gate)
        {
            if (_forwarded is { Count: > 0 })
            {
                foreach (var handler in _forwarded) _inner.StateChanged -= handler;
                _forwarded.Clear();
            }
        }

        if (_onDispose is not null) await _onDispose().ConfigureAwait(false);
    }
}
