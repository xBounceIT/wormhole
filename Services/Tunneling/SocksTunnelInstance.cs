using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Wormhole.Models;

namespace Wormhole.Services.Tunneling;

/// <summary>
/// Generic <see cref="ITunnelInstance"/> backed by a local SOCKS5 endpoint. Any provider whose
/// userspace stack exposes SOCKS5 on 127.0.0.1 (current: wireguard-go sidecar; future: OpenVPN /
/// vendor sidecars; plain SOCKS5 / HTTP CONNECT external proxies) wraps itself in this.
/// </summary>
public sealed class SocksTunnelInstance : ITunnelInstance
{
    private readonly IPEndPoint _socksEndpoint;
    private readonly ILogger _logger;
    private readonly Func<ValueTask>? _onDispose;
    private readonly List<LocalTcpForwarder> _forwarders = new();
    private readonly object _gate = new();
    private int _disposedFlag;

    public SocksTunnelInstance(IPEndPoint socksEndpoint, ILogger logger, Func<ValueTask>? onDispose = null)
    {
        _socksEndpoint = socksEndpoint ?? throw new ArgumentNullException(nameof(socksEndpoint));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _onDispose = onDispose;
    }

    public TunnelState State => Volatile.Read(ref _disposedFlag) != 0 ? TunnelState.Closed : TunnelState.Up;

    public event EventHandler<TunnelStateChangedEventArgs>? StateChanged;

    public IPEndPoint? Socks5Endpoint => _socksEndpoint;

    public async Task<Stream> DialAsync(string host, int port, CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        return await Socks5Client.ConnectAsync(_socksEndpoint, host, port, cancellationToken).ConfigureAwait(false);
    }

    public async Task<int> BindLocalForwarderAsync(string host, int port, CancellationToken cancellationToken)
    {
        // Reuse an existing live listener for the same target instead of binding a new one per
        // connect. The tunnel is shared across connections (TunnelManager pools it per config), so
        // forwarders live for the whole shared tunnel's lifetime — without this, repeated RDP/web
        // connects through a long-lived tunnel would pile up loopback listeners. The whole
        // check-or-start runs under one gate (Start is a synchronous loopback bind, microseconds),
        // which removes both races — concurrent DisposeAsync and concurrent same-target bind — by
        // construction instead of compensating for them.
        LocalTcpForwarder? stale = null;
        int boundPort;
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposedFlag) != 0, this);

            if (FindForwarderLocked(host, port) is { } existing)
            {
                if (existing.IsAlive) return existing.LocalPort;
                // The accept loop crashed: its listener no longer accepts, so handing its port out
                // would dead-end every future connect to this target. Replace it.
                _forwarders.Remove(existing);
                stale = existing;
            }

            var fwd = LocalTcpForwarder.Start(this, host, port, _logger);
            _forwarders.Add(fwd);
            boundPort = fwd.LocalPort;
        }

        if (stale is not null)
        {
            try { await stale.DisposeAsync().ConfigureAwait(false); }
            catch (Exception ex) { _logger.LogDebug(ex, "Stale forwarder dispose failed."); }
        }
        return boundPort;
    }

    private LocalTcpForwarder? FindForwarderLocked(string host, int port)
    {
        foreach (var fwd in _forwarders)
        {
            // Hostnames are case-insensitive; forwarders are keyed by the literal target the
            // caller dialed (no DNS normalization — "10.0.0.5" and a name resolving to it stay
            // distinct, which only costs an extra listener).
            if (fwd.TargetPort == port && string.Equals(fwd.TargetHost, host, StringComparison.OrdinalIgnoreCase))
            {
                return fwd;
            }
        }
        return null;
    }

    public async ValueTask DisposeAsync()
    {
        // Interlocked guard makes DisposeAsync idempotent under concurrent calls — the
        // sidecar process tear-down (via _onDispose) must run exactly once.
        if (Interlocked.Exchange(ref _disposedFlag, 1) != 0) return;

        LocalTcpForwarder[] fwds;
        lock (_gate) { fwds = _forwarders.ToArray(); _forwarders.Clear(); }
        foreach (var fwd in fwds)
        {
            try { await fwd.DisposeAsync().ConfigureAwait(false); } catch (Exception ex) { _logger.LogDebug(ex, "Forwarder dispose failed."); }
        }
        StateChanged?.Invoke(this, new TunnelStateChangedEventArgs(TunnelState.Closed));
        if (_onDispose is not null)
        {
            try { await _onDispose().ConfigureAwait(false); } catch (Exception ex) { _logger.LogWarning(ex, "Tunnel onDispose hook failed."); }
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposedFlag) != 0, this);
    }
}
